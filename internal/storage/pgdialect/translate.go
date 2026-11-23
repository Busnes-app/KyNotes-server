// Package pgdialect runs the store's SQLite-dialect SQL on Postgres: a small statement
// translator and the kynotespg database/sql driver that applies it and serialises writers.
package pgdialect

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Translate rewrites one SQLite-dialect statement (or script) for Postgres. It knows
// exactly these rules, applied outside string literals, quoted identifiers and comments:
//   - ? placeholders become $1..$n;
//   - INSERT OR IGNORE INTO t ... becomes INSERT INTO t ... ON CONFLICT DO NOTHING (before
//     a top-level RETURNING, otherwise at the end of the statement);
//   - unixepoch() becomes the current statement's time in whole seconds;
//   - LIKE becomes ILIKE: SQLite's LIKE folds ASCII case, and ILIKE does the same on a C-locale
//     database, so every LIKE keeps its meaning (ESCAPE clauses are unchanged);
//   - instr( becomes strpos( (same arguments, same 1-based result, 0 when absent);
//   - the random identifier idiom lower(hex(randomblob(16))) becomes 32 random hex digits;
//   - a blob literal X'00ff' becomes '\x00ff'::bytea (KyNotes);
//   - zeroblob(n) becomes decode(repeat('00',n),'hex'), n copied as is (KyNotes);
//   - ?NNN (an explicitly numbered placeholder) becomes $NNN, and a later bare ? takes the
//     next number after the largest so far, as SQLite numbers them (KyNotes);
//   - lower(hex(randomblob(N))) for N up to 16 becomes 2N random hex digits (KyNotes).
//
// Anything else that differs is written out at the call site for each backend. This is
// not a parser: keep it to rules that are true token by token.
func Translate(q string) string {
	out, _ := TranslateArgs(q, -1)
	return out
}

// TranslateArgs is Translate for a statement bound to nargs arguments. SQLite lets a
// statement leave arguments unused (code passes one list to several statements, each taking
// what it needs: ?1 and ?3 but not ?2); PostgreSQL refuses both an unused argument and a
// placeholder it cannot type. So the placeholders used are renumbered $1..$k in order, and
// keep lists the 0-based arguments to pass, in that order. With nargs<0 numbers stay as
// written and keep is nil.
func TranslateArgs(q string, nargs int) (string, []int) {
	out, used := translate(q)
	if nargs < 0 {
		return placeholders.ReplaceAllString(out, "$$$1"), nil
	}
	nums := make([]int, 0, len(used))
	for k := range used {
		nums = append(nums, k)
	}
	sort.Ints(nums)
	renumber := map[string]string{}
	keep := make([]int, len(nums))
	for i, k := range nums {
		renumber[strconv.Itoa(k)] = "$" + strconv.Itoa(i+1)
		keep[i] = k - 1
	}
	return placeholders.ReplaceAllStringFunc(out, func(m string) string { return renumber[m[1:len(m)-1]] }), keep
}

// placeholders marks the numbers translate writes; NUL never occurs in SQL text.
var placeholders = regexp.MustCompile("\x00([0-9]+)\x00")

func translate(q string) (string, map[int]bool) {
	used := map[int]bool{}
	var b strings.Builder
	b.Grow(len(q) + 16)
	n, depth := 0, 0
	ignore := false    // inside an INSERT OR IGNORE statement, owed its ON CONFLICT clause
	var zeroblob []int // depths of open zeroblob( calls
	flush := func() {
		if ignore {
			trimmed := strings.TrimRight(b.String(), " \t\r\n")
			b.Reset()
			b.WriteString(trimmed)
			b.WriteString(" ON CONFLICT DO NOTHING")
			ignore = false
		}
	}
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case (c == 'x' || c == 'X') && i+1 < len(q) && q[i+1] == '\'' && (i == 0 || !isWordByte(q[i-1])):
			j := strings.IndexByte(q[i+2:], '\'')
			if j < 0 {
				j = len(q) - i - 2
			}
			b.WriteString(`'\x` + q[i+2:i+2+j] + `'::bytea`)
			i = min(i+3+j, len(q))
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(q) {
				if q[j] == c {
					if j+1 < len(q) && q[j+1] == c {
						j += 2
						continue
					}
					break
				}
				j++
			}
			j = min(j+1, len(q))
			b.WriteString(q[i:j])
			i = j
		case c == '-' && strings.HasPrefix(q[i:], "--"):
			j := strings.IndexByte(q[i:], '\n')
			if j < 0 {
				j = len(q) - i
			}
			b.WriteString(q[i : i+j])
			i += j
		case c == '/' && strings.HasPrefix(q[i:], "/*"):
			j := strings.Index(q[i+2:], "*/")
			if j < 0 {
				j = len(q) - i - 2
			} else {
				j += 2
			}
			b.WriteString(q[i : i+2+j])
			i += 2 + j
		case c == '$' && strings.HasPrefix(q[i:], "$$"):
			// A $$-quoted body (a plpgsql function in Postgres-only DDL) is copied as is.
			j := strings.Index(q[i+2:], "$$")
			if j < 0 {
				j = len(q) - i - 4
			}
			b.WriteString(q[i : i+4+j])
			i += 4 + j
		case c == '?':
			j := i + 1
			for j < len(q) && q[j] >= '0' && q[j] <= '9' {
				j++
			}
			if j > i+1 {
				k, _ := strconv.Atoi(q[i+1 : j])
				n = max(n, k)
				used[k] = true
				b.WriteString("\x00" + q[i+1:j] + "\x00")
			} else {
				n++
				used[n] = true
				b.WriteString("\x00" + strconv.Itoa(n) + "\x00")
			}
			i = j
		case c == '(':
			depth++
			b.WriteByte(c)
			i++
		case c == ')':
			if k := len(zeroblob); k > 0 && zeroblob[k-1] == depth {
				zeroblob = zeroblob[:k-1]
				b.WriteString("),'hex'")
			}
			depth--
			b.WriteByte(c)
			i++
		case c == ';':
			if depth == 0 {
				flush()
			}
			b.WriteByte(c)
			i++
		case isWordStart(c) && (i == 0 || !isWordByte(q[i-1])):
			j := i
			for j < len(q) && isWordByte(q[j]) {
				j++
			}
			word := q[i:j]
			switch strings.ToUpper(word) {
			case "INSERT":
				if rest, ok := skipWords(q[j:], "OR", "IGNORE"); ok {
					b.WriteString(word)
					ignore = true
					i = len(q) - len(rest)
					continue
				}
			case "RETURNING":
				if depth == 0 && ignore {
					flush()
					b.WriteByte(' ')
				}
			case "LIKE":
				b.WriteString("ILIKE")
				i = j
				continue
			case "INSTR":
				if strings.HasPrefix(q[j:], "(") {
					b.WriteString("strpos")
					i = j
					continue
				}
			case "LOWER":
				if rest, ok := skipWords(q[j:], "(", "hex", "(", "randomblob", "("); ok {
					rest = strings.TrimLeft(rest, " \t\r\n")
					k := 0
					for k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
						k++
					}
					if size, _ := strconv.Atoi(rest[:k]); size > 0 && size <= 16 {
						if after, ok := skipWords(rest[k:], ")", ")", ")"); ok {
							if size == 16 {
								b.WriteString("replace(gen_random_uuid()::text,'-','')")
							} else {
								b.WriteString("substr(replace(gen_random_uuid()::text,'-',''),1," + strconv.Itoa(2*size) + ")")
							}
							i = len(q) - len(after)
							continue
						}
					}
				}
			case "ZEROBLOB":
				if strings.HasPrefix(q[j:], "(") {
					b.WriteString("decode(repeat('00',")
					i = j + 1
					depth++ // the call's own ")" closes the repeat; decode's is added there
					zeroblob = append(zeroblob, depth)
					continue
				}
			case "UNIXEPOCH":
				if rest, ok := skipWords(q[j:], "(", ")"); ok {
					b.WriteString("(floor(extract(epoch from statement_timestamp()))::bigint)")
					i = len(q) - len(rest)
					continue
				}
			}
			b.WriteString(word)
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	if depth == 0 {
		flush()
	}
	return b.String(), used
}

// skipWords consumes the given tokens (words compared without case, or single
// punctuation), each optionally preceded by whitespace, and returns what follows.
func skipWords(s string, tokens ...string) (string, bool) {
	for _, t := range tokens {
		s = strings.TrimLeft(s, " \t\r\n")
		if len(s) < len(t) || !strings.EqualFold(s[:len(t)], t) {
			return "", false
		}
		if isWordStart(t[0]) && len(s) > len(t) && isWordByte(s[len(t)]) {
			return "", false
		}
		s = s[len(t):]
	}
	return s, true
}

func isWordStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isWordByte(c byte) bool { return isWordStart(c) || c >= '0' && c <= '9' || c == '$' }

// Split cuts a script into its statements at top-level semicolons (outside literals,
// quoted identifiers, comments and $$ bodies) and counts each one's ? placeholders.
// Postgres takes several statements in one call only without arguments, while the
// store's SQLite scripts sometimes bind them; the driver runs such a script piece by piece.
func Split(q string) (stmts []string, params []int) {
	start, n := 0, 0
	for i := 0; i < len(q); i++ {
		switch c := q[i]; {
		case c == '\'' || c == '"':
			for i++; i < len(q) && q[i] != c; i++ {
			}
		case c == '-' && strings.HasPrefix(q[i:], "--"):
			for i < len(q) && q[i] != '\n' {
				i++
			}
		case c == '/' && strings.HasPrefix(q[i:], "/*"):
			if j := strings.Index(q[i+2:], "*/"); j >= 0 {
				i += j + 3
			} else {
				i = len(q)
			}
		case c == '$' && strings.HasPrefix(q[i:], "$$"):
			if j := strings.Index(q[i+2:], "$$"); j >= 0 {
				i += j + 3
			} else {
				i = len(q)
			}
		case c == '?':
			n++
		case c == ';':
			if strings.TrimSpace(q[start:i]) != "" {
				stmts, params = append(stmts, q[start:i]), append(params, n)
			}
			start, n = i+1, 0
		}
	}
	if strings.TrimSpace(q[start:]) != "" {
		stmts, params = append(stmts, q[start:]), append(params, n)
	}
	return stmts, params
}

// IsRead reports whether a statement only reads: it starts with SELECT, VALUES, SHOW or
// EXPLAIN. Everything else, a WITH included, is treated as a write.
func IsRead(q string) bool {
	for {
		q = strings.TrimLeft(q, " \t\r\n(")
		switch {
		case strings.HasPrefix(q, "--"):
			if i := strings.IndexByte(q, '\n'); i >= 0 {
				q = q[i:]
				continue
			}
			return false
		case strings.HasPrefix(q, "/*"):
			if i := strings.Index(q, "*/"); i >= 0 {
				q = q[i+2:]
				continue
			}
			return false
		}
		break
	}
	j := 0
	for j < len(q) && isWordByte(q[j]) {
		j++
	}
	switch strings.ToUpper(q[:j]) {
	case "SELECT", "VALUES", "SHOW", "EXPLAIN":
		return true
	}
	return false
}
