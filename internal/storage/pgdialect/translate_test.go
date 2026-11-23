package pgdialect

import (
	"fmt"
	"testing"
)

func TestTranslate(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`SELECT a FROM t WHERE b=? AND c=?`, `SELECT a FROM t WHERE b=$1 AND c=$2`},
		{`SELECT '?', "x?" FROM t WHERE a=? -- why?
 AND b=? /* c=? */`, `SELECT '?', "x?" FROM t WHERE a=$1 -- why?
 AND b=$2 /* c=? */`},
		{`SELECT 'it''s ?' WHERE a=?`, `SELECT 'it''s ?' WHERE a=$1`},
		{`INSERT OR IGNORE INTO t(a) VALUES(?)`, `INSERT INTO t(a) VALUES($1) ON CONFLICT DO NOTHING`},
		{`SELECT ?1,?3,?2, ? WHERE a=?1`, `SELECT $1,$3,$2, $4 WHERE a=$1`},
		{`SELECT 'mem_' || lower(hex(randomblob(12))), lower(hex(randomblob(17)))`, `SELECT 'mem_' || substr(replace(gen_random_uuid()::text,'-',''),1,24), lower(hex(randomblob(17)))`},
		{`INSERT INTO t VALUES(X'00Ff',x'',?) -- X'ab'`, `INSERT INTO t VALUES('\x00Ff'::bytea,'\x'::bytea,$1) -- X'ab'`},
		{`SELECT max_x'a', 'X''b'`, `SELECT max_x'a', 'X''b'`},
		{`UPDATE t SET p=zeroblob(64), q=zeroblob(length(?)+1) WHERE a=ZEROBLOB (2)`, `UPDATE t SET p=decode(repeat('00',64),'hex'), q=decode(repeat('00',length($1)+1),'hex') WHERE a=ZEROBLOB (2)`},
		{"insert  or\n ignore into t SELECT x FROM y WHERE z=?;\n", "insert into t SELECT x FROM y WHERE z=$1 ON CONFLICT DO NOTHING;\n"},
		{`INSERT OR IGNORE INTO t(a) VALUES(?) RETURNING a`, `INSERT INTO t(a) VALUES($1) ON CONFLICT DO NOTHING RETURNING a`},
		{`INSERT OR IGNORE INTO t(a) SELECT x FROM (SELECT 1 x) s; INSERT OR IGNORE INTO u VALUES(?)`, `INSERT INTO t(a) SELECT x FROM (SELECT 1 x) s ON CONFLICT DO NOTHING; INSERT INTO u VALUES($1) ON CONFLICT DO NOTHING`},
		{`INSERT INTO t(a) VALUES(?) ON CONFLICT(a) DO NOTHING`, `INSERT INTO t(a) VALUES($1) ON CONFLICT(a) DO NOTHING`},
		{`INSERT OR REPLACE INTO t VALUES(1)`, `INSERT OR REPLACE INTO t VALUES(1)`},
		{`SELECT 1 WHERE e>unixepoch() AND f<UNIXEPOCH ( )+?`, `SELECT 1 WHERE e>(floor(extract(epoch from statement_timestamp()))::bigint) AND f<(floor(extract(epoch from statement_timestamp()))::bigint)+$1`},
		{`SELECT unixepoch_x, my_unixepoch() FROM t`, `SELECT unixepoch_x, my_unixepoch() FROM t`},
		{`SELECT 'unixepoch()' FROM t`, `SELECT 'unixepoch()' FROM t`},
		{`WHERE action LIKE ? ESCAPE '\' AND b NOT like 'group:%'`, `WHERE action ILIKE $1 ESCAPE '\' AND b NOT ILIKE 'group:%'`},
		{`SELECT likes, unlike, x ILIKE y FROM t`, `SELECT likes, unlike, x ILIKE y FROM t`},
		{`CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN INSERT INTO t VALUES(NEW.a) ON CONFLICT DO NOTHING; RETURN NULL; END $$ LANGUAGE plpgsql; SELECT ?`, `CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN INSERT INTO t VALUES(NEW.a) ON CONFLICT DO NOTHING; RETURN NULL; END $$ LANGUAGE plpgsql; SELECT $1`},
		{`WHERE instr(lower(u.name),lower(?))>0 AND instr (a,b) AND my_instr(a,b)`, `WHERE strpos(lower(u.name),lower($1))>0 AND instr (a,b) AND my_instr(a,b)`},
		{`INSERT INTO t(id) SELECT lower(hex(randomblob(16))), lower( hex( randomblob( 16 ) ) ), lower(hex(randomblob(8))) FROM s`, `INSERT INTO t(id) SELECT replace(gen_random_uuid()::text,'-',''), replace(gen_random_uuid()::text,'-',''), substr(replace(gen_random_uuid()::text,'-',''),1,16) FROM s`},
		{`SELECT $1, ? FROM t`, `SELECT $1, $1 FROM t`}, // mixing styles is a caller bug; it is not detected
		{`SELECT 'unterminated ?`, `SELECT 'unterminated ?`},
	} {
		if got := Translate(c.in); got != c.want {
			t.Errorf("Translate(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestIsRead(t *testing.T) {
	for q, want := range map[string]bool{
		"SELECT 1":                           true,
		"  \n select x from t":               true,
		"(SELECT 1) UNION (SELECT 2)":        true,
		"-- note\nSELECT 1":                  true,
		"/* note */ VALUES (1)":              true,
		"SHOW transaction_read_only":         true,
		"UPDATE t SET a=1 RETURNING a":       false,
		"INSERT INTO t VALUES(1)":            false,
		"DELETE FROM t":                      false,
		"WITH x AS (DELETE FROM t) SELECT 1": false,
		"CREATE TABLE t(a int)":              false,
		"selectx FROM t":                     false,
		"":                                   false,
	} {
		if got := IsRead(q); got != want {
			t.Errorf("IsRead(%q) = %v, want %v", q, got, want)
		}
	}
}

func TestSplit(t *testing.T) {
	stmts, params := Split("UPDATE a SET x=?; DELETE FROM b; -- c;\nUPDATE c SET y=';?' WHERE z=? AND w=?;\n")
	want := []string{"UPDATE a SET x=?", " DELETE FROM b", " -- c;\nUPDATE c SET y=';?' WHERE z=? AND w=?"}
	if len(stmts) != 3 || stmts[0] != want[0] || stmts[1] != want[1] || stmts[2] != want[2] || params[0] != 1 || params[1] != 0 || params[2] != 2 {
		t.Fatalf("Split = %q %v", stmts, params)
	}
}

func TestTranslateArgsPassesOnlyTheArgumentsUsed(t *testing.T) {
	for _, c := range []struct {
		in    string
		nargs int
		want  string
		keep  []int
	}{
		{`SELECT ? , ?`, 2, `SELECT $1 , $2`, []int{0, 1}},
		{`UPDATE t SET a=?3 WHERE id=?1 OR team=?1`, 3, `UPDATE t SET a=$2 WHERE id=$1 OR team=$1`, []int{0, 2}},
		{`DELETE FROM t WHERE id=?1`, 2, `DELETE FROM t WHERE id=$1`, []int{0}},
		{`SELECT '?1', x FROM t WHERE y=?2`, 2, `SELECT '?1', x FROM t WHERE y=$1`, []int{1}},
		{`SELECT 1`, 2, `SELECT 1`, []int{}},
	} {
		got, keep := TranslateArgs(c.in, c.nargs)
		if got != c.want || fmt.Sprint(keep) != fmt.Sprint(c.keep) {
			t.Errorf("TranslateArgs(%q, %d) = %q %v, want %q %v", c.in, c.nargs, got, keep, c.want, c.keep)
		}
	}
}
