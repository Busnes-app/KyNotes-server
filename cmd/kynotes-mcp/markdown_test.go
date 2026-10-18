package main

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func doc(blocks string) string {
	return `{"format":"kynotes.blocknote.v1","document":[` + blocks + `]}`
}

func TestPageMarkdownBlockTypes(t *testing.T) {
	body := doc(`
		{"type":"heading","props":{"level":2},"content":[{"type":"text","text":"Plan","styles":{"bold":true}}]},
		{"type":"paragraph","content":[{"type":"text","text":"See "},{"type":"link","href":"https://x.test","content":[{"type":"text","text":"docs"}]}]},
		{"type":"bulletListItem","content":"one","children":[{"type":"bulletListItem","content":"nested"}]},
		{"type":"bulletListItem","content":"two"},
		{"type":"numberedListItem","content":"first"},
		{"type":"numberedListItem","content":"second"},
		{"type":"checkListItem","props":{"checked":true},"content":"done"},
		{"type":"checkListItem","props":{"checked":false},"content":"open"},
		{"type":"quote","content":"wise\nwords"},
		{"type":"codeBlock","props":{"language":"go"},"content":[{"type":"text","text":"x := 1"}]},
		{"type":"table","content":{"type":"tableContent","rows":[{"cells":[[{"type":"text","text":"a"}],{"type":"tableCell","content":[{"type":"text","text":"b"}]}]}]}},
		{"type":"image","props":{"name":"cat.png"}},
		{"type":"mystery","content":"still text"}`)
	want := "## Plan\n\nSee [docs](https://x.test)\n\n- one\n  - nested\n- two\n1. first\n2. second\n- [x] done\n- [ ] open\n\n> wise\n> words\n\n```go\nx := 1\n```\n\n| a | b |\n\n[cat.png]\n\nstill text"
	if got := pageMarkdown(body); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestPageMarkdownCanvasReadingOrder(t *testing.T) {
	box := func(id string, x, y int, text string) string {
		b, _ := json.Marshal(map[string]any{"id": id, "x": x, "y": y, "width": 300, "blocks": []any{map[string]any{"type": "paragraph", "content": text}}})
		return string(b)
	}
	body := `{"format":"kynotes.canvas.v1","boxes":[` + box("c", 0, 500, "third") + `,` + box("b", 400, 10, "second") + `,` + box("a", 0, 10, "first") + `],"strokes":[]}`
	if got := pageMarkdown(body); got != "first\n\nsecond\n\nthird" {
		t.Fatalf("got %q", got)
	}
}

func TestPageMarkdownOtherBodiesArePlainText(t *testing.T) {
	if got := pageMarkdown("just text # not json"); got != "just text # not json" {
		t.Fatalf("plain: %q", got)
	}
	tiptap := `{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"old"},{"type":"text","text":"note"}]}]}`
	if got := pageMarkdown(tiptap); got != "old note" {
		t.Fatalf("legacy: %q", got)
	}
}

func TestTruncateKeepsRunes(t *testing.T) {
	s := strings.Repeat("é", maxText) // two bytes each
	got, cut := truncate(s, maxText)
	if !cut || len(got) > maxText || !utf8.ValidString(got) || len(got) < maxText-1 {
		t.Fatalf("cut=%v len=%d", cut, len(got))
	}
	if got, cut := truncate("short", maxText); cut || got != "short" {
		t.Fatal("short text was cut")
	}
}

func TestMarkdownBlocksOnlyParagraphsAndChecklists(t *testing.T) {
	got, _ := json.Marshal(markdownBlocks("Hello\nworld\n\n- [ ] todo\n* [x] done\n# Head\n\n\n"))
	want := `[{"content":[{"styles":{},"text":"Hello\nworld","type":"text"}],"type":"paragraph"},` +
		`{"content":[{"styles":{},"text":"todo","type":"text"}],"props":{"checked":false},"type":"checkListItem"},` +
		`{"content":[{"styles":{},"text":"done","type":"text"}],"props":{"checked":true},"type":"checkListItem"},` +
		`{"content":[{"styles":{},"text":"# Head","type":"text"}],"type":"paragraph"}]`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if b := markdownBlocks(" \n\n"); len(b) != 0 {
		t.Fatalf("blank input made %d blocks", len(b))
	}
}

func TestAppendBlocksKeepsEverythingElse(t *testing.T) {
	blocks := markdownBlocks("added")
	body := `{"format":"kynotes.blocknote.v1","extra":{"n":12345678901234567},"document":[{"id":"x","type":"paragraph","content":"kept"}]}`
	got, err := appendBlocks(body, blocks)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"n":12345678901234567`) || pageMarkdown(got) != "kept\n\nadded" {
		t.Fatalf("got %s", got)
	}
	if got, err = appendBlocks("", blocks); err != nil || pageMarkdown(got) != "added" {
		t.Fatalf("empty body: %s %v", got, err)
	}
	for _, old := range []string{"plain text", `{"type":"doc","content":[]}`} {
		if _, err := appendBlocks(old, blocks); err != errOldFormat {
			t.Fatalf("%s: %v", old, err)
		}
	}
}

func TestAppendToCanvasAddsABoxBelow(t *testing.T) {
	body := `{"format":"kynotes.canvas.v1","boxes":[{"id":"a","x":10,"y":100,"width":300,"blocks":[{"type":"paragraph","content":"top"},{"type":"paragraph","content":"two"}]}],"strokes":[{"id":"s","tool":"pen","color":"ink","size":4,"points":[0,900,0.5]}]}`
	got, err := appendBlocks(body, markdownBlocks("below"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Boxes []struct {
			ID string
			X  float64
			Y  float64
		}
		Strokes []any
	}
	if err := json.Unmarshal([]byte(got), &v); err != nil || len(v.Boxes) != 2 || len(v.Strokes) != 1 {
		t.Fatalf("got %s %v", got, err)
	}
	if nb := v.Boxes[1]; nb.Y <= 900 || nb.X != 0 || !strings.HasPrefix(nb.ID, "mcp-") {
		t.Fatalf("new box %+v", nb)
	}
	if pageMarkdown(got) != "top\n\ntwo\n\nbelow" {
		t.Fatalf("order: %q", pageMarkdown(got))
	}
}

func TestKeyAfterMatchesOrderTS(t *testing.T) {
	// Values from web/src/order.ts keyBetween(last, null).
	for last, want := range map[string]string{"": "i", "i": "j", "y": "z", "z": "z1", "zz": "zz1", "i5": "j", "z9": "za"} {
		if got, err := keyAfter(last); err != nil || got != want {
			t.Fatalf("keyAfter(%q)=%q %v, want %q", last, got, err, want)
		}
	}
}
