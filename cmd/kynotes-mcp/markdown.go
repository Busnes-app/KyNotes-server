package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	blocknoteFormat = "kynotes.blocknote.v1"
	canvasFormat    = "kynotes.canvas.v1"
	maxText         = 64 << 10
	maxCoord        = 100_000
	maxBoxes        = 500
)

// decodeJSON keeps numbers exact, so an appended body re-encodes untouched fields as they were.
func decodeJSON(s string) (any, bool) {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil || d.More() {
		return nil, false
	}
	return v, true
}

func num(v any) float64 {
	n, ok := v.(json.Number)
	if !ok {
		return 0
	}
	f, _ := n.Float64()
	return f
}

// pageMarkdown turns a page body into Markdown: BlockNote documents and canvas boxes (reading
// order, top to bottom then left to right); any other body becomes its plain text.
func pageMarkdown(body string) string {
	v, ok := decodeJSON(body)
	if !ok {
		return body
	}
	doc, _ := v.(map[string]any)
	switch doc["format"] {
	case canvasFormat:
		var parts []string
		for _, box := range canvasBoxes(doc["boxes"]) {
			blocks, _ := box["blocks"].([]any)
			parts = append(parts, blocksMarkdown(blocks))
		}
		return strings.Join(parts, "\n\n")
	case blocknoteFormat:
		if blocks, ok := doc["document"].([]any); ok {
			return blocksMarkdown(blocks)
		}
	}
	return strings.Join(plainText(v, nil), " ")
}

// canvasBoxes are the boxes in reading order, capped like document.ts parseItems.
func canvasBoxes(v any) []map[string]any {
	list, _ := v.([]any)
	var boxes []map[string]any
	for _, item := range list[:min(len(list), maxBoxes)] {
		if box, ok := item.(map[string]any); ok {
			boxes = append(boxes, box)
		}
	}
	slices.SortStableFunc(boxes, func(a, b map[string]any) int {
		if d := num(a["y"]) - num(b["y"]); d != 0 {
			return sign(d)
		}
		return sign(num(a["x"]) - num(b["x"]))
	})
	return boxes
}

func sign(f float64) int {
	if f < 0 {
		return -1
	}
	if f > 0 {
		return 1
	}
	return 0
}

// plainText collects every "text" string, as document.ts documentText does.
func plainText(v any, out []string) []string {
	switch v := v.(type) {
	case map[string]any:
		if t, ok := v["text"].(string); ok {
			out = append(out, t)
		}
		for _, k := range slices.Sorted(maps.Keys(v)) {
			if k != "text" {
				out = plainText(v[k], out)
			}
		}
	case []any:
		for _, child := range v {
			out = plainText(child, out)
		}
	}
	return out
}

func isListItem(t string) bool {
	return t == "bulletListItem" || t == "numberedListItem" || t == "checkListItem"
}

func blocksMarkdown(blocks []any) string {
	var b strings.Builder
	number, prev := 0, ""
	for _, raw := range blocks {
		block, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		t, _ := block["type"].(string)
		props, _ := block["props"].(map[string]any)
		if b.Len() > 0 {
			b.WriteString("\n")
			if !isListItem(t) || !isListItem(prev) {
				b.WriteString("\n")
			}
		}
		if t == "numberedListItem" {
			number++
		} else {
			number = 0
		}
		prev = t
		text := inline(block["content"])
		switch t {
		case "heading":
			level := min(max(int(num(props["level"])), 1), 6)
			b.WriteString(strings.Repeat("#", level) + " " + text)
		case "bulletListItem":
			b.WriteString("- " + indentRest(text))
		case "numberedListItem":
			b.WriteString(fmt.Sprintf("%d. ", number) + indentRest(text))
		case "checkListItem":
			mark := "[ ]"
			if props["checked"] == true {
				mark = "[x]"
			}
			b.WriteString("- " + mark + " " + indentRest(text))
		case "quote":
			b.WriteString("> " + strings.ReplaceAll(text, "\n", "\n> "))
		case "codeBlock":
			lang, _ := props["language"].(string)
			b.WriteString("```" + strings.Map(func(r rune) rune {
				if r == '\n' || r == '`' {
					return -1
				}
				return r
			}, lang) + "\n" + text + "\n```")
		case "table":
			b.WriteString(table(block["content"]))
		default:
			if name, _ := props["name"].(string); text == "" && name != "" {
				text = "[" + name + "]"
			}
			b.WriteString(text)
		}
		if children, ok := block["children"].([]any); ok && len(children) > 0 {
			b.WriteString("\n  " + strings.ReplaceAll(blocksMarkdown(children), "\n", "\n  "))
		}
	}
	return b.String()
}

func indentRest(s string) string { return strings.ReplaceAll(s, "\n", "\n  ") }

// inline is the text of BlockNote inline content: a string, or text and link nodes.
func inline(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case []any:
		var b strings.Builder
		for _, item := range v {
			node, _ := item.(map[string]any)
			if node["type"] == "link" {
				href, _ := node["href"].(string)
				b.WriteString("[" + inline(node["content"]) + "](" + href + ")")
			} else if t, ok := node["text"].(string); ok {
				b.WriteString(t)
			}
		}
		return b.String()
	}
	return ""
}

// table renders BlockNote table content one row per line; a cell is inline content or a tableCell.
func table(v any) string {
	content, _ := v.(map[string]any)
	rows, _ := content["rows"].([]any)
	var lines []string
	for _, r := range rows {
		row, _ := r.(map[string]any)
		cells, _ := row["cells"].([]any)
		var texts []string
		for _, c := range cells {
			if cell, ok := c.(map[string]any); ok {
				c = cell["content"]
			}
			texts = append(texts, strings.ReplaceAll(inline(c), "\n", " "))
		}
		lines = append(lines, "| "+strings.Join(texts, " | ")+" |")
	}
	return strings.Join(lines, "\n")
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

var checkLine = regexp.MustCompile(`^\s*[-*] \[([ xX])\] ?(.*)$`)

// markdownBlocks makes BlockNote blocks for a write: "- [ ]" and "- [x]" lines become checklist
// items; every other run of lines, up to a blank line, is one paragraph, kept verbatim.
func markdownBlocks(md string) []any {
	var blocks []any
	var para []string
	text := func(s string) []any {
		return []any{map[string]any{"type": "text", "text": s, "styles": map[string]any{}}}
	}
	flush := func() {
		if len(para) > 0 {
			blocks = append(blocks, map[string]any{"type": "paragraph", "content": text(strings.Join(para, "\n"))})
			para = nil
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		if m := checkLine.FindStringSubmatch(line); m != nil {
			flush()
			blocks = append(blocks, map[string]any{"type": "checkListItem", "props": map[string]any{"checked": m[1] != " "}, "content": text(m[2])})
		} else if strings.TrimSpace(line) == "" {
			flush()
		} else {
			para = append(para, line)
		}
	}
	flush()
	return blocks
}

// newPageBody is a BlockNote document of blocks; BlockNote needs at least one block.
func newPageBody(blocks []any) (string, error) {
	if len(blocks) == 0 {
		blocks = []any{map[string]any{"type": "paragraph", "content": ""}}
	}
	return marshal(map[string]any{"format": blocknoteFormat, "document": blocks})
}

var errOldFormat = errors.New("this page uses an older format the bridge does not change; edit it once in KyNotes first")

// appendBlocks adds blocks to a page body: to the end of a BlockNote document, or in a new box
// below everything on a canvas. Every other field is kept as it was.
func appendBlocks(body string, blocks []any) (string, error) {
	if body == "" {
		return newPageBody(blocks)
	}
	v, ok := decodeJSON(body)
	doc, _ := v.(map[string]any)
	if !ok || doc == nil {
		return "", errOldFormat
	}
	switch doc["format"] {
	case blocknoteFormat:
		existing, ok := doc["document"].([]any)
		if !ok {
			return "", errOldFormat
		}
		doc["document"] = append(existing, blocks...)
	case canvasFormat:
		boxes, _ := doc["boxes"].([]any)
		if len(boxes) >= maxBoxes {
			return "", errors.New("this canvas page holds the most boxes it can")
		}
		id := make([]byte, 8)
		_, _ = rand.Read(id)
		doc["boxes"] = append(boxes, map[string]any{"id": "mcp-" + hex.EncodeToString(id), "x": 0, "y": canvasBottom(doc), "width": 640, "blocks": blocks})
	default:
		return "", errOldFormat
	}
	return marshal(doc)
}

// canvasBottom is a y below every box and stroke.
// ponytail: box heights are not stored, so a box is assumed 48px per block plus a margin; it
// can overlap a box with long paragraphs. Upgrade: store measured heights in the canvas format.
func canvasBottom(doc map[string]any) int {
	bottom := 0.0
	boxes, _ := doc["boxes"].([]any)
	for _, item := range boxes {
		box, _ := item.(map[string]any)
		blocks, _ := box["blocks"].([]any)
		bottom = max(bottom, num(box["y"])+48*float64(countBlocks(blocks)))
	}
	strokes, _ := doc["strokes"].([]any)
	for _, item := range strokes {
		stroke, _ := item.(map[string]any)
		points, _ := stroke["points"].([]any)
		for i := 1; i < len(points); i += 3 {
			bottom = max(bottom, num(points[i]))
		}
	}
	return int(min(bottom+48, maxCoord))
}

func countBlocks(blocks []any) int {
	n := 0
	for _, item := range blocks {
		n++
		if block, ok := item.(map[string]any); ok {
			children, _ := block["children"].([]any)
			n += countBlocks(children)
		}
	}
	return n
}

// marshal matches JSON.stringify: no HTML escaping, no trailing newline.
func marshal(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}
