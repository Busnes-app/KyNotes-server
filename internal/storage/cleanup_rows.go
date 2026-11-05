package storage

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// cleanupRowPaddingTx keeps the replacement cell from becoming larger on its
// B-tree page. A shorter record is not sufficient: crossing SQLite's overflow
// threshold can move almost a page of payload back into the leaf. Retain only
// the bounded zero padding needed for that layout, releasing whole overflow pages.
// Table names and replacement columns come exclusively from the three callers.
func cleanupRowPaddingTx(tx *sql.Tx, table, id string, changes map[string]any, minimum int) (int, error) {
	switch table {
	case "comments", "containers", "sealed_share_links":
	default:
		return 0, ErrCleanupInvariant
	}
	var page []byte
	if err := tx.QueryRow(`SELECT data FROM sqlite_dbpage('main') WHERE pgno=1`).Scan(&page); err != nil {
		return 0, err
	}
	if len(page) < 100 {
		return 0, ErrCleanupInvariant
	}
	usable := len(page) - int(page[20])
	encoding := binary.BigEndian.Uint32(page[56:60])
	rows, err := tx.Query(`SELECT * FROM `+table+` WHERE id=?`, id)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, err
		}
		return 0, sql.ErrNoRows
	}
	values, refs := make([]any, len(columns)), make([]any, len(columns))
	for i := range values {
		refs[i] = &values[i]
	}
	if err := rows.Scan(refs...); err != nil {
		return 0, err
	}
	oldSize := sqliteRecordBytes(values, encoding)
	padIndex := -1
	for i, column := range columns {
		if value, ok := changes[column]; ok {
			values[i] = value
		}
		if column == "cleanup_padding" {
			padIndex = i
		}
	}
	if padIndex < 0 {
		return 0, ErrCleanupInvariant
	}
	oldCell, oldOverflow := sqliteCellLayout(oldSize, usable)
	values[padIndex] = cleanupPaddingBytes(0)
	header, body := sqliteRecordParts(values, encoding)
	// An overflow cycle is usable-4 bytes. One cycle plus the at-most-nine-byte
	// record/header varints covers the next safe layout; the old record itself
	// remains the upper size limit. Never preserve comment-sized zero ciphertext.
	for pad := minimum; pad <= minimum+usable+18; pad++ {
		size := sqliteRecordSize(header-1+sqliteVarintBytes(12+2*pad), body+pad)
		if size > oldSize {
			break
		}
		cell, overflow := sqliteCellLayout(size, usable)
		if cell <= oldCell && overflow <= oldOverflow {
			return pad, nil
		}
	}
	return 0, fmt.Errorf("%w: no non-growing %s cleanup layout", ErrCleanupInvariant, table)
}

type cleanupPaddingBytes int

// SQLite file format, record serial types and header-length varint. Strings use
// the database encoding; counters use their signed integer representation.
func sqliteRecordBytes(values []any, encoding uint32) int {
	header, body := sqliteRecordParts(values, encoding)
	return sqliteRecordSize(header, body)
}

func sqliteRecordParts(values []any, encoding uint32) (header, body int) {
	for _, value := range values {
		serial, n := 0, 0
		switch value := value.(type) {
		case nil:
		case int64:
			switch {
			case value == 0:
				serial = 8
			case value == 1:
				serial = 9
			case value >= -128 && value <= 127:
				serial, n = 1, 1
			case value >= -32768 && value <= 32767:
				serial, n = 2, 2
			case value >= -8388608 && value <= 8388607:
				serial, n = 3, 3
			case value >= -2147483648 && value <= 2147483647:
				serial, n = 4, 4
			case value >= -140737488355328 && value <= 140737488355327:
				serial, n = 5, 6
			default:
				serial, n = 6, 8
			}
		case float64:
			serial, n = 7, 8
		case cleanupPaddingBytes:
			n = int(value)
			serial = 12 + 2*n
		case []byte:
			n = len(value)
			serial = 12 + 2*n
		case string:
			n = len(value)
			if encoding == 2 || encoding == 3 {
				n = 2 * len(utf16.Encode([]rune(value)))
			}
			serial = 13 + 2*n
		default:
			panic("unexpected SQLite value type")
		}
		header += sqliteVarintBytes(serial)
		body += n
	}
	return header, body
}

func sqliteRecordSize(header, body int) int {
	for size := 1; ; size++ {
		if sqliteVarintBytes(header+size) == size {
			return header + size + body
		}
	}
}

func sqliteVarintBytes(n int) int {
	for size := 1; size < 9; size++ {
		if uint64(n) < uint64(1)<<(7*size) {
			return size
		}
	}
	return 9
}

// Table-leaf cell bytes excluding the unchanged rowid varint, and overflow pages.
func sqliteCellLayout(payload, usable int) (int, int) {
	local, overflow := payload, 0
	if payload > usable-35 {
		minimum := (usable-12)*32/255 - 23
		local = minimum + (payload-minimum)%(usable-4)
		if local > usable-35 {
			local = minimum
		}
		overflow = (payload - local + usable - 5) / (usable - 4)
	}
	cell := sqliteVarintBytes(payload) + local
	if overflow > 0 {
		cell += 4
	}
	return cell, overflow
}
