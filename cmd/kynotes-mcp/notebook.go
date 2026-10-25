package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/Busnes-app/kynotes-server/internal/notecrypto"
)

// notebook is the one container the bridge may touch, and the keys it accepted for it.
type notebook struct {
	c         *client
	id        string
	trustPath string
	trust     *trustState
	log       io.Writer // first-contact pins are reported here

	role                   string
	keyGeneration, shared  int64 // as reported, raised to the stored floor
	migrated               bool  // the notebook's migration marker was seen: v1 objects are refused
	ring                   map[int64][]byte
	cache                  map[string]cached // object ID → payload at a change sequence
	sections, pages, other []entry           // filled by index
}

type cached struct {
	seq     int64
	payload notecrypto.Payload
	ok      bool // false: unreadable or not a page/section
}

type entry struct {
	id string
	notecrypto.Payload
}

type container struct {
	ID               string `json:"id"`
	KeyGeneration    int64  `json:"keyGeneration"`
	SharedGeneration int64  `json:"sharedGeneration"`
	MetaCiphertext   string `json:"metaCiphertext"`
}

var (
	errNotMember = errors.New("the agent account is not a member of this notebook (removed, or a wrong --notebook)")
	errOlderMeta = errors.New("the server serves this notebook's name from before its encryption upgrade, which this bridge has seen (possible rollback); refusing")
)

// refresh re-reads the notebook's key state, members and envelopes and opens the keys this
// identity accepts. Nothing is used before the raised floor and new pins are stored.
func (n *notebook) refresh(ctx context.Context) error {
	var list []container
	if err := n.c.call(ctx, http.MethodGet, "/api/v1/containers", nil, &list, true); err != nil {
		return err
	}
	i := slices.IndexFunc(list, func(c container) bool { return c.ID == n.id })
	if i < 0 {
		return errNotMember
	}
	reported := list[i]
	known := n.trust.Containers[n.id]
	if known == nil {
		known = &keyState{}
		n.trust.Containers[n.id] = known
	}
	if err := known.raise(reported); err != nil {
		return err
	}
	if err := n.trust.save(n.trustPath); err != nil {
		return err
	}
	n.keyGeneration, n.shared = reported.KeyGeneration, reported.SharedGeneration

	var members []member
	if err := n.c.call(ctx, http.MethodGet, "/api/v1/containers/"+n.id+"/members", nil, &members, true); err != nil {
		return err
	}
	n.role = ""
	for i := range members {
		m := &members[i]
		if m.UserID == n.c.userID {
			n.role = m.Role
			continue
		}
		if !isSteward(m.Role) || !userID.MatchString(m.UserID) {
			continue // only stewards' keys are ever trusted, and only under a well-formed ID
		}
		var id publicIdentity
		err := n.c.call(ctx, http.MethodGet, "/api/v1/users/"+url.PathEscape(m.UserID)+"/identity", nil, &id, true)
		var api *apiError
		if errors.As(err, &api) && api.status == http.StatusNotFound {
			continue
		}
		if err != nil {
			return err
		}
		m.identity = &id
	}
	var rows []envelopeRow
	if err := n.c.call(ctx, http.MethodGet, "/api/v1/containers/"+n.id+"/envelopes", nil, &rows, true); err != nil {
		return err
	}
	me := self{userID: n.c.userID, deviceID: n.c.identityDevice, key: n.c.identity}
	opened, err := openKeyring(n.id, rows, me, members, n.trust.Pins, *known)
	if err != nil {
		return err
	}
	for _, m := range opened.fresh {
		pub, _ := base64.StdEncoding.DecodeString(m.identity.PublicKey)
		fmt.Fprintf(n.log, "kynotes-mcp: trusting the %s %s · %q on first contact, key fingerprint %s\n", clean(m.Role), clean(m.UserID), clean(m.Username), fingerprint(pub))
		n.trust.Pins[m.UserID] = m.identity.PublicKey
	}
	*known = opened.known
	// The migration marker (a v2 name carrying objects: 2) is pinned in trust.json. After it, a
	// name without it (v1, which then fails to open, or v2 unmarked) is a rollback. Without the
	// name's key nothing is decided.
	if meta, _ := base64.StdEncoding.DecodeString(reported.MetaCiphertext); len(meta) > 0 {
		if key := readKey(opened.ring, n.shared, n.keyGeneration); key != nil {
			if _, migrated, _ := notecrypto.OpenContainerName(key, n.id, meta, known.Objects < 2); migrated {
				known.Objects = 2
			} else if known.Objects == 2 {
				return errOlderMeta
			}
		}
	}
	if err := n.trust.save(n.trustPath); err != nil {
		return err
	}
	if known.Objects == 2 && !n.migrated {
		n.cache = nil // pages read as v1 before the marker are read again
	}
	n.ring, n.migrated = opened.ring, known.Objects == 2
	return nil
}

func (n *notebook) canWrite() bool {
	return n.role == "owner" || n.role == "admin" || n.role == "editor"
}

// writeKey is keyring.ts writeKey: the current generation's key, or none.
func (n *notebook) writeKey() ([]byte, int64, error) {
	if key := n.ring[n.keyGeneration]; n.shared > 0 && key != nil {
		return key, n.keyGeneration, nil
	}
	return nil, 0, errors.New("this bridge has no key for the notebook's current generation yet; an owner or admin must open the notebook in KyNotes so their browser shares it")
}

// index lists every page and section, reading only objects changed since the last call.
func (n *notebook) index(ctx context.Context) error {
	if n.cache == nil {
		n.cache = map[string]cached{}
	}
	live := map[string]bool{}
	for cursor := "0"; ; {
		var page struct {
			Changes []struct {
				ID        string `json:"id"`
				Kind      string `json:"kind"`
				ChangeSeq int64  `json:"changeSeq"`
				Deleted   bool   `json:"deleted"`
			} `json:"changes"`
			NextCursor string `json:"nextCursor"`
			HasMore    bool   `json:"hasMore"`
		}
		if err := n.c.call(ctx, http.MethodGet, "/api/v1/containers/"+n.id+"/changes?limit=1000&since="+url.QueryEscape(cursor), nil, &page, true); err != nil {
			return err
		}
		for _, ch := range page.Changes {
			if ch.Kind != "object" || ch.Deleted {
				continue
			}
			live[ch.ID] = true
			if c, ok := n.cache[ch.ID]; ok && c.seq == ch.ChangeSeq {
				continue
			}
			p, err := n.open(ctx, ch.ID)
			var api *apiError
			if errors.As(err, &api) && api.status == http.StatusNotFound {
				err = errUnreadable // created, never saved
			}
			if err != nil && !errors.Is(err, errUnreadable) {
				return err
			}
			n.cache[ch.ID] = cached{seq: ch.ChangeSeq, payload: p.Payload, ok: err == nil}
		}
		if !page.HasMore || page.NextCursor == cursor {
			break
		}
		cursor = page.NextCursor
	}
	n.sections, n.pages = nil, nil
	for id, c := range n.cache {
		switch {
		case !live[id]:
			delete(n.cache, id)
		case !c.ok:
		case c.payload.Type == "section":
			n.sections = append(n.sections, entry{id, c.payload})
		case c.payload.Type == "page":
			n.pages = append(n.pages, entry{id, c.payload})
		}
	}
	slices.SortFunc(n.sections, compareOrdered)
	return nil
}

var errUnreadable = errors.New("this page cannot be opened with the keys this bridge accepted")

type opened struct {
	notecrypto.Payload
	version int64
}

// open reads and decrypts one object's current version.
func (n *notebook) open(ctx context.Context, id string) (opened, error) {
	body, version, generation, err := n.c.readObject(ctx, id)
	if err != nil {
		return opened{}, err
	}
	key := readKey(n.ring, n.shared, generation)
	if key == nil {
		return opened{}, errUnreadable
	}
	p, err := notecrypto.OpenObject(key, n.id, id, body, !n.migrated)
	if err != nil {
		return opened{}, errUnreadable
	}
	return opened{p, version}, nil
}

// compareOrdered is pages.ts compareOrdered: ordered before unordered, then by ID.
func compareOrdered(a, b entry) int {
	if a.Order != "" && b.Order != "" && a.Order != b.Order {
		return strings.Compare(a.Order, b.Order)
	}
	if (a.Order != "") != (b.Order != "") {
		if a.Order != "" {
			return -1
		}
		return 1
	}
	return cmp.Compare(a.id, b.id)
}

// inSection is pages.ts pagesInSection; section "" is Quick Notes, which also holds pages whose
// section no longer exists.
func (n *notebook) inSection(section string) []entry {
	var out []entry
	for _, p := range n.pages {
		known := slices.ContainsFunc(n.sections, func(s entry) bool { return s.id == p.Section })
		if section == "" && !known || section != "" && p.Section == section {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, compareOrdered)
	return out
}

// ordered is every page in notebook order: sections by order, Quick Notes last.
func (n *notebook) ordered() []entry {
	var out []entry
	for _, s := range n.sections {
		out = append(out, n.inSection(s.id)...)
	}
	return append(out, n.inSection("")...)
}

func (n *notebook) sectionTitle(id string) string {
	for _, s := range n.sections {
		if s.id == id {
			return s.Title
		}
	}
	return "Quick Notes"
}

// page is a page of this notebook from the last index, or an error for anything else.
func (n *notebook) page(id string) (entry, error) {
	for _, p := range n.pages {
		if p.id == id {
			return p, nil
		}
	}
	return entry{}, errNoPage
}

var errNoPage = errors.New("no such page in this notebook; run list_pages")

// keyAfter is order.ts keyBetween(last, null): the order key after last ("" when none is ordered).
func keyAfter(last string) (string, error) {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if last == "" {
		return "i", nil
	}
	out := ""
	for i := 0; ; i++ {
		low := 0
		if i < len(last) {
			low = strings.IndexByte(digits, last[i])
		}
		if low+1 < len(digits) {
			if key := out + string(digits[low+1]); len(key) <= 512 {
				return key, nil
			}
			return "", errors.New("order key limit reached; reorder this section in KyNotes")
		}
		out += string(digits[low])
	}
}

// endOrder is pages.ts endOrder.
func endOrder(list []entry) (string, error) {
	last := ""
	for _, e := range list {
		if e.Order > last {
			last = e.Order
		}
	}
	return keyAfter(last)
}

// create makes a page at the end of section ("" for Quick Notes) and returns its ID.
func (n *notebook) create(ctx context.Context, title, body, section string) (string, error) {
	key, generation, err := n.writeKey()
	if err != nil {
		return "", err
	}
	order, err := endOrder(n.inSection(section))
	if err != nil {
		return "", err
	}
	var obj struct {
		ID string `json:"id"`
	}
	if err := n.c.call(ctx, http.MethodPost, "/api/v1/containers/"+n.id+"/objects", map[string]string{"kind": "note"}, &obj, true); err != nil {
		return "", err
	}
	sealed, err := notecrypto.SealObject(key, n.id, obj.ID, notecrypto.Payload{Type: "page", Title: title, Body: body, Section: section, Order: order, Legacy: map[string]string{}})
	if err != nil {
		return "", err
	}
	if err := n.c.saveObject(ctx, obj.ID, sealed, 0, generation); err != nil {
		return "", err
	}
	return obj.ID, nil
}

var errConflict = errors.New("the page changed while appending, twice; nothing was appended. Read it again and retry")

// appendTo adds blocks to the latest version of a page. A version conflict re-reads once.
func (n *notebook) appendTo(ctx context.Context, id string, blocks []any) error {
	key, generation, err := n.writeKey()
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		p, err := n.open(ctx, id)
		if err != nil {
			return err
		}
		if p.Type != "page" {
			return errNoPage
		}
		if p.Body, err = appendBlocks(p.Body, blocks); err != nil {
			return err
		}
		sealed, err := notecrypto.SealObject(key, n.id, id, p.Payload)
		if err != nil {
			return err
		}
		err = n.c.saveObject(ctx, id, sealed, p.version, generation)
		var api *apiError
		if !errors.As(err, &api) || api.code != "version_conflict" {
			return err
		}
		// The server kept the rejected text as a conflict; resolve it so no browser turns it into a copy.
		if api.conflictID != "" {
			_ = n.c.call(ctx, http.MethodPost, "/api/v1/conflicts/"+url.PathEscape(api.conflictID)+"/resolve", nil, nil, true)
		}
	}
	return errConflict
}
