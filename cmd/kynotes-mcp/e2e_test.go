package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Busnes-app/kynotes-server/internal/auth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	serverconfig "github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/httpapi"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/notecrypto"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busnes-app/kynotes-server/internal/teamkeys"
)

const iterations = auth.LoginIterations

// stack is a real KyNotes router with its database and blobs in one temp directory.
type stack struct {
	url, root string
	db        *sql.DB
}

func newStack(t *testing.T) stack {
	t.Helper()
	root := t.TempDir()
	s, err := storage.Open(filepath.Join(root, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := blobstore.New(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := serverconfig.Defaults()
	cfg.Server.DevInsecureCookies = true
	cfg.RateLimit.LoginPerMinute = 1000 // one test signs in more often than a person
	srv := httptest.NewServer(httpapi.NewRouter(logging.New(io.Discard, "info", "json"), cfg.Server.MaxRequestBytes, func() bool { return true }, s.DB(), blobs, cfg))
	t.Cleanup(func() { srv.Close(); s.Close() })
	return stack{srv.URL, root, s.DB()}
}

// browser is a person's KyNotes web client: an everyday account with a password-wrapped identity.
type browser struct {
	*client
	salt string
}

func (s stack) browser(t *testing.T, username, password string) browser {
	t.Helper()
	ctx := context.Background()
	id, _ := ids.Mint("usr")
	salt := base64.StdEncoding.EncodeToString([]byte(username + "-salt-0123456789")[:16])
	secret, _ := auth.DeriveAuthSecret(password, salt, iterations)
	hash, _ := auth.HashAuthSecret(secret)
	if _, err := s.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES(?,?,?,?,?,'now','now')`, id, username, hash, salt, iterations); err != nil {
		t.Fatal(err)
	}
	c := newClient(s.url, username, password)
	if err := c.login(ctx); !errors.Is(err, errNoIdentity) {
		t.Fatalf("first sign-in: %v", err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kek, _ := teamkeys.UserKEK(password, salt, iterations)
	wrapped, _ := teamkeys.SealIdentity(kek, key.Bytes(), id)
	b := browser{c, salt}
	b.stepUp(t)
	must(t, c.call(ctx, http.MethodPut, "/api/v1/me/identity", map[string]string{"publicKey": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), "wrapAlg": "aes-256-gcm", "wrappedPrivateKey": base64.StdEncoding.EncodeToString(wrapped)}, nil, false))
	must(t, c.login(ctx))
	return b
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0o700))
	return dir
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (b browser) stepUp(t *testing.T) {
	t.Helper()
	secret, _ := auth.DeriveAuthSecret(b.password, b.salt, iterations)
	must(t, b.call(context.Background(), http.MethodPost, "/api/v1/auth/step-up", map[string]string{"authSecret": secret}, nil, false))
}

func (b browser) envelope(t *testing.T, cid string, generation int64, key []byte, to *client) map[string]any {
	t.Helper()
	env, err := teamkeys.SealEnvelope(key, to.identity.PublicKey().Bytes(), cid, uint32(generation), to.identityDevice, b.identity, b.identityDevice)
	must(t, err)
	return map[string]any{"deviceId": to.identityDevice, "keyGeneration": generation, "alg": envelopeAlg, "envelope": base64.StdEncoding.EncodeToString(env)}
}

// rotate mints a new key for the members given, as an owner's browser sweep does.
func (b browser) rotate(t *testing.T, cid string, expected int64, members ...*client) []byte {
	t.Helper()
	key := randomKey()
	var envs []any
	for _, m := range members {
		envs = append(envs, b.envelope(t, cid, expected+1, key, m))
	}
	b.stepUp(t)
	must(t, b.call(context.Background(), http.MethodPost, "/api/v1/containers/"+cid+"/key-rotations", map[string]any{"expectedGeneration": expected, "envelopes": envs}, nil, false))
	return key
}

// team creates a team notebook, invites the agent with role and keys it for both.
func (b browser) team(t *testing.T, agent browser, role string) (string, []byte) {
	t.Helper()
	ctx := context.Background()
	var c struct{ ID string }
	must(t, b.call(ctx, http.MethodPost, "/api/v1/containers", map[string]string{"kind": "team"}, &c, false))
	var inv struct{ ID, Token string }
	must(t, b.call(ctx, http.MethodPost, "/api/v1/containers/"+c.ID+"/invitations", map[string]string{"inviteeId": agent.userID, "role": role}, &inv, false))
	must(t, agent.call(ctx, http.MethodPost, "/api/v1/invitations/"+inv.ID+"/accept", map[string]string{"token": inv.Token}, nil, false))
	return c.ID, b.rotate(t, c.ID, 1, b.client, agent.client)
}

func (b browser) put(t *testing.T, cid string, key []byte, generation int64, p notecrypto.Payload) string {
	t.Helper()
	var obj struct{ ID string }
	must(t, b.call(context.Background(), http.MethodPost, "/api/v1/containers/"+cid+"/objects", map[string]string{"kind": "note"}, &obj, false))
	sealed, err := notecrypto.SealObject(key, cid, obj.ID, p)
	must(t, err)
	must(t, b.saveObject(context.Background(), obj.ID, sealed, 0, generation))
	return obj.ID
}

func (b browser) open(t *testing.T, cid string, key []byte, id string) (notecrypto.Payload, int64) {
	t.Helper()
	body, version, _, err := b.readObject(context.Background(), id)
	must(t, err)
	p, err := notecrypto.OpenObject(key, cid, id, body, false)
	must(t, err)
	return p, version
}

// agentSession runs the bridge for cid and connects an MCP client to it in memory.
func agentSession(t *testing.T, s stack, password, cid string, readOnly bool, stateDir string, log io.Writer) (*bridge, *mcp.ClientSession) {
	t.Helper()
	ctx := context.Background()
	b, err := newBridge(ctx, config{server: s.url, username: "agent", password: password, notebook: cid, stateDir: stateDir, readOnly: readOnly}, log)
	must(t, err)
	t.Cleanup(b.close)
	st, ct := mcp.NewInMemoryTransports()
	ss, err := b.server().Connect(ctx, st, nil)
	must(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1"}, nil).Connect(ctx, ct, nil)
	must(t, err)
	t.Cleanup(func() { _ = cs.Close() })
	return b, cs
}

// callTool decodes a structured result into out and returns the tool error text, "" on success.
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args, out any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error %v", name, err)
	}
	if res.IsError {
		var text []string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text = append(text, tc.Text)
			}
		}
		return strings.Join(text, " ") + " "
	}
	if out != nil {
		data, _ := json.Marshal(res.StructuredContent)
		must(t, json.Unmarshal(data, out))
	}
	return ""
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	must(t, err)
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func blocknote(md string) string {
	body, _ := newPageBody(markdownBlocks(md))
	return body
}

// Secret markers: none of them may reach the server's database or blob files in plaintext.
const (
	alphaTitle = "Alpha-plaintext-title"
	alphaText  = "alpha-plaintext-body"
	gammaText  = "gamma holds the NEEDLE-plaintext"
	agentTitle = "Agent-plaintext-title"
	agentText  = "agent-plaintext-body"
	appendText = "appended-plaintext-line"
)

func TestBridgeEndToEnd(t *testing.T) {
	ctx := context.Background()
	s := newStack(t)
	owner := s.browser(t, "owner", "owner password")
	agent := s.browser(t, "agent", "agent password")
	cid, key := owner.team(t, agent, "editor")
	const gen = 2

	plans := owner.put(t, cid, key, gen, notecrypto.Payload{Type: "section", Title: "Plans", Color: "blue", Order: "i"})
	archive := owner.put(t, cid, key, gen, notecrypto.Payload{Type: "section", Title: "Archive", Color: "gray", Order: "j"})
	alpha := owner.put(t, cid, key, gen, notecrypto.Payload{Type: "page", Title: alphaTitle, Section: plans, Order: "i", Body: doc(`{"type":"heading","props":{"level":1},"content":"Goals"},{"type":"checkListItem","props":{"checked":true},"content":"` + alphaText + `"}`)})
	canvas := `{"format":"kynotes.canvas.v1","boxes":[{"id":"b","x":0,"y":300,"width":300,"blocks":[{"type":"paragraph","content":"lower"}]},{"id":"a","x":0,"y":0,"width":300,"blocks":[{"type":"paragraph","content":"upper"}]}],"strokes":[]}`
	beta := owner.put(t, cid, key, gen, notecrypto.Payload{Type: "page", Title: "Beta", Section: plans, Order: "j", Body: canvas})
	gamma := owner.put(t, cid, key, gen, notecrypto.Payload{Type: "page", Title: "Gamma", Section: archive, Order: "i", Body: blocknote(gammaText)})
	loose := owner.put(t, cid, key, gen, notecrypto.Payload{Type: "page", Title: "Loose", Body: blocknote("quick")})

	// A second notebook the agent also belongs to: never reachable through this bridge.
	otherCID, otherKey := owner.team(t, agent, "editor")
	other := owner.put(t, otherCID, otherKey, gen, notecrypto.Payload{Type: "page", Title: "Other", Body: blocknote("other")})

	open := t.TempDir()
	must(t, os.Chmod(open, 0o755))
	if _, err := newBridge(ctx, config{server: s.url, username: "agent", password: "agent password", notebook: cid, stateDir: open}, io.Discard); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("a state dir others can reach: %v", err)
	}
	stateDir := privateDir(t)
	var stderr bytes.Buffer
	b, cs := agentSession(t, s, "agent password", cid, false, stateDir, &stderr)
	if !strings.Contains(stderr.String(), "trusting the owner "+owner.userID) || !strings.Contains(stderr.String(), fingerprint(owner.identity.PublicKey().Bytes())) {
		t.Fatalf("first contact not reported: %q", stderr.String())
	}
	if got := toolNames(t, cs); !slices.Equal(got, []string{"append_to_page", "create_page", "list_pages", "read_page", "search"}) {
		t.Fatalf("tools %v", got)
	}

	var list listOut
	if msg := callTool(t, cs, "list_pages", map[string]any{}, &list); msg != "" {
		t.Fatal(msg)
	}
	want := []pageRef{{alpha, alphaTitle, "Plans", 0}, {beta, "Beta", "Plans", 0}, {gamma, "Gamma", "Archive", 0}, {loose, "Loose", "Quick Notes", 0}}
	if !slices.Equal(list.Pages, want) {
		t.Fatalf("list_pages %+v\nwant %+v", list.Pages, want)
	}

	var page readOut
	if msg := callTool(t, cs, "read_page", idIn{alpha}, &page); msg != "" || page.UntrustedText != "# Goals\n\n- [x] "+alphaText || page.Truncated || page.SectionTitle != "Plans" {
		t.Fatalf("read_page %+v %s", page, msg)
	}
	if msg := callTool(t, cs, "read_page", idIn{beta}, &page); msg != "" || page.UntrustedText != "upper\n\nlower" {
		t.Fatalf("canvas %+v %s", page, msg)
	}

	var found searchOut
	if msg := callTool(t, cs, "search", searchIn{"needle-PLAINTEXT"}, &found); msg != "" || len(found.Pages) != 1 || found.Pages[0].ID != gamma || !strings.Contains(found.Pages[0].UntrustedSnippet, "NEEDLE") {
		t.Fatalf("search %+v %s", found, msg)
	}
	if msg := callTool(t, cs, "search", searchIn{"loose"}, &found); msg != "" || len(found.Pages) != 1 || found.Pages[0].ID != loose {
		t.Fatalf("title search %+v %s", found, msg)
	}

	// The other notebook's pages are refused, though the account can read them.
	if msg := callTool(t, cs, "read_page", idIn{other}, nil); !strings.Contains(msg, "no such page") {
		t.Fatalf("other notebook read: %q", msg)
	}
	if msg := callTool(t, cs, "append_to_page", appendIn{other, "x"}, nil); !strings.Contains(msg, "no such page") {
		t.Fatalf("other notebook append: %q", msg)
	}
	if _, err := newBridge(ctx, config{server: s.url, username: "agent", password: "agent password", notebook: "cnt_0123456789abcdefghjkmnpqrs", stateDir: privateDir(t)}, io.Discard); !errors.Is(err, errNotMember) {
		t.Fatalf("bridge for a notebook the agent is not in: %v", err)
	}

	var created idOut
	if msg := callTool(t, cs, "create_page", createIn{agentTitle, agentText + "\n\n- [ ] follow up", "plans"}, &created); msg != "" {
		t.Fatal(msg)
	}
	p, _ := owner.open(t, cid, key, created.ID)
	if p.Title != agentTitle || p.Section != plans || p.Order != "k" || pageMarkdown(p.Body) != agentText+"\n\n- [ ] follow up" || !strings.Contains(p.Body, `"format":"kynotes.blocknote.v1"`) || p.Legacy == nil || len(p.Legacy) != 0 {
		t.Fatalf("created page %+v", p)
	}
	if msg := callTool(t, cs, "create_page", createIn{"x", "", "No such section"}, nil); !strings.Contains(msg, "no section") {
		t.Fatalf("unknown section: %q", msg)
	}
	if msg := callTool(t, cs, "create_page", createIn{"Quick", "", ""}, &created); msg != "" {
		t.Fatal(msg)
	}
	if p, _ := owner.open(t, cid, key, created.ID); p.Section != "" || p.Order != "i" {
		t.Fatalf("Quick Notes page %+v", p)
	}

	if msg := callTool(t, cs, "append_to_page", appendIn{alpha, appendText}, nil); msg != "" {
		t.Fatal(msg)
	}
	if p, _ := owner.open(t, cid, key, alpha); p.Title != alphaTitle || pageMarkdown(p.Body) != "# Goals\n\n- [x] "+alphaText+"\n\n"+appendText {
		t.Fatalf("appended %+v", p)
	}
	if msg := callTool(t, cs, "append_to_page", appendIn{beta, "on canvas"}, nil); msg != "" {
		t.Fatal(msg)
	}
	if p, _ := owner.open(t, cid, key, beta); pageMarkdown(p.Body) != "upper\n\nlower\n\non canvas" {
		t.Fatalf("canvas append %q", pageMarkdown(p.Body))
	}

	// A save racing another writer re-reads once; a second race refuses and leaves no conflict copy.
	race := &racer{base: http.DefaultTransport, before: func() {
		p, version := owner.open(t, cid, key, gamma)
		p.Body, _ = appendBlocks(p.Body, markdownBlocks("owner edit"))
		sealed, _ := notecrypto.SealObject(key, cid, gamma, p)
		must(t, owner.saveObject(ctx, gamma, sealed, version, gen))
	}}
	b.nb.c.hc.Transport = race
	race.left = 1
	if msg := callTool(t, cs, "append_to_page", appendIn{gamma, "agent after race"}, nil); msg != "" {
		t.Fatal(msg)
	}
	if p, _ := owner.open(t, cid, key, gamma); pageMarkdown(p.Body) != gammaText+"\n\nowner edit\n\nagent after race" {
		t.Fatalf("after one race %q", pageMarkdown(p.Body))
	}
	race.left = 2
	if msg := callTool(t, cs, "append_to_page", appendIn{gamma, "never lands"}, nil); !strings.Contains(msg, "changed while appending") {
		t.Fatalf("two races: %q", msg)
	}
	b.nb.c.hc.Transport = nil
	var unresolved int
	must(t, s.db.QueryRow(`SELECT COUNT(*) FROM conflicts WHERE resolved_at=''`).Scan(&unresolved))
	if p, _ := owner.open(t, cid, key, gamma); unresolved != 0 || strings.Contains(p.Body, "never lands") {
		t.Fatalf("open conflicts=%d body=%q", unresolved, pageMarkdown(p.Body))
	}

	// A lost session signs in again once.
	must(t, b.nb.c.call(ctx, http.MethodPost, "/api/v1/auth/logout", nil, nil, false))
	if msg := callTool(t, cs, "list_pages", map[string]any{}, &list); msg != "" || len(list.Pages) != 6 {
		t.Fatalf("after logout: %s %d", msg, len(list.Pages))
	}

	// The server and its files hold only ciphertext.
	for _, secret := range []string{alphaTitle, alphaText, "NEEDLE-plaintext", agentTitle, agentText, appendText, "agent after race", "Plans"} {
		if file := grep(t, s.root, secret); file != "" {
			t.Errorf("%q in plaintext in %s", secret, file)
		}
		if file := grep(t, stateDir, secret); file != "" {
			t.Errorf("%q in the bridge state in %s", secret, file)
		}
	}
	audit, _ := os.ReadFile(filepath.Join(stateDir, "audit.jsonl"))
	if n := strings.Count(string(audit), "\n"); n < 15 || !strings.Contains(string(audit), `"tool":"append_to_page","pages":["`+gamma+`"],"outcome":"error","code":"version_conflict"`) {
		t.Fatalf("audit (%d lines):\n%s", n, audit)
	}

	// Read-only bridges and viewers get no write tools.
	_, ro := agentSession(t, s, "agent password", cid, true, privateDir(t), io.Discard)
	viewerCID, _ := owner.team(t, agent, "viewer")
	_, viewer := agentSession(t, s, "agent password", viewerCID, false, privateDir(t), io.Discard)
	for _, cs := range []*mcp.ClientSession{ro, viewer} {
		if got := toolNames(t, cs); !slices.Equal(got, []string{"list_pages", "read_page", "search"}) {
			t.Fatalf("tools %v", got)
		}
	}

	// Removal rotates the key: the agent is refused, and nothing it held opens what is written next.
	held := b.nb.ring
	owner.stepUp(t)
	must(t, owner.call(ctx, http.MethodDelete, "/api/v1/containers/"+cid+"/members/"+agent.userID, nil, nil, false))
	var removedGen int64
	must(t, s.db.QueryRow(`SELECT key_generation FROM containers WHERE id=?`, cid).Scan(&removedGen))
	newKey := owner.rotate(t, cid, removedGen, owner.client)
	after := owner.put(t, cid, newKey, removedGen+1, notecrypto.Payload{Type: "page", Title: "After", Body: blocknote("written after removal")})
	if msg := callTool(t, cs, "list_pages", map[string]any{}, nil); !strings.Contains(msg, "not a member") {
		t.Fatalf("removed agent: %q", msg)
	}
	sealed, _, _, err := owner.readObject(ctx, after)
	must(t, err)
	for g, k := range held {
		if _, err := notecrypto.OpenObject(k, cid, after, sealed, true); err == nil {
			t.Fatalf("held key of generation %d opens content written after removal", g)
		}
	}
	if _, _, _, err := b.nb.c.readObject(ctx, after); err == nil {
		t.Fatal("removed agent read the new page's ciphertext")
	}
}

// racer runs before ahead of the next left object saves, as a person saving at the same moment.
type racer struct {
	base   http.RoundTripper
	before func()
	mu     sync.Mutex
	left   int
}

func (r *racer) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	run := req.Method == http.MethodPut && strings.HasPrefix(req.URL.Path, "/api/v1/objects/") && r.left > 0
	if run {
		r.left--
	}
	r.mu.Unlock()
	if run {
		r.before()
	}
	return r.base.RoundTrip(req)
}

// grep returns the first file under dir that holds s, "" when none does.
func grep(t *testing.T, dir, s string) string {
	t.Helper()
	found := ""
	must(t, filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte(s)) {
			found = path
		}
		return err
	}))
	return found
}

// A second bridge on the same state directory is refused while the first runs: each replaces
// trust.json whole, so the stale one would erase the newer pins and generation floors.
func TestOneBridgePerStateDirectory(t *testing.T) {
	ctx := context.Background()
	s := newStack(t)
	owner := s.browser(t, "owner", "owner password")
	agent := s.browser(t, "agent", "agent password")
	cid, _ := owner.team(t, agent, "editor")
	stateDir := privateDir(t)
	c := config{server: s.url, username: "agent", password: "agent password", notebook: cid, stateDir: stateDir}

	first, err := newBridge(ctx, c, io.Discard)
	must(t, err)
	if _, err := newBridge(ctx, c, io.Discard); err == nil || !strings.Contains(err.Error(), "another kynotes-mcp") {
		t.Fatalf("a second bridge on the same state directory: %v", err)
	}
	first.close()

	again, err := newBridge(ctx, c, io.Discard)
	must(t, err)
	defer again.close()
	if again.nb.trust.Pins[owner.userID] == "" {
		t.Fatalf("the owner's pin did not survive a restart: %+v", again.nb.trust.Pins)
	}
	if k := again.nb.trust.Containers[cid]; k == nil || k.Generation < 2 || k.Mark < 2 {
		t.Fatalf("the generation floor did not survive a restart: %+v", k)
	}
}

// sealV1 writes the pre-v2 form an older client wrote: nonce ‖ AES-256-GCM(HKDF(key, cid, label)), no AAD.
func sealV1(t *testing.T, key []byte, cid, label string, plaintext []byte) []byte {
	t.Helper()
	subkey, err := hkdf.Key(sha256.New, key, []byte(cid), label, 32)
	must(t, err)
	block, _ := aes.NewCipher(subkey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

// The bridge reads v1 pages only until it sees the migration marker, pins the marker in
// trust.json, and from then on refuses a name without it, across restarts.
func TestBridgeFollowsTheMigrationMarker(t *testing.T) {
	ctx := context.Background()
	s := newStack(t)
	owner := s.browser(t, "owner", "owner password")
	agent := s.browser(t, "agent", "agent password")
	cid, key := owner.team(t, agent, "editor")
	const gen = 2
	var obj struct{ ID string }
	must(t, owner.call(ctx, http.MethodPost, "/api/v1/containers/"+cid+"/objects", map[string]string{"kind": "note"}, &obj, false))
	must(t, owner.saveObject(ctx, obj.ID, sealV1(t, key, cid, "kynotes/object/v1", []byte(`{"type":"page","title":"Old","body":""}`)), 0, gen))
	owner.put(t, cid, key, gen, notecrypto.Payload{Type: "page", Title: "New", Body: blocknote("new"), Legacy: map[string]string{}})
	metaVersion := int64(0)
	name := func(sealed []byte) {
		var out struct{ MetaVersion int64 }
		must(t, owner.call(ctx, http.MethodPatch, "/api/v1/containers/"+cid, map[string]any{"metaCiphertext": base64.StdEncoding.EncodeToString(sealed), "baseVersion": metaVersion, "keyGeneration": gen}, &out, false))
		metaVersion = out.MetaVersion
	}
	titles := func(cs *mcp.ClientSession) (out []string, msg string) {
		var list listOut
		msg = callTool(t, cs, "list_pages", map[string]any{}, &list)
		for _, p := range list.Pages {
			out = append(out, p.Title)
		}
		slices.Sort(out) // unordered pages sort by ID, which is random within a millisecond
		return out, msg
	}

	unmarked, _ := notecrypto.SealContainerName(key, cid, "Notes", false)
	name(unmarked)
	stateDir := privateDir(t)
	b, cs := agentSession(t, s, "agent password", cid, false, stateDir, io.Discard)
	if got, msg := titles(cs); msg != "" || !slices.Equal(got, []string{"New", "Old"}) {
		t.Fatalf("before the marker: %v %s", got, msg)
	}

	marked, _ := notecrypto.SealContainerName(key, cid, "Notes", true)
	name(marked)
	if got, msg := titles(cs); msg != "" || !slices.Equal(got, []string{"New"}) {
		t.Fatalf("after the marker the v1 page must be refused: %v %s", got, msg)
	}
	if k := b.nb.trust.Containers[cid]; k == nil || k.Objects != 2 {
		t.Fatalf("marker not pinned: %+v", k)
	}
	b.close()

	// A server serving the older name again, unmarked v2 or v1, is refused, also after a restart.
	for _, older := range [][]byte{unmarked, sealV1(t, key, cid, "kynotes/container-meta/v1", []byte(`{"name":"Notes"}`))} {
		name(older)
		if _, err := newBridge(ctx, config{server: s.url, username: "agent", password: "agent password", notebook: cid, stateDir: stateDir}, io.Discard); !errors.Is(err, errOlderMeta) {
			t.Fatalf("older name after the marker: %v", err)
		}
	}
}
