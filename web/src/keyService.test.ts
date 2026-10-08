import "fake-indexeddb/auto";
import { bytesToHex } from "@noble/ciphers/utils.js";
import { sha256 } from "./fallbackCrypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { base64, legacyKeyRef } from "./crypto";
import type { PublicIdentity } from "./identity";
import { newContainerKey, readKeys, sealFor, writeKey, type Envelope, type KeyState, type Member } from "./keyring";
import { syncContainerKeys, type KeyAPI, type PinStore } from "./keyService";
import { isPinConfirmation, type PinChange, type PinConfirmation, type Pins } from "./pins";
import { generateIdentity } from "./teamKeys";
import { clearAllDeviceKeys, getKeyState, getPins, storeConfirmedPin, storeDeviceKey, storeKeyState, storePins, type PinsStored } from "./storage";

const cnt = `cnt_${"a".repeat(26)}`;
const user = (name: string, c: string, role: string, withIdentity = true) => {
  const id = generateIdentity();
  const userId = `usr_${c.repeat(26)}`;
  return {
    member: { userId, username: name, role } as Member,
    held: withIdentity ? { ...id, deviceId: `dev_${c.repeat(26)}` } : undefined,
    public: withIdentity ? { deviceId: `dev_${c.repeat(26)}`, publicKey: base64(id.publicKey), fingerprint: "" } as PublicIdentity : undefined,
  };
};
type User = ReturnType<typeof user>;
const conflict = () => Object.assign(new Error("conflict"), { code: "already_exists" });

/** In-memory server with the P2/P3a envelope rules that matter to the client. */
function server(users: User[], generation = 1, shared = 0) {
  const state = { generation, shared, envelopes: [] as Envelope[], members: users };
  const accept = (rows: Envelope[], at: (row: Envelope) => boolean) => {
    for (const row of rows) {
      if (!at(row) || state.envelopes.some((e) => e.deviceId === row.deviceId && e.keyGeneration === row.keyGeneration)) throw conflict();
    }
    state.envelopes.push(...rows);
  };
  const api: KeyAPI = {
    container: async () => ({ id: cnt, keyGeneration: state.generation, sharedGeneration: state.shared }),
    envelopes: async () => state.envelopes.map((row) => ({ ...row })),
    members: async () => state.members.map((entry) => entry.member),
    userIdentity: async (id) => state.members.find((entry) => entry.member.userId === id)?.public,
    stepUp: vi.fn(async () => {}),
    putEnvelopes: vi.fn(async (_cid, rows) => accept(rows, (row) => row.keyGeneration >= state.shared && row.keyGeneration <= state.generation && state.envelopes.some((e) => e.keyGeneration === row.keyGeneration))),
    rotate: vi.fn(async (_cid, expected, rows) => {
      if (expected !== state.generation) throw conflict();
      state.generation += 1;
      state.shared ||= state.generation;
      accept(rows, (row) => row.keyGeneration === state.generation);
      return { keyGeneration: state.generation };
    }),
  };
  return { state, api };
}
/** This device's store; keeps pins add-only and only accepts real confirmations, like storage.ts. */
const memoryStore = (initial: Pins = {}, known: KeyState = { mark: 0, digests: {} }, keeps = true) => {
  let pins = initial;
  let state = known;
  return {
    load: async () => pins,
    addFresh: vi.fn(async (next: Pins): Promise<PinsStored> => {
      if (!keeps) return { ok: false, conflicts: [] };
      const conflicts = Object.keys(next).filter((member) => pins[member] !== undefined && pins[member] !== next[member]);
      if (conflicts.length) return { ok: false, conflicts };
      pins = { ...next, ...pins };
      return { ok: true };
    }),
    confirm: vi.fn(async (confirmation: PinConfirmation) => { if (!isPinConfirmation(confirmation)) return false; pins = { ...pins, [confirmation.userId]: confirmation.key }; return true; }),
    loadKeyState: async () => state,
    saveKeyState: vi.fn(async (_cid: string, next: KeyState) => { state = next; return true; }),
    get: () => pins,
    known: () => state,
  } satisfies PinStore & Record<string, unknown>;
};
const as = (u: User, canWrap = true) => ({ userId: u.member.userId, identity: u.held, canWrap });
const never = () => false;

describe("syncContainerKeys", () => {
  it("mints once every member has an identity, and every member opens the same key", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { state, api } = server([owner, editor]);
    const store = memoryStore();
    const result = await syncContainerKeys(api, cnt, as(owner), store, never);
    expect(result.minted).toBe(true);
    expect(result.container).toEqual({ id: cnt, keyGeneration: 2, sharedGeneration: 2 });
    expect(store.known().mark).toBe(2);
    const editorStore = memoryStore();
    const theirs = await syncContainerKeys(api, cnt, as(editor), editorStore, never);
    expect(theirs.ring.get(2)).toEqual(result.ring.get(2));
    expect(theirs.fresh.map((member) => member.username)).toEqual(["owner"]);
    expect(editorStore.get()).toEqual({ [owner.member.userId]: owner.public!.publicKey });
    expect(store.get()).toEqual({ [editor.member.userId]: editor.public!.publicKey });
    expect(state.envelopes).toHaveLength(2);
  });

  it("does not share a never-shared container while a member has no identity", async () => {
    const owner = user("owner", "b", "owner"), sso = user("sso", "c", "editor", false);
    const { api } = server([owner, sso]);
    const result = await syncContainerKeys(api, cnt, as(owner), memoryStore(), never);
    expect(result.plan).toEqual({ kind: "blocked", waitingFor: ["sso"] });
    expect(api.rotate).not.toHaveBeenCalled();
    expect(api.stepUp).not.toHaveBeenCalled();
  });

  it("re-mints after a removal and wraps history for a newcomer", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor"), newcomer = user("new", "d", "editor");
    const { state, api } = server([owner, editor]);
    const store = memoryStore();
    await syncContainerKeys(api, cnt, as(owner), store, never);
    state.generation += 1; // removal of someone else: generation 3 has no envelopes
    const second = await syncContainerKeys(api, cnt, as(owner), store, never);
    expect(second.container.keyGeneration).toBe(4);
    state.members.push(newcomer);
    await syncContainerKeys(api, cnt, as(owner), store, never);
    const theirs = await syncContainerKeys(api, cnt, as(newcomer), memoryStore(), never);
    expect([...theirs.ring.keys()].sort()).toEqual([2, 4]);
  });

  it("stops at a changed colleague key unless the user confirms it", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    const store = memoryStore({ [editor.member.userId]: base64(new Uint8Array(32).fill(9)) });
    const refused = await syncContainerKeys(api, cnt, as(owner), store, never);
    expect(refused.plan).toEqual({ kind: "untrusted", members: ["editor"] });
    expect(api.rotate).not.toHaveBeenCalled();
    const confirm = vi.fn(() => true);
    const accepted = await syncContainerKeys(api, cnt, as(owner), store, confirm);
    expect(confirm).toHaveBeenCalledOnce();
    expect(accepted.minted).toBe(true);
    expect(store.get()[editor.member.userId]).toBe(editor.public!.publicKey);
  });

  it("re-reads and re-plans once when another steward rotated first", async () => {
    const owner = user("owner", "b", "owner"), admin = user("admin", "c", "admin");
    const { state, api } = server([owner, admin]);
    const rotate = api.rotate;
    let raced = false;
    // The admin's browser mints between the owner's read and the owner's rotation.
    const racing: KeyAPI = { ...api, rotate: async (cid, expected, rows) => {
      if (!raced) { raced = true; await syncContainerKeys(api, cnt, as(admin), memoryStore(), never); }
      return rotate(cid, expected, rows);
    } };
    const result = await syncContainerKeys(racing, cnt, as(owner), memoryStore(), never);
    expect(result.minted).toBe(false);
    expect(result.container.keyGeneration).toBe(2);
    expect(result.ring.size).toBe(1);
    expect(state.envelopes.filter((row) => row.keyGeneration === 2)).toHaveLength(2); // one key, no split
    // The admin was first pinned by the attempt that lost the race; it is still surfaced.
    expect(result.fresh.map((member) => member.username)).toEqual(["admin"]);
  });

  it("only reads keys for a member, or a session that may not wrap", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    await syncContainerKeys(api, cnt, as(editor), memoryStore(), never);
    await syncContainerKeys(api, cnt, as(owner, false), memoryStore(), never);
    expect(api.stepUp).not.toHaveBeenCalled();
    expect(api.rotate).not.toHaveBeenCalled();
  });

  it("gives a reader no key from a sender who is neither a steward nor pinned", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor"), reader = user("reader", "d", "viewer");
    const { state, api } = server([owner, editor, reader], 1, 1);
    const me = { ...editor.held!, userId: editor.member.userId };
    const target = { ...reader.member, identity: reader.public };
    state.envelopes.push(sealFor(target, cnt, 1, newContainerKey(), me, {}).envelope);
    const store = memoryStore();
    const result = await syncContainerKeys(api, cnt, as(reader), store, never);
    expect(result.ring.size).toBe(0);
    expect(store.addFresh).not.toHaveBeenCalled();
    expect(store.get()).toEqual({});
  });

  it("persists nothing and writes nothing when a changed key is declined", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    const stale = { [editor.member.userId]: base64(new Uint8Array(32).fill(9)) };
    const store = memoryStore(stale);
    const confirm = vi.fn(() => false);
    const result = await syncContainerKeys(api, cnt, as(owner), store, confirm);
    expect(confirm).toHaveBeenCalledWith([expect.objectContaining({ pinned: stale[editor.member.userId] })]);
    expect(result.plan).toEqual({ kind: "untrusted", members: ["editor"] });
    expect(store.get()).toEqual(stale);
    expect(store.addFresh).not.toHaveBeenCalled();
    expect(store.confirm).not.toHaveBeenCalled();
    expect(api.stepUp).not.toHaveBeenCalled();
    expect(api.putEnvelopes).not.toHaveBeenCalled();
    expect(api.rotate).not.toHaveBeenCalled();
  });

  it("does not wrap when this device cannot keep a first-seen pin", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    const result = await syncContainerKeys(api, cnt, as(owner), memoryStore({}, undefined, false), never);
    expect(result.plan).toEqual({ kind: "pins-unsaved" });
    expect(api.stepUp).not.toHaveBeenCalled();
    expect(api.rotate).not.toHaveBeenCalled();
    await syncContainerKeys(api, cnt, as(owner), memoryStore(), never);
    const reader = await syncContainerKeys(api, cnt, as(editor), memoryStore({}, undefined, false), never);
    expect(reader.plan).toEqual({ kind: "pins-unsaved" });
  });

  it("surfaces a key conflict and never wraps that generation", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor"), newcomer = user("new", "d", "editor");
    const { state, api } = server([owner, editor]);
    const first = await syncContainerKeys(api, cnt, as(owner), memoryStore(), never);
    // A reader that remembers a different key for generation 2 refuses the envelope.
    const remembered = memoryStore({}, { mark: 2, digests: { 2: "00".repeat(32) } });
    const reader = await syncContainerKeys(api, cnt, as(editor), remembered, never);
    expect(reader.conflicts).toEqual([2]);
    expect(reader.ring.has(2)).toBe(false);
    expect(remembered.known().digests[2]).toBe("00".repeat(32));
    // A steward holding a different key for generation 2 in this session does not wrap it.
    state.members.push(newcomer);
    const odd = new Map([[2, newContainerKey()]]);
    const steward = await syncContainerKeys(api, cnt, as(owner), memoryStore(), never, odd);
    expect(steward.conflicts).toEqual([2]);
    expect(steward.ring.get(2)).not.toEqual(first.ring.get(2));
    expect(steward.plan).toEqual({ kind: "idle" });
    expect(api.putEnvelopes).not.toHaveBeenCalled();
  });

  it("refuses a changed steward-sender key until the reader confirms it", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    await syncContainerKeys(api, cnt, as(owner), memoryStore(), never);
    const stale = { [owner.member.userId]: base64(new Uint8Array(32).fill(9)) };
    const store = memoryStore(stale);
    const declined = await syncContainerKeys(api, cnt, as(editor), store, never);
    expect(declined.plan).toEqual({ kind: "untrusted", members: ["owner"] });
    expect(declined.changed.map((change) => change.member.username)).toEqual(["owner"]);
    expect(declined.ring.size).toBe(0);
    expect(store.get()).toEqual(stale);
    const accepted = await syncContainerKeys(api, cnt, as(editor), store, () => true);
    expect(store.confirm).toHaveBeenCalledOnce();
    expect(isPinConfirmation(store.confirm.mock.calls[0][0])).toBe(true);
    expect(accepted.ring.has(2)).toBe(true);
    expect(store.get()[owner.member.userId]).toBe(owner.public!.publicKey);
  });

  it("asks again when a confirmation reveals another changed recipient", async () => {
    const owner = user("owner", "b", "owner"), admin = user("admin", "c", "admin"), editor = user("editor", "d", "editor");
    const { state, api } = server([owner, admin]);
    await syncContainerKeys(api, cnt, as(admin), memoryStore(), never);
    state.members.push(editor);
    const nine = base64(new Uint8Array(32).fill(9));
    const store = memoryStore({ [admin.member.userId]: nine, [editor.member.userId]: nine });
    const confirm = vi.fn((_changes: PinChange[]) => true);
    const result = await syncContainerKeys(api, cnt, as(owner), store, confirm);
    expect(confirm.mock.calls.map(([changes]) => changes.map((change) => change.member.username))).toEqual([["admin"], ["editor"]]);
    expect(result.plan.kind).toBe("wrap");
    expect(state.envelopes.some((row) => row.deviceId === editor.public!.deviceId)).toBe(true);
  });

  it("only an explicit true confirms a changed key", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    const store = memoryStore({ [editor.member.userId]: base64(new Uint8Array(32).fill(9)) });
    const result = await syncContainerKeys(api, cnt, as(owner), store, (() => "yes") as unknown as () => boolean);
    expect(result.plan).toEqual({ kind: "untrusted", members: ["editor"] });
    expect(store.confirm).not.toHaveBeenCalled();
  });

  it("keeps key memory when the step-up fails, and reports an unsaved one", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor"), newcomer = user("new", "d", "editor");
    const { state, api } = server([owner, editor]);
    const minted = await syncContainerKeys(api, cnt, as(owner), memoryStore(), never);
    expect(minted.keyStateSaved).toBe(true);
    state.members.push(newcomer);
    const store = memoryStore();
    const failing: KeyAPI = { ...api, stepUp: async () => { throw new Error("cancelled"); } };
    await expect(syncContainerKeys(failing, cnt, as(owner), store, never)).rejects.toThrow("cancelled");
    expect(store.known().mark).toBe(2);
    expect(Object.keys(store.known().digests)).toEqual(["2"]);
    const unkept = { ...memoryStore(), saveKeyState: async () => false };
    expect((await syncContainerKeys(api, cnt, as(editor), unkept, never)).keyStateSaved).toBe(false);
  });
});

vi.stubGlobal("localStorage", { getItem: () => null, removeItem: () => undefined });

/** The browser's real store (IndexedDB vault record), as main.tsx wires it. */
const vault = (u: User): PinStore => ({
  load: () => getPins("me", u.member.userId),
  addFresh: (pins) => storePins("me", u.member.userId, pins),
  confirm: (confirmation) => storeConfirmedPin("me", u.member.userId, confirmation),
  loadKeyState: (id) => getKeyState("me", u.member.userId, id),
  saveKeyState: (id, state) => storeKeyState("me", u.member.userId, id, state),
});
const login = legacyKeyRef("a".repeat(64));

describe("sharing-state rollback", () => {
  beforeEach(async () => { await clearAllDeviceKeys(); await storeDeviceKey("me", "a".repeat(64)); });

  it("never writes with the login key once this device has seen the notebook shared, even after a reload", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { state, api } = server([owner, editor]);
    const ownerStore = memoryStore();
    await syncContainerKeys(api, cnt, as(owner), ownerStore, never);
    const seen = await syncContainerKeys(api, cnt, as(editor), vault(editor), never);
    expect(writeKey(seen.container, seen.ring, login, seen.known)).toEqual({ key: seen.ring.get(2), generation: 2 });
    // The server now reports the notebook as never shared (legacy metadata).
    state.shared = 0;
    for (const who of [editor, owner]) {
      const store = who === editor ? vault(editor) : ownerStore;
      const after = await syncContainerKeys(api, cnt, as(who), store, never);
      expect(after.plan).toEqual({ kind: "rollback" });
      expect(writeKey(after.container, after.ring, login, after.known)).toBeUndefined();
      expect(readKeys(after.container, after.ring, login, 2, after.known)).not.toContain(login);
    }
    // A steward is not tricked into minting a "first" key or uploading anything.
    expect(api.rotate).toHaveBeenCalledOnce();
    expect(api.putEnvelopes).not.toHaveBeenCalled();
    // Reload: only what storage kept.
    const known = await getKeyState("me", editor.member.userId, cnt);
    expect(known).toMatchObject({ shared: 2, generation: 2 });
    expect(writeKey({ id: cnt, keyGeneration: 2, sharedGeneration: 0 }, seen.ring, login, known)).toBeUndefined();
  });

  it("refuses a lowered key generation, persisted across a reload", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { state, api } = server([owner, editor]);
    await syncContainerKeys(api, cnt, as(owner), memoryStore(), never);
    state.generation = 3; // a removal: this device sees generation 3
    await syncContainerKeys(api, cnt, as(editor), vault(editor), never);
    state.generation = 2; // a colluding server rolls back to a generation a removed member holds
    const after = await syncContainerKeys(api, cnt, as(editor), vault(editor), never);
    expect(after.plan).toEqual({ kind: "rollback" });
    expect(after.ring.get(2)).toBeDefined();
    expect(writeKey(after.container, after.ring, login, after.known)).toBeUndefined();
    expect(writeKey(after.container, after.ring, login, await getKeyState("me", editor.member.userId, cnt))).toBeUndefined();
  });
});

describe("conflicting first pins", () => {
  beforeEach(async () => { await clearAllDeviceKeys(); await storeDeviceKey("me", "a".repeat(64)); });

  it("lets only one of two overlapping passes pin a recipient; the other uploads nothing", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor"), substitute = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    // Both passes read the (empty) pins before either stores, then see different keys for the editor.
    let arrived = 0;
    let release!: () => void;
    const together = new Promise<void>((resolve) => { release = resolve; });
    const passApi = (identity: PublicIdentity): KeyAPI => ({
      ...api,
      userIdentity: async (id) => (id === editor.member.userId ? identity : api.userIdentity(id)),
      members: async (id) => { arrived += 1; if (arrived === 2) release(); await together; return api.members(id); },
    });
    const results = await Promise.all([editor.public!, substitute.public!].map((identity) => syncContainerKeys(passApi(identity), cnt, as(owner), vault(owner), never)));
    const losers = results.filter((result) => !result.minted);
    expect(results.filter((result) => result.minted)).toHaveLength(1);
    expect(losers).toHaveLength(1);
    expect(losers[0].plan).toEqual({ kind: "untrusted", members: ["editor"] });
    expect(api.rotate).toHaveBeenCalledOnce();
    expect(api.putEnvelopes).not.toHaveBeenCalled();
    // What was uploaded is sealed for the pin that won.
    const pinned = (await getPins("me", owner.member.userId))[editor.member.userId];
    const sent = vi.mocked(api.rotate).mock.calls[0][2];
    expect(sent.map((row) => row.deviceId)).toContain(editor.public!.deviceId);
    expect([editor.public!.publicKey, substitute.public!.publicKey]).toContain(pinned);
  });

  it("aborts before upload when storage already holds a different pin than the one just sealed for", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    const other = base64(new Uint8Array(32).fill(5));
    const store: PinStore = {
      ...vault(owner),
      // Another pass stores its pin between this pass's read and its sealFor.
      load: async () => { const pins = await getPins("me", owner.member.userId); await storePins("me", owner.member.userId, { [editor.member.userId]: other }); return pins; },
    };
    const result = await syncContainerKeys(api, cnt, as(owner), store, never);
    expect(result.plan).toEqual({ kind: "untrusted", members: ["editor"] });
    expect(api.stepUp).not.toHaveBeenCalled();
    expect(api.rotate).not.toHaveBeenCalled();
    expect((await getPins("me", owner.member.userId))[editor.member.userId]).toBe(other);
    // The next pass re-reads the pins and goes through the changed-key confirmation.
    const confirm = vi.fn(() => false);
    expect((await syncContainerKeys(api, cnt, as(owner), vault(owner), confirm)).plan).toEqual({ kind: "untrusted", members: ["editor"] });
    expect(confirm).toHaveBeenCalledOnce();
  });
});

describe("keys from a refused first-contact sender", () => {
  beforeEach(async () => { await clearAllDeviceKeys(); await storeDeviceKey("me", "a".repeat(64)); });

  it("are never returned, remembered or accepted later when a concurrent pass pinned another key", async () => {
    const owner = user("owner", "b", "owner"), forged = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    expect(forged.public!.deviceId).toBe(owner.public!.deviceId); // the server swaps only the key
    const view = (sender: User, key: Uint8Array): KeyAPI => {
      const envelope = sealFor({ ...editor.member, identity: editor.public }, cnt, 2, key, { ...sender.held!, userId: owner.member.userId }, {}).envelope;
      return {
        container: async () => ({ id: cnt, keyGeneration: 2, sharedGeneration: 2 }),
        envelopes: async () => [envelope],
        members: async () => [owner.member, editor.member],
        userIdentity: async (id) => (id === owner.member.userId ? sender.public : editor.public),
        stepUp: vi.fn(async () => {}), putEnvelopes: vi.fn(async () => {}), rotate: vi.fn(async () => ({ keyGeneration: 2 })),
      };
    };
    const real = newContainerKey(), substituted = newContainerKey();
    const views = [view(owner, real), view(forged, substituted)];
    // Both passes read the empty pins before either stores its first-contact pin.
    let arrived = 0;
    let release!: () => void;
    const together = new Promise<void>((resolve) => { release = resolve; });
    const racing = views.map((api): KeyAPI => ({ ...api, members: async (id) => { arrived += 1; if (arrived === 2) release(); await together; return api.members(id); } }));
    const results = await Promise.all(racing.map((api) => syncContainerKeys(api, cnt, as(editor), vault(editor), never)));
    const loser = results.findIndex((result) => result.plan.kind === "untrusted");
    expect(loser).toBeGreaterThanOrEqual(0);
    const winner = 1 - loser;
    const keys = [real, substituted];
    expect(results[winner].ring.get(2)).toEqual(keys[winner]);
    // The loser returns no key for the generation, so nothing could be written with it.
    expect(results[loser].ring.get(2)).toBeUndefined();
    expect(writeKey(results[loser].container, results[loser].ring, login, results[loser].known)).toBeUndefined();
    // Only the winner's key digest is remembered.
    const stored = await getKeyState("me", editor.member.userId, cnt);
    expect(stored.digests[2]).toBe(bytesToHex(sha256(keys[winner])));
    // After a reload, a fresh pass that sees the losing key again still refuses it.
    const again = await syncContainerKeys(views[loser], cnt, as(editor), vault(editor), never);
    expect(again.plan).toEqual({ kind: "untrusted", members: ["owner"] });
    expect(again.ring.get(2)).toBeUndefined();
    expect((await getKeyState("me", editor.member.userId, cnt)).digests[2]).toBe(bytesToHex(sha256(keys[winner])));
  });
});
