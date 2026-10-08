import "fake-indexeddb/auto";
import { bytesToHex } from "@noble/ciphers/utils.js";
import { sha256 } from "./fallbackCrypto";
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { base64, legacyKeyRef } from "./crypto";
import type { PublicIdentity } from "./identity";
import { memberKeyStatus, mergeFloor, newContainerKey, openKeyring, readKeys, sealFor, writeKey, type Envelope, type InvitationEnvelope, type KeyFloor, type Keyring, type KeyState, type Member, type ReportedContainer } from "./keyring";
import { inviteWithKeys, syncContainerKeys, type Caller, type InviteAPI, type InviteKeys, type InviteTarget, type KeyAPI, type PinStore } from "./keyService";
import { displayName, isPinConfirmation, type PinChange, type PinConfirmation, type Pins } from "./pins";
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
const shown = (u: User) => displayName(u.member.username, u.member.userId);
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
    expect(result.plan).toEqual({ kind: "blocked", waitingFor: [shown(sso)] });
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
    expect(refused.plan).toEqual({ kind: "untrusted", members: [shown(editor)] });
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
    expect(result.plan).toEqual({ kind: "untrusted", members: [shown(editor)] });
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
    expect(declined.plan).toEqual({ kind: "untrusted", members: [shown(owner)] });
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
    expect(result.plan).toEqual({ kind: "untrusted", members: [shown(editor)] });
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
    expect(losers[0].plan).toEqual({ kind: "untrusted", members: [shown(editor)] });
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
    expect(result.plan).toEqual({ kind: "untrusted", members: [shown(editor)] });
    expect(api.stepUp).not.toHaveBeenCalled();
    expect(api.rotate).not.toHaveBeenCalled();
    expect((await getPins("me", owner.member.userId))[editor.member.userId]).toBe(other);
    // The next pass re-reads the pins and goes through the changed-key confirmation.
    const confirm = vi.fn(() => false);
    expect((await syncContainerKeys(api, cnt, as(owner), vault(owner), confirm)).plan).toEqual({ kind: "untrusted", members: [shown(editor)] });
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
    expect(again.plan).toEqual({ kind: "untrusted", members: [shown(owner)] });
    expect(again.ring.get(2)).toBeUndefined();
    expect((await getKeyState("me", editor.member.userId, cnt)).digests[2]).toBe(bytesToHex(sha256(keys[winner])));
  });
});

describe("a pass that stops on an unstored first-contact pin", () => {
  it("reports key memory unsaved when no record keeps it", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    await syncContainerKeys(api, cnt, as(owner), memoryStore(), never);
    const unkept = { ...memoryStore({}, undefined, false), saveKeyState: vi.fn(async () => false) };
    const result = await syncContainerKeys(api, cnt, as(editor), unkept, never);
    expect(result.plan).toEqual({ kind: "pins-unsaved" });
    expect(result.keyStateSaved).toBe(false);
  });

  it("returns held keys only when they match the stored digests", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    const minted = await syncContainerKeys(api, cnt, as(owner), memoryStore(), never);
    const real = bytesToHex(sha256(minted.ring.get(2)!));
    const store = memoryStore({}, { mark: 2, digests: { 2: real } }, false);
    const result = await syncContainerKeys(api, cnt, as(editor), store, never, new Map([[2, newContainerKey()]]));
    expect(result.plan).toEqual({ kind: "pins-unsaved" });
    expect(result.ring.has(2)).toBe(false);
    expect(result.conflicts).toEqual([2]);
  });
});

describe("a pass that fails after raising the floor", () => {
  it("never lowers a floor it merges", () => {
    expect(mergeFloor({ shared: 2, generation: 3 }, { shared: 1, generation: 4 })).toMatchObject({ shared: 2, generation: 4 });
    expect(mergeFloor(undefined, { shared: 2, generation: 2 })).toMatchObject({ shared: 2, generation: 2 });
  });

  it.each<[string, { id: string; keyGeneration: number; sharedGeneration: number }, KeyState]>([
    ["a rotation", { id: cnt, keyGeneration: 2, sharedGeneration: 2 }, { mark: 2, digests: {}, shared: 2, generation: 2 }],
    ["first sharing", { id: cnt, keyGeneration: 1, sharedGeneration: 0 }, { mark: 0, digests: {} }],
  ])("hands the raised floor to memory before the envelope fetch fails (%s)", async (_name, old, prior) => {
    const editor = user("editor", "c", "editor");
    const raised = { id: cnt, keyGeneration: 3, sharedGeneration: old.sharedGeneration || 3 };
    const api: KeyAPI = {
      container: async () => raised,
      envelopes: async () => { throw new Error("offline"); },
      members: async () => [editor.member], userIdentity: async () => editor.public,
      stepUp: vi.fn(async () => {}), putEnvelopes: vi.fn(async () => {}), rotate: vi.fn(async () => ({ keyGeneration: 3 })),
    };
    let memory: KeyFloor = { shared: prior.shared, generation: prior.generation };
    const ring = new Map([[2, newContainerKey()]]);
    expect(writeKey(old, ring, login, memory)).toBeDefined();
    await expect(syncContainerKeys(api, cnt, as(editor), memoryStore({}, prior), never, ring, (id, floor) => { expect(id).toBe(cnt); memory = mergeFloor(memory, floor); })).rejects.toThrow("offline");
    expect(memory).toMatchObject({ generation: 3, shared: raised.sharedGeneration });
    // The open notebook still holds the old container: nothing may be written under its key or the login key.
    expect(writeKey(old, ring, login, memory)).toBeUndefined();
  });
});

describe("a mint the server accepted", () => {
  const afterMint = (api: KeyAPI): KeyAPI => ({ ...api, envelopes: async (id) => { if (vi.mocked(api.rotate).mock.calls.length) throw new Error("offline"); return api.envelopes(id); } });
  const check = async (api: KeyAPI, store: ReturnType<typeof memoryStore>, owner: User, old: { id: string; keyGeneration: number; sharedGeneration: number }, generation: number, shared: number) => {
    let memory: KeyFloor = { shared: store.known().shared, generation: store.known().generation };
    const result = await syncContainerKeys(afterMint(api), cnt, as(owner), store, never, undefined, (_id, floor) => { memory = mergeFloor(memory, floor); });
    expect(result.minted).toBe(true);
    expect(store.known()).toMatchObject({ shared, generation, mark: generation });
    expect(memory).toMatchObject({ shared, generation });
    expect(writeKey(old, result.ring, login, memory)).toBeUndefined();
    // The minted key is this browser's own and stays usable without a re-fetch.
    expect(writeKey(result.container, result.ring, login, memory)?.generation).toBe(generation);
  };

  it("raises and publishes the floor with no post-mint fetch (first sharing)", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { api } = server([owner, editor]);
    await check(api, memoryStore(), owner, { id: cnt, keyGeneration: 1, sharedGeneration: 0 }, 2, 2);
  });

  it("raises and publishes the floor with no post-mint fetch (re-mint after a removal)", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor");
    const { state, api } = server([owner, editor]);
    const store = memoryStore();
    await syncContainerKeys(api, cnt, as(owner), store, never);
    state.generation += 1;
    vi.mocked(api.rotate).mockClear();
    await check(api, store, owner, { id: cnt, keyGeneration: 3, sharedGeneration: 2 }, 4, 2);
  });
});

describe("key status from a sync", () => {
  it("reports members and the envelopes after its own writes", async () => {
    const owner = user("owner", "b", "owner"), editor = user("editor", "c", "editor"), newcomer = user("newcomer", "d", "editor");
    const { state, api } = server([owner, editor]);
    const ownerStore = memoryStore();
    const minted = await syncContainerKeys(api, cnt, as(owner), ownerStore, never);
    expect(memberKeyStatus(minted.container, minted.members, minted.envelopes)).toEqual({ [owner.member.userId]: "has-key", [editor.member.userId]: "has-key" });
    state.members.push(newcomer);
    const seen = await syncContainerKeys(api, cnt, as(editor), memoryStore(), never);
    expect(memberKeyStatus(seen.container, seen.members, seen.envelopes)[newcomer.member.userId]).toBe("waiting");
    const wrapped = await syncContainerKeys(api, cnt, as(owner), ownerStore, never);
    expect(wrapped.plan.kind).toBe("wrap");
    expect(memberKeyStatus(wrapped.container, wrapped.members, wrapped.envelopes)[newcomer.member.userId]).toBe("has-key");
  });
});

describe("inviteWithKeys", () => {
  const team: ReportedContainer = { id: cnt, kind: "team", keyGeneration: 2, sharedGeneration: 2 };
  const teamKey = newContainerKey();
  const target: InviteTarget = { container: team, ring: new Map([[2, teamKey]]) as Keyring, floor: {} };
  // This device accepted teamKey at generation 2 (its stored digest).
  const known: KeyState = { mark: 2, digests: { 2: bytesToHex(sha256(teamKey)) } };
  const keyed = (pins: Pins = {}, keeps = true) => memoryStore(pins, known, keeps);
  const owner = user("owner", "e", "owner"), invitee = user("invitee", "f", "editor");
  const invited: Member = { ...invitee.member, role: "editor" };
  const inviteAPI = (visible = true, refuseKeys = false) => {
    const calls: Array<{ envelopes: InvitationEnvelope[] }> = [];
    const api: InviteAPI = {
      userIdentity: async (id) => (visible && id === invitee.member.userId ? invitee.public : undefined),
      stepUp: vi.fn(async () => {}),
      invite: vi.fn(async (_cid: string, _id: string, _role: string, envelopes: InvitationEnvelope[]) => {
        if (refuseKeys && envelopes.length) throw conflict();
        calls.push({ envelopes });
        return { id: `inv_${"g".repeat(26)}`, token: "t".repeat(43), expiresAt: "2026-10-08T00:00:00Z" };
      }),
    };
    return { api, calls };
  };

  it("seals the team's current key for a visible invitee, pinned and stepped up first", async () => {
    const { api, calls } = inviteAPI();
    const store = keyed();
    const result = await inviteWithKeys(api, target, invited, as(owner), store, never);
    expect(result.keys).toBe("sealed");
    expect(result.recipient?.identity?.publicKey).toBe(invitee.public!.publicKey);
    expect(calls[0].envelopes.map((row) => [row.containerId, row.keyGeneration, row.deviceId])).toEqual([[team.id, 2, invitee.held!.deviceId]]);
    expect(store.get()).toEqual({ [invitee.member.userId]: invitee.public!.publicKey });
    const sent = (api.invite as Mock).mock.invocationCallOrder[0];
    expect(store.addFresh.mock.invocationCallOrder[0]).toBeLessThan(sent);
    expect((api.stepUp as Mock).mock.invocationCallOrder[0]).toBeLessThan(sent);
    // The invitee opens the key as one a current steward sent.
    const steward = { ...owner.member, identity: { deviceId: owner.public!.deviceId, publicKey: owner.public!.publicKey } };
    const opened = openKeyring({ containerID: team.id, envelopes: calls[0].envelopes, me: { ...invitee.held!, userId: invitee.member.userId }, members: [steward], pins: {}, known: { mark: 0, digests: {} } });
    expect(opened.ring.get(team.keyGeneration)).toEqual(teamKey);
  });

  it("invites without keys when it cannot see the invitee, cannot wrap, or holds no current key", async () => {
    const cases: Array<[boolean, Caller, typeof target, InviteKeys]> = [
      [false, as(owner), target, "no-identity"],
      [true, as(owner, false), target, "cannot-wrap"],
      [true, { userId: owner.member.userId, canWrap: true }, target, "cannot-wrap"],
      [true, as(owner), { container: team, ring: new Map([[1, teamKey]]), floor: {} }, "no-keys"],
      [true, as(owner), { container: { ...team, keyGeneration: 1, sharedGeneration: 0 }, ring: new Map([[1, teamKey]]), floor: {} }, "no-keys"],
      // The tab has not loaded this notebook's floor yet.
      [true, as(owner), { ...target, floor: undefined }, "no-keys"],
      // The held key is not the one this device accepted for the generation, or none was recorded.
      [true, as(owner), { ...target, ring: new Map([[2, newContainerKey()]]) }, "no-keys"],
    ];
    for (const [visible, caller, given, keys] of cases) {
      const { api, calls } = inviteAPI(visible);
      expect((await inviteWithKeys(api, given, invited, caller, keyed(), never)).keys).toBe(keys);
      expect(calls).toEqual([{ envelopes: [] }]);
      expect(api.stepUp).not.toHaveBeenCalled();
    }
  });

  it("sends no keys for a team this device saw at a later sharing state, or saw shared and now reported personal", async () => {
    const cases: Array<[ReportedContainer, KeyFloor]> = [
      [team, { shared: 2, generation: 3 }], // the server rolled the generation back
      [{ ...team, kind: "workbook" }, { shared: 2, generation: 2 }], // relabelled personal, no teamId
    ];
    for (const [container, floor] of cases) {
      const { api, calls } = inviteAPI();
      expect((await inviteWithKeys(api, { container, ring: target.ring, floor: {} }, invited, as(owner), memoryStore({}, { ...known, ...floor }), never)).keys).toBe("rollback");
      expect(calls).toEqual([{ envelopes: [] }]);
      expect(api.stepUp).not.toHaveBeenCalled();
    }
  });

  it("also honours this tab's in-memory floor when storage lags behind it", async () => {
    const { api, calls } = inviteAPI();
    // The stored floor never caught up (a failed save); the tab saw generation 3.
    expect((await inviteWithKeys(api, { ...target, floor: { shared: 2, generation: 3 } }, invited, as(owner), keyed(), never)).keys).toBe("rollback");
    expect(calls).toEqual([{ envelopes: [] }]);
    expect(api.stepUp).not.toHaveBeenCalled();
  });

  it("sends nothing when the step-up fails", async () => {
    const { api, calls } = inviteAPI();
    (api.stepUp as Mock).mockRejectedValueOnce(new Error("step-up refused"));
    await expect(inviteWithKeys(api, target, invited, as(owner), keyed(), never)).rejects.toThrow("step-up refused");
    expect(calls).toEqual([]);
  });

  it("asks before sealing for a changed invitee key; a decline sends no keys", async () => {
    const stale = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
    const store = keyed({ [invitee.member.userId]: stale });
    const declined = inviteAPI();
    const ask = vi.fn(() => false);
    expect((await inviteWithKeys(declined.api, target, invited, as(owner), store, ask)).keys).toBe("untrusted");
    expect(ask).toHaveBeenCalledWith([{ member: expect.objectContaining({ userId: invitee.member.userId }), pinned: stale }]);
    expect(declined.calls).toEqual([{ envelopes: [] }]);
    expect(store.get()[invitee.member.userId]).toBe(stale);
    const confirmed = inviteAPI();
    expect((await inviteWithKeys(confirmed.api, target, invited, as(owner), store, () => true)).keys).toBe("sealed");
    expect(store.confirm).toHaveBeenCalledTimes(1);
    expect(store.get()[invitee.member.userId]).toBe(invitee.public!.publicKey);
    expect(confirmed.calls[0].envelopes).toHaveLength(1);
  });

  it("never sends keys whose recipient pin this device could not keep", async () => {
    const { api, calls } = inviteAPI();
    expect((await inviteWithKeys(api, target, invited, as(owner), keyed({}, false), never)).keys).toBe("pins-unsaved");
    expect(calls).toEqual([{ envelopes: [] }]);
    expect(api.stepUp).not.toHaveBeenCalled();
  });

  it("sends no keys when another pass pinned a different key for the invitee first", async () => {
    const { api, calls } = inviteAPI();
    // storePins compares in its own transaction: the first-seen pin lost to a concurrent pass.
    const store = { ...keyed(), addFresh: vi.fn(async (): Promise<PinsStored> => ({ ok: false, conflicts: [invitee.member.userId] })) };
    expect((await inviteWithKeys(api, target, invited, as(owner), store, never)).keys).toBe("untrusted");
    expect(calls).toEqual([{ envelopes: [] }]);
    expect(api.stepUp).not.toHaveBeenCalled();
  });

  it("falls back to an invitation without keys when a generation moved meanwhile", async () => {
    const { api, calls } = inviteAPI(true, true);
    expect((await inviteWithKeys(api, target, invited, as(owner), keyed(), never)).keys).toBe("moved");
    expect(calls).toEqual([{ envelopes: [] }]);
  });

  it("invites without keys, and says so, when the invitee's key is malformed or the server refuses it", async () => {
    const malformed = inviteAPI();
    malformed.api.userIdentity = async () => ({ ...invitee.public!, publicKey: "AAAA" });
    expect((await inviteWithKeys(malformed.api, target, invited, as(owner), keyed(), never)).keys).toBe("invalid-identity");
    expect(malformed.calls).toEqual([{ envelopes: [] }]);
    expect(malformed.api.stepUp).not.toHaveBeenCalled();
    // The invitee's device changed between the lookup and the insert: the server answers invalid_request.
    const refused = inviteAPI();
    const invite = refused.api.invite;
    refused.api.invite = vi.fn(async (cid: string, id: string, role: string, envelopes: InvitationEnvelope[]) => {
      if (envelopes.length) throw Object.assign(new Error("bad device"), { code: "invalid_request" });
      return invite(cid, id, role, envelopes);
    });
    expect((await inviteWithKeys(refused.api, target, invited, as(owner), keyed(), never)).keys).toBe("invalid-identity");
    expect(refused.calls).toEqual([{ envelopes: [] }]);
  });

  it("proposes only the invitee's pin, so an unrelated colleague's pin never blocks it", async () => {
    const { api } = inviteAPI();
    const colleague = user("colleague", "h", "editor");
    const store = keyed({ [colleague.member.userId]: colleague.public!.publicKey });
    expect((await inviteWithKeys(api, target, invited, as(owner), store, never)).keys).toBe("sealed");
    expect(store.addFresh).toHaveBeenCalledWith({ [invitee.member.userId]: invitee.public!.publicKey });
  });
});
