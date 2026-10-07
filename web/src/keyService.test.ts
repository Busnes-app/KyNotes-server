import { describe, expect, it, vi } from "vitest";
import { base64 } from "./crypto";
import type { PublicIdentity } from "./identity";
import { newContainerKey, sealFor, type Envelope, type KeyState, type Member } from "./keyring";
import { syncContainerKeys, type KeyAPI, type PinStore } from "./keyService";
import { isPinConfirmation, type PinConfirmation, type Pins } from "./pins";
import { generateIdentity } from "./teamKeys";

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
    addFresh: vi.fn(async (next: Pins) => { if (keeps) pins = { ...next, ...pins }; return keeps; }),
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
});
