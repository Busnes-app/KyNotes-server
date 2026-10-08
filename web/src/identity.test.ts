import { describe, expect, it, vi } from "vitest";
import { bytesToHex } from "@noble/ciphers/utils.js";
import { base64, type LoginKeys } from "./crypto";
import { unfinishedReset, currentCopy, DEVICE_ONLY_WRAP, recoverable, ensureIdentity, identityStatus, openIdentity, rewrapIdentity, settlePasswordIdentity, settleSSOIdentity, type HeldIdentity, type IdentityAPI, type IdentityRecord, type IdentityStore, type IdentityUpload } from "./identity";
import { generateIdentity, wrapIdentity } from "./teamKeys";

const userID = "usr_0123456789abcdefghjkmnpqrs";
const deviceId = "dev_00000000000000000000000000";
/** ensureIdentity for flows where an identity must result. */
const ensure = async (...args: Parameters<typeof ensureIdentity>) => {
  const result = await ensureIdentity(...args);
  if (typeof result === "string") throw new Error(result);
  return result;
};
const keys = (fill: number): LoginKeys => ({ authSecret: fill.toString(16).padStart(2, "0").repeat(32), userKEK: new Uint8Array(32).fill(fill) });

// Mirrors the server: the wrapped key only in step-up/login bodies, GET public only, PUT create-only.
function fakeServer(adminKnown = false) {
  let stored: IdentityRecord | undefined;
  const uploads: IdentityUpload[] = [];
  const api = {
    myIdentity: vi.fn(async () => stored && { deviceId: stored.deviceId, publicKey: stored.publicKey, fingerprint: stored.fingerprint }),
    stepUp: vi.fn(async (_authSecret: string) => stored),
    putMyIdentity: vi.fn(async (input: IdentityUpload) => {
      if (stored) throw Object.assign(new Error("identity exists"), { code: "identity_exists" });
      if (adminKnown) throw Object.assign(new Error("password change required"), { code: "password_change_required" });
      uploads.push(input);
      stored = { ...input, deviceId, fingerprint: "f" };
      return { deviceId };
    }),
  } satisfies IdentityAPI;
  return { api, uploads, record: () => stored!, set: (r: IdentityRecord) => { stored = r; }, ownPasswordChange: () => { adminKnown = false; } };
}

describe("identity lifecycle", () => {
  it("creates once on first sign-in after a step-up and uploads only wrapped material", async () => {
    const server = fakeServer();
    const k = keys(1);
    const identity = await ensure(server.api, userID, k, undefined);
    expect(server.api.stepUp).toHaveBeenCalledWith(k.authSecret);
    expect(server.api.stepUp.mock.invocationCallOrder[0]).toBeLessThan(server.api.putMyIdentity.mock.invocationCallOrder[0]);
    expect(server.uploads).toHaveLength(1);
    expect(identity.deviceId).toBe(deviceId);
    const body = JSON.stringify(server.uploads[0]);
    for (const secret of [identity.privateKey, k.userKEK]) {
      expect(body).not.toContain(bytesToHex(secret));
      expect(body).not.toContain(base64(secret));
    }
    expect(body).not.toContain(k.authSecret);
  });

  it("opens the login copy in a second browser profile without a step-up or upload", async () => {
    const server = fakeServer();
    const first = await ensure(server.api, userID, keys(1), undefined);
    server.api.stepUp.mockClear();
    const second = await ensure(server.api, userID, keys(1), server.record());
    expect(bytesToHex(second.privateKey)).toBe(bytesToHex(first.privateKey));
    expect(server.uploads).toHaveLength(1);
    expect(server.api.stepUp).not.toHaveBeenCalled();
  });

  it("adopts an identity created between login and step-up", async () => {
    const server = fakeServer();
    const first = await ensure(server.api, userID, keys(1), undefined);
    const second = await ensure(server.api, userID, keys(1), undefined); // login body predates the other tab's PUT
    expect(bytesToHex(second.privateKey)).toBe(bytesToHex(first.privateKey));
    expect(server.uploads).toHaveLength(1);
  });

  it("adopts the winner when another tab's PUT lands first (409)", async () => {
    const server = fakeServer();
    const first = await ensure(server.api, userID, keys(1), undefined);
    server.api.stepUp.mockResolvedValueOnce(undefined); // this tab's step-up ran before the other tab's PUT
    const second = await ensure(server.api, userID, keys(1), undefined);
    expect(bytesToHex(second.privateKey)).toBe(bytesToHex(first.privateKey));
    expect(second.deviceId).toBe(deviceId);
    expect(server.uploads).toHaveLength(1);
  });

  it("never replaces an identity it cannot open", async () => {
    const server = fakeServer();
    await ensureIdentity(server.api, userID, keys(1), undefined);
    await expect(ensureIdentity(server.api, userID, keys(2), server.record())).rejects.toThrow();
    await expect(ensureIdentity(server.api, userID, keys(2), undefined)).rejects.toThrow();
    expect(server.api.putMyIdentity).toHaveBeenCalledTimes(1);
  });

  it("refuses a server-substituted public key or another user's binding", async () => {
    const server = fakeServer();
    await ensureIdentity(server.api, userID, keys(1), undefined);
    const record = server.record();
    expect(() => openIdentity({ ...record, publicKey: base64(new Uint8Array(32).fill(9)) }, keys(1).userKEK, userID)).toThrow("identity public key mismatch");
    expect(() => openIdentity(record, keys(1).userKEK, "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz")).toThrow();
  });
});

describe("admin-known password", () => {
  it("skips creation until the user's own password change, then wraps under the new password", async () => {
    const server = fakeServer(true);
    expect(await ensureIdentity(server.api, userID, keys(1), undefined)).toBe("admin-password");
    expect(server.uploads).toHaveLength(0);
    expect(await rewrapIdentity(server.api, userID, keys(1), keys(2), undefined)).toBeUndefined();
    server.ownPasswordChange();
    const created = await ensure(server.api, userID, keys(2), undefined);
    expect(server.api.stepUp).toHaveBeenLastCalledWith(keys(2).authSecret);
    expect(bytesToHex(openIdentity(server.record(), keys(2).userKEK, userID).privateKey)).toBe(bytesToHex(created.privateKey));
    expect(() => openIdentity(server.record(), keys(1).userKEK, userID)).toThrow();
  });
});

describe("password change re-wrap", () => {
  it("sends nothing when no identity exists", async () => {
    const server = fakeServer();
    expect(await rewrapIdentity(server.api, userID, keys(1), keys(2), undefined)).toBeUndefined();
    expect(server.api.stepUp).not.toHaveBeenCalled();
  });

  it("re-wraps the same key, bound to the identity device ID", async () => {
    const server = fakeServer();
    const original = await ensure(server.api, userID, keys(1), undefined);
    const payload = (await rewrapIdentity(server.api, userID, keys(1), keys(2), undefined))!;
    expect(payload.identityDeviceId).toBe(deviceId);
    expect(JSON.stringify(payload)).not.toContain(base64(original.privateKey));
    server.set({ ...server.record(), wrappedPrivateKey: payload.wrappedIdentityKey });
    expect(bytesToHex(openIdentity(server.record(), keys(2).userKEK, userID).privateKey)).toBe(bytesToHex(original.privateKey));
    expect(() => openIdentity(server.record(), keys(1).userKEK, userID)).toThrow();
  });

  it("falls back to the vault copy when step-up withholds the wrapped key (SSO session)", async () => {
    const server = fakeServer();
    const original = await ensure(server.api, userID, keys(1), undefined);
    server.api.stepUp.mockResolvedValue(undefined);
    const payload = (await rewrapIdentity(server.api, userID, keys(1), keys(2), original))!;
    expect(bytesToHex(openIdentity({ ...server.record(), wrappedPrivateKey: payload.wrappedIdentityKey }, keys(2).userKEK, userID).privateKey)).toBe(bytesToHex(original.privateKey));
  });

  it("refuses a stale vault copy rather than sending a wrap the server cannot bind", async () => {
    const server = fakeServer();
    const original = await ensure(server.api, userID, keys(1), undefined);
    server.api.stepUp.mockResolvedValue(undefined);
    await expect(rewrapIdentity(server.api, userID, keys(1), keys(2), { ...original, deviceId: "dev_11111111111111111111111111" })).rejects.toThrow();
    await expect(rewrapIdentity(server.api, userID, keys(1), keys(2), undefined)).rejects.toThrow();
  });
});

const dev = `dev_${"d".repeat(26)}`;
const heldOf = (deviceId = dev): HeldIdentity => ({ ...generateIdentity(), deviceId });
const publicOf = (held: HeldIdentity, deviceId = held.deviceId) => ({ deviceId, publicKey: base64(held.publicKey), fingerprint: "" });
/** A vault in memory that records the order of saves; expected makes a save a compare-and-swap, like storage.ts. */
function vault(initial?: HeldIdentity, keeps = true) {
  let stored = initial;
  const saves: HeldIdentity[] = [];
  const store: IdentityStore = {
    load: async () => stored,
    save: async (identity, expected) => {
      saves.push(identity);
      if (expected !== undefined && (expected === null ? stored !== undefined : !stored || base64(stored.publicKey) !== base64(expected.publicKey))) return false;
      if (keeps) stored = identity;
      return keeps;
    },
  };
  return { store, saves, get: () => stored };
}

describe("device-only identities", () => {
  it("are never unlocked or re-wrapped by a password", async () => {
    const api = { myIdentity: vi.fn(async () => ({ deviceId: dev, publicKey: base64(generateIdentity().publicKey), fingerprint: "", wrapAlg: DEVICE_ONLY_WRAP })), putMyIdentity: vi.fn(), stepUp: vi.fn() };
    const record = { deviceId: dev, publicKey: "", fingerprint: "", wrapAlg: DEVICE_ONLY_WRAP, wrappedPrivateKey: "" };
    expect(await ensureIdentity(api, userID, keys(1), record)).toBe("device-only");
    expect(api.putMyIdentity).not.toHaveBeenCalled();
    expect(await rewrapIdentity(api, userID, keys(1), keys(2), undefined)).toBeUndefined();
    expect(api.stepUp).not.toHaveBeenCalled();
  });
});

describe("settlePasswordIdentity", () => {
  it("keeps the server's identity, compare-and-swap against the copy read first", async () => {
    const server = fakeServer();
    const v = vault();
    expect(await settlePasswordIdentity(server.api, v.store, userID, keys(1), undefined)).toBe(true);
    expect(base64(v.get()!.publicKey)).toBe(server.record().publicKey);
  });

  it("reports a create the server refused for an administrator-set password, and only that", async () => {
    expect(await settlePasswordIdentity(fakeServer(true).api, vault().store, userID, keys(1), undefined)).toBe("admin-password");
    expect(await settlePasswordIdentity(fakeServer().api, vault().store, userID, keys(1), undefined)).toBe(true);
  });

  it("calls a device-only identity device-only, never admin-password (M2)", async () => {
    const server = fakeServer();
    server.set({ deviceId: dev, publicKey: base64(generateIdentity().publicKey), fingerprint: "", wrapAlg: DEVICE_ONLY_WRAP, wrappedPrivateKey: "" });
    const v = vault();
    expect(await settlePasswordIdentity(server.api, v.store, userID, keys(1), undefined)).toBe("device-only");
    expect(await settlePasswordIdentity(server.api, v.store, userID, keys(1), server.record())).toBe("device-only");
    expect(v.saves).toHaveLength(0);
  });

  it("never overwrites a key another tab kept while it was signing in", async () => {
    const server = fakeServer();
    await ensure(server.api, userID, keys(1), undefined);
    const v = vault();
    const other = heldOf();
    // Another tab (a link, an SSO set-up) keeps a key between this run's read and its write.
    server.api.stepUp.mockImplementationOnce(async () => { await v.store.save(other, null); return server.record(); });
    expect(await settlePasswordIdentity(server.api, v.store, userID, keys(1), undefined)).toBe(false);
    expect(v.get()).toBe(other);
  });
});

describe("settleSSOIdentity", () => {
  it("keeps the new key on this browser before the server learns it", async () => {
    const v = vault();
    const order: string[] = [];
    const api = { myIdentity: async () => undefined, putDeviceOnlyIdentity: vi.fn(async (publicKey: string) => { order.push(`put ${publicKey}`); return { deviceId: dev }; }) };
    const saving = v.store.save;
    v.store.save = async (identity) => { order.push(`save ${identity.deviceId || "pending"}`); return saving(identity); };
    const settled = await settleSSOIdentity(api, v.store);
    expect(settled.kind).toBe("held");
    expect(order).toEqual(["save pending", `put ${base64(v.saves[0].publicKey)}`, `save ${dev}`]);
    expect(v.get()!.deviceId).toBe(dev);
  });

  it("creates nothing when this browser cannot keep it, or cannot read its vault", async () => {
    const api = { myIdentity: async () => undefined, putDeviceOnlyIdentity: vi.fn(async () => ({ deviceId: dev })) };
    expect((await settleSSOIdentity(api, vault(undefined, false).store)).kind).toBe("unsaved");
    await expect(settleSSOIdentity(api, { load: async () => { throw new Error("blocked"); }, save: async () => true })).rejects.toThrow("blocked");
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
  });

  it("finishes an identity an interrupted run created", async () => {
    const pending = heldOf("");
    const v = vault(pending);
    const api = { myIdentity: async () => publicOf(pending, dev), putDeviceOnlyIdentity: vi.fn() };
    expect(await settleSSOIdentity(api, v.store)).toEqual({ kind: "held", identity: { ...pending, deviceId: dev } });
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
  });

  it("links rather than creates when another browser holds the account's identity", async () => {
    const api = { myIdentity: async () => publicOf(heldOf()), putDeviceOnlyIdentity: vi.fn() };
    expect((await settleSSOIdentity(api, vault().store)).kind).toBe("link");
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
  });

  it("never adopts the server's device ID for a different key this browser holds", async () => {
    for (const mine of [heldOf(), heldOf("")]) {
      const v = vault(mine);
      const api = { myIdentity: async () => publicOf(heldOf()), putDeviceOnlyIdentity: vi.fn() };
      expect(await settleSSOIdentity(api, v.store)).toEqual({ kind: "link" });
      expect(v.get()).toBe(mine);
      expect(v.saves).toEqual([]);
    }
  });

  it("never replaces an identity this browser holds unless asked", async () => {
    const mine = heldOf();
    const v = vault(mine);
    const api = { myIdentity: async () => undefined, putDeviceOnlyIdentity: vi.fn(async () => ({ deviceId: `dev_${"e".repeat(26)}` })) };
    expect((await settleSSOIdentity(api, v.store)).kind).toBe("orphaned");
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
    const replaced = await settleSSOIdentity(api, v.store, true);
    expect(replaced.kind).toBe("held");
    expect(base64(v.get()!.publicKey)).not.toBe(base64(mine.publicKey));
  });

  it("never overwrites a key another tab kept after this run read the vault", async () => {
    const theirs = heldOf();
    const v = vault();
    let loads = 0;
    // This run reads an empty vault; the other tab then finishes its identity before this run writes.
    const store: IdentityStore = { load: async () => (loads++ === 0 ? undefined : v.get()), save: v.store.save };
    await v.store.save(theirs);
    const api = { myIdentity: vi.fn(async () => (loads > 1 ? publicOf(theirs) : undefined)), putDeviceOnlyIdentity: vi.fn() };
    expect(await settleSSOIdentity(api, store)).toEqual({ kind: "held", identity: theirs });
    expect(v.get()).toBe(theirs);
    expect(api.putDeviceOnlyIdentity).not.toHaveBeenCalled();
  });

  it("re-reads the vault before sending this browser to link", async () => {
    const mine = heldOf();
    const v = vault();
    let loads = 0;
    // The first read predates another tab of this browser finishing the identity.
    const store: IdentityStore = { load: async () => (loads++ === 0 ? undefined : v.get()), save: v.store.save };
    await v.store.save(mine);
    const api = { myIdentity: async () => publicOf(mine), putDeviceOnlyIdentity: vi.fn() };
    expect(await settleSSOIdentity(api, store)).toEqual({ kind: "held", identity: mine });
  });

  it("adopts on a second identity_exists when the server lists the key the vault holds", async () => {
    const theirs = heldOf("");
    const v = vault();
    let loads = 0;
    let live: ReturnType<typeof publicOf> | undefined;
    const store: IdentityStore = { load: async () => (loads++ === 0 ? undefined : v.get()), save: v.store.save };
    await v.store.save(theirs); // the other tab's pending key, kept after this run's first read
    const api = {
      myIdentity: async () => live,
      // The other tab's PUT of the same key lands first.
      putDeviceOnlyIdentity: vi.fn(async (_publicKey: string): Promise<{ deviceId: string }> => { live = publicOf(theirs, dev); throw Object.assign(new Error("exists"), { code: "identity_exists" }); }),
    };
    expect(await settleSSOIdentity(api, store)).toEqual({ kind: "held", identity: { ...theirs, deviceId: dev } });
    expect(v.get()).toEqual({ ...theirs, deviceId: dev });
  });

  it("links when another browser's identity lands before this one", async () => {
    const v = vault();
    let live: ReturnType<typeof publicOf> | undefined;
    const api = {
      myIdentity: async () => live,
      putDeviceOnlyIdentity: vi.fn(async (_publicKey: string): Promise<{ deviceId: string }> => { live = publicOf(heldOf()); throw Object.assign(new Error("exists"), { code: "identity_exists" }); }),
    };
    expect(await settleSSOIdentity(api, v.store)).toEqual({ kind: "link" });
    expect(api.putDeviceOnlyIdentity).toHaveBeenCalledTimes(1);
  });

  it("is not held when the vault stops keeping the key before the final save", async () => {
    let stored: HeldIdentity | undefined;
    let saves = 0;
    // "Forget this device" in another tab deletes the record between the pending and final saves.
    const store: IdentityStore = { load: async () => stored, save: async (identity) => { if (++saves > 1) { stored = undefined; return false; } stored = identity; return true; } };
    const api = { myIdentity: async () => undefined, putDeviceOnlyIdentity: vi.fn(async () => ({ deviceId: dev })) };
    expect(await settleSSOIdentity(api, store)).toEqual({ kind: "unsaved" });
  });

  it("adopts the identity another tab created meanwhile", async () => {
    const v = vault();
    let live: ReturnType<typeof publicOf> | undefined;
    const api = {
      myIdentity: async () => live,
      putDeviceOnlyIdentity: vi.fn(async () => { live = publicOf(v.get()!, dev); throw Object.assign(new Error("exists"), { code: "identity_exists" }); }),
    };
    expect((await settleSSOIdentity(api, v.store)).kind).toBe("held");
  });

  it("leaves exactly one identity when two tabs race to create it, held by the winner", async () => {
    // One shared vault and server; each tab reads an empty vault before either writes.
    const v = vault();
    let live: ReturnType<typeof publicOf> | undefined;
    let reads = 0;
    let release!: () => void;
    const bothRead = new Promise<void>((resolve) => { release = resolve; });
    const store: IdentityStore = { load: async () => { const seen = v.get(); if (++reads === 2) release(); if (reads <= 2) await bothRead; return seen; }, save: v.store.save };
    const api = {
      myIdentity: async () => live,
      putDeviceOnlyIdentity: vi.fn(async (publicKey: string) => {
        if (live) throw Object.assign(new Error("exists"), { code: "identity_exists" });
        live = { deviceId: dev, publicKey, fingerprint: "" };
        return { deviceId: dev };
      }),
    };
    const [a, b] = await Promise.all([settleSSOIdentity(api, store), settleSSOIdentity(api, store)]);
    // Every key the server was offered is the one key the vault keeps.
    expect(new Set(api.putDeviceOnlyIdentity.mock.calls.map(([key]) => key))).toEqual(new Set([live!.publicKey]));
    expect(a).toEqual({ kind: "held", identity: v.get() });
    expect(b).toEqual({ kind: "held", identity: v.get() });
    expect(base64(v.get()!.publicKey)).toBe(live!.publicKey);
    expect(v.get()!.deviceId).toBe(dev);
  });

  it.each(["step_up_pending", "sso_sign_in_required", "password_change_required"])("surfaces %s unchanged and keeps the pending key for the next run", async (code) => {
    const v = vault();
    const refusal = Object.assign(new Error(code), { code });
    const api = { myIdentity: async () => undefined, putDeviceOnlyIdentity: vi.fn(async (_publicKey: string): Promise<{ deviceId: string }> => { throw refusal; }) };
    await expect(settleSSOIdentity(api, v.store)).rejects.toBe(refusal);
    const pending = v.get()!;
    expect(pending.deviceId).toBe("");
    api.putDeviceOnlyIdentity.mockResolvedValueOnce({ deviceId: dev });
    expect(await settleSSOIdentity(api, v.store)).toEqual({ kind: "held", identity: { ...pending, deviceId: dev } });
    expect(api.putDeviceOnlyIdentity.mock.calls.map(([key]) => key)).toEqual([base64(pending.publicKey), base64(pending.publicKey)]);
  });
});

describe("which identity this browser may use", () => {
  it("is the vault copy only while the server lists it, or cannot be asked", () => {
    const mine = heldOf();
    expect(identityStatus(mine, publicOf(mine))).toBe("held");
    expect(identityStatus(undefined, publicOf(mine))).toBe("link");
    expect(identityStatus(heldOf(), publicOf(mine))).toBe("link");
    expect(identityStatus(undefined, undefined)).toBe("create");
    expect(identityStatus(heldOf(""), undefined)).toBe("create");
    expect(identityStatus(mine, undefined)).toBe("orphaned");
    expect(currentCopy(mine, publicOf(mine))).toBe(mine);
    expect(currentCopy(mine, "unreachable")).toBe(mine);
    expect(currentCopy(mine, publicOf(heldOf()))).toBeUndefined();
    expect(currentCopy(mine, undefined)).toBeUndefined();
    expect(currentCopy(heldOf(""), "unreachable")).toBeUndefined();
  });
});

describe("recoverable", () => {
  it("is true only with a password copy or a recovery-code copy on the server", () => {
    const base = { deviceId: "dev", publicKey: "", fingerprint: "" };
    expect(recoverable(undefined)).toBe(false);
    expect(recoverable({ ...base, wrapAlg: "aes-256-gcm" })).toBe(true);
    expect(recoverable({ ...base, wrapAlg: "none" })).toBe(false);
    expect(recoverable({ ...base, wrapAlg: "none", recoveryId: "" })).toBe(false);
    expect(recoverable({ ...base, wrapAlg: "none", recoveryId: "rcv_1" })).toBe(true);
  });
});

describe("password copy after a reset stripped it", () => {
  const stripped = (held: HeldIdentity, passwordCopy?: string) => ({ myIdentity: vi.fn(async () => ({ ...publicOf(held), wrapAlg: DEVICE_ONLY_WRAP, passwordCopy })), stepUp: vi.fn() });

  it("is re-added from the copy this browser holds, bound to the listed identity", async () => {
    const mine = heldOf();
    const api = stripped(mine, "addable");
    const payload = (await rewrapIdentity(api, userID, keys(1), keys(2), mine))!;
    expect(payload.identityDeviceId).toBe(mine.deviceId);
    const record = { ...publicOf(mine), wrapAlg: "aes-256-gcm", wrappedPrivateKey: payload.wrappedIdentityKey };
    expect(bytesToHex(openIdentity(record, keys(2).userKEK, userID).privateKey)).toBe(bytesToHex(mine.privateKey));
    expect(api.stepUp).not.toHaveBeenCalled();
  });

  it("is not added when the server does not offer it, or this browser holds another copy or none", async () => {
    const mine = heldOf();
    expect(await rewrapIdentity(stripped(mine), userID, keys(1), keys(2), mine)).toBeUndefined();
    expect(await rewrapIdentity(stripped(mine, "addable"), userID, keys(1), keys(2), undefined)).toBeUndefined();
    expect(await rewrapIdentity(stripped(mine, "addable"), userID, keys(1), keys(2), heldOf())).toBeUndefined();
    expect(await rewrapIdentity(stripped(mine, "addable"), userID, keys(1), keys(2), { ...mine, deviceId: `dev_${"z".repeat(26)}` })).toBeUndefined();
  });
});

describe("password copy integrity", () => {
  it("is never sent unless it opens under the new password's key to the listed public key", async () => {
    const mine = heldOf();
    const api = { myIdentity: vi.fn(async () => ({ ...publicOf(mine), wrapAlg: DEVICE_ONLY_WRAP, passwordCopy: "addable" })), stepUp: vi.fn() };
    // A damaged vault copy: the listed public key with some other private key.
    const damaged = { ...mine, privateKey: generateIdentity().privateKey };
    await expect(rewrapIdentity(api, userID, keys(1), keys(2), damaged)).rejects.toThrow(/damaged/);
    const payload = (await rewrapIdentity(api, userID, keys(1), keys(2), mine))!;
    const record = { ...publicOf(mine), wrapAlg: "aes-256-gcm", wrappedPrivateKey: payload.wrappedIdentityKey };
    expect(() => openIdentity(record, keys(1).userKEK, userID)).toThrow();
    expect(bytesToHex(openIdentity(record, keys(2).userKEK, userID).privateKey)).toBe(bytesToHex(mine.privateKey));
  });

  it("a planted password copy of another key is refused at unlock, never substituted", () => {
    const mine = heldOf();
    const planted = { ...publicOf(mine), wrapAlg: "aes-256-gcm", wrappedPrivateKey: base64(wrapIdentity(keys(1).userKEK, generateIdentity().privateKey, userID)) };
    expect(() => openIdentity(planted, keys(1).userKEK, userID)).toThrow(/public key mismatch/);
  });
});

describe("unfinishedReset (M4)", () => {
  it("is true only when the server lists the key this browser's reset sent and the vault holds another", () => {
    const old = heldOf();
    const sent = heldOf(`dev_${"s".repeat(26)}`);
    expect(unfinishedReset(old, publicOf(sent), sent.publicKey)).toBe(true);
    expect(unfinishedReset(sent, publicOf(sent), sent.publicKey)).toBe(false); // kept here
    expect(unfinishedReset(old, publicOf(old), sent.publicKey)).toBe(false); // the reset never committed
    expect(unfinishedReset(old, publicOf(heldOf()), sent.publicKey)).toBe(false); // someone else's reset
    expect(unfinishedReset(old, publicOf(sent), undefined)).toBe(false);
    expect(unfinishedReset(undefined, publicOf(sent), sent.publicKey)).toBe(false); // nothing to forget: restore works
  });
});
