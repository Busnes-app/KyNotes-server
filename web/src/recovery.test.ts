import { describe, expect, it, vi } from "vitest";
import { bytesToHex, hexToBytes as h } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import vectors from "../../testdata/protocol/recovery_vectors.json";
import { APIRequestError } from "./api";
import * as cryptoModule from "./crypto";
import { base64, deriveRecoveryKEK } from "./crypto";
import { pbkdf2Sha256 } from "./fallbackCrypto";
import { DEVICE_ONLY_WRAP, type HeldIdentity, type IdentityStore, type PublicIdentity } from "./identity";
import { OTHER_COPY } from "./linkFlow";
import { CONFIRM_FIRST, confirmRecoverySaved, recheck, RESET_UNCERTAIN, ResetUncertainError, formatRecoveryCode, newRecoveryCode, openRecovery, parseRecoveryCode, prepareRecovery, RECOVERY_ALG, RECOVERY_BYTES, RECOVERY_MOVED, RECOVERY_NONE, RECOVERY_RATE_LIMITED, RECOVERY_STALE, RECOVERY_TYPO, RECOVERY_WRONG, RecoveryCodeError, RecoveryMovedError, recoveryRefusal, resetConfirmed, RESET_CONFIRM, RESET_UNCONFIRMED, resetIdentity, restoreIdentity, saveRecovery, sealRecovery, sealRecoveryForVector, type PreparedRecovery, type RecoveryAPI, type ReplaceInput } from "./recovery";
import source from "./recovery.ts?raw";
import { generateIdentity, unwrapIdentity } from "./teamKeys";

vi.mock("./crypto", async (original) => {
  const actual = await original<typeof import("./crypto")>();
  return { ...actual, deriveRecoveryKEK: vi.fn(actual.deriveRecoveryKEK) };
});
// Call-through spy: shows which check refused a copy (the derive check runs only after the AEAD opened it).
vi.mock("@noble/curves/ed25519.js", async (original) => {
  const actual = await original<typeof import("@noble/curves/ed25519.js")>();
  return { ...actual, x25519: { ...actual.x25519, getPublicKey: vi.fn(actual.x25519.getPublicKey) } };
});
const kdf = vi.mocked(cryptoModule.deriveRecoveryKEK);
const derive = vi.mocked(x25519.getPublicKey);

const dev = `dev_${"a".repeat(26)}`;
const listedOf = (publicKey: string, wrapAlg = RECOVERY_ALG) => ({ deviceId: dev, publicKey: base64(h(publicKey)), wrapAlg });

describe("recovery code format", () => {
  it("matches the Go vectors: code, KEK and sealed copy", async () => {
    for (const v of vectors.codes) {
      expect(formatRecoveryCode(h(v.secret))).toBe(v.code);
      expect(bytesToHex(parseRecoveryCode(v.code))).toBe(v.secret);
      expect(bytesToHex(await deriveRecoveryKEK(h(v.secret), h(v.salt)))).toBe(v.kek);
      const sealed = await sealRecoveryForVector(h(v.secret), h(v.privateKey), v.userId, h(v.salt), h(v.nonce));
      expect(sealed).toHaveLength(RECOVERY_BYTES);
      expect(bytesToHex(sealed)).toBe(v.wrapped);
      expect(bytesToHex((await openRecovery(h(v.secret), h(v.wrapped), v.userId, listedOf(v.publicKey))).privateKey)).toBe(v.privateKey);
    }
  }, 60_000);

  it("accepts the code however it is typed", () => {
    const secret = h(vectors.codes[0].secret);
    const fullWidth = vectors.codes[0].code.replace(/[0-9A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0));
    for (const input of [...vectors.aliases.map((a) => a.input), fullWidth]) expect(parseRecoveryCode(input)).toEqual(secret);
  });

  it("refuses every Go reject vector with a typo error", () => {
    expect(vectors.rejects.map((r) => r.case)).toEqual(["short", "long", "bad-symbol", "overflow", "typo", "transposed", "bad-checksum"]);
    for (const r of vectors.rejects) expect(() => parseRecoveryCode(r.input), r.case).toThrow(RecoveryCodeError);
  });

  it("is 128 fresh random bits in seven groups of four", () => {
    const a = newRecoveryCode(), b = newRecoveryCode();
    expect(a.code).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(a.secret).toHaveLength(16);
    expect(parseRecoveryCode(a.code)).toEqual(a.secret);
    expect(a.code).not.toBe(b.code);
  });
});

describe("opening a recovery copy", () => {
  it("refuses every Go open-reject vector; a downgraded label or salt never reaches the KDF", async () => {
    expect(vectors.openRejects.map((r) => r.case)).toEqual(["low-iterations", "short-salt", "wrong-code", "wrong-user", "wrong-public-key", "tamper", "key-mismatch"]);
    for (const r of vectors.openRejects) {
      kdf.mockClear();
      derive.mockClear();
      await expect(openRecovery(h(r.secret), h(r.wrapped), r.userId, listedOf(r.publicKey, r.wrapAlg)), r.case).rejects.toThrow(RECOVERY_WRONG);
      expect(kdf.mock.calls.length, r.case).toBe(r.reason === "alg" || r.reason === "format" ? 0 : 1);
      // Only a copy the AEAD opened reaches the derive check: aead rejects stop before it, key-mismatch fails at it.
      expect(derive.mock.calls.length, r.case).toBe(r.reason === "public-key" ? 1 : 0);
    }
  }, 60_000);

  it("refuses a secret of the wrong length before the KDF", async () => {
    const v = vectors.codes[0];
    kdf.mockClear();
    await expect(openRecovery(h(v.secret).subarray(1), h(v.wrapped), v.userId, listedOf(v.publicKey))).rejects.toThrow(RECOVERY_WRONG);
    expect(kdf).not.toHaveBeenCalled();
  });

  it("refuses a malformed server public key as a wrong code, before the KDF", async () => {
    const v = vectors.codes[0];
    kdf.mockClear();
    for (const publicKey of ["not base64!", base64(new Uint8Array(31)), ""]) {
      await expect(openRecovery(h(v.secret), h(v.wrapped), v.userId, { deviceId: dev, publicKey, wrapAlg: RECOVERY_ALG }), publicKey).rejects.toThrow(RecoveryCodeError);
    }
    expect(kdf).not.toHaveBeenCalled();
  });

  it("derives the vector KEK on plain-HTTP origins too (no WebCrypto: the pure PBKDF2 fallback)", async () => {
    const v = vectors.codes[0];
    vi.stubGlobal("crypto", { getRandomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto) });
    try {
      expect(globalThis.crypto.subtle).toBeUndefined();
      expect(bytesToHex(await deriveRecoveryKEK(h(v.secret), h(v.salt)))).toBe(v.kek);
    } finally {
      vi.unstubAllGlobals();
    }
    const labelled = new Uint8Array([...new TextEncoder().encode("kynotes/recovery-kek/v1"), ...h(v.salt)]);
    expect(bytesToHex(await pbkdf2Sha256(h(v.secret), labelled, 600_000, 32))).toBe(v.kek);
  }, 120_000);

  it("opens only with this code, for this user and this public key", async () => {
    const identity = generateIdentity();
    const { secret } = newRecoveryCode();
    const user = `usr_${"b".repeat(26)}`;
    const sealed = await sealRecovery(secret, identity, user);
    expect(bytesToHex(sealed.subarray(0, 16))).not.toBe(bytesToHex((await sealRecovery(secret, identity, user)).subarray(0, 16)));
    const listed = { deviceId: dev, publicKey: base64(identity.publicKey), wrapAlg: RECOVERY_ALG };
    expect((await openRecovery(secret, sealed, user, listed)).privateKey).toEqual(identity.privateKey);
    await expect(openRecovery(newRecoveryCode().secret, sealed, user, listed)).rejects.toThrow(RECOVERY_WRONG);
    await expect(openRecovery(secret, sealed, `usr_${"c".repeat(26)}`, listed)).rejects.toThrow(RECOVERY_WRONG);
    await expect(openRecovery(secret, sealed, user, { ...listed, publicKey: base64(generateIdentity().publicKey) })).rejects.toThrow(RECOVERY_WRONG);
    await expect(openRecovery(secret, sealed.slice(1), user, listed)).rejects.toThrow(RECOVERY_WRONG);
  }, 30_000);

  it("leaves the caller's secret intact for it to zero", async () => {
    const identity = generateIdentity();
    const { secret } = newRecoveryCode();
    const copy = secret.slice();
    const user = `usr_${"b".repeat(26)}`;
    await sealRecovery(secret, identity, user);
    expect(secret).toEqual(copy);
  }, 30_000);
});

describe("code lifetime", () => {
  it("recovery.ts never logs or persists anything", () => {
    expect(source).not.toMatch(/console\.|indexedDB|localStorage|sessionStorage|caches\./);
  });
});

const user = `usr_${"d".repeat(26)}`;
const held = (): HeldIdentity => ({ ...generateIdentity(), deviceId: dev });
const sameKey = (a: HeldIdentity, b: HeldIdentity) => bytesToHex(a.publicKey) === bytesToHex(b.publicKey);
/** An IdentityStore with compare-and-swap like storage.ts storeIdentityKey. */
function memoryStore(initial?: HeldIdentity) {
  let current = initial;
  const save = vi.fn(async (identity: HeldIdentity, expected?: HeldIdentity | null) => {
    if (expected !== undefined && (expected === null ? current !== undefined : current === undefined || !sameKey(current, expected))) return false;
    current = identity;
    return true;
  });
  return { load: async () => current, save, held: () => current, set: (next?: HeldIdentity) => { current = next; } } satisfies IdentityStore & Record<string, unknown>;
}
/** The group the dialog asks for (prepared.check, 1–7). */
const asked = (prepared: PreparedRecovery) => prepared.code.split("-")[prepared.check - 1];
const listed = (identity: HeldIdentity, extra: Partial<PublicIdentity> = {}): PublicIdentity => ({ deviceId: identity.deviceId, publicKey: base64(identity.publicKey), fingerprint: "x", ...extra });
const isZero = (bytes: Uint8Array) => bytes.every((b) => b === 0);
const apiError = (code: string, status: number) => new APIRequestError(code, { error: { code, message: code } }, status);

describe("saving a recovery code", () => {
  it("asks for a CSPRNG-picked group, not always the same one, and zeroes the code's bytes", async () => {
    const checks = new Set<number>();
    kdf.mockClear();
    for (let i = 0; i < 12; i++) checks.add((await prepareRecovery(held(), user)).check);
    expect([...checks].every((group) => Number.isInteger(group) && group >= 1 && group <= 7)).toBe(true);
    expect(checks.size).toBeGreaterThan(1); // a random pick is one group 12 times with probability 7^-11
    expect(kdf.mock.calls.map(([secret]) => isZero(secret))).toEqual(Array(12).fill(true));
    expect(source).toMatch(/randomBytes\(1\)\[0\]/); // the group comes from noble's CSPRNG, never Math.random
    expect(source).not.toMatch(/Math\.random/);
  }, 120_000);

  it("uploads only after the user typed back the asked group, and never the code", async () => {
    const me = held();
    const prepared = await prepareRecovery(me, user);
    const api = { putRecovery: vi.fn(async () => ({ recoveryId: "rcv_1" })), myIdentity: vi.fn(async () => undefined) };
    await expect(saveRecovery(api, prepared, me, "")).rejects.toThrow(CONFIRM_FIRST);
    expect(confirmRecoverySaved(prepared, "UUUU")).toBe(false); // U is not a code symbol: never a match
    const other = prepared.code.split("-").find((group, i) => i !== prepared.check - 1 && group !== asked(prepared));
    if (other) expect(confirmRecoverySaved(prepared, other)).toBe(false); // another group of the same code
    await expect(saveRecovery(api, prepared, me, "")).rejects.toThrow(CONFIRM_FIRST);
    expect(api.putRecovery).not.toHaveBeenCalled();
    expect(confirmRecoverySaved(prepared, ` ${asked(prepared).toLowerCase()} `)).toBe(true);
    expect(await saveRecovery(api, prepared, me, "")).toBe("rcv_1");
    expect(api.putRecovery).toHaveBeenCalledWith({ deviceId: dev, expectedRecoveryId: "", wrapAlg: RECOVERY_ALG, wrappedKey: prepared.wrappedKey });
    const sent = JSON.stringify(api.putRecovery.mock.calls);
    expect(sent).not.toContain(prepared.code);
    expect(sent).not.toContain(prepared.code.replaceAll("-", ""));
  }, 30_000);

  it("a rotation names the copy it replaces; a prepared code is sent once, and only for the key it wraps", async () => {
    const me = held();
    const prepared = await prepareRecovery(me, user);
    const api = { putRecovery: vi.fn(async () => ({ recoveryId: "rcv_2" })), myIdentity: vi.fn(async () => undefined) };
    confirmRecoverySaved(prepared, asked(prepared));
    await expect(saveRecovery(api, prepared, held(), "rcv_1")).rejects.toThrow();
    expect(await saveRecovery(api, prepared, me, "rcv_1")).toBe("rcv_2");
    expect(api.putRecovery.mock.calls[0]).toEqual([expect.objectContaining({ expectedRecoveryId: "rcv_1" })]);
    await expect(saveRecovery(api, prepared, me, "rcv_2")).rejects.toThrow(CONFIRM_FIRST);
    expect(api.putRecovery).toHaveBeenCalledTimes(1);
  }, 30_000);

  it("a save whose response was lost is re-sent, and the server's 200 for the same copy counts as saved", async () => {
    const me = held();
    const prepared = await prepareRecovery(me, user);
    confirmRecoverySaved(prepared, asked(prepared));
    const sent: string[] = [];
    const api = {
      putRecovery: vi.fn(async (input: { wrappedKey: string }) => { sent.push(input.wrappedKey); if (sent.length === 1) throw new TypeError("Failed to fetch"); return { recoveryId: "rcv_1" }; }),
      myIdentity: vi.fn(async () => undefined),
    };
    await expect(saveRecovery(api, prepared, me, "")).rejects.toThrow(TypeError);
    expect(await saveRecovery(api, prepared, me, "")).toBe("rcv_1");
    expect(sent).toEqual([prepared.wrappedKey, prepared.wrappedKey]); // byte-identical: the server's replay check
  }, 30_000);

  it("a lost compare-and-swap re-reads the server, says so, and spends the code instead of retrying", async () => {
    const me = held();
    const prepared = await prepareRecovery(me, user);
    confirmRecoverySaved(prepared, asked(prepared));
    const now = listed(me, { recoveryId: "rcv_other" });
    const api = { putRecovery: vi.fn(async () => { throw apiError("already_exists", 409); }), myIdentity: vi.fn(async () => now) };
    const error = await saveRecovery(api, prepared, me, "rcv_old").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RecoveryMovedError);
    expect(error).toMatchObject({ code: "already_exists", message: RECOVERY_MOVED, live: now });
    expect(api.myIdentity).toHaveBeenCalledTimes(1);
    await expect(saveRecovery(api, prepared, me, "rcv_other")).rejects.toThrow(CONFIRM_FIRST);
    expect(api.putRecovery).toHaveBeenCalledTimes(1);
  }, 30_000);
});

describe("restoring with a recovery code", () => {
  const copyOf = async (me: HeldIdentity) => {
    const prepared = await prepareRecovery(me, user);
    const copy = { deviceId: me.deviceId, publicKey: base64(me.publicKey), recoveryId: "rcv_1", wrapAlg: RECOVERY_ALG, wrappedKey: prepared.wrappedKey };
    return { code: prepared.code, api: { fetchRecovery: vi.fn(async () => copy), myIdentity: vi.fn(async (): Promise<PublicIdentity | undefined> => listed(me)) } };
  };
  const stepUp = () => vi.fn(async () => undefined);

  it("steps up, then fetches, then keeps the key by compare-and-swap; the code's bytes are zeroed", async () => {
    const me = held();
    const { code, api } = await copyOf(me);
    const store = memoryStore();
    const up = stepUp();
    kdf.mockClear();
    const restored = await restoreIdentity(api, store, user, code.toLowerCase(), up);
    expect(restored.privateKey).toEqual(me.privateKey);
    expect(store.save).toHaveBeenCalledWith(restored, null);
    expect(up.mock.invocationCallOrder[0]).toBeLessThan(api.fetchRecovery.mock.invocationCallOrder[0]);
    expect(isZero(kdf.mock.calls[0][0])).toBe(true);
  }, 30_000);

  it("makes no request but the copy and the identity: no link requests", async () => {
    const me = held();
    const { code, api } = await copyOf(me);
    const touched = new Set<string>();
    const watched = new Proxy(api, { get: (target, name: string) => { touched.add(name); return target[name as keyof typeof target]; } });
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    try {
      await restoreIdentity(watched, memoryStore(), user, code, stepUp());
    } finally {
      vi.unstubAllGlobals();
    }
    expect([...touched].sort()).toEqual(["fetchRecovery", "myIdentity"]);
    expect(fetchSpy).not.toHaveBeenCalled();
  }, 30_000);

  it("never overwrites another key this browser holds, even one another tab kept meanwhile", async () => {
    const me = held();
    const { code, api } = await copyOf(me);
    const store = memoryStore(held());
    const up = stepUp();
    await expect(restoreIdentity(api, store, user, code, up)).rejects.toThrow(OTHER_COPY);
    expect(OTHER_COPY).toMatch(/Use Forget this device first/);
    expect(store.save).not.toHaveBeenCalled();
    // Refused before the step-up, the audited fetch and the KDF.
    expect(up).not.toHaveBeenCalled();
    expect(api.fetchRecovery).not.toHaveBeenCalled();
    const raced = memoryStore();
    const other = held();
    raced.save.mockImplementationOnce(async () => { raced.set(other); return false; });
    await expect(restoreIdentity(api, raced, user, code, stepUp())).rejects.toThrow(OTHER_COPY);
    expect(raced.held()).toBe(other);
  }, 30_000);

  it("a browser already holding the listed key needs no restore: no step-up, no fetch", async () => {
    const me = held();
    const { code, api } = await copyOf(me);
    const up = stepUp();
    expect(await restoreIdentity(api, memoryStore(me), user, code, up)).toBe(me);
    expect(up).not.toHaveBeenCalled();
    expect(api.fetchRecovery).not.toHaveBeenCalled();
  }, 30_000);

  it("zeroes the opened key on every path that does not keep it", async () => {
    const me = held();
    const { code, api } = await copyOf(me);
    const raced = memoryStore();
    let opened: HeldIdentity | undefined;
    // Another tab kept the same key meanwhile: its copy is returned and ours is wiped.
    raced.save.mockImplementationOnce(async (identity: HeldIdentity) => { opened = identity; raced.set({ ...me, privateKey: me.privateKey.slice() }); return false; });
    const got = await restoreIdentity(api, raced, user, code, stepUp());
    expect(got).toBe(raced.held());
    expect(isZero(opened!.privateKey)).toBe(true);
    expect(isZero(got.privateKey)).toBe(false);
    const blocked = memoryStore();
    blocked.save.mockImplementationOnce(async (identity: HeldIdentity) => { opened = identity; return false; });
    await expect(restoreIdentity(api, blocked, user, code, stepUp())).rejects.toThrow(/cannot keep an encryption key/);
    expect(isZero(opened!.privateKey)).toBe(true);
  }, 30_000);

  it("catches a typo before the step-up and any request", async () => {
    const { code, api } = await copyOf(held());
    const up = stepUp();
    await expect(restoreIdentity(api, memoryStore(), user, code.slice(0, -1), up)).rejects.toThrow(RECOVERY_TYPO);
    expect(up).not.toHaveBeenCalled();
    expect(api.fetchRecovery).not.toHaveBeenCalled();
  }, 30_000);

  it("refuses a copy that is not for the identity GET /me/identity lists, before the KDF", async () => {
    const me = held();
    const { code, api } = await copyOf(me);
    for (const live of [listed(held()), listed(me, { deviceId: `dev_${"f".repeat(26)}` })]) {
      api.myIdentity.mockResolvedValueOnce(live);
      kdf.mockClear();
      await expect(restoreIdentity(api, memoryStore(), user, code, stepUp())).rejects.toThrow(RECOVERY_STALE);
      expect(kdf).not.toHaveBeenCalled();
    }
    // No identity listed (or a malformed one): nothing to restore, so no step-up either.
    for (const live of [undefined, listed(me, { publicKey: "AAAA" })]) {
      api.myIdentity.mockResolvedValueOnce(live);
      const up = stepUp();
      await expect(restoreIdentity(api, memoryStore(), user, code, up)).rejects.toThrow(RECOVERY_NONE);
      expect(up).not.toHaveBeenCalled();
    }
  }, 30_000);

  it("opens only for this user, and says so when a valid code is not this account's, or there is no copy", async () => {
    const me = held();
    const { code, api } = await copyOf(me);
    await expect(restoreIdentity(api, memoryStore(), `usr_${"e".repeat(26)}`, code, stepUp())).rejects.toThrow(RECOVERY_WRONG);
    await expect(restoreIdentity(api, memoryStore(), user, newRecoveryCode().code, stepUp())).rejects.toThrow(RECOVERY_WRONG);
    await expect(restoreIdentity({ ...api, fetchRecovery: async () => undefined }, memoryStore(), user, newRecoveryCode().code, stepUp())).rejects.toThrow(RECOVERY_NONE);
  }, 30_000);
});

describe("resetting the identity", () => {
  const prepared = async (fresh = generateIdentity()) => {
    const p = await prepareRecovery(fresh, user);
    confirmRecoverySaved(p, asked(p));
    return { fresh, p };
  };
  const was = `dev_${"e".repeat(26)}`; // the identity the browser saw listed

  it("lists what is lost and needs the typed phrase", async () => {
    expect(RESET_CONFIRM).toMatch(/personal notebooks become unreadable for good/);
    expect(RESET_CONFIRM).toMatch(/no other owner or admin/);
    expect(RESET_CONFIRM).toMatch(/unsent edits/i);
    expect(resetConfirmed(" RESET ")).toBe(true);
    for (const typed of [null, "", "reset", "RESE"]) expect(resetConfirmed(typed)).toBe(false);
    const { p } = await prepared();
    const api = { replaceIdentity: vi.fn(async () => ({ deviceId: dev })), myIdentity: vi.fn(async () => undefined) };
    await expect(resetIdentity(api, memoryStore(), p, was, "reset")).rejects.toThrow(RESET_UNCONFIRMED);
    expect(api.replaceIdentity).not.toHaveBeenCalled();
  }, 30_000);

  it("a password session steps up with the same keys that wrap its password copy; otherwise device-only", async () => {
    const keys = { authSecret: "a".repeat(64), userKEK: new Uint8Array(32).fill(9) };
    const userKEK = keys.userKEK;
    const { fresh, p } = await prepared();
    const api = { replaceIdentity: vi.fn(async (_input: ReplaceInput) => ({ deviceId: dev })), myIdentity: vi.fn(async () => undefined) };
    // A wrong password fails the step-up: nothing is sent, so no unusable password copy is planted.
    const refused = vi.fn(async () => { throw apiError("unauthenticated", 401); });
    await expect(resetIdentity(api, memoryStore(), p, was, "RESET", { keys, stepUp: refused })).rejects.toMatchObject({ code: "unauthenticated" });
    expect(api.replaceIdentity).not.toHaveBeenCalled();
    const up = vi.fn(async (_authSecret: string) => undefined);
    await resetIdentity(api, memoryStore(), p, was, "RESET", { keys, stepUp: up });
    expect(up).toHaveBeenCalledWith(keys.authSecret);
    expect(up.mock.invocationCallOrder[0]).toBeLessThan(api.replaceIdentity.mock.invocationCallOrder[0]);
    const [body] = api.replaceIdentity.mock.calls[0];
    expect(body).toMatchObject({ publicKey: base64(fresh.publicKey), wrapAlg: "aes-256-gcm", expectedDeviceId: was, recovery: { wrapAlg: RECOVERY_ALG, wrappedKey: p.wrappedKey } });
    expect(unwrapIdentity(userKEK, cryptoModule.fromBase64(body.wrappedPrivateKey!), user).privateKey).toEqual(fresh.privateKey);
    const second = await prepared();
    await resetIdentity(api, memoryStore(), second.p, was, "RESET");
    expect(api.replaceIdentity.mock.calls[1][0]).toEqual({ publicKey: base64(second.fresh.publicKey), wrapAlg: DEVICE_ONLY_WRAP, expectedDeviceId: was, recovery: { wrapAlg: RECOVERY_ALG, wrappedKey: second.p.wrappedKey } });
  }, 30_000);

  it("sends the expected identity, and a lost response finishes only for its own key", async () => {
    const fresh = generateIdentity();
    const p = await prepareRecovery(fresh, user);
    const api: Pick<RecoveryAPI, "replaceIdentity" | "myIdentity"> = { replaceIdentity: vi.fn(async () => ({ deviceId: dev })), myIdentity: vi.fn(async () => undefined) };
    await expect(resetIdentity(api, memoryStore(), p, was, "RESET")).rejects.toThrow(CONFIRM_FIRST);
    confirmRecoverySaved(p, asked(p));
    const lost = new TypeError("Failed to fetch");
    const dropped = { ...api, replaceIdentity: vi.fn(async () => { throw lost; }) };
    // The server lists the old key: nothing was committed, the error stands and the prepared code stays usable.
    dropped.myIdentity = vi.fn(async () => ({ deviceId: dev, publicKey: base64(generateIdentity().publicKey), fingerprint: "x" }));
    await expect(resetIdentity(dropped, memoryStore(), p, was, "RESET")).rejects.toBe(lost);
    // A lost compare-and-swap (another identity now) is reported as such.
    const moved = apiError("already_exists", 409);
    await expect(resetIdentity({ ...dropped, replaceIdentity: vi.fn(async () => { throw moved; }) }, memoryStore(), p, was, "RESET")).rejects.toBe(moved);
    // The server lists the new key: the reset committed before the response was lost.
    dropped.myIdentity = vi.fn(async () => ({ deviceId: dev, publicKey: base64(fresh.publicKey), fingerprint: "x" }));
    const store = memoryStore(held());
    const done = await resetIdentity(dropped, store, p, was, "RESET");
    expect(done.identity).toMatchObject({ deviceId: dev, publicKey: fresh.publicKey });
    expect(done.kept).toBe(true);
    expect(store.held()?.publicKey).toEqual(fresh.publicKey);
    expect(dropped.replaceIdentity.mock.calls[0]).toEqual([{ publicKey: base64(fresh.publicKey), wrapAlg: DEVICE_ONLY_WRAP, expectedDeviceId: was, recovery: { wrapAlg: RECOVERY_ALG, wrappedKey: p.wrappedKey } }]);
    expect(JSON.stringify(dropped.replaceIdentity.mock.calls)).not.toContain(p.code.replaceAll("-", ""));
  }, 30_000);
});

describe("resetting a KySignOn-linked account or losing the answer (M3, M4)", () => {
  const was = `dev_${"e".repeat(26)}`;
  it("re-sends device-only when the server refuses a password copy, and notes the new key before sending", async () => {
    const fresh = generateIdentity();
    const p = await prepareRecovery(fresh, user);
    confirmRecoverySaved(p, asked(p));
    const order: string[] = [];
    const replace = vi.fn(async (input: ReplaceInput) => {
      order.push(`replace:${input.wrapAlg}`);
      if (input.wrapAlg !== DEVICE_ONLY_WRAP) throw apiError("device_only_required", 409);
      return { deviceId: dev };
    });
    const store = { ...memoryStore(), noteReset: vi.fn(async (publicKey: Uint8Array) => { order.push(`noted:${base64(publicKey)}`); }) };
    const keys = { authSecret: "a".repeat(64), userKEK: new Uint8Array(32).fill(9) };
    const done = await resetIdentity({ replaceIdentity: replace, myIdentity: async () => undefined }, store, p, was, "RESET", { keys, stepUp: async () => undefined });
    expect(order).toEqual([`noted:${base64(fresh.publicKey)}`, "replace:aes-256-gcm", `replace:${DEVICE_ONLY_WRAP}`]);
    expect(replace.mock.calls[1][0]).toEqual({ publicKey: base64(fresh.publicKey), wrapAlg: DEVICE_ONLY_WRAP, expectedDeviceId: was, recovery: { wrapAlg: RECOVERY_ALG, wrappedKey: p.wrappedKey } });
    expect(done.identity.publicKey).toEqual(fresh.publicKey);
  }, 30_000);

  it("refuses a wrong typed phrase before anything is noted or sent (M9)", async () => {
    const p = await prepareRecovery(generateIdentity(), user);
    confirmRecoverySaved(p, asked(p));
    const replace = vi.fn(async () => ({ deviceId: dev }));
    const store = { ...memoryStore(), noteReset: vi.fn(async () => undefined) };
    for (const typed of ["RESET!", "RESTE", "reset", ""]) {
      await expect(resetIdentity({ replaceIdentity: replace, myIdentity: async () => undefined }, store, p, was, typed)).rejects.toThrow(RESET_UNCONFIRMED);
    }
    expect(replace).not.toHaveBeenCalled();
    expect(store.noteReset).not.toHaveBeenCalled();
  }, 30_000);
});

describe("showing the code again (I1)", () => {
  it("asks for a different group each time, so the group just read is never the one asked", async () => {
    const p = await prepareRecovery(generateIdentity(), user);
    const seen = new Set<number>();
    let current = p;
    for (let i = 0; i < 30; i++) {
      const next = recheck(current);
      expect(next.check).not.toBe(current.check);
      expect(next.code).toBe(p.code);
      expect(next.identity).toBe(p.identity);
      // The old group no longer confirms; only the newly asked one does.
      if (asked(current) !== asked(next)) expect(confirmRecoverySaved(next, asked(current))).toBe(false);
      seen.add(next.check);
      current = next;
    }
    expect(seen.size).toBeGreaterThan(3);
    expect(confirmRecoverySaved(current, asked(current))).toBe(true);
  }, 30_000);

  it("is not confirmed by a confirmation of the shown-again code's predecessor", async () => {
    const p = await prepareRecovery(generateIdentity(), user);
    confirmRecoverySaved(p, asked(p));
    const again = recheck(p);
    const api = { putRecovery: vi.fn(async () => ({ recoveryId: "rcv_x" })), myIdentity: vi.fn(async () => undefined) };
    await expect(saveRecovery(api, again, { ...p.identity, deviceId: dev }, "")).rejects.toThrow(CONFIRM_FIRST);
  }, 30_000);
});

describe("a reset whose response was lost (M5)", () => {
  const was = `dev_${"e".repeat(26)}`;
  it("keeps the same new key for a retry when the server still lists the old one, or cannot be read", async () => {
    const fresh = generateIdentity();
    const p = await prepareRecovery(fresh, user);
    confirmRecoverySaved(p, asked(p));
    const lost = new TypeError("Failed to fetch");
    const replace = vi.fn(async (_input: ReplaceInput): Promise<{ deviceId: string }> => { throw lost; });
    // Old key listed: nothing committed; the error stands.
    await expect(resetIdentity({ replaceIdentity: replace, myIdentity: async () => ({ deviceId: was, publicKey: base64(generateIdentity().publicKey), fingerprint: "x" }) }, memoryStore(), p, was, "RESET")).rejects.toBe(lost);
    // The re-read fails too: whether it committed is unknown, and the caller is told so.
    const unknown = resetIdentity({ replaceIdentity: replace, myIdentity: async () => { throw lost; } }, memoryStore(), p, was, "RESET");
    await expect(unknown).rejects.toBeInstanceOf(ResetUncertainError);
    await expect(unknown).rejects.toThrow(RESET_UNCERTAIN);
    // The retry sends the same new key and code copy, and succeeds.
    replace.mockImplementationOnce(async () => ({ deviceId: dev }));
    const store = memoryStore();
    const done = await resetIdentity({ replaceIdentity: replace, myIdentity: async () => undefined }, store, p, was, "RESET");
    expect(done.identity.publicKey).toEqual(fresh.publicKey);
    const bodies = replace.mock.calls.map(([input]) => input);
    expect(new Set(bodies.map((input) => input.publicKey))).toEqual(new Set([base64(fresh.publicKey)]));
    expect(new Set(bodies.map((input) => input.recovery.wrappedKey))).toEqual(new Set([p.wrappedKey]));
  }, 30_000);
});

describe("refusals", () => {
  it("names every step-up refusal and the rate limit", async () => {
    const message = (code: string, status: number) => recoveryRefusal(apiError(code, status), "restore your key").message;
    expect(message("step_up_pending", 409)).toMatch(/KySignOn confirmation is still open/);
    expect(recoveryRefusal(new APIRequestError("x", { error: { code: "step_up_pending", challenge: "chl_1" } }, 409), "restore your key").cancel).toBeTypeOf("function");
    expect(message("sso_sign_in_required", 409)).toMatch(/Sign in with KySignOn.*restore your key/);
    expect(message("sso_step_up_required", 403)).toMatch(/Confirm with KySignOn to restore your key/);
    expect(message("step_up_required", 403)).toMatch(/Confirm your password to restore your key/);
    expect(message("password_change_required", 409)).toMatch(/Change your password before you restore your key/);
    expect(message("rate_limited", 429)).toBe(RECOVERY_RATE_LIMITED);
    expect(message("already_exists", 409)).toMatch(/another tab or browser/);
    expect(message("identity_exists", 409)).toBe("Start the reset again: a new key is needed.");
    expect(message("unauthenticated", 401)).toMatch(/Sign in again/);
    // Anything else from the server is generic copy, never its raw message.
    for (const [code, status] of [["invalid_request", 400], ["csrf_failed", 403], ["internal", 500], ["", 502]] as const) {
      const shown = message(code, status);
      expect(shown, code).toBe("Could not restore your key. Try again.");
    }
    expect(recoveryRefusal(new TypeError("Failed to fetch"), "reset your encryption key").message).toMatch(/Could not reach KyNotes/);
    expect(recoveryRefusal(new RecoveryMovedError(undefined), "save a recovery code").message).toBe(RECOVERY_MOVED);
    expect(recoveryRefusal("boom", "restore your key").message).toBe("Could not restore your key.");
  });
});
