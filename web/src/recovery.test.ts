import { describe, expect, it, vi } from "vitest";
import { bytesToHex, hexToBytes as h } from "@noble/ciphers/utils.js";
import vectors from "../../testdata/protocol/recovery_vectors.json";
import * as crypto from "./crypto";
import { base64, deriveRecoveryKEK } from "./crypto";
import { formatRecoveryCode, newRecoveryCode, openRecovery, parseRecoveryCode, RECOVERY_ALG, RECOVERY_BYTES, RECOVERY_WRONG, RecoveryCodeError, sealRecovery, sealRecoveryForVector } from "./recovery";
import source from "./recovery.ts?raw";
import { generateIdentity } from "./teamKeys";

vi.mock("./crypto", async (original) => {
  const actual = await original<typeof import("./crypto")>();
  return { ...actual, deriveRecoveryKEK: vi.fn(actual.deriveRecoveryKEK) };
});

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
    const kdf = vi.mocked(crypto.deriveRecoveryKEK);
    for (const r of vectors.openRejects) {
      kdf.mockClear();
      await expect(openRecovery(h(r.secret), h(r.wrapped), r.userId, listedOf(r.publicKey, r.wrapAlg)), r.case).rejects.toThrow(RECOVERY_WRONG);
      expect(kdf.mock.calls.length, r.case).toBe(r.reason === "alg" || r.reason === "format" ? 0 : 1);
    }
  }, 60_000);

  it("refuses a secret of the wrong length before the KDF", async () => {
    const v = vectors.codes[0];
    const kdf = vi.mocked(crypto.deriveRecoveryKEK);
    kdf.mockClear();
    await expect(openRecovery(h(v.secret).subarray(1), h(v.wrapped), v.userId, listedOf(v.publicKey))).rejects.toThrow(RECOVERY_WRONG);
    expect(kdf).not.toHaveBeenCalled();
  });

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
