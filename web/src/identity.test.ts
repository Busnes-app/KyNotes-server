import { describe, expect, it, vi } from "vitest";
import { bytesToHex } from "@noble/ciphers/utils.js";
import { base64, type LoginKeys } from "./crypto";
import { ensureIdentity, openIdentity, rewrapIdentity, type IdentityAPI, type IdentityRecord, type IdentityUpload } from "./identity";

const userID = "usr_0123456789abcdefghjkmnpqrs";
const deviceId = "dev_00000000000000000000000000";
/** ensureIdentity for flows where an identity must result. */
const ensure = async (...args: Parameters<typeof ensureIdentity>) => (await ensureIdentity(...args))!;
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
    expect(await ensureIdentity(server.api, userID, keys(1), undefined)).toBeUndefined();
    expect(server.uploads).toHaveLength(0);
    expect(await rewrapIdentity(server.api, userID, keys(1), keys(2).userKEK, undefined)).toBeUndefined();
    server.ownPasswordChange();
    const created = (await ensureIdentity(server.api, userID, keys(2), undefined))!;
    expect(server.api.stepUp).toHaveBeenLastCalledWith(keys(2).authSecret);
    expect(bytesToHex(openIdentity(server.record(), keys(2).userKEK, userID).privateKey)).toBe(bytesToHex(created.privateKey));
    expect(() => openIdentity(server.record(), keys(1).userKEK, userID)).toThrow();
  });
});

describe("password change re-wrap", () => {
  it("sends nothing when no identity exists", async () => {
    const server = fakeServer();
    expect(await rewrapIdentity(server.api, userID, keys(1), keys(2).userKEK, undefined)).toBeUndefined();
    expect(server.api.stepUp).not.toHaveBeenCalled();
  });

  it("re-wraps the same key, bound to the identity device ID", async () => {
    const server = fakeServer();
    const original = await ensure(server.api, userID, keys(1), undefined);
    const payload = (await rewrapIdentity(server.api, userID, keys(1), keys(2).userKEK, undefined))!;
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
    const payload = (await rewrapIdentity(server.api, userID, keys(1), keys(2).userKEK, original))!;
    expect(bytesToHex(openIdentity({ ...server.record(), wrappedPrivateKey: payload.wrappedIdentityKey }, keys(2).userKEK, userID).privateKey)).toBe(bytesToHex(original.privateKey));
  });

  it("refuses a stale vault copy rather than sending a wrap the server cannot bind", async () => {
    const server = fakeServer();
    const original = await ensure(server.api, userID, keys(1), undefined);
    server.api.stepUp.mockResolvedValue(undefined);
    await expect(rewrapIdentity(server.api, userID, keys(1), keys(2).userKEK, { ...original, deviceId: "dev_11111111111111111111111111" })).rejects.toThrow();
    await expect(rewrapIdentity(server.api, userID, keys(1), keys(2).userKEK, undefined)).rejects.toThrow();
  });
});
