import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { base64, deriveLoginKeys, LEGACY_LOGIN_ITERATIONS, LOGIN_ITERATIONS } from "./crypto";
import { openIdentity } from "./identity";
import { loginFloor, pinLogin, upgradeLogin, type LoginUpgrade } from "./loginUpgrade";
import { generateIdentity, IDENTITY_WRAP_ALG, wrapIdentity } from "./teamKeys";

const SALT = "MDEyMzQ1Njc4OWFiY2RlZg==";
const USER = "usr_0123456789abcdefghjkmnpqrs";

describe("login iteration pins", () => {
  beforeEach(() => {
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v) });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("lets an unpinned account sign in at the legacy count, never below", async () => {
    expect(loginFloor("Alice")).toBe(LEGACY_LOGIN_ITERATIONS);
    await expect(deriveLoginKeys("pw", SALT, LEGACY_LOGIN_ITERATIONS - 1, loginFloor("alice"))).rejects.toThrow(/too few password iterations/);
  });

  it("refuses a downgrade once the account is pinned", async () => {
    pinLogin(" Alice ");
    expect(loginFloor("alice")).toBe(LOGIN_ITERATIONS);
    expect(loginFloor("bob")).toBe(LEGACY_LOGIN_ITERATIONS);
    await expect(deriveLoginKeys("pw", SALT, LEGACY_LOGIN_ITERATIONS, loginFloor("alice"))).rejects.toThrow(/too few password iterations/);
    pinLogin("alice");
    expect(JSON.parse(localStorage.getItem("kynotes.login-pins.v1")!)).toEqual(["alice"]);
  });

  it("keeps the legacy floor when storage is unreadable", () => {
    vi.stubGlobal("localStorage", { getItem: () => "{not json", setItem: () => { throw new Error("blocked"); } });
    pinLogin("alice");
    expect(loginFloor("alice")).toBe(LEGACY_LOGIN_ITERATIONS);
  });
});

describe("upgradeLogin", () => {
  it("re-derives at LOGIN_ITERATIONS and moves the password copy with the verifier", async () => {
    const current = await deriveLoginKeys("pw", SALT, LEGACY_LOGIN_ITERATIONS, LEGACY_LOGIN_ITERATIONS);
    const held = generateIdentity();
    const record = { deviceId: "dev_0123456789abcdefghjkmnpqrs", publicKey: base64(held.publicKey), fingerprint: "f", wrapAlg: IDENTITY_WRAP_ALG, wrappedPrivateKey: base64(wrapIdentity(current.userKEK, held.privateKey, USER)) };
    const sent: LoginUpgrade[] = [];
    const { keys, identity } = await upgradeLogin(async (input) => void sent.push(input), USER, "pw", current, record);

    expect(sent).toHaveLength(1);
    const [input] = sent;
    expect(input.iterations).toBe(LOGIN_ITERATIONS);
    expect(input.currentAuthSecret).toBe(current.authSecret);
    expect(input.newLoginSalt).not.toBe(SALT);
    expect(input.newAuthSecret).toBe((await deriveLoginKeys("pw", input.newLoginSalt, LOGIN_ITERATIONS)).authSecret);
    expect(keys.authSecret).toBe(input.newAuthSecret);
    expect(input.identityDeviceId).toBe(record.deviceId);
    // The copy opens under the new userKEK to the same key, and no longer under the old one.
    expect(identity!.wrappedPrivateKey).toBe(input.wrappedIdentityKey);
    expect(openIdentity(identity!, keys.userKEK, USER).privateKey).toEqual(held.privateKey);
    expect(() => openIdentity(identity!, current.userKEK, USER)).toThrow();
  });

  it("sends no password copy for an account without one, and fails closed on a copy it cannot open", async () => {
    const current = await deriveLoginKeys("pw", SALT, LEGACY_LOGIN_ITERATIONS, LEGACY_LOGIN_ITERATIONS);
    const sent: LoginUpgrade[] = [];
    await upgradeLogin(async (input) => void sent.push(input), USER, "pw", current);
    expect(sent[0].wrappedIdentityKey).toBeUndefined();
    expect(sent[0].identityDeviceId).toBeUndefined();

    const other = generateIdentity();
    const foreign = { deviceId: "dev_0123456789abcdefghjkmnpqrs", publicKey: base64(other.publicKey), fingerprint: "f", wrapAlg: IDENTITY_WRAP_ALG, wrappedPrivateKey: base64(wrapIdentity(new Uint8Array(32).fill(1), other.privateKey, USER)) };
    await expect(upgradeLogin(async (input) => void sent.push(input), USER, "pw", current, foreign)).rejects.toThrow();
    expect(sent).toHaveLength(1);
  });
});
