import { describe, expect, it } from "vitest";
import { comparePins, confirmFingerprintChange, displayName, fingerprint, isPinConfirmation, PinConfirmation, pinRows, retrustMessage, retrustTarget, sameKey } from "./pins";

const key = (fill: number) => btoa(String.fromCharCode(...new Uint8Array(32).fill(fill)));
const member = (id: string, publicKey?: string) => ({ userId: id, username: id, role: "editor", identity: publicKey ? { deviceId: "dev", publicKey } : undefined });

describe("pins", () => {
  it("separates first-seen and changed keys and ignores members without one", () => {
    const result = comparePins({ a: key(1), b: key(2) }, [member("a", key(1)), member("b", key(9)), member("c", key(3)), member("d")]);
    expect(result.fresh.map((entry) => entry.userId)).toEqual(["c"]);
    expect(result.changed).toEqual([{ member: member("b", key(9)), pinned: key(2) }]);
  });

  it("compares decoded key bytes, and treats a malformed key as changed", () => {
    // Same 32 bytes; the second spelling sets the unused low bits of the last character.
    const canonical = key(0);
    const variant = `${canonical.slice(0, 42)}B=`;
    expect(variant).not.toBe(canonical);
    expect(sameKey(canonical, variant)).toBe(true);
    expect(comparePins({ a: canonical }, [member("a", variant)])).toEqual({ fresh: [], changed: [] });
    expect(sameKey(canonical, btoa("short"))).toBe(false);
    expect(sameKey(canonical, "not base64!")).toBe(false);
    expect(comparePins({ a: canonical }, [member("a", "not base64!")]).changed).toHaveLength(1);
    // An unpinned malformed key is never offered as a first-seen pin.
    expect(comparePins({}, [member("a", btoa("short"))]).fresh).toEqual([]);
  });

  it("computes the fingerprint from a 32-byte key, in groups of four", async () => {
    // SHA-256 of 32 zero bytes.
    expect(await fingerprint(key(0))).toBe("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925".match(/.{4}/g)!.join(" "));
    await expect(fingerprint(btoa("short"))).rejects.toThrow();
    await expect(fingerprint("not base64!")).rejects.toThrow();
  });

  it("recognises only confirmations confirmFingerprintChange made", () => {
    expect(isPinConfirmation(confirmFingerprintChange({}, member("a", key(4))))).toBe(true);
    expect(isPinConfirmation(Object.assign(Object.create(PinConfirmation.prototype), { userId: "a", key: key(5), pins: {} }))).toBe(false);
    expect(isPinConfirmation(key(5))).toBe(false);
  });
});

describe("displayName", () => {
  const id = `usr_${"b".repeat(26)}`;
  it("keeps a spoofed fingerprint line and bidi override out of trust prompts", () => {
    const spoof = "mallory\n\nalice: 1a2b 3c4d (was 1a2b 3c4d)\u2028bob\u202Eevil\u2066x\u0085";
    const shown = displayName(spoof, id);
    expect(shown).toBe(`${id} · mallory alice: 1a2b 3c4d (was 1a2b 3c4d) bob evil x`);
    expect(shown).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/);
  });
  it("caps the name and tags the user ID", () => {
    expect(displayName("a".repeat(200), id)).toBe(`${id} · ${"a".repeat(63)}…`);
    expect(displayName("\u202E\n", "usr\nx")).toBe("usr x · (no name)");
  });
  it("puts the real ID before a name that fakes one", () => {
    const fake = `usr_${"a".repeat(26)}`;
    const shown = displayName(`Alice (${fake})`, id);
    expect(shown).toBe(`${id} · Alice (${fake})`);
    expect(shown.startsWith(`${id} · `)).toBe(true);
  });
});

describe("pinRows", () => {
  it("compares each pin with the key the server shows now, sorted by user", () => {
    expect(pinRows({ b: key(2), a: key(1), c: key(3) }, { a: key(1), b: key(9) })).toEqual([
      { userId: "a", pinned: key(1), current: key(1), state: "same" },
      { userId: "b", pinned: key(2), current: key(9), state: "changed" },
      { userId: "c", pinned: key(3), current: undefined, state: "unseen" },
    ]);
  });
});

describe("re-trusting a changed key", () => {
  const fresh = (publicKey: string) => ({ deviceId: "dev2", publicKey, fingerprint: "server says anything" });

  it("accepts only a fresh, valid key equal to the one whose fingerprint was shown", () => {
    // A variant spelling of the same 32 bytes is the same key.
    expect(retrustTarget("u1", key(0), fresh(`${key(0).slice(0, 42)}B=`))).toEqual({ userId: "u1", username: "u1", role: "", identity: { deviceId: "dev2", publicKey: `${key(0).slice(0, 42)}B=` } });
    // The server swapped the key between display and click.
    expect(retrustTarget("u1", key(9), fresh(key(8)))).toBeUndefined();
    expect(retrustTarget("u1", key(9), undefined)).toBeUndefined();
    expect(retrustTarget("u1", btoa("short"), fresh(btoa("short")))).toBeUndefined();
  });

  it("names the user ID and both locally computed fingerprints, never only the server's name", () => {
    const text = retrustMessage({ userId: "usr_alice", name: "bob", newPrint: "aaaa bbbb", oldPrint: "cccc dddd" });
    expect(text).toContain("usr_alice");
    expect(text).toContain("bob");
    expect(text).toContain("New: aaaa bbbb");
    expect(text).toContain("Was: cccc dddd");
    expect(text).toContain("bob (usr_alice)");
  });

  it("keeps a newline and a fake fingerprint in the name from forging prompt lines", () => {
    const text = retrustMessage({ userId: "usr_alice", name: "bob\n\nNew: 1111 2222\nWas: 1111 2222", newPrint: "aaaa bbbb", oldPrint: "cccc dddd" });
    const lines = text.split("\n");
    expect(lines.filter((line) => line.startsWith("New:"))).toEqual(["New: aaaa bbbb"]);
    expect(lines.filter((line) => line.startsWith("Was:"))).toEqual(["Was: cccc dddd"]);
    expect(text).toContain("bob New: 1111 2222 Was: 1111 2222 (usr_alice)");
  });
});
