import { describe, expect, it } from "vitest";
import { comparePins, fingerprint, sameKey } from "./pins";

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
});
