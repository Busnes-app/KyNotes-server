import { describe, expect, it } from "vitest";
import { comparePins, fingerprint } from "./pins";

const member = (id: string, publicKey?: string) => ({ userId: id, username: id, role: "editor", identity: publicKey ? { deviceId: "dev", publicKey } : undefined });

describe("pins", () => {
  it("separates first-seen and changed keys and ignores members without one", () => {
    const result = comparePins({ a: "K1", b: "K2" }, [member("a", "K1"), member("b", "K9"), member("c", "K3"), member("d")]);
    expect(result.fresh.map((entry) => entry.userId)).toEqual(["c"]);
    expect(result.changed).toEqual([{ member: member("b", "K9"), pinned: "K2" }]);
  });
  it("computes the fingerprint from the key, in groups of four", async () => {
    // SHA-256 of 32 zero bytes.
    expect(await fingerprint(btoa(String.fromCharCode(...new Uint8Array(32))))).toBe("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925".match(/.{4}/g)!.join(" "));
  });
});
