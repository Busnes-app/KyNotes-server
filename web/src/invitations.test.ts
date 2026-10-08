import { describe, expect, it, vi } from "vitest";
import { clearStashedInvite, inviteLink, keyRequestText, parseInviteLink, stashInviteLink, stashedInvite } from "./invitations";

const id = `inv_${"a".repeat(26)}`;
const token = `${"A-_z".repeat(10)}abc`; // 43 base64url characters
const memory = () => {
  const items = new Map<string, string>();
  return { getItem: (key: string) => items.get(key) ?? null, setItem: (key: string, value: string) => void items.set(key, value), removeItem: (key: string) => void items.delete(key) };
};

describe("invitation links", () => {
  it("round-trips an invitation through its link and rejects anything else", () => {
    const link = inviteLink("https://notes.example", { id, token });
    expect(link).toBe(`https://notes.example/#/invite/${id}/${token}`);
    expect(parseInviteLink(new URL(link).hash)).toEqual({ id, token });
    for (const hash of ["", `#/invite/${id}`, `#/invite/${id}/${token}x`, `#/invite/inv_short/${token}`, `#/invite/${id}/${token.slice(1)}=`, `#/cnt_${"a".repeat(26)}`]) {
      expect(parseInviteLink(hash)).toBeUndefined();
    }
  });

  it("moves a link from the address bar into session storage, and only a link", () => {
    const storage = memory();
    const replaceState = vi.fn();
    expect(stashInviteLink({ hash: `#/cnt_${"a".repeat(26)}`, pathname: "/" }, { replaceState }, storage)).toBe(false);
    expect(replaceState).not.toHaveBeenCalled();
    expect(stashInviteLink({ hash: `#/invite/${id}/${token}`, pathname: "/" }, { replaceState }, storage)).toBe(true);
    expect(replaceState).toHaveBeenCalledWith(null, "", "/");
    expect(stashedInvite(storage)).toEqual({ id, token });
    clearStashedInvite(storage);
    expect(stashedInvite(storage)).toBeUndefined();
  });

  it("clears the address bar even when session storage refuses the link", () => {
    const replaceState = vi.fn();
    const refusing = { setItem: () => { throw new Error("QuotaExceededError"); } };
    expect(() => stashInviteLink({ hash: `#/invite/${id}/${token}`, pathname: "/app" }, { replaceState }, refusing)).toThrow();
    expect(replaceState).toHaveBeenCalledWith(null, "", "/app");
  });

  it("ignores a tampered stash", () => {
    const storage = memory();
    storage.setItem("kynotes-invitation", JSON.stringify({ id: "inv_x", token }));
    expect(stashedInvite(storage)).toBeUndefined();
    storage.setItem("kynotes-invitation", "{not json");
    expect(stashedInvite(storage)).toBeUndefined();
  });

  it("writes a key request that names the stewards and carries the fingerprint and link", () => {
    const text = keyRequestText({ notebook: "Plans", stewards: ["alice", "bob"], fingerprint: "abcd ef01", link: "https://notes.example/#/cnt_x" });
    expect(text).toContain("alice or bob");
    expect(text).toContain("abcd ef01");
    expect(text).toContain("https://notes.example/#/cnt_x");
    expect(keyRequestText({ notebook: "Plans", stewards: [], fingerprint: "", link: "l" })).toContain("a team owner");
  });
});
