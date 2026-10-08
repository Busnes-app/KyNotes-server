import { describe, expect, it, vi } from "vitest";
import { dropInvite, finalRefusal, inviteLink, keyRequestText, parseInviteLink, pendingInvite, sessionStore, takeInviteLink } from "./invitations";

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
    expect(takeInviteLink({ hash: `#/cnt_${"a".repeat(26)}`, pathname: "/" }, { replaceState }, storage)).toBeUndefined();
    expect(replaceState).not.toHaveBeenCalled();
    expect(takeInviteLink({ hash: `#/invite/${id}/${token}`, pathname: "/" }, { replaceState }, storage)).toEqual({ id, token });
    expect(replaceState).toHaveBeenCalledWith(null, "", "/");
    expect(storage.getItem("kynotes-invitation")).toBe(JSON.stringify({ id, token }));
    expect(pendingInvite(storage)).toEqual({ id, token });
    dropInvite(storage);
    expect(pendingInvite(storage)).toBeUndefined();
  });

  it("keeps the link in memory for this page load when session storage refuses it, and still clears the address bar", () => {
    const replaceState = vi.fn();
    const refusing = { setItem: () => { throw new Error("QuotaExceededError"); }, getItem: () => null, removeItem: () => undefined };
    expect(takeInviteLink({ hash: `#/invite/${id}/${token}`, pathname: "/app" }, { replaceState }, refusing)).toEqual({ id, token });
    expect(replaceState).toHaveBeenCalledWith(null, "", "/app");
    expect(pendingInvite(refusing)).toEqual({ id, token });
    dropInvite(refusing);
    expect(pendingInvite(refusing)).toBeUndefined();
  });

  it("works with session storage unavailable altogether", () => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
    Object.defineProperty(globalThis, "sessionStorage", { configurable: true, get: () => { throw new DOMException("denied", "SecurityError"); } });
    try {
      expect(sessionStore()).toBeUndefined();
      const replaceState = vi.fn();
      expect(takeInviteLink({ hash: `#/invite/${id}/${token}`, pathname: "/" }, { replaceState }, sessionStore())).toEqual({ id, token });
      expect(replaceState).toHaveBeenCalledWith(null, "", "/");
      expect(pendingInvite(sessionStore())).toEqual({ id, token });
      dropInvite(sessionStore());
      expect(pendingInvite(sessionStore())).toBeUndefined();
    } finally {
      if (descriptor) Object.defineProperty(globalThis, "sessionStorage", descriptor);
      else delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
    }
  });

  it("ignores a tampered stash", () => {
    const storage = memory();
    storage.setItem("kynotes-invitation", JSON.stringify({ id: "inv_x", token }));
    expect(pendingInvite(storage)).toBeUndefined();
    storage.setItem("kynotes-invitation", "{not json");
    expect(pendingInvite(storage)).toBeUndefined();
  });

  it("drops an invitation only on a definitive refusal; network errors, 5xx and 429 keep it for a retry", () => {
    for (const status of [403, 404, 409, 410]) expect(finalRefusal(status)).toBe(true);
    for (const status of [undefined, 429, 500, 502, 503]) expect(finalRefusal(status)).toBe(false);
  });

  it("writes a key request that names the stewards and carries the fingerprint and link", () => {
    const text = keyRequestText({ notebook: "Plans", stewards: ["alice", "bob"], fingerprint: "abcd ef01", link: "https://notes.example/#/cnt_x" });
    expect(text).toContain("alice or bob");
    expect(text).toContain("abcd ef01");
    expect(text).toContain("https://notes.example/#/cnt_x");
    expect(keyRequestText({ notebook: "Plans", stewards: [], fingerprint: "", link: "l" })).toContain("a team owner");
  });
});
