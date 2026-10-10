import { describe, expect, it } from "vitest";
import { queuedNotice, resetNotice, STEWARD_NO_KEY, STEWARD_SHARED, STEWARD_UNKEYED, stewardOf, UNRECOVERABLE, WAITING, waitingNotice } from "./keyNotices";

const me = "usr_me";
const base = { held: true, recoverable: true, shared: false };

describe("key waiting copy", () => {
  it("decides by this user's role in the member list, never by kind", () => {
    expect(stewardOf([{ userId: me, role: "owner" }], me)).toBe(true);
    expect(stewardOf([{ userId: "usr_o", role: "owner" }, { userId: me, role: "admin" }], me)).toBe(true);
    expect(stewardOf([{ userId: "usr_o", role: "owner" }, { userId: me, role: "editor" }], me)).toBe(false);
    expect(stewardOf(undefined, me)).toBeUndefined();
  });

  it("tells only a non-steward to wait for a team owner", () => {
    expect(waitingNotice({ ...base, steward: false })).toEqual({ text: WAITING, action: "ask" });
    expect(queuedNotice(false)).toMatch(/team owner/);
    for (const steward of [true, undefined]) {
      expect(waitingNotice({ ...base, steward }).text).not.toMatch(/team owner/);
      expect(queuedNotice(steward)).not.toMatch(/team owner/);
    }
  });

  it("points an owner (every personal notebook) at what this browser or account lacks", () => {
    expect(waitingNotice({ ...base, steward: true, held: false })).toEqual({ text: STEWARD_NO_KEY, action: "settings" });
    expect(waitingNotice({ ...base, steward: true, recoverable: false })).toEqual({ text: UNRECOVERABLE, action: "settings" });
    expect(waitingNotice({ ...base, steward: true })).toEqual({ text: STEWARD_UNKEYED });
    expect(waitingNotice({ ...base, steward: true, shared: true })).toEqual({ text: STEWARD_SHARED, action: "ask" });
  });
});

describe("resetNotice", () => {
  it("names the member whose reset most recently retired the key, and nothing without one", () => {
    const at = "2026-10-08T10:00:00Z";
    const later = "2026-10-08T12:00:00Z";
    const members = [
      { userId: `usr_${"a".repeat(26)}`, username: "ann" },
      { userId: `usr_${"b".repeat(26)}`, username: "bob", keyResetAt: at },
      { userId: `usr_${"c".repeat(26)}`, username: "cat", keyResetAt: later },
    ];
    const notice = resetNotice(members)!;
    expect(notice).toMatch(new RegExp(`^usr_${"c".repeat(26)} · cat reset their encryption key on .*retired this notebook.s key`));
    expect(notice).toContain(new Date(later).toLocaleString());
    expect(resetNotice(members.slice(0, 1))).toBeUndefined();
  });
});
