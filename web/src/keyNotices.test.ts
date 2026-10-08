import { describe, expect, it } from "vitest";
import { queuedNotice, STEWARD_NO_KEY, STEWARD_SHARED, STEWARD_UNKEYED, stewardOf, UNRECOVERABLE, WAITING, waitingNotice } from "./keyNotices";

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
