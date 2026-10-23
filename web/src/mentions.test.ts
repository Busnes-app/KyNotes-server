import { describe, expect, it } from "vitest";
import { mentionedUserIDs } from "./mentions";

const member = (userId: string, username: string) => ({ userId, username, role: "editor" });
const team = [member("usr_me", "me"), member("usr_bob", "bob"), member("usr_bs", "bob.smith"), member("usr_ann", "Ann")];

describe("mentionedUserIDs", () => {
  it("finds each member named as @username once, never the author", () => {
    expect(mentionedUserIDs("@bob, ask @ann and @bob. cc @me", team, "usr_me")).toEqual(["usr_bob", "usr_ann"]);
  });
  it("ignores partial names, addresses and non-members", () => {
    expect(mentionedUserIDs("mail bob@example.com, @bobby or @carol", team, "usr_me")).toEqual([]);
    expect(mentionedUserIDs("@bob.smith please", team, "usr_me")).toEqual(["usr_bs"]);
  });
});
