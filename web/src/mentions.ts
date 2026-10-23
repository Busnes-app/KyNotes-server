import type { Member } from "./keyring";

/**
 * The members a comment mentions: each `@username` that stands as its own word (case-insensitive),
 * once each, the author left out. The server refuses a mention of anyone who is not a member.
 */
export function mentionedUserIDs(text: string, members: readonly Member[], author: string): string[] {
  return members
    .filter((member) => member.userId !== author && mentionPattern(member.username).test(text))
    .map((member) => member.userId);
}

// "@bob," and "@bob." mention bob; "@bobby" and "@bob.smith" do not.
const mentionPattern = (username: string) =>
  new RegExp(`(^|\\s)@${username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}\\p{N}_-]|\\.[\\p{L}\\p{N}])`, "iu");
