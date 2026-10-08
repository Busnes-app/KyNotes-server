import { isSteward, type Member } from "./keyring";
import { displayName } from "./pins";

/**
 * Whether this user is an owner or admin of the open notebook, from its member list (never from kind:
 * a personal notebook's only member is its owner). undefined while this tab has no member list for it.
 */
export const stewardOf = (members: ReadonlyArray<Pick<Member, "userId" | "role">> | undefined, me: string): boolean | undefined => {
  if (!members) return undefined;
  const self = members.find((member) => member.userId === me);
  return Boolean(self && isSteward(self.role));
};

export const WAITING = "This notebook is read-only until its keys reach this browser.";
export const UNRECOVERABLE = "This notebook gets its own key once your encryption key can be recovered. Save a recovery code in Settings first.";
export const STEWARD_NO_KEY = "This notebook is read-only here: this browser does not hold your encryption key. Link it, or restore your key with your recovery code, in Settings.";
export const STEWARD_SHARED = "This notebook is read-only until another owner's browser shares its current key with you.";
export const STEWARD_UNKEYED = "This notebook is read-only until its key is set up. Reopen it to try again.";

export type WaitingNotice = { text: string; action?: "ask" | "settings" };
/**
 * Why the open notebook is read-only for keys, and what helps. Only a member who cannot set keys up is
 * told to ask an owner; an owner (every personal notebook's user) is pointed at what this browser lacks.
 */
export function waitingNotice(input: { steward: boolean | undefined; held: boolean; recoverable: boolean; shared: boolean }): WaitingNotice {
  if (input.steward === undefined) return { text: WAITING };
  if (!input.steward) return { text: WAITING, action: "ask" };
  if (!input.held) return { text: STEWARD_NO_KEY, action: "settings" };
  if (input.shared) return { text: STEWARD_SHARED, action: "ask" };
  return input.recoverable ? { text: STEWARD_UNKEYED } : { text: UNRECOVERABLE, action: "settings" };
}

export const resetWhen = (at: string): string => new Date(at).toLocaleString();

/**
 * For owners and admins (the server sends keyResetAt to them only): the member whose own key reset
 * most recently retired this notebook's key, so the cause of a wait is visible.
 */
export function resetNotice(members: ReadonlyArray<Pick<Member, "userId" | "username" | "keyResetAt">>): string | undefined {
  const latest = members.filter((member) => member.keyResetAt).sort((a, b) => Date.parse(b.keyResetAt!) - Date.parse(a.keyResetAt!))[0];
  return latest && `${displayName(latest.username, latest.userId)} reset their encryption key on ${resetWhen(latest.keyResetAt!)}, which retired this notebook's key; an owner's next open shares a new one.`;
}

/** The toast after an edit is kept only on this device. */
export const queuedNotice = (steward: boolean | undefined): string => steward === false
  ? "Saved on this device only. It is sent once a team owner shares this notebook's keys; until then, do not clear this browser's data."
  : "Saved on this device only. It is sent once this notebook's key reaches this browser; until then, do not clear this browser's data.";
