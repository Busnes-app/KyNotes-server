import type { Invitation } from "./api";

/** An invitation as its link carries it; the server checks the token and that the session is the invitee. */
export type InviteLink = Pick<Invitation, "id" | "token">;
const LINK = /^#\/invite\/(inv_[0-9a-hjkmnp-tv-z]{26})\/([A-Za-z0-9_-]{43})$/;
const KEY = "kynotes-invitation";

/** The one-time link; the token travels in the fragment, which browsers never send to the server. */
export const inviteLink = (origin: string, invitation: InviteLink) => `${origin}/#/invite/${invitation.id}/${invitation.token}`;

export function parseInviteLink(hash: string): InviteLink | undefined {
  const match = LINK.exec(hash);
  return match ? { id: match[1], token: match[2] } : undefined;
}

/**
 * Moves an invitation link out of the address bar (and history) into this tab's session storage,
 * so it survives a sign-in that leaves the page (single sign-on). True when there was one.
 */
export function stashInviteLink(location: Pick<Location, "hash" | "pathname">, history: Pick<History, "replaceState">, storage: Pick<Storage, "setItem">): boolean {
  const link = parseInviteLink(location.hash);
  if (!link) return false;
  storage.setItem(KEY, JSON.stringify(link));
  history.replaceState(null, "", location.pathname);
  return true;
}

/** The stashed invitation, re-validated: storage is not trusted to hold what was written. */
export function stashedInvite(storage: Pick<Storage, "getItem">): InviteLink | undefined {
  try {
    const value = JSON.parse(storage.getItem(KEY) ?? "null") as Partial<InviteLink> | null;
    return value ? parseInviteLink(`#/invite/${value.id}/${value.token}`) : undefined;
  } catch {
    return undefined;
  }
}

export const clearStashedInvite = (storage: Pick<Storage, "removeItem">) => storage.removeItem(KEY);

/** What a member waiting for keys sends an owner or admin, out of band. */
export function keyRequestText(input: { notebook: string; stewards: string[]; fingerprint: string; link: string }): string {
  const who = input.stewards.length ? input.stewards.join(" or ") : "a team owner";
  const key = input.fingerprint ? ` My encryption key fingerprint is ${input.fingerprint}; please check it matches what your browser shows for me.` : "";
  return `Hi ${who}: please open the team notebook "${input.notebook}" in KyNotes so your browser shares its key with me.${key} ${input.link}`;
}
