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

// The link as taken at load or hashchange, for this page load: session storage may refuse it.
let pageInvite: InviteLink | undefined;

/** sessionStorage, or undefined where the browser refuses access to it. */
export function sessionStore(): Storage | undefined {
  try { return globalThis.sessionStorage; } catch { return undefined; }
}

/**
 * Moves an invitation link out of the address bar and this tab's session-history entry into its
 * session storage, so it survives a sign-in that leaves the page (single sign-on), and into memory,
 * so this page load keeps it even when storage is refused. Returns it, or undefined when there is none.
 */
export function takeInviteLink(location: Pick<Location, "hash" | "pathname">, history: Pick<History, "replaceState">, storage: Pick<Storage, "setItem"> | undefined): InviteLink | undefined {
  const link = parseInviteLink(location.hash);
  if (!link) return undefined;
  pageInvite = link;
  try { storage?.setItem(KEY, JSON.stringify(link)); } catch { /* kept in memory for this page load */ }
  history.replaceState(null, "", location.pathname);
  return link;
}

/** The pending invitation: the stashed one, re-validated (storage is not trusted to hold what was written), else this page load's. */
export function pendingInvite(storage: Pick<Storage, "getItem"> | undefined): InviteLink | undefined {
  try {
    const value = JSON.parse(storage?.getItem(KEY) ?? "null") as Partial<InviteLink> | null;
    const stashed = value ? parseInviteLink(`#/invite/${value.id}/${value.token}`) : undefined;
    if (stashed) return stashed;
  } catch { /* an unreadable stash is no invitation */ }
  return pageInvite;
}

export function dropInvite(storage: Pick<Storage, "removeItem"> | undefined) {
  pageInvite = undefined;
  try { storage?.removeItem(KEY); } catch { /* nothing kept */ }
}

/**
 * A definitive answer to an accept: the invitation is gone (404 not_found, 410) or the account is
 * already a member (409 already_exists). Anything else may pass and keeps it: network, 5xx, 429,
 * and every 403 (csrf_failed, an expired session).
 */
export const finalRefusal = (status: number | undefined, code: string | undefined) =>
  (status === 404 && code === "not_found") || (status === 409 && code === "already_exists") || status === 410;

/** What a member waiting for keys sends an owner or admin, out of band. */
export function keyRequestText(input: { notebook: string; stewards: string[]; fingerprint: string; link: string }): string {
  const who = input.stewards.length ? input.stewards.join(" or ") : "a team owner";
  const key = input.fingerprint ? ` My encryption key fingerprint is ${input.fingerprint}; please check it matches what your browser shows for me.` : "";
  return `Hi ${who}: please open the team notebook "${input.notebook}" in KyNotes so your browser shares its key with me.${key} ${input.link}`;
}
