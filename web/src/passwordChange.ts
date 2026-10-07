// ponytail: stopgap until shared keys (team-keys P3/P5) stop deriving content keys from the password.
export const PASSWORD_CHANGE_WARNING =
  "Your notes are encrypted with keys derived from your current password. After a password change, notes you already have become unreadable, even if you change it back, until shared keys arrive in a later release.";

/** Why the change form may not be submitted yet, or undefined when it may. */
export function passwordChangeProblem(next: string, confirmation: string, acknowledged: boolean): string | undefined {
  if (!next || next !== confirmation) return "New passwords do not match.";
  if (!acknowledged) return "Confirm that you understand existing notes become unreadable.";
  return undefined;
}
