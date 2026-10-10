/** Why the first-run form may not be sent yet, or undefined. The server never sees either password, so this is the only place they are compared. */
export function setupProblem(input: { admin: string; adminPassword: string; adminConfirm: string; everyday: string; everydayPassword: string; everydayConfirm: string }): string | undefined {
  const admin = input.admin.trim().toLowerCase();
  const everyday = input.everyday.trim().toLowerCase();
  if (!admin || !everyday) return "Both usernames are required.";
  if (admin === everyday) return "Use a different username for each account.";
  if (input.adminPassword !== input.adminConfirm || input.everydayPassword !== input.everydayConfirm) return "Passwords do not match.";
  if (input.adminPassword.length < 8 || input.everydayPassword.length < 8) return "Passwords must be at least 8 characters.";
  if (input.adminPassword === input.everydayPassword) return "Use a different password for each account.";
  return undefined;
}
