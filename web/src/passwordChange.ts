/** Why the change form may not be submitted yet, or undefined when it may. */
export function passwordChangeProblem(next: string, confirmation: string): string | undefined {
  if (!next || next !== confirmation) return "New passwords do not match.";
  return undefined;
}
