const dayStart = (date: Date) => new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();

/** A page row's date as a notes app shows it: today's time, Yesterday, a weekday this week, else the date. */
export function relativeDate(iso: string, now = new Date()): string {
  const date = new Date(iso);
  if (!iso || Number.isNaN(date.getTime())) return "";
  const days = Math.round((dayStart(now) - dayStart(date)) / 86_400_000);
  if (days <= 0) return date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (days === 1) return "Yesterday";
  if (days < 7) return date.toLocaleDateString([], { weekday: "long" });
  return date.toLocaleDateString([], date.getFullYear() === now.getFullYear() ? { month: "short", day: "numeric" } : { month: "short", day: "numeric", year: "numeric" });
}
