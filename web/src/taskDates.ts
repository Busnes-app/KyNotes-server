// Plain-word task dates inside checklist text: due:2026-11-01 repeat:monthly remind:2026-11-01T09:00.
// Everything here is pure and runs on decrypted text in the browser only.

export type Repeat = { unit: "day" | "week" | "month" | "year"; every: number };
export type TaskDates = { text: string; due?: string; repeat?: Repeat; remind?: string };
export type TaskGroup = "overdue" | "today" | "upcoming" | "later" | "undated";
export const TASK_GROUPS: Array<[TaskGroup, string]> = [["overdue", "Overdue"], ["today", "Today"], ["upcoming", "Upcoming"], ["later", "Later"], ["undated", "No date"]];

const pad = (value: number, size = 2) => String(value).padStart(size, "0");
const UNITS: Record<string, Repeat> = { daily: { unit: "day", every: 1 }, weekly: { unit: "week", every: 1 }, monthly: { unit: "month", every: 1 }, yearly: { unit: "year", every: 1 } };

function validDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return false;
  const [y, m, d] = match.slice(1).map(Number);
  const date = new Date(Date.UTC(y, m - 1, d));
  return date.getUTCFullYear() === y && date.getUTCMonth() === m - 1 && date.getUTCDate() === d;
}

function parseRepeat(value: string): Repeat | undefined {
  if (UNITS[value]) return UNITS[value];
  const match = /^every-(\d{1,3})-(days|weeks)$/.exec(value);
  const every = Number(match?.[1]);
  return match && every >= 1 && every <= 365 ? { unit: match[2] === "days" ? "day" : "week", every } : undefined;
}

export function repeatToken(repeat: Repeat): string {
  if (repeat.every === 1) return `repeat:${Object.keys(UNITS).find((key) => UNITS[key].unit === repeat.unit)}`;
  return `repeat:every-${repeat.every}-${repeat.unit}s`;
}

type Token = { key: "due" | "repeat" | "remind"; start: number; end: number };

/** Valid tokens with their character ranges; the first valid token of each key wins, later ones stay text. */
export function findTokens(text: string): Array<Token & { value: string }> {
  const found: Array<Token & { value: string }> = [];
  for (const match of text.matchAll(/\S+/g)) {
    const word = /^(due|repeat|remind):(\S+)$/.exec(match[0]);
    if (!word || found.some((token) => token.key === word[1])) continue;
    const [, key, value] = word;
    const valid = key === "due" ? validDate(value)
      : key === "repeat" ? Boolean(parseRepeat(value))
      : /^(\d{4}-\d{2}-\d{2})T([01]\d|2[0-3]):[0-5]\d$/.test(value) && validDate(value.slice(0, 10));
    if (valid) found.push({ key: key as Token["key"], value, start: match.index, end: match.index + match[0].length });
  }
  return found;
}

export function parseTaskDates(raw: string): TaskDates {
  const task: TaskDates = { text: "" };
  let text = raw;
  for (const token of findTokens(raw).reverse()) {
    if (token.key === "repeat") task.repeat = parseRepeat(token.value);
    else task[token.key] = token.value;
    text = text.slice(0, token.start) + text.slice(token.end);
  }
  task.text = text.replace(/\s+/g, " ").trim();
  return task;
}

export function localDate(now: Date): string {
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}

/**
 * Advances a calendar date. Months and years clamp to the month's end (2026-01-31 monthly is
 * 2026-02-28), and the next step starts from the clamped day (then 2026-03-28), so a series
 * that starts on the 29th-31st drifts to the shortest month it crossed.
 */
export function addRepeat(date: string, repeat: Repeat): string {
  const [y, m, d] = date.split("-").map(Number);
  if (repeat.unit === "day" || repeat.unit === "week") {
    const next = new Date(Date.UTC(y, m - 1, d + repeat.every * (repeat.unit === "week" ? 7 : 1)));
    return `${pad(next.getUTCFullYear(), 4)}-${pad(next.getUTCMonth() + 1)}-${pad(next.getUTCDate())}`;
  }
  const months = (m - 1) + repeat.every * (repeat.unit === "year" ? 12 : 1);
  const year = y + Math.floor(months / 12);
  const month = months % 12;
  const last = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  return `${pad(year, 4)}-${pad(month + 1)}-${pad(Math.min(d, last))}`;
}

/** The next occurrence's due and remind; with no due date, the due date advances from today. */
export function nextOccurrence(task: TaskDates, today: string): { due?: string; remind?: string } {
  if (!task.repeat) return {};
  return {
    due: addRepeat(task.due ?? today, task.repeat),
    remind: task.remind && `${addRepeat(task.remind.slice(0, 10), task.repeat)}${task.remind.slice(10)}`,
  };
}

/** Local wall-clock reminder time in epoch ms. */
export function remindAt(remind: string): number {
  const [y, m, d] = remind.slice(0, 10).split("-").map(Number);
  return new Date(y, m - 1, d, Number(remind.slice(11, 13)), Number(remind.slice(14, 16))).getTime();
}

/** A missed reminder counts as overdue; upcoming is the next 7 days. */
export function classifyTask(task: TaskDates, now: Date, missedReminder = false): TaskGroup {
  if (missedReminder) return "overdue";
  if (!task.due) return "undated";
  const today = localDate(now);
  if (task.due < today) return "overdue";
  if (task.due === today) return "today";
  return task.due <= addRepeat(today, { unit: "day", every: 7 }) ? "upcoming" : "later";
}

export type ReminderPlan = { fire: string[]; missed: Set<string>; next?: number };

/**
 * Which reminders fire now. A reminder fires once, only if its time passed after `since` (this tab
 * opened) and reminders are on; any other passed, unfired reminder is missed and never fires.
 */
export function planReminders(tasks: Array<{ key: string; remind?: string }>, now: number, since: number, fired: ReadonlySet<string>, enabled: boolean): ReminderPlan {
  const plan: ReminderPlan = { fire: [], missed: new Set() };
  for (const { key, remind } of tasks) {
    if (!remind || fired.has(key)) continue;
    const at = remindAt(remind);
    if (at > now) plan.next = Math.min(plan.next ?? at, at);
    else if (enabled && at > since) plan.fire.push(key);
    else plan.missed.add(key);
  }
  return plan;
}

// --- Recurrence in BlockNote blocks ---

export type InlineNode = { type?: string; text?: string; [key: string]: unknown };
export type TaskBlock = { id?: string; type?: string; props?: Record<string, unknown>; content?: unknown; children?: TaskBlock[] };
export type RecurrenceEdit = { id: string; content: InlineNode[]; next: { type: "checkListItem"; props: { checked: false }; content: InlineNode[] } };

const MAX_DEPTH = 100;

/** Replaces character ranges of the joined text, keeping each node's styles; inserted text joins the node it starts in. */
function rewrite(content: InlineNode[], edits: Array<{ start: number; end: number; text: string }>): InlineNode[] {
  const last = content.map((node) => typeof node.text === "string").lastIndexOf(true);
  let offset = 0;
  return content.map((node, position) => {
    if (typeof node.text !== "string") return node;
    const from = offset;
    offset += node.text.length;
    let text = "";
    // The last text node also takes insertions at the very end.
    for (let index = from; index < offset + (position === last ? 1 : 0); index += 1) {
      for (const edit of edits) if (edit.start === index) text += edit.text;
      if (index < offset && !edits.some((edit) => index >= edit.start && index < edit.end)) text += node.text[index - from];
    }
    return { ...node, text };
  }).filter((node) => node.text !== "");
}

const textOf = (content: InlineNode[]) => content.map((node) => typeof node.text === "string" ? node.text : "").join("");
/** The token plus the whitespace before it (or after it, at the start). */
const cut = (text: string, token: Token) => {
  const before = /\s$/.test(text.slice(0, token.start)) ? 1 : 0;
  const after = before || !/^\s/.test(text.slice(token.end)) ? 0 : 1;
  return { start: token.start - before, end: token.end + after };
};

/**
 * For every checked checklist item carrying a repeat token: drop the token from it and add an
 * unchecked copy after it with due/remind advanced. A completed item loses its token, so running
 * this again on the result finds nothing.
 */
export function recurrenceEdits(blocks: TaskBlock[], today: string): RecurrenceEdit[] {
  const edits: RecurrenceEdit[] = [];
  const visit = (block: TaskBlock, depth: number) => {
    if (depth > MAX_DEPTH) return;
    if (block.type === "checkListItem" && block.props?.checked === true && block.id && Array.isArray(block.content)) {
      const content: InlineNode[] = block.content;
      const text = textOf(content);
      const tokens = findTokens(text);
      const repeat = tokens.find((token) => token.key === "repeat");
      if (repeat) {
        const next = nextOccurrence(parseTaskDates(text), today);
        const advanced = tokens.flatMap(({ key, start, end }) => key === "repeat" ? [] : [{ start, end, text: `${key}:${next[key]}` }]);
        if (!tokens.some((token) => token.key === "due")) advanced.push({ start: text.length, end: text.length, text: `${/\S$/.test(text) ? " " : ""}due:${next.due}` });
        edits.push({ id: block.id, content: rewrite(content, [{ ...cut(text, repeat), text: "" }]), next: { type: "checkListItem", props: { checked: false }, content: rewrite(content, advanced) } });
      }
    }
    block.children?.forEach((child) => visit(child, depth + 1));
  };
  blocks.forEach((block) => visit(block, 0));
  return edits;
}
