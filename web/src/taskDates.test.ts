import { describe, expect, it } from "vitest";
import { addRepeat, classifyTask, nextOccurrence, parseTaskDates, planReminders, recurrenceEdits, remindAt, type RecurrenceEdit, type TaskBlock } from "./taskDates";
import { noteDatedTasks, noteTasks } from "./knowledge";
import { stringifyNoteDocument } from "./document";

const text = (value: string, styles = {}) => ({ type: "text", text: value, styles });
const item = (id: string, content: TaskBlock["content"], checked = true): TaskBlock => ({ id, type: "checkListItem", props: { checked }, content, children: [] });
const joined = (block: { content?: unknown }) => Array.isArray(block.content) ? block.content.map((node) => node.text).join("") : "";

/** The editor's application of the edits, over a plain block tree. */
function apply(blocks: TaskBlock[], edits: RecurrenceEdit[]): TaskBlock[] {
  const byID = new Map(edits.map((edit) => [edit.id, edit]));
  return blocks.flatMap((block) => {
    const edit = block.id ? byID.get(block.id) : undefined;
    const kept = { ...block, children: block.children && apply(block.children, edits), ...(edit && { content: edit.content }) };
    return edit ? [kept, { ...edit.next, id: `${block.id}-next`, children: [] }] : [kept];
  });
}

describe("task date tokens", () => {
  it("parses valid tokens and strips them from the shown text", () => {
    expect(parseTaskDates("Pay rent due:2026-11-01 repeat:monthly remind:2026-11-01T09:00")).toEqual({
      text: "Pay rent", due: "2026-11-01", repeat: { unit: "month", every: 1 }, remind: "2026-11-01T09:00",
    });
    expect(parseTaskDates("repeat:every-3-days Water plants").repeat).toEqual({ unit: "day", every: 3 });
    expect(parseTaskDates("x repeat:every-2-weeks").repeat).toEqual({ unit: "week", every: 2 });
  });

  it("leaves invalid tokens as text", () => {
    for (const raw of ["a due:2026-02-30", "a due:2026-13-01", "a repeat:hourly", "a repeat:every-0-days", "a repeat:every-366-days", "a remind:2026-11-01T24:00", "a remind:2026-11-01 09:00", "a Due:2026-11-01", "a repeat:Daily"])
      expect(parseTaskDates(raw)).toEqual({ text: raw });
    expect(parseTaskDates("a due:2024-02-29").due).toBe("2024-02-29");
    expect(parseTaskDates("a repeat:every-365-days").repeat).toEqual({ unit: "day", every: 365 });
  });

  it("opts a reminder into push with push:yes only beside a remind: time", () => {
    expect(parseTaskDates("Pay rent remind:2026-11-01T09:00 push:yes")).toEqual({ text: "Pay rent", remind: "2026-11-01T09:00", push: true });
    expect(parseTaskDates("push:yes Pay rent remind:2026-11-01T09:00").push).toBe(true);
    // Without a reminder time it means nothing.
    expect(parseTaskDates("Pay rent due:2026-11-01 push:yes")).toEqual({ text: "Pay rent", due: "2026-11-01" });
    // Anything but push:yes stays text and opts nothing in.
    for (const raw of ["a remind:2026-11-01T09:00 push:no", "a remind:2026-11-01T09:00 push:Yes", "a remind:2026-11-01T09:00 push:true", "a remind:2026-11-01T24:00 push:yes"])
      expect(parseTaskDates(raw).push, raw).toBeUndefined();
  });

  it("keeps push:yes on the next occurrence and the done item", () => {
    const [edit] = recurrenceEdits([item("a", [text("Pay rent remind:2026-11-01T09:00 push:yes repeat:monthly")])], "2026-10-17");
    expect(joined({ content: edit.next.content })).toBe("Pay rent remind:2026-12-01T09:00 push:yes repeat:monthly due:2026-11-17");
    expect(joined({ content: edit.content })).toBe("Pay rent remind:2026-11-01T09:00 push:yes");
  });

  it("keeps a second token of the same key as text", () => {
    expect(parseTaskDates("a due:2026-01-01 due:2026-02-01")).toEqual({ text: "a due:2026-02-01", due: "2026-01-01" });
  });

  it("advances dates, clamping months to their end", () => {
    expect(addRepeat("2026-12-31", { unit: "day", every: 1 })).toBe("2027-01-01");
    expect(addRepeat("2026-03-01", { unit: "week", every: 2 })).toBe("2026-03-15");
    expect(addRepeat("2026-01-31", { unit: "month", every: 1 })).toBe("2026-02-28");
    expect(addRepeat("2026-02-28", { unit: "month", every: 1 })).toBe("2026-03-28"); // from the clamped day
    expect(addRepeat("2026-11-15", { unit: "month", every: 3 })).toBe("2027-02-15");
    expect(addRepeat("2024-02-29", { unit: "year", every: 1 })).toBe("2025-02-28");
    expect(nextOccurrence(parseTaskDates("a due:2026-10-16 repeat:daily remind:2026-10-16T08:30"), "2026-10-17")).toEqual({ due: "2026-10-17", remind: "2026-10-17T08:30" });
    expect(nextOccurrence(parseTaskDates("a repeat:weekly"), "2026-10-17")).toEqual({ due: "2026-10-24", remind: undefined });
    expect(nextOccurrence(parseTaskDates("a due:2026-10-16"), "2026-10-17")).toEqual({});
  });

  it("classifies against the local day", () => {
    const now = new Date(2026, 9, 17, 23, 59);
    const group = (raw: string, missed = false) => classifyTask(parseTaskDates(raw), now, missed);
    expect(group("a due:2026-10-16")).toBe("overdue");
    expect(group("a due:2026-10-17")).toBe("today");
    expect(group("a due:2026-10-18")).toBe("upcoming");
    expect(group("a due:2026-10-24")).toBe("upcoming");
    expect(group("a due:2026-10-25")).toBe("later");
    expect(group("a")).toBe("undated");
    expect(group("a due:2026-12-01", true)).toBe("overdue");
  });
});

describe("reminder planning", () => {
  const at = (value: string) => remindAt(value);
  const since = at("2026-10-17T09:00");
  const tasks = [
    { key: "closed", remind: "2026-10-17T08:00" }, // passed before this tab opened
    { key: "open", remind: "2026-10-17T09:30" }, // passed while open
    { key: "soon", remind: "2026-10-17T11:00" },
    { key: "later", remind: "2026-10-18T11:00" },
    { key: "none" },
  ];
  it("fires once only what passed while the tab was open, and reports the next time", () => {
    const now = at("2026-10-17T10:00");
    const plan = planReminders(tasks, now, since, new Set(), true);
    expect(plan.fire).toEqual(["open"]);
    expect([...plan.missed]).toEqual(["closed"]);
    expect(plan.next).toBe(at("2026-10-17T11:00"));
    const again = planReminders(tasks, now, since, new Set(["open"]), true);
    expect(again.fire).toEqual([]);
    expect([...again.missed]).toEqual(["closed"]);
  });
  it("fires nothing while reminders are off; passed ones are missed", () => {
    const plan = planReminders(tasks, at("2026-10-17T10:00"), since, new Set(), false);
    expect(plan.fire).toEqual([]);
    expect([...plan.missed].sort()).toEqual(["closed", "open"]);
  });
});

describe("recurrence edits", () => {
  it("adds the next unchecked occurrence and drops repeat from the done item, once", () => {
    const blocks = [item("a", [text("Water "), text("plants", { bold: true }), text(" due:2026-10-16 repeat:daily remind:2026-10-16T08:00")])];
    const edits = recurrenceEdits(blocks, "2026-10-17");
    expect(edits).toHaveLength(1);
    const after = apply(blocks, edits);
    expect(after.map(joined)).toEqual(["Water plants due:2026-10-16 remind:2026-10-16T08:00", "Water plants due:2026-10-17 repeat:daily remind:2026-10-17T08:00"]);
    expect(after[1].props).toEqual({ checked: false });
    // Styles survive in both items.
    expect(after[0].content).toContainEqual(text("plants", { bold: true }));
    expect(after[1].content).toContainEqual(text("plants", { bold: true }));
    // Idempotent: the done item has no repeat, the new one is unchecked.
    expect(recurrenceEdits(after, "2026-10-17")).toEqual([]);
  });

  it("finds a token split across styled nodes and nested items, and ignores unchecked or plain ones", () => {
    const nested: TaskBlock = { id: "p", type: "paragraph", content: [], children: [item("b", [text("Report "), text("repeat:", { italic: true }), text("weekly")])] };
    const edits = recurrenceEdits([nested, item("c", [text("x repeat:daily")], false), item("d", [text("y repeat:fortnightly")])], "2026-10-17");
    expect(edits.map((edit) => edit.id)).toEqual(["b"]);
    expect(joined(edits[0])).toBe("Report");
    expect(joined(edits[0].next)).toBe("Report repeat:weekly due:2026-10-24"); // no due: from today
  });

  it("keeps links and other inline nodes in place", () => {
    const link = { type: "link", href: "https://example.test", content: [text("doc")] };
    const [edit] = recurrenceEdits([item("a", [text("Read "), link, text(" repeat:monthly due:2026-01-31")])], "2026-10-17");
    expect(edit.content).toEqual([text("Read "), link, text(" due:2026-01-31")]);
    expect(edit.next.content).toEqual([text("Read "), link, text(" repeat:monthly due:2026-02-28")]);
  });
});

describe("dated tasks from pages", () => {
  it("projects open checklist items with dates, cached per note object", () => {
    const body = stringifyNoteDocument([
      { type: "checkListItem", props: { checked: false }, content: [{ type: "text", text: "Pay rent due:2026-11-01 repeat:monthly", styles: {} }] },
      { type: "checkListItem", props: { checked: true }, content: [{ type: "text", text: "Done due:2026-10-01", styles: {} }] },
    ]);
    const note = { id: "a", title: "", body, updatedAt: "" };
    expect(noteTasks(note)).toEqual(["Pay rent due:2026-11-01 repeat:monthly"]);
    const [task] = noteDatedTasks(note);
    expect(task).toEqual({ text: "Pay rent", due: "2026-11-01", repeat: { unit: "month", every: 1 }, raw: "Pay rent due:2026-11-01 repeat:monthly" });
    expect(noteDatedTasks(note)[0]).toBe(task);
    expect(noteDatedTasks({ id: "b", title: "", body: "- [ ] Call due:2026-10-18", updatedAt: "" })[0].due).toBe("2026-10-18");
  });
});
