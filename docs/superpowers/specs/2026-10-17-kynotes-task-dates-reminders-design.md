# KyNotes tasks: due dates, recurrence, reminders (design, decided)

Status: **decided 2026-10-17 by Yoshi: option B (opt-in server reminder time) and plain-word syntax.**
§1 is amended by the syntax decision: items read `[ ] Pay rent due:2026-11-01 repeat:monthly remind:2026-11-01T09:00`.

Build order:
1. Plain-word dates, recurrence, the dated work queue and in-tab notifications. These are client-only and leak nothing.
2. The opt-in "remind me even when KyNotes is closed" store plus content-free delivery. Browsers get Web Push with VAPID, implemented with the standard library and no new dependency. FCM and APNs wait for the KyPost relay (IMPLEMENTATION_PLAN.md §15).

- PROMPT.md and DESIGN.md:88 promise due dates, recurrence and reminders.
- IMPLEMENTATION_PLAN.md §8 says the server parses no tasks or dates; task views are built in
  the client.
- Today the web client finds open checklist items (`knowledge.ts` `parseTasks`) and has no
  dates.

## 1. Where the data lives (both options)

Dates go **inside the encrypted page**, as plain text in the checklist item. We use the
Obsidian Tasks convention, so the Markdown export (PR #82) works in other tools unchanged:

```
[ ] Pay rent 📅 2026-11-01 🔁 every month ⏰ 2026-11-01 09:00
```

- **Fields:**
  - `📅 YYYY-MM-DD`: due date.
  - `🔁 every day|week|month|year` and `every N days|weeks`: recurrence.
  - `⏰ YYYY-MM-DD HH:mm`: reminder, in the browser's local time.
- **Typing:** the editor gets a small "Due…" control that inserts the text, so nobody has to
  type emoji.
- **Recurrence:** ticking a recurring item adds the next unchecked occurrence below it, in the
  same save. No server involvement and no new schema.
- **Work queue:** shows Overdue, Today, Upcoming and No date, built from decrypted pages only.

## 2. The privacy question

**The server cannot remind about a date it cannot read.** The only ways to fire a reminder
while no KyNotes tab is open are:

- the server knows when, or
- another device the user owns (a phone app) knows when.

## 3. Options — **Yoshi picks one**

### A. Client-side only (recommended)

- **Reminders while a tab is open:** an open KyNotes tab (any notebook) schedules web
  notifications for the reminders it can decrypt. They are re-planned after every load and
  sync.
- **Notification text:** "A task is due", with the page title only when the user turns that
  on. The default shows no content on the lock screen.
- **Tab closed:** reminders that fired while every tab was closed show as "missed" on next open.
- **Server:** nothing new. It learns nothing about dates.
- **Mobile:** mobile clients later do the same with OS local notifications. That is still
  client-side, and push is never needed for it.
- **Cost:** a browser alone does not wake the user when no tab is open.

### B. Opt-in plaintext reminder times (deliberate leak)

- **What the server stores:** per task the user explicitly marks "Remind me even when
  KyNotes is closed", the client sends one row: `{reminderId (random), at (UTC minute)}`. There
  is no page, task id, title or notebook in it.
- **Delivery:** at that time the server sends a content-free push or Web Push that wakes the
  client, which then decrypts and shows the reminder itself.
- **What leaks:**
  - when the user has reminders, and how many;
  - which account owns them;
  - push delivery metadata to FCM, APNs or the browser vendor.
- **Cost:**
  - new tables and routes, plus a scheduler;
  - an extension of the Phase 9 push payload, whose contract today allows only
    `kynotes.changes`;
  - KyPost relay endpoints, which are still undefined (IMPLEMENTATION_PLAN.md §15).
- **Default:** off, per task, with copy that names the leak.

## 4. Decision needed

1. **A or B.** The recommendation is A. B can be added later without changing the stored task
   format.
2. **Syntax:** the Obsidian Tasks emoji (portable) or plain words (`due:2026-11-01`)?
