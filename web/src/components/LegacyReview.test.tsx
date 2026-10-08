import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { APIRequestError } from "../api";
import { encryptAttachment, encryptAttachmentMetadata, encryptComment, encryptNote, base64, legacyKeyRef } from "../crypto";
import { isReopenConfirmation, type ReopenConfirmation } from "../keyring";
import { approveMigration, isMigrationApproval, reviewLegacy, type LegacyReview as Review, type MigrationApproval, type Migrated, type ReviewAPI } from "../migration";
import {
  checkFailure, LEGACY_BLOCKED, LEGACY_LEFT_BEHIND, LEGACY_STILL_OPEN, SAVE_COPY, TICK_IT, LEGACY_CHECKING, LEGACY_CLOSED, LEGACY_INCOMPLETE, LEGACY_LABEL, LEGACY_SHARE_INCOMPLETE, LEGACY_UNCHECKED, LegacyItems, legacyLeave, LegacyReview,
  REOPEN_CONFIRM, REOPEN_LEGACY, REVIEW_BLOCKED, SHARE_BUTTON, shareOutcomeText, STOP_BUTTON, submitReopen, submitShare, TICK_THESE, tickThese,
} from "./LegacyReview";

const cnt = `cnt_${"a".repeat(26)}`;
const me = `usr_${"a".repeat(26)}`;
const mine = legacyKeyRef("a".repeat(64));
const id = (prefix: string, c: string) => `${prefix}_${c.repeat(26)}`;
const container = { id: cnt, kind: "team", keyGeneration: 2, sharedGeneration: 2 };

/** A real (branded) review of a page, a comment, a PNG, an SVG and a conflict, all this user's. */
async function review(complete = true): Promise<Review> {
  const page = await encryptNote(mine, cnt, { type: "page", title: "Budget", body: "Line one of the budget" });
  const png = await encryptAttachment(mine, cnt, new Uint8Array([137, 80, 78, 71]));
  const svg = await encryptAttachment(mine, cnt, new Uint8Array([60]));
  const conflict = await encryptNote(mine, cnt, { type: "page", title: "Old budget", body: "Older line" });
  const api: ReviewAPI = {
    legacyRows: async () => ({
      complete,
      objects: [{ id: id("obj", "a"), version: 3, keyGeneration: 1 }],
      comments: [{ id: id("cmt", "a"), objectId: id("obj", "a"), authorUserId: me, bodyCiphertext: base64(await encryptComment(mine, cnt, "Check the totals")), keyGeneration: 1 }],
      attachments: [
        { id: id("att", "a"), objectIds: [id("obj", "a")], bytes: 4, metadataCiphertext: base64(await encryptAttachmentMetadata(mine, cnt, { name: "chart.png", type: "image/png", size: 2048 })), keyGeneration: 1 },
        { id: id("att", "b"), objectIds: [id("obj", "a")], bytes: 1, metadataCiphertext: base64(await encryptAttachmentMetadata(mine, cnt, { name: "logo.svg", type: "image/svg+xml", size: 1 })), keyGeneration: 1 },
      ],
      conflicts: [{ id: id("cfl", "a"), objectId: id("obj", "a"), keyGeneration: 1, createdAt: "t" }],
    }),
    readObject: async () => ({ bytes: page, version: 3, keyGeneration: 1 }),
    conflictBytes: async () => conflict,
    downloadAttachment: async (aid) => (aid === id("att", "a") ? png : svg),
  };
  return reviewLegacy(api, { container, floorNow: () => ({ shared: 2, generation: 2 }), legacy: mine, userId: me });
}
/** A page holding a link, a table and a PDF, and the PDF itself: all this user's (I3, M4). */
async function richReview(): Promise<Review> {
  const pdf = id("att", "p");
  const body = JSON.stringify({ format: "kynotes-blocknote-v1", document: [
    { id: "b1", type: "paragraph", props: { textColor: "default", backgroundColor: "default", textAlignment: "left" }, content: [{ type: "text", text: "Pay ", styles: {} }, { type: "link", href: "https://evil.example/pay", content: [{ type: "text", text: "here", styles: {} }] }], children: [] },
    { id: "b2", type: "table", props: {}, content: { type: "tableContent", rows: [{ cells: [[{ type: "text", text: "IBAN", styles: {} }], [{ type: "text", text: "GB00 EVIL", styles: {} }]] }] }, children: [] },
    { id: "b3", type: "file", props: { name: "invoice.pdf", url: `attachment://${pdf}` }, children: [] },
  ] });
  const page = await encryptNote(mine, cnt, { type: "page", title: "Invoice", body });
  const bytes = new Uint8Array([37, 80, 68, 70, 45]);
  const sealed = await encryptAttachment(mine, cnt, bytes);
  const api: ReviewAPI = {
    legacyRows: async () => ({
      complete: true,
      objects: [{ id: id("obj", "p"), keyGeneration: 1 }],
      comments: [],
      attachments: [{ id: pdf, objectIds: [id("obj", "p")], metadataCiphertext: base64(await encryptAttachmentMetadata(mine, cnt, { name: "invoice.pdf", type: "application/pdf", size: 5 })), keyGeneration: 1 }],
      conflicts: [],
    }),
    readObject: async () => ({ bytes: page, version: 1, keyGeneration: 1 }),
    conflictBytes: async () => { throw new Error("none"); },
    downloadAttachment: async () => sealed,
  };
  return reviewLegacy(api, { container, floorNow: () => ({ shared: 2, generation: 2 }), legacy: mine, userId: me });
}
const noop = async () => {};
const banner = (props: Partial<Parameters<typeof LegacyReview>[0]>) =>
  renderToStaticMarkup(<LegacyReview userID={me} containerID={cnt} review={undefined} checking={false} closed={false} reopened={false} labelled={false} onShare={noop} onStop={noop} onReopen={noop} {...props} />);
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/\s+/g, " ");
const outcome = (result: Partial<Migrated>): Migrated => ({ shared: [], failed: [], closed: false, incomplete: false, blockedBy: [], ...result });

describe("the pre-sharing banner", () => {
  it("shows while the check runs, with Stop and without a review button", () => {
    const html = text(banner({ checking: true }));
    expect(html).toContain(LEGACY_CHECKING);
    expect(html).toContain(STOP_BUTTON);
    expect(html).not.toContain("Review and share");
  });

  it("a failed check shows the banner, the reason and Stop (N2)", () => {
    for (const error of [new APIRequestError("slow", {}, 429), new APIRequestError("boom", {}, 500), new TypeError("Failed to fetch")]) {
      const html = text(banner({ failure: checkFailure(error) }));
      expect(html).toContain(LEGACY_UNCHECKED);
      expect(html).toContain(checkFailure(error));
      expect(html).toContain(STOP_BUTTON);
    }
    expect(checkFailure(new APIRequestError("slow", {}, 429))).toMatch(/limiting/);
    expect(checkFailure(new APIRequestError("boom", {}, 500))).toMatch(/500/);
    expect(checkFailure(new TypeError("Failed to fetch"))).toMatch(/could not reach/);
  });

  it("an incomplete check shows the banner and Stop, with or without items of this user's", async () => {
    const empty = { ...(await review(false)) };
    const partial = await review(false);
    for (const value of [partial, { ...empty, mine: [] } as Review]) {
      const html = text(banner({ review: value }));
      expect(html).toContain(LEGACY_INCOMPLETE);
      expect(html).toContain(STOP_BUTTON);
    }
  });

  it("a reopened notebook always offers Stop, even when the server lists nothing of this user's (I2)", async () => {
    const nothing = { ...(await review()), mine: [] } as Review;
    // Without the mark, a complete empty list shows no banner at all.
    expect(text(banner({ review: nothing }))).not.toContain(STOP_BUTTON);
    for (const props of [{ reopened: true }, { labelled: true }]) {
      const html = text(banner({ review: nothing, ...props }));
      expect(html).toContain(STOP_BUTTON);
      expect(html).toContain(LEGACY_STILL_OPEN);
      expect(html).not.toContain(REOPEN_LEGACY);
    }
    // Closed wins: the only action is to show them again.
    const closed = text(banner({ review: nothing, reopened: true, labelled: true, closed: true }));
    expect(closed).toContain(REOPEN_LEGACY);
    expect(closed).not.toContain(STOP_BUTTON);
  });

  it("a closed notebook offers only \"Show pre-sharing items again\"", async () => {
    const html = text(banner({ review: await review(), closed: true }));
    expect(html).toContain(LEGACY_CLOSED);
    expect(html).toContain(REOPEN_LEGACY);
    expect(html).not.toContain(STOP_BUTTON);
    expect(html).not.toContain("Review and share");
    expect(text(banner({ review: await review() }))).not.toContain(REOPEN_LEGACY);
  });

  it("says why a share did not close: incomplete, or named pages that still use a shared attachment", async () => {
    const html = text(banner({ review: await review(), outcome: outcome({ incomplete: true, blockedBy: [{ id: id("obj", "a"), title: "Budget", attachment: id("att", "a") }, { id: id("obj", "z"), title: "", attachment: id("att", "a") }] }) }));
    expect(html).toContain(LEGACY_SHARE_INCOMPLETE);
    expect(html).toContain(LEGACY_BLOCKED);
    expect(html).toContain("Budget");
    expect(html).toContain("Untitled page");
    expect(html).toContain(REVIEW_BLOCKED);
    expect(html).not.toContain(TICK_THESE); // ticking happens in the dialog, by the user
    expect(shareOutcomeText(outcome({ shared: ["x"], incomplete: true }))).toBe(`Shared 1 item. ${LEGACY_SHARE_INCOMPLETE}`);
    expect(shareOutcomeText(outcome({ shared: ["x", "y"], closed: true }))).toBe(`Shared 2 items. ${LEGACY_CLOSED}`);
    expect(shareOutcomeText(outcome({ failed: [{ id: "x", reason: "offline" }] }))).toMatch(/^1 of the ticked items could not be shared \(offline\)/);
  });

  it("\"Tick these too\" offers only the blocked pages and their attachments that the review still offers", async () => {
    const value = await review();
    expect([...tickThese(value, [{ id: id("obj", "a"), title: "", attachment: id("att", "a") }, { id: id("obj", "z"), title: "", attachment: id("att", "z") }])].sort()).toEqual([id("att", "a"), id("obj", "a")]);
  });
});

describe("the review dialog", () => {
  it("shows each item's actual content, labelled unverified, unticked, with an image preview for raster images only", async () => {
    const value = await review();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:preview" }));
    const html = renderToStaticMarkup(<LegacyItems review={value} onTick={() => {}} picked={new Set()} highlight={new Set()} busy={false} onToggle={() => {}} onTickHighlighted={() => {}} onSelectAll={() => {}} onCancel={() => {}} onShare={() => {}} />);
    vi.unstubAllGlobals();
    const shown = text(html);
    for (const expected of ["Page: Budget", "Line one of the budget", "Comment: Check the totals", "Attachment: chart.png (2 KB)", "Attachment: logo.svg (1 KB)", "Conflicting version: Old budget", "Older line"]) expect(shown).toContain(expected);
    expect(shown.split(LEGACY_LABEL)).toHaveLength(value.mine.length + 1);
    expect(html.match(/type="checkbox"/g)).toHaveLength(value.mine.length);
    expect(html).not.toMatch(/checked=""/);
    expect(html.match(/<img /g)).toHaveLength(1);
    expect(html).toContain('alt="chart.png"');
    // Share is disabled until something is ticked.
    expect(html).toMatch(new RegExp(`<button disabled="">${SHARE_BUTTON}</button>`));
    const ticked = renderToStaticMarkup(<LegacyItems review={value} onTick={() => {}} picked={new Set([id("obj", "a")])} highlight={new Set()} busy={false} onToggle={() => {}} onTickHighlighted={() => {}} onSelectAll={() => {}} onCancel={() => {}} onShare={() => {}} />);
    expect(ticked).toContain(`<button>${SHARE_BUTTON}</button>`);
  });

  it("shows everything a tick seals: link targets, table cells, attachment name, type and size, and a copy of the reviewed bytes (I3)", async () => {
    const value = await richReview();
    const blobs: Blob[] = [];
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: (blob: Blob) => { blobs.push(blob); return "blob:copy"; } }));
    const html = renderToStaticMarkup(<LegacyItems review={value} onTick={() => {}} picked={new Set()} highlight={new Set()} busy={false} onToggle={() => {}} onTickHighlighted={() => {}} onSelectAll={() => {}} onCancel={() => {}} onShare={() => {}} />);
    vi.unstubAllGlobals();
    const shown = text(html);
    for (const expected of ["title: Invoice", "Pay", "href: https://evil.example/pay", "here", "IBAN | GB00 EVIL", "url: attachment://", "→ attachment invoice.pdf (application/pdf, 5 bytes)", "Attachment: invoice.pdf (application/pdf, 5 bytes)"])
      expect(shown).toContain(expected);
    expect(shown).not.toMatch(/textColor|textAlignment/); // unstyled defaults are not content
    // No preview of a PDF in the page; a local copy of exactly the reviewed bytes instead, never rendered inline.
    expect(html).not.toContain("<img");
    expect(html).toContain(`<a href="blob:copy" download="invoice.pdf">${SAVE_COPY}</a>`);
    expect(blobs).toHaveLength(1);
    expect(blobs[0].type).toBe("application/octet-stream");
    const reviewed = value.mine.find((item) => item.kind === "attachment")!;
    expect(new Uint8Array(await blobs[0].arrayBuffer())).toEqual(reviewed.kind === "attachment" ? reviewed.plaintext : undefined);
  });

  it("a ticked page using an unticked attachment blocks Share and offers \"Tick it too\" (M4)", async () => {
    const value = await richReview();
    const page = new Set([id("obj", "p")]);
    const onTick = vi.fn();
    const html = renderToStaticMarkup(<LegacyItems review={value} onTick={onTick} picked={page} highlight={new Set()} busy={false} onToggle={() => {}} onTickHighlighted={() => {}} onSelectAll={() => {}} onCancel={() => {}} onShare={() => {}} />);
    expect(text(html)).toContain(LEGACY_LEFT_BEHIND);
    expect(text(html)).toContain(`Invoice: invoice.pdf ${TICK_IT}`);
    expect(html).toContain(`<button disabled="">${SHARE_BUTTON}</button>`);
    // No approval for it either, whatever calls approveMigration.
    expect(() => approveMigration(me, cnt, value, page, 1)).toThrow(/attachment/);
    const both = new Set([id("obj", "p"), id("att", "p")]);
    expect(text(renderToStaticMarkup(<LegacyItems review={value} onTick={onTick} picked={both} highlight={new Set()} busy={false} onToggle={() => {}} onTickHighlighted={() => {}} onSelectAll={() => {}} onCancel={() => {}} onShare={() => {}} />))).not.toContain(LEGACY_LEFT_BEHIND);
    expect(isMigrationApproval(approveMigration(me, cnt, value, both, 0), me, cnt)).toBe(true);
    // The attachment alone is fine: no ticked page is left pointing at the login key.
    expect(isMigrationApproval(approveMigration(me, cnt, value, [id("att", "p")], 1), me, cnt)).toBe(true);
  });

  it("shares nothing with nothing ticked, and asks before hiding the unticked count", async () => {
    const value = await review();
    const onShare = vi.fn(async (_approval: MigrationApproval) => {});
    const ask = vi.fn(() => false);
    expect(await submitShare({ userID: me, containerID: cnt, review: value, picked: new Set(), ask, onShare })).toBe(false);
    expect(ask).not.toHaveBeenCalled();
    // Two ticked of five: the user is asked about three, and declining sends nothing.
    const picked = new Set([id("obj", "a"), id("cmt", "a")]);
    expect(await submitShare({ userID: me, containerID: cnt, review: value, picked, ask, onShare })).toBe(false);
    expect(ask).toHaveBeenCalledWith(legacyLeave(value.mine.length - 2));
    expect(onShare).not.toHaveBeenCalled();
    // Confirmed: the approval is minted for this user and notebook with the confirmed count.
    expect(await submitShare({ userID: me, containerID: cnt, review: value, picked, ask: () => true, onShare })).toBe(true);
    const approval = onShare.mock.calls[0][0];
    expect(isMigrationApproval(approval, me, cnt)).toBe(true);
    expect(approval).toMatchObject({ unticked: value.mine.length - 2, hideConfirmed: value.mine.length - 2, complete: true, shared: 2 });
    // Everything ticked: nothing is hidden, so nothing to confirm.
    const all = vi.fn(() => false);
    expect(await submitShare({ userID: me, containerID: cnt, review: value, picked: new Set(value.mine.map((item) => item.id)), ask: all, onShare })).toBe(true);
    expect(all).not.toHaveBeenCalled();
  });

  it("mints a reopen confirmation only after the user confirms the unverified warning", async () => {
    expect(REOPEN_CONFIRM).toMatch(/not end-to-end verified/);
    const onReopen = vi.fn(async (_confirmation: ReopenConfirmation) => {});
    expect(await submitReopen(me, cnt, () => false, onReopen)).toBe(false);
    expect(onReopen).not.toHaveBeenCalled();
    const ask = vi.fn(() => true);
    expect(await submitReopen(me, cnt, ask, onReopen)).toBe(true);
    expect(ask).toHaveBeenCalledWith(REOPEN_CONFIRM);
    expect(isReopenConfirmation(onReopen.mock.calls[0][0], me, cnt)).toBe(true);
  });

  it("highlights blocked pages unticked, and ticks them only on the user's \"Tick these too\" (I2)", async () => {
    const value = await review();
    const highlight = new Set([id("obj", "a")]);
    const onTickHighlighted = vi.fn();
    const html = renderToStaticMarkup(<LegacyItems review={value} onTick={() => {}} picked={new Set()} highlight={highlight} busy={false} onToggle={() => {}} onTickHighlighted={onTickHighlighted} onSelectAll={() => {}} onCancel={() => {}} onShare={() => {}} />);
    expect(text(html)).toContain(LEGACY_BLOCKED);
    expect(text(html)).toContain(TICK_THESE);
    expect(html.match(/class="legacy-highlight"/g)).toHaveLength(1);
    expect(html).not.toMatch(/checked=""/);
    const source = import.meta.glob<string>("./LegacyReview.tsx", { query: "?raw", import: "default", eager: true })["./LegacyReview.tsx"];
    // Opening never ticks; the only setPicked calls are the user's toggle, Select all, Tick these too and Tick it too.
    expect(source).toContain("setShown(review); setPicked(new Set()); setHighlight(marked);");
    expect(source.match(/setPicked\(/g)).toHaveLength(5);
    expect(source).toContain("onTick={(id) => setPicked((value) => new Set([...value, id]))}");
    expect(source).toContain("onTickHighlighted={() => setPicked((value) => new Set([...value, ...highlight]))}");
  });

  it("only this component calls submitShare and submitReopen, under any name (M1)", () => {
    const sources = import.meta.glob<string>(["../**/*.{ts,tsx}", "!../**/*.test.{ts,tsx}", "!../ky-ui/**"], { query: "?raw", import: "default", eager: true });
    const naming = (all: Record<string, string>, name: string) => Object.entries(all).filter(([file, text]) => new RegExp(`\\b${name}\\b`).test(text) && (!file.endsWith("/components/LegacyReview.tsx") && file !== "./LegacyReview.tsx" || new RegExp(`\\b${name}\\s+as\\b`).test(text))).map(([file]) => file);
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(["../main.tsx", "./LegacyReview.tsx"]));
    for (const name of ["submitShare", "submitReopen"]) {
      expect(naming(sources, name)).toEqual([]);
      expect(naming({ "../main.tsx": `import { ${name} as go } from "./components/LegacyReview"; go();`, "../x.ts": `import * as l from "./components/LegacyReview"; l.${name}();` }, name)).toEqual(["../main.tsx", "../x.ts"]);
    }
  });

  it("reads content from the review it shows, never from an approval, and mints only in submitShare and submitReopen", () => {
    const source = import.meta.glob<string>("./LegacyReview.tsx", { query: "?raw", import: "default", eager: true })["./LegacyReview.tsx"];
    expect(source).not.toMatch(/approval\.\w/);
    expect(source.match(/\bapproveMigration\(/g)).toHaveLength(1);
    expect(source.match(/\bconfirmReopenLegacy\(/g)).toHaveLength(1);
    expect(source).toMatch(/export async function submitShare[^]*?approveMigration\(input\.userID, input\.containerID, input\.review, ticked, hide\)/);
    expect(source).toMatch(/if \(!ask\(REOPEN_CONFIRM\)\) return false;\n\s*await onReopen\(confirmReopenLegacy\(userID, containerID\)\);/);
    // The dialog starts with nothing ticked unless "Tick these too" names items.
    expect(source).toContain("openDialog(new Set())");
  });
});
