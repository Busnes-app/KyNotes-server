import { afterEach, describe, expect, it, vi } from "vitest";
import { legacyRows, type LegacyRows } from "./api";
import { base64, encryptAttachment, encryptAttachmentMetadata, encryptComment, encryptNote, legacyKeyRef } from "./crypto";
import type { KeyFloor, ReportedContainer } from "./keyring";
import { autoCloses, itemLabel, reviewLegacy, type ReviewAPI } from "./migration";
import type { ObjectPayload } from "./pages";

const cnt = `cnt_${"a".repeat(26)}`;
const me = `usr_${"a".repeat(26)}`, other = `usr_${"b".repeat(26)}`;
const mine = legacyKeyRef("a".repeat(64)), theirs = legacyKeyRef("b".repeat(64));
const id = (prefix: string, c: string) => `${prefix}_${c.repeat(26)}`;
const container: ReportedContainer = { id: cnt, kind: "team", keyGeneration: 2, sharedGeneration: 2 };
const floor: KeyFloor = { shared: 2, generation: 2 };
const page = (title: string, body = ""): ObjectPayload => ({ type: "page", title, body });

type Stored = { bytes: Uint8Array; version: number; keyGeneration: number };
/** A server holding objects, conflicts and attachment bytes, listing what the test puts in rows. */
function server(objects: Record<string, Stored>, rows: Partial<LegacyRows>, conflicts: Record<string, Uint8Array> = {}, files: Record<string, Uint8Array> = {}): ReviewAPI {
  const found = <T>(value: T | undefined) => { if (!value) throw new Error("not found"); return value; };
  return {
    legacyRows: async () => ({ complete: true, objects: [], comments: [], attachments: [], conflicts: [], ...rows }),
    readObject: async (oid) => ({ ...found(objects[oid]) }),
    conflictBytes: async (fid) => found(conflicts[fid]),
    downloadAttachment: async (aid) => found(files[aid]),
  };
}

describe("reviewLegacy", () => {
  it("offers only rows below sharing that this user's login key opens; other authors' rows are counted", async () => {
    const objects = {
      [id("obj", "a")]: { bytes: await encryptNote(mine, cnt, page("Mine")), version: 3, keyGeneration: 1 },
      [id("obj", "b")]: { bytes: await encryptNote(theirs, cnt, page("Theirs")), version: 1, keyGeneration: 1 },
      // Relabelled at the shared generation: never opened with the login key.
      [id("obj", "c")]: { bytes: await encryptNote(mine, cnt, page("Relabelled")), version: 1, keyGeneration: 2 },
    };
    const rows: Partial<LegacyRows> = {
      objects: Object.entries(objects).map(([oid, row]) => ({ id: oid, version: row.version, keyGeneration: 1 })),
      comments: [
        { id: id("cmt", "a"), objectId: id("obj", "a"), authorUserId: me, bodyCiphertext: base64(await encryptComment(mine, cnt, "my note")), keyGeneration: 1 },
        { id: id("cmt", "b"), objectId: id("obj", "b"), authorUserId: other, bodyCiphertext: base64(await encryptComment(theirs, cnt, "their note")), keyGeneration: 1 },
      ],
      attachments: [{ id: id("att", "a"), objectIds: [id("obj", "a")], bytes: 4, metadataCiphertext: base64(await encryptAttachmentMetadata(mine, cnt, { name: "a.txt", type: "text/plain", size: 4 })), keyGeneration: 1 }],
      conflicts: [{ id: id("cfl", "a"), objectId: id("obj", "a"), keyGeneration: 1, createdAt: "t" }],
    };
    const conflicts = { [id("cfl", "a")]: await encryptNote(mine, cnt, page("Older mine")) };
    const files = { [id("att", "a")]: await encryptAttachment(mine, cnt, new Uint8Array([1, 2, 3, 4])) };
    const review = await reviewLegacy(server(objects, rows, conflicts, files), { container, floor, legacy: mine, userId: me });
    expect(review.mine.map((item) => [item.kind, item.id])).toEqual([["object", id("obj", "a")], ["comment", id("cmt", "a")], ["attachment", id("att", "a")], ["conflict", id("cfl", "a")]]);
    expect(review.mine.map(itemLabel)).toEqual(["Page: Mine", "Comment: my note", "Attachment: a.txt (1 KB)", "Conflicting version: Older mine"]);
    expect(review).toMatchObject({ others: 2, refused: 0, complete: true }); // obj b, cmt b; obj c is not legacy any more
    expect(autoCloses(review)).toBe(false);
    // The other author sees the mirror image.
    const theirsReview = await reviewLegacy(server(objects, rows, conflicts, files), { container, floor, legacy: theirs, userId: other });
    expect(theirsReview.mine.map((item) => item.id)).toEqual([id("obj", "b"), id("cmt", "b")]);
  });

  it("refuses a comment that opens with this key but names another author", async () => {
    const forged = { id: id("cmt", "c"), objectId: id("obj", "a"), authorUserId: other, bodyCiphertext: base64(await encryptComment(mine, cnt, "forged")), keyGeneration: 1 };
    const review = await reviewLegacy(server({}, { comments: [forged] }), { container, floor, legacy: mine, userId: me });
    expect(review).toMatchObject({ mine: [], refused: 1, others: 0 });
    expect(autoCloses(review)).toBe(true);
  });

  it("never closes by itself on an incomplete list or a row it could not fetch", async () => {
    expect(autoCloses(await reviewLegacy(server({}, { complete: false }), { container, floor, legacy: mine, userId: me }))).toBe(false);
    const missing = await reviewLegacy(server({}, { objects: [{ id: id("obj", "z"), version: 1, keyGeneration: 1 }] }), { container, floor, legacy: mine, userId: me });
    expect(missing.complete).toBe(false);
    expect(autoCloses(missing)).toBe(false);
    const conflict = await reviewLegacy(server({}, { conflicts: [{ id: id("cfl", "z"), objectId: id("obj", "a"), keyGeneration: 1, createdAt: "t" }] }), { container, floor, legacy: mine, userId: me });
    expect(autoCloses(conflict)).toBe(false);
    expect(autoCloses(await reviewLegacy(server({}, {}), { container, floor, legacy: mine, userId: me }))).toBe(true);
  });

  it("reads nothing once this device closed, and counts every listed row as someone else's", async () => {
    const api = server({}, { objects: [{ id: id("obj", "a"), version: 1, keyGeneration: 1 }], comments: [{ id: id("cmt", "a"), objectId: id("obj", "a"), authorUserId: me, bodyCiphertext: "", keyGeneration: 1 }] });
    api.readObject = async () => { throw new Error("must not read"); };
    expect(await reviewLegacy(api, { container, floor: { ...floor, closed: 2 }, legacy: mine, userId: me })).toEqual({ mine: [], others: 2, refused: 0, complete: true });
  });

  it("lists nothing for a notebook this device has never seen shared", async () => {
    const api = server({}, { objects: [{ id: id("obj", "a"), version: 1, keyGeneration: 1 }] });
    expect(await reviewLegacy(api, { container: { ...container, sharedGeneration: 0, keyGeneration: 1 }, floor: {}, legacy: mine, userId: me })).toEqual({ mine: [], others: 0, refused: 0, complete: true });
  });

  it("offers an attachment with the bytes it opened, so sharing seals what the dialog opens", async () => {
    const row = (c: string) => ({ id: id("att", c), objectIds: [id("obj", "a")], bytes: 4, keyGeneration: 1 });
    const meta = base64(await encryptAttachmentMetadata(mine, cnt, { name: "a", type: "", size: 4 }));
    const api = server({}, { attachments: [{ ...row("a"), metadataCiphertext: meta }, { ...row("b"), metadataCiphertext: meta }, { ...row("c"), metadataCiphertext: meta }] }, {}, {
      [id("att", "a")]: await encryptAttachment(mine, cnt, new Uint8Array([7, 7])),
      [id("att", "b")]: await encryptAttachment(theirs, cnt, new Uint8Array([6])), // metadata opens, bytes do not
    });
    const review = await reviewLegacy(api, { container, floor, legacy: mine, userId: me });
    expect(review.mine).toHaveLength(1);
    expect(review.mine[0]).toMatchObject({ kind: "attachment", generation: 1, objectIds: [id("obj", "a")], file: { name: "a" }, plaintext: new Uint8Array([7, 7]) });
    // b's bytes do not open and c's cannot be fetched: neither is offered, and the list is not complete.
    expect(review.complete).toBe(false);
  });
});

describe("the /legacy check over the wire (N2)", () => {
  afterEach(() => { vi.unstubAllGlobals(); });
  /** reviewLegacy against the real legacyRows: only the fetch is stubbed. */
  const wired = (reply: () => Response) => {
    vi.stubGlobal("fetch", vi.fn(async () => reply()));
    return reviewLegacy({ ...server({}, {}), legacyRows }, { container, floor, legacy: mine, userId: me });
  };
  const empty = { objects: [], comments: [], attachments: [], conflicts: [] };

  it("an unfinished check is never an empty list: 429, 500 and no network leave no review to auto-close", async () => {
    await expect(wired(() => Response.json({ error: { code: "rate_limited", message: "slow down" } }, { status: 429 }))).rejects.toThrow();
    await expect(wired(() => new Response("boom", { status: 500 }))).rejects.toThrow();
    await expect(wired(() => { throw new TypeError("Failed to fetch"); })).rejects.toThrow();
  });

  it("auto-closes only on a successful complete:true list with nothing of this user's", async () => {
    expect(autoCloses(await wired(() => Response.json({ ...empty, complete: false })))).toBe(false);
    expect(autoCloses(await wired(() => Response.json(empty)))).toBe(false); // complete missing
    expect(autoCloses(await wired(() => Response.json({ ...empty, complete: "true" })))).toBe(false);
    expect(autoCloses(await wired(() => Response.json({ ...empty, complete: true })))).toBe(true);
  });
});
