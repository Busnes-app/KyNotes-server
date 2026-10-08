import { afterEach, describe, expect, it, vi } from "vitest";
import { legacyRows, type LegacyRows } from "./api";
import { base64, encryptAttachment, encryptAttachmentMetadata, encryptComment, encryptNote, legacyKeyRef } from "./crypto";
import type { KeyFloor, ReportedContainer } from "./keyring";
import { autoCloses, itemLabel, LegacyClosedError, reviewLegacy, type ReviewAPI } from "./migration";
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
    const review = await reviewLegacy(server(objects, rows, conflicts, files), { container, floorNow: () => floor, legacy: mine, userId: me });
    expect(review.mine.map((item) => [item.kind, item.id])).toEqual([["object", id("obj", "a")], ["comment", id("cmt", "a")], ["attachment", id("att", "a")], ["conflict", id("cfl", "a")]]);
    expect(review.mine.map(itemLabel)).toEqual(["Page: Mine", "Comment: my note", "Attachment: a.txt (1 KB)", "Conflicting version: Older mine"]);
    expect(review).toMatchObject({ others: 2, refused: 0, complete: true }); // obj b, cmt b; obj c is not legacy any more
    expect(autoCloses(review, floor)).toBe(false);
    // The other author sees the mirror image.
    const theirsReview = await reviewLegacy(server(objects, rows, conflicts, files), { container, floorNow: () => floor, legacy: theirs, userId: other });
    expect(theirsReview.mine.map((item) => item.id)).toEqual([id("obj", "b"), id("cmt", "b")]);
  });

  it("refuses a comment that opens with this key but names another author", async () => {
    const forged = { id: id("cmt", "c"), objectId: id("obj", "a"), authorUserId: other, bodyCiphertext: base64(await encryptComment(mine, cnt, "forged")), keyGeneration: 1 };
    const review = await reviewLegacy(server({}, { comments: [forged] }), { container, floorNow: () => floor, legacy: mine, userId: me });
    expect(review).toMatchObject({ mine: [], refused: 1, others: 0 });
    expect(autoCloses(review, floor)).toBe(true);
  });

  it("never closes by itself on an incomplete list or a row it could not fetch", async () => {
    expect(autoCloses(await reviewLegacy(server({}, { complete: false }), { container, floorNow: () => floor, legacy: mine, userId: me }), floor)).toBe(false);
    const missing = await reviewLegacy(server({}, { objects: [{ id: id("obj", "z"), version: 1, keyGeneration: 1 }] }), { container, floorNow: () => floor, legacy: mine, userId: me });
    expect(missing.complete).toBe(false);
    expect(autoCloses(missing, floor)).toBe(false);
    const conflict = await reviewLegacy(server({}, { conflicts: [{ id: id("cfl", "z"), objectId: id("obj", "a"), keyGeneration: 1, createdAt: "t" }] }), { container, floorNow: () => floor, legacy: mine, userId: me });
    expect(autoCloses(conflict, floor)).toBe(false);
    expect(autoCloses(await reviewLegacy(server({}, {}), { container, floorNow: () => floor, legacy: mine, userId: me }), floor)).toBe(true);
  });

  it("reads nothing once this device closed, and counts every listed row as someone else's", async () => {
    const api = server({}, { objects: [{ id: id("obj", "a"), version: 1, keyGeneration: 1 }], comments: [{ id: id("cmt", "a"), objectId: id("obj", "a"), authorUserId: me, bodyCiphertext: "", keyGeneration: 1 }] });
    api.readObject = async () => { throw new Error("must not read"); };
    expect(await reviewLegacy(api, { container, floorNow: () => ({ ...floor, closed: 2 }), legacy: mine, userId: me })).toEqual({ mine: [], others: 2, refused: 0, complete: true, shared: 2 });
  });

  it("lists nothing for a notebook this device has never seen shared", async () => {
    const api = server({}, { objects: [{ id: id("obj", "a"), version: 1, keyGeneration: 1 }] });
    expect(await reviewLegacy(api, { container: { ...container, sharedGeneration: 0, keyGeneration: 1 }, floorNow: () => ({}), legacy: mine, userId: me })).toEqual({ mine: [], others: 0, refused: 0, complete: true, shared: 0 });
  });

  it("offers an attachment with the bytes it opened, so sharing seals what the dialog opens", async () => {
    const row = (c: string) => ({ id: id("att", c), objectIds: [id("obj", "a")], bytes: 4, keyGeneration: 1 });
    const meta = base64(await encryptAttachmentMetadata(mine, cnt, { name: "a", type: "", size: 4 }));
    const api = server({}, { attachments: [{ ...row("a"), metadataCiphertext: meta }, { ...row("b"), metadataCiphertext: meta }, { ...row("c"), metadataCiphertext: meta }] }, {}, {
      [id("att", "a")]: await encryptAttachment(mine, cnt, new Uint8Array([7, 7])),
      [id("att", "b")]: await encryptAttachment(theirs, cnt, new Uint8Array([6])), // metadata opens, bytes do not
    });
    const review = await reviewLegacy(api, { container, floorNow: () => floor, legacy: mine, userId: me });
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
    return reviewLegacy({ ...server({}, {}), legacyRows }, { container, floorNow: () => floor, legacy: mine, userId: me });
  };
  const empty = { objects: [], comments: [], attachments: [], conflicts: [] };

  it("an unfinished check is never an empty list: 429, 500 and no network leave no review to auto-close", async () => {
    await expect(wired(() => Response.json({ error: { code: "rate_limited", message: "slow down" } }, { status: 429 }))).rejects.toThrow();
    await expect(wired(() => new Response("boom", { status: 500 }))).rejects.toThrow();
    await expect(wired(() => { throw new TypeError("Failed to fetch"); })).rejects.toThrow();
  });

  it("auto-closes only on a successful complete:true list with nothing of this user's", async () => {
    expect(autoCloses(await wired(() => Response.json({ ...empty, complete: false })), floor)).toBe(false);
    expect(autoCloses(await wired(() => Response.json(empty)), floor)).toBe(false); // complete missing
    expect(autoCloses(await wired(() => Response.json({ ...empty, complete: "true" })), floor)).toBe(false);
    expect(autoCloses(await wired(() => Response.json({ ...empty, complete: true })), floor)).toBe(true);
  });
});

describe("review binding and closure (fix round 1)", () => {
  it("a review taken before sharing never closes once the notebook is shared (I1)", async () => {
    const unshared = await reviewLegacy(server({}, {}), { container: { ...container, sharedGeneration: 0, keyGeneration: 1 }, floorNow: () => ({}), legacy: mine, userId: me });
    expect(unshared).toMatchObject({ shared: 0, complete: true, mine: [] });
    expect(autoCloses(unshared, {})).toBe(false);
    expect(autoCloses(unshared, { shared: 2, generation: 2 })).toBe(false);
    // A review at sharing generation 2 says nothing about generation 3.
    const atTwo = await reviewLegacy(server({}, {}), { container, floorNow: () => floor, legacy: mine, userId: me });
    expect(autoCloses(atTwo, floor)).toBe(true);
    expect(autoCloses(atTwo, { shared: 3, generation: 3 })).toBe(false);
    expect(autoCloses(atTwo, undefined)).toBe(false);
  });

  it("an object with no valid generation leaves the review incomplete (M1)", async () => {
    const objects = { [id("obj", "a")]: { bytes: await encryptNote(mine, cnt, page("Mine")), version: 1, keyGeneration: undefined as unknown as number } };
    const review = await reviewLegacy(server(objects, { objects: [{ id: id("obj", "a"), version: 1, keyGeneration: 1 }] }), { container, floorNow: () => floor, legacy: mine, userId: me });
    expect(review).toMatchObject({ mine: [], complete: false });
    expect(autoCloses(review, floor)).toBe(false);
  });

  it("stops decrypting once this notebook's closure rises mid-review (M3)", async () => {
    const objects = {
      [id("obj", "a")]: { bytes: await encryptNote(mine, cnt, page("First")), version: 1, keyGeneration: 1 },
      [id("obj", "b")]: { bytes: await encryptNote(mine, cnt, page("Second")), version: 1, keyGeneration: 1 },
    };
    let now: KeyFloor = floor;
    const api = server(objects, { objects: Object.keys(objects).map((oid) => ({ id: oid, version: 1, keyGeneration: 1 })) });
    const read = api.readObject;
    // Another tab presses Stop while the second row is fetched.
    api.readObject = async (oid) => { if (oid === id("obj", "b")) now = { ...floor, closed: 2 }; return read(oid); };
    await expect(reviewLegacy(api, { container, floorNow: () => now, legacy: mine, userId: me })).rejects.toBeInstanceOf(LegacyClosedError);
    // A floor that is not loaded opens nothing either.
    await expect(reviewLegacy(server({}, {}), { container, floorNow: () => undefined, legacy: mine, userId: me })).rejects.toBeInstanceOf(LegacyClosedError);
  });
});

describe("destructive migration calls (M2)", () => {
  it("only migration.ts detaches attachments; only it and main.tsx's conflict flow resolve conflicts", () => {
    const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./api.ts", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(["./main.tsx", "./migration.ts"]));
    const callers = (name: string) => Object.entries(sources).filter(([, text]) => new RegExp(`\\b${name}\\b`).test(text)).map(([file]) => file);
    expect(callers("detachAttachment").filter((file) => file !== "./migration.ts")).toEqual([]);
    expect(callers("resolveConflict").filter((file) => file !== "./migration.ts" && file !== "./main.tsx")).toEqual([]);
  });
});
