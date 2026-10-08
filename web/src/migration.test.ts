import { afterEach, describe, expect, it, vi } from "vitest";
import { legacyRows, type LegacyRows } from "./api";
import { base64, decryptAttachment, decryptComment, decryptObject, encryptAttachment, encryptAttachmentMetadata, encryptComment, encryptNote, fromBase64, legacyKeyRef } from "./crypto";
import { clearFloors, raiseFloorIn } from "./floors";
import { keysAllowed, newContainerKey, writeKey, type KeyFloor, type ReportedContainer, type WriteKey } from "./keyring";
import { approveMigration, autoCloses, checkLegacyRows, isMigrationApproval, itemLabel, LegacyClosedError, migrateLegacy, reviewLegacy, rewriteRefs, type LegacyReview, type MigrationAPI, type MigrationApproval, type MigrationInput, type ReviewAPI } from "./migration";
import { KeysWaitingError, sendObject, setWriteKeySource } from "./outbound";
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
    expect(callers("detachAttachment").filter((file) => file !== "./migration.ts" && file !== "./main.tsx")).toEqual([]);
    // main.tsx only hands detach to migrateLegacy (its import and the MigrationAPI field), which orders it after the re-save.
    const main = sources["./main.tsx"];
    expect(main.match(/\bdetachAttachment\b/g)).toHaveLength(2);
    expect(main).toContain("    detach: detachAttachment,\n");
    expect(main).toContain("    resolve: resolveConflict,\n");
    expect(callers("resolveConflict").filter((file) => file !== "./migration.ts" && file !== "./main.tsx")).toEqual([]);
  });
});

const ck = newContainerKey();
const write: WriteKey = { key: ck, generation: 2 };
type Attached = { objectIds: string[]; bytes: Uint8Array; meta: string; keyGeneration: number };
/** A server that applies what it is sent and lists rows below generation 2, as GET /containers/{id}/legacy does. */
function liveServer() {
  const objects = new Map<string, Stored>();
  const comments = new Map<string, { objectId: string; authorUserId: string; body: string; keyGeneration: number }>();
  const attachments = new Map<string, Attached>();
  const conflicts = new Map<string, { objectId: string; bytes: Uint8Array; keyGeneration: number }>();
  const sends: string[] = [];
  const fresh = ["g", "h", "j", "k", "m"];
  const failing = new Set<string>();
  const api: MigrationAPI & ReviewAPI = {
    legacyRows: async () => ({
      complete: true,
      objects: [...objects].filter(([, row]) => row.keyGeneration < 2).map(([oid, row]) => ({ id: oid, version: row.version, keyGeneration: row.keyGeneration })),
      comments: [...comments].filter(([, row]) => row.keyGeneration < 2).map(([cid, row]) => ({ id: cid, objectId: row.objectId, authorUserId: row.authorUserId, bodyCiphertext: row.body, keyGeneration: row.keyGeneration })),
      attachments: [...attachments].filter(([, row]) => row.keyGeneration < 2 && row.objectIds.length).map(([aid, row]) => ({ id: aid, objectIds: [...row.objectIds], bytes: row.bytes.byteLength, metadataCiphertext: row.meta, keyGeneration: row.keyGeneration })),
      conflicts: [...conflicts].filter(([, row]) => row.keyGeneration < 2).map(([fid, row]) => ({ id: fid, objectId: row.objectId, keyGeneration: row.keyGeneration, createdAt: "t" })),
    }),
    readObject: async (oid) => ({ ...objects.get(oid)! }),
    conflictBytes: async (fid) => conflicts.get(fid)!.bytes,
    sendObject: async (sealed, oid, bytes, base) => {
      sends.push(`object:${oid}`);
      const row = objects.get(oid)!;
      if (failing.has(oid) || row.version !== base) throw Object.assign(new Error("version_conflict"), { code: "version_conflict" });
      objects.set(oid, { bytes, version: base + 1, keyGeneration: sealed.generation });
      return { version: base + 1 };
    },
    sendCommentRewrite: async (sealed, cid, body) => { sends.push(`comment:${cid}`); comments.set(cid, { ...comments.get(cid)!, body, keyGeneration: sealed.generation }); },
    downloadAttachment: async (aid) => attachments.get(aid)!.bytes,
    uploadAttachment: async (oid, _version, plaintext, file) => {
      const aid = id("att", fresh.shift()!);
      sends.push(`upload:${aid}`);
      attachments.set(aid, { objectIds: [oid], bytes: await encryptAttachment(ck, cnt, plaintext), meta: base64(await encryptAttachmentMetadata(ck, cnt, file)), keyGeneration: 2 });
      return aid;
    },
    attach: async (oid, aid) => { attachments.get(aid)!.objectIds.push(oid); },
    detach: async (oid, aid) => { sends.push(`detach:${aid}:${oid}`); const row = attachments.get(aid)!; row.objectIds = row.objectIds.filter((entry) => entry !== oid); },
    copyConflict: async (_oid, fid) => { sends.push(`copy:${fid}`); return true; },
    resolve: async (fid) => { sends.push(`resolve:${fid}`); conflicts.delete(fid); },
  };
  const state = () => JSON.stringify({ objects: [...objects].map(([k, v]) => [k, v.version, v.keyGeneration, [...v.bytes]]), comments: [...comments], attachments: [...attachments].map(([k, v]) => [k, v.objectIds, v.keyGeneration]), conflicts: [...conflicts.keys()] });
  return { api, objects, comments, attachments, conflicts, sends, failing, state };
}
/** A notebook with one pre-sharing page by "me" holding an inline image, its comment and a conflict, plus a shared page using the same image. */
async function seeded() {
  const live = liveServer();
  const image = id("att", "a");
  live.attachments.set(image, { objectIds: [id("obj", "a"), id("obj", "s")], bytes: await encryptAttachment(mine, cnt, new Uint8Array([7, 7])), meta: base64(await encryptAttachmentMetadata(mine, cnt, { name: "i.png", type: "image/png", size: 2 })), keyGeneration: 1 });
  live.objects.set(id("obj", "a"), { bytes: await encryptNote(mine, cnt, page("Mine", `![](attachment://${image})`)), version: 3, keyGeneration: 1 });
  live.objects.set(id("obj", "s"), { bytes: await encryptNote(ck, cnt, page("Shared", `see attachment://${image}`)), version: 1, keyGeneration: 2 });
  live.objects.set(id("obj", "f"), { bytes: await encryptNote(mine, cnt, page("Forged")), version: 1, keyGeneration: 1 });
  live.comments.set(id("cmt", "a"), { objectId: id("obj", "a"), authorUserId: me, body: base64(await encryptComment(mine, cnt, "my note")), keyGeneration: 1 });
  live.conflicts.set(id("cfl", "a"), { objectId: id("obj", "a"), bytes: await encryptNote(mine, cnt, page("Older mine")), keyGeneration: 1 });
  return { live, image };
}
const unticked = (review: LegacyReview, ids: string[]) => review.mine.filter((item) => !ids.includes(item.id)).length;
/** A fresh review as the dialog shows it, approved for the reviewed items with these IDs; the user confirmed hiding the rest. */
const prepared = async (live: ReturnType<typeof liveServer>, ids: string[], options: { containerID?: string; userID?: string; hide?: number } = {}): Promise<MigrationInput> => {
  const review = await reviewLegacy(live.api, { container, floorNow: () => floor, legacy: mine, userId: me });
  const approval = approveMigration(options.userID ?? me, options.containerID ?? cnt, review, ids, options.hide ?? unticked(review, ids));
  return { container, floorNow: () => floor, legacy: mine, userId: me, write, ring: new Map([[2, ck]]), approval };
};

describe("migrateLegacy", () => {
  it("sends nothing without an approval for this user and notebook", async () => {
    const { live } = await seeded();
    const close = vi.fn(async () => true);
    const good = await prepared(live, [id("obj", "a")]);
    const lookalike = { ...good, approval: { userID: me, containerID: cnt, shared: 2, complete: true, unticked: 0, hideConfirmed: 0 } as unknown as MigrationApproval };
    expect(isMigrationApproval(lookalike.approval, me, cnt)).toBe(false);
    expect(isMigrationApproval(Object.create(good.approval), me, cnt)).toBe(false);
    expect(isMigrationApproval(good.approval, me, cnt)).toBe(true);
    for (const input of [lookalike, await prepared(live, [id("obj", "a")], { containerID: `cnt_${"b".repeat(26)}` }), await prepared(live, [id("obj", "a")], { userID: other })])
      await expect(migrateLegacy(live.api, input, close)).rejects.toThrow();
    expect(live.sends).toEqual([]);
    expect(close).not.toHaveBeenCalled();
  });

  it("seals what the review showed, never a later read or a later change to the review, and only once", async () => {
    const { live, image } = await seeded();
    const review = await reviewLegacy(live.api, { container, floorNow: () => floor, legacy: mine, userId: me });
    const approval = approveMigration(me, cnt, review, [id("obj", "a"), image], unticked(review, [id("obj", "a"), image]));
    const input: MigrationInput = { container, floorNow: () => floor, legacy: mine, userId: me, write, ring: new Map([[2, ck]]), approval };
    // The approval exposes no content; the review the dialog showed changes after approval and that does not reach the seal.
    expect("items" in approval).toBe(false);
    for (const item of review.mine) {
      if (item.kind === "object" && item.payload.type === "page") item.payload.title = "Edited later";
      if (item.kind === "attachment") item.plaintext.fill(1);
    }
    expect(Object.isFrozen(approval)).toBe(true);
    // After the review the server swaps the page body and the attachment bytes, keeping the version.
    live.objects.set(id("obj", "a"), { ...live.objects.get(id("obj", "a"))!, bytes: await encryptNote(mine, cnt, page("Swapped")) });
    live.attachments.get(image)!.bytes = await encryptAttachment(mine, cnt, new Uint8Array([6]));
    await migrateLegacy(live.api, input, vi.fn(async () => true));
    expect((await decryptObject(ck, cnt, live.objects.get(id("obj", "a"))!.bytes))?.title).toBe("Mine");
    expect(await decryptAttachment(ck, cnt, live.attachments.get(id("att", "g"))!.bytes)).toEqual(new Uint8Array([7, 7]));
    // A spent approval sends nothing.
    live.sends.length = 0;
    await expect(migrateLegacy(live.api, input, vi.fn(async () => true))).rejects.toThrow("Choose the items to share in the review first.");
    expect(live.sends).toEqual([]);
  });

  it("re-seals only approved rows under the current key, then closes", async () => {
    const { live } = await seeded();
    const close = vi.fn(async () => true);
    const all = [id("obj", "a"), id("cmt", "a"), id("att", "a"), id("cfl", "a")]; // not the forged page
    const result = await migrateLegacy(live.api, await prepared(live, all), close);
    expect(result).toMatchObject({ failed: [], closed: true });
    expect([...result.shared].sort()).toEqual([...all].sort());
    expect(close).toHaveBeenCalledOnce();
    const migrated = live.objects.get(id("obj", "a"))!;
    expect(migrated.keyGeneration).toBe(2);
    expect((await decryptObject(ck, cnt, migrated.bytes))?.title).toBe("Mine");
    await expect(decryptObject(mine, cnt, migrated.bytes)).rejects.toThrow();
    expect(await decryptComment(ck, cnt, fromBase64(live.comments.get(id("cmt", "a"))!.body))).toMatchObject({ body: "my note" });
    // The unapproved forgery was not touched; the conflict became a copy, then was resolved.
    expect(live.objects.get(id("obj", "f"))!.keyGeneration).toBe(1);
    expect(live.sends.indexOf(`copy:${id("cfl", "a")}`)).toBeLessThan(live.sends.indexOf(`resolve:${id("cfl", "a")}`));
    expect(live.sends).not.toContain(`object:${id("obj", "f")}`);
  });

  it("resolves a conflict only after its copy was placed", async () => {
    const { live } = await seeded();
    live.api.copyConflict = async (_oid, fid) => { live.sends.push(`copy:${fid}`); return false; };
    const close = vi.fn(async () => true);
    const result = await migrateLegacy(live.api, await prepared(live, [id("cfl", "a")]), close);
    expect(live.sends).toEqual([`copy:${id("cfl", "a")}`]);
    expect(live.conflicts.has(id("cfl", "a"))).toBe(true);
    expect(result).toMatchObject({ closed: false, failed: [{ id: id("cfl", "a") }] });
  });

  it("rewrites inline references and detaches the old copy only from pages that point at the new one", async () => {
    const { live, image } = await seeded();
    live.failing.add(id("obj", "s")); // the shared page cannot be re-saved this time
    const close = vi.fn(async () => true);
    const result = await migrateLegacy(live.api, await prepared(live, [id("obj", "a"), image]), close);
    const replacement = id("att", "g");
    const body = (await decryptObject(ck, cnt, live.objects.get(id("obj", "a"))!.bytes)) as { body: string };
    expect(body.body).toBe(`![](attachment://${replacement})`);
    expect(await decryptAttachment(ck, cnt, live.attachments.get(replacement)!.bytes)).toEqual(new Uint8Array([7, 7]));
    expect(live.attachments.get(replacement)!.objectIds.sort()).toEqual([id("obj", "a"), id("obj", "s")].sort());
    // Detached from the page now pointing at the new copy; still attached to the page that failed.
    expect(live.attachments.get(image)!.objectIds).toEqual([id("obj", "s")]);
    expect(result.failed.map((entry) => entry.id)).toEqual([id("obj", "s")]);
    expect(result.closed).toBe(false);
    expect(close).not.toHaveBeenCalled();
    // The detach came after the page re-save.
    expect(live.sends.indexOf(`object:${id("obj", "a")}`)).toBeLessThan(live.sends.indexOf(`detach:${image}:${id("obj", "a")}`));
  });

  it("never re-seals an unticked pre-sharing page, even one that points at a ticked attachment", async () => {
    const { live, image } = await seeded();
    const untickedPage = id("obj", "b");
    live.objects.set(untickedPage, { bytes: await encryptNote(mine, cnt, page("Unticked", `attachment://${image}`)), version: 1, keyGeneration: 1 });
    live.attachments.get(image)!.objectIds.push(untickedPage);
    const close = vi.fn(async () => true);
    const result = await migrateLegacy(live.api, await prepared(live, [id("obj", "a"), image]), close);
    expect(live.sends).not.toContain(`object:${untickedPage}`);
    expect(live.objects.get(untickedPage)!.keyGeneration).toBe(1);
    expect(live.attachments.get(image)!.objectIds).toEqual([untickedPage]); // it keeps the old copy it points at
    expect(result.failed.map((entry) => entry.id)).toEqual([untickedPage]);
    expect(result.closed).toBe(false);
  });

  it("a refused or conflicting write keeps legacy reads open and never overwrites the newer version", async () => {
    const { live } = await seeded();
    const close = vi.fn(async () => true);
    const input = await prepared(live, [id("obj", "a"), id("cmt", "a")]);
    const newer = { ...live.objects.get(id("obj", "a"))!, version: 4 }; // another tab saved meanwhile
    live.objects.set(id("obj", "a"), newer);
    live.api.sendCommentRewrite = async () => { throw Object.assign(new Error("insufficient role"), { code: "forbidden" }); };
    const result = await migrateLegacy(live.api, input, close);
    expect(result.failed.map((entry) => entry.id).sort()).toEqual([id("cmt", "a"), id("obj", "a")].sort());
    expect(live.objects.get(id("obj", "a"))).toBe(newer);
    expect(result.closed).toBe(false);
    expect(close).not.toHaveBeenCalled();
  });

  it("closes only when the user confirmed hiding exactly the unticked items", async () => {
    for (const hide of [0, 2]) {
      const { live } = await seeded();
      const close = vi.fn(async () => true);
      // Ticked: everything but the forged page, so one item stays hidden; the user confirmed a different count.
      const result = await migrateLegacy(live.api, await prepared(live, [id("obj", "a"), id("cmt", "a"), id("att", "a"), id("cfl", "a")], { hide }), close);
      expect(result).toMatchObject({ failed: [], closed: false });
      expect(close).not.toHaveBeenCalled();
    }
  });

  it("refuses an approval from before a sharing change, and never closes after one mid-run", async () => {
    const { live } = await seeded();
    const close = vi.fn(async () => true);
    const stale = await prepared(live, [id("obj", "a")]);
    await expect(migrateLegacy(live.api, { ...stale, floorNow: () => ({ shared: 3, generation: 3 }) }, close)).rejects.toThrow(/review/i);
    await expect(migrateLegacy(live.api, { ...(await prepared(live, [id("obj", "a")])), floorNow: () => undefined }, close)).rejects.toThrow(/review/i);
    // A review of a notebook that was not shared yet approves nothing to seal under a container key.
    const unsharedReview = await reviewLegacy(live.api, { container: { ...container, sharedGeneration: 0 }, floorNow: () => ({}), legacy: mine, userId: me });
    const unshared = approveMigration(me, cnt, unsharedReview, [], 0);
    await expect(migrateLegacy(live.api, { ...stale, floorNow: () => ({}), approval: unshared }, close)).rejects.toThrow(/review/i);
    expect(live.sends).toEqual([]);
    // The floor rises while the run is sending: the writes stand, but nothing closes.
    let now: KeyFloor = floor;
    const input = await prepared(live, [id("obj", "a"), id("cmt", "a"), id("att", "a"), id("cfl", "a")]);
    const send = live.api.sendCommentRewrite;
    live.api.sendCommentRewrite = async (...args) => { now = { shared: 3, generation: 3 }; return send(...args); };
    const result = await migrateLegacy(live.api, { ...input, floorNow: () => now }, close);
    expect(result).toMatchObject({ failed: [], closed: false });
    expect(close).not.toHaveBeenCalled();
  });

  it("a second run shares only what the first left, and running it again changes nothing", async () => {
    const { live } = await seeded();
    const close = vi.fn(async () => true);
    const both = [id("obj", "a"), id("cmt", "a")];
    const working = live.api.sendCommentRewrite;
    live.api.sendCommentRewrite = async () => { throw new Error("offline"); }; // the first run dies at the comment
    await migrateLegacy(live.api, await prepared(live, both), close);
    expect(live.objects.get(id("obj", "a"))!.keyGeneration).toBe(2);
    expect(close).not.toHaveBeenCalled();
    // Reconnected: the review no longer offers the page, so only the comment is sent, and the run closes.
    live.api.sendCommentRewrite = working;
    live.sends.length = 0;
    const offered = await reviewLegacy(live.api, { container, floorNow: () => floor, legacy: mine, userId: me });
    expect(offered.mine.map((item) => item.id)).not.toContain(id("obj", "a"));
    const second = await prepared(live, both);
    await migrateLegacy(live.api, second, close);
    expect(live.sends).toEqual([`comment:${id("cmt", "a")}`]);
    expect(close).toHaveBeenCalledOnce();
    // Only unticked rows are left: a third run sends nothing and leaves the server as it was.
    live.sends.length = 0;
    const before = live.state();
    await migrateLegacy(live.api, await prepared(live, both), close);
    expect(live.sends).toEqual([]);
    expect(live.state()).toBe(before);
  });

  it("rewriteRefs replaces only whole attachment IDs and returns the same object when nothing changed", () => {
    const old = id("att", "a"), next = id("att", "b");
    const payload = page("p", `attachment://${old} attachment://${id("att", "c")}`);
    expect(rewriteRefs(payload, { [old]: next })).toEqual(page("p", `attachment://${next} attachment://${id("att", "c")}`));
    expect(rewriteRefs(payload, {})).toBe(payload);
    expect(rewriteRefs(payload, { "att_bad": next, [old]: "att_x\"}" })).toBe(payload); // malformed IDs are ignored
  });

  it("shares the ticked rows of an incomplete review but never closes (I1)", async () => {
    const { live } = await seeded();
    // The fetch of one listed page fails during the review: the user never saw it, so its row cannot be counted.
    const read = live.api.readObject;
    live.api.readObject = async (oid) => { if (oid === id("obj", "f")) throw new Error("500"); return read(oid); };
    const review = await reviewLegacy(live.api, { container, floorNow: () => floor, legacy: mine, userId: me });
    expect(review.complete).toBe(false);
    live.api.readObject = read;
    const all = review.mine.map((item) => item.id);
    const close = vi.fn(async () => true);
    const result = await migrateLegacy(live.api, { container, floorNow: () => floor, legacy: mine, userId: me, write, ring: new Map([[2, ck]]), approval: approveMigration(me, cnt, review, all, 0) }, close);
    expect(result).toMatchObject({ failed: [], closed: false, incomplete: true });
    expect([...result.shared].sort()).toEqual([...all].sort());
    expect(close).not.toHaveBeenCalled();
    expect(live.objects.get(id("obj", "f"))!.keyGeneration).toBe(1);
  });

  it("approves only a review that reviewLegacy produced (M3)", async () => {
    const { live } = await seeded();
    const review = await reviewLegacy(live.api, { container, floorNow: () => floor, legacy: mine, userId: me });
    for (const fake of [{ ...review }, { mine: review.mine, others: 0, refused: 0, complete: true, shared: 2 }, Object.create(review)])
      expect(() => approveMigration(me, cnt, fake as LegacyReview, [id("obj", "a")], 0)).toThrow();
    expect(() => approveMigration(me, cnt, review, [id("obj", "a")], 0)).not.toThrow();
  });

  it("names the unticked pages that keep a shared attachment and block closing (M4)", async () => {
    const { live, image } = await seeded();
    const untickedPage = id("obj", "b");
    live.objects.set(untickedPage, { bytes: await encryptNote(mine, cnt, page("Leftover", `attachment://${image}`)), version: 1, keyGeneration: 1 });
    live.attachments.get(image)!.objectIds.push(untickedPage);
    const close = vi.fn(async () => true);
    const result = await migrateLegacy(live.api, await prepared(live, [id("obj", "a"), image]), close);
    expect(result.closed).toBe(false);
    expect(result.blockedBy).toEqual([{ id: untickedPage, title: "Leftover", attachment: image }]);
    expect(close).not.toHaveBeenCalled();
  });

  it("only LegacyReview.tsx mints approvals", () => {
    const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(["./main.tsx", "./migration.ts"]));
    // The identifier itself, so an aliased import, a re-export or a namespace access is caught too.
    const naming = (all: Record<string, string>) => Object.entries(all).filter(([name, text]) => /\bapproveMigration\b/.test(text) && (!["./migration.ts", "./components/LegacyReview.tsx"].includes(name) || /\bapproveMigration\s+as\b/.test(text))).map(([name]) => name);
    expect(naming(sources)).toEqual([]);
    expect(naming({
      "./main.tsx": 'import { approveMigration as approve } from "./migration";\napprove(u, c, r, t, 0);',
      "./other.ts": 'import * as m from "./migration"; m.approveMigration(u, c, r, t, 0);',
      "./reexport.ts": 'export { approveMigration as a } from "./migration";',
      "./components/LegacyReview.tsx": 'import { approveMigration as ok } from "../migration";',
    })).toEqual(["./main.tsx", "./other.ts", "./reexport.ts", "./components/LegacyReview.tsx"]);
  });
});

describe("migrateLegacy through the outbound gate", () => {
  const fetches = vi.fn(async () => new Response(JSON.stringify({ version: 4 }), { status: 200, headers: { "X-Kynotes-Version": "4" } }));
  afterEach(() => { vi.unstubAllGlobals(); clearFloors(); fetches.mockClear(); });

  it("sends nothing sealed for a key that is no longer the current one", async () => {
    vi.stubGlobal("fetch", fetches);
    vi.stubGlobal("document", { cookie: "" });
    const { live } = await seeded();
    const input = await prepared(live, [id("obj", "a")]);
    // This tab has moved on to generation 3 (a rotation): the run's generation-2 write key is stale.
    clearFloors();
    raiseFloorIn(cnt, { shared: 2, generation: 3 });
    const rotated: ReportedContainer = { ...container, keyGeneration: 3 };
    const unregister = setWriteKeySource((reported) => keysAllowed(reported, floor) ? writeKey(rotated, new Map([[3, newContainerKey()]]), mine, { shared: 2, generation: 3 }) : undefined);
    try {
      const result = await migrateLegacy({ ...live.api, sendObject }, input, vi.fn(async () => true));
      expect(result).toMatchObject({ closed: false, failed: [{ id: id("obj", "a"), reason: new KeysWaitingError().message }] });
      expect(fetches).not.toHaveBeenCalled();
    } finally { unregister(); }
  });
});

describe("checkLegacyRows (the workspace's check)", () => {
  const empty = () => reviewLegacy(server({}, {}), { container, floorNow: () => floor, legacy: mine, userId: me });
  it("never closes after a rejected review, and hands the rejection back (N2)", async () => {
    for (const failure of [new Error("429"), new Error("500"), new TypeError("Failed to fetch"), new LegacyClosedError()]) {
      const close = vi.fn(async () => true);
      expect(await checkLegacyRows(() => Promise.reject(failure), () => floor, close)).toEqual({ failed: failure });
      expect(close).not.toHaveBeenCalled();
    }
  });

  it("auto-closes only a complete review with nothing of this user's, while open and not just reopened", async () => {
    const close = vi.fn(async () => true);
    expect(await checkLegacyRows(empty, () => floor, close)).toMatchObject({ autoClosed: true });
    expect(close).toHaveBeenCalledOnce();
    close.mockClear();
    const incomplete = () => reviewLegacy(server({}, { complete: false }), { container, floorNow: () => floor, legacy: mine, userId: me });
    expect(await checkLegacyRows(incomplete, () => floor, close)).toMatchObject({ autoClosed: false });
    expect(await checkLegacyRows(empty, () => ({ ...floor, closed: 2 }), close)).toMatchObject({ autoClosed: false });
    expect(await checkLegacyRows(empty, () => ({ shared: 3, generation: 3 }), close)).toMatchObject({ autoClosed: false });
    expect(await checkLegacyRows(empty, () => floor, close, false)).toMatchObject({ autoClosed: false });
    expect(close).not.toHaveBeenCalled();
    // A close that storage did not keep is reported as not closed.
    expect(await checkLegacyRows(empty, () => floor, async () => false)).toMatchObject({ autoClosed: false });
  });
});
