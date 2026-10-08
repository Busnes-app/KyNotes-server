import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { decryptAttachment, decryptAttachmentMetadata, encryptAttachment, encryptAttachmentMetadata, fromBase64, base64, legacyKeyRef } from "./crypto";
import { attachmentStep, sealAttachment } from "./drain";
import { clearFloors, floorOf, raiseFloorIn } from "./floors";
import { keysAllowed, newContainerKey, writeKey, type ReportedContainer } from "./keyring";
import { confirmCheckCode, discardLinkKey, newLinkKey } from "./linking";
import { collectLinkBundle, KeysWaitingError, sendCiphertext, sendLinkBundle, sendUploadChunk, setWriteKeySource } from "./outbound";
import type { PendingUpload } from "./storage";

const cnt = `cnt_${"a".repeat(26)}`;
const login = legacyKeyRef("a".repeat(64));
const file = { name: "photo.png", type: "image/png", size: 4 };
const shared: ReportedContainer = { id: cnt, kind: "team", keyGeneration: 2, sharedGeneration: 2 };

describe("outbound ciphertext gate", () => {
  const ring = new Map<number, Uint8Array>();
  let unregister = () => {};
  const fetches = vi.fn(async () => new Response(JSON.stringify({ receivedBytes: 4, nextChunk: 1 }), { status: 200 }));
  beforeEach(() => {
    clearFloors();
    ring.clear();
    fetches.mockClear();
    vi.stubGlobal("fetch", fetches);
    vi.stubGlobal("document", { cookie: "" });
    // main.tsx's writeKeyFor: the tab-wide floor, this tab's ring, the login key.
    unregister = setWriteKeySource((container) => {
      const floor = floorOf(container.id);
      return floor && keysAllowed(container, floor) ? writeKey(container, ring, login, floor) : undefined;
    });
  });
  afterEach(() => { unregister(); vi.unstubAllGlobals(); });

  it("sends no chunk of a legacy pending upload once sharing is known, and re-seals it for the current key", async () => {
    const plaintext = new Uint8Array([1, 2, 3, 4]);
    // Started before sharing: sealed with the login key at generation 1.
    const job: PendingUpload = { uploadId: "upl", containerID: cnt, objectID: "obj", objectVersion: 1, keyGeneration: 1, chunkBytes: 4, nextChunk: 0, payload: await encryptAttachment(login, cnt, plaintext), metadataCiphertext: base64(await encryptAttachmentMetadata(login, cnt, file)), ...file };
    raiseFloorIn(cnt, { shared: 2, generation: 2 });
    // Keys missing: the resume waits, and the gate refuses the stored chunk outright.
    expect((await attachmentStep(job, shared, floorOf(cnt), undefined, ring, login)).kind).toBe("wait");
    expect(() => sendUploadChunk({ container: shared, generation: job.keyGeneration }, job.uploadId, 0, job.payload)).toThrow(KeysWaitingError);
    expect(fetches).not.toHaveBeenCalled();
    // The key arrives: the payload and metadata are re-sealed before any chunk is sent.
    const key = newContainerKey();
    ring.set(2, key);
    const write = writeKey(shared, ring, login, floorOf(cnt)!)!;
    const step = await attachmentStep(job, shared, floorOf(cnt), write, ring, login);
    expect(step.kind).toBe("reseal");
    if (step.kind !== "reseal") return;
    const resealed = await sealAttachment(write, cnt, step.plaintext, step.file);
    expect(resealed.keyGeneration).toBe(2);
    expect(await decryptAttachment(key, cnt, resealed.payload)).toEqual(plaintext);
    expect(await decryptAttachmentMetadata(key, cnt, fromBase64(resealed.metadataCiphertext))).toEqual(file);
    await expect(decryptAttachment(login, cnt, resealed.payload)).rejects.toThrow();
    // The old ciphertext still never passes; the re-sealed one does.
    expect(() => sendUploadChunk({ container: shared, generation: 1 }, job.uploadId, 0, job.payload)).toThrow(KeysWaitingError);
    await sendUploadChunk({ container: shared, generation: 2 }, "upl2", 0, resealed.payload);
    expect(fetches).toHaveBeenCalledOnce();
    expect((fetches.mock.calls[0] as unknown as [string, RequestInit])[1].body).toEqual(resealed.payload);
  });

  it("refuses a stale container object, an unloaded floor, and any send with no workspace mounted", () => {
    raiseFloorIn(cnt, { shared: 0, generation: 1 });
    const unshared: ReportedContainer = { id: cnt, kind: "team", keyGeneration: 1, sharedGeneration: 0 };
    expect(() => sendCiphertext({ container: unshared, generation: 1 })).not.toThrow();
    raiseFloorIn(cnt, { shared: 2, generation: 2 });
    expect(() => sendCiphertext({ container: unshared, generation: 1 })).toThrow(KeysWaitingError);
    expect(() => sendCiphertext({ container: { ...unshared, id: `cnt_${"b".repeat(26)}` }, generation: 1 })).toThrow(KeysWaitingError);
    unregister();
    ring.set(2, newContainerKey());
    expect(() => sendCiphertext({ container: shared, generation: 2 })).toThrow(KeysWaitingError);
  });

  it("lets a link bundle leave only with that request's check-code confirmation", async () => {
    const id = `lnk_${"a".repeat(26)}`;
    const bundle = new Uint8Array(61);
    expect(() => sendLinkBundle({ requestID: id } as never, id, bundle)).toThrow(/check codes/);
    expect(() => sendLinkBundle(confirmCheckCode(`lnk_${"b".repeat(26)}`, "123 456"), id, bundle)).toThrow(/check codes/);
    expect(fetches).not.toHaveBeenCalled();
    await sendLinkBundle(confirmCheckCode(id, "123 456"), id, bundle);
    expect((fetches.mock.calls[0] as unknown as [string])[0]).toBe(`/api/v1/me/link-requests/${id}/approve`);
  });

  it("collects a link bundle only while this attempt's one-time key is held", async () => {
    const id = `lnk_${"a".repeat(26)}`;
    const key = newLinkKey();
    await collectLinkBundle(key, id);
    expect((fetches.mock.calls[0] as unknown as [string, RequestInit])[0]).toBe(`/api/v1/me/link-requests/${id}/collect`);
    discardLinkKey(key);
    // Collecting deletes the bundle; without the key it could never be opened.
    expect(() => collectLinkBundle(key, id)).toThrow(/ended/);
    expect(() => collectLinkBundle({ ...newLinkKey() }, id)).toThrow(/ended/);
    expect(fetches).toHaveBeenCalledOnce();
  });
});

describe("outbound structure", () => {
  it("only outbound.ts reaches the ciphertext upload API functions", () => {
    const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./api.ts", "!./outbound.ts", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
    expect(Object.keys(sources)).toContain("./main.tsx");
    const raw = /\b(saveObject|uploadChunk|finalizeUpload|createUpload|createComment|updateContainer|approveLinkRequest|collectLinkRequest)\b/;
    expect(Object.entries(sources).filter(([, text]) => raw.test(text)).map(([name]) => name)).toEqual([]);
  });

  it("never lets a failed local cache write stop an edit from being sent", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    // A rejected cacheWrite is captured (cacheMiss) and reported; the send runs regardless.
    expect(main).not.toMatch(/await cacheWrite\(/);
    expect(main.match(/await cacheMiss\(/g)).toHaveLength(2);
  });
});
