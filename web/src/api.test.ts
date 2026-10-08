import { afterEach, describe, expect, it, vi } from "vitest";
import { acceptInvitation, APIRequestError, cancelLinkRequest, claimLinkRequest, collectLinkRequest, createLinkRequest, inviteMember, legacyRows, putDeviceOnlyIdentity, readObject, revealLinkRequest, serverGeneration } from "./api";

const obj = `obj_${"a".repeat(26)}`;
const serve = (headers: Record<string, string>) => vi.stubGlobal("fetch", vi.fn(async () => new Response(new Uint8Array([1]), { headers })));

describe("readObject key generation", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("reads the generation the server sent", async () => {
    serve({ "X-Kynotes-Version": "3", "X-Kynotes-Key-Generation": "4" });
    expect((await readObject(obj)).keyGeneration).toBe(4);
  });

  it("is undefined when the header is missing or malformed", async () => {
    for (const headers of [{} as Record<string, string>, { "X-Kynotes-Key-Generation": "" }, { "X-Kynotes-Key-Generation": "2x" }, { "X-Kynotes-Key-Generation": "-1" }, { "X-Kynotes-Key-Generation": "1.5" }, { "X-Kynotes-Key-Generation": "99999999999999999999" }]) {
      serve(headers);
      expect((await readObject(obj)).keyGeneration).toBeUndefined();
    }
  });
});

describe("serverGeneration", () => {
  it("passes non-negative safe integers and nothing else", () => {
    for (const value of [0, 1, 7, "0", "7"]) expect(serverGeneration(value)).toBe(Number(value));
    for (const value of [undefined, null, -1, 1.5, Number.NaN, "", "-1", "1.5", "0x1", true, {}, 2 ** 60]) expect(serverGeneration(value)).toBeUndefined();
  });
});

describe("inviteMember", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("sends envelopes only when it has some, so a keyless invitation needs no step-up", async () => {
    const sent: unknown[] = [];
    vi.stubGlobal("document", { cookie: "" });
    vi.stubGlobal("fetch", vi.fn(async (_path: string, init?: RequestInit) => {
      sent.push(JSON.parse(String(init?.body)));
      return Response.json({ id: "inv", token: "t", expiresAt: "e" });
    }));
    const cnt = `cnt_${"a".repeat(26)}`, usr = `usr_${"b".repeat(26)}`;
    const envelope = { containerId: cnt, deviceId: `dev_${"c".repeat(26)}`, keyGeneration: 2, alg: "x25519-hkdf-sha256-chacha20poly1305", envelope: "AA==" };
    await inviteMember(cnt, usr, "editor");
    await inviteMember(cnt, usr, "editor", [envelope]);
    expect(sent).toEqual([{ inviteeId: usr, role: "editor" }, { inviteeId: usr, role: "editor", envelopes: [envelope] }]);
  });
});

describe("acceptInvitation", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("sends the token in the body only, never in the URL", async () => {
    const token = "T".repeat(43);
    const calls: Array<[string, RequestInit | undefined]> = [];
    vi.stubGlobal("document", { cookie: "" });
    vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => { calls.push([path, init]); return new Response(null, { status: 204 }); }));
    await acceptInvitation(`inv_${"a".repeat(26)}`, token);
    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe(`/api/v1/invitations/inv_${"a".repeat(26)}/accept`);
    expect(calls[0][0]).not.toContain(token);
    expect(JSON.parse(String(calls[0][1]?.body))).toEqual({ token });
  });
});

describe("device-only identities and device links", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("sends device-only identities and link calls in the documented shapes", async () => {
    vi.stubGlobal("document", { cookie: "" });
    const fetches = vi.fn(async (_path: string, _init?: RequestInit) => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetches);
    await putDeviceOnlyIdentity("cHVi");
    await createLinkRequest("Y29t");
    await claimLinkRequest(`lnk_${"a".repeat(26)}`, "YXBw");
    await revealLinkRequest(`lnk_${"a".repeat(26)}`, "bmV3");
    await collectLinkRequest(`lnk_${"a".repeat(26)}`);
    const bodies = fetches.mock.calls.map(([url, init]) => `${init?.method} ${url} ${init?.body}`);
    expect(bodies).toEqual([
      `PUT /api/v1/me/identity {"publicKey":"cHVi","wrapAlg":"none"}`,
      `POST /api/v1/me/link-requests {"commitment":"Y29t"}`,
      `POST /api/v1/me/link-requests/lnk_${"a".repeat(26)}/claim {"approverKey":"YXBw"}`,
      `POST /api/v1/me/link-requests/lnk_${"a".repeat(26)}/reveal {"newcomerKey":"bmV3"}`,
      `POST /api/v1/me/link-requests/lnk_${"a".repeat(26)}/collect undefined`,
    ]);
  });

  it("cancels a link request with CSRF, and with keepalive when the page is going away", async () => {
    vi.stubGlobal("document", { cookie: "csrf_token=t" });
    const fetches = vi.fn(async (_path: string, _init?: RequestInit) => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetches);
    const id = `lnk_${"a".repeat(26)}`;
    await cancelLinkRequest(id);
    await cancelLinkRequest(id, true);
    for (const [path, init] of fetches.mock.calls) {
      expect(path).toBe(`/api/v1/me/link-requests/${id}`);
      expect(init?.method).toBe("DELETE");
      expect(new Headers(init?.headers).get("X-CSRF-Token")).toBe("t");
    }
    expect(fetches.mock.calls.map(([, init]) => init?.keepalive)).toEqual([false, true]);
  });

  it("keeps the open challenge of a step_up_pending refusal, so it can be cancelled", async () => {
    vi.stubGlobal("document", { cookie: "" });
    const challenge = `rea_${"a".repeat(26)}`;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: { code: "step_up_pending", message: "finish", challenge } }), { status: 409 })));
    const refusal = await putDeviceOnlyIdentity("cHVi").catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(APIRequestError);
    expect(refusal).toMatchObject({ code: "step_up_pending", challenge, status: 409 });
  });
});

describe("legacyRows", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("keeps only server generations it can trust, well-formed IDs and an explicit complete flag", async () => {
    const id = (prefix: string, c: string) => `${prefix}_${c.repeat(26)}`;
    const cnt = id("cnt", "a");
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({
      complete: "yes",
      objects: [{ id: id("obj", "a"), version: 2, keyGeneration: "1" }, { id: id("obj", "b"), version: 1, keyGeneration: -1 }, { id: "obj_../x", version: 1, keyGeneration: 1 }, { id: 7 }],
      comments: [{ id: id("cmt", "a"), objectId: id("obj", "a"), authorUserId: id("usr", "a"), bodyCiphertext: "AA==", keyGeneration: 1.5 }, { id: id("cmt", "b"), objectId: id("obj", "a"), authorUserId: id("usr", "a"), bodyCiphertext: 3 }],
      attachments: [{ id: id("att", "a"), objectIds: [id("obj", "a"), "obj_bad", 4], bytes: 4, metadataCiphertext: "AA==", keyGeneration: 1 }],
    })));
    const rows = await legacyRows(cnt);
    expect(rows.complete).toBe(false);
    expect(rows.objects.map((row) => [row.id, row.keyGeneration])).toEqual([[id("obj", "a"), 1], [id("obj", "b"), undefined]]);
    expect(rows.comments.map((row) => [row.id, row.keyGeneration])).toEqual([[id("cmt", "a"), undefined]]);
    expect(rows.attachments.map((row) => row.objectIds)).toEqual([[id("obj", "a")]]);
    expect(rows.conflicts).toEqual([]);
  });

  it("drops conflicts, attachments and comments with a malformed ID or ciphertext field", async () => {
    const id = (prefix: string, c: string) => `${prefix}_${c.repeat(26)}`;
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({
      complete: true,
      comments: [{ id: id("cmt", "a"), objectId: "obj_x", authorUserId: id("usr", "a"), bodyCiphertext: "" }, { id: id("cmt", "b"), objectId: id("obj", "a"), authorUserId: "me", bodyCiphertext: "" }],
      attachments: [{ id: id("att", "a"), objectIds: [], bytes: 1, metadataCiphertext: null }, { id: "att_x", objectIds: [], bytes: 1, metadataCiphertext: "" }],
      conflicts: [{ id: id("cfl", "a"), objectId: id("obj", "a"), createdAt: "t" }, { id: id("cfl", "b"), objectId: "../", createdAt: "t" }, { id: "x", objectId: id("obj", "a"), createdAt: "t" }],
    })));
    const rows = await legacyRows(`cnt_${"a".repeat(26)}`);
    expect(rows).toMatchObject({ complete: true, objects: [], comments: [], attachments: [] });
    expect(rows.conflicts.map((row) => row.id)).toEqual([id("cfl", "a")]);
  });

  it("fails on a rate limit, a server error or no network, never answering with an empty list", async () => {
    const cnt = `cnt_${"a".repeat(26)}`;
    for (const reply of [() => Response.json({ error: { code: "rate_limited", message: "slow down" } }, { status: 429 }), () => new Response("boom", { status: 500 }), () => { throw new TypeError("Failed to fetch"); }]) {
      vi.stubGlobal("fetch", vi.fn(async () => reply()));
      await expect(legacyRows(cnt)).rejects.toThrow();
    }
  });
});
