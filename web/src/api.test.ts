import { afterEach, describe, expect, it, vi } from "vitest";
import { acceptInvitation, APIRequestError, cancelLinkRequest, claimLinkRequest, collectLinkRequest, createLinkRequest, inviteMember, putDeviceOnlyIdentity, readObject, revealLinkRequest, serverGeneration } from "./api";

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
