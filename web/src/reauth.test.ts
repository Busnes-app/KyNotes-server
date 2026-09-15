import { afterEach, describe, expect, it, vi } from "vitest";
import { actionFetch } from "./api";
import { confirmSSOAction } from "./reauth";
vi.mock("./reauth", () => ({ confirmSSOAction: vi.fn() }));
afterEach(() => { vi.unstubAllGlobals(); vi.resetAllMocks(); });
describe("action-bound SSO retry", () => {
  it("retries the same body once with the verified challenge, including binary downloads", async () => {
    vi.stubGlobal("document", { cookie: "csrf_token=csrf" });
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: "sso_step_up_required", challenge: "rea_test" } }), { status: 403 }))
      .mockResolvedValueOnce(new Response(new Uint8Array([1, 2, 3])));
    vi.stubGlobal("fetch", fetcher);
    const init = { method: "POST", body: '{"target":1}', headers: { "X-CSRF-Token": "csrf" }, credentials: "include" } satisfies RequestInit;
    const response = await actionFetch("/action", init);
    expect(confirmSSOAction).toHaveBeenCalledWith("rea_test", "csrf");
    expect(fetcher).toHaveBeenCalledTimes(2);
    const retry = fetcher.mock.calls[1]?.[1];
    expect(retry.body).toBe(init.body);
    expect(retry.headers.get("X-Kynotes-Step-Up")).toBe("rea_test");
    expect(retry.headers.get("X-CSRF-Token")).toBe("csrf");
    expect(Array.from(new Uint8Array(await response.arrayBuffer()))).toEqual([1, 2, 3]);
  });
  it("never retries a cancelled confirmation", async () => {
    vi.stubGlobal("document", { cookie: "" });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: "sso_step_up_required", challenge: "rea_test" } }), { status: 403 })));
    vi.mocked(confirmSSOAction).mockRejectedValue(new Error("cancelled"));
    await expect(actionFetch("/action")).rejects.toThrow("cancelled");
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("does not reinterpret unrelated denials", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('{"error":{"code":"forbidden"}}', { status: 403 })));
    expect((await actionFetch("/action")).status).toBe(403);
    expect(confirmSSOAction).not.toHaveBeenCalled();
  });
});

it("detaches the popup opener before navigating to the issuer", async () => {
  const { confirmSSOAction: confirm } = await vi.importActual<typeof import("./reauth")>("./reauth");
  class Element {
    textContent = "";
    onclick: (() => void) | null = null;
    append() {}
    setAttribute() {}
    addEventListener() {}
    showModal() {}
    close() {}
    remove() {}
  }
  const elements: Element[] = [];
  vi.stubGlobal("document", { createElement: () => { const element = new Element(); elements.push(element); return element; }, body: { append() {} } });
  let navigated = false;
  const popup = {
    opener: {}, closed: false, close: vi.fn(),
    location: { set href(value: string) { expect(popup.opener).toBeNull(); expect(value).toBe("https://issuer.example/authorize"); navigated = true; } },
  };
  vi.stubGlobal("window", { open: vi.fn(() => popup) });
  vi.stubGlobal("fetch", vi.fn()
    .mockResolvedValueOnce(new Response('{"url":"https://issuer.example/authorize"}'))
    .mockResolvedValueOnce(new Response('{"verified":true}')));
  const pending = confirm("rea_popup", "csrf");
  const proceed = elements.find(element => element.textContent === "Continue to KySignOn");
  expect(proceed?.onclick).toBeTypeOf("function");
  proceed?.onclick?.();
  await pending;
  expect(navigated).toBe(true);
  expect(popup.close).toHaveBeenCalledOnce();
});
