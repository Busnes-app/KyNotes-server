import { afterEach, describe, expect, it, vi } from "vitest";
import { serviceStatus } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("service status probes", () => {
  it("reports HTTP refusal independently", async () => {
    vi.stubGlobal("fetch", vi.fn((url: string) => Promise.resolve(new Response(null, { status: url === "/healthz" ? 200 : 503 }))));
    await expect(serviceStatus()).resolves.toEqual({ health: true, ready: false });
  });

  it.each(["/healthz", "/readyz"])("keeps the other result when %s is unreachable", async (failed) => {
    vi.stubGlobal("fetch", vi.fn((url: string) => url === failed ? Promise.reject(new TypeError("Failed to fetch")) : Promise.resolve(new Response(null, { status: 200 }))));
    await expect(serviceStatus()).resolves.toEqual({ health: failed !== "/healthz", ready: failed !== "/readyz" });
  });

  it("returns failed probes after a network outage and recovers on retry", async () => {
    const fetcher = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    vi.stubGlobal("fetch", fetcher);
    await expect(serviceStatus()).resolves.toEqual({ health: false, ready: false });
    fetcher.mockResolvedValue(new Response(null, { status: 200 }));
    await expect(serviceStatus()).resolves.toEqual({ health: true, ready: true });
  });
});
