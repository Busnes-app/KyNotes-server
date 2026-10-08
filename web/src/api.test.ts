import { afterEach, describe, expect, it, vi } from "vitest";
import { readObject } from "./api";

const obj = `obj_${"a".repeat(26)}`;
const serve = (headers: Record<string, string>) => vi.stubGlobal("fetch", vi.fn(async () => new Response(new Uint8Array([1]), { headers })));

describe("readObject key generation", () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it("reads the generation the server sent", async () => {
    serve({ "X-Kynotes-Version": "3", "X-Kynotes-Key-Generation": "4" });
    expect((await readObject(obj)).keyGeneration).toBe(4);
  });

  it("is undefined when the header is missing or malformed, never 0", async () => {
    for (const headers of [{} as Record<string, string>, { "X-Kynotes-Key-Generation": "" }, { "X-Kynotes-Key-Generation": "2x" }, { "X-Kynotes-Key-Generation": "-1" }]) {
      serve(headers);
      expect((await readObject(obj)).keyGeneration).toBeUndefined();
    }
  });
});
