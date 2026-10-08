import { afterEach, describe, expect, it, vi } from "vitest";
import { readObject, serverGeneration } from "./api";

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
