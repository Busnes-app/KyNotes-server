import { afterEach, describe, expect, it, vi } from "vitest";
import type { KeyFloor } from "./keyring";

/** Same-origin tabs: every channel of a name hears every other one, never itself. */
class FakeChannel {
  static open: FakeChannel[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  constructor(readonly name: string) { FakeChannel.open.push(this); }
  postMessage(data: unknown) {
    for (const peer of FakeChannel.open) if (peer !== this && peer.name === this.name) peer.onmessage?.({ data } as MessageEvent);
  }
}
const tab = async () => { vi.resetModules(); return import("./floors"); };
const cnt = `cnt_${"a".repeat(26)}`;

describe("floors across tabs", () => {
  afterEach(() => { vi.unstubAllGlobals(); FakeChannel.open = []; });

  it("a raise in one tab reaches another; malformed and lower messages are ignored", async () => {
    vi.stubGlobal("BroadcastChannel", FakeChannel);
    const [a, b] = [await tab(), await tab()];
    b.raiseFloorIn(cnt, { shared: 1, generation: 1 });
    a.raiseFloorIn(cnt, { shared: 2, generation: 3 });
    expect(b.floorOf(cnt)).toMatchObject({ shared: 2, generation: 3 });
    const forge = FakeChannel.open[0];
    for (const data of [
      { containerID: cnt, shared: 1, generation: 1 }, // lower: never lowers
      { containerID: cnt, shared: -1, generation: 9 },
      { containerID: cnt, shared: 2, generation: 1.5 },
      { containerID: cnt, shared: 2, generation: Number.MAX_SAFE_INTEGER + 1 },
      { containerID: cnt, shared: "9", generation: 9 },
      { containerID: "cnt_../../x", shared: 9, generation: 9 },
      { containerID: `cnt_${"I".repeat(26)}`, shared: 9, generation: 9 },
      null,
      "cnt",
    ]) forge.postMessage(data);
    expect(b.floorOf(cnt)).toMatchObject({ shared: 2, generation: 3 });
  });

  it("does not create a floor a tab has not loaded, applies a peer raise as a minimum on load, and works without a channel", async () => {
    vi.stubGlobal("BroadcastChannel", FakeChannel);
    const [a, b] = [await tab(), await tab()];
    a.raiseFloorIn(cnt, { shared: 2, generation: 2 });
    expect(b.floorOf(cnt)).toBeUndefined();
    // Held as a minimum: a lower stored floor loading later still comes out at the peer's floor.
    b.publishFloor(cnt, { shared: 0, generation: 1 }, true);
    expect(b.floorOf(cnt)).toMatchObject({ shared: 2, generation: 2 });
    // Unreadable storage keeps an unloaded container unknown, minimum or not.
    a.raiseFloorIn(`cnt_${"b".repeat(26)}`, { shared: 3, generation: 3 });
    b.publishFloor(`cnt_${"b".repeat(26)}`, { shared: 0, generation: 0 }, false);
    expect(b.floorOf(`cnt_${"b".repeat(26)}`)).toBeUndefined();
    vi.stubGlobal("BroadcastChannel", undefined);
    const alone = await tab();
    alone.raiseFloorIn(cnt, { shared: 1, generation: 1 });
    expect(alone.floorOf(cnt)).toMatchObject({ shared: 1, generation: 1 });
  });
  it("keeps only generations: a closure in a message or a stored floor from an older build is dropped", async () => {
    vi.stubGlobal("BroadcastChannel", FakeChannel);
    const [a, b] = [await tab(), await tab()];
    a.raiseFloorIn(cnt, { shared: 2, generation: 2, closed: 2 } as KeyFloor);
    expect(a.floorOf(cnt)).toEqual({ shared: 2, generation: 2 });
    b.raiseFloorIn(cnt, { shared: 2, generation: 2 });
    FakeChannel.open[0].postMessage({ containerID: cnt, shared: 2, generation: 3, closed: 2, reopened: true });
    expect(b.floorOf(cnt)).toEqual({ shared: 2, generation: 3 });
    // A message for a container not loaded yet is held as a minimum: also generations only.
    const other = `cnt_${"c".repeat(26)}`;
    FakeChannel.open[0].postMessage({ containerID: other, shared: 4, generation: 4, closed: 4 });
    b.publishFloor(other, { shared: 1, generation: 1 }, true);
    expect(b.floorOf(other)).toEqual({ shared: 4, generation: 4 });
  });

  it("the floor store reads and forwards only shared and generation", () => {
    const source = import.meta.glob<string>("./floors.ts", { query: "?raw", import: "default", eager: true })["./floors.ts"];
    const code = source.replace(/\/\*[^]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    // Every floor field it destructures, builds or posts: the two generations and the container ID.
    expect(code).not.toMatch(/\bclosed\b|\breopened\b|\.\.\.(?:floor|next|event\.data|data)\b/);
    expect(code).toContain("const { containerID, shared, generation } = (event.data ?? {}) as Record<string, unknown>;");
  });
});
