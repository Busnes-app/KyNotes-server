import { afterEach, describe, expect, it, vi } from "vitest";

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

  it("does not create a floor a tab has not loaded, and works without a channel", async () => {
    vi.stubGlobal("BroadcastChannel", FakeChannel);
    const [a, b] = [await tab(), await tab()];
    a.raiseFloorIn(cnt, { shared: 2, generation: 2 });
    expect(b.floorOf(cnt)).toBeUndefined();
    vi.stubGlobal("BroadcastChannel", undefined);
    const alone = await tab();
    alone.raiseFloorIn(cnt, { shared: 1, generation: 1 });
    expect(alone.floorOf(cnt)).toMatchObject({ shared: 1, generation: 1 });
  });
});
