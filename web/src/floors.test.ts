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
  it("a closure reaches other tabs and never reopens; older messages without it are still read", async () => {
    vi.stubGlobal("BroadcastChannel", FakeChannel);
    const [a, b] = [await tab(), await tab()];
    b.raiseFloorIn(cnt, { shared: 2, generation: 2 });
    a.raiseFloorIn(cnt, { shared: 2, generation: 2, closed: 2 });
    expect(b.floorOf(cnt)).toMatchObject({ closed: 2 });
    const forge = FakeChannel.open[0];
    for (const data of [
      { containerID: cnt, shared: 2, generation: 3 }, // no closed field: an older tab
      { containerID: cnt, shared: 2, generation: 3, closed: 0 },
      // Malformed closures reject the whole message: their generation 9 never lands.
      { containerID: cnt, shared: 2, generation: 9, closed: -1 },
      { containerID: cnt, shared: 2, generation: 9, closed: "2" },
    ]) forge.postMessage(data);
    expect(b.floorOf(cnt)).toMatchObject({ closed: 2, generation: 3 });
  });

  it("no raise, publish or message lowers a closure", async () => {
    vi.stubGlobal("BroadcastChannel", FakeChannel);
    const [a, b] = [await tab(), await tab()];
    a.raiseFloorIn(cnt, { shared: 2, generation: 2, closed: 2 });
    b.raiseFloorIn(cnt, { shared: 2, generation: 2 });
    a.raiseFloorIn(cnt, { shared: 2, generation: 3, closed: 0 });
    a.raiseFloorIn(cnt, { shared: 2, generation: 3 });
    a.publishFloor(cnt, { shared: 2, generation: 3 }, true);
    a.publishFloor(cnt, { shared: 2, generation: 3, closed: 0 }, false);
    for (const tab of [a, b]) expect(tab.floorOf(cnt)).toMatchObject({ closed: 2 });
  });

  it("a reopen message never lowers a closure: a tab lowers it only to what storage holds", async () => {
    vi.stubGlobal("BroadcastChannel", FakeChannel);
    const [a, b, c] = [await tab(), await tab(), await tab()];
    let stored: KeyFloor = { shared: 2, generation: 2, closed: 2 };
    const read = vi.fn(async () => stored);
    for (const t of [a, b]) t.setClosureReader(read);
    a.raiseFloorIn(cnt, { shared: 2, generation: 2, closed: 2 });
    expect(b.floorOf(cnt)).toBeUndefined(); // b holds the closure only as a minimum for now
    b.publishFloor(cnt, { shared: 2, generation: 2 }, true);
    c.raiseFloorIn(cnt, { shared: 2, generation: 2 });
    expect(c.floorOf(cnt)).toMatchObject({ closed: 2 });
    // Hints while storage still holds the closure, and a tab with no reader: nothing lowers.
    const forge = FakeChannel.open[0];
    forge.postMessage({ containerID: cnt, reopened: true });
    await a.reopenFloorIn(cnt);
    await vi.waitFor(() => expect(read).toHaveBeenCalledTimes(3));
    for (const t of [a, b, c]) expect(t.floorOf(cnt)).toMatchObject({ closed: 2 });
    // Storage reopened (storage.ts reopenLegacy): a reads it, b reads it on a's hint, c has no reader.
    stored = { shared: 2, generation: 2 };
    await a.reopenFloorIn(cnt);
    expect(a.floorOf(cnt)).toEqual({ shared: 2, generation: 2 });
    await vi.waitFor(() => expect(b.floorOf(cnt)).toEqual({ shared: 2, generation: 2 }));
    expect(c.floorOf(cnt)).toMatchObject({ closed: 2 });
    // A peer minimum for a container not loaded yet drops its closure too, and only from storage.
    const other = `cnt_${"d".repeat(26)}`;
    c.raiseFloorIn(other, { shared: 1, generation: 1, closed: 1 });
    forge.postMessage({ containerID: other, reopened: true });
    await vi.waitFor(() => expect(read).toHaveBeenCalledTimes(6));
    await new Promise((resolve) => setTimeout(resolve)); // b's adoption settles
    b.publishFloor(other, { shared: 1, generation: 1 }, true);
    expect(b.floorOf(other)).toEqual({ shared: 1, generation: 1 });
  });

});
