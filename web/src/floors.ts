import { useSyncExternalStore } from "react";
import { closedOf, mergeFloor, type KeyFloor } from "./keyring";

/**
 * This tab's one in-memory sharing floor per container, shared by every component. Add-only:
 * a floor only rises until clearFloors (sign-out), except closed, which adoptStored lowers to
 * what storage holds. Key decisions read floorOf at decision time.
 */
let floors: Readonly<Record<string, KeyFloor>> = {};
/** Peer raises for containers this tab has not loaded: never a loaded floor, only a minimum applied on load. */
let pending: Record<string, KeyFloor> = {};
const listeners = new Set<() => void>();
const changed = () => { for (const listener of listeners) listener(); };
/** Bumped each time a closure rises in this tab, so a storage read begun earlier cannot lower it. */
const closures: Record<string, number> = {};
const noteClosure = (containerID: string, before: KeyFloor | undefined, after: KeyFloor) => {
  if (closedOf(after) > closedOf(before)) closures[containerID] = (closures[containerID] ?? 0) + 1;
};
/** Without the closure: what a raise carries once the tab holds a floor (single writer, closeFloorIn). */
const open = (floor: KeyFloor): KeyFloor => { const { closed: _, ...rest } = floor; return rest; };
/**
 * closing false: a closure in floor is taken only on the tab's first load of the container (the
 * stored floor). After that only closeFloorIn and a peer's close message raise it, so a stale read
 * landing after a reopen never closes the tab again.
 */
const merge = (containerID: string, floor: KeyFloor, closing = false) => {
  const minimum = pending[containerID];
  if (minimum) delete pending[containerID];
  const before = floors[containerID];
  floors = { ...floors, [containerID]: mergeFloor(mergeFloor(before, closing || !before ? floor : open(floor)), minimum ?? {}) };
  noteClosure(containerID, before, floors[containerID]);
  changed();
};

/**
 * Other tabs of this origin hear every raise: numbers only, nothing secret. A message is a server
 * claim relayed by a peer: validated here and merged add-only. For a container this tab has not
 * loaded it is kept as a minimum applied when the stored floor loads; it never makes a floor known.
 * A forged one can at most raise a floor or close legacy reads (denial of service, never a key).
 * A reopen message only makes this tab re-read storage (adoptStored); it never lowers anything itself.
 */
const channel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel("kynotes-floors");
const containerIDPattern = /^cnt_[0-9abcdefghjkmnpqrstvwxyz]{26}$/;
const count = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
if (channel) channel.onmessage = (event: MessageEvent) => {
  const { containerID, shared, generation, closed = 0, reopened } = (event.data ?? {}) as Record<string, unknown>;
  if (typeof containerID !== "string" || !containerIDPattern.test(containerID)) return;
  if (reopened === true) { void adoptStored(containerID); return; }
  if (!count(shared) || !count(generation) || !count(closed)) return;
  const floor: KeyFloor = { shared, generation, ...(closed ? { closed } : {}) };
  // Only closeFloorIn sends a closure, so one in a message is a peer's close.
  if (floors[containerID]) merge(containerID, floor, true);
  else {
    const before = pending[containerID];
    pending[containerID] = mergeFloor(before, floor);
    noteClosure(containerID, before, pending[containerID]);
  }
};

/** This device's stored key memory (storage.ts getKeyState for the signed-in user); none: closures never fall. */
let readStored: ((containerID: string) => Promise<KeyFloor>) | undefined;
export const setClosureReader = (read: typeof readStored) => { readStored = read; };
const withClosure = (floor: KeyFloor, closed: number): KeyFloor => {
  const { closed: _, ...open } = floor;
  return closed ? { ...open, closed } : open;
};
/** The only way a closure falls in memory: to what storage holds, unless a closure rose during the read. */
async function adoptStored(containerID: string): Promise<void> {
  const epoch = closures[containerID];
  const stored = await readStored?.(containerID).catch(() => undefined);
  if (!stored || closures[containerID] !== epoch) return;
  const closed = closedOf(stored);
  if (floors[containerID] && closedOf(floors[containerID]) > closed) {
    floors = { ...floors, [containerID]: withClosure(floors[containerID], closed) };
    changed();
  }
  if (pending[containerID] && closedOf(pending[containerID]) > closed) pending[containerID] = withClosure(pending[containerID], closed);
}

/** undefined: not loaded in this tab, so no key. */
export const floorOf = (containerID: string): KeyFloor | undefined => floors[containerID];
/** Raises generations; a closure in floor counts only as this tab's first load (merge). Peers hear the generations only. */
export function raiseFloorIn(containerID: string, floor: KeyFloor): void {
  merge(containerID, floor);
  const { shared = 0, generation = 0 } = floors[containerID];
  channel?.postMessage({ containerID, shared, generation });
}
/** The in-memory half of observe.ts closeLegacy: this tab, then every other one, stops opening legacy rows. */
export function closeFloorIn(containerID: string, closed: number): void {
  merge(containerID, { closed }, true);
  const { shared = 0, generation = 0 } = floors[containerID];
  channel?.postMessage({ containerID, shared, generation, closed: closedOf(floors[containerID]) });
}
/** Second half of a reopen, after storage.ts reopenLegacy returned true: this tab, then every other one, adopts the stored closure. */
export async function reopenFloorIn(containerID: string): Promise<void> {
  await adoptStored(containerID);
  channel?.postMessage({ containerID, reopened: true });
}
/** loaded false (storage unreadable): only a floor this tab already holds may rise; unknown stays unknown. */
export function publishFloor(containerID: string, floor: KeyFloor, loaded: boolean): void {
  if (loaded || floors[containerID]) raiseFloorIn(containerID, floor);
}
export function clearFloors(): void {
  floors = {};
  pending = {};
  readStored = undefined;
  changed();
}
const subscribe = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };
/** Re-renders the caller when any floor rises. */
export const useFloors = () => useSyncExternalStore(subscribe, () => floors);
