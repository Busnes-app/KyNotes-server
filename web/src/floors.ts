import { useSyncExternalStore } from "react";
import { mergeFloor, type KeyFloor } from "./keyring";

/**
 * This tab's one in-memory sharing floor per container, shared by every component. Add-only: a
 * floor only rises until clearFloors (sign-out). Key decisions read floorOf at decision time.
 */
let floors: Readonly<Record<string, KeyFloor>> = {};
/** Peer raises for containers this tab has not loaded: never a loaded floor, only a minimum applied on load. */
let pending: Record<string, KeyFloor> = {};
const listeners = new Set<() => void>();
const changed = () => { for (const listener of listeners) listener(); };
const merge = (containerID: string, floor: KeyFloor) => {
  const minimum = pending[containerID];
  if (minimum) delete pending[containerID];
  floors = { ...floors, [containerID]: mergeFloor(mergeFloor(floors[containerID], floor), minimum ?? {}) };
  changed();
};

/**
 * Other tabs of this origin hear every raise: numbers only, nothing secret. A message is a server
 * claim relayed by a peer: validated here and merged add-only. For a container this tab has not
 * loaded it is kept as a minimum applied when the stored floor loads; it never makes a floor known.
 * A forged one can at most raise a floor (denial of service, never a key).
 */
const channel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel("kynotes-floors");
const containerIDPattern = /^cnt_[0-9abcdefghjkmnpqrstvwxyz]{26}$/;
const count = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
if (channel) channel.onmessage = (event: MessageEvent) => {
  const { containerID, shared, generation } = (event.data ?? {}) as Record<string, unknown>;
  if (typeof containerID !== "string" || !containerIDPattern.test(containerID)) return;
  if (!count(shared) || !count(generation)) return;
  if (floors[containerID]) merge(containerID, { shared, generation });
  else pending[containerID] = mergeFloor(pending[containerID], { shared, generation });
};

/** undefined: not loaded in this tab, so no key. */
export const floorOf = (containerID: string): KeyFloor | undefined => floors[containerID];
/** Raises this tab's floor, then tells the others. */
export function raiseFloorIn(containerID: string, floor: KeyFloor): void {
  merge(containerID, floor);
  const { shared = 0, generation = 0 } = floors[containerID];
  channel?.postMessage({ containerID, shared, generation });
}
/** loaded false (storage unreadable): only a floor this tab already holds may rise; unknown stays unknown. */
export function publishFloor(containerID: string, floor: KeyFloor, loaded: boolean): void {
  if (loaded || floors[containerID]) raiseFloorIn(containerID, floor);
}
export function clearFloors(): void {
  floors = {};
  pending = {};
  changed();
}
const subscribe = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };
/** Re-renders the caller when any floor rises. */
export const useFloors = () => useSyncExternalStore(subscribe, () => floors);
