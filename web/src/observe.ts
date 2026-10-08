import { adminTeams, containers, createAdminTeam, createContainer } from "./api";
import { closeFloorIn, floorOf, publishFloor } from "./floors";
import { mergeFloor, type KeyFloor, type KeyState } from "./keyring";
import type { ClosureStored } from "./storage";

/** This device's key memory; the observed floor also goes to the tab-wide store (floors.ts). */
export type FloorSink = {
  load: (containerID: string) => Promise<KeyFloor>;
  /** Add-only merge (storeKeyState); false or a throw means it was not kept. */
  save: (containerID: string, state: KeyState) => Promise<boolean>;
};
type Reported = { id: string; keyGeneration?: number; sharedGeneration?: number };

/**
 * Every container row the server sends passes here before anyone uses it: the generations it
 * reports raise this device's floor in memory (always) and in storage (add-only, best effort).
 */
export async function observeContainer<C extends Reported>(sink: FloorSink, container: C): Promise<C> {
  const seen = { shared: container.sharedGeneration ?? 0, generation: container.keyGeneration ?? 0 };
  const stored = await sink.load(container.id).then((floor) => floor, () => undefined);
  const floor = mergeFloor(stored, seen);
  publishFloor(container.id, floor, stored !== undefined);
  if (floor.shared !== (stored?.shared ?? 0) || floor.generation !== (stored?.generation ?? 0) || !stored)
    await sink.save(container.id, { mark: 0, digests: {}, ...seen }).catch(() => false);
  return container;
}
export const observeContainers = <C extends Reported>(sink: FloorSink, list: C[]) => Promise.all(list.map((entry) => observeContainer(sink, entry)));

/** storage.ts closeLegacyStored for the signed-in user. */
export type ClosureSink = { close: (containerID: string, closed: number, auto: boolean) => Promise<ClosureStored> };
/**
 * closed: closed in every tab and in storage. unsaved: storage could not keep it; a user's Stop
 * still closed every tab until a reload, an automatic close closed nothing. reopened: an automatic
 * close refused because the user reopened the notebook. not-shared: this tab has not loaded the
 * notebook or this device has not seen it shared; nothing changed.
 */
export type Closed = ClosureStored | "not-shared";
/**
 * Stops this device opening a shared container's legacy rows with the login key. A user's close
 * (Stop, a completed share) closes every tab at once (floors.ts), then storage. An automatic one
 * (auto) writes storage first, refused there while the reopen mark is set, and closes the tabs only
 * once storage kept it: a browser that cannot keep a closure never closes by itself.
 */
export async function closeLegacy(sink: ClosureSink, containerID: string, auto = false): Promise<Closed> {
  const shared = floorOf(containerID)?.shared ?? 0;
  if (shared === 0) return "not-shared";
  if (!auto) closeFloorIn(containerID, shared);
  const stored = await sink.close(containerID, shared, auto).catch(() => "unsaved" as const);
  if (auto && stored === "closed") closeFloorIn(containerID, shared);
  return stored;
}

// The only callers of the raw container fetchers; every other module imports these instead (observe.test.ts).
export const listContainers = async (sink: FloorSink) => observeContainers(sink, await containers());
export const newContainer = async (sink: FloorSink, ...args: Parameters<typeof createContainer>) => observeContainer(sink, await createContainer(...args));
export const listAdminTeams = async (sink: FloorSink) => observeContainers(sink, await adminTeams());
export const newAdminTeam = async (sink: FloorSink, metaCiphertext: string) => observeContainer(sink, await createAdminTeam(metaCiphertext));
