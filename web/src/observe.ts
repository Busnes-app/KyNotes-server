import { adminTeams, containers, createAdminTeam, createContainer } from "./api";
import { floorOf, publishFloor, raiseFloorIn } from "./floors";
import { mergeFloor, type KeyFloor, type KeyState } from "./keyring";

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

/**
 * Stops this device opening a shared container's legacy rows with the login key: in this tab and
 * every other one at once (floors.ts), and in storage (add-only). Never for a container this tab
 * has not loaded or this device has not seen shared. False when storage did not keep it; memory
 * still does until a reload, after which the review runs again.
 */
export async function closeLegacy(sink: FloorSink, containerID: string): Promise<boolean> {
  const floor = floorOf(containerID);
  const shared = floor?.shared ?? 0;
  if (!floor || shared === 0) return false;
  raiseFloorIn(containerID, { ...floor, closed: shared });
  return sink.save(containerID, { mark: 0, digests: {}, shared, generation: floor.generation ?? 0, closed: shared }).catch(() => false);
}

// The only callers of the raw container fetchers; every other module imports these instead (observe.test.ts).
export const listContainers = async (sink: FloorSink) => observeContainers(sink, await containers());
export const newContainer = async (sink: FloorSink, ...args: Parameters<typeof createContainer>) => observeContainer(sink, await createContainer(...args));
export const listAdminTeams = async (sink: FloorSink) => observeContainers(sink, await adminTeams());
export const newAdminTeam = async (sink: FloorSink, metaCiphertext: string) => observeContainer(sink, await createAdminTeam(metaCiphertext));
