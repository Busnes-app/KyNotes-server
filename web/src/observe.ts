import { adminTeams, containers, createAdminTeam, createContainer } from "./api";
import { publishFloor } from "./floors";
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

// The only callers of the raw container fetchers; every other module imports these instead (observe.test.ts).
export const listContainers = async (sink: FloorSink) => observeContainers(sink, await containers());
export const newContainer = async (sink: FloorSink, ...args: Parameters<typeof createContainer>) => observeContainer(sink, await createContainer(...args));
export const listAdminTeams = async (sink: FloorSink) => observeContainers(sink, await adminTeams());
export const newAdminTeam = async (sink: FloorSink, metaCiphertext: string) => observeContainer(sink, await createAdminTeam(metaCiphertext));

export const NOT_CREATED = "The notebook could not get its own key, so it was not created. Try again.";
/**
 * Creates a container, then keys and names it (setUp). If setUp fails the new container is still empty
 * and unnamed, so it is deleted rather than left behind as an "Unnamed" notebook; NOT_CREATED then says
 * so. If the delete is refused too, setUp's own error stands (NOT_KEYED: reopen it to finish).
 */
export async function createKeyed<C extends { id: string }>(create: () => Promise<C>, setUp: (created: C) => Promise<C>, remove: (id: string) => Promise<void>): Promise<C> {
  const created = await create();
  try {
    return await setUp(created);
  } catch (error) {
    if (await remove(created.id).then(() => true, () => false)) throw new Error(NOT_CREATED, { cause: error });
    throw error;
  }
}

