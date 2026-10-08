import { adminTeams, containers, createAdminTeam, createContainer } from "./api";
import { mergeFloor, type KeyFloor, type KeyState } from "./keyring";

/** Where an observed floor goes: this device's key memory, and the caller's in-memory floors. */
export type FloorSink = {
  load: (containerID: string) => Promise<KeyFloor>;
  /** Add-only merge (storeKeyState); false or a throw means it was not kept. */
  save: (containerID: string, state: KeyState) => Promise<boolean>;
  /** loaded is false when storage could not be read: only a floor already in memory may rise. */
  publish: (containerID: string, floor: KeyFloor, loaded: boolean) => void;
};
type Reported = { id: string; keyGeneration?: number; sharedGeneration?: number };

/** The in-memory floor after a publish; an unknown floor stays unknown (no key) unless storage was read. */
export const nextFloor = (current: KeyFloor | undefined, floor: KeyFloor, loaded: boolean): KeyFloor | undefined =>
  loaded || current ? mergeFloor(current, floor) : undefined;

/**
 * Every container row the server sends passes here before anyone uses it: the generations it
 * reports raise this device's floor in memory (always) and in storage (add-only, best effort).
 */
export async function observeContainer<C extends Reported>(sink: FloorSink, container: C): Promise<C> {
  const seen = { shared: container.sharedGeneration ?? 0, generation: container.keyGeneration ?? 0 };
  const stored = await sink.load(container.id).then((floor) => floor, () => undefined);
  const floor = mergeFloor(stored, seen);
  sink.publish(container.id, floor, stored !== undefined);
  if (floor.shared !== (stored?.shared ?? 0) || floor.generation !== (stored?.generation ?? 0) || !stored)
    await sink.save(container.id, { mark: 0, digests: {}, ...seen }).catch(() => false);
  return container;
}
export const observeContainers = <C extends Reported>(sink: FloorSink, list: C[]) => Promise.all(list.map((entry) => observeContainer(sink, entry)));

// The only callers of the raw container fetchers; main.tsx imports these instead (observe.test.ts).
export const listContainers = async (sink: FloorSink) => observeContainers(sink, await containers());
export const newContainer = async (sink: FloorSink, ...args: Parameters<typeof createContainer>) => observeContainer(sink, await createContainer(...args));
export const listAdminTeams = async (sink: FloorSink) => observeContainers(sink, await adminTeams());
export const newAdminTeam = async (sink: FloorSink, metaCiphertext: string) => observeContainer(sink, await createAdminTeam(metaCiphertext));
