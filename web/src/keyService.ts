import { base64 } from "./crypto";
import type { HeldIdentity, PublicIdentity } from "./identity";
import { newContainerKey, openKeyring, planSweep, sealFor, type Envelope, type KeyedContainer, type KeyState, type Keyring, type Member, type MemberKey, type OpenedKeyring, type SweepPlan } from "./keyring";
import { comparePins, confirmFingerprintChange, type PinChange, type PinConfirmation, type Pins } from "./pins";

export type KeyAPI = {
  /** The container's current generations; read at the start of every pass, never trusted from a tab's memory. */
  container: (containerID: string) => Promise<KeyedContainer>;
  envelopes: (containerID: string) => Promise<Envelope[]>;
  members: (containerID: string) => Promise<Member[]>;
  userIdentity: (userID: string) => Promise<PublicIdentity | undefined>;
  /** Proves the cached login secret again; envelope writes need a fresh user step-up. */
  stepUp: () => Promise<void>;
  putEnvelopes: (containerID: string, envelopes: Envelope[]) => Promise<void>;
  rotate: (containerID: string, expectedGeneration: number, envelopes: Envelope[]) => Promise<{ keyGeneration: number }>;
};
/** This device's pins and per-container key memory. Writes return false when nothing was kept. */
export type PinStore = {
  load: () => Promise<Pins>;
  /** Add-only: an existing pin is never overwritten. */
  addFresh: (pins: Pins) => Promise<boolean>;
  /** Replaces one pin; only a confirmFingerprintChange result. */
  confirm: (confirmation: PinConfirmation) => Promise<boolean>;
  loadKeyState: (containerID: string) => Promise<KeyState>;
  saveKeyState: (containerID: string, state: KeyState) => Promise<boolean>;
};
export type Caller = { userId: string; identity?: HeldIdentity; canWrap: boolean };
/**
 * plan: "untrusted" the user declined a changed colleague key; "pins-unsaved" this device
 * could not keep a pin. Neither shared anything. fresh: pinned this pass; changed: the
 * changed keys asked about; conflicts: generations whose envelope disagreed with an
 * accepted key (reported, never used or wrapped); known: the key memory persisted.
 */
export type KeySync = {
  container: KeyedContainer; ring: Keyring; minted: boolean; known: KeyState;
  plan: SweepPlan | { kind: "untrusted"; members: string[] } | { kind: "pins-unsaved" };
  fresh: MemberKey[]; changed: PinChange[]; conflicts: number[];
};

const code = (error: unknown) => (error as { code?: string }).code;
const isSteward = (role: string | undefined) => role === "owner" || role === "admin";

/**
 * Loads this browser's keys for a team container, authenticating senders against the
 * members' identities and this device's pins. When the caller is an owner or admin whose
 * session may wrap, it then shares keys: the first mint, the re-mint after a removal, and
 * wraps for members missing a generation. A changed colleague key stops everything unless
 * the user confirms it. Another steward winning a race (409 already_exists) is retried
 * once from fresh server state.
 */
export async function syncContainerKeys(api: KeyAPI, containerID: string, caller: Caller, store: PinStore, confirmChanged: (changes: PinChange[]) => boolean | Promise<boolean>, held?: Keyring): Promise<KeySync> {
  const identity = caller.identity;
  const me = identity && { ...identity, userId: caller.userId };
  for (let attempt = 0; ; attempt += 1) {
    let container = await api.container(containerID);
    const envelopes = await api.envelopes(container.id);
    const own = identity && { deviceId: identity.deviceId, publicKey: base64(identity.publicKey) };
    const members: MemberKey[] = await Promise.all((await api.members(container.id)).map(async (member) => ({ ...member, identity: member.userId === caller.userId && own ? own : await api.userIdentity(member.userId) })));
    const known = await store.loadKeyState(container.id);
    const open = (pins: Pins, rows: Envelope[], ring?: Keyring): OpenedKeyring => openKeyring({ containerID: container.id, envelopes: rows, me, members, pins, known, held: ring ?? held });
    const wraps = !!me && caller.canWrap && isSteward(members.find((member) => member.userId === caller.userId)?.role);
    const plan = (opened: OpenedKeyring): SweepPlan => {
      if (!wraps) return { kind: "idle" };
      const next = planSweep({ container, me: caller.userId, members, envelopes, ring: opened.ring });
      if (next.kind !== "wrap") return next;
      const grants = next.grants.filter((grant) => !opened.conflicts.includes(grant.generation));
      return grants.length ? { kind: "wrap", grants } : { kind: "idle" };
    };
    const targets = (next: SweepPlan): MemberKey[] => next.kind === "mint" ? next.recipients : next.kind === "wrap" ? next.grants.map((grant) => grant.member) : [];

    let pins = await store.load();
    let opened = open(pins, envelopes);
    let sweep = plan(opened);
    const changed = [...opened.changed, ...comparePins(pins, targets(sweep).filter((member) => member.userId !== caller.userId)).changed]
      .filter((change, i, all) => all.findIndex((other) => other.member.userId === change.member.userId) === i);
    const done = async (result: Omit<KeySync, "container" | "changed" | "conflicts" | "known">, last = opened): Promise<KeySync> => {
      await store.saveKeyState(container.id, last.known);
      return { container, changed, conflicts: last.conflicts, known: last.known, ...result };
    };
    if (changed.length) {
      if (!(await confirmChanged(changed))) return done({ ring: opened.ring, plan: { kind: "untrusted", members: changed.map((change) => change.member.username) }, minted: false, fresh: [] });
      for (const change of changed) {
        const confirmation = confirmFingerprintChange(pins, change.member);
        if (!(await store.confirm(confirmation))) return done({ ring: opened.ring, plan: { kind: "pins-unsaved" }, minted: false, fresh: [] });
        pins = confirmation.pins;
      }
      opened = open(pins, envelopes);
      sweep = plan(opened);
    }
    const fresh = [...opened.fresh];
    if (opened.fresh.length && !(await store.addFresh(opened.pins))) return done({ ring: opened.ring, plan: { kind: "pins-unsaved" }, minted: false, fresh });
    if (sweep.kind === "idle" || sweep.kind === "blocked") return done({ ring: opened.ring, plan: sweep, minted: false, fresh });

    // Seal first so every recipient's pin is stored before anything leaves this browser.
    pins = opened.pins;
    const seal = (member: MemberKey, generation: number, key: Uint8Array) => {
      const sealed = sealFor(member, container.id, generation, key, me!, pins);
      pins = sealed.pins;
      fresh.push(...sealed.fresh);
      return sealed.envelope;
    };
    let rows: Envelope[];
    if (sweep.kind === "mint") {
      const key = newContainerKey();
      rows = sweep.recipients.map((member) => seal(member, container.keyGeneration + 1, key));
    } else {
      rows = sweep.grants.map((grant) => seal(grant.member, grant.generation, opened.ring.get(grant.generation)!));
    }
    if (fresh.length > opened.fresh.length && !(await store.addFresh(pins))) return done({ ring: opened.ring, plan: { kind: "pins-unsaved" }, minted: false, fresh });
    try {
      await api.stepUp();
      if (sweep.kind === "mint") {
        const result = await api.rotate(container.id, container.keyGeneration, rows);
        container = { ...container, keyGeneration: result.keyGeneration, sharedGeneration: container.sharedGeneration || result.keyGeneration };
      } else {
        await api.putEnvelopes(container.id, rows);
      }
    } catch (error) {
      // already_exists: another steward rotated or wrapped first. Re-read once; the caller's container may be stale.
      if (code(error) !== "already_exists" || attempt > 0) throw error;
      continue;
    }
    if (sweep.kind === "wrap") return done({ ring: opened.ring, plan: sweep, minted: false, fresh });
    const after = open(pins, await api.envelopes(container.id), opened.ring);
    return done({ ring: after.ring, plan: sweep, minted: true, fresh }, after);
  }
}
