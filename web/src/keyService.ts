import { base64 } from "./crypto";
import type { HeldIdentity, PublicIdentity } from "./identity";
import { guardContainer, newContainerKey, openKeyring, planSweep, raiseFloor, sealFor, type Envelope, type KeyedContainer, type KeyState, type Keyring, type Member, type MemberKey, type OpenedKeyring, type SweepPlan } from "./keyring";
import { comparePins, confirmFingerprintChange, type PinChange, type PinConfirmation, type Pins } from "./pins";
import type { PinsStored } from "./storage";

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
  /** Add-only and atomic: a member already pinned to a different key is a conflict, and nothing is written. */
  addFresh: (pins: Pins) => Promise<PinsStored>;
  /** Replaces one pin; only a confirmFingerprintChange result. */
  confirm: (confirmation: PinConfirmation) => Promise<boolean>;
  loadKeyState: (containerID: string) => Promise<KeyState>;
  saveKeyState: (containerID: string, state: KeyState) => Promise<boolean>;
};
export type Caller = { userId: string; identity?: HeldIdentity; canWrap: boolean };
/**
 * plan: "untrusted" the user declined a changed colleague key, or another pass pinned a
 * different key first; "pins-unsaved" this device could not keep a pin; "rollback" the server
 * reported an older sharing state than this device has seen. None of them shared anything. fresh: pinned by this call; changed: the
 * changed keys asked about; conflicts: generations whose envelope disagreed with an
 * accepted key (reported, never used or wrapped); known: the key memory written, and
 * keyStateSaved whether this device kept it.
 */
export type KeySync = {
  container: KeyedContainer; ring: Keyring; minted: boolean; known: KeyState; keyStateSaved: boolean;
  plan: SweepPlan | { kind: "untrusted"; members: string[] } | { kind: "pins-unsaved" } | { kind: "rollback" };
  fresh: MemberKey[]; changed: PinChange[]; conflicts: number[];
};
type Pass = Omit<KeySync, "keyStateSaved">;
type Latest = { saved?: { containerID: string; known: KeyState } };

const code = (error: unknown) => (error as { code?: string }).code;
const uniqueBy = <T>(items: T[], id: (item: T) => string) => items.filter((item, i) => items.findIndex((other) => id(other) === id(item)) === i);

/**
 * Loads this browser's keys for a team container, authenticating senders against the
 * members' identities and this device's pins. When the caller is an owner or admin whose
 * session may wrap, it then shares keys: the first mint, the re-mint after a removal, and
 * wraps for members missing a generation. A changed colleague key stops everything unless
 * the user confirms it. Another steward winning a race (409 already_exists) is retried
 * once from fresh server state. Key memory is written after every attempt, even one that throws.
 */
export async function syncContainerKeys(api: KeyAPI, containerID: string, caller: Caller, store: PinStore, confirmChanged: (changes: PinChange[]) => boolean | Promise<boolean>, held?: Keyring): Promise<KeySync> {
  const identity = caller.identity;
  const me = identity && { ...identity, userId: caller.userId };
  const own = identity && { deviceId: identity.deviceId, publicKey: base64(identity.publicKey) };
  // First-contact pins already stored by an attempt that lost a race.
  const carried: MemberKey[] = [];

  /** latest receives the key memory of the newest keyring this attempt opened. */
  const pass = async (attempt: number, latest: Latest): Promise<Pass | "retry"> => {
    let container = await api.container(containerID);
    // Sharing state never goes backwards on this device: persist what was seen before any use.
    const prior = await store.loadKeyState(container.id);
    const { rollback } = guardContainer(container, prior);
    const known = raiseFloor(prior, container);
    if (known.shared !== prior.shared || known.generation !== prior.generation) await store.saveKeyState(container.id, known).catch(() => false);
    const envelopes = await api.envelopes(container.id);
    const members: MemberKey[] = await Promise.all((await api.members(container.id)).map(async (member) => ({ ...member, identity: member.userId === caller.userId && own ? own : await api.userIdentity(member.userId) })));
    // An open is speculative while it holds first-contact pins this device has not stored: its keys,
    // digests and mark are used and saved only once those pins are persisted (trusted).
    const open = (pins: Pins, rows: Envelope[], ring?: Keyring): OpenedKeyring =>
      openKeyring({ containerID: container.id, envelopes: rows, me, members, pins, known, held: ring ?? held });
    const trusted = (opened: OpenedKeyring): OpenedKeyring => {
      latest.saved = { containerID: container.id, known: raiseFloor(opened.known, container) };
      return opened;
    };
    /**
     * After a pin write failed or was refused: re-open against the pins actually stored. If that
     * still needs a first-contact pin, nothing new is adopted: only held keys matching the stored
     * digests, and this device's prior key memory with the raised floor.
     */
    const persistedOnly = async (): Promise<OpenedKeyring> => {
      const stored = await store.load();
      const again = open(stored, envelopes);
      if (!again.fresh.length) return trusted(again);
      latest.saved = { containerID: container.id, known };
      return { ...open(stored, []), known };
    };
    /** A conflict means another pass pinned a different key first: stop; the next pass asks about it. */
    const pinFailure = (stored: PinsStored): KeySync["plan"] | undefined => {
      if (stored.ok) return undefined;
      if (!stored.conflicts.length) return { kind: "pins-unsaved" };
      return { kind: "untrusted", members: members.filter((member) => stored.conflicts.includes(member.userId)).map((member) => member.username) };
    };
    // planSweep itself is idle for a caller who is not a steward with an identity.
    const plan = (opened: OpenedKeyring): SweepPlan => {
      if (!me || !caller.canWrap) return { kind: "idle" };
      const next = planSweep({ container, me: caller.userId, members, envelopes, ring: opened.ring });
      if (next.kind !== "wrap") return next;
      const grants = next.grants.filter((grant) => !opened.conflicts.includes(grant.generation));
      return grants.length ? { kind: "wrap", grants } : { kind: "idle" };
    };
    const targets = (next: SweepPlan): MemberKey[] => (next.kind === "mint" ? next.recipients : next.kind === "wrap" ? next.grants.map((grant) => grant.member) : []).filter((member) => member.userId !== caller.userId);

    let pins = await store.load();
    let opened = open(pins, envelopes);
    // Reads only: nothing is pinned, wrapped or minted against a rolled-back server.
    if (rollback) {
      const safe = opened.fresh.length ? await persistedOnly() : trusted(opened);
      return { container, changed: [], conflicts: safe.conflicts, known: raiseFloor(safe.known, container), fresh: [], ring: safe.ring, plan: { kind: "rollback" }, minted: false };
    }
    let sweep = plan(opened);
    const changed: PinChange[] = [];
    const result = (rest: Omit<Pass, "container" | "changed" | "conflicts" | "known" | "fresh">, fresh: MemberKey[], last = opened): Pass =>
      ({ container, changed, conflicts: last.conflicts, known: raiseFloor(last.known, container), fresh: uniqueBy([...carried, ...fresh], (member) => member.userId), ...rest });
    /** A pass that stops on a pin it could not keep returns only what the stored pins vouch for. */
    const stopped = async (plan: KeySync["plan"], fresh: MemberKey[]): Promise<Pass> => {
      const safe = await persistedOnly();
      return result({ ring: safe.ring, plan, minted: false }, fresh, safe);
    };
    // Each confirmation pins the member's current key, so a re-opened ring or re-planned sweep can only add new members.
    for (;;) {
      const pending = uniqueBy([...opened.changed, ...comparePins(pins, targets(sweep)).changed], (change) => change.member.userId);
      if (!pending.length) break;
      changed.push(...pending);
      if ((await confirmChanged(pending)) !== true) return stopped({ kind: "untrusted", members: pending.map((change) => change.member.username) }, []);
      for (const change of pending) {
        const confirmation = confirmFingerprintChange(pins, change.member);
        if (!(await store.confirm(confirmation))) return stopped({ kind: "pins-unsaved" }, []);
        pins = confirmation.pins;
      }
      opened = open(pins, envelopes);
      sweep = plan(opened);
    }
    const fresh = [...opened.fresh];
    const firstContact = opened.fresh.length ? pinFailure(await store.addFresh(opened.pins)) : undefined;
    // A refused first pin: the keys its sender sealed are never returned, adopted or remembered.
    if (firstContact) return stopped(firstContact, []);
    trusted(opened);
    if (sweep.kind === "idle" || sweep.kind === "blocked") return result({ ring: opened.ring, plan: sweep, minted: false }, fresh);

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
    // A pin another pass stored meanwhile wins: the sealed rows are discarded, never uploaded.
    const sealedFor = fresh.length > opened.fresh.length ? pinFailure(await store.addFresh(pins)) : undefined;
    if (sealedFor) return stopped(sealedFor, opened.fresh);
    try {
      await api.stepUp();
      if (sweep.kind === "mint") {
        const rotated = await api.rotate(container.id, container.keyGeneration, rows);
        container = { ...container, keyGeneration: rotated.keyGeneration, sharedGeneration: container.sharedGeneration || rotated.keyGeneration };
      } else {
        await api.putEnvelopes(container.id, rows);
      }
    } catch (error) {
      // already_exists: another steward rotated or wrapped first. Re-read once; the caller's container may be stale.
      if (code(error) !== "already_exists" || attempt > 0) throw error;
      carried.push(...fresh);
      return "retry";
    }
    if (sweep.kind === "wrap") return result({ ring: opened.ring, plan: sweep, minted: false }, fresh);
    const after = trusted(open(pins, await api.envelopes(container.id), opened.ring));
    return result({ ring: after.ring, plan: sweep, minted: true }, fresh, after);
  };

  for (let attempt = 0; ; attempt += 1) {
    const latest: Latest = {};
    let outcome: Pass | "retry";
    let keyStateSaved = false;
    try {
      outcome = await pass(attempt, latest);
    } finally {
      // A failing save never hides the pass's own error; it reads as keyStateSaved false.
      if (latest.saved) keyStateSaved = await store.saveKeyState(latest.saved.containerID, latest.saved.known).catch(() => false);
    }
    if (outcome !== "retry") return { ...outcome, keyStateSaved };
  }
}
