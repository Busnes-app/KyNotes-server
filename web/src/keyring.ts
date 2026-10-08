import { bytesToHex, randomBytes } from "@noble/ciphers/utils.js";
import { base64, fromBase64, type KeyRef } from "./crypto";
import { sha256 } from "./fallbackCrypto";
import type { HeldIdentity, PublicIdentity } from "./identity";
import { displayName, FingerprintChangedError, publicKeyBytes, sameKey, type PinChange, type Pins } from "./pins";
import { ENVELOPE_ALG, envelopeSender, unwrapEnvelope, wrapEnvelope } from "./teamKeys";

/** An envelope as written, and as read back from GET /containers/{id}/envelopes (every recipient's row for a session). */
export type Envelope = { deviceId: string; keyGeneration: number; alg: string; envelope: string };
/** An envelope sent with an invitation; the web client seals only for the team invited to (never a teamId-claimed child). */
export type InvitationEnvelope = Envelope & { containerId: string };
/** The fields of a container that decide its keys. */
export type KeyedContainer = { id: string; keyGeneration: number; sharedGeneration: number };
/** Container keys this browser unwrapped, by generation. */
export type Keyring = ReadonlyMap<number, Uint8Array>;
export type WriteKey = { key: KeyRef; generation: number };
export type Member = { userId: string; username: string; role: string };
/** A member and its identity, when it has one the server shows us. */
export type MemberKey = Member & { identity?: Pick<PublicIdentity, "deviceId" | "publicKey"> };

/** This browser's identity and the user it belongs to. */
export type Me = HeldIdentity & { userId: string };
/**
 * Keys opened, pins to persist (only first-contact additions), key holders to surface
 * (fresh: pinned now; changed: refused), generations whose envelope disagreed with a key
 * already accepted, and this device's new high-water mark to persist (storeKeyMark).
 */
export type OpenedKeyring = { ring: Keyring; pins: Pins; fresh: MemberKey[]; changed: PinChange[]; conflicts: number[]; known: KeyState };
/**
 * What this device remembers per container: the highest generation it accepted from
 * itself or a current steward, and the SHA-256 (hex) of every key it accepted, so a
 * different key for a known generation is refused even after a reload. shared and
 * generation are the highest sharedGeneration and keyGeneration the server ever reported
 * (KeyFloor); all of it only rises.
 */
/** reopened: the user chose "Show pre-sharing items again" here (storage.ts reopenLegacy); nothing closes by itself until a user close clears it. */
export type KeyState = KeyFloor & { mark: number; digests: Record<number, string>; reopened?: true };
/**
 * The highest sharedGeneration and keyGeneration this device has seen for a container; absent is 0.
 * closed: the shared generation at which this device stopped opening the container's legacy rows
 * with the login key (observe.ts closeLegacy); absent or 0 is open. All three only rise, except
 * that the user may reopen closed (storage.ts reopenLegacy, with a ReopenConfirmation).
 */
export type KeyFloor = { shared?: number; generation?: number; closed?: number };

/**
 * The one closure decision (legacyKeys reads it too): undefined or 0 is open, a positive safe
 * integer is that closure, and anything else is malformed and fails closed, as 1.
 */
export const closedOf = (floor: KeyFloor | undefined): number => {
  const closed = floor?.closed;
  if (closed === undefined || closed === 0) return 0;
  return Number.isSafeInteger(closed) && closed > 0 ? closed : 1;
};

/** Unused confirmations; consuming one removes it, so a kept object never reopens twice. */
const reopenConfirmations = new WeakSet<ReopenConfirmation>();
let mintReopen: (userID: string, containerID: string) => ReopenConfirmation;
/** Proof one user confirmed "Show pre-sharing items again" for one container; only confirmReopenLegacy makes one. */
export class ReopenConfirmation {
  private declare readonly brand: true; // nominal: look-alike objects do not type-check
  static {
    mintReopen = (userID, containerID) => {
      // Frozen: a holder cannot re-target it at another user or container.
      const confirmation = new ReopenConfirmation(userID, containerID);
      Object.freeze(confirmation);
      reopenConfirmations.add(confirmation);
      return confirmation;
    };
  }
  private constructor(readonly userID: string, readonly containerID: string) {}
}
/** Call only from the user's own confirm of "Show pre-sharing items again" (LegacyReview; keyring.test.ts checks the callers). */
export const confirmReopenLegacy = (userID: string, containerID: string): ReopenConfirmation => mintReopen(userID, containerID);
export const isReopenConfirmation = (value: unknown, userID: string, containerID: string): value is ReopenConfirmation =>
  typeof value === "object" && value !== null && reopenConfirmations.has(value as ReopenConfirmation) &&
  (value as ReopenConfirmation).userID === userID && (value as ReopenConfirmation).containerID === containerID;
/** Single use: true once for an unused confirmation of this user and container, false ever after. */
export const consumeReopenConfirmation = (value: unknown, userID: string, containerID: string): boolean =>
  isReopenConfirmation(value, userID, containerID) && reopenConfirmations.delete(value);
/** For containers this device never tracks (personal notebooks until P5). */
export const NO_FLOOR: KeyFloor = {};

/** floor raised by what the server reports now: the value to persist before using the container. */
export const raiseFloor = <T extends KeyFloor>(floor: T, container: KeyedContainer): T =>
  ({ ...floor, shared: Math.max(floor.shared ?? 0, container.sharedGeneration), generation: Math.max(floor.generation ?? 0, container.keyGeneration) });

/** Add-only merge of a floor into this device's in-memory one: no field ever falls, and a malformed closure keeps the old one. */
export const mergeFloor = <T extends KeyFloor>(floor: KeyFloor | undefined, next: T): T => {
  const { closed: _, ...rest } = next;
  const closed = Math.max(closedOf(floor), closedOf(next));
  return { ...rest, shared: Math.max(floor?.shared ?? 0, next.shared ?? 0), generation: Math.max(floor?.generation ?? 0, next.generation ?? 0), ...(closed ? { closed } : {}) } as T;
};

/**
 * The one choke point for a server-reported container: sharing state never goes backwards on
 * this device. rollback is true when the server reports a lower sharedGeneration or
 * keyGeneration than this device has seen; nothing may be written then (writeKey), and reads
 * use the higher sharedGeneration, so a shared container never falls back to the login key.
 */
export function guardContainer<C extends KeyedContainer>(container: C, floor: KeyFloor): { container: C; rollback: boolean } {
  const shared = floor.shared ?? 0, generation = floor.generation ?? 0;
  return {
    container: { ...container, sharedGeneration: Math.max(container.sharedGeneration, shared), keyGeneration: Math.max(container.keyGeneration, generation) },
    rollback: container.sharedGeneration < shared || container.keyGeneration < generation,
  };
}
/** A container as the server lists it; kind and teamId are server claims, for layout only. */
export type ReportedContainer = KeyedContainer & { kind: string; teamId?: string };

/**
 * Whether this device may hand out any key for the container now. False on a rollback, and when
 * a container this device has seen shared is reported as personal: kind and teamId come from the
 * server, so they never lower the floor. writeKey still applies the floor itself.
 */
export function keysAllowed(container: ReportedContainer, floor: KeyFloor): boolean {
  const relabelled = (floor.shared ?? 0) > 0 && container.kind !== "team" && !container.teamId;
  return !relabelled && !guardContainer(container, floor).rollback;
}
const sharedFloor = (container: Pick<KeyedContainer, "sharedGeneration">, floor: KeyFloor) => Math.max(container.sharedGeneration, floor.shared ?? 0);
export type OpenKeyringInput = {
  containerID: string; envelopes: Envelope[]; me: Me | undefined; members: MemberKey[]; pins: Pins;
  /** This device's key memory for the container (getKeyState); never taken from the server. */
  known: KeyState;
  /** Keys accepted earlier in this session; they always win. */
  held?: Keyring;
};

const isSteward = (role: string) => role === "owner" || role === "admin";

/**
 * Opens this identity's envelopes, accepting only keys a trusted sender sealed:
 * this identity itself, a current owner or admin whose identity key matches its
 * pin, or, below this device's own high-water mark, any identity already pinned
 * here (so a removed or demoted steward's history stays readable). The mark is
 * never taken from the server. A first-contact steward is pinned once its envelope
 * opens (TOFU); a changed steward key is surfaced and refused. The first key
 * accepted for a generation wins; a different one is reported, never used.
 */
export function openKeyring(input: OpenKeyringInput): OpenedKeyring {
  const { containerID, envelopes, me, members, pins } = input;
  const ring = new Map<number, Uint8Array>();
  const known = { ...input.known, mark: Math.max(0, input.known.mark), digests: { ...input.known.digests } };
  const out = { ring, pins: { ...pins }, fresh: [] as MemberKey[], changed: [] as PinChange[], conflicts: [] as number[], known };
  const pinnedKeys = Object.values(pins).flatMap((key) => { try { return [publicKeyBytes(key)]; } catch { return []; } });
  /** First key per generation wins, across reloads through the stored digest. */
  const accept = (generation: number, key: Uint8Array): boolean => {
    const digest = bytesToHex(sha256(key));
    const prior = ring.get(generation);
    const matches = prior ? bytesToHex(sha256(prior)) === digest : (known.digests[generation] ?? digest) === digest;
    if (!matches) {
      if (!out.conflicts.includes(generation)) out.conflicts.push(generation);
      return false;
    }
    ring.set(generation, prior ?? key);
    known.digests[generation] ??= digest;
    return true;
  };
  // Held keys pass the same digest check as envelopes; a mismatch is dropped and reported.
  for (const [generation, key] of input.held ?? []) accept(generation, key);
  if (!me) return out;
  const open = (envelope: Uint8Array, generation: number, sender: Uint8Array) => {
    try { return unwrapEnvelope(envelope, me.privateKey, containerID, generation, me.deviceId, sender); } catch { return undefined; }
  };
  // Pass 1: self and current stewards; these alone raise the mark.
  const deferred: Array<{ envelope: Uint8Array; generation: number }> = [];
  for (const row of envelopes) {
    if (row.deviceId !== me.deviceId || row.alg !== ENVELOPE_ALG) continue;
    try {
      const envelope = fromBase64(row.envelope);
      const sender = envelopeSender(envelope);
      const self = sender === me.deviceId;
      const member = self ? undefined : members.find((entry) => entry.identity?.deviceId === sender);
      if (member?.userId === me.userId) continue;
      const steward = member && isSteward(member.role) ? member : undefined;
      const pinned = steward && out.pins[steward.userId];
      const trusted = self || (steward && (pinned === undefined || sameKey(pinned, steward.identity!.publicKey)));
      if (steward && !trusted && !out.changed.some((change) => change.member.userId === steward.userId)) out.changed.push({ member: steward, pinned: pinned! });
      const key = trusted ? open(envelope, row.keyGeneration, self ? me.publicKey : publicKeyBytes(steward!.identity!.publicKey)) : undefined;
      if (!key) { deferred.push({ envelope, generation: row.keyGeneration }); continue; }
      if (!accept(row.keyGeneration, key)) continue;
      known.mark = Math.max(known.mark, row.keyGeneration);
      if (steward && pinned === undefined) {
        out.pins[steward.userId] = steward.identity!.publicKey;
        out.fresh.push(steward);
      }
    } catch { /* A row this identity cannot open is someone else's mistake, never a key. */ }
  }
  // Pass 2: history from identities pinned before this call, strictly below the device's mark.
  for (const { envelope, generation } of deferred) {
    if (generation >= known.mark) continue;
    for (const sender of pinnedKeys) {
      const key = open(envelope, generation, sender);
      if (key) { accept(generation, key); break; }
    }
  }
  return out;
}

/**
 * The key new content in this container is sealed with. Legacy containers keep the
 * login-derived key. A shared container needs the container key at its current
 * generation; undefined means "waiting for keys" and nothing may be written.
 */
export function writeKey(reported: KeyedContainer, ring: Keyring, legacy: KeyRef, floor: KeyFloor): WriteKey | undefined {
  const { container, rollback } = guardContainer(reported, floor);
  if (rollback) return undefined;
  if (container.sharedGeneration === 0) return { key: legacy, generation: container.keyGeneration };
  const key = ring.get(container.keyGeneration);
  return key && { key, generation: container.keyGeneration };
}

/**
 * Generation 0 marks a local edit made while the current key is missing. It is sealed with
 * the login-derived key, stays on this device (the server's generations start at 1, and the
 * queue never sends it) and is re-sealed for the current key once that key arrives.
 */
export const WAITING_GENERATION = 0;

/** The key a local copy is sealed with: writeKey, or the waiting seal while that is missing. */
export function localKey(container: KeyedContainer, ring: Keyring, legacy: KeyRef, floor: KeyFloor): WriteKey {
  return writeKey(container, ring, legacy, floor) ?? { key: legacy, generation: WAITING_GENERATION };
}

/**
 * The login-derived key for a legacy row, or none once this device closed legacy reads for the
 * container: the server can derive that key, so after the closure no server row opens with it.
 */
export const legacyKeys = (floor: KeyFloor, legacy: KeyRef): KeyRef[] => (closedOf(floor) === 0 ? [legacy] : []);

/**
 * The one key a server row may be read with. Rows at or above sharedGeneration open only with
 * their own generation's CK, so neither a relabelled legacy row nor a removed member's older CK
 * can stand in for a newer generation. Older rows, and never-shared containers, use the login key
 * until this device closes legacy reads (legacyKeys). Callers label such rows (legacyRow) and
 * re-seal them only on an explicit edit, move or review (migration.ts).
 */
export function readKeys(container: Pick<KeyedContainer, "sharedGeneration">, ring: Keyring, legacy: KeyRef, generation: number | undefined, floor: KeyFloor): KeyRef[] {
  // A never-shared container has only the legacy key, so a row without a generation (old cache) still reads.
  if (sharedFloor(container, floor) === 0) return legacyKeys(floor, legacy);
  // The same decision labels the row, so a row read with the legacy key is always labelled.
  if (legacyRow(container, generation, floor)) return legacyKeys(floor, legacy);
  if (generation === undefined || !Number.isInteger(generation)) return [];
  const key = ring.get(generation);
  return key ? [key] : [];
}

/**
 * readKeys for an entry this browser wrote to IndexedDB itself (queued saves, pending uploads,
 * cached copies). The server cannot write those, so the closure, which guards server rows, does
 * not apply: an edit queued before the closure, or waiting at generation 0, still re-seals.
 */
export const localReadKeys = (container: Pick<KeyedContainer, "sharedGeneration">, ring: Keyring, legacy: KeyRef, generation: number | undefined, floor: KeyFloor): KeyRef[] =>
  readKeys(container, ring, legacy, generation, { ...floor, closed: 0 });

/**
 * True exactly when readKeys opens a shared container's row with the login-derived key: the
 * reader's own pre-sharing content or waiting edit, or a server forgery. Callers label it as
 * not end-to-end verified and re-seal it only on an explicit edit, move or review.
 */
export function legacyRow(container: Pick<KeyedContainer, "sharedGeneration">, generation: number | undefined, floor: KeyFloor): boolean {
  const shared = sharedFloor(container, floor);
  return shared > 0 && Number.isInteger(generation) && generation! < shared;
}

/** A block move would re-seal a labelled row the user did not pick: any member but the head. */
export const movesLabelledSubpage = (block: ReadonlyArray<{ id: string }>, head: string, labelled: ReadonlySet<string>) =>
  block.some((page) => page.id !== head && labelled.has(page.id));

/** Conflict versions that may become copies: never a legacy-key one, which copying would re-seal unseen. */
export function copyableConflicts<T extends { keyGeneration?: number }>(container: Pick<KeyedContainer, "sharedGeneration">, conflicts: T[], floor: KeyFloor): { copy: T[]; kept: number } {
  const copy = conflicts.filter((conflict) => !legacyRow(container, conflict.keyGeneration, floor));
  return { copy, kept: conflicts.length - copy.length };
}

/** Runs open with each key in turn; AES-GCM authentication makes a wrong key fail, not misread. */
export async function openFirst<T>(keys: KeyRef[], open: (key: KeyRef) => Promise<T>): Promise<T> {
  let last: unknown = new Error("no content key");
  for (const key of keys) {
    try { return await open(key); } catch (error) { last = error; }
  }
  throw last;
}

export type SweepPlan =
  | { kind: "idle" }
  | { kind: "blocked"; waitingFor: string[] }
  | { kind: "mint"; recipients: MemberKey[] }
  | { kind: "wrap"; grants: Array<{ member: MemberKey; generation: number }> };


/**
 * What an owner or admin's browser must do so every member holds the container keys.
 * - Never shared: mint the first key, but only once every member has an identity, so
 *   no member (SSO-only users, accounts awaiting a password change) is locked out.
 * - Shared, current generation empty (after a removal): mint the next key.
 * - Otherwise wrap every generation this browser holds for each member missing it,
 *   so newcomers read history and members whose identity was reset get back in.
 * Only keys this browser unwrapped are ever wrapped (P2 rule 7).
 */
export function planSweep(input: { container: KeyedContainer; me: string; members: MemberKey[]; envelopes: Envelope[]; ring: Keyring }): SweepPlan {
  const { container, me, members, envelopes, ring } = input;
  const self = members.find((member) => member.userId === me);
  if (!self?.identity || !isSteward(self.role)) return { kind: "idle" };
  const keyed = members.filter((member) => member.identity);
  if (container.sharedGeneration === 0) {
    const waitingFor = members.filter((member) => !member.identity).map((member) => displayName(member.username, member.userId));
    return waitingFor.length ? { kind: "blocked", waitingFor } : { kind: "mint", recipients: keyed };
  }
  if (!envelopes.some((row) => row.keyGeneration === container.keyGeneration)) return { kind: "mint", recipients: keyed };
  const held = new Set(envelopes.map((row) => `${row.deviceId}:${row.keyGeneration}`));
  const grants = keyed.flatMap((member) => [...ring.keys()]
    .filter((generation) => generation >= container.sharedGeneration && generation <= container.keyGeneration)
    .filter((generation) => !held.has(`${member.identity!.deviceId}:${generation}`))
    .map((generation) => ({ member, generation })));
  return grants.length ? { kind: "wrap", grants } : { kind: "idle" };
}

/**
 * Wraps key for member, sealed by this browser's identity. Wrapping for this user
 * only ever targets this browser's own identity. A first-seen recipient is pinned
 * and returned in fresh (persist pins, surface fresh); a changed key throws
 * FingerprintChangedError.
 */
export function sealFor(member: MemberKey, containerID: string, generation: number, key: Uint8Array, me: Me, pins: Pins): { envelope: Envelope; pins: Pins; fresh: MemberKey[] } {
  const identity = member.identity!;
  const recipient = publicKeyBytes(identity.publicKey);
  let next = pins;
  let fresh: MemberKey[] = [];
  if (member.userId === me.userId) {
    if (identity.deviceId !== me.deviceId || !sameKey(identity.publicKey, base64(me.publicKey))) throw new Error("own identity mismatch");
  } else if (pins[member.userId] === undefined) {
    next = { ...pins, [member.userId]: identity.publicKey };
    fresh = [member];
  } else if (!sameKey(pins[member.userId], identity.publicKey)) {
    throw new FingerprintChangedError(member, pins[member.userId]);
  }
  const envelope = base64(wrapEnvelope(key, recipient, containerID, generation, identity.deviceId, me));
  return { envelope: { deviceId: identity.deviceId, keyGeneration: generation, alg: ENVELOPE_ALG, envelope }, pins: next, fresh };
}

/** 32 bytes from the platform CSPRNG; noble throws rather than fall back to Math.random. */
export const newContainerKey = (): Uint8Array => randomBytes(32);

export type MemberKeyStatus = "has-key" | "waiting" | "no-identity";

/**
 * What each member holds, for the member list. Shared notebooks: the current generation's key
 * (has-key), an identity waiting for a steward (waiting), or no identity to wrap for. A
 * never-shared notebook lists only members without an identity, who block its first key.
 * Built from server data: it informs and never decides trust.
 */
export function memberKeyStatus(container: KeyedContainer, members: MemberKey[], envelopes: Envelope[]): Record<string, MemberKeyStatus> {
  const held = new Set(envelopes.filter((row) => row.keyGeneration === container.keyGeneration).map((row) => row.deviceId));
  return Object.fromEntries(members.flatMap((member): Array<[string, MemberKeyStatus]> => {
    if (!member.identity) return [[member.userId, "no-identity"]];
    if (container.sharedGeneration === 0) return [];
    return [[member.userId, held.has(member.identity.deviceId) ? "has-key" : "waiting"]];
  }));
}
