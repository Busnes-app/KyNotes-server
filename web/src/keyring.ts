import { bytesToHex, randomBytes } from "@noble/ciphers/utils.js";
import { asContentKey, base64, fromBase64, type KeyRef } from "./crypto";
import { hkdfSha256, sha256 } from "./fallbackCrypto";
import type { HeldIdentity, PublicIdentity } from "./identity";
import { FingerprintChangedError, publicKeyBytes, sameKey, type PinChange, type Pins } from "./pins";
import { ENVELOPE_ALG, envelopeSender, unwrapEnvelope, wrapEnvelope, type Identity } from "./teamKeys";

/** An envelope as written, and as read back from GET /containers/{id}/envelopes (every recipient's row for a session). */
export type Envelope = { deviceId: string; keyGeneration: number; alg: string; envelope: string };
/** An envelope sent with an invitation; the web client seals only for the team invited to (never a teamId-claimed child). */
export type InvitationEnvelope = Envelope & { containerId: string };
/** The fields of a container that decide its keys. */
export type KeyedContainer = { id: string; keyGeneration: number; sharedGeneration: number };
/** Container keys this browser unwrapped, by generation. */
export type Keyring = ReadonlyMap<number, KeyRef>;
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
 * What this device remembers per container: the highest generation it accepted from itself or a
 * current steward, the SHA-256 (hex) of every key it accepted (a different key for a known
 * generation is refused even after a reload), and the floor. All of it only rises.
 */
export type KeyState = KeyFloor & { mark: number; digests: Record<number, string> };
/** The highest sharedGeneration and keyGeneration this device has seen for a container; absent is 0. Only rises. */
export type KeyFloor = { shared?: number; generation?: number };

/** For containers this device never tracks (a container this tab has not loaded a floor for). */
export const NO_FLOOR: KeyFloor = {};

/** floor raised by what the server reports now: the value to persist before using the container. */
export const raiseFloor = <T extends KeyFloor>(floor: T, container: KeyedContainer): T =>
  ({ ...floor, shared: Math.max(floor.shared ?? 0, container.sharedGeneration), generation: Math.max(floor.generation ?? 0, container.keyGeneration) });

/** Add-only merge of a floor into this device's in-memory one: no field ever falls. Only the two generations survive. */
export const mergeFloor = <T extends KeyFloor>(floor: KeyFloor | undefined, next: T): T =>
  ({ shared: Math.max(floor?.shared ?? 0, next.shared ?? 0), generation: Math.max(floor?.generation ?? 0, next.generation ?? 0) }) as T;

/**
 * The one choke point for a server-reported container: sharing state never goes backwards on
 * this device. rollback is true when the server reports a lower sharedGeneration or
 * keyGeneration than this device has seen; nothing may be written then (writeKey), and reads
 * use the higher sharedGeneration, so a keyed container never reads a row below its first key.
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
 * Whether this device may hand out any key for the container now: not while the server reports an
 * older sharing state than this device has seen. kind and teamId are server claims and decide nothing.
 */
export function keysAllowed(container: KeyedContainer, floor: KeyFloor): boolean {
  return !guardContainer(container, floor).rollback;
}
export type OpenKeyringInput = {
  containerID: string; envelopes: Envelope[]; me: Me | undefined; members: MemberKey[]; pins: Pins;
  /** This device's key memory for the container (getKeyState); never taken from the server. */
  known: KeyState;
  /** Keys accepted earlier in this session; they always win. */
  held?: Keyring;
};

export const isSteward = (role: string) => role === "owner" || role === "admin";

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
  const ring = new Map<number, KeyRef>();
  const known = { ...input.known, mark: Math.max(0, input.known.mark), digests: { ...input.known.digests } };
  const out = { ring, pins: { ...pins }, fresh: [] as MemberKey[], changed: [] as PinChange[], conflicts: [] as number[], known };
  const pinnedKeys = Object.values(pins).flatMap((key) => { try { return [publicKeyBytes(key)]; } catch { return []; } });
  /** First key per generation wins, across reloads through the stored digest. */
  const accept = (generation: number, key: KeyRef): boolean => {
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
    try { return asContentKey(unwrapEnvelope(envelope, me.privateKey, containerID, generation, me.deviceId, sender)); } catch { return undefined; }
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
 * The key new content in this container is sealed with: the container key at its current generation.
 * Never the login-derived key, which the server can derive (F1): a container that was never shared has
 * no write key until its first key is minted. undefined means read-only and "waiting for keys".
 */
export function writeKey(reported: KeyedContainer, ring: Keyring, floor: KeyFloor): WriteKey | undefined {
  const { container, rollback } = guardContainer(reported, floor);
  if (rollback || container.sharedGeneration === 0) return undefined;
  const key = ring.get(container.keyGeneration);
  return key && { key, generation: container.keyGeneration };
}

/**
 * Generation 0 marks a local edit made while the current key is missing. It is sealed with the
 * identity's waitingKey, stays on this device (server generations start at 1 and the queue never
 * sends it) and is re-sealed for the current key once that key arrives.
 */
export const WAITING_GENERATION = 0;

/** The key a local copy is sealed with: writeKey, or seal (waitingKey) at WAITING_GENERATION while that is missing. */
export function localKey(container: KeyedContainer, ring: Keyring, seal: KeyRef, floor: KeyFloor): WriteKey {
  return writeKey(container, ring, floor) ?? { key: seal, generation: WAITING_GENERATION };
}

/**
 * Seals this browser's edits that wait for a key (N3). Derived from the identity alone, so they survive
 * a password change, and "Forget this device" once the identity comes back (link, recovery code, password).
 */
export const waitingKey = (identity: Pick<Identity, "privateKey">): KeyRef =>
  asContentKey(hkdfSha256(identity.privateKey, 32, new Uint8Array(0), new TextEncoder().encode("kynotes/waiting/v1")));

/**
 * The one key a server row may be read with: the container key of the row's own generation, at or
 * above the first keyed generation (the higher of the server's report and this device's floor).
 * A missing, malformed, waiting or older generation gets no key; nothing else is ever tried.
 */
export function readKeys(container: Pick<KeyedContainer, "sharedGeneration">, ring: Keyring, generation: number | undefined, floor: KeyFloor): KeyRef[] {
  const shared = Math.max(container.sharedGeneration, floor.shared ?? 0);
  if (shared === 0 || generation === undefined || !Number.isInteger(generation) || generation < shared) return [];
  const key = ring.get(generation);
  return key ? [key] : [];
}

/** Keys for a copy this browser stored itself (cache, queue, upload): the waiting key for a waiting entry, otherwise readKeys. */
export const ownCopyKeys = (container: Pick<KeyedContainer, "sharedGeneration">, ring: Keyring, generation: number | undefined, floor: KeyFloor, waiting?: KeyRef): KeyRef[] =>
  generation === WAITING_GENERATION ? (waiting ? [waiting] : []) : readKeys(container, ring, generation, floor);

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
  | { kind: "unrecoverable" }
  | { kind: "mint"; recipients: MemberKey[] }
  | { kind: "wrap"; grants: Array<{ member: MemberKey; generation: number }> };

/**
 * What an owner or admin's browser must do so every member holds the container keys.
 * - Never shared: mint the first key for every member with an identity (the others are wrapped by a
 *   later sweep), but only once the caller's own identity is recoverable: a key only a browser holds
 *   would lose the notebook with the browser.
 * - Shared, current generation empty (after a removal): mint the next key.
 * - Otherwise wrap every generation this browser holds for each member missing it.
 * Only keys this browser unwrapped are ever wrapped (P2 rule 7).
 */
export function planSweep(input: { container: KeyedContainer; me: string; members: MemberKey[]; envelopes: Envelope[]; ring: Keyring; recoverable: boolean }): SweepPlan {
  const { container, me, members, envelopes, ring } = input;
  const self = members.find((member) => member.userId === me);
  if (!self?.identity || !isSteward(self.role)) return { kind: "idle" };
  const keyed = members.filter((member) => member.identity);
  if (container.sharedGeneration === 0) return input.recoverable ? { kind: "mint", recipients: keyed } : { kind: "unrecoverable" };
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
export function sealFor(member: MemberKey, containerID: string, generation: number, key: KeyRef, me: Me, pins: Pins): { envelope: Envelope; pins: Pins; fresh: MemberKey[] } {
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
export const newContainerKey = (): KeyRef => asContentKey(randomBytes(32));

export type MemberKeyStatus = "has-key" | "waiting" | "no-identity";

/**
 * What each member holds, for the member list. Shared notebooks: the current generation's key
 * (has-key), an identity waiting for a steward (waiting), or no identity to wrap for. A
 * never-shared notebook lists only members without an identity; the first key is minted without them.
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
