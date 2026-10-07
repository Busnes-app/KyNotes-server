import { randomBytes } from "@noble/ciphers/utils.js";
import { base64, fromBase64, type KeyRef } from "./crypto";
import type { HeldIdentity, PublicIdentity } from "./identity";
import { FingerprintChangedError, publicKeyBytes, sameKey, type PinChange, type Pins } from "./pins";
import { ENVELOPE_ALG, envelopeSender, unwrapEnvelope, wrapEnvelope } from "./teamKeys";

/** An envelope as written, and as read back from GET /containers/{id}/envelopes (every recipient's row for a session). */
export type Envelope = { deviceId: string; keyGeneration: number; alg: string; envelope: string };
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
/** Keys opened, pins to persist, and key holders to surface: fresh were pinned now, changed were refused. */
export type OpenedKeyring = { ring: Keyring; pins: Pins; fresh: MemberKey[]; changed: PinChange[] };

const isSteward = (role: string) => role === "owner" || role === "admin";

/**
 * Opens this identity's envelopes, accepting only keys a trusted sender sealed:
 * this identity itself, or a current owner or admin whose identity key matches
 * its pin. A first-contact sender is pinned once its envelope opens (TOFU); a
 * changed key is refused until the user confirms it (confirmFingerprintChange).
 */
export function openKeyring(containerID: string, envelopes: Envelope[], me: Me | undefined, members: MemberKey[], pins: Pins): OpenedKeyring {
  const ring = new Map<number, Uint8Array>();
  const out = { ring, pins: { ...pins }, fresh: [] as MemberKey[], changed: [] as PinChange[] };
  if (!me) return out;
  for (const row of envelopes) {
    if (row.deviceId !== me.deviceId || row.alg !== ENVELOPE_ALG) continue;
    try {
      const envelope = fromBase64(row.envelope);
      const sender = envelopeSender(envelope);
      const self = sender === me.deviceId;
      const member = self ? undefined : members.find((entry) => entry.identity?.deviceId === sender);
      if (!self && (!member || member.userId === me.userId || !isSteward(member.role))) continue;
      const pinned = member && out.pins[member.userId];
      if (member && pinned !== undefined && !sameKey(pinned, member.identity!.publicKey)) {
        if (!out.changed.some((change) => change.member.userId === member.userId)) out.changed.push({ member, pinned });
        continue;
      }
      const senderPublic = member ? publicKeyBytes(member.identity!.publicKey) : me.publicKey;
      ring.set(row.keyGeneration, unwrapEnvelope(envelope, me.privateKey, containerID, row.keyGeneration, me.deviceId, senderPublic));
      if (member && pinned === undefined) {
        out.pins[member.userId] = member.identity!.publicKey;
        out.fresh.push(member);
      }
    } catch { /* A row this identity cannot open is someone else's mistake, never a key. */ }
  }
  return out;
}

/**
 * The key new content in this container is sealed with. Legacy containers keep the
 * login-derived key. A shared container needs the container key at its current
 * generation; undefined means "waiting for keys" and nothing may be written.
 */
export function writeKey(container: KeyedContainer, ring: Keyring, legacy: KeyRef): WriteKey | undefined {
  if (container.sharedGeneration === 0) return { key: legacy, generation: container.keyGeneration };
  const key = ring.get(container.keyGeneration);
  return key && { key, generation: container.keyGeneration };
}

/**
 * The one key a row may be read with. Rows at or above sharedGeneration open only
 * with their own generation's CK, so neither a relabelled legacy row nor a removed
 * member's older CK can stand in for a newer generation. Older rows are legacy.
 */
export function readKeys(container: Pick<KeyedContainer, "sharedGeneration">, ring: Keyring, legacy: KeyRef, generation: number | undefined): KeyRef[] {
  if (generation === undefined || !Number.isInteger(generation)) return [];
  if (container.sharedGeneration === 0 || generation < container.sharedGeneration) return [legacy];
  const key = ring.get(generation);
  return key ? [key] : [];
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
    const waitingFor = members.filter((member) => !member.identity).map((member) => member.username);
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
 * Wraps key for member, signed by this browser's identity. Wrapping for this user
 * only ever targets this browser's own identity. A first-seen recipient is pinned
 * (persist the returned pins); a changed key throws FingerprintChangedError.
 */
export function sealFor(member: MemberKey, containerID: string, generation: number, key: Uint8Array, me: Me, pins: Pins): { envelope: Envelope; pins: Pins } {
  const identity = member.identity!;
  const recipient = publicKeyBytes(identity.publicKey);
  let next = pins;
  if (member.userId === me.userId) {
    if (identity.deviceId !== me.deviceId || !sameKey(identity.publicKey, base64(me.publicKey))) throw new Error("own identity mismatch");
  } else if (pins[member.userId] === undefined) {
    next = { ...pins, [member.userId]: identity.publicKey };
  } else if (!sameKey(pins[member.userId], identity.publicKey)) {
    throw new FingerprintChangedError(member, pins[member.userId]);
  }
  const envelope = base64(wrapEnvelope(key, recipient, containerID, generation, identity.deviceId, me));
  return { envelope: { deviceId: identity.deviceId, keyGeneration: generation, alg: ENVELOPE_ALG, envelope }, pins: next };
}

/** 32 bytes from the platform CSPRNG; noble throws rather than fall back to Math.random. */
export const newContainerKey = (): Uint8Array => randomBytes(32);
