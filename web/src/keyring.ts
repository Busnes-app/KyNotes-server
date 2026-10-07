import { randomBytes } from "@noble/ciphers/utils.js";
import { base64, fromBase64, type KeyRef } from "./crypto";
import type { HeldIdentity, PublicIdentity } from "./identity";
import { ENVELOPE_ALG, unwrapEnvelope, wrapEnvelope } from "./teamKeys";

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

export function openKeyring(containerID: string, envelopes: Envelope[], identity: HeldIdentity | undefined): Keyring {
  const ring = new Map<number, Uint8Array>();
  if (!identity) return ring;
  for (const row of envelopes) {
    if (row.deviceId !== identity.deviceId || row.alg !== ENVELOPE_ALG) continue;
    try {
      ring.set(row.keyGeneration, unwrapEnvelope(fromBase64(row.envelope), identity.privateKey, containerID, row.keyGeneration, identity.deviceId));
    } catch { /* A row this identity cannot open is someone else's mistake, never a key. */ }
  }
  return ring;
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

/** Keys to try on read: the row's own generation first, then newest first, then legacy. */
export function readKeys(ring: Keyring, legacy: KeyRef, hint?: number): KeyRef[] {
  const first = hint === undefined ? undefined : ring.get(hint);
  const rest = [...ring.entries()].filter(([generation]) => generation !== hint).sort(([a], [b]) => b - a).map(([, key]) => key);
  return [...(first ? [first] : []), ...rest, legacy];
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

const isSteward = (role: string) => role === "owner" || role === "admin";

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

export function sealFor(member: MemberKey, containerID: string, generation: number, key: Uint8Array): Envelope {
  const identity = member.identity!;
  return { deviceId: identity.deviceId, keyGeneration: generation, alg: ENVELOPE_ALG, envelope: base64(wrapEnvelope(key, fromBase64(identity.publicKey), containerID, generation, identity.deviceId)) };
}

/** 32 bytes from the platform CSPRNG; noble throws rather than fall back to Math.random. */
export const newContainerKey = (): Uint8Array => randomBytes(32);
