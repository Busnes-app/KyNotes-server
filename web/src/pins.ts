import { digestSha256Hex, fromBase64 } from "./crypto";
import type { MemberKey } from "./keyring";

/** Trust-on-first-use pins: colleague user ID → identity public key (standard base64). */
export type Pins = Record<string, string>;
export type PinChange = { member: MemberKey; pinned: string };

/** Decodes a standard-base64 X25519 public key; anything but exactly 32 bytes throws. */
export function publicKeyBytes(publicKey: string): Uint8Array {
  const raw = fromBase64(publicKey);
  if (raw.length !== 32) throw new Error("invalid identity public key");
  return raw;
}

const validKey = (key: string): boolean => { try { return publicKeyBytes(key).length === 32; } catch { return false; } };

/** True only when both decode to the same 32 bytes. */
export function sameKey(a: string, b: string): boolean {
  try {
    const [x, y] = [publicKeyBytes(a), publicKeyBytes(b)];
    return x.every((byte, i) => byte === y[i]);
  } catch {
    return false;
  }
}

/** A recipient's identity key differs from its pin; wrap only after the user confirms (confirmFingerprintChange). */
export class FingerprintChangedError extends Error {
  constructor(readonly member: MemberKey, readonly pinned: string) {
    super(`${member.username}'s identity key changed`);
    this.name = "FingerprintChangedError";
  }
}

/** Confirmations confirmFingerprintChange made; a prototype or look-alike object is never in here. */
const confirmations = new WeakSet<PinConfirmation>();
let mintConfirmation: (userId: string, key: string, pins: Pins) => PinConfirmation;

/** Proof the user confirmed a changed fingerprint; only confirmFingerprintChange makes one. */
export class PinConfirmation {
  private declare readonly brand: true; // nominal: look-alike objects do not type-check
  static {
    mintConfirmation = (userId, key, pins) => {
      const confirmation = new PinConfirmation(userId, key, pins);
      confirmations.add(confirmation);
      return confirmation;
    };
  }
  private constructor(readonly userId: string, readonly key: string, readonly pins: Pins) {}
}

export const isPinConfirmation = (value: unknown): value is PinConfirmation => typeof value === "object" && value !== null && confirmations.has(value as PinConfirmation);

/** The user compared the new fingerprint out of band and accepts it. Persist with storeConfirmedPin; retry sealFor with .pins. */
export function confirmFingerprintChange(pins: Pins, member: MemberKey): PinConfirmation {
  const key = member.identity?.publicKey;
  if (!key || !validKey(key)) throw new Error("invalid identity public key");
  return mintConfirmation(member.userId, key, { ...pins, [member.userId]: key });
}

/** Splits keyed members into first-seen and changed; unchanged pins are neither. */
export function comparePins(pins: Pins, members: MemberKey[]): { fresh: MemberKey[]; changed: PinChange[] } {
  const fresh: MemberKey[] = [];
  const changed: PinChange[] = [];
  for (const member of members) {
    const key = member.identity?.publicKey;
    if (!key) continue;
    const pinned = pins[member.userId];
    if (pinned === undefined) { if (validKey(key)) fresh.push(member); }
    else if (!sameKey(pinned, key)) changed.push({ member, pinned });
  }
  return { fresh, changed };
}

// C0, DEL, C1, zero-width, line/paragraph separators, and bidi marks, embeddings, overrides and isolates.
const unsafe = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/g;
const clean = (text: string) => {
  const chars = [...text.replace(unsafe, " ").replace(/\s+/g, " ").trim()];
  return chars.length > 64 ? `${chars.slice(0, 63).join("")}…` : chars.join("");
};
/** A server-supplied name for trust prompts and key notices: the user ID first, so a name cannot pose as it. */
export function displayName(username: string, userId: string): string {
  return `${clean(userId)} · ${clean(username) || "(no name)"}`;
}

/** Computed locally from the key, never taken from the server: SHA-256, hex in groups of four. */
export async function fingerprint(publicKey: string): Promise<string> {
  return (await digestSha256Hex(publicKeyBytes(publicKey))).match(/.{4}/g)!.join(" ");
}

export type PinRow = { userId: string; pinned: string; current?: string; state: "same" | "changed" | "unseen" };

/** Settings rows: each pin against the key the server shows now; unseen when it shows none (no shared notebook, or no identity). */
export function pinRows(pins: Pins, current: Record<string, string | undefined>): PinRow[] {
  return Object.entries(pins).sort(([a], [b]) => a.localeCompare(b)).map(([userId, pinned]) => {
    const now = current[userId];
    return { userId, pinned, current: now, state: now === undefined ? "unseen" : sameKey(pinned, now) ? "same" : "changed" };
  });
}
