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

/** Computed locally from the key, never taken from the server: SHA-256, hex in groups of four. */
export async function fingerprint(publicKey: string): Promise<string> {
  return (await digestSha256Hex(publicKeyBytes(publicKey))).match(/.{4}/g)!.join(" ");
}
