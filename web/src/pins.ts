import { digestSha256Hex } from "./crypto";
import type { MemberKey } from "./keyring";

/** Trust-on-first-use pins: colleague user ID → identity public key (standard base64). */
export type Pins = Record<string, string>;
export type PinChange = { member: MemberKey; pinned: string };

/** Splits keyed members into first-seen and changed; unchanged pins are neither. */
export function comparePins(pins: Pins, members: MemberKey[]): { fresh: MemberKey[]; changed: PinChange[] } {
  const fresh: MemberKey[] = [];
  const changed: PinChange[] = [];
  for (const member of members) {
    const key = member.identity?.publicKey;
    if (!key) continue;
    const pinned = pins[member.userId];
    if (pinned === undefined) fresh.push(member);
    else if (pinned !== key) changed.push({ member, pinned });
  }
  return { fresh, changed };
}

/** Computed locally from the key, never taken from the server: SHA-256, hex in groups of four. */
export async function fingerprint(publicKey: string): Promise<string> {
  const raw = Uint8Array.from(atob(publicKey), (char) => char.charCodeAt(0));
  return (await digestSha256Hex(raw)).match(/.{4}/g)!.join(" ");
}
