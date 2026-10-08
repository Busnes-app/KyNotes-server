import { describe, expect, it } from "vitest";
import { asContentKey, base64, decryptNote, encryptNote, type KeyRef } from "./crypto";
import { guardContainer, mergeFloor, memberKeyStatus, keysAllowed, NO_FLOOR, ownCopyKeys, raiseFloor, localKey, newContainerKey, openFirst, openKeyring, planSweep, readKeys, sealFor, WAITING_GENERATION, waitingKey, writeKey, type Envelope, type KeyFloor, type Me, type MemberKey } from "./keyring";
import { generateIdentity } from "./teamKeys";
import { confirmFingerprintChange, FingerprintChangedError, PinConfirmation } from "./pins";

const cnt = `cnt_${"a".repeat(26)}`;
const dev = (c: string) => `dev_${c.repeat(26)}`;
const person = (name: string, c: string, role = "editor") => {
  const id = generateIdentity();
  const held: Me = { ...id, deviceId: dev(c), userId: `usr_${c.repeat(26)}` };
  const member: MemberKey = { userId: held.userId, username: name, role, identity: { deviceId: dev(c), publicKey: base64(id.publicKey) } };
  return { held, member };
};
/** openKeyring with this device's stored high-water mark (generations it accepted from a current steward). */
const open = (mark: number, envelopes: Envelope[], me: Me | undefined, members: MemberKey[], pins: Record<string, string>, held?: Map<number, KeyRef>, digests: Record<number, string> = {}) =>
  openKeyring({ containerID: cnt, envelopes, me, members, pins, known: { mark, digests }, held });
/** An envelope sealed with no pins in play. */
const seal = (member: MemberKey, generation: number, key: KeyRef, by: Me) => sealFor(member, cnt, generation, key, by, {}).envelope;

describe("keyring", () => {
  it("opens only this identity's envelopes, by generation, and skips rows it cannot open", () => {
    const owner = person("owner", "b", "owner");
    const editor = person("editor", "c");
    const k2 = newContainerKey();
    const k3 = newContainerKey();
    const rows: Envelope[] = [seal(owner.member, 2, k2, owner.held), seal(editor.member, 2, k2, owner.held), seal(owner.member, 3, k3, owner.held)];
    const forged = { ...seal(owner.member, 4, k3, owner.held), keyGeneration: 5 }; // AAD binds the generation
    const opened = open(3, [...rows, forged], owner.held, [owner.member, editor.member], {});
    expect([...opened.ring.keys()].sort()).toEqual([2, 3]);
    expect(opened.ring.get(3)).toEqual(k3);
    // Self-sealed envelopes need no pin and add none.
    expect(opened).toMatchObject({ pins: {}, fresh: [], changed: [] });
    expect(open(3, rows, undefined, [owner.member], {}).ring.size).toBe(0);
  });

  describe("sender authentication", () => {
    const owner = person("owner", "b", "owner");
    const admin = person("admin", "f", "admin");
    const editor = person("editor", "c");
    const k2 = newContainerKey();
    const members = [owner.member, admin.member, editor.member];
    const fromOwner = [seal(editor.member, 2, k2, owner.held)];

    it("accepts a current steward whose key matches its pin", () => {
      const pins = { [owner.member.userId]: owner.member.identity!.publicKey };
      const opened = open(2, fromOwner, editor.held, members, pins);
      expect(opened.ring.get(2)).toEqual(k2);
      expect(opened).toMatchObject({ pins, fresh: [], changed: [] });
    });

    it("pins a first-contact steward and surfaces it as a new key holder", () => {
      const opened = open(2, fromOwner, editor.held, members, {});
      expect(opened.ring.get(2)).toEqual(k2);
      expect(opened.pins).toEqual({ [owner.member.userId]: owner.member.identity!.publicKey });
      expect(opened.fresh).toEqual([owner.member]);
    });

    it("rejects and surfaces a steward whose key no longer matches its pin", () => {
      const pinned = admin.member.identity!.publicKey;
      const opened = open(2, fromOwner, editor.held, members, { [owner.member.userId]: pinned });
      expect(opened.ring.size).toBe(0);
      expect(opened.changed).toEqual([{ member: owner.member, pinned }]);
      expect(opened.pins).toEqual({ [owner.member.userId]: pinned });
    });

    it("ignores senders that are not current stewards", () => {
      const fromEditor = [seal(owner.member, 2, k2, editor.held)];
      expect(open(2, fromEditor, owner.held, members, {}).ring.size).toBe(0);
      // A removed steward is no longer in the member list.
      expect(open(2, fromOwner, editor.held, [admin.member, editor.member], {}).ring.size).toBe(0);
    });

    it("ignores an envelope forged in a steward's name and pins nothing", () => {
      const server = generateIdentity();
      const forged = [seal(editor.member, 2, k2, { ...server, deviceId: owner.held.deviceId, userId: owner.held.userId })];
      const opened = open(2, forged, editor.held, members, {});
      expect(opened).toMatchObject({ pins: {}, fresh: [], changed: [] });
      expect(opened.ring.size).toBe(0);
    });

    it("ignores a steward listed under this user's ID with another identity", () => {
      const impostor = person("editor", "g", "owner");
      const fake: MemberKey = { ...impostor.member, userId: editor.member.userId };
      const rows = [seal(editor.member, 2, k2, impostor.held)];
      expect(open(2, rows, editor.held, [owner.member, fake], {}).ring.size).toBe(0);
    });

    it("keeps history from a pinned former steward, but never at the current generation", () => {
      const pins = { [owner.member.userId]: owner.member.identity!.publicKey };
      const remaining = [admin.member, editor.member]; // owner removed; this device has since accepted generation 3
      const old = open(3, fromOwner, editor.held, remaining, pins);
      expect(old.ring.get(2)).toEqual(k2);
      expect(old).toMatchObject({ pins, fresh: [], changed: [] });
      // At or above this device's mark, the same sender needs to be a current steward.
      expect(open(2, fromOwner, editor.held, remaining, pins).ring.size).toBe(0);
      // Demoted rather than removed: same rule.
      const demoted = [{ ...owner.member, role: "editor" }, editor.member];
      expect(open(3, fromOwner, editor.held, demoted, pins).ring.get(2)).toEqual(k2);
      expect(open(2, fromOwner, editor.held, demoted, pins).ring.size).toBe(0);
    });

    it("ignores a pinned former steward at a generation this device never accepted from a current steward", () => {
      const pins = { [owner.member.userId]: owner.member.identity!.publicKey };
      // The server may claim any keyGeneration; only this device's own mark counts.
      expect(open(1, fromOwner, editor.held, [admin.member, editor.member], pins).ring.size).toBe(0);
      expect(open(0, fromOwner, editor.held, [admin.member, editor.member], pins).ring.size).toBe(0);
    });

    it("raises the mark only for keys accepted from a current steward or itself, and never lowers it", () => {
      expect(open(0, fromOwner, editor.held, members, {}).known.mark).toBe(2);
      expect(open(5, fromOwner, editor.held, members, {}).known.mark).toBe(5);
      const pins = { [owner.member.userId]: owner.member.identity!.publicKey };
      // Accepted only through the pinned exception: no new mark.
      expect(open(3, fromOwner, editor.held, [admin.member, editor.member], pins).known.mark).toBe(3);
      expect(open(0, [seal(owner.member, 4, k2, owner.held)], owner.held, members, {}).known.mark).toBe(4);
    });

    it("keeps the first key accepted for a generation and reports a different one as a conflict", () => {
      const other = newContainerKey();
      const second = seal(editor.member, 2, other, admin.held);
      const both = open(0, [...fromOwner, second], editor.held, members, {});
      expect(both.ring.get(2)).toEqual(k2);
      expect(both.conflicts).toEqual([2]);
      expect(open(0, [...fromOwner, ...fromOwner], editor.held, members, {}).conflicts).toEqual([]);
      // A key already held from an earlier open is never replaced.
      const held = new Map([[2, other]]);
      const later = open(0, fromOwner, editor.held, members, {}, held);
      expect(later.ring.get(2)).toEqual(other);
      expect(later.conflicts).toEqual([2]);
      expect(held.get(2)).toEqual(other);
    });

    it("after a reload, refuses a pinned-history key that differs from the one this device accepted", () => {
      const first = open(0, fromOwner, editor.held, members, {});
      expect(first.known).toEqual({ mark: 2, digests: { 2: expect.stringMatching(/^[0-9a-f]{64}$/) } });
      // Reload: nothing held. The server withholds the owner's envelope and serves a pinned
      // former steward's envelope for generation 2 with another key.
      const pins = { ...first.pins, [admin.member.userId]: admin.member.identity!.publicKey };
      const known = { mark: 3, digests: first.known.digests };
      const swapped = [seal(editor.member, 2, newContainerKey(), admin.held)];
      const reloaded = openKeyring({ containerID: cnt, envelopes: swapped, me: editor.held, members: [editor.member], pins, known });
      expect(reloaded.ring.size).toBe(0);
      expect(reloaded.conflicts).toEqual([2]);
      expect(reloaded.known).toEqual(known);
      // The same key from that pinned sender is fine.
      const same = [seal(editor.member, 2, k2, admin.held)];
      expect(openKeyring({ containerID: cnt, envelopes: same, me: editor.held, members: [editor.member], pins, known }).ring.get(2)).toEqual(k2);
    });

    it("drops a held key that disagrees with the stored digest, even beside a matching envelope", () => {
      const digests = open(0, fromOwner, editor.held, members, {}).known.digests;
      const other = newContainerKey();
      const opened = open(2, fromOwner, editor.held, members, {}, new Map([[2, other]]), digests);
      expect(opened.ring.get(2)).toEqual(k2);
      expect(opened.conflicts).toEqual([2]);
      expect(opened.known.digests).toEqual(digests);
      // A held key with no stored digest is recorded.
      const recorded = open(0, [], editor.held, members, {}, new Map([[5, other]]));
      expect(recorded.ring.get(5)).toEqual(other);
      expect(Object.keys(recorded.known.digests)).toEqual(["5"]);
    });

    it("never rewrites a pin from server data", () => {
      const pinned = admin.member.identity!.publicKey;
      const pins = { [owner.member.userId]: pinned };
      const opened = open(0, fromOwner, editor.held, members, pins);
      expect(opened.pins[owner.member.userId]).toBe(pinned);
      expect(pins).toEqual({ [owner.member.userId]: pinned });
    });

    it("ignores an unpinned non-steward even for an old generation", () => {
      const fromEditor = [seal(owner.member, 2, k2, editor.held)];
      expect(open(3, fromEditor, owner.held, members, {}).ring.size).toBe(0);
      expect(open(3, fromOwner, editor.held, [admin.member, editor.member], {}).ring.size).toBe(0);
    });
  });

  it("never writes with the login key: a never-shared container has no write key, a shared one only the current key", () => {
    const k3 = newContainerKey();
    const ring = new Map([[3, k3]]);
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 0 }, ring, NO_FLOOR)).toBeUndefined();
    expect(writeKey({ id: cnt, keyGeneration: 3, sharedGeneration: 2 }, ring, NO_FLOOR)).toEqual({ key: k3, generation: 3 });
    // Waiting for keys: never fall back to the legacy key in a shared container.
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 2 }, ring, NO_FLOOR)).toBeUndefined();
  });

  it("reads a keyed generation only with its own key, and nothing below the first key", async () => {
    const [k2, k3, k4] = [newContainerKey(), newContainerKey(), newContainerKey()];
    const ring = new Map([[2, k2], [4, k4], [3, k3]]);
    const shared = { sharedGeneration: 2 };
    expect(readKeys(shared, ring, 3, NO_FLOOR)).toEqual([k3]);
    for (const generation of [undefined, Number.NaN, 0, 1, 5]) expect(readKeys(shared, ring, generation, NO_FLOOR)).toEqual([]);
    for (const generation of [undefined, 0, 1, 2, 5]) expect(readKeys({ sharedGeneration: 0 }, ring, generation, NO_FLOOR)).toEqual([]);
    // A server relabelling generation-2 ciphertext as generation 3 cannot make it open.
    const old = await encryptNote(k2, cnt, { title: "L", body: "" });
    await expect(openFirst(readKeys(shared, ring, 3, NO_FLOOR), (key) => decryptNote(key, cnt, old))).rejects.toThrow();
  });

  it("seals an edit made while keys are missing for this device only, and reads it back only as its own copy", async () => {
    const shared = { id: cnt, keyGeneration: 3, sharedGeneration: 2 };
    const seal = waitingKey(generateIdentity());
    const waiting = localKey(shared, new Map(), seal, NO_FLOOR);
    expect(waiting).toEqual({ key: seal, generation: WAITING_GENERATION });
    // Never a generation the server would accept, and never the current key's slot.
    expect(WAITING_GENERATION).toBeLessThan(1);
    const sealed = await encryptNote(waiting.key, cnt, { title: "W", body: "" });
    await expect(openFirst(ownCopyKeys(shared, new Map(), WAITING_GENERATION, NO_FLOOR, seal), (key) => decryptNote(key, cnt, sealed))).resolves.toEqual({ title: "W", body: "" });
    expect(readKeys(shared, new Map(), WAITING_GENERATION, NO_FLOOR)).toEqual([]);
    const k3 = newContainerKey();
    expect(localKey(shared, new Map([[3, k3]]), seal, NO_FLOOR)).toEqual({ key: k3, generation: 3 });
  });

  it("never opens a newer row with a removed member's older key", async () => {
    const k2 = newContainerKey();
    const removed = new Map([[2, k2]]); // keys a member held before removal re-keyed to generation 3
    const forged = await encryptNote(k2, cnt, { title: "F", body: "" });
    expect(readKeys({ sharedGeneration: 2 }, removed, 3, NO_FLOOR)).toEqual([]);
    await expect(openFirst(readKeys({ sharedGeneration: 2 }, removed, 3, NO_FLOOR), (key) => decryptNote(key, cnt, forged))).rejects.toThrow();
  });
});

describe("sealFor pins", () => {
  const owner = person("owner", "b", "owner");
  const editor = person("editor", "c");
  const swapped: MemberKey = { ...editor.member, identity: { ...editor.member.identity!, publicKey: base64(generateIdentity().publicKey) } };
  const k2 = newContainerKey();

  it("pins a recipient on first wrap and keeps a matching pin", () => {
    const first = sealFor(editor.member, cnt, 2, k2, owner.held, {});
    expect(first.pins).toEqual({ [editor.member.userId]: editor.member.identity!.publicKey });
    expect(first.fresh).toEqual([editor.member]);
    const again = sealFor(editor.member, cnt, 2, k2, owner.held, first.pins);
    expect(again.pins).toEqual(first.pins);
    expect(again.fresh).toEqual([]);
  });

  it("refuses a changed key until the user confirms the new fingerprint", () => {
    const pins = { [editor.member.userId]: editor.member.identity!.publicKey };
    let error: unknown;
    try { sealFor(swapped, cnt, 2, k2, owner.held, pins); } catch (caught) { error = caught; }
    expect(error).toBeInstanceOf(FingerprintChangedError);
    expect(error).toMatchObject({ member: swapped, pinned: pins[editor.member.userId] });
    const confirmed = confirmFingerprintChange(pins, swapped);
    expect(confirmed).toBeInstanceOf(PinConfirmation);
    expect(confirmed.pins).toEqual({ [editor.member.userId]: swapped.identity!.publicKey });
    expect(sealFor(swapped, cnt, 2, k2, owner.held, confirmed.pins).envelope.deviceId).toBe(editor.member.identity!.deviceId);
  });

  it("wraps for this user only to this browser's own identity", () => {
    const self: MemberKey = { ...owner.member, identity: { deviceId: dev("h"), publicKey: base64(generateIdentity().publicKey) } };
    expect(() => sealFor(self, cnt, 2, k2, owner.held, {})).toThrow();
    expect(sealFor(owner.member, cnt, 2, k2, owner.held, {}).pins).toEqual({});
  });
});

describe("planSweep", () => {
  const owner = person("owner", "b", "owner");
  const editor = person("editor", "c");
  const container = (keyGeneration: number, sharedGeneration: number) => ({ id: cnt, keyGeneration, sharedGeneration });

  it("mints the first key for every keyed member, once the caller is recoverable", () => {
    const sso: MemberKey = { userId: `usr_${"d".repeat(26)}`, username: "sso-user", role: "editor" };
    const base = { me: owner.member.userId, envelopes: [], ring: new Map(), recoverable: true };
    // A member without an identity no longer holds the first key back: it is wrapped later by the sweep.
    expect(planSweep({ ...base, container: container(1, 0), members: [owner.member, editor.member, sso] })).toEqual({ kind: "mint", recipients: [owner.member, editor.member] });
    // A first key waits for a recoverable identity; a re-mint never does.
    expect(planSweep({ ...base, recoverable: false, container: container(1, 0), members: [owner.member, editor.member] })).toEqual({ kind: "unrecoverable" });
    expect(planSweep({ ...base, recoverable: false, container: container(3, 2), members: [owner.member, editor.member], envelopes: [] }).kind).toBe("mint");
    expect(planSweep({ ...base, container: container(1, 0), members: [owner.member, editor.member] })).toEqual({ kind: "mint", recipients: [owner.member, editor.member] });
  });

  it("never acts for a non-steward or a steward without an identity", () => {
    const base = { container: container(1, 0), envelopes: [], ring: new Map(), recoverable: true };
    expect(planSweep({ ...base, me: editor.member.userId, members: [owner.member, editor.member] }).kind).toBe("idle");
    expect(planSweep({ ...base, me: owner.member.userId, members: [{ ...owner.member, identity: undefined }, editor.member] }).kind).toBe("idle");
  });

  it("re-mints after a removal emptied the current generation, skipping members without identities", () => {
    const k2 = newContainerKey();
    const envelopes = [seal(owner.member, 2, k2, owner.held), seal(editor.member, 2, k2, owner.held)];
    const sso: MemberKey = { userId: `usr_${"d".repeat(26)}`, username: "sso-user", role: "editor" };
    expect(planSweep({ container: container(3, 2), recoverable: true, me: owner.member.userId, members: [owner.member, editor.member, sso], envelopes, ring: new Map([[2, k2]]) }))
      .toEqual({ kind: "mint", recipients: [owner.member, editor.member] });
  });

  it("wraps every held generation for a member missing it, and nothing it does not hold", () => {
    const newcomer = person("newcomer", "e");
    const [k2, k4] = [newContainerKey(), newContainerKey()];
    const envelopes = [seal(owner.member, 2, k2, owner.held), seal(editor.member, 2, k2, owner.held), seal(owner.member, 4, k4, owner.held), seal(editor.member, 4, k4, owner.held)];
    // Generation 3 was emptied by a removal and never held; generation 1 predates sharing.
    const plan = planSweep({ container: container(4, 2), recoverable: true, me: owner.member.userId, members: [owner.member, editor.member, newcomer.member], envelopes, ring: new Map([[2, k2], [4, k4]]) });
    expect(plan).toEqual({ kind: "wrap", grants: [{ member: newcomer.member, generation: 2 }, { member: newcomer.member, generation: 4 }] });
    expect(planSweep({ container: container(4, 2), recoverable: true, me: owner.member.userId, members: [owner.member, editor.member], envelopes, ring: new Map([[2, k2], [4, k4]]) }).kind).toBe("idle");
  });
});

describe("main.tsx key wiring", () => {
  const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];

  it("never hands content crypto the login secret", () => {
    expect(main).not.toMatch(/(?:en|de)crypt\w*\(\s*(?:auth\.)?authSecret\b/);
    expect(main).not.toMatch(/\blegacy\b/);
  });

  it("AdminTeams decrypts nothing: it shows names the workspace already opened", () => {
    const admin = main.slice(main.indexOf("function AdminTeams("));
    const body = admin.slice(0, admin.indexOf("\nfunction ", 1)).replace(/\/\/.*$/gm, "");
    expect(body).not.toMatch(/decrypt|openFirst|readKeys|authSecret/);
    expect(body).toContain('{knownNames[entry.id] ?? "Unnamed team"}');
    expect(body).toContain("setTeams(await listAdminTeams(sink));");
  });

  it("never seals with anything but a write key or the waiting key", () => {
    const sources = import.meta.glob<string>(["./drain.ts", "./outbound.ts", "./keyService.ts", "./keyring.ts"], { query: "?raw", import: "default", eager: true });
    for (const [file, source] of Object.entries({ "./main.tsx": main, ...sources }))
      expect(source, file).not.toMatch(/(?:encrypt|seal)\w*\(\s*(?:legacy|login|from)\b/i);
    expect(writeKey).toHaveLength(3); // (container, ring, floor): nothing to fall back to
    const localKeyFor = main.slice(main.indexOf("  const localKeyFor"), main.indexOf("\n", main.indexOf("  const localKeyFor")));
    expect(localKeyFor).toContain("waitingRef.current");
  });

  it("uses ownCopyKeysFor only for entries this browser sealed itself", () => {
    const own = [...main.matchAll(/ownCopyKeysFor\([^,]+, ([\w.!]+)\)/g)].map((match) => match[1]);
    expect(main.match(/ownCopyKeysFor\(/g)).toHaveLength(own.length);
    expect(own).toHaveLength(4); // the cache (fresh and fallback), another tab's draft, unsent edits
    expect(new Set(own)).toEqual(new Set(["cached!.keyGeneration", "cached.keyGeneration", "item.keyGeneration"]));
    // The cache holds only ciphertext this browser just sealed from its own edit, never a server read.
    const writes = main.match(/putNote\([^]*?\}\)/g)!;
    expect(writes).toHaveLength(3);
    for (const write of writes) expect(write).toMatch(/payload: (?:encrypted|await encryptNote\(write\.key)/);
  });
});

describe("sharing-state rollback", () => {
  const k3 = newContainerKey();
  const ring = new Map([[3, k3]]);
  const seen = raiseFloor({}, { id: cnt, keyGeneration: 3, sharedGeneration: 2 });

  it("remembers the highest generations reported, and never lowers them", () => {
    expect(seen).toEqual({ shared: 2, generation: 3 });
    expect(raiseFloor(seen, { id: cnt, keyGeneration: 1, sharedGeneration: 0 })).toEqual(seen);
    expect(raiseFloor(seen, { id: cnt, keyGeneration: 5, sharedGeneration: 2 })).toEqual({ shared: 2, generation: 5 });
  });

  it("refuses every write when the server reports a seen-keyed notebook as unkeyed; reads keep the floor", () => {
    const unkeyed = { id: cnt, keyGeneration: 3, sharedGeneration: 0 };
    expect(guardContainer(unkeyed, seen).rollback).toBe(true);
    expect(writeKey(unkeyed, ring, seen)).toBeUndefined();
    // The local waiting seal never leaves the device; it is never a server write key.
    const seal = waitingKey(generateIdentity());
    expect(localKey(unkeyed, ring, seal, seen).generation).toBe(WAITING_GENERATION);
    // Reads keep the floor's first keyed generation: the current one opens with its key, older ones with none.
    expect(readKeys(unkeyed, ring, 3, seen)).toEqual([k3]);
    expect(readKeys(unkeyed, new Map([[1, k3]]), 1, seen)).toEqual([]);
  });

  it("refuses a lowered key generation, so nothing is sealed under an older key", () => {
    const lowered = { id: cnt, keyGeneration: 2, sharedGeneration: 2 };
    const withOld = new Map([[2, newContainerKey()], [3, k3]]);
    expect(guardContainer(lowered, seen).rollback).toBe(true);
    expect(writeKey(lowered, withOld, seen)).toBeUndefined();
    expect(writeKey({ id: cnt, keyGeneration: 3, sharedGeneration: 2 }, withOld, seen)).toEqual({ key: k3, generation: 3 });
  });
});

describe("nothing is sealed before the first key, and kind never decides keys", () => {
  const k2 = newContainerKey();
  const seen = { shared: 2, generation: 2 };

  it("gives an unkeyed notebook no write key and no read key", () => {
    const fresh = { id: cnt, kind: "workbook", keyGeneration: 1, sharedGeneration: 0 };
    expect(writeKey(fresh, new Map([[1, k2]]), {})).toBeUndefined();
    // A local copy waits under the seal the caller passes (waitingKey), at generation 0.
    const seal = waitingKey(generateIdentity());
    expect(localKey(fresh, new Map(), seal, {})).toEqual({ key: seal, generation: WAITING_GENERATION });
    expect(readKeys(fresh, new Map([[1, k2]]), 1, {})).toEqual([]);
  });

  it("keeps the keys of a keyed notebook the server calls personal; only a lower report pauses it", () => {
    const personal = { id: cnt, kind: "workbook", keyGeneration: 2, sharedGeneration: 2 };
    expect(keysAllowed(personal, seen)).toBe(true);
    expect(writeKey(personal, new Map([[2, k2]]), seen)).toEqual({ key: k2, generation: 2 });
    expect(keysAllowed({ ...personal, sharedGeneration: 0 }, seen)).toBe(false);
    expect(writeKey({ ...personal, sharedGeneration: 0 }, new Map([[2, k2]]), seen)).toBeUndefined();
  });
});

describe("waiting edits (N3)", () => {
  it("seal with a key derived from the identity alone, not from the password", () => {
    const identity = generateIdentity();
    expect(waitingKey(identity)).toEqual(waitingKey({ privateKey: identity.privateKey.slice() }));
    expect(waitingKey(identity)).toHaveLength(32);
    expect(waitingKey(identity)).not.toEqual(waitingKey(generateIdentity()));
    expect(waitingKey(identity)).not.toEqual(identity.privateKey);
  });

  it("open with the waiting key only, for generation 0 only", () => {
    const waiting = waitingKey(generateIdentity());
    const k1 = asContentKey(new Uint8Array(32).fill(1));
    const shared = { sharedGeneration: 2 };
    expect(ownCopyKeys(shared, new Map([[0, k1]]), WAITING_GENERATION, { shared: 2 }, waiting)).toEqual([waiting]);
    expect(ownCopyKeys(shared, new Map(), 1, { shared: 2 }, waiting)).toEqual([]);
    expect(ownCopyKeys(shared, new Map(), WAITING_GENERATION, { shared: 2 })).toEqual([]);
  });
});

describe("memberKeyStatus", () => {
  const owner = person("owner", "b", "owner"), editor = person("editor", "c"), newcomer = person("newcomer", "d");
  const bare: MemberKey = { userId: `usr_${"e".repeat(26)}`, username: "sso", role: "viewer" };
  const row = (member: MemberKey, generation: number): Envelope => ({ deviceId: member.identity!.deviceId, keyGeneration: generation, alg: "x", envelope: "" });

  it("reports has key, waiting and no identity against the current generation only", () => {
    const status = memberKeyStatus({ id: cnt, keyGeneration: 3, sharedGeneration: 2 }, [owner.member, editor.member, newcomer.member, bare], [row(owner.member, 3), row(editor.member, 3), row(newcomer.member, 2)]);
    expect(status).toEqual({ [owner.member.userId]: "has-key", [editor.member.userId]: "has-key", [newcomer.member.userId]: "waiting", [bare.userId]: "no-identity" });
  });

  it("in a never-shared notebook, names only members without an identity", () => {
    expect(memberKeyStatus({ id: cnt, keyGeneration: 1, sharedGeneration: 0 }, [owner.member, bare], [])).toEqual({ [bare.userId]: "no-identity" });
  });
});

describe("key floors", () => {
  it("a floor carries only generations: a stored closure from an older build is dropped", () => {
    const merged = mergeFloor({ shared: 2, generation: 3, closed: 2 } as KeyFloor, { shared: 2, generation: 4 });
    expect(merged).toEqual({ shared: 2, generation: 4 });
  });
});

describe("key decisions read no server claim about kind", () => {
  const sources = import.meta.glob<string>(["./keyring.ts", "./keyService.ts", "./drain.ts", "./outbound.ts", "./floors.ts", "./observe.ts", "./recovery.ts", "./identity.ts"], { query: "?raw", import: "default", eager: true });
  const code = (source: string) => source.replace(/\/\*[^]*?\*\//g, "").replace(/\/\/.*$/gm, "");

  it("no key module compares kind or reads teamId", () => {
    for (const [file, source] of Object.entries(sources)) {
      // Property reads only: ReportedContainer still declares teamId as a layout field.
      expect(code(source), file).not.toMatch(/\.teamId\b|\.kind\s*[!=]==?\s*["'](?:team|workbook|project|personal)["']/);
    }
  });

  it("main.tsx gives every notebook a key pass and decides keys without kind", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    expect(main).not.toMatch(/needsKeyPass/);
    for (const start of ["  const writeKeyFor", "  const readKeysFor", "  const ownCopyKeysFor", "  const localKeyFor", "  async function syncKeys(", "  async function sendable("]) {
      const from = main.indexOf(start);
      expect(from, start).toBeGreaterThan(-1);
      const rest = main.slice(from + start.length);
      // plan.kind and similar discriminants are fine; a container's kind or teamId is not.
      expect(code(start + rest.slice(0, rest.search(/\n {2}(?:async function|function|const) /))), start).not.toMatch(/\.teamId\b|\.kind\s*[!=]==?\s*["'](?:team|workbook|project|personal)["']/);
    }
  });
});
