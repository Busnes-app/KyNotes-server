import { describe, expect, it } from "vitest";
import { base64, decryptNote, encryptNote, legacyKeyRef } from "./crypto";
import { closedOf, confirmReopenLegacy, consumeReopenConfirmation, legacyKeys, copyableConflicts, guardContainer, isReopenConfirmation, localReadKeys, mergeFloor, ReopenConfirmation, memberKeyStatus, keysAllowed, legacyRow, NO_FLOOR, raiseFloor, localKey, movesLabelledSubpage, newContainerKey, openFirst, openKeyring, planSweep, readKeys, sealFor, WAITING_GENERATION, writeKey, type Envelope, type KeyFloor, type Me, type MemberKey } from "./keyring";
import { generateIdentity } from "./teamKeys";
import { confirmFingerprintChange, displayName, FingerprintChangedError, PinConfirmation } from "./pins";

const cnt = `cnt_${"a".repeat(26)}`;
const dev = (c: string) => `dev_${c.repeat(26)}`;
const person = (name: string, c: string, role = "editor") => {
  const id = generateIdentity();
  const held: Me = { ...id, deviceId: dev(c), userId: `usr_${c.repeat(26)}` };
  const member: MemberKey = { userId: held.userId, username: name, role, identity: { deviceId: dev(c), publicKey: base64(id.publicKey) } };
  return { held, member };
};
const legacy = legacyKeyRef("5a".repeat(32));
/** openKeyring with this device's stored high-water mark (generations it accepted from a current steward). */
const open = (mark: number, envelopes: Envelope[], me: Me | undefined, members: MemberKey[], pins: Record<string, string>, held?: Map<number, Uint8Array>, digests: Record<number, string> = {}) =>
  openKeyring({ containerID: cnt, envelopes, me, members, pins, known: { mark, digests }, held });
/** An envelope sealed with no pins in play. */
const seal = (member: MemberKey, generation: number, key: Uint8Array, by: Me) => sealFor(member, cnt, generation, key, by, {}).envelope;

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

  it("writes legacy containers with the login key and shared ones only with the current key", () => {
    const k3 = newContainerKey();
    const ring = new Map([[3, k3]]);
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 0 }, ring, legacy, NO_FLOOR)).toEqual({ key: legacy, generation: 4 });
    expect(writeKey({ id: cnt, keyGeneration: 3, sharedGeneration: 2 }, ring, legacy, NO_FLOOR)).toEqual({ key: k3, generation: 3 });
    // Waiting for keys: never fall back to the legacy key in a shared container.
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 2 }, ring, legacy, NO_FLOOR)).toBeUndefined();
  });

  it("reads a shared generation only with its own key, and legacy rows only with the legacy key", async () => {
    const [k2, k3, k4] = [newContainerKey(), newContainerKey(), newContainerKey()];
    const ring = new Map([[2, k2], [4, k4], [3, k3]]);
    const shared = { sharedGeneration: 2 };
    expect(readKeys(shared, ring, legacy, 3, NO_FLOOR)).toEqual([k3]);
    expect(readKeys(shared, ring, legacy, 1, NO_FLOOR)).toEqual([legacy]);
    expect(readKeys({ sharedGeneration: 0 }, ring, legacy, 5, NO_FLOOR)).toEqual([legacy]);
    expect(readKeys(shared, ring, legacy, undefined, NO_FLOOR)).toEqual([]);
    expect(readKeys(shared, ring, legacy, 5, NO_FLOOR)).toEqual([]);
    const note = { title: "L", body: "" };
    // Legacy rows below sharedGeneration still decrypt.
    const old = await encryptNote(legacy, cnt, note);
    await expect(openFirst(readKeys(shared, ring, legacy, 1, NO_FLOOR), (key) => decryptNote(key, cnt, old))).resolves.toEqual(note);
    // A server relabelling legacy-key ciphertext as shared cannot downgrade the read.
    await expect(openFirst(readKeys(shared, ring, legacy, 3, NO_FLOOR), (key) => decryptNote(key, cnt, old))).rejects.toThrow();
  });

  it("reads a personal container with the legacy key even without a row generation", () => {
    // Old cache entries carry no keyGeneration; a never-shared container has only the legacy key.
    expect(readKeys({ sharedGeneration: 0 }, new Map(), legacy, undefined, NO_FLOOR)).toEqual([legacy]);
    expect(readKeys({ sharedGeneration: 0 }, new Map(), legacy, Number.NaN, NO_FLOOR)).toEqual([legacy]);
  });

  it("seals an edit made while keys are missing for this device only, and reads it back", async () => {
    const shared = { id: cnt, keyGeneration: 3, sharedGeneration: 2 };
    const waiting = localKey(shared, new Map(), legacy, NO_FLOOR);
    expect(waiting).toEqual({ key: legacy, generation: WAITING_GENERATION });
    // Never a generation the server would accept, and never the current key's slot.
    expect(WAITING_GENERATION).toBeLessThan(1);
    const sealed = await encryptNote(waiting.key, cnt, { title: "W", body: "" });
    await expect(openFirst(readKeys(shared, new Map(), legacy, WAITING_GENERATION, NO_FLOOR), (key) => decryptNote(key, cnt, sealed))).resolves.toEqual({ title: "W", body: "" });
    const k3 = newContainerKey();
    expect(localKey(shared, new Map([[3, k3]]), legacy, NO_FLOOR)).toEqual({ key: k3, generation: 3 });
  });

  it("never opens a newer row with a removed member's older key", async () => {
    const k2 = newContainerKey();
    const removed = new Map([[2, k2]]); // keys a member held before removal re-keyed to generation 3
    const forged = await encryptNote(k2, cnt, { title: "F", body: "" });
    expect(readKeys({ sharedGeneration: 2 }, removed, legacy, 3, NO_FLOOR)).toEqual([]);
    await expect(openFirst(readKeys({ sharedGeneration: 2 }, removed, legacy, 3, NO_FLOOR), (key) => decryptNote(key, cnt, forged))).rejects.toThrow();
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

  it("mints the first key only when every member has an identity", () => {
    const sso: MemberKey = { userId: `usr_${"d".repeat(26)}`, username: "sso-user", role: "editor" };
    const base = { me: owner.member.userId, envelopes: [], ring: new Map() };
    expect(planSweep({ ...base, container: container(1, 0), members: [owner.member, editor.member, sso] })).toEqual({ kind: "blocked", waitingFor: [displayName("sso-user", sso.userId)] });
    expect(planSweep({ ...base, container: container(1, 0), members: [owner.member, editor.member] })).toEqual({ kind: "mint", recipients: [owner.member, editor.member] });
  });

  it("never acts for a non-steward or a steward without an identity", () => {
    const base = { container: container(1, 0), envelopes: [], ring: new Map() };
    expect(planSweep({ ...base, me: editor.member.userId, members: [owner.member, editor.member] }).kind).toBe("idle");
    expect(planSweep({ ...base, me: owner.member.userId, members: [{ ...owner.member, identity: undefined }, editor.member] }).kind).toBe("idle");
  });

  it("re-mints after a removal emptied the current generation, skipping members without identities", () => {
    const k2 = newContainerKey();
    const envelopes = [seal(owner.member, 2, k2, owner.held), seal(editor.member, 2, k2, owner.held)];
    const sso: MemberKey = { userId: `usr_${"d".repeat(26)}`, username: "sso-user", role: "editor" };
    expect(planSweep({ container: container(3, 2), me: owner.member.userId, members: [owner.member, editor.member, sso], envelopes, ring: new Map([[2, k2]]) }))
      .toEqual({ kind: "mint", recipients: [owner.member, editor.member] });
  });

  it("wraps every held generation for a member missing it, and nothing it does not hold", () => {
    const newcomer = person("newcomer", "e");
    const [k2, k4] = [newContainerKey(), newContainerKey()];
    const envelopes = [seal(owner.member, 2, k2, owner.held), seal(editor.member, 2, k2, owner.held), seal(owner.member, 4, k4, owner.held), seal(editor.member, 4, k4, owner.held)];
    // Generation 3 was emptied by a removal and never held; generation 1 predates sharing.
    const plan = planSweep({ container: container(4, 2), me: owner.member.userId, members: [owner.member, editor.member, newcomer.member], envelopes, ring: new Map([[2, k2], [4, k4]]) });
    expect(plan).toEqual({ kind: "wrap", grants: [{ member: newcomer.member, generation: 2 }, { member: newcomer.member, generation: 4 }] });
    expect(planSweep({ container: container(4, 2), me: owner.member.userId, members: [owner.member, editor.member], envelopes, ring: new Map([[2, k2], [4, k4]]) }).kind).toBe("idle");
  });
});

describe("main.tsx key wiring", () => {
  it("derives the legacy key in exactly two places and never hands content crypto the login secret", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    // Workspace (legacy reads, personal notebooks) and AdminTeams (admin-created names).
    expect(main.match(/legacyKeyRef\(/g)).toHaveLength(2);
    expect(main).not.toMatch(/(?:en|de)crypt\w*\(\s*(?:auth\.)?authSecret\b/);
  });

  it("opens server rows with the login key only through readKeys", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    // The two bare uses check this browser's own cache (ownsCached) and queue (the drain stamp).
    expect(main.match(/decrypt\w*\(legacy\b/g)).toEqual(["decryptObject(legacy", "decryptObject(legacy"]);
    // No hand-built key list puts the login key beside container keys.
    expect(main).not.toMatch(/\[legacy,/);
  });

  it("uses the local exception only for entries this browser sealed itself", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    // localReadKeysFor opens only cache and queue entries, never a server row's generation.
    const local = [...main.matchAll(/localReadKeysFor\(\w+, ([\w.!]+)\)/g)].map((match) => match[1]);
    expect(main.match(/localReadKeysFor\(/g)).toHaveLength(local.length);
    expect(local).toHaveLength(4); // the cache (fresh and fallback), another tab's draft, unsent edits
    expect(new Set(local)).toEqual(new Set(["cached!.keyGeneration", "cached.keyGeneration", "item.keyGeneration"]));
    // The cache holds only ciphertext this browser just sealed from its own edit, never a server read.
    const writes = main.match(/putNote\([^]*?\}\)/g)!;
    expect(writes).toHaveLength(3);
    for (const write of writes) expect(write).toMatch(/payload: (?:encrypted|await encryptNote\(write\.key)/);
  });
});

describe("legacyRow", () => {
  const ck = newContainerKey();
  const legacy = legacyKeyRef("a".repeat(64));

  it("labels exactly the rows readKeys opens with the legacy key", () => {
    for (const shared of [{ sharedGeneration: 0 }, { sharedGeneration: 3 }]) {
      for (const generation of [undefined, Number.NaN, 1.5, -1, 0, 1, 2, 3, 4]) {
        const legacyRead = readKeys(shared, new Map([[3, ck]]), legacy, generation, NO_FLOOR)[0] === legacy;
        expect(legacyRow(shared, generation, NO_FLOOR)).toBe(shared.sharedGeneration > 0 && legacyRead);
      }
    }
  });

  it("labels generation 0 in a shared container, never in a personal one", () => {
    expect(legacyRow({ sharedGeneration: 3 }, WAITING_GENERATION, NO_FLOOR)).toBe(true);
    expect(legacyRow({ sharedGeneration: 3 }, 2, NO_FLOOR)).toBe(true);
    expect(legacyRow({ sharedGeneration: 3 }, 3, NO_FLOOR)).toBe(false);
    expect(legacyRow({ sharedGeneration: 3 }, undefined, NO_FLOOR)).toBe(false); // no key at all
    expect(legacyRow({ sharedGeneration: 0 }, 0, NO_FLOOR)).toBe(false);
    expect(readKeys({ sharedGeneration: 0 }, new Map(), legacy, 0, NO_FLOOR)).toEqual([legacy]); // personal reads unchanged
  });

  it("never copies a labelled conflict version, generation 0 included", () => {
    const conflicts = [{ id: "a", keyGeneration: 0 }, { id: "b", keyGeneration: 2 }, { id: "c", keyGeneration: 3 }, { id: "d", keyGeneration: undefined }];
    expect(copyableConflicts({ sharedGeneration: 3 }, conflicts, NO_FLOOR)).toEqual({ copy: [conflicts[2], conflicts[3]], kept: 2 });
    expect(copyableConflicts({ sharedGeneration: 0 }, conflicts, NO_FLOOR)).toEqual({ copy: conflicts, kept: 0 });
  });

  it("refuses a block move that would re-seal a labelled subpage, not one of the head", () => {
    const block = [{ id: "head" }, { id: "sub" }];
    expect(movesLabelledSubpage(block, "head", new Set(["sub"]))).toBe(true);
    expect(movesLabelledSubpage(block, "head", new Set(["head"]))).toBe(false);
    expect(movesLabelledSubpage(block, "head", new Set())).toBe(false);
  });
});

describe("sharing-state rollback", () => {
  const legacy = legacyKeyRef("a".repeat(64));
  const k3 = newContainerKey();
  const ring = new Map([[3, k3]]);
  const seen = raiseFloor({}, { id: cnt, keyGeneration: 3, sharedGeneration: 2 });

  it("remembers the highest generations reported, and never lowers them", () => {
    expect(seen).toEqual({ shared: 2, generation: 3 });
    expect(raiseFloor(seen, { id: cnt, keyGeneration: 1, sharedGeneration: 0 })).toEqual(seen);
    expect(raiseFloor(seen, { id: cnt, keyGeneration: 5, sharedGeneration: 2 })).toEqual({ shared: 2, generation: 5 });
  });

  it("refuses every write when the server reports a seen-shared notebook as legacy", () => {
    const legacyReport = { id: cnt, keyGeneration: 3, sharedGeneration: 0 };
    expect(guardContainer(legacyReport, seen).rollback).toBe(true);
    expect(writeKey(legacyReport, ring, legacy, seen)).toBeUndefined();
    // The local waiting seal never leaves the device; it is never a server write key.
    expect(localKey(legacyReport, ring, legacy, seen).generation).toBe(WAITING_GENERATION);
    // Reads keep the shared rule: the current generation opens only with its container key.
    expect(readKeys(legacyReport, ring, legacy, 3, seen)).toEqual([k3]);
    expect(legacyRow(legacyReport, 3, seen)).toBe(false);
    expect(legacyRow(legacyReport, 1, seen)).toBe(true);
  });

  it("refuses a lowered key generation, so nothing is sealed under an older key", () => {
    const lowered = { id: cnt, keyGeneration: 2, sharedGeneration: 2 };
    const withOld = new Map([[2, newContainerKey()], [3, k3]]);
    expect(guardContainer(lowered, seen).rollback).toBe(true);
    expect(writeKey(lowered, withOld, legacy, seen)).toBeUndefined();
    expect(writeKey({ id: cnt, keyGeneration: 3, sharedGeneration: 2 }, withOld, legacy, seen)).toEqual({ key: k3, generation: 3 });
  });
});

describe("server-claimed kind never decides keys", () => {
  const legacy = legacyKeyRef("a".repeat(64));
  const k2 = newContainerKey();
  const seen = { shared: 2, generation: 2 };

  it("gives a seen-shared notebook relabelled personal no write key and no legacy read", () => {
    const relabelled = { id: cnt, kind: "personal", keyGeneration: 2, sharedGeneration: 0 };
    expect(keysAllowed(relabelled, seen)).toBe(false);
    expect(writeKey(relabelled, new Map([[2, k2]]), legacy, seen)).toBeUndefined();
    expect(readKeys(relabelled, new Map([[2, k2]]), legacy, 2, seen)).not.toContain(legacy);
    // Still shared on the server, but called personal: also refused.
    expect(keysAllowed({ ...relabelled, sharedGeneration: 2 }, seen)).toBe(false);
  });

  it("leaves a never-shared personal notebook and a team notebook alone", () => {
    expect(keysAllowed({ id: cnt, kind: "workbook", keyGeneration: 1, sharedGeneration: 0 }, {})).toBe(true);
    expect(keysAllowed({ id: cnt, kind: "team", keyGeneration: 2, sharedGeneration: 2 }, seen)).toBe(true);
    expect(keysAllowed({ id: cnt, kind: "workbook", teamId: "cnt_t", keyGeneration: 2, sharedGeneration: 2 }, seen)).toBe(true);
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

describe("legacy closure", () => {
  const container = { id: cnt, keyGeneration: 3, sharedGeneration: 2 };
  const ck = newContainerKey();
  const ring = new Map([[3, ck]]);
  const closed: KeyFloor = { shared: 2, generation: 3, closed: 2 };

  it("refuses the login key for every server row once this device closed legacy reads", () => {
    // Open: a row below sharing reads with the login key (and is labelled).
    expect(readKeys(container, ring, legacy, 1, { shared: 2, generation: 3 })).toEqual([legacy]);
    for (const generation of [0, 1, undefined, 1.5]) expect(readKeys(container, ring, legacy, generation, closed)).toEqual([]);
    expect(readKeys(container, ring, legacy, 3, closed)).toEqual([ck]);
    // A server that reports the notebook as never shared changes nothing.
    expect(readKeys({ ...container, sharedGeneration: 0 }, ring, legacy, 1, closed)).toEqual([]);
    expect(readKeys({ sharedGeneration: 0 }, new Map(), legacy, 1, { closed: 2 })).toEqual([]);
  });

  it("still opens this browser's own queued and cached entries with the login key", () => {
    expect(localReadKeys(container, ring, legacy, WAITING_GENERATION, closed)).toEqual([legacy]);
    expect(localReadKeys(container, ring, legacy, 1, closed)).toEqual([legacy]);
    expect(localReadKeys(container, ring, legacy, 3, closed)).toEqual([ck]);
    expect(closed.closed).toBe(2); // the caller's floor is untouched
  });

  it("never reopens: merges and raises keep the closure", () => {
    expect(mergeFloor(closed, { shared: 2, generation: 4 })).toMatchObject({ closed: 2, generation: 4 });
    expect(mergeFloor({ shared: 2 }, { shared: 2, closed: 2 }).closed).toBe(2);
    expect(raiseFloor(closed, { id: cnt, keyGeneration: 5, sharedGeneration: 2 }).closed).toBe(2);
    expect(mergeFloor({ shared: 1 }, { shared: 1 })).not.toHaveProperty("closed");
  });
});

describe("reopening legacy reads", () => {
  const me = `usr_${"m".repeat(26)}`;
  it("recognises only confirmations confirmReopenLegacy made, for that user and container, once", () => {
    const real = confirmReopenLegacy(me, cnt);
    expect(isReopenConfirmation(real, me, cnt)).toBe(true);
    expect(Object.isFrozen(real)).toBe(true);
    expect(isReopenConfirmation(real, me, `cnt_${"b".repeat(26)}`)).toBe(false);
    expect(isReopenConfirmation(real, `usr_${"n".repeat(26)}`, cnt)).toBe(false);
    for (const forged of [{ userID: me, containerID: cnt }, Object.create(ReopenConfirmation.prototype), Object.assign(Object.create(ReopenConfirmation.prototype), { userID: me, containerID: cnt }), null, cnt])
      expect(isReopenConfirmation(forged, me, cnt)).toBe(false);
    // Another user's or container's check does not use it up; the first real use does.
    expect(consumeReopenConfirmation(real, `usr_${"n".repeat(26)}`, cnt)).toBe(false);
    expect(consumeReopenConfirmation(real, me, cnt)).toBe(true);
    expect(consumeReopenConfirmation(real, me, cnt)).toBe(false);
    expect(isReopenConfirmation(real, me, cnt)).toBe(false);
  });

  it("treats a malformed closure as closed, never as open", () => {
    for (const bad of [NaN, "x", -1, 1.5, Infinity, null, {}] as unknown as number[]) {
      expect(mergeFloor({ shared: 2, closed: 2 }, { shared: 2, closed: bad }).closed).toBe(2);
      expect(legacyKeys(mergeFloor({ shared: 2 }, { shared: 2, closed: bad }), legacy)).toEqual([]);
      expect(legacyKeys({ closed: bad }, legacy)).toEqual([]); // a malformed value in hand fails closed
    }
    expect(legacyKeys(mergeFloor({ shared: 2, closed: 2 }, { shared: 2, closed: NaN }), legacy)).toEqual([]);
  });

  it("a malformed closure blocks a legacy read through readKeys and legacyKeys alike", () => {
    const container = { sharedGeneration: 2 };
    for (const bad of [NaN, "x", -1, 1.5, Infinity, null, {}] as unknown as number[]) {
      for (const floor of [{ shared: 2, closed: bad }, mergeFloor({ shared: 2 }, { shared: 2, closed: bad })]) {
        expect(legacyKeys(floor, legacy)).toEqual([]);
        expect(readKeys(container, new Map(), legacy, 1, floor)).toEqual([]);
        expect(readKeys({ sharedGeneration: 0 }, new Map(), legacy, 1, floor)).toEqual([]);
        // This browser's own entries still open (the local exception).
        expect(localReadKeys(container, new Map(), legacy, 1, floor)).toEqual([legacy]);
      }
    }
    // Open floors still read: the decision is not simply "always closed".
    for (const floor of [{ shared: 2 }, { shared: 2, closed: 0 }]) expect(readKeys(container, new Map(), legacy, 1, floor)).toEqual([legacy]);
  });

  it("closedOf and legacyKeys make one closure decision", () => {
    for (const closed of [undefined, 0, 1, 2, 2 ** 53, NaN, "x", -1, 1.5, Infinity, null, {}, "0", false] as unknown as number[]) {
      const floor: KeyFloor = { closed };
      expect(legacyKeys(floor, legacy).length === 1).toBe(closedOf(floor) === 0);
    }
    expect(closedOf({})).toBe(0);
    expect(closedOf({ closed: 0 })).toBe(0);
    expect(closedOf({ closed: 3 })).toBe(3);
    expect(closedOf({ closed: NaN })).toBeGreaterThan(0);
    // One decision, not two that happen to agree today.
    const source = import.meta.glob<string>("./keyring.ts", { query: "?raw", import: "default", eager: true })["./keyring.ts"];
    expect(source).toMatch(/export const legacyKeys = [^\n]*=> \(closedOf\(floor\) === 0 \?/);
  });

  it("mints a reopen confirmation only from the user's \"Show pre-sharing items again\" confirm", () => {
    const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(["./main.tsx", "./keyring.ts"]));
    // The identifier itself, so an aliased import, a re-export or a namespace access is caught too.
    const naming = (all: Record<string, string>) => Object.entries(all).filter(([name, text]) => /\bconfirmReopenLegacy\b/.test(text) && (!["./keyring.ts", "./components/LegacyReview.tsx"].includes(name) || /\bconfirmReopenLegacy\s+as\b/.test(text))).map(([name]) => name);
    expect(naming(sources)).toEqual([]);
    expect(naming({ "./x.ts": 'import { confirmReopenLegacy as yes } from "./keyring"; yes(u, c);', "./components/LegacyReview.tsx": 'import { confirmReopenLegacy as ok } from "../keyring";' })).toEqual(["./x.ts", "./components/LegacyReview.tsx"]);
  });
});
