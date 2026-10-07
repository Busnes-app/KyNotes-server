import { describe, expect, it } from "vitest";
import { base64, decryptNote, encryptNote, legacyKeyRef } from "./crypto";
import { newContainerKey, openFirst, openKeyring, planSweep, readKeys, sealFor, writeKey, type Envelope, type Me, type MemberKey } from "./keyring";
import { generateIdentity } from "./teamKeys";

const cnt = `cnt_${"a".repeat(26)}`;
const dev = (c: string) => `dev_${c.repeat(26)}`;
const person = (name: string, c: string, role = "editor") => {
  const id = generateIdentity();
  const held: Me = { ...id, deviceId: dev(c), userId: `usr_${c.repeat(26)}` };
  const member: MemberKey = { userId: held.userId, username: name, role, identity: { deviceId: dev(c), publicKey: base64(id.publicKey) } };
  return { held, member };
};
const legacy = legacyKeyRef("5a".repeat(32));
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
    const opened = openKeyring(cnt, [...rows, forged], owner.held, [owner.member, editor.member], {});
    expect([...opened.ring.keys()].sort()).toEqual([2, 3]);
    expect(opened.ring.get(3)).toEqual(k3);
    // Self-sealed envelopes need no pin and add none.
    expect(opened).toMatchObject({ pins: {}, fresh: [], changed: [] });
    expect(openKeyring(cnt, rows, undefined, [owner.member], {}).ring.size).toBe(0);
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
      const opened = openKeyring(cnt, fromOwner, editor.held, members, pins);
      expect(opened.ring.get(2)).toEqual(k2);
      expect(opened).toMatchObject({ pins, fresh: [], changed: [] });
    });

    it("pins a first-contact steward and surfaces it as a new key holder", () => {
      const opened = openKeyring(cnt, fromOwner, editor.held, members, {});
      expect(opened.ring.get(2)).toEqual(k2);
      expect(opened.pins).toEqual({ [owner.member.userId]: owner.member.identity!.publicKey });
      expect(opened.fresh).toEqual([owner.member]);
    });

    it("rejects and surfaces a steward whose key no longer matches its pin", () => {
      const pinned = admin.member.identity!.publicKey;
      const opened = openKeyring(cnt, fromOwner, editor.held, members, { [owner.member.userId]: pinned });
      expect(opened.ring.size).toBe(0);
      expect(opened.changed).toEqual([{ member: owner.member, pinned }]);
      expect(opened.pins).toEqual({ [owner.member.userId]: pinned });
    });

    it("ignores senders that are not current stewards", () => {
      const fromEditor = [seal(owner.member, 2, k2, editor.held)];
      expect(openKeyring(cnt, fromEditor, owner.held, members, {}).ring.size).toBe(0);
      // A removed steward is no longer in the member list.
      expect(openKeyring(cnt, fromOwner, editor.held, [admin.member, editor.member], {}).ring.size).toBe(0);
    });

    it("ignores an envelope forged in a steward's name and pins nothing", () => {
      const server = generateIdentity();
      const forged = [seal(editor.member, 2, k2, { ...server, deviceId: owner.held.deviceId, userId: owner.held.userId })];
      const opened = openKeyring(cnt, forged, editor.held, members, {});
      expect(opened).toMatchObject({ pins: {}, fresh: [], changed: [] });
      expect(opened.ring.size).toBe(0);
    });

    it("ignores a steward listed under this user's ID with another identity", () => {
      const impostor = person("editor", "g", "owner");
      const fake: MemberKey = { ...impostor.member, userId: editor.member.userId };
      const rows = [seal(editor.member, 2, k2, impostor.held)];
      expect(openKeyring(cnt, rows, editor.held, [owner.member, fake], {}).ring.size).toBe(0);
    });
  });

  it("writes legacy containers with the login key and shared ones only with the current key", () => {
    const k3 = newContainerKey();
    const ring = new Map([[3, k3]]);
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 0 }, ring, legacy)).toEqual({ key: legacy, generation: 4 });
    expect(writeKey({ id: cnt, keyGeneration: 3, sharedGeneration: 2 }, ring, legacy)).toEqual({ key: k3, generation: 3 });
    // Waiting for keys: never fall back to the legacy key in a shared container.
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 2 }, ring, legacy)).toBeUndefined();
  });

  it("reads a shared generation only with its own key, and legacy rows only with the legacy key", async () => {
    const [k2, k3, k4] = [newContainerKey(), newContainerKey(), newContainerKey()];
    const ring = new Map([[2, k2], [4, k4], [3, k3]]);
    const shared = { sharedGeneration: 2 };
    expect(readKeys(shared, ring, legacy, 3)).toEqual([k3]);
    expect(readKeys(shared, ring, legacy, 1)).toEqual([legacy]);
    expect(readKeys({ sharedGeneration: 0 }, ring, legacy, 5)).toEqual([legacy]);
    expect(readKeys(shared, ring, legacy, undefined)).toEqual([]);
    expect(readKeys(shared, ring, legacy, 5)).toEqual([]);
    const note = { title: "L", body: "" };
    // Legacy rows below sharedGeneration still decrypt.
    const old = await encryptNote(legacy, cnt, note);
    await expect(openFirst(readKeys(shared, ring, legacy, 1), (key) => decryptNote(key, cnt, old))).resolves.toEqual(note);
    // A server relabelling legacy-key ciphertext as shared cannot downgrade the read.
    await expect(openFirst(readKeys(shared, ring, legacy, 3), (key) => decryptNote(key, cnt, old))).rejects.toThrow();
  });

  it("never opens a newer row with a removed member's older key", async () => {
    const k2 = newContainerKey();
    const removed = new Map([[2, k2]]); // keys a member held before removal re-keyed to generation 3
    const forged = await encryptNote(k2, cnt, { title: "F", body: "" });
    expect(readKeys({ sharedGeneration: 2 }, removed, legacy, 3)).toEqual([]);
    await expect(openFirst(readKeys({ sharedGeneration: 2 }, removed, legacy, 3), (key) => decryptNote(key, cnt, forged))).rejects.toThrow();
  });
});

describe("planSweep", () => {
  const owner = person("owner", "b", "owner");
  const editor = person("editor", "c");
  const container = (keyGeneration: number, sharedGeneration: number) => ({ id: cnt, keyGeneration, sharedGeneration });

  it("mints the first key only when every member has an identity", () => {
    const sso: MemberKey = { userId: `usr_${"d".repeat(26)}`, username: "sso-user", role: "editor" };
    const base = { me: owner.member.userId, envelopes: [], ring: new Map() };
    expect(planSweep({ ...base, container: container(1, 0), members: [owner.member, editor.member, sso] })).toEqual({ kind: "blocked", waitingFor: ["sso-user"] });
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
});
