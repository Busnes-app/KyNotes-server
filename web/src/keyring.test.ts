import { describe, expect, it } from "vitest";
import { base64, decryptNote, encryptNote, legacyKeyRef } from "./crypto";
import { newContainerKey, openFirst, openKeyring, planSweep, readKeys, sealFor, writeKey, type Envelope, type MemberKey } from "./keyring";
import { generateIdentity } from "./teamKeys";

const cnt = `cnt_${"a".repeat(26)}`;
const dev = (c: string) => `dev_${c.repeat(26)}`;
const person = (name: string, c: string, role = "editor") => {
  const id = generateIdentity();
  const held = { ...id, deviceId: dev(c) };
  const member: MemberKey = { userId: `usr_${c.repeat(26)}`, username: name, role, identity: { deviceId: dev(c), publicKey: base64(id.publicKey) } };
  return { held, member };
};
const legacy = legacyKeyRef("5a".repeat(32));

describe("keyring", () => {
  it("opens only this identity's envelopes, by generation, and skips rows it cannot open", () => {
    const owner = person("owner", "b", "owner");
    const editor = person("editor", "c");
    const k2 = newContainerKey();
    const k3 = newContainerKey();
    const rows: Envelope[] = [sealFor(owner.member, cnt, 2, k2), sealFor(editor.member, cnt, 2, k2), sealFor(owner.member, cnt, 3, k3)];
    const forged = { ...sealFor(owner.member, cnt, 4, k3), keyGeneration: 5 }; // AAD binds the generation
    const ring = openKeyring(cnt, [...rows, forged], owner.held);
    expect([...ring.keys()].sort()).toEqual([2, 3]);
    expect(ring.get(3)).toEqual(k3);
    expect(openKeyring(cnt, rows, undefined).size).toBe(0);
  });

  it("writes legacy containers with the login key and shared ones only with the current key", () => {
    const k3 = newContainerKey();
    const ring = new Map([[3, k3]]);
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 0 }, ring, legacy)).toEqual({ key: legacy, generation: 4 });
    expect(writeKey({ id: cnt, keyGeneration: 3, sharedGeneration: 2 }, ring, legacy)).toEqual({ key: k3, generation: 3 });
    // Waiting for keys: never fall back to the legacy key in a shared container.
    expect(writeKey({ id: cnt, keyGeneration: 4, sharedGeneration: 2 }, ring, legacy)).toBeUndefined();
  });

  it("reads with the row's generation first, then newest, then legacy", async () => {
    const [k2, k3, k4] = [newContainerKey(), newContainerKey(), newContainerKey()];
    const ring = new Map([[2, k2], [4, k4], [3, k3]]);
    expect(readKeys(ring, legacy, 3)).toEqual([k3, k4, k2, legacy]);
    expect(readKeys(ring, legacy)).toEqual([k4, k3, k2, legacy]);
    const old = await encryptNote(legacy, cnt, { title: "L", body: "" });
    await expect(openFirst(readKeys(ring, legacy, 4), (key) => decryptNote(key, cnt, old))).resolves.toEqual({ title: "L", body: "" });
    await expect(openFirst([k2, k3], (key) => decryptNote(key, cnt, old))).rejects.toThrow();
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
    const envelopes = [sealFor(owner.member, cnt, 2, k2), sealFor(editor.member, cnt, 2, k2)];
    const sso: MemberKey = { userId: `usr_${"d".repeat(26)}`, username: "sso-user", role: "editor" };
    expect(planSweep({ container: container(3, 2), me: owner.member.userId, members: [owner.member, editor.member, sso], envelopes, ring: new Map([[2, k2]]) }))
      .toEqual({ kind: "mint", recipients: [owner.member, editor.member] });
  });

  it("wraps every held generation for a member missing it, and nothing it does not hold", () => {
    const newcomer = person("newcomer", "e");
    const [k2, k4] = [newContainerKey(), newContainerKey()];
    const envelopes = [sealFor(owner.member, cnt, 2, k2), sealFor(editor.member, cnt, 2, k2), sealFor(owner.member, cnt, 4, k4), sealFor(editor.member, cnt, 4, k4)];
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
