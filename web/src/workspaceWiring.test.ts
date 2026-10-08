import { describe, expect, it } from "vitest";

// The workspace has no unit harness: its key wiring is pinned here.
const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
/** The source of one local function or const in main.tsx, up to the next one at the same indent. */
const block = (start: string) => {
  const from = main.indexOf(start);
  expect(from, start).toBeGreaterThan(-1);
  const rest = main.slice(from + start.length);
  const end = rest.search(/\n {2}(?:async function|function|const|\/\*\*|\/\/) /);
  return start + rest.slice(0, end);
};

describe("workspace keys after P5", () => {
  it("creates every notebook through createNamed and never seals with the login key", () => {
    const create = block("  async function createNamed(");
    // Refused before anything is created, so a refused mint never leaves an unnamed notebook behind.
    expect(create).toContain("if (!(await heldIdentity())) throw new Error(NO_KEY_HERE);");
    expect(create).toContain("if (!recoverable(liveRef.current)) throw new Error(UNRECOVERABLE);");
    expect(create.indexOf("throw new Error(UNRECOVERABLE)")).toBeLessThan(create.indexOf("createKeyed(create,"));
    expect(create.indexOf("throw new Error(NO_KEY_HERE)")).toBeLessThan(create.indexOf("createKeyed(create,"));
    // A failed mint or naming deletes the still-empty notebook (observe.ts createKeyed, M2).
    expect(create).toContain("}, deleteContainer);");
    expect(create).toContain("const container = await syncKeys(created, false, () => false, true);");
    expect(create).toContain("if (!write) throw new Error(NOT_KEYED);");
    expect(main.match(/createNamed\(/g)).toHaveLength(4); // the definition, a notebook, a team workspace, an administrator's team
    // Every creation goes through createNamed.
    const creations = main.split("\n").filter((line) => /new(?:Container|AdminTeam)\(floorSink/.test(line));
    expect(creations).toHaveLength(3);
    for (const line of creations) expect(line).toContain("createNamed(");
    expect(main).not.toMatch(/nameUnsharedTeam|renameTeam/);
    expect(main).toMatch(/writeKey\(container, ringsRef\.current\[container\.id\] \?\? noKeys, floor\)/);
  });

  it("seals waiting edits with the identity, and tells the sweep whether the account is recoverable", () => {
    expect(block("  const localKeyFor")).toContain("writeKeyFor(container) ?? (waitingRef.current && { key: waitingRef.current, generation: WAITING_GENERATION })");
    expect(block("  async function syncKeys(")).toContain("recoverable: recoverable(liveRef.current)");
    expect(main).toContain("canWrap: false, recoverable: false }"); // the list's read-only pass never mints
    expect(main.match(/waitingRef\.current\)/g)?.length).toBeGreaterThanOrEqual(3); // ownCopyKeysFor, readyToSend, attachmentStep
    expect(main).toContain("waitingRef.current = identityRef.current && waitingKey(identityRef.current);");
    expect(main).toContain('{knownNames[entry.id] ?? "Unnamed team"}'); // AdminTeams reads the live prop, not a stale closure
  });

  it("checks the account's identity once per session until it changes (M5)", () => {
    // null means "checked, none": only an unchecked session refetches before a key pass or a creation.
    expect(main).toContain("liveRef.current = live ?? null;");
    expect(main.match(/if \(liveRef\.current === undefined\) await refreshIdentity\(\)/g)).toHaveLength(2);
    expect(main).not.toMatch(/if \(!liveRef\.current\)/);
    // A password change that creates the identity re-checks it.
    expect(main).toContain("settleIdentity(name, userID, newKeys).then(onIdentityCreated,");
  });

  it("never tells an owner to wait for a team owner; copy follows the member list (keyNotices.ts)", () => {
    expect(main).not.toMatch(/once a team owner shares|Waiting for a team owner/);
    expect(main.match(/queuedNotice\(stewardHere\(selected\)\)/g)).toHaveLength(2);
    expect(main).toContain("waitingNotice({ steward: stewardHere(selected),");
    expect(main).toContain("others ? `Sealed this notebook's name with its key: ${name}.` : \"\"");
    // Only when the server refused the identity create for an administrator-set password (M2).
    expect(main).toContain("{!auth.sso && identityState === \"create\" && adminSetPassword.has(auth.user.id) && <div className=\"conflict-banner\" role=\"status\">{ADMIN_PASSWORD_FIRST}");
    expect(main).toContain("if ((await settlePasswordIdentity(identityAPI, store, userID, keys, fromLogin)) === \"admin-password\") adminSetPassword.add(userID);");
  });

  it("changes the password without a content warning: nothing depends on it", () => {
    expect(main).toContain("passwordChangeProblem(next, confirmation)");
    expect(main).toContain('setStatus("Password changed.");');
    expect(main).not.toMatch(/acknowledged|atRisk|legacyAtRisk|PASSWORD_CHANGE_NOTE|passwordChangedStatus|resealWaitingEdits/);
  });
});

describe("recovery code wiring (P5 Task 8)", () => {
  it("offers restore beside linking, the code card to a held browser, and reset to any account with a key", () => {
    expect(main).toContain('{identityState === "link" && <RecoveryRestore ');
    expect(main.indexOf("<RecoveryRestore ")).toBeGreaterThan(main.indexOf('{identityState === "link" && <LinkThisBrowser '));
    expect(main).toContain('{identityState === "held" && <RecoverySetup ');
    // A password session types its password for the reset; an SSO session confirms with KySignOn.
    expect(main).toContain("password={sso ? undefined : passwordReset(username)}");
    expect(main).toContain("exportWaiting={exportWaiting}");
  });

  it("re-reads the identity and runs a key pass after a link, restore, reset or saved code", () => {
    expect(main).toContain("onIdentityChanged={() => { setRecoveryPrompt(false); void refreshIdentity().then(() => refreshKeys.current(), () => undefined); }}");
    expect(main).not.toMatch(/onLinked\(identity\)/);
    // The first SSO browser is shown its code right away.
    expect(main).toContain('if (settled.kind === "held") { setRecoveryPrompt(true); setView("settings"); }');
    expect(main).toContain("{identityState === \"held\" && live && !live.recoveryId && <div className=\"conflict-banner\" role=\"status\">{RECOVERY_MISSING}");
  });

  it("tells users and administrators that a reset keeps the key and the recovery code restores it", () => {
    expect(main).toMatch(/const FORGET_DEVICE = "[^"]*enter your recovery code[^"]*KySignOn have no password copy/);
    expect(main).toMatch(/alert\("Password reset\.[^"]*keeps its encryption key[^"]*recovery code[^"]*KySignOn gets no password copy back/);
    expect(main).not.toMatch(/encryption identity was deleted|an administrator reset removes it/);
  });
});

