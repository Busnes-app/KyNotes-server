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
    expect(main.match(/createNamed\(/g)).toHaveLength(3); // the definition, a notebook, a team workspace
    // Every creation goes through createNamed.
    const creations = main.split("\n").filter((line) => /newContainer\(floorSink/.test(line));
    expect(creations).toHaveLength(2);
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
  });

  it("checks the account's identity once per session until it changes (M5)", () => {
    // null means "checked, none": only an unchecked session refetches before a key pass or a creation.
    expect(main).toContain("liveRef.current = live ?? null;");
    expect(main.match(/if \(liveRef\.current === undefined\) await refreshIdentity\(\)/g)).toHaveLength(2);
    expect(main).not.toMatch(/if \(!liveRef\.current\)/);
    // A password change that creates the identity finishes it before the workspace opens, then re-checks it.
    expect(main).toContain("await settleIdentity(name, userID, newKeys);\n        onIdentityCreated();");
    expect(main).not.toMatch(/void settleIdentity\(/);
  });

  it("an approval shares keys for the team and its workspaces, as an SSO steward too", () => {
    expect(block("  async function approve(")).toContain("await reloadTeamMembers(selected, true);");
    const reload = block("  async function reloadTeamMembers(");
    expect(reload).toContain("await syncKeys(child, false, () => false, share)");
    expect(reload).toContain("await syncKeys(team, false, () => false, share)");
  });

  it("never tells an owner to wait for a team owner; copy follows the member list (keyNotices.ts)", () => {
    expect(main).not.toMatch(/once a team owner shares|Waiting for a team owner/);
    expect(main.match(/queuedNotice\(stewardHere\(selected\)\)/g)).toHaveLength(2);
    expect(main).toContain("waitingNotice({ steward: stewardHere(selected),");
    expect(main).toContain("others ? `Sealed this notebook's name with its key: ${name}.` : \"\"");
    // An administrator-set password is changed on ChoosePassword before the workspace opens.
    expect(main).not.toMatch(/adminSetPassword|ADMIN_PASSWORD_FIRST/);
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

  it("re-reads the identity and the notebooks after a link, restore, reset or saved code", () => {
    expect(main).toContain("onIdentityChanged={afterIdentityChange}");
    expect(main).toContain(".finally(afterIdentityChange); }}");
    // A key pass alone left the names and items it could not decrypt hidden until a reload.
    const after = block("  const afterIdentityChange");
    expect(after).toContain("void refreshIdentity().then(() => loadContainers(), () => undefined);");
    expect(after.indexOf('setError("")')).toBeLessThan(after.indexOf("loadContainers()"));
    expect(main).not.toContain("refreshIdentity().then(() => refreshKeys.current()");
    expect(main).not.toMatch(/onLinked\(identity\)/);
    // The first SSO browser is shown its code right away.
    expect(main).toContain('if (settled.kind === "held") { setRecoveryPrompt(true); setView("settings"); }');
    expect(main).toContain('const recoveryNudge = identityState === "held" && live && !live.recoveryId && !recoveryDismissed && (');
    expect(main).toContain('<div className="recovery-notice-body" role="status">{RECOVERY_MISSING}');
  });

  it("tells users and administrators that a reset keeps the key and the recovery code restores it", () => {
    expect(main).toMatch(/const FORGET_DEVICE = "[^"]*enter your recovery code[^"]*KySignOn have no password copy/);
    const adminConsole = import.meta.glob<string>("./components/AdminConsole.tsx", { query: "?raw", import: "default", eager: true })["./components/AdminConsole.tsx"];
    expect(adminConsole).toContain("All existing sessions and paired device credentials were revoked.");
    expect(adminConsole).toMatch(/RESET_DONE = "Password reset\.[^"]*keeps its encryption key[^"]*recovery code[^"]*KySignOn gets no password copy back/);
    expect(adminConsole).toContain("alert(RESET_DONE)");
    expect(main).not.toMatch(/encryption identity was deleted|an administrator reset removes it/);
  });

  it("never asks a single sign-on session for a password; a refused password lets no one in (I1)", () => {
    expect(main).toContain("if (res.user.accountKind === \"admin\" || res.passwordChangeRequired) {");
    expect(main).toContain("if (res.sso) {\n          await openVault(res.user.username).catch(() => undefined); // no IndexedDB: the identity cannot be kept\n          setAuth({ username: res.user.username, authSecret: \"\", user: res.user, sso: true });\n          return;\n        }\n        setSessionUser(res.user);");
    expect(main.indexOf("res.passwordChangeRequired) {")).toBeLessThan(main.indexOf("if (res.sso) {"));
    expect(main).not.toMatch(/master password|Master Password|note-encryption keys|storeDeviceKey|getDeviceKey/);
    const submit = block("  async function submit(");
    expect(submit).not.toMatch(/sso: true/);
    expect(submit.match(/catch/g)).toHaveLength(1); // the error shown on the form; no fallback sign-in
    expect(submit).toContain("const result = await login(activeName, authSecret);");
    // Only an everyday account on its own password keeps a vault record, after the server accepted the password.
    expect(submit).toContain("if (everyday && !result.passwordChangeRequired) {\n        await rememberAfter(async () => result, activeName);");
  });

  it("a reopened password session holds no login secret: it steps up by asking, and background passes never ask", () => {
    expect(main).toContain("if (await vaultReady(res.user.username)) setAuth({ username: res.user.username, authSecret: \"\", user: res.user });");
    expect(main).toContain("asked.current ??= stepUpAsking(auth.username).then((secret) => { onAuthSecret(secret); return secret; });\n      try { await stepUp(await asked.current); } catch (error) { asked.current = undefined; throw error; }");
    expect(main).toContain("canWrap: share || (!auth.sso && (!background || auth.authSecret !== \"\"))");
  });

  it("asks stewards to approve administrator-added members and to name a team an administrator created", () => {
    expect(main).toContain("const UNNAMED_TEAM = \"An administrator created this team notebook for you. Name it so its members can find it.\";");
    expect(main).toMatch(/approvalText = \(name: string\) => `\$\{name\} was added by an administrator\. They get this notebook's keys only after you approve them\.`/);
    expect(main).toContain("teamSteward && membersForTeam.filter((member) => member.approved === false)");
    expect(main).toContain("await approveMember(");
  });

  it("shows member management and team notebooks only to stewards, from the server's member list (M1)", () => {
    expect(main).toContain("const teamSteward = stewardOf(membersForTeam, auth.user.id) === true;");
    expect(main).toContain('{selected.kind === "team" && teamSteward && <button className="quiet" onClick={() => { closeMenu("notebook-menu"); void invite(); }}>Add person</button>}');
    expect(main).toContain('{selected.kind === "team" && teamSteward && <button className="quiet" disabled={busy} onClick={() => { closeMenu("notebook-menu"); void newTeamWorkspace(selected); }}>Create team notebook</button>}');
    expect(main).toContain("{teamSteward && member.userId !== auth.user.id && (");
  });

  it("never sends an edit sealed for a key a reset replaced, and explains an unanswered reset (M4, M5)", () => {
    expect(block("  async function drainNow(")).toContain(".filter((item) => item.owner === auth.user.id).filter((item) => !item.previousKey);");
    expect(main).toContain("onReset={(next) => { void retireWaitingEdits(next)");
    expect(main).toContain("setResetUnfinished(unfinishedReset(local, live, sent));");
    expect(main).toContain("noteReset: (publicKey) => noteResetSent(auth.username, auth.user.id, publicKey)");
    expect(main).toContain("{resetUnfinished && <div className=\"conflict-banner\" role=\"status\">{RESET_UNFINISHED} <button className=\"secondary\" onClick={() => { if (confirm(FORGET_DEVICE)) onForgetDevice?.(); }}>Forget this device</button></div>}");
  });

  it("renders waitingHeld from state set with the waiting key, never from the ref (N2)", () => {
    expect(main).toContain("waitingRef.current = identityRef.current && waitingKey(identityRef.current);\n      setWaitingHeld(Boolean(waitingRef.current));");
    expect(main).toContain("waitingHeld={waitingHeld}");
    expect(main).not.toMatch(/=\{[^}]*waitingRef\.current/); // no JSX prop reads the ref during render
  });
});

describe("save queue wiring", () => {
  it("runs the queue drain in the save chain, never beside a live save", () => {
    expect(block("  function drainQueue(")).toContain("void chained(drainNow);");
    expect(block("  function save(")).toContain("return chained(");
    expect(main.match(/saveChain\.current\.then\(/g)).toHaveLength(1); // only chained() appends
  });

  it("clears after a save only the queued copy this tab wrote", () => {
    expect(main).not.toMatch(/clearQueuedSave\(auth\.user\.id, (note\.)?id\)/);
    expect(main.match(/\bqueueSave\(/g)).toHaveLength(1); // only queueOwn writes the queue
    expect(block("  async function clearOwnQueued(")).toContain("await clearQueuedSave(auth.user.id, id, updatedAt);");
  });

  it("does not autosave a page in conflict, and keystrokes do not restart the 15 s autosave", () => {
    expect(main).toContain("const autosaving = dirty && selectedNote !== null && !conflicted.has(selectedNote.id);");
    expect(main).toContain("}, [selectedNote?.title, selectedNote?.body, autosaving]);");
    expect(main).toContain("}, [selectedNote?.id, autosaving]);");
    expect(main).not.toContain("}, [selectedNote, dirty]);");
  });

  it("says when a notebook load could not read an object instead of dropping it silently", () => {
    const read = block("  async function readContainerObjects(");
    expect(read).toContain("unreadable += 1;");
    expect(read).not.toContain("Ignore an invalid local draft");
    expect(block("  async function loadContainer(")).toContain("if (objects.unreadable) setError(unreadableNotice(objects.unreadable));");
  });

  it("revokes the object URLs the editor resolved when the page closes", () => {
    expect(block("  async function resolveFileUrl(")).toContain("resolvedURLs.current.push(objectURL);");
    expect(main).toContain("resolvedURLs.current.forEach((url) => URL.revokeObjectURL(url));");
  });

  it("an automatic notebook load never closes a work queue opened before it finished", () => {
    expect(block("  async function loadContainer(")).toContain("if (leaveQueue) setQueueMode(false);");
    expect(main.match(/setQueueMode\(false\)/g)).toHaveLength(1);
    expect(main).toContain("await selectContainer(start, start.id === route.container ? route : undefined, false);");
    expect(main.match(/selectContainer\([^)]*, false\)/g)).toHaveLength(1); // only the sign-in / reload load
    // A queue opened before the notebook list arrived is rebuilt from it.
    expect(main).toContain("if ((reminderPrefs.enabled || reminderPrefs.push || queueMode) && items.length) void loadWorkQueue()");
  });
});

describe("content v2 refusal point", () => {
  it("server copies open v1 only before the marker, and the pinned marker is loaded before any read", () => {
    const read = block("  async function readContainerObjects(");
    expect(read).toContain("const v1 = !migrated.current.has(container.id);");
    expect(read).toContain(": await server(v1).then(");
    const load = block("  async function loadContainer(");
    expect(load.indexOf("if ((await pinStore.loadKeyState(keyed.id)).objects === 2) migrated.current.add(keyed.id);")).toBeGreaterThan(-1);
    expect(load.indexOf("loadKeyState(keyed.id)")).toBeLessThan(load.indexOf("readContainerObjects(keyed)"));
    // A pinned notebook's name without the marker is refused, as a rollback.
    expect(block("  async function loadContainers(")).toContain("if (migrated.current.has(item.id) && meta.objects !== 2) olderMeta = true;");
  });

  it("opens with v1 forced on only this browser's own copies, the name it then judges, and the pre-marker pass", () => {
    const lines = main.split("\n").filter((line) => /(?:decrypt\w+|openObject)\(key[^;]*, true\)/.test(line));
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) expect(line).toMatch(/cached!?\.payload, true|item\.payload, true|old, item\.containerID|fromBase64\(container\.metaCiphertext\), true|decryptAttachment\(key, container\.id, pageID, bytes, true\)/);
    expect(block("  async function childPins(")).toContain("decryptAttachment(key, container.id, pageID, bytes, true)");
  });
});
