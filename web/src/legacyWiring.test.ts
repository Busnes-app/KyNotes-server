import { describe, expect, it } from "vitest";

// The workspace has no unit harness: its pre-sharing wiring is pinned here, and its pieces are tested
// in migration.test.ts and components/LegacyReview.test.tsx.
const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
/** The source of one local function or const in main.tsx, up to the next one at the same indent. */
const block = (start: string) => {
  const from = main.indexOf(start);
  expect(from, start).toBeGreaterThan(-1);
  const rest = main.slice(from + start.length);
  const end = rest.search(/\n {2}(?:async function|function|const|\/\*\*|\/\/) /);
  return start + rest.slice(0, end);
};

describe("workspace pre-sharing wiring", () => {
  it("sets this user's closure reader at sign-in", () => {
    expect(main).toContain("useEffect(() => { setClosureReader(pinStore.loadKeyState); }, [auth.username, auth.user.id]);");
    expect(main).toContain("loadKeyState: (containerID) => getKeyState(auth.username, auth.user.id, containerID),");
  });

  it("checks after every load, shows the check while it runs, and never closes on a failed check", () => {
    const check = block("  async function checkLegacy(");
    expect(check).toContain("setLegacyCheck({ containerID: container.id, checking: true });");
    expect(check).toContain("const autoClose = await mayAutoClose(() => stored);");
    // The check's own close is automatic: closeLegacyStored re-reads the reopen mark in its transaction (M1).
    expect(check).toContain("await checkLegacyRows(() => reviewLegacy(reviewAPI, { container, floorNow, legacy, userId: auth.user.id }), floorNow, async () => (await stopLegacy(container, true)) === \"closed\", autoClose);");
    expect(main).toContain("const closureSink: ClosureSink = { close: (containerID, closed, auto) => closeLegacyStored(auth.username, auth.user.id, containerID, closed, auto) };");
    expect(block("  async function stopLegacy(")).toContain("const outcome = await closeLegacy(closureSink, container.id, auto);");
    // The stored reopen mark keeps Stop on screen (I2), and rows read with the login key do too.
    expect(check).toContain("const reopened = !autoClose && (await stored.then((state) => state.reopened === true, () => false));");
    expect(check.match(/, reopened \}/g)).toHaveLength(3);
    expect(main).toContain("reopened={legacyCheck.reopened === true} labelled={unverified.size > 0}");
    expect(main).not.toMatch(/reopenedRef/);
    expect(check).toMatch(/if \("failed" in check\) \{[^]*failure: checkFailure\(check\.failed\), reopened \}\);\n\s*return;\n\s*\}/);
    expect(check.match(/stopLegacy/g)).toHaveLength(1); // only as checkLegacyRows' close
    // Only checkLegacyRows decides to close by itself; nothing turns a rejection into a review.
    expect(main).not.toMatch(/\bautoCloses\(/);
    expect(main).not.toMatch(/reviewLegacy\([^)]*\)\)?\.catch\(/);
    const load = block("  async function loadContainer(");
    expect(load).toContain("setLegacyCheck(undefined);");
    expect(load).toMatch(/patchNotes\(\(\) => loaded\);\n\s*void checkLegacy\(keyed, superseded\);/);
  });

  it("reloads the open notebook when its closure rises, here or in another tab", () => {
    expect(main).toContain("const closedNow = selected ? closedOf(floorFor(selected)) : 0;");
    // Always, labelled pages or not: the review dialog, comments and previews leave the screen too (M3).
    expect(main).toContain("const rose = before.closed === 0 && closedNow > 0;");
    expect(block("  async function loadContainer(")).toMatch(/setCommentsForNote\(\[\]\);[^]*setLegacyCheck\(undefined\);/);
    // A reopen here or in another tab (floors.ts adoptStored lowers the closure) refreshes the view too (M2).
    expect(main).toContain("const fell = before.closed > 0 && closedNow === 0;");
    expect(main).toContain("if (selected && before.id === selected.id && (rose || fell)) void selectContainer(selected, parseRoute(location.hash));");
    expect(main).toContain("}, [selected?.id, closedNow]);");
  });

  it("shares through the outbound gate at the floor current now, and closes only through migrateLegacy", () => {
    const api = block("  const migrationAPI = ");
    expect(api).toMatch(/\n\s{4}sendObject,\n\s{4}sendCommentRewrite,\n/);
    expect(api).toContain("detach: detachAttachment,");
    expect(api).toContain("resolve: resolveConflict,");
    expect(main).toMatch(/import \{[^}]*\bsendCommentRewrite\b[^}]*\bsendObject\b[^}]*\} from "\.\/outbound";/);
    const share = block("  async function shareLegacy(");
    expect(share).toContain("floorNow: () => floorFor(container)");
    expect(share).toContain("async () => (await stopLegacy(container)) === \"closed\");");
    expect(share).not.toMatch(/closeLegacy\(/);
  });

  it("counts a conflict copy as placed only once it is saved on the server", () => {
    const place = block("  async function placeConflictCopy(");
    expect(place).toContain("const saved = await writeObject(object.id, 0, page);\n    if (saved === null) return false;");
    expect(block("  const migrationAPI = ")).toContain("return Boolean(original) && placeConflictCopy(container.id, original!, payload);");
    // writeObject returns a version only after the server accepted the save; queued or kept-local paths return null.
    const write = block("  async function writeObject(");
    expect(write).toMatch(/const result = await sendObject\([^)]*\);[^]*return result\.version;/);
    expect(write.match(/return null;/g)).toHaveLength(3);
    // keepConflictCopies resolves only after its copy, too.
    expect(main).toContain("if (!(await placeConflictCopy(containerID, current, group.payload, sameNotebook))) { failed += 1; continue; }");
  });

  it("reopens only with the dialog's confirmation, then lowers this tab and tells the others", () => {
    const reopen = block("  async function reopenLegacyReads(");
    expect(reopen).toMatch(/if \(!\(await reopenLegacy\(auth\.username, auth\.user\.id, container\.id, confirmation\)\)\)[^]*return;\n\s*\}\n[^]*await reopenFloorIn\(container\.id\);/);
    expect(main).toContain("onReopen={(confirmation) => reopenLegacyReads(selected, confirmation)}");
  });

  it("makes no key or closure decision from kind or teamId", () => {
    for (const name of ["  async function checkLegacy(", "  async function stopLegacy(", "  const migrationAPI = ", "  async function shareLegacy(", "  async function reopenLegacyReads(", "  async function placeConflictCopy("])
      expect(block(name)).not.toMatch(/\.kind\b|teamId/);
    expect(main).toContain("closed={closedOf(floorFor(selected)) > 0}");
  });
});

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
    expect(main).not.toMatch(/encrypt\w*\(\s*legacy\b/);
    expect(main).not.toMatch(/nameUnsharedTeam|renameTeam/);
    expect(main).toMatch(/writeKey\(container, ringsRef\.current\[container\.id\] \?\? noKeys, floor\)/);
  });

  it("seals waiting edits with the identity, and tells the sweep whether the account is recoverable", () => {
    expect(block("  const localKeyFor")).toContain("writeKeyFor(container) ?? (waitingRef.current && { key: waitingRef.current, generation: WAITING_GENERATION })");
    // Read at submit time, not captured at render (M3).
    expect(main).toContain("resealWaitingEdits(currentKeys.authSecret, newKeys.authSecret, waiting())");
    expect(main).toContain("waiting={() => waitingRef.current}");
    expect(block("  async function syncKeys(")).toContain("recoverable: recoverable(liveRef.current)");
    expect(main).toContain("canWrap: false, recoverable: false }"); // the list's read-only pass never mints
    expect(main.match(/waitingRef\.current\)/g)?.length).toBeGreaterThanOrEqual(3); // localReadKeysFor, readyToSend, attachmentStep
    expect(main).toContain("waitingRef.current = identityRef.current && waitingKey(identityRef.current);");
    expect(main).toMatch(/knownNames\[entry\.id\] \?\? teamNames\[entry\.id\]/); // AdminTeams reads the live prop, not a stale closure
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
    expect(main).toContain("{!auth.sso && identityState === \"create\" && <div className=\"conflict-banner\" role=\"status\">{ADMIN_PASSWORD_FIRST}");
  });

  it("asks for the password-change acknowledgement only while login-key items remain", () => {
    expect(main).toContain("passwordChangeProblem(next, confirmation, acknowledged, atRisk)");
    expect(main).toContain("atRisk={legacyAtRisk(items, floorOf)}");
    expect(main).toContain("{warning && <p className=\"config-muted\" role=\"alert\">{warning}</p>}");
    expect(main).toContain("<button disabled={busy || (atRisk > 0 && !acknowledged)}>");
    expect(main).toContain("<p className=\"config-muted\">{PASSWORD_CHANGE_NOTE}</p>");
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

