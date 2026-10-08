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
    expect(check).toContain("const autoClose = await mayAutoClose(() => pinStore.loadKeyState(container.id));");
    expect(check).toContain("await checkLegacyRows(() => reviewLegacy(reviewAPI, { container, floorNow, legacy, userId: auth.user.id }), floorNow, () => stopLegacy(container), autoClose);");
    expect(main).not.toMatch(/reopenedRef/);
    expect(check).toMatch(/if \("failed" in check\) \{[^]*failure: checkFailure\(check\.failed\) \}\);\n\s*return;\n\s*\}/);
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
    expect(main).toContain("const rose = before.closed === 0 && closedNow > 0 && unverifiedRef.current.size > 0;");
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
    expect(share).toContain("() => stopLegacy(container));");
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
