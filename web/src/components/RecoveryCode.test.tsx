import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { OTHER_COPY } from "../linkFlow";
import { newRecoveryCode, RECOVERY_TYPO } from "../recovery";
import { CodeShown, IdentityReset, normalizeCodeInput, RECOVERY_LAST, RECOVERY_REPLACED, recoveryFileText, RecoveryRestore, restoreAfterStepUp, resetConfirmed, RESET_CONFIRM, TypeBack } from "./RecoveryCode";

const sources = import.meta.glob<string>(["../**/*.ts", "../**/*.tsx", "!../**/*.test.ts", "!../**/*.test.tsx"], { query: "?raw", import: "default", eager: true });
const component = sources["./RecoveryCode.tsx"];
/** Static markup, unescaped and with attribute names lower-cased (React versions differ). */
const render = (node: Parameters<typeof renderToStaticMarkup>[0]) => renderToStaticMarkup(node).replace(/&#x27;/g, "'").replace(/ ([a-zA-Z-]+)=/g, (_, name: string) => ` ${name.toLowerCase()}=`);
const code = "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345";
const store = { load: async () => undefined, save: async () => false };
/** The password-manager and browser autofill opt-outs every code field carries. */
const NO_FILL = ['autocomplete="off"', 'spellcheck="false"', 'autocapitalize="characters"', 'data-1p-ignore="true"', 'data-lpignore="true"', 'data-bwignore="true"', 'data-form-type="other"'];

describe("recovery code UI", () => {
  it("only RecoveryCode.tsx lets a code be uploaded", () => {
    const callers = Object.entries(sources).filter(([, source]) => /\bconfirmRecoverySaved\(/.test(source)).map(([file]) => file).sort();
    expect(callers).toEqual(["../recovery.ts", "./RecoveryCode.tsx"]);
  });

  it("shows the code once, in groups, with print and download, and says it is the only way back", () => {
    const html = render(<CodeShown code={code} onNext={() => undefined} />);
    expect(html).toContain(code);
    expect(html).toContain('class="recovery-code"');
    expect(html).toMatch(/shows it once/);
    expect(html).toContain(RECOVERY_LAST);
    expect(RECOVERY_LAST).toMatch(/only way back/);
    expect(html).toContain("Print");
    expect(html).toContain("Download as a text file");
    expect(recoveryFileText(code)).toContain(code);
  });

  it("never puts the code on the clipboard, in storage, in the URL or in a log", () => {
    expect(component).toBeDefined();
    expect(component).not.toMatch(/clipboard|localStorage|sessionStorage|indexedDB|history\.|location\.|console\.|searchParams|putNote|queueSave/);
  });

  it("drops the code and an unused reset key when the card unmounts", () => {
    // Cleanup returned from an effect: the prepared code is cleared, and a reset's new key zeroed unless used.
    expect(component).toContain("useEffect(() => () => { forget(); }, []);");
    expect(component).toContain("useEffect(() => () => { dropKeys(); }, []);"); // the reset's password-derived keys
    expect(component).toMatch(/identity\.privateKey\.fill\(0\)/);
  });

  it("asks for a random group with every autofill opt-out, and the restore field too", () => {
    const prepared = { code, check: 3, identity: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) }, userID: "usr_x", wrappedKey: "" };
    const typeBack = render(<TypeBack prepared={prepared} onBack={() => undefined} onConfirmed={async () => undefined} />);
    expect(typeBack).toContain("Type group 3 of 7");
    expect(typeBack).not.toContain(code); // hidden while asked
    const restore = render(<RecoveryRestore userID="usr_x" sso={false} store={store} stepUp={async () => undefined} onRestored={() => undefined} />);
    for (const html of [typeBack, restore]) for (const attribute of NO_FILL) expect(html).toContain(attribute);
  });

  it("normalises what is typed into groups", () => {
    expect(normalizeCodeInput(" abcd efgh-jkmn ")).toBe("ABCD-EFGH-JKMN");
    expect(normalizeCodeInput("abcdefghjkmnpqrstvwxyz012345")).toBe(code);
  });

  it("checks the code's form before any step-up, and explains a browser holding another key", async () => {
    const stepUp = vi.fn(async () => undefined);
    expect(await restoreAfterStepUp(stepUp, "ABCD", async () => { throw new Error("no request"); })).toBe(RECOVERY_TYPO);
    expect(stepUp).not.toHaveBeenCalled();
    const valid = newRecoveryCode().code.toLowerCase();
    expect(await restoreAfterStepUp(stepUp, valid, async () => { throw new Error(OTHER_COPY); })).toMatch(/Use Forget this device first/);
    const restore = vi.fn(async (step: () => Promise<void>) => { await step(); });
    expect(await restoreAfterStepUp(stepUp, valid, restore)).toBeUndefined();
    expect(stepUp).toHaveBeenCalledOnce();
  });

  it("resets only after RESET is typed, names every loss, and offers to export waiting edits first", () => {
    expect(RESET_CONFIRM).toMatch(/personal notebooks become unreadable for good/);
    expect(RESET_CONFIRM).toMatch(/no other owner or admin/);
    expect(RESET_CONFIRM).toMatch(/unsent edits/i);
    expect(RECOVERY_REPLACED).toMatch(/older server backups/);
    expect(resetConfirmed("RESET")).toBe(true);
    for (const typed of ["reset", "RESETX", "", null]) expect(resetConfirmed(typed)).toBe(false);
    const html = render(<IdentityReset userID="usr_x" store={store} live={undefined} held={false} stepUp={async () => undefined} exportWaiting={async () => 0} onReset={() => undefined} startOpen />);
    expect(html).toContain(RESET_CONFIRM);
    expect(html).toContain("Export unsent edits first");
  });

  it("asks a password session for its password, and derives the new password copy from it", () => {
    const html = render(<IdentityReset userID="usr_x" store={store} live={undefined} held={false} stepUp={async () => undefined} exportWaiting={async () => 0} onReset={() => undefined} password={{ derive: async () => ({ authSecret: "", userKEK: new Uint8Array(32) }), stepUp: async () => undefined }} startOpen />);
    expect(html).toContain('type="password"');
    expect(html).toContain('autocomplete="current-password"');
    // The typed password is turned into keys and handed to resetIdentity, which steps up with them.
    expect(component).toMatch(/resetIdentity\(recoveryAPI, store, prepared!, live\?\.deviceId \?\? "", RESET_PHRASE, keys && \{ keys, stepUp: password!\.stepUp \}\)/);
  });
});
