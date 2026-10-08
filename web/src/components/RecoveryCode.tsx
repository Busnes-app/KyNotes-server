import { useEffect, useRef, useState } from "react";
import { recoveryAPI } from "../api";
import type { LoginKeys } from "../crypto";
import { downloadFile } from "../download";
import type { HeldIdentity, IdentityStore, PublicIdentity } from "../identity";
import { confirmRecoverySaved, parseRecoveryCode, prepareRecovery, recheck, recoveryRefusal, recoveryTypeBack, RESET_CONFIRM, RESET_PHRASE, resetConfirmed, resetIdentity, restoreIdentity, saveRecovery, type PreparedRecovery } from "../recovery";
import { generateIdentity } from "../teamKeys";

export { RESET_CONFIRM, resetConfirmed };

export const RECOVERY_MISSING = "Save a recovery code so you can get your encryption key back if you lose this browser.";
export const RECOVERY_INTRO = "A recovery code gets your encryption key back on a new browser when no other browser holds it. KyNotes shows it once and cannot show it again. The server keeps only a copy of your key locked with the code, which it cannot open.";
export const RECOVERY_KEEP = "Write this code down or store it in a password manager. Anyone who has it and can sign in as you can read your notebooks.";
export const RECOVERY_LAST = "If every browser that holds your key is lost, this code is the only way back to your notebooks.";
export const RECOVERY_SAVED = "Recovery code saved. Keep it somewhere safe.";
export const RECOVERY_REPLACED = "New recovery code saved. Your previous code no longer works here, but older server backups still hold a copy it opens: if it may have leaked, reset your encryption key instead.";
export const RECOVERY_RESTORE = "No other browser holds your key? Enter your recovery code.";
export const RECOVERY_RESTORED = "Restored. This browser now holds your encryption key.";
export const RESET_HELD = "This browser holds your encryption key, so you do not need a reset to get it back: save a recovery code instead. Reset only if a browser that holds your key was lost or stolen.";
export const RESET_NOT_HELD = "Only if no browser holds your key and you have no recovery code. Your personal notebooks are lost.";
export const RESET_DONE = "Your encryption key was reset. Team owners share their notebooks' keys with you again when they next open them.";
export const RESET_UNKEPT = "Your encryption key was reset, but this browser could not keep it (site storage is blocked). Restore it with your new recovery code in a browser that allows site storage.";
export const RESET_WRONG_PASSWORD = "That password is not right. Nothing was reset.";
export const RESET_RETRY = "The reset did not go through. Keep the code you saved: trying again sends the same new key.";
export const TYPE_BACK_WRONG = "That group does not match. Check your saved copy, or go back to see the code again.";
export const stepUpPrompt = (sso: boolean) => sso ? "Confirm it is you in the KySignOn window that opens." : "Confirming it is you…";

/** Code fields: no autofill, no form history, no password-manager capture, no spelling help. */
const NO_FILL = { autoComplete: "off", spellCheck: false, autoCapitalize: "characters", autoCorrect: "off", "data-1p-ignore": "true", "data-lpignore": "true", "data-bwignore": "true", "data-form-type": "other" } as const;

/** What is typed, upper-cased and in groups of four; parseRecoveryCode does the real folding (I, L, O). */
export const normalizeCodeInput = (value: string) => value.normalize("NFKC").toUpperCase().replace(/[^0-9A-Z]/g, "").slice(0, 28).match(/.{1,4}/g)?.join("-") ?? "";

export const recoveryFileText = (code: string) => `KyNotes recovery code\n\n${code}\n\n${RECOVERY_KEEP}\n${RECOVERY_LAST}\n`;

/** Prints only the code sheet (styles.css .print-recovery), on the user's click. */
function printCode() {
  document.body.classList.add("print-recovery");
  try { window.print(); } finally { document.body.classList.remove("print-recovery"); }
}

/** The code's form is checked before any step-up or request; returns the message to show, or undefined once restored. */
export async function restoreAfterStepUp(stepUp: () => Promise<void>, code: string, restore: (stepUp: () => Promise<void>) => Promise<unknown>): Promise<string | undefined> {
  try { parseRecoveryCode(code).fill(0); } catch (error) { return (error as Error).message; }
  try {
    await restore(stepUp);
    return undefined;
  } catch (error) {
    return recoveryRefusal(error, "restore your key").message;
  }
}

/**
 * The reset's password, checked by a step-up before any code is shown (M1): its keys, or the message to
 * show. A wrong password's userKEK is zeroed at once.
 */
export async function checkedPasswordKeys(password: { derive: (password: string) => Promise<LoginKeys>; stepUp: (authSecret: string) => Promise<unknown> }, typed: string): Promise<LoginKeys | string> {
  const keys = await password.derive(typed);
  try {
    await password.stepUp(keys.authSecret);
    return keys;
  } catch (error) {
    keys.userKEK.fill(0);
    return (error as { code?: string }).code === "unauthenticated" ? RESET_WRONG_PASSWORD : recoveryRefusal(error, "reset your encryption key").message;
  }
}

/**
 * Holds a prepared code only while its card is mounted. Dropping it (unmount, cancel, failure) forgets the
 * code; zeroNew: it carries a new identity (reset) whose private key is zeroed unless the reset used it.
 */
function usePrepared(zeroNew: boolean) {
  const [prepared, setPrepared] = useState<PreparedRecovery>();
  const current = useRef<PreparedRecovery | undefined>(undefined);
  const forget = (used = false) => {
    if (zeroNew && !used) current.current?.identity.privateKey.fill(0);
    current.current = undefined;
    setPrepared(undefined);
  };
  const hold = (next: PreparedRecovery) => { forget(); current.current = next; setPrepared(next); };
  /** "Show the code again": the same code and key, asked back by a new group (recheck); nothing is zeroed. */
  const showAgain = () => { if (!current.current) return; current.current = recheck(current.current); setPrepared(current.current); };
  useEffect(() => () => { forget(); }, []);
  return { prepared, hold, forget, showAgain };
}

/** The code, once: selectable as a whole, printable or downloadable on a click, never copied or stored. */
export function CodeShown({ code, onNext }: { code: string; onNext: () => void }) {
  return (
    <div className="recovery-step recovery-sheet">
      <p className="config-muted">{RECOVERY_INTRO}</p>
      <code className="recovery-code" aria-label="Recovery code">{code}</code>
      <p className="config-muted">{RECOVERY_KEEP} KyNotes shows it once.</p>
      <p role="note"><strong>{RECOVERY_LAST}</strong></p>
      <div className="recovery-actions">
        <button type="button" className="quiet" onClick={printCode}>Print</button>
        <button type="button" className="quiet" onClick={() => downloadFile("kynotes-recovery-code.txt", recoveryFileText(code), "text/plain")}>Download as a text file</button>
        <button type="button" onClick={onNext}>I saved it</button>
      </div>
    </div>
  );
}

/** Hides the code and asks for one random group from the user's copy; only then may it be uploaded. */
export function TypeBack({ prepared, onBack, onConfirmed }: { prepared: PreparedRecovery; onBack: () => void; onConfirmed: () => Promise<void> }) {
  const [typed, setTyped] = useState("");
  const [problem, setProblem] = useState("");
  return (
    <form className="recovery-step" onSubmit={(event) => {
      event.preventDefault();
      if (!confirmRecoverySaved(prepared, typed)) { setProblem(TYPE_BACK_WRONG); return; }
      void onConfirmed();
    }}>
      <label className="field"><span>{recoveryTypeBack(prepared.check)}</span>
        <input name="recovery-group" value={typed} onChange={(event) => setTyped(event.target.value.toUpperCase())} maxLength={8} {...NO_FILL} />
      </label>
      {problem && <p role="alert">{problem}</p>}
      <button type="button" className="quiet" onClick={onBack}>Show the code again</button>
      <button>Save recovery code</button>
    </form>
  );
}

/** Create or replace the account's recovery code (held identity required). */
export function RecoverySetup({ userID, held, live, sso, stepUp, autoStart = false, onSaved }: { userID: string; held: () => Promise<HeldIdentity | undefined>; live: PublicIdentity | null | undefined; sso: boolean; stepUp: () => Promise<void>; autoStart?: boolean; onSaved: () => void }) {
  const { prepared, hold, forget, showAgain } = usePrepared(false);
  const [hidden, setHidden] = useState(false);
  const [status, setStatus] = useState("");
  async function start() {
    setStatus("");
    const identity = await held();
    if (!identity) { setStatus("This browser does not hold your encryption key."); return; }
    hold(await prepareRecovery(identity, userID));
    setHidden(false);
  }
  // Right after an SSO key set-up (§8 item 1: the first browser shows the code).
  useEffect(() => { if (autoStart) void start(); }, [autoStart]);
  async function save() {
    try {
      const identity = await held();
      if (!identity) throw new Error("This browser does not hold your encryption key.");
      setStatus(stepUpPrompt(sso));
      await stepUp();
      await saveRecovery(recoveryAPI, prepared!, identity, live?.recoveryId ?? "");
      setStatus(live?.recoveryId ? RECOVERY_REPLACED : RECOVERY_SAVED);
      forget();
      onSaved();
    } catch (error) {
      // A lost race (RECOVERY_MOVED) spent this code; any other failure keeps it, so a retry re-sends the same bytes.
      setStatus(recoveryRefusal(error, "save a recovery code").message);
      if ((error as { code?: string }).code === "already_exists") forget();
    }
  }
  return (
    <section id="recovery" className="config-card">
      <h2>Recovery code</h2>
      <p className="config-muted">{live?.recoveryId ? `You saved a recovery code on ${new Date(live.recoverySetAt ?? "").toLocaleDateString()}.` : RECOVERY_MISSING}</p>
      {!prepared && <button onClick={() => void start()}>{live?.recoveryId ? "Replace recovery code" : "Create recovery code"}</button>}
      {prepared && !hidden && <CodeShown code={prepared.code} onNext={() => setHidden(true)} />}
      {prepared && hidden && <TypeBack prepared={prepared} onBack={() => { showAgain(); setHidden(false); }} onConfirmed={save} />}
      {status && <p role="status">{status}</p>}
    </section>
  );
}

/** On a browser without the key, beside "Link this browser": restore it from the server's copy and the typed code. */
export function RecoveryRestore({ userID, sso, store, stepUp, onRestored }: { userID: string; sso: boolean; store: IdentityStore; stepUp: () => Promise<void>; onRestored: (identity: HeldIdentity) => void }) {
  const [code, setCode] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <form id="recovery-restore" className="config-card" onSubmit={(event) => {
      event.preventDefault();
      setBusy(true);
      setStatus("Checking…");
      void (async () => {
        let restored: HeldIdentity | undefined;
        const problem = await restoreAfterStepUp(stepUp, code, async (step) => {
          restored = await restoreIdentity(recoveryAPI, store, userID, code, async () => { setStatus(stepUpPrompt(sso)); await step(); });
        });
        setBusy(false);
        // On failure the input is kept so a typo can be fixed.
        if (problem) { setStatus(problem); return; }
        setCode("");
        setStatus(RECOVERY_RESTORED);
        onRestored(restored!);
      })();
    }}>
      <h2>Use a recovery code</h2>
      <p className="config-muted">{RECOVERY_RESTORE}</p>
      <label className="field"><span>Recovery code</span>
        <input name="recovery-code" value={code} onChange={(event) => setCode(normalizeCodeInput(event.target.value))} {...NO_FILL} />
      </label>
      <button disabled={busy || !code.trim()}>Restore</button>
      {status && <p role="status">{status}</p>}
    </form>
  );
}

/**
 * Spec §8 item 5: lose everything, explicitly. The dialog names the losses (RESET_CONFIRM), offers to
 * export this browser's unsent edits first, and needs RESET typed; a password session also types its
 * password, from which the new key's password copy and the step-up are derived (resetIdentity). A new key
 * and its recovery code replace the listed key (live.deviceId, compare-and-swap) in one request.
 */
export function IdentityReset({ userID, store, live, held, stepUp, exportWaiting, onReset, password, startOpen = false }: {
  userID: string; store: IdentityStore; live: PublicIdentity | null | undefined; held: boolean; stepUp: () => Promise<void>;
  /** Downloads this browser's unsent edits; returns how many were exported. */
  exportWaiting: () => Promise<number>;
  onReset: () => void;
  password?: { derive: (password: string) => Promise<LoginKeys>; stepUp: (authSecret: string) => Promise<unknown> };
  startOpen?: boolean;
}) {
  const { prepared, hold, forget, showAgain } = usePrepared(true);
  // A failed reset keeps the new key and code (it may have committed): the user retries with the same key.
  const [failed, setFailed] = useState(false);
  const [open, setOpen] = useState(startOpen);
  const [phrase, setPhrase] = useState("");
  const [typedPassword, setTypedPassword] = useState("");
  const [hidden, setHidden] = useState(false);
  const [status, setStatus] = useState("");
  const keysRef = useRef<LoginKeys | undefined>(undefined);
  const dropKeys = () => { keysRef.current?.userKEK.fill(0); keysRef.current = undefined; };
  useEffect(() => () => { dropKeys(); }, []);
  function cancel() { forget(); dropKeys(); setFailed(false); setOpen(false); setPhrase(""); setTypedPassword(""); }
  async function exportFirst() {
    try {
      const count = await exportWaiting();
      setStatus(count ? `Exported ${count} unsent edit${count === 1 ? "" : "s"}.` : "This browser has no unsent edits to export.");
    } catch {
      setStatus("Could not export the unsent edits.");
    }
  }
  async function begin() {
    if (!resetConfirmed(phrase)) return;
    setStatus("");
    try {
      if (password) {
        dropKeys();
        const checked = await checkedPasswordKeys(password, typedPassword);
        setTypedPassword("");
        if (typeof checked === "string") { setStatus(checked); return; }
        keysRef.current = checked;
      }
      hold(await prepareRecovery(generateIdentity(), userID));
      setHidden(false);
    } catch (error) {
      setStatus(recoveryRefusal(error, "reset your encryption key").message);
    }
  }
  async function finish() {
    const keys = keysRef.current;
    try {
      setStatus(stepUpPrompt(!password));
      if (!keys) await stepUp();
      const { kept } = await resetIdentity(recoveryAPI, store, prepared!, live?.deviceId ?? "", RESET_PHRASE, keys && { keys, stepUp: password!.stepUp });
      setStatus(kept ? RESET_DONE : RESET_UNKEPT);
      setFailed(false);
      forget(true);
      dropKeys();
      setOpen(false);
      onReset();
    } catch (error) {
      // Never discarded here: the server may have taken it (ResetUncertainError), and a retry needs the same key.
      const message = recoveryRefusal(error, "reset your encryption key").message;
      setStatus(error instanceof Error && error.name === "ResetUncertainError" ? message : `${message} ${RESET_RETRY}`);
      setFailed(true);
    }
  }
  return (
    <section id="identity-reset" className="config-card">
      <h2>Reset encryption key</h2>
      <p className="config-muted">{held ? RESET_HELD : RESET_NOT_HELD}</p>
      {!open && <button className="secondary danger" onClick={() => setOpen(true)}>Reset encryption key…</button>}
      {open && !prepared && (
        <form className="recovery-step" onSubmit={(event) => { event.preventDefault(); void begin(); }}>
          <p role="alert">{RESET_CONFIRM}</p>
          <button type="button" className="quiet" onClick={() => void exportFirst()}>Export unsent edits first</button>
          <label className="field"><span>Type {RESET_PHRASE} to confirm</span>
            <input name="reset-phrase" value={phrase} onChange={(event) => setPhrase(event.target.value)} {...NO_FILL} />
          </label>
          {password && (
            <label className="field"><span>Your password</span>
              <input name="reset-password" type="password" autoComplete="current-password" value={typedPassword} onChange={(event) => setTypedPassword(event.target.value)} />
            </label>
          )}
          <button type="button" className="quiet" onClick={cancel}>Cancel</button>
          <button className="secondary danger" disabled={!resetConfirmed(phrase) || (Boolean(password) && !typedPassword)}>Continue</button>
        </form>
      )}
      {prepared && !hidden && <CodeShown code={prepared.code} onNext={() => setHidden(true)} />}
      {prepared && hidden && !failed && <TypeBack prepared={prepared} onBack={() => { showAgain(); setHidden(false); }} onConfirmed={finish} />}
      {prepared && failed && (
        <div className="recovery-actions">
          <button className="secondary danger" onClick={() => void finish()}>Try the reset again</button>
          <button className="quiet" onClick={cancel}>Cancel</button>
        </div>
      )}
      {status && <p role="status">{status}</p>}
    </section>
  );
}
