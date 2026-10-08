import { useEffect, useRef, useState } from "react";
import { APIRequestError, cancelLinkRequest, claimLinkRequest, createLinkRequest, linkRequests, myIdentity, revealLinkRequest, type LinkRequestRow } from "../api";
import type { HeldIdentity, IdentityStore } from "../identity";
import { approveLink, claimLink, confirmTypedCode, endLink, keepClaim, finishNewcomerLink, LinkEndedError, linkRefusal, LinkTamperedError, OTHER_COPY, otherCopyHeld, pollNewcomerLink, revealedLink, startNewcomerLink, type ApproverLink, type NewcomerLink } from "../linkFlow";
import { confirmCheckCode, type CheckCodeConfirmation } from "../linking";
import { collectLinkBundle } from "../outbound";

/** The six characters people match to pick the right request on the trusted browser; identification only. */
export const linkCodeOf = (id: string) => id.slice(-6).toUpperCase();
const POLL_MS = 2000;
const ENDED = "This link request ended: it was cancelled on the other browser or expired. Start again.";
const DIFFERED = "Linking cancelled: the codes differed. Someone may be interfering; start again on both browsers.";
const CANCELLED = "Request cancelled.";
const pause = () => new Promise((resolve) => setTimeout(resolve, POLL_MS));
const ended = (error: unknown) => error instanceof LinkEndedError || (error instanceof APIRequestError && error.code === "not_found");
/** leaving: the page is going away (pagehide), so the cancel is sent keepalive. */
const quietCancel = (id: string, leaving = false) => void cancelLinkRequest(id, leaving).catch(() => undefined);
export type Status = ReturnType<typeof linkRefusal>;

/** A refusal or outcome; an open KySignOn confirmation it names can be cancelled from here. */
export function LinkStatus({ status, set }: { status?: Status; set: (next?: Status) => void }) {
  if (!status) return null;
  const cancel = status.cancel;
  return (
    <p role="status" className="link-status">
      {status.message}
      {cancel && <> <button className="quiet" onClick={() => void cancel().then(() => set(undefined), (error) => set(linkRefusal(error)))}>Cancel the KySignOn confirmation</button></>}
    </p>
  );
}

/** On a browser without the identity: asks a trusted browser of the same account to send it. */
export function LinkThisBrowser({ userID, canKeep, store, onLinked }: { userID: string; canKeep: () => Promise<boolean>; store: IdentityStore; onLinked: (identity: HeldIdentity) => void }) {
  // The poll's view of the attempt, for display (it carries the check code).
  const [link, setLink] = useState<NewcomerLink>();
  const [confirmed, setConfirmed] = useState(false);
  const [status, setStatus] = useState<Status>();
  const generation = useRef(0);
  // attempt: the one NewcomerLink every call of this attempt uses. confirmation: minted only by the "Codes match" click.
  const state = useRef<{ attempt?: NewcomerLink; bundle?: Uint8Array; confirmation?: CheckCodeConfirmation }>({});
  const api = { create: createLinkRequest, collect: collectLinkBundle, reveal: revealLinkRequest, myIdentity };

  /** Ends the attempt here (the one-time key is zeroed) and on the server. Nothing retries: a new attempt is a new click. */
  function stop(message?: string, leaving = false) {
    generation.current += 1;
    const { attempt } = state.current;
    state.current = {};
    setLink(undefined);
    setConfirmed(false);
    setStatus(message ? { message } : undefined);
    if (attempt) {
      endLink(attempt);
      quietCancel(attempt.id, leaving);
    }
  }
  // Leaving the screen, or the page (reload, close), abandons the attempt.
  useEffect(() => {
    const leave = () => stop(undefined, true);
    addEventListener("pagehide", leave);
    return () => { removeEventListener("pagehide", leave); stop(); };
  }, []);

  /** Runs once both the bundle has arrived and this screen's user confirmed the code. */
  async function finish() {
    const { attempt, bundle, confirmation } = state.current;
    if (!attempt || !bundle || !confirmation) return;
    generation.current += 1;
    state.current = {};
    setLink(undefined);
    setConfirmed(false);
    try {
      onLinked(await finishNewcomerLink(attempt, bundle, confirmation, userID, api, store));
    } catch (error) {
      quietCancel(attempt.id);
      setStatus(linkRefusal(error));
    }
  }
  async function begin() {
    stop();
    const mine = generation.current;
    try {
      if (await otherCopyHeld(api, store)) {
        setStatus({ message: OTHER_COPY });
        return;
      }
      const attempt = await startNewcomerLink(api, canKeep, userID);
      if (generation.current !== mine) {
        endLink(attempt);
        quietCancel(attempt.id);
        return;
      }
      state.current.attempt = attempt;
      setLink(attempt);
      while (generation.current === mine) {
        await pause();
        if (generation.current !== mine) return;
        const next = await pollNewcomerLink(api, attempt, userID);
        if (generation.current !== mine) return;
        setLink(next.link);
        if (next.bundle) {
          state.current.bundle = next.bundle;
          await finish();
          return;
        }
      }
    } catch (error) {
      if (generation.current !== mine) return;
      stop();
      setStatus(ended(error) ? { message: ENDED } : linkRefusal(error));
    }
  }
  function codesMatch() {
    if (!link?.code) return;
    state.current.confirmation = confirmCheckCode(link.id, link.code);
    setConfirmed(true);
    void finish();
  }
  return (
    <section id="link-this-browser" className="config-card">
      <h2>Link this browser</h2>
      {!link && (
        <>
          <p className="config-muted">This browser does not hold your encryption key, so it cannot open team notebooks. A browser where you already use KyNotes can send it here; KyNotes only relays it encrypted.</p>
          <button onClick={() => void begin()}>Link this browser</button>
        </>
      )}
      {link && !link.code && (
        <>
          <p>On a browser that holds your key, open Settings → Link another browser and approve request <code className="link-code">{linkCodeOf(link.id)}</code>. Waiting…</p>
          <button className="secondary" onClick={() => stop(CANCELLED)}>Cancel</button>
        </>
      )}
      {link?.code && (
        <>
          <p>Check code: <code className="check-code">{link.code}</code></p>
          <p className="config-muted">Type this code on the other browser. Choose Codes match once it accepts the code; if it does not, choose Codes differ.</p>
          {confirmed ? (
            <>
              <p>Waiting for the other browser to send the key…</p>
              <button className="secondary" onClick={() => stop(CANCELLED)}>Cancel</button>
            </>
          ) : (
            <div className="link-actions">
              <button onClick={codesMatch}>Codes match</button>
              <button className="secondary" onClick={() => stop(DIFFERED)}>Codes differ</button>
            </div>
          )}
        </>
      )}
      <LinkStatus status={status} set={setStatus} />
    </section>
  );
}

/** On a browser that holds the identity: lists the account's link requests and sends the key to one after its user typed the other screen's code. */
export function LinkRequests({ userID, held, stepUp }: { userID: string; held: () => Promise<HeldIdentity | undefined>; stepUp: () => Promise<void> }) {
  const [rows, setRows] = useState<LinkRequestRow[]>([]);
  const [active, setActive] = useState<ApproverLink>();
  // Only ever the input field's value.
  const [typed, setTyped] = useState("");
  const [status, setStatus] = useState<Status>();
  const [busy, setBusy] = useState(false);
  const activeRef = useRef<ApproverLink | undefined>(undefined);
  const sending = useRef(false);
  // One claim at a time, and only while this screen is open.
  const claiming = useRef(false);
  const [claimPending, setClaimPending] = useState(false);
  const mounted = useRef(false);
  const keep = (next?: ApproverLink) => { activeRef.current = next; setActive(next); };

  /** Ends this browser's attempt (one-time key zeroed) and cancels the request on the server. */
  function drop(id: string | undefined, message?: string) {
    const open = activeRef.current;
    if (open) endLink(open);
    keep(undefined);
    setTyped("");
    setStatus(message ? { message } : undefined);
    if (id) quietCancel(id);
  }
  useEffect(() => {
    mounted.current = true;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const next = await linkRequests();
        if (stopped) return;
        setRows(next);
        const open = activeRef.current;
        if (open && !sending.current) {
          const row = next.find((entry) => entry.id === open.id);
          if (!row) {
            endLink(open);
            keep(undefined);
            setTyped("");
            setStatus({ message: ENDED });
          } else if (!open.newcomerKey) keep(revealedLink(open, row, userID));
        }
      } catch (error) {
        if (!stopped) {
          if (error instanceof LinkTamperedError || error instanceof LinkEndedError) drop(activeRef.current?.id, error.message);
          else setStatus(linkRefusal(error));
        }
      }
      if (!stopped) timer = setTimeout(() => void tick(), POLL_MS);
    };
    timer = setTimeout(() => void tick(), 0);
    // Leaving the screen, or the page, abandons the attempt. A send in flight may have stored the
    // bundle: never delete it from under the newcomer (it collects it, or the request expires).
    const abandon = (leaving: boolean) => {
      const open = activeRef.current;
      activeRef.current = undefined;
      if (open) {
        endLink(open);
        if (!sending.current) quietCancel(open.id, leaving);
      }
    };
    const leave = () => { abandon(true); setActive(undefined); setTyped(""); };
    addEventListener("pagehide", leave);
    return () => {
      stopped = true;
      mounted.current = false;
      clearTimeout(timer);
      removeEventListener("pagehide", leave);
      abandon(false);
    };
  }, [userID]);

  async function approve(row: LinkRequestRow) {
    if (claiming.current || activeRef.current) return;
    claiming.current = true;
    setClaimPending(true);
    setStatus(undefined);
    setTyped("");
    try {
      // A claim that resolves after the screen closed (or another attempt opened) is ended and cancelled.
      const link = await keepClaim(claimLink({ claim: claimLinkRequest }, row, userID), () => mounted.current && !activeRef.current, cancelLinkRequest);
      if (link) keep(link);
    } catch (error) {
      if (mounted.current) setStatus(linkRefusal(error));
    } finally {
      claiming.current = false;
      if (mounted.current) setClaimPending(false);
    }
  }
  /** Approve stays disabled until the typed code is the one this attempt expects. */
  function accepted(link: ApproverLink) {
    try { return Boolean(confirmTypedCode(link, typed)); } catch { return false; }
  }
  async function send() {
    const link = activeRef.current;
    if (!link) return;
    setStatus(undefined);
    sending.current = true;
    setBusy(true);
    try {
      const identity = await held();
      if (!identity) {
        drop(link.id, "This browser no longer holds your encryption key.");
        return;
      }
      await approveLink(link, confirmTypedCode(link, typed), identity, userID, stepUp);
      keep(undefined);
      setTyped("");
      setStatus({ message: "Key sent. Finish on the other browser." });
    } catch (error) {
      if (error instanceof LinkTamperedError || error instanceof LinkEndedError || ended(error)) drop(link.id, ended(error) ? ENDED : (error as Error).message);
      else setStatus(linkRefusal(error));
    } finally {
      sending.current = false;
      setBusy(false);
    }
  }
  return (
    <section id="link-devices" className="config-card">
      <h2>Link another browser</h2>
      <p className="config-muted">Approve only a request you started yourself, on a browser in front of you. That browser then shows a check code; type it here to send your key.</p>
      {!active && (rows.length ? rows.map((row) => (
        <div className="pin-row" key={row.id}>
          <span>Request <code className="link-code">{linkCodeOf(row.id)}</code> · started {new Date(row.createdAt).toLocaleTimeString()}</span>
          <button disabled={claimPending} onClick={() => void approve(row)}>Approve…</button>
          <button className="secondary" onClick={() => drop(row.id, CANCELLED)}>Not me</button>
        </div>
      )) : <p className="config-muted">No browser is asking to be linked.</p>)}
      {active && !active.code && (
        <>
          <p>Waiting for request <code className="link-code">{linkCodeOf(active.id)}</code> to answer…</p>
          <button className="secondary" onClick={() => drop(active.id, CANCELLED)}>Cancel</button>
        </>
      )}
      {active?.code && (
        <>
          <label className="field">
            <span>Check code shown on the other browser</span>
            <input className="check-code-input" value={typed} onChange={(event) => setTyped(event.currentTarget.value)} inputMode="numeric" autoComplete="off" spellCheck={false} data-1p-ignore data-lpignore="true" />
          </label>
          <p className="config-muted">Type it from the other browser's screen. If that browser shows no code, or this one does not accept it, choose Codes differ.</p>
          <div className="link-actions">
            <button disabled={busy || !accepted(active)} onClick={() => void send()}>Approve — send key</button>
            <button className="secondary" disabled={busy} onClick={() => drop(active.id, DIFFERED)}>Codes differ</button>
          </div>
        </>
      )}
      <LinkStatus status={status} set={setStatus} />
    </section>
  );
}
