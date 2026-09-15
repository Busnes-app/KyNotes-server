import { session } from "../api";
import { useEffect, useState } from "react";
import { backupAction, backupStatus, downloadCapsule, runBackup, runDrill, runMirror, type BackupStatus } from "../backup";
import { isStepUpRequired, stepUpWithPassword } from "../stepup";

export function AdminBackup({ username }: { username: string }) {
  const [sso, setSSO] = useState<boolean | null>(null);
  useEffect(() => { void session().then(value => setSSO(value.sso === true)).catch(() => setSSO(null)); }, []);
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [password, setPassword] = useState("");
  const [minutes, setMinutes] = useState("1440");
  const [remoteURL, setRemoteURL] = useState("https://kyrecovery.urlxl.us");
  const [code, setCode] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [threshold, setThreshold] = useState("2");
  const [total, setTotal] = useState("3");
  async function refresh() { const next = await backupStatus(); setStatus(next); setMinutes(String(next.intervalSeconds / 60)); }
  useEffect(() => { void refresh().catch(error => setMessage(error instanceof Error ? error.message : "Backup status unavailable")); }, []);
  async function act(operation: () => Promise<string | void>) {
    setBusy(true); setMessage("");
    try { const result = await operation(); await refresh(); setMessage(result ?? "Backup settings updated."); }
    catch (error) { setMessage(isStepUpRequired(error) ? "Confirm your password below, then repeat the action." : error instanceof Error ? error.message : "Backup action failed"); }
    finally { setBusy(false); }
  }
  return <section id="backups" className="config-card">
    <h2>Backups and recovery</h2>
    <p>Sealed capsules carry the database, deployment secrets, recovery public key, configuration and blob inventory. Note and attachment ciphertext blobs require a separate mirror; a capsule alone cannot restore that content.</p>
    {status && <>
      <div className="backup-facts">
        <div><h3>Recovery key</h3><p className="backup-key">{status.keyID || "No key pinned"}</p>{status.keyError && <p role="alert">Pinned key is missing or invalid.</p>}</div>
        <div><h3>KyRecovery</h3><p>{status.paired ? status.remoteURL : "Not paired"}</p>{status.receipt && <><p>Receipt: {status.receipt.id}</p><p>{status.receipt.at}</p><details><summary>Receipt digest</summary><p className="backup-key">{status.receipt.digest}</p></details></>}</div>
        <div><h3>Local copies</h3><p>{status.localDirectory || "No local directory configured"}</p><p>{status.localCopies} retained</p>{status.localError && <p role="alert">Local directory unavailable.</p>}</div>
        <div><h3>Ciphertext blobs</h3><p>{status.mirror.configured ? status.mirror.target : "No mirror configured"}</p><p>{status.mirror.configured ? `${status.mirror.pending} awaiting upload` : "Configure KYNOTES_BLOB_TARGET to protect note and attachment content."}</p>{status.mirror.last && <p>Last mirror: {status.mirror.last.uploaded} uploaded, {status.mirror.last.skipped} already recorded, {status.mirror.last.failed} failed ({status.mirror.last.missing} missing).</p>}</div>
        <div><h3>Schedule</h3><p>{status.intervalSeconds ? `Every ${status.intervalSeconds / 60} minutes` : "Off"}</p><p>Next: {status.nextRun ? new Date(status.nextRun).toLocaleString() : "Not scheduled"}</p><p>Last attempt: {status.lastAttempt || "None"} {status.lastResult}</p></div>
      </div>
      {!status.keyID && <p role="status">Pair with KyRecovery or pin the suite public key by hand to enable backups.</p>}
      {status.keyID && !status.paired && !status.localDirectory && <p role="status">The key is pinned, but there is no destination. Pair KyRecovery or configure KYNOTES_BACKUP_DIR.</p>}
      {!status.intervalSeconds && <p role="status">Automatic backups are off.</p>}
      <p>{status.blobCount} ciphertext blobs ({status.blobBytes.toLocaleString()} bytes) are excluded from capsules.</p>
    </>}
    <div className="backup-actions">
      <button disabled={busy} onClick={() => void act(runBackup)}>Back up now</button>
      <button disabled={busy} onClick={() => void act(downloadCapsule)}>Download capsule</button>
      <button disabled={busy || !status?.mirror.configured} onClick={() => void act(runMirror)}>Mirror now</button>
      <button disabled={busy} onClick={() => void act(runDrill)}>Run drill</button>
      <button disabled={busy} onClick={() => void act(refresh)}>Refresh status</button>
    </div>
    <p aria-live="polite">{busy ? "Working…" : message}</p>
    {sso === true && <p>Backup changes require confirmation with KySignOn for each action.</p>}
    {sso === false && <form onSubmit={event => { event.preventDefault(); const entered = password; setPassword(""); void act(async () => { await stepUpWithPassword(username, entered); return "Password confirmed for ten minutes."; }); }}>
      <label>Confirm your password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
      <button disabled={busy}>Authorize backup changes</button>
    </form>}
    <form onSubmit={event => { event.preventDefault(); void act(async () => { await backupAction("schedule", { interval_seconds: Number(minutes) * 60 }); }); }}>
      <label>Backup interval in minutes (0 turns it off; otherwise at least 15)<input type="number" min="0" max="527040" step="1" value={minutes} onChange={event => setMinutes(event.target.value)} required /></label>
      <button disabled={busy}>Save schedule</button>
    </form>
    <details><summary>Pair with KyRecovery</summary>
      <p>Generate a six-digit pairing code in KyRecovery. Compare the suite key fingerprint out of band, or pin it below before pairing. HTTPS protects the incoming key, token and receipt.</p>
      <form onSubmit={event => { event.preventDefault(); const pairingCode = code; setCode(""); void act(async () => { await backupAction("pair-remote", { url: remoteURL, pairing_code: pairingCode }); }); }}>
        <label>KyRecovery HTTPS URL<input type="url" value={remoteURL} onChange={event => setRemoteURL(event.target.value)} required /></label>
        <label>Six-digit pairing code<input inputMode="numeric" pattern="[0-9]{6}" maxLength={6} value={code} onChange={event => setCode(event.target.value)} required /></label>
        <button disabled={busy}>Pair KyRecovery</button>
      </form>
      <p>Private recovery destinations are {status?.allowPrivate ? "enabled" : "disabled"}. For a LAN host, configure KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY and the documented DNS override.</p>
      <p>Unpair removes this server’s URL and token rows. The key, receipts and local copies remain. A KyRecovery administrator must separately revoke the credential.</p>
      <button disabled={busy || !status?.paired} onClick={() => void act(async () => { await backupAction("unpair"); })}>Unpair</button>
    </details>
    <details><summary>Pin the suite public key by hand</summary>
      <form onSubmit={event => { event.preventDefault(); void act(async () => { await backupAction("pin-key", { public_key: publicKey, threshold: Number(threshold), total_shares: Number(total) }); }); }}>
        <label>Public key (base64)<textarea value={publicKey} onChange={event => setPublicKey(event.target.value)} required /></label>
        <label>Required custodian cards<input type="number" min="2" max="255" value={threshold} onChange={event => setThreshold(event.target.value)} required /></label>
        <label>Total cards<input type="number" min="2" max="255" value={total} onChange={event => setTotal(event.target.value)} required /></label>
        <p>Only paste the public key. Custodian shares are entered locally during restore. A different pinned key is refused.</p>
        <button disabled={busy}>Pin public key</button>
      </form>
    </details>
  </section>;
}
