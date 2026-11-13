import { useEffect, useState, type FormEvent } from "react";
import { adminExemptNetworks, saveAdminExemptNetworks, type ExemptNetworks } from "../api";
import { withStepUp } from "../stepup";

/** The stored comma-separated list, one network per line. */
export const networkLines = (list: string) => list.split(",").filter(Boolean).join("\n");
/** What the administrator typed (lines, commas or spaces) as the comma-separated list the server takes. */
export const networkList = (text: string) => text.split(/[\s,]+/).filter(Boolean).join(",");

type ViewProps = {
  status: ExemptNetworks | null;
  text: string;
  busy: boolean;
  message: { text: string; error: boolean } | null;
  onText: (text: string) => void;
  onSave: (event: FormEvent) => void;
};

/** Office networks whose sign-ins skip the per-address rate limit. */
export function OfficeNetworksView({ status, text, busy, message, onText, onSave }: ViewProps) {
  return (
    <section className="config-card office-networks" aria-labelledby="office-networks-heading">
      <h2 id="office-networks-heading">Office networks</h2>
      <p className="admin-note">
        Sign-in is limited per network address. Staff in one office usually share one address and can trip that limit together. Networks
        listed here skip it; per-account limits and lockouts still apply.
      </p>
      <form onSubmit={onSave}>
        <label>
          Networks that skip the per-address limit, one per line
          <textarea rows={4} value={text} onChange={(event) => onText(event.target.value)} placeholder="203.0.113.0/24" aria-describedby="office-networks-hint" disabled={!status} spellCheck={false} />
        </label>
        <p id="office-networks-hint" className="admin-note">
          List only networks you control: everyone behind a listed address loses the limit, so never add guest Wi-Fi, a VPN provider or
          your reverse proxy. The widest range accepted is /16 (IPv4) or /48 (IPv6).
        </p>
        <button disabled={busy || !status}>{busy ? "Saving…" : "Save networks"}</button>
      </form>
      {message && <p role={message.error ? "alert" : "status"} className={message.error ? "error" : "status-line"}>{message.text}</p>}
      {status && (
        <dl className="status-list">
          {status.environment && <div><dt>Also set by the server configuration</dt><dd className="backup-key">{status.environment.split(",").join(", ")}</dd></div>}
          <div><dt>Requests that skipped the limit</dt><dd>{status.exempted} since the last change or restart</dd></div>
        </dl>
      )}
    </section>
  );
}

export function OfficeNetworks({ username }: { username: string }) {
  const [status, setStatus] = useState<ExemptNetworks | null>(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);
  const show = (next: ExemptNetworks) => { setStatus(next); setText(networkLines(next.networks)); };
  useEffect(() => {
    adminExemptNetworks().then(show, () => setMessage({ text: "Could not load the networks.", error: true }));
  }, []);
  async function save(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const next = await withStepUp(username, () => saveAdminExemptNetworks(networkList(text)));
      show(next);
      setMessage({ text: next.networks ? "Saved. These networks now skip the per-address limit." : "Saved. No network you listed skips the limit.", error: false });
    } catch (error) {
      // The server's refusal is shown as it was given; what was typed stays for correction.
      if (error instanceof Error && error.message === "Password confirmation cancelled") return;
      setMessage({ text: error instanceof Error ? error.message : "Could not save the networks.", error: true });
    } finally {
      setBusy(false);
    }
  }
  return <OfficeNetworksView status={status} text={text} busy={busy} message={message} onText={setText} onSave={(event) => void save(event)} />;
}
