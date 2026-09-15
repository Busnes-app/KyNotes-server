import { useEffect, useState } from "react";
import { session } from "../api";
import { stepUpWithPassword } from "../stepup";

/** Password re-proof for local sessions; SSO sessions confirm each action with KySignOn instead. */
export function ConfirmPassword({ username, what }: { username: string; what: string }) {
  const [sso, setSSO] = useState<boolean | null>(null);
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { void session().then(value => setSSO(value.sso === true)).catch(() => setSSO(null)); }, []);
  if (sso === true) return <p>{what} require confirmation with KySignOn for each action.</p>;
  if (sso !== false) return null;
  return <form onSubmit={event => {
    event.preventDefault();
    const entered = password; setPassword(""); setBusy(true); setMessage("");
    void stepUpWithPassword(username, entered)
      .then(() => setMessage("Password confirmed for ten minutes."))
      .catch(error => setMessage(error instanceof Error ? error.message : "Password not confirmed"))
      .finally(() => setBusy(false));
  }}>
    <label>Confirm your password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
    <button disabled={busy}>Authorize {what.toLowerCase()}</button>
    <p aria-live="polite">{message}</p>
  </form>;
}
