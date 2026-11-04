import { useEffect, useState } from "react";
import { listShareLinks, revokeShareLink, type ShareLinkSummary } from "../api";

/**
 * This account's live encrypted share links. The server holds only their ciphertext and never the key,
 * so a row cannot say which page it shares: it shows when the link was made, when it expires and its
 * size. Revoking stops the link working at once, for everyone who has it.
 */
export function ShareLinks() {
  const [links, setLinks] = useState<ShareLinkSummary[] | undefined>();
  const [error, setError] = useState("");
  const load = () => listShareLinks().then((list) => { setLinks(list); setError(""); }, () => setError("Unable to load your share links."));
  useEffect(() => { void load(); }, []);
  async function revoke(link: ShareLinkSummary) {
    if (!confirm(`Revoke the share link made ${when(link.createdAt)}? Anyone who has it can no longer open it. This cannot be undone.`)) return;
    try {
      await revokeShareLink(link.id);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Unable to revoke the link.");
    }
    await load();
  }
  return (
    <section id="share-links" className="config-card">
      <h2>Share links</h2>
      <p className="config-muted">Links you made with Share. Each holds an encrypted copy of the page as it was then, counts toward your storage and stops working when it expires (30 days at most). The server cannot read them, so they are listed by date.</p>
      {error && <p className="error" role="alert">{error}</p>}
      {links?.length === 0 && <p className="config-muted">You have no live share links.</p>}
      {links?.map((link) => (
        <div className="pin-row" key={link.id}>
          <span>Made {when(link.createdAt)}, expires {when(link.expiresAt)} ({Math.max(1, Math.round(link.bytes / 1024))} KB)</span>
          <button type="button" className="secondary danger" onClick={() => void revoke(link)}>Revoke</button>
        </div>
      ))}
    </section>
  );
}

const when = (iso: string) => new Date(iso).toLocaleString();
