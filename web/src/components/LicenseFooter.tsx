import { useEffect, useRef, useState, type ReactNode } from "react";
import { session } from "../api";
import mitLicenseText from "../mit.txt?raw";

/** The About dialog's contents (ky-ui shell); the version pill shows only once the server has named it. */
export function LicenseWindow({ version, onClose }: { version: string; onClose: () => void }) {
  const year = new Date().getFullYear();
  return (
    <>
      <div className="ky-about-head">
        <div>
          <h2 className="ky-about-name">KyNotes {version ? <span className="ky-about-version">v{version}</span> : null}</h2>
          <p className="ky-about-meta">Developed by Busnes.app</p>
          <p className="ky-about-meta">&copy; {year} &middot; Licensed under the MIT License</p>
        </div>
        <button type="button" className="ky-about-close" onClick={onClose}>Close</button>
      </div>
      <textarea className="ky-about-license" readOnly value={mitLicenseText} aria-label="MIT License" />
    </>
  );
}

/** The licence line that opens the About dialog. The version comes from the session, so signed-out pages show none. */
export function LicenseFooter({ signedIn, className = "app-footer", children }: { signedIn: boolean; className?: string; children?: ReactNode }) {
  const [version, setVersion] = useState("");
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open || !signedIn) return;
    let cancelled = false;
    session().then((res) => { if (!cancelled) setVersion(res.version ?? ""); }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [open, signedIn]);
  return (
    <footer className={className}>
      {children}
      <button type="button" className="ky-license-link" onClick={() => { dialogRef.current?.showModal(); setOpen(true); }}>
        &copy; {new Date().getFullYear()} &middot; MIT License
      </button>
      <dialog ref={dialogRef} className="ky-about" aria-label="About KyNotes" onClose={() => setOpen(false)} onClick={(event) => { if (event.target === dialogRef.current) dialogRef.current.close(); }}>
        <LicenseWindow version={signedIn ? version : ""} onClose={() => dialogRef.current?.close()} />
      </dialog>
    </footer>
  );
}

/** The sidebar user block, one row: name over role, then the account's icon buttons. */
export function UserBlock({ name, role, actions }: { name: string; role: string; actions: ReactNode }) {
  return (
    <div className="ky-user">
      <div className="ky-user-copy">
        <p className="ky-user-name">{name}</p>
        <p className="ky-user-role">{role}</p>
      </div>
      <div className="ky-user-actions">{actions}</div>
    </div>
  );
}
