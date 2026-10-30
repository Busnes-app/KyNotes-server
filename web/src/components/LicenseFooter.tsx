import { useEffect, useRef, useState } from "react";
import { session } from "../api";
import mitLicenseText from "../mit.txt?raw";

/** The About window's contents; the version badge shows only once the server has named it. */
export function LicenseWindow({ version, onClose }: { version: string; onClose: () => void }) {
  const year = new Date().getFullYear();
  return (
    <div className="license-window">
      <div className="license-window-header">
        <div className="license-window-title">
          <div className="license-title-main">
            <span className="license-app-name">KyNotes</span>
            {version ? <span className="license-version-badge">v{version}</span> : null}
          </div>
          <p className="license-title-sub">Developed by Busnes.app</p>
          <p className="license-title-sub">&copy; {year} &middot; Licensed under the MIT License</p>
        </div>
        <button type="button" className="secondary" onClick={onClose}>Close</button>
      </div>
      <textarea className="license-text" readOnly value={mitLicenseText} aria-label="MIT License" />
    </div>
  );
}

/** Copyright line that opens the About window. The version comes from the session, so signed-out pages show none. */
export function LicenseFooter({ signedIn }: { signedIn: boolean }) {
  const [open, setOpen] = useState(false);
  const [version, setVersion] = useState("");
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    else if (!open && dialog.open) dialog.close();
  }, [open]);
  useEffect(() => {
    if (!open || !signedIn) return;
    let cancelled = false;
    session().then((res) => { if (!cancelled) setVersion(res.version ?? ""); }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [open, signedIn]);
  const close = () => setOpen(false);
  return (
    <div className="sidebar-footer">
      <p>
        <button type="button" className="license-link" onClick={() => setOpen(true)}>
          &copy; {new Date().getFullYear()} &middot; MIT License
        </button>
      </p>
      <dialog ref={dialogRef} className="license-backdrop" onClose={close} onClick={(event) => { if (event.target === dialogRef.current) close(); }}>
        <LicenseWindow version={signedIn ? version : ""} onClose={close} />
      </dialog>
    </div>
  );
}
