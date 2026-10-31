import { useEffect, type ReactNode, type Ref } from "react";
import { AppMark, NavIcon, type IconName } from "../NavIcon";

/** One destination row. Only the current destination carries the shared accent (aria-current="page"). */
export function NavItem({ icon, label, current, href, disabled, onClick }: { icon: IconName; label: string; current?: boolean; href?: string; disabled?: boolean; onClick?: () => void }) {
  const body = <><NavIcon name={icon} /><span>{label}</span></>;
  const className = "ky-nav-item nav-item";
  return href
    ? <a className={className} href={href} aria-current={current ? "page" : undefined} onClick={onClick}>{body}</a>
    : <button type="button" className={className} aria-current={current ? "page" : undefined} disabled={disabled} onClick={onClick}>{body}</button>;
}

/**
 * The suite's single left navigation region, shared by the workspace and the administration console.
 * Desktop shows it whole; phones show a Menu button that opens the same panel as a drawer.
 */
export function AppNav({ open, onToggle, toggleRef, onHome, children, foot }: { open: boolean; onToggle: () => void; toggleRef?: Ref<HTMLButtonElement>; onHome: () => void; children: ReactNode; foot: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const close = (event: KeyboardEvent) => { if (event.key === "Escape" && !document.querySelector("dialog[open]")) onToggle(); };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [open, onToggle]);
  return (
    <aside className={`app-nav${open ? " nav-open" : ""}`} aria-label="Navigation">
      <div className="app-nav-bar">
        <button ref={toggleRef} type="button" className="nav-menu-toggle icon-button quiet" aria-label="Menu" aria-expanded={open} aria-controls="app-navigation" onClick={onToggle}><NavIcon name="menu" /></button>
        <button type="button" className="app-nav-brand" onClick={onHome}>
          <AppMark size={28} />
          <span>KyNotes</span>
        </button>
      </div>
      <div id="app-navigation" className="app-nav-panel">
        {children}
        <div className="app-nav-foot">{foot}</div>
      </div>
      {open && <div className="nav-scrim" aria-hidden="true" onClick={onToggle} />}
    </aside>
  );
}
