import { useSyncExternalStore, type ReactNode } from "react";
import { AppMark, NavIcon, type IconName } from "../NavIcon";
import { LicenseFooter } from "./LicenseFooter";

const PHONE = "(max-width: 720px)";
const watchPhone = (change: () => void) => {
  const query = matchMedia(PHONE);
  query.addEventListener("change", change);
  return () => query.removeEventListener("change", change);
};
/** Whether the ky-ui phone layout (720px and narrower) is showing. */
export function usePhone() {
  return useSyncExternalStore(watchPhone, () => matchMedia(PHONE).matches);
}

/** One destination row. Only the current destination carries the shared accent (aria-current="page"). */
export function NavItem({ icon, label, current, href, disabled, expanded, controls, onClick }: { icon: IconName; label: string; current?: boolean; href?: string; disabled?: boolean; expanded?: boolean; controls?: string; onClick?: () => void }) {
  const body = <><NavIcon name={icon} /><span>{label}</span></>;
  return href
    ? <a className="ky-nav-item" href={href} aria-current={current ? "page" : undefined} onClick={onClick}>{body}</a>
    : <button type="button" className="ky-nav-item" aria-current={current ? "page" : undefined} aria-expanded={expanded} aria-controls={controls} disabled={disabled} onClick={onClick}>{body}</button>;
}

/**
 * The ky-ui app frame shared by the workspace and the administration console: brand, one
 * navigation, an optional notebook tree, the user block, then the page. Phones get the brand with
 * an icon-only Sign out, the navigation as a row of tabs, and the licence line at the page end.
 */
export function AppFrame({ label, nav, tree, foot, onSignOut, className = "", children }: { label: string; nav: ReactNode; tree?: ReactNode; foot: ReactNode; onSignOut: () => void; className?: string; children: ReactNode }) {
  return (
    <div className={`ky-app ${className}`}>
      <header className="ky-sidebar">
        <div className="ky-mobile-head">
          <div className="ky-brand"><AppMark size={28} /><span>KyNotes</span></div>
          <button type="button" className="ky-mobile-signout" aria-label="Sign out" onClick={onSignOut}><NavIcon name="signout" /></button>
        </div>
        <nav className="ky-nav" aria-label={label}>{nav}</nav>
        {tree}
        <div className="ky-sidebar-foot">{foot}</div>
      </header>
      <main className="ky-content">
        {children}
        <LicenseFooter signedIn className="ky-content-foot" />
      </main>
    </div>
  );
}
