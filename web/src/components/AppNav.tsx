import { useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { suiteApps, type SuiteApp } from "../api";
import { appMark } from "../ky-ui/appmarks";
import { AppMark, NavIcon, type IconName } from "../NavIcon";
import { LicenseFooter, UserBlock } from "./LicenseFooter";

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

/** The ky-ui app rail: the suite apps this account may open, KyNotes marked current. Nothing when there are none. */
export function AppRail({ apps }: { apps: SuiteApp[] }) {
  if (!apps.length) return null;
  return (
    <nav className="ky-app-rail" aria-label="Apps">
      <p className="ky-app-rail-label" aria-hidden="true">Apps</p>
      <ul>
        {apps.map((app) => (
          <li key={app.id}>
            <a href={app.url} title={app.name} aria-label={app.name} aria-current={app.id === "kynotes" ? "page" : undefined}><img src={appMark(app.id)} width={24} height={24} alt="" /></a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/**
 * The ky-ui app frame shared by the workspace and the administration console: brand, one
 * navigation, an optional notebook tree, the account footer, then the page. The footer's icon
 * buttons, Settings then Sign out, move to the phone header on phones; the navigation becomes a
 * row of tabs and the licence line closes the page.
 */
export function AppFrame({ label, nav, tree, user, settings, onSignOut, className = "", children }: { label: string; nav: ReactNode; tree?: ReactNode; user: { name: string; role: string }; settings: { href: string; current: boolean }; onSignOut: () => void; className?: string; children: ReactNode }) {
  const [apps, setApps] = useState<SuiteApp[]>([]);
  useEffect(() => {
    let live = true;
    suiteApps().then((res) => { if (live) setApps(res.apps); }).catch(() => undefined);
    return () => { live = false; };
  }, []);
  // ky-ui shows the sidebar copy on desktop and the page-end copy on phones.
  const rail = <AppRail apps={apps} />;
  const actions = <>
    <a className="ky-icon-button" href={settings.href} aria-label="Settings" title="Settings" aria-current={settings.current ? "page" : undefined}><NavIcon name="settings" /></a>
    <button type="button" className="ky-icon-button" aria-label="Sign out" title="Sign out" onClick={onSignOut}><NavIcon name="signout" /></button>
  </>;
  return (
    <div className={`ky-app ${className}`}>
      <header className="ky-sidebar">
        <div className="ky-mobile-head">
          <div className="ky-brand"><AppMark size={28} /><span>KyNotes</span></div>
          <div className="ky-mobile-actions">{actions}</div>
        </div>
        <nav className="ky-nav" aria-label={label}>{nav}</nav>
        {tree}
        <div className="ky-sidebar-foot">{rail}<UserBlock name={user.name} role={user.role} actions={actions} /><LicenseFooter signedIn /></div>
      </header>
      <main className="ky-content">
        {children}
        <LicenseFooter signedIn className="ky-content-foot">{rail}</LicenseFooter>
      </main>
    </div>
  );
}
