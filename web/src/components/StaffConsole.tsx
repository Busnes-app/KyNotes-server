import { useEffect, useState, type ReactNode } from "react";
import { adminSSO, serviceStatus, type SSOSettings } from "../api";
import { staffAudit, staffOrgs, staffUsers, type StaffOrg, type StaffUser } from "../staffAPI";
import { AppFrame, NavItem } from "./AppNav";
import { Appearance } from "./Appearance";
import { AdminBackup } from "./AdminBackup";
import { OfficeNetworks } from "./OfficeNetworks";
import type { IconName } from "../NavIcon";

type Scoped<T> = { scope: string; state: Remote<T> };
type Remote<T> = { kind: "loading" } | { kind: "failed"; message: string } | { kind: "ready"; value: T };
const sections = [
  ["orgs", "Organizations", "team", "Organization status and shared storage-pool metadata."],
  ["users", "Users", "users", "Select an organization to inspect its accounts. KyIdentity manages customer accounts."],
  ["sso", "Single sign-on", "sso", "Shared sign-in configuration is managed by the deployment."],
  ["backups", "Backups", "backups", "Platform recovery configuration and scheduled backups."],
  ["audit", "Audit log", "audit", "Platform events or one organization's metadata-only audit history."],
  ["server", "Server", "server", "Health, readiness and platform office-network settings."],
] as const satisfies ReadonlyArray<readonly [string, string, IconName, string]>;
type Section = (typeof sections)[number][0] | "account" | "appearance";
const bytes = (value: number) => `${value.toLocaleString()} B`;
const failure = (error: unknown) => error instanceof Error ? error.message : "Metadata could not be read. Refresh to try again.";

export function StaffConsole({ username, sso, onLogout, password }: { username: string; sso: boolean; onLogout: () => void; password: ReactNode }) {
  const settings = [...(sso ? [] : [["account", "Account"] as const]), ["appearance", "Appearance"] as const];
  const fromHash = (): Section => [...sections, ...settings].find(([id]) => location.hash === `#${id}`)?.[0] ?? "orgs";
  const [section, setSection] = useState<Section>(fromHash);
  const [refresh, setRefresh] = useState(0);
  const [orgs, setOrgs] = useState<Remote<StaffOrg[]>>({ kind: "loading" });
  const [selectedOrg, setSelectedOrg] = useState("");
  const [auditOrg, setAuditOrg] = useState("");
  const [users, setUsers] = useState<Scoped<StaffUser[]>>({ scope: "", state: { kind: "loading" } });
  const [audit, setAudit] = useState<Scoped<Array<Record<string, string>>>>({ scope: "", state: { kind: "loading" } });
  const [signOn, setSignOn] = useState<Remote<SSOSettings>>({ kind: "loading" });
  const [status, setStatus] = useState<{ health: boolean; ready: boolean } | null>(null);
  useEffect(() => {
    window.scrollTo(0, 0);
    const follow = () => setSection(fromHash());
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, []);
  useEffect(() => {
    let live = true;
    setOrgs({ kind: "loading" });
    void staffOrgs().then((value) => {
      if (!live) return;
      setOrgs({ kind: "ready", value });
      setSelectedOrg((current) => value.some((org) => org.id === current) ? current : "");
    }).catch((error: unknown) => { if (live) setOrgs({ kind: "failed", message: failure(error) }); });
    void adminSSO().then((value) => { if (live) setSignOn({ kind: "ready", value }); }).catch((error: unknown) => { if (live) setSignOn({ kind: "failed", message: failure(error) }); });
    void serviceStatus().then((value) => { if (live) setStatus(value); }).catch(() => { if (live) setStatus(null); });
    return () => { live = false; };
  }, [refresh]);
  useEffect(() => {
    let live = true;
    if (section !== "users") return;
    setUsers({ scope: selectedOrg, state: { kind: "loading" } });
    if (!selectedOrg) { setUsers({ scope: selectedOrg, state: { kind: "ready", value: [] } }); return; }
    void staffUsers(selectedOrg).then((value) => { if (live) setUsers({ scope: selectedOrg, state: { kind: "ready", value } }); }).catch((error: unknown) => { if (live) setUsers({ scope: selectedOrg, state: { kind: "failed", message: failure(error) } }); });
    return () => { live = false; };
  }, [selectedOrg, refresh, section]);
  useEffect(() => {
    let live = true;
    if (section !== "audit") return;
    setAudit({ scope: auditOrg, state: { kind: "loading" } });
    void staffAudit(auditOrg).then((value) => { if (live) setAudit({ scope: auditOrg, state: { kind: "ready", value } }); }).catch((error: unknown) => { if (live) setAudit({ scope: auditOrg, state: { kind: "failed", message: failure(error) } }); });
    return () => { live = false; };
  }, [auditOrg, refresh, section]);
  const selectOrg = (id: string) => { setSelectedOrg(id); location.hash = "users"; setSection("users"); };
  const choices = orgs.kind === "ready" ? orgs.value : [];
  return <AppFrame className="admin-shell" label="Administration sections" onSignOut={onLogout} user={{ name: username, role: "Staff administrator" }}
    settings={{ items: settings.map(([id, label]) => ({ href: `#${id}`, label, current: section === id })), current: settings.some(([id]) => id === section) }}
    nav={<>{sections.map(([id, label, icon]) => <NavItem key={id} icon={icon} label={label} href={`#${id}`} current={section === id} />)}</>}>
    <section className="page-view admin-view" hidden={!settings.some(([id]) => id === section)} aria-labelledby="staff-settings-heading">
      <header className="ky-page-head"><div><h1 id="staff-settings-heading" className="ky-page-title">Settings</h1><p className="ky-page-lede">Your administrator account and browser appearance.</p></div></header>
      <nav className="ky-settings-tabs" aria-label="Settings sections">{settings.map(([id, label]) => <a key={id} className="ky-nav-item" href={`#${id}`} aria-current={section === id ? "page" : undefined}>{label}</a>)}</nav>
      {!sso && <div hidden={section !== "account"}>{password}</div>}<div hidden={section !== "appearance"}><Appearance /></div>
    </section>
    {sections.map(([id, title, , lede]) => <section key={id} id={id} className="page-view admin-view" hidden={section !== id} aria-labelledby={`staff-${id}-heading`}>
      <header className="ky-page-head"><div><h1 id={`staff-${id}-heading`} className="ky-page-title">{title}</h1><p className="ky-page-lede">{lede}</p></div><button className="secondary" type="button" onClick={() => setRefresh((value) => value + 1)}>Refresh</button></header>
      {id === "orgs" && <Metadata state={orgs} empty="No organizations are mirrored yet.">{(value) => <Table label="Organization directory"><thead><tr><th scope="col">Organization</th><th scope="col">Status</th><th scope="col">Region</th><th scope="col">Notes stored</th><th scope="col">Shared pool</th><th scope="col">Last poll</th></tr></thead><tbody>{value.map((org) => <tr key={org.id}><th scope="row"><button className="quiet" onClick={() => selectOrg(org.id)}>{org.id}</button></th><td><span className="ky-status" data-ky-status={org.status === "active" && org.enabled ? "success" : undefined}>{org.status === "active" && !org.enabled ? "App disabled" : org.status.replaceAll("_", " ")}</span></td><td>{org.homeRegion}</td><td>{bytes(org.notesUsedBytes)}</td><td>{bytes(org.orgUsedBytes)} / {bytes(org.poolBytes)}</td><td>{org.lastPoll || "Not polled"}</td></tr>)}</tbody></Table>}</Metadata>}
      {(id === "users" || id === "audit") && orgs.kind === "failed" && <p role="alert">{orgs.message}</p>}
      {id === "users" && <><label className="field">Organization<select value={selectedOrg} onChange={(event) => setSelectedOrg(event.target.value)} disabled={choices.length === 0}><option value="">Select an organization</option>{choices.map((org) => <option key={org.id} value={org.id}>{org.id}</option>)}</select></label><Metadata state={users.scope === selectedOrg ? users.state : { kind: "loading" }} empty={selectedOrg ? "No accounts in this organization." : "Select an organization to view accounts."}>{(value) => <Table label="Organization accounts"><thead><tr><th scope="col">Account</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Stored</th></tr></thead><tbody>{value.map((user) => <tr key={user.id}><th scope="row">{user.username}</th><td>{user.accountKind === "admin" ? "Administrator" : "Everyday"}</td><td><span className="ky-status" data-ky-status={user.status === "active" ? "success" : undefined}>{user.status}</span></td><td>{bytes(user.usedBytes)}</td></tr>)}</tbody></Table>}</Metadata></>}
      {id === "audit" && <><label className="field">Audit scope<select value={auditOrg} onChange={(event) => setAuditOrg(event.target.value)}><option value="">Platform</option>{choices.map((org) => <option key={org.id} value={org.id}>{org.id}</option>)}</select></label><Metadata state={audit.scope === auditOrg ? audit.state : { kind: "loading" }} empty="No audit events recorded.">{(value) => <div className="audit-log">{value.map((entry, index) => <div className="audit-row" key={`${entry.at}-${index}`}><strong>{entry.event}</strong><span>{entry.outcome} · {entry.at}</span></div>)}</div>}</Metadata></>}
      {id === "sso" && (signOn.kind === "ready" ? <dl className="status-list"><div><dt>Status</dt><dd>{signOn.value.enabled ? "Enabled" : "Disabled"}</dd></div><div><dt>Issuer</dt><dd>{signOn.value.issuerUrl}</dd></div><div><dt>Client</dt><dd>{signOn.value.clientId}</dd></div></dl> : <p role={signOn.kind === "failed" ? "alert" : "status"}>{signOn.kind === "failed" ? signOn.message : "Loading sign-in configuration…"}</p>)}
      {id === "backups" && <AdminBackup username={username} />}
      {id === "server" && <><p role="note" className="admin-note">Staff administration does not grant access to notes or content keys.</p><dl className="status-list"><div><dt>Health</dt><dd><Probe ok={status?.health} /></dd></div><div><dt>Readiness</dt><dd><Probe ok={status?.ready} /></dd></div></dl><OfficeNetworks username={username} /></>}
    </section>)}
  </AppFrame>;
}
function Metadata<T extends readonly unknown[]>({ state, empty, children }: { state: Remote<T>; empty: string; children: (value: T) => ReactNode }) {
  switch (state.kind) {
    case "loading": return <p role="status">Loading metadata…</p>;
    case "failed": return <p role="alert">{state.message}</p>;
    case "ready": return state.value.length === 0 ? <p className="config-muted">{empty}</p> : children(state.value);
  }
}
function Table({ label, children }: { label: string; children: ReactNode }) {
  return <div role="region" aria-label={label} tabIndex={0} style={{ overflowX: "auto" }}><table className="data-table">{children}</table></div>;
}

function Probe({ ok }: { ok?: boolean }) {
  return <span className="ky-status" data-ky-status={ok === undefined ? undefined : ok ? "success" : "danger"}>{ok === undefined ? "Checking…" : ok ? "OK" : "Failed"}</span>;
}
