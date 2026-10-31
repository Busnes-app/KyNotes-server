import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  addAdminTeamMember,
  adminAudit,
  adminSSO,
  adminTeams,
  adminUsers,
  createAdminTeam,
  createAdminUser,
  pairAdminSSO,
  resetAdminPassword,
  saveAdminSSO,
  serviceStatus,
  updateAdminUser,
  type AccountKind,
  type AdminTeam,
  type AdminUser,
  type SSOSettings,
} from "../api";
import { deriveAuthSecret, randomLoginSalt } from "../crypto";
import { AdminBackup } from "./AdminBackup";
import { LicenseFooter, UserBlock } from "./LicenseFooter";
import { NavIcon, type IconName } from "../NavIcon";
import { AppFrame, NavItem } from "./AppNav";
import { Appearance } from "./Appearance";
import { withStepUp } from "../stepup";

export const ADMIN_ACCOUNT_NOTE = "This is an administrator account. It manages KyNotes and cannot open notes. Sign in with your everyday account to write.";

// The administration group; Appearance and Settings (#account) sit in the navigation's lower group.
const SECTIONS = [
  ["users", "Users", "users", "Everyone who can sign in to this server."],
  ["teams", "Teams", "team", "A team belongs to an everyday owner, who names it and shares its keys. Administrators never see its name or its notes."],
  ["sso", "Single sign-on", "sso", "Connect KyNotes to KySignOn Server for one-click single sign-on and automated user directory replication."],
  ["backups", "Backups", "backups", "Scheduled backups of this server, kept in a local directory or in KyRecovery."],
  ["audit", "Audit log", "audit", "Metadata-only records of administrative actions."],
  ["server", "Server", "server", "Health and readiness of this KyNotes server."],
  ["account", "Settings", "settings", "Your administrator password."],
] as const satisfies ReadonlyArray<readonly [string, string, IconName, string]>;
type SectionID = (typeof SECTIONS)[number][0] | "appearance";

/** Everything an administrator account reaches: no key, vault, notebook or content crypto (adminSeparation.test.ts). */
export function AdminConsole({ username, sso, onLogout, password }: { username: string; sso: boolean; onLogout: () => void; password: ReactNode }) {
  const sections = SECTIONS.filter(([id]) => id !== "account" || !sso);
  const fromHash = (): SectionID => location.hash === "#appearance" ? "appearance" : sections.find(([id]) => location.hash === `#${id}`)?.[0] ?? "users";
  const [section, setSection] = useState<SectionID>(fromHash);
  const link = (id: SectionID, label: string, icon: IconName) => <NavItem key={id} icon={icon} label={label} href={`#${id}`} current={section === id} />;
  const [status, setStatus] = useState<{ health: boolean; ready: boolean } | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [audit, setAudit] = useState<Array<Record<string, string>>>([]);
  useEffect(() => {
    // The console replaces the setup or sign-in page in the same window: start at its top, not their scroll offset.
    window.scrollTo(0, 0);
    const follow = () => setSection(fromHash());
    window.addEventListener("hashchange", follow);
    void Promise.all([adminUsers(), adminAudit(), serviceStatus()])
      .then(([nextUsers, nextAudit, nextStatus]) => {
        setUsers(nextUsers);
        setAudit(nextAudit);
        setStatus(nextStatus);
      })
      .catch(() => {});
    return () => window.removeEventListener("hashchange", follow);
  }, []);
  return (
    // The same frame as the notes. An administrator account opens no notes, so it has no Notes item.
    <AppFrame
      className="admin-shell"
      label="Administration sections"
      onSignOut={onLogout}
      nav={<>
        {sections.filter(([id]) => id !== "account").map(([id, label, icon]) => link(id, label, icon))}
        {link("appearance", "Appearance", "palette")}
        {!sso && link("account", "Settings", "settings")}
      </>}
      foot={<>
        <UserBlock name={username} role="Administrator" onSignOut={onLogout} />
        <LicenseFooter signedIn />
      </>}
    >
        <div id="appearance" hidden={section !== "appearance"}><Appearance /></div>
        {/* Every section stays mounted, so switching keeps lists loaded and half-typed forms intact. */}
        {sections.map(([id, title, , lede]) => (
          <section key={id} id={id} className="page-view admin-view" hidden={section !== id} aria-labelledby={`${id}-heading`}>
            <header className="ky-page-head">
              <div>
                <h1 id={`${id}-heading`} className="ky-page-title">{title}</h1>
                <p className="ky-page-lede">{lede}</p>
              </div>
              {id === "users" && <CreateUser username={username} onCreated={() => void adminUsers().then(setUsers)} />}
            </header>
            {id === "users" && <UserTable username={username} users={users} onChange={(user) => setUsers((value) => value.map((entry) => (entry.id === user.id ? user : entry)))} />}
            {id === "teams" && <AdminTeams users={users} username={username} />}
            {id === "sso" && <AdminSSO username={username} />}
            {id === "backups" && <AdminBackup username={username} />}
            {id === "audit" && (
              <div className="audit-log">
                {audit.length === 0 ? (
                  <p className="config-muted">No audit events recorded.</p>
                ) : (
                  audit.map((entry, index) => (
                    <div className="audit-row" key={`${entry.at}-${index}`}>
                      <strong>{entry.event}</strong>
                      <span>{entry.outcome} · {entry.at}</span>
                    </div>
                  ))
                )}
              </div>
            )}
            {id === "server" && (
              <>
                <p role="note" className="admin-note">{ADMIN_ACCOUNT_NOTE}</p>
                <dl className="status-list">
                  <div><dt>Health</dt><dd>{status ? (status.health ? "OK" : "Failed") : "Checking…"}</dd></div>
                  <div><dt>Readiness</dt><dd>{status ? (status.ready ? "OK" : "Failed") : "Checking…"}</dd></div>
                </dl>
              </>
            )}
            {/* SSO administrators change no password here. */}
            {id === "account" && password}
          </section>
        ))}
    </AppFrame>
  );
}

const failed = (fallback: string) => (error: unknown) => {
  // A cancelled password dialog is the administrator's own choice, not a failure to report.
  if (error instanceof Error && error.message === "Password confirmation cancelled") return;
  alert(error instanceof Error ? error.message : fallback);
};

/** Create user: a header action that opens its own dialog; the password step-up asks only if the server wants it. */
function CreateUser({ username: admin, onCreated }: { username: string; onCreated: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [kind, setKind] = useState<AccountKind>("user");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const salt = randomLoginSalt();
      const authSecret = await deriveAuthSecret(password, salt, 600000);
      await withStepUp(admin, () => createAdminUser({ username, authSecret, loginSalt: salt, iterations: 600000, accountKind: kind }));
      setUsername("");
      setPassword("");
      dialog.current?.close();
      onCreated();
    } catch (error) {
      failed("Unable to create user")(error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <button type="button" className="ky-page-action" onClick={() => dialog.current?.showModal()}><NavIcon name="plus" />Create user</button>
      <dialog ref={dialog} className="ky-dialog" aria-labelledby="create-user-heading">
        <form onSubmit={submit}>
          <h2 id="create-user-heading">Create user</h2>
          <label>Username<input autoComplete="off" value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
          <label>Temporary password<input type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
          <label>Account type
            <select value={kind} onChange={(event) => setKind(event.target.value as AccountKind)}>
              <option value="user">Everyday</option>
              <option value="admin">Administrator</option>
            </select>
          </label>
          <p className="dialog-hint">They choose their own password at first sign-in.</p>
          <div className="dialog-actions">
            <button type="button" className="secondary" onClick={() => dialog.current?.close()}>Cancel</button>
            <button disabled={busy}>{busy ? "Creating…" : "Create user"}</button>
          </div>
        </form>
      </dialog>
    </>
  );
}

const RESET_DONE = "Password reset. All existing sessions and paired device credentials were revoked. The account keeps its encryption key: after changing the temporary password, the user gets it back from a browser that holds it or with their recovery code (an account linked to KySignOn gets no password copy back). With neither, they can reset it themselves, and their personal notebooks are lost. If a browser holding the key was lost or stolen, ask the user to reset their encryption key in Settings: this reset does not cut that browser off.";

/** Account / Role / Status, with each row's actions in a ⋯ menu. */
function UserTable({ username: admin, users, onChange }: { username: string; users: AdminUser[]; onChange: (user: AdminUser) => void }) {
  const close = (id: string) => document.getElementById(id)?.hidePopover();
  async function save(user: AdminUser) {
    try {
      await withStepUp(admin, () => updateAdminUser(user));
      onChange(user);
    } catch (error) {
      failed("Unable to update user")(error);
    }
  }
  async function reset(user: AdminUser) {
    const password = prompt(`New temporary password for ${user.username}`);
    if (!password) return;
    try {
      const salt = randomLoginSalt();
      const secret = await deriveAuthSecret(password, salt, 600000);
      await withStepUp(admin, () => resetAdminPassword(user.id, { newAuthSecret: secret, newLoginSalt: salt, iterations: 600000 }));
      alert(RESET_DONE);
    } catch (error) {
      failed("Unable to reset password")(error);
    }
  }
  return (
    <table className="data-table">
      <thead>
        <tr><th scope="col">Account</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col"><span className="visually-hidden">Actions</span></th></tr>
      </thead>
      <tbody>
        {users.map((user, index) => {
          const menu = `user-menu-${index}`;
          const active = user.status === "active";
          return (
            <tr key={user.id} className="admin-user">
              <th scope="row">{user.username}</th>
              <td>{user.accountKind === "admin" ? (user.role === "admin" ? "Administrator" : "Administrator, grant revoked") : "Everyday"}</td>
              <td><span className={`status-badge${active ? "" : " status-off"}`}>{active ? "Active" : "Disabled"}</span></td>
              <td className="row-actions">
                <button className="icon-button quiet menu-button" popoverTarget={menu} aria-label={`Actions for ${user.username}`} style={{ anchorName: `--${menu}` }}><NavIcon name="more" /></button>
                <div className="section-menu anchored-menu row-menu" id={menu} popover="auto" style={{ positionAnchor: `--${menu}` } as React.CSSProperties}>
                  <button className="quiet" onClick={() => { close(menu); void reset(user); }}>Reset password</button>
                  {user.accountKind === "admin" && (
                    <button className="quiet" onClick={() => { close(menu); void save({ ...user, role: user.role === "admin" ? "user" : "admin" }); }}>{user.role === "admin" ? "Revoke administrator grant" : "Restore administrator grant"}</button>
                  )}
                  <button className={active ? "quiet danger" : "quiet"} onClick={() => { close(menu); void save({ ...user, status: active ? "disabled" : "active" }); }}>{active ? "Disable account" : "Enable account"}</button>
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function AdminTeams({ users, username }: { users: AdminUser[]; username: string }) {
  const [teams, setTeams] = useState<AdminTeam[]>([]);
  const [owner, setOwner] = useState("");
  const [team, setTeam] = useState("");
  const [user, setUser] = useState("");
  const [role, setRole] = useState("editor");
  const everyday = users.filter((entry) => entry.status === "active" && entry.accountKind === "user");
  async function reload() {
    try {
      setTeams(await adminTeams());
    } catch {
      /* The admin page remains usable if the list refresh is unavailable. */
    }
  }
  useEffect(() => {
    void reload();
  }, []);
  async function create() {
    if (!owner) return;
    try {
      setTeam((await withStepUp(username, () => createAdminTeam(owner))).id);
      await reload();
    } catch (error) {
      failed("Unable to create team")(error);
    }
  }
  async function add() {
    if (!team || !user) return;
    try {
      await withStepUp(username, () => addAdminTeamMember(team, user, role));
      alert("Person added. They get the team's keys once one of its owners approves them.");
      await reload();
    } catch (error) {
      failed("Unable to add person")(error);
    }
  }
  return (
    <div className="admin-panel">
      <label className="field">
        <span>Owner</span>
        <select value={owner} onChange={(event) => setOwner(event.target.value)}>
          <option value="">Select owner</option>
          {everyday.map((entry) => <option key={entry.id} value={entry.id}>{entry.username}</option>)}
        </select>
      </label>
      <button disabled={!owner} onClick={() => void create()}>Create team</button>
      <ul className="admin-teams">
        {teams.map((entry) => (
          <li key={entry.id}><code>{entry.id}</code> · owner {entry.ownerUsername} · {entry.memberCount} {entry.memberCount === 1 ? "member" : "members"} · {entry.named ? "named" : "not named yet"} · {entry.keyed ? "keyed" : "waiting for its owner"}</li>
        ))}
      </ul>
      <label className="field">
        <span>Team</span>
        <select value={team} onChange={(event) => setTeam(event.target.value)}>
          <option value="">Select team</option>
          {teams.map((entry) => <option key={entry.id} value={entry.id}>{entry.id} · {entry.ownerUsername}</option>)}
        </select>
      </label>
      <label className="field">
        <span>Person</span>
        <select value={user} onChange={(event) => setUser(event.target.value)}>
          <option value="">Select person</option>
          {everyday.map((entry) => <option key={entry.id} value={entry.id}>{entry.username}</option>)}
        </select>
      </label>
      <label className="field">
        <span>Role</span>
        <select value={role} onChange={(event) => setRole(event.target.value)}>
          <option>editor</option>
          <option>commenter</option>
          <option>viewer</option>
        </select>
      </label>
      <button className="secondary" onClick={() => void add()}>Add to team</button>
    </div>
  );
}

function AdminSSO({ username }: { username: string }) {
  const [settings, setSettings] = useState<SSOSettings | null>(null);
  const [pairingToken, setPairingToken] = useState("");
  const [pairingIssuer, setPairingIssuer] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);

  useEffect(() => {
    void adminSSO().then(setSettings).catch(() => {});
  }, []);

  async function handlePair(e: FormEvent) {
    e.preventDefault();
    if (!pairingToken.trim() || !pairingIssuer.trim()) return;
    setBusy(true);
    setMessage(null);
    try {
      const res = await withStepUp(username, () => pairAdminSSO(pairingIssuer.trim(), pairingToken.trim()));
      setSettings(res.settings);
      setPairingToken("");
      setMessage({ text: `Successfully paired with KySignOn (System ID: ${res.systemId})!`, type: "success" });
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : "Pairing failed", type: "error" });
    } finally {
      setBusy(false);
    }
  }

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    if (!settings) return;
    setBusy(true);
    setMessage(null);
    try {
      const updated = await withStepUp(username, () => saveAdminSSO(settings));
      setSettings(updated);
      setMessage({ text: "Single Sign-On settings saved successfully.", type: "success" });
    } catch (err) {
      setMessage({ text: err instanceof Error ? err.message : "Unable to save SSO settings", type: "error" });
    } finally {
      setBusy(false);
    }
  }

  if (!settings) return <p className="config-muted">Loading Single Sign-On configuration…</p>;

  return (
    <div className="admin-panel">
      {message && (
        <p className={message.type === "error" ? "error" : "status-line"} style={{ margin: "14px 0" }}>
          {message.text}
        </p>
      )}

      <div style={{ background: "var(--accent-soft)", padding: "16px", borderRadius: "4px", margin: "18px 0" }}>
        <h3 style={{ margin: "0 0 8px", fontSize: "14px", font: "12px Mono, monospace", letterSpacing: ".1em", textTransform: "uppercase" }}>
          Quick Pair with KySignOn
        </h3>
        <p className="config-muted" style={{ margin: "0 0 14px", fontSize: "13px" }}>
          Generate a 90-second system pairing token in KySignOn Admin Dashboard to pair KyNotes automatically.
        </p>
        <form onSubmit={handlePair} style={{ display: "grid", gap: "12px" }}>
          <label className="field" style={{ marginTop: 0 }}>
            <span>KySignOn Issuer URL</span>
            <input
              placeholder="http://localhost:5867 or https://auth.example.com"
              value={pairingIssuer}
              onChange={(e) => setPairingIssuer(e.target.value)}
              required
            />
          </label>
          <label className="field" style={{ marginTop: 0 }}>
            <span>90-Second Pairing Token</span>
            <input
              placeholder="Enter pairing token from KySignOn UI"
              value={pairingToken}
              onChange={(e) => setPairingToken(e.target.value)}
              required
            />
          </label>
          <button disabled={busy} style={{ width: "fit-content" }}>
            {busy ? "Pairing…" : "Pair with KySignOn"}
          </button>
        </form>
      </div>

      <form onSubmit={handleSave} style={{ marginTop: "24px" }}>
        <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={settings.enabled}
            onChange={(e) => setSettings({ ...settings, enabled: e.target.checked })}
            style={{ width: "18px", height: "18px" }}
          />
          <strong style={{ fontSize: "14px" }}>Enable OpenID Connect / Single Sign-On</strong>
        </label>
        <label className="field">
          <span>OIDC Issuer URL</span>
          <input
            value={settings.issuerUrl}
            onChange={(e) => setSettings({ ...settings, issuerUrl: e.target.value })}
            placeholder="https://auth.example.com"
          />
        </label>
        <label className="field">
          <span>Client ID</span>
          <input
            value={settings.clientId}
            onChange={(e) => setSettings({ ...settings, clientId: e.target.value })}
            placeholder="kynotes"
          />
        </label>
        <label className="field">
          <span>{settings.clientSecretSet ? "Client Secret: set. Enter a new one only to replace it" : "Client Secret (Optional for PKCE)"}</span>
          <input
            type="password"
            autoComplete="new-password"
            value={settings.clientSecret ?? ""}
            onChange={(e) => setSettings({ ...settings, clientSecret: e.target.value })}
            placeholder={settings.clientSecretSet ? "Leave empty to keep the current secret" : ""}
          />
        </label>
        {settings.clientSecretSet && (
          <label style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <input type="checkbox" checked={settings.clearClientSecret ?? false} onChange={(e) => setSettings({ ...settings, clearClientSecret: e.target.checked })} />
            <span>Remove the client secret</span>
          </label>
        )}
        <p className="config-muted">Directory sync secret: {settings.hmacSecretSet ? "set" : "not set"}</p>
        {settings.hmacSecretSet && (
          <label style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <input type="checkbox" checked={settings.clearHmacSecret ?? false} onChange={(e) => setSettings({ ...settings, clearHmacSecret: e.target.checked })} />
            <span>Remove the directory sync secret (turns directory sync off)</span>
          </label>
        )}
        <label className="field">
          <span>Custom Redirect URI (Optional override)</span>
          <input
            value={settings.redirectUri ?? ""}
            onChange={(e) => setSettings({ ...settings, redirectUri: e.target.value })}
            placeholder="https://notes.example.com/api/v1/auth/oidc/callback"
          />
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "16px", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={settings.autoProvision}
            onChange={(e) => setSettings({ ...settings, autoProvision: e.target.checked })}
            style={{ width: "18px", height: "18px" }}
          />
          <span style={{ fontSize: "13px" }}>Auto-provision new user accounts on first SSO login</span>
        </label>
        <button disabled={busy} style={{ marginTop: "20px" }}>
          {busy ? "Saving…" : "Save SSO Settings"}
        </button>
      </form>
    </div>
  );
}
