import { useEffect, useState, type FormEvent, type ReactNode } from "react";
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
import { ConfirmPassword } from "./ConfirmPassword";

export const ADMIN_ACCOUNT_NOTE = "This is an administrator account. It manages KyNotes and cannot open notes. Sign in with your everyday account to write.";

/** Everything an administrator account reaches: no key, vault, notebook or content crypto (adminSeparation.test.ts). */
export function AdminConsole({ username, sso, onLogout, password }: { username: string; sso: boolean; onLogout: () => void; password: ReactNode }) {
  const [status, setStatus] = useState<{ health: boolean; ready: boolean } | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [audit, setAudit] = useState<Array<Record<string, string>>>([]);
  useEffect(() => {
    void Promise.all([adminUsers(), adminAudit(), serviceStatus()])
      .then(([nextUsers, nextAudit, nextStatus]) => {
        setUsers(nextUsers);
        setAudit(nextAudit);
        setStatus(nextStatus);
      })
      .catch(() => {});
  }, []);
  async function saveUser(user: AdminUser) {
    try {
      await updateAdminUser(user);
      setUsers((value) => value.map((entry) => (entry.id === user.id ? user : entry)));
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to update user");
    }
  }
  return (
    <main className="settings-layout admin-settings-layout">
      <aside className="settings-sidebar">
        <div className="section-label">ADMIN</div>
        <p className="config-muted">{username}</p>
        <button className="quiet" onClick={onLogout}>Sign out</button>
      </aside>
      <div className="settings-content">
        <div className="settings-header">
          <div className="section-label">ADMIN</div>
          <h1>Administration</h1>
          <p>Manage people, teams, and metadata-only audit records.</p>
          <p role="note">{ADMIN_ACCOUNT_NOTE}</p>
        </div>
        <nav className="settings-nav admin-main-tabs" aria-label="Administration sections">
          <a href="#server">Server</a>
          <a href="#sso">Single Sign-On</a>
          <a href="#users">Users</a>
          <a href="#teams">Teams</a>
          <a href="#audit">Audit log</a>
          <a href="#backups">Backups</a>
          {!sso && <a href="#account">Account</a>}
        </nav>
        <section id="server" className="config-card">
          <h2>Server status</h2>
          <p className="status-line">
            Health: {status ? (status.health ? "OK" : "failed") : "checking…"} · Readiness: {status ? (status.ready ? "OK" : "failed") : "checking…"}
          </p>
        </section>
        <AdminSSO username={username} />
        <AdminBackup username={username} />
        <section id="users" className="config-card">
          <h2>Users</h2>
          <ConfirmPassword username={username} what="User creation and password resets" />
          <AdminCreateUser onCreated={() => void adminUsers().then(setUsers)} />
          {users.map((user) => (
            <div className="admin-user" key={user.id}>
              <strong>{user.username}</strong>
              {user.accountKind === "admin" ? (
                <select aria-label={`Administrator grant for ${user.username}`} value={user.role} onChange={(event) => void saveUser({ ...user, role: event.target.value })}>
                  <option value="admin">Grant</option>
                  <option value="user">Revoked</option>
                </select>
              ) : (
                <span>Everyday</span>
              )}
              <select value={user.status} onChange={(event) => void saveUser({ ...user, status: event.target.value })}>
                <option>active</option>
                <option>disabled</option>
              </select>
              <AdminUserActions user={user} onReset={() => {}} />
            </div>
          ))}
        </section>
        <div id="teams">
          <AdminTeams users={users} username={username} />
        </div>
        <section id="audit" className="config-card">
          <h2>Audit log</h2>
          <div className="audit-log">
            {audit.length === 0 ? (
              <p className="config-muted">No audit events recorded.</p>
            ) : (
              audit.map((entry, index) => (
                <div className="audit-row" key={`${entry.at}-${index}`}>
                  <strong>{entry.event}</strong>
                  <span>
                    {entry.outcome} · {entry.at}
                  </span>
                </div>
              ))
            )}
          </div>
        </section>
        {/* SSO administrators change no password here. */}
        <div id="account">{!sso && password}</div>
      </div>
    </main>
  );
}

function AdminCreateUser({ onCreated }: { onCreated: () => void }) {
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
      await createAdminUser({
        username,
        authSecret,
        loginSalt: salt,
        iterations: 600000,
        accountKind: kind,
      });
      setUsername("");
      setPassword("");
      onCreated();
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to create user");
    } finally {
      setBusy(false);
    }
  }
  return (
    <form className="admin-create" onSubmit={submit}>
      <h3>Create user</h3>
      <input
        placeholder="Username"
        value={username}
        onChange={(event) => setUsername(event.target.value)}
        required
      />
      <input
        placeholder="Temporary password"
        type="password"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        required
      />
      <select aria-label="Account type" value={kind} onChange={(event) => setKind(event.target.value as AccountKind)}>
        <option value="user">Everyday</option>
        <option value="admin">Administrator</option>
      </select>
      <button disabled={busy}>Create user</button>
    </form>
  );
}

function AdminUserActions({
  user,
  onReset,
}: {
  user: AdminUser;
  onReset: () => void;
}) {
  async function reset() {
    const password = prompt(`New temporary password for ${user.username}`);
    if (!password) return;
    try {
      const salt = randomLoginSalt();
      const secret = await deriveAuthSecret(password, salt, 600000);
      await resetAdminPassword(user.id, {
        newAuthSecret: secret,
        newLoginSalt: salt,
        iterations: 600000,
      });
      onReset();
      alert("Password reset. All existing sessions and paired device credentials were revoked. The account keeps its encryption key: after changing the temporary password, the user gets it back from a browser that holds it or with their recovery code (an account linked to KySignOn gets no password copy back). With neither, they can reset it themselves, and their personal notebooks are lost. If a browser holding the key was lost or stolen, ask the user to reset their encryption key in Settings: this reset does not cut that browser off.");
    } catch (error) {
      alert(
        error instanceof Error ? error.message : "Unable to reset password",
      );
    }
  }
  return (
    <button className="quiet" onClick={() => void reset()}>
      Reset password
    </button>
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
      setTeam((await createAdminTeam(owner)).id);
      await reload();
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to create team");
    }
  }
  async function add() {
    if (!team || !user) return;
    try {
      await addAdminTeamMember(team, user, role);
      alert("Person added. They get the team's keys once one of its owners approves them.");
      await reload();
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to add person");
    }
  }
  return (
    <section className="config-card">
      <h2>Teams</h2>
      <p className="config-muted">A team belongs to an everyday owner, who names it and shares its keys. Administrators never see its name or its notes.</p>
      <ConfirmPassword username={username} what="Creating teams and adding people" />
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
      <button onClick={() => void add()}>Add to team</button>
    </section>
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
      const res = await pairAdminSSO(pairingIssuer.trim(), pairingToken.trim());
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
      const updated = await saveAdminSSO(settings);
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
    <section id="sso" className="config-card">
      <h2>Single Sign-On (KySignOn / OIDC)</h2>
      <ConfirmPassword username={username} what="Single sign-on changes" />
      <p className="config-muted">
        Connect KyNotes to KySignOn Server for one-click single sign-on and automated user directory replication.
      </p>
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
    </section>
  );
}
