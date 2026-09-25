import { AdminBackup } from "./components/AdminBackup";
import { ConfirmPassword } from "./components/ConfirmPassword";
import React, { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  addAdminTeamMember,
  adminAudit,
  adminSSO,
  adminTeams,
  adminUsers,
  attachToObject,
  APIRequestError,
  changePassword,
  changes,
  checkSetup,
  comments,
  containers,
  createAdminUser,
  createAdminTeam,
  createComment,
  createContainer,
  createObject,
  createUpload,
  deleteUpload,
  createSealedShareLink,
  deleteObject,
  downloadAttachment,
  fetchShareCiphertext,
  finalizeUpload,
  inviteMember,
  login,
  loginParams,
  logout,
  members,
  notifications,
  objectConflicts,
  objectAttachments,
  pairAdminSSO,
  readObject,
  removeMember,
  resetAdminPassword,
  saveAdminSSO,
  saveObject,
  serviceStatus,
  session,
  setupInit,
  ssoConfig,
  updateAdminUser,
  updateContainer,
  updatePresence,
  uploadChunk,
  uploadStatus,
  type AdminTeam,
  type AdminUser,
  type Container,
  type Note,
  type Session,
  type SSOSettings,
} from "./api";
import {
  decryptComment,
  decryptAttachment,
  decryptAttachmentMetadata,
  decryptContainerMeta,
  decryptNote,
  decryptSharePayload,
  deriveAuthSecret,
  digestSha256Hex,
  encryptComment,
  encryptAttachment,
  encryptAttachmentMetadata,
  encryptContainerMeta,
  encryptNote,
  encryptSharePayload,
  fromBase64,
  randomLoginSalt,
  type NotePayload,
} from "./crypto";
import {
  clearDeviceKey,
  clearQueuedSave,
  deleteNote as deleteCachedNote,
  getDeviceKey,
  getNote,
  clearUpload,
  pendingSaves,
  pendingUploads,
  putNote,
  putUpload,
  queueSave,
  storeDeviceKey,
} from "./storage";
import {
  applyStoredTheme,
  applyTheme,
  getStoredTheme,
  THEME_OPTIONS,
  type ThemeName,
} from "./theme";
import { contextualNotes, graphEdges, indexNotes, noteTasks, openTaskNotes, searchNotes } from "./knowledge";
import { documentText, emptyNoteDocument, isStructuredNoteBody, parseNoteDocument, stringifyNoteDocument } from "./document";
import { commitToastLabel, commitToastVisible, COMMIT_TOAST_DURATION_MS } from "./commitToast";
import type { Block } from "@blocknote/core";
import "./styles.css";
import "./ky-ui/tokens.css";
import "./ky-ui/navigation.css";

const MAX_CHANGE_PAGES = 100;

const BlockNoteEditor = lazy(() => import("./BlockNoteEditor").then((module) => ({ default: module.BlockNoteEditor })));

type AuthState = {
  username: string;
  authSecret: string;
  user: Session["user"];
};
type PlainComment = {
  id: string;
  username: string;
  body: string;
  section?: string;
  createdAt: string;
};
type PlainAttachment = { id: string; name: string; type: string; size: number };
type QueueEntry = { note: Note; container: Container };

function App() {
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [sessionUser, setSessionUser] = useState<Session["user"] | null>(null);
  const [checking, setChecking] = useState(true);
  useEffect(() => {
    applyStoredTheme();

    session()
      .then(async (res) => {
        setSessionUser(res.user);
        if (res.user?.username) {
          const cachedKey = await getDeviceKey(res.user.username).catch(() => undefined);
          if (cachedKey) {
            setAuth({
              username: res.user.username,
              authSecret: cachedKey,
              user: res.user,
            });
          }
        }
      })
      .catch(() => {
        setSessionUser(null);
      })
      .finally(() => setChecking(false));
  }, []);
  if (checking) return <main className="center">Loading KyNotes…</main>;
  if (location.pathname.startsWith("/share/")) return <SharedNote />;
  return auth ? (
    <Workspace
      auth={auth}
      onLogout={() => {
        void logout().finally(() => {
          setAuth(null);
          setSessionUser(null);
        });
      }}
      onForgetDevice={() => {
        void clearDeviceKey(auth.username).then(() => {
          void logout().finally(() => {
            setAuth(null);
            setSessionUser(null);
          });
        });
      }}
    />
  ) : (
    <Login
      sessionUser={sessionUser}
      onClearSession={() => {
        void logout().finally(() => setSessionUser(null));
      }}
      onForgetDevice={(username) => {
        void clearDeviceKey(username).then(() => {
          void logout().finally(() => setSessionUser(null));
        });
      }}
      onLogin={setAuth}
    />
  );
}

function SharedNote() {
  const [state, setState] = useState<{ note?: NotePayload; error?: string }>(
    {},
  );
  useEffect(() => {
    const token = location.pathname.split("/").pop() ?? "";
    const key = location.hash.slice(1);
    if (!token || !key) {
      setState({ error: "This link is missing its decryption key." });
      return;
    }
    void fetchShareCiphertext(token)
      .then((bytes) => decryptSharePayload(bytes, key))
      .then((note) => setState({ note }))
      .catch((error) =>
        setState({
          error:
            error instanceof Error
              ? error.message
              : "Unable to decrypt this note.",
        }),
      );
  }, []);
  if (state.error)
    return (
      <main className="center">
        <section className="auth-card">
          <img src="/app-icon.png" width={56} height={56} alt="KyNotes" />
          <h2>Encrypted link unavailable</h2>
          <p className="error">{state.error}</p>
        </section>
      </main>
    );
  if (!state.note)
    return <main className="center">Decrypting encrypted note…</main>;
  return (
    <main className="auth-page">
      <article className="shared-note">
        <div className="eyebrow">ENCRYPTED KYNOTES LINK</div>
        <h1>{state.note.title}</h1>
        <div className="shared-note-body">{documentText(state.note.body)}</div>
      </article>
    </main>
  );
}

function Login({
  onLogin,
  sessionUser,
  onClearSession,
  onForgetDevice,
}: {
  onLogin: (auth: AuthState) => void;
  sessionUser?: Session["user"] | null;
  onClearSession?: () => void;
  onForgetDevice?: (username: string) => void;
}) {
  const [setupRequired, setSetupRequired] = useState(false);
  const [username, setUsername] = useState(() => sessionUser?.username ?? sessionStorage.getItem("kynotes-last-username") ?? "");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sso, setSSO] = useState<{ enabled: boolean; issuerUrl: string; clientId: string } | null>(null);

  useEffect(() => {
    void checkSetup().then((res) => {
      if (res.setupRequired) {
        setSetupRequired(true);
        setUsername((prev) => prev || "admin");
      }
    }).catch(() => {});
    void ssoConfig().then(setSSO).catch(() => {});
  }, []);

  useEffect(() => {
    if (sessionUser?.username) {
      setUsername(sessionUser.username);
    }
  }, [sessionUser]);

  async function submitSetup(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    setBusy(true);
    try {
      const name = username.trim() || "admin";
      const params = await loginParams(name).catch(() => ({
        loginSalt: randomLoginSalt(),
        iterations: 600000,
      }));
      const salt = params.loginSalt || randomLoginSalt();
      const iterations = params.iterations || 600000;
      const authSecret = await deriveAuthSecret(password, salt, iterations);
      const result = await setupInit(name, password, authSecret, salt, iterations);
      await storeDeviceKey(name, authSecret);
      sessionStorage.setItem("kynotes-last-username", name);
      onLogin({ username: name, authSecret, user: result.user });
      setPassword("");
      setConfirmPassword("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to initialize administrator account");
    } finally {
      setBusy(false);
    }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const activeName = username.trim() || sessionUser?.username || "";
      const params = await loginParams(activeName);
      const authSecret = await deriveAuthSecret(
        password,
        params.loginSalt,
        params.iterations,
      );
      await storeDeviceKey(activeName, authSecret);
      if (sessionUser) {
        // If SSO session is active, verify credentials or enter directly
        try {
          const result = await login(activeName, authSecret);
          sessionStorage.setItem("kynotes-last-username", activeName);
          onLogin({ username: activeName, authSecret, user: result.user });
        } catch {
          // If login endpoint failed but SSO session is valid, allow user entry with their derived key
          sessionStorage.setItem("kynotes-last-username", activeName);
          onLogin({ username: activeName, authSecret, user: sessionUser });
        }
      } else {
        const result = await login(activeName, authSecret);
        sessionStorage.setItem("kynotes-last-username", activeName);
        onLogin({ username: activeName, authSecret, user: result.user });
      }
      setPassword("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to sign in");
    } finally {
      setBusy(false);
    }
  }

  if (setupRequired) {
    return (
      <main className="auth-page">
        <section className="auth-card">
          <img src="/app-icon.png" width={56} height={56} alt="KyNotes" />
          <div className="eyebrow">INITIAL SETUP</div>
          <h1>Create Admin Account</h1>
          <p className="lede">
            Welcome to KyNotes. Set up your organization's primary administrator username and master encryption password.
          </p>
          <form onSubmit={submitSetup}>
            <label>
              Administrator Username
              <input
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
                autoFocus
              />
            </label>
            <label>
              Master Password
              <input
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                minLength={8}
              />
            </label>
            <label>
              Confirm Password
              <input
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                required
                minLength={8}
              />
            </label>
            {error && <p className="error">{error}</p>}
            <button disabled={busy}>
              {busy ? "Initializing…" : "Initialize KyNotes"}
            </button>
          </form>
          <p className="hint">
            Your master password is used in memory to derive your authentication
            verifier and zero-knowledge note-encryption keys. It is never stored on the server.
          </p>
        </section>
      </main>
    );
  }
  return (
    <main className="auth-page">
      <section className="auth-card">
          <img src="/app-icon.png" width={56} height={56} alt="KyNotes" />
        <div className="eyebrow">PRIVATE NOTES</div>
        <h1>Keep the thread.</h1>
        <p className="lede">
          Your notes are encrypted in this browser before they leave it.
        </p>
        {sessionUser ? (
          <div
            style={{
              background: "var(--surface)",
              border: "1px solid var(--accent)",
              borderRadius: "4px",
              padding: "12px 14px",
              marginBottom: "18px",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
            }}
          >
            <div>
              <div style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--accent)", letterSpacing: ".08em", fontWeight: 600 }}>
                KySignOn SSO Active
              </div>
              <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--ink-strong)" }}>
                {sessionUser.username || sessionUser.id}
              </div>
              <div style={{ fontSize: "12px", color: "var(--ink)", marginTop: "4px" }}>
                Enter your master password once to unlock and trust this device for 1-click SSO.
              </div>
            </div>
            {onClearSession && (
              <button
                type="button"
                className="secondary small"
                onClick={onClearSession}
                style={{ fontSize: "11px", padding: "4px 8px", whiteSpace: "nowrap" }}
              >
                Sign out SSO
              </button>
            )}
          </div>
        ) : sso?.enabled ? (
          <div>
            <a
              href="/api/v1/auth/oidc/login"
              style={{
                display: "block",
                textAlign: "center",
                padding: "13px 18px",
                background: "transparent",
                color: "var(--ink-strong)",
                border: "1px solid var(--accent)",
                boxShadow: "0 0 12px var(--glow)",
                borderRadius: "3px",
                textDecoration: "none",
                fontWeight: 600,
                marginBottom: "20px",
              }}
            >
              Sign In with KySignOn SSO
            </a>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", margin: "16px 0", color: "var(--ink)" }}>
              <div style={{ flex: 1, height: "1px", background: "var(--line)" }} />
              <span style={{ font: "11px Mono, monospace", textTransform: "uppercase", letterSpacing: ".1em" }}>or password</span>
              <div style={{ flex: 1, height: "1px", background: "var(--line)" }} />
            </div>
          </div>
        ) : null}
        <form onSubmit={submit}>
          {!sessionUser && (
            <label>
              Username
              <input
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
              />
            </label>
          )}
          <label>
            {sessionUser ? "Master Password (to unlock notes)" : "Password"}
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              autoFocus={!!sessionUser}
            />
          </label>
          {error && <p className="error">{error}</p>}
          <button disabled={busy}>
            {busy ? "Unlocking…" : "Unlock KyNotes"}
          </button>
        </form>
        <p className="hint">
          The password is used in memory to derive your authentication and
          note-encryption keys. It is never stored.
        </p>
      </section>
    </main>
  );
}

function Workspace({
  auth,
  onLogout,
  onForgetDevice,
}: {
  auth: AuthState;
  onLogout: () => void;
  onForgetDevice?: () => void;
}) {
  const [items, setItems] = useState<Container[]>([]);
  const [names, setNames] = useState<Record<string, string>>({});
  const [selected, setSelected] = useState<Container | null>(null);
  const [notes, setNotes] = useState<Note[]>([]);
  const [queueEntries, setQueueEntries] = useState<QueueEntry[]>([]);
  const [selectedNote, setSelectedNote] = useState<Note | null>(null);
  const [commentsForNote, setCommentsForNote] = useState<PlainComment[]>([]);
  const [attachmentsForNote, setAttachmentsForNote] = useState<PlainAttachment[]>([]);
  const [attachmentSources, setAttachmentSources] = useState<Record<string, string>>({});
  const [uploadProgress, setUploadProgress] = useState<Record<string, { name: string; uploaded: number; total: number; failed?: boolean }>>({});
  const cancelledUploads = useRef(new Set<string>());
  const [commentText, setCommentText] = useState("");
  const [commentSection, setCommentSection] = useState("");
  const [conflicted, setConflicted] = useState<Set<string>>(new Set());
  const [lastSavedAt, setLastSavedAt] = useState("");
  const [syncStatus, setSyncStatus] = useState<"saved" | "local" | "syncing" | "attention">("saved");
  const draining = useRef(false);
  const drainingUploads = useRef(false);
  const saveChain = useRef(Promise.resolve());
  const syncChannel = useRef<BroadcastChannel | null>(null);
  const selectedNoteRef = useRef<Note | null>(null);
  selectedNoteRef.current = selectedNote;
  const [notificationCount, setNotificationCount] = useState(0);
  const [membersForTeam, setMembersForTeam] = useState<
    Array<{ userId: string; username: string; role: string }>
  >([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [view, setView] = useState<"workspace" | "settings" | "admin">(
    "workspace",
  );
  const [queueMode, setQueueMode] = useState(false);
  const [sort, setSort] = useState<"updated" | "title">("updated");
  const [query, setQuery] = useState("");
  const [commitToastAt, setCommitToastAt] = useState<number | null>(null);
  const [, setCommitToastTick] = useState(0);
  const pinsKey = `kynotes-pins-${auth.user.id}`;
  const pinned = useMemo(() => {
    try {
      return new Set(
        JSON.parse(localStorage.getItem(pinsKey) || "[]") as string[],
      );
    } catch {
      return new Set<string>();
    }
  }, [pinsKey, notes]);
  const nameOf = (container: Container) =>
    names[container.id] || `Workspace ${container.id.slice(4, 10)}`;
  const orderedNotes = useMemo(
    () =>
      [...notes].sort((a, b) => {
        const pinDiff = Number(pinned.has(b.id)) - Number(pinned.has(a.id));
        if (pinDiff) return pinDiff;
        return sort === "title"
          ? a.title.localeCompare(b.title)
          : b.updatedAt.localeCompare(a.updatedAt);
      }),
    [notes, pinned, sort],
  );
  const searchableNotes = useMemo(() => indexNotes(orderedNotes), [orderedNotes]);
  useEffect(() => {
    let cancelled = false;
    const urls: string[] = [];
    void Promise.all(
      attachmentsForNote
        .filter((attachment) => attachment.type.startsWith("image/"))
        .map(async (attachment) => {
          try {
            const encrypted = await downloadAttachment(attachment.id);
            const plaintext = await decryptAttachment(auth.authSecret, selected?.id ?? "", encrypted);
            const url = URL.createObjectURL(new Blob([plaintext.slice().buffer as ArrayBuffer], { type: attachment.type }));
            urls.push(url);
            return [attachment.id, url] as const;
          } catch {
            return null;
          }
        }),
    ).then((entries) => {
      if (cancelled) return;
      setAttachmentSources(Object.fromEntries(entries.filter((entry): entry is readonly [string, string] => entry !== null)));
    });
    return () => {
      cancelled = true;
      urls.forEach((url) => URL.revokeObjectURL(url));
      setAttachmentSources({});
    };
  }, [attachmentsForNote, auth.authSecret, selected?.id]);
  const visibleNotes = useMemo(() => {
    const filtered = searchNotes(searchableNotes, query);
    return filtered.map((match) => match.note);
  }, [searchableNotes, query]);
  const visibleQueueEntries = useMemo(() => {
    const indexed = indexNotes(queueEntries.map((entry) => entry.note));
    const matches = openTaskNotes(searchNotes(indexed, query));
    const entriesByID = new Map(queueEntries.map((entry) => [entry.note.id, entry]));
    return matches.map((match) => entriesByID.get(match.note.id)).filter((entry): entry is QueueEntry => Boolean(entry));
  }, [queueEntries, query]);
  const listEntries = queueMode
    ? visibleQueueEntries
    : visibleNotes.map((note) => ({ note, container: selected })).filter((entry): entry is QueueEntry => Boolean(entry.container));
  const relatedNotes = useMemo(
    () => contextualNotes(searchableNotes, selectedNote ? indexNotes([selectedNote])[0] : undefined).map((match) => match.note),
    [searchableNotes, selectedNote],
  );
  const links = useMemo(() => graphEdges(searchableNotes), [searchableNotes]);
  useEffect(() => {
    void loadContainers();
  }, []);
  useEffect(() => {
    void resumeUploads();
    const timer = window.setInterval(() => void resumeUploads(), 15000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    const channel = typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel("kynotes-sync");
    syncChannel.current = channel;
    channel?.addEventListener("message", () => void drainQueue());
    const retry = () => void drainQueue();
    window.addEventListener("online", retry);
    void drainQueue();
    const timer = window.setInterval(retry, 15000);
    return () => {
      window.removeEventListener("online", retry);
      window.clearInterval(timer);
      channel?.close();
      syncChannel.current = null;
    };
  }, []);
  useEffect(() => {
    if (!commitToastAt) return;
    const timer = window.setInterval(() => setCommitToastTick((value) => value + 1), 1000);
    const expiry = window.setTimeout(() => setCommitToastAt(null), COMMIT_TOAST_DURATION_MS);
    return () => { window.clearInterval(timer); window.clearTimeout(expiry); };
  }, [commitToastAt]);
  useEffect(() => {
    if (!selected) return;
    void updatePresence(
      selected.id,
      selectedNote ? "editing" : "viewing",
    ).catch(() => {});
    const timer = window.setInterval(() => {
      void updatePresence(
        selected.id,
        selectedNote ? "editing" : "viewing",
      ).catch(() => {});
    }, 30000);
    return () => window.clearInterval(timer);
  }, [selected?.id, selectedNote?.id]);
  useEffect(() => {
    const refresh = () =>
      void notifications()
        .then((value) => setNotificationCount(value.length))
        .catch(() => setNotificationCount(0));
    refresh();
    const timer = window.setInterval(refresh, 90000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    document.title = notificationCount
      ? `(${notificationCount}) KyNotes`
      : "KyNotes";
  }, [notificationCount]);
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (
        (event.ctrlKey || event.metaKey) &&
        event.shiftKey &&
        event.key.toLowerCase() === "l" &&
        selectedNote
      ) {
        event.preventDefault();
        void shareNote();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [selectedNote]);
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (
        (event.ctrlKey || event.metaKey) &&
        event.key.toLowerCase() === "s" &&
        selectedNote
      ) {
        event.preventDefault();
        void save(selectedNote);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [selectedNote, selected]);
  useEffect(() => {
    if (!dirty || !selectedNote) return;
    const timer = window.setTimeout(() => {
      void save(selectedNote, true);
    }, 900);
    return () => window.clearTimeout(timer);
  }, [selectedNote?.title, selectedNote?.body, dirty]);
  useEffect(() => {
    if (!dirty || !selectedNote) return;
    const timer = window.setInterval(() => {
      void save(selectedNote, true);
    }, 15000);
    return () => window.clearInterval(timer);
  }, [selectedNote, dirty]);
  useEffect(() => {
    const flushDraft = () => {
      const note = selectedNoteRef.current;
      if (!note || !dirty) return;
      // Background tabs may throttle timers. Persist the encrypted draft
      // before the page is hidden, then let the normal queue drain finish it.
      persistDraft(note);
      void save(note, true);
    };
    const onVisibilityChange = () => {
      if (document.visibilityState === "hidden") flushDraft();
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("pagehide", flushDraft);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("pagehide", flushDraft);
    };
  }, [dirty, selected?.id]);
  async function loadContainers() {
    try {
      const value = await containers();
      const loaded = value;
      const nextNames: Record<string, string> = {};
      for (const item of loaded) {
        try {
          if (item.metaCiphertext)
            nextNames[item.id] = (
              await decryptContainerMeta(
                auth.authSecret,
                item.id,
                fromBase64(item.metaCiphertext),
              )
            ).name;
        } catch {
          /* encrypted metadata may be unavailable in a session-only resume */
        }
      }
      setNames(nextNames);
      setItems(loaded);
      if (loaded[0]) await selectContainer(loaded[0]);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to load workspaces",
      );
    }
  }
  async function readContainerNotes(container: Container): Promise<Note[]> {
    const loaded: Note[] = [];
    let since = 0;
    for (let page = 0; page < MAX_CHANGE_PAGES; page += 1) {
      const result = await changes(container.id, since);
      for (const change of result.changes.filter((entry) => entry.kind === "object" && !entry.deleted)) {
        try {
          const object = await readObject(change.id);
          const cached = await getNote(change.id);
          const payload =
            cached && cached.version >= object.version
              ? await decryptNote(auth.authSecret, container.id, cached.payload)
              : await decryptNote(auth.authSecret, container.id, object.bytes);
          loaded.push({
            id: change.id,
            ...payload,
            body: payload.body,
            version: cached && cached.version >= object.version ? cached.version : object.version,
            updatedAt: cached && cached.version >= object.version ? cached.updatedAt : new Date().toISOString(),
          });
        } catch {
          const cached = await getNote(change.id);
          if (cached) {
            try {
              const payload = await decryptNote(auth.authSecret, container.id, cached.payload);
              loaded.push({ id: change.id, ...payload, body: payload.body, version: cached.version, updatedAt: cached.updatedAt });
            } catch {
              /* Ignore an invalid local draft. */
            }
          }
        }
      }
      if (!result.hasMore) break;
      const next = Number(result.nextCursor);
      if (!Number.isSafeInteger(next) || next <= since) break;
      since = next;
    }
    return loaded;
  }
  async function selectContainer(container: Container): Promise<Note[]> {
    const previousContainer = selected;
    const previousNote = selectedNoteRef.current;
    if (previousContainer && previousNote && previousContainer.id !== container.id && dirty) {
      // Workspace navigation destroys the current editor. Finish its latest
      // encrypted save before replacing the note list so the next load cannot
      // fall back to an older plain document.
      await save(previousNote, true);
    }
    setSelected(container);
    setQueueMode(false);
    setSelectedNote(null);
    setCommentsForNote([]);
    setAttachmentsForNote([]);
    let loaded: Note[] = [];
    try {
      loaded = await readContainerNotes(container);
      setNotes(loaded);
      if (container.kind === "team")
        setMembersForTeam(await members(container.id));
      else setMembersForTeam([]);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to load workspace",
      );
    }
    return loaded;
  }
  async function openWorkQueue() {
    setView("workspace");
    setQueueMode(true);
    setBusy(true);
    try {
      const personalContainers = items.filter((item) => item.kind !== "team" && !item.teamId);
      const results = await Promise.allSettled(personalContainers.map(async (container) => ({
        container,
        notes: await readContainerNotes(container),
      })));
      if (results.some((result) => result.status === "rejected")) {
        setError("Some personal workspaces could not be loaded; the work queue may be incomplete.");
      }
      const entries = results.flatMap((result) => result.status === "fulfilled"
        ? result.value.notes.map((note) => ({ note, container: result.value.container }))
        : []);
      setQueueEntries(entries);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to load work queue");
    } finally {
      setBusy(false);
    }
  }
  async function selectQueueNote(entry: QueueEntry) {
    const loaded = await selectContainer(entry.container);
    const note = loaded.find((candidate) => candidate.id === entry.note.id);
    if (note) await selectNote(note, entry.container.id);
    setQueueMode(true);
  }
  async function selectNote(note: Note, containerID = selected?.id) {
    setSelectedNote(note);
    setDirty(false);
    setLastSavedAt(note.version > 0 ? note.updatedAt : "");
    try { const conflicts = await objectConflicts(note.id); setConflicted((value) => { const next = new Set(value); if (conflicts.some((item) => !item.resolved)) next.add(note.id); else next.delete(note.id); return next; }); } catch { /* conflict metadata is advisory */ }
    try {
      const remote = await comments(note.id);
      const decoded: PlainComment[] = [];
      for (const item of remote) {
        try {
          const decrypted = await decryptComment(
            auth.authSecret,
            containerID ?? "",
            fromBase64(item.bodyCiphertext),
          );
          decoded.push({
            id: item.id,
            username: item.username,
            body: decrypted.body,
            section: decrypted.section,
            createdAt: item.createdAt,
          });
        } catch {
          /* Ignore comments encrypted for another key. */
        }
      }
      setCommentsForNote(decoded);
    } catch {
      setCommentsForNote([]);
    }
    try {
      const remote = await objectAttachments(note.id);
      const decoded: PlainAttachment[] = [];
      for (const item of remote) {
        try {
          const metadata = await decryptAttachmentMetadata(auth.authSecret, containerID ?? "", fromBase64(item.metadataCiphertext));
          decoded.push({ id: item.id, ...metadata });
        } catch { /* Ignore metadata encrypted for another key. */ }
      }
      setAttachmentsForNote(decoded);
    } catch {
      setAttachmentsForNote([]);
    }
  }
  async function newWorkspace() {
    const name = prompt("Personal workspace name", "My personal workspace")?.trim();
    if (!name) return;
    setBusy(true);
    try {
      const container = await createContainer("workbook");
      const encrypted = await encryptContainerMeta(
        auth.authSecret,
        container.id,
        name,
      );
      const encoded = btoa(String.fromCharCode(...encrypted));
      const result = await updateContainer(
        container.id,
        encoded,
        container.metaVersion,
      );
      const named = {
        ...container,
        metaCiphertext: encoded,
        metaVersion: result.metaVersion,
        changeSeq: result.changeSeq,
      };
      setNames((value) => ({ ...value, [named.id]: name }));
      setItems((value) => [...value, named]);
      await selectContainer(named);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to create workspace",
      );
    } finally {
      setBusy(false);
    }
  }
  async function newTeamWorkspace(teamContainer: Container) {
    const name = prompt("Team workspace name", "New workspace")?.trim();
    if (!name) return;
    setBusy(true);
    try {
      const container = await createContainer("workbook", "", teamContainer.id);
      const encrypted = await encryptContainerMeta(auth.authSecret, container.id, name);
      const encoded = btoa(String.fromCharCode(...encrypted));
      const result = await updateContainer(container.id, encoded, container.metaVersion);
      const named = { ...container, metaCiphertext: encoded, metaVersion: result.metaVersion, changeSeq: result.changeSeq };
      setNames((value) => ({ ...value, [named.id]: name }));
      setItems((value) => [...value, named]);
      await selectContainer(named);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to create team workspace");
    } finally {
      setBusy(false);
    }
  }
  async function renameWorkspace() {
    if (!selected) return;
    const name = prompt("Workspace name", nameOf(selected))?.trim();
    if (!name) return;
    setBusy(true);
    try {
      const encrypted = await encryptContainerMeta(
        auth.authSecret,
        selected.id,
        name,
      );
      const encoded = btoa(String.fromCharCode(...encrypted));
      const result = await updateContainer(
        selected.id,
        encoded,
        selected.metaVersion,
      );
      const next = {
        ...selected,
        metaCiphertext: encoded,
        metaVersion: result.metaVersion,
        changeSeq: result.changeSeq,
      };
      setNames((value) => ({ ...value, [selected.id]: name }));
      setItems((value) =>
        value.map((entry) => (entry.id === next.id ? next : entry)),
      );
      setSelected(next);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to rename workspace",
      );
    } finally {
      setBusy(false);
    }
  }
  function togglePin(note: Note) {
    const next = new Set(pinned);
    next.has(note.id) ? next.delete(note.id) : next.add(note.id);
    localStorage.setItem(pinsKey, JSON.stringify([...next]));
    setNotes((value) => [...value]);
  }
  async function newNote() {
    if (!selected) return;
    setBusy(true);
    try {
      const object = await createObject(selected.id);
      const note = {
        id: object.id,
        title: "Untitled note",
        body: stringifyNoteDocument(emptyNoteDocument().document),
        version: 0,
        updatedAt: new Date().toISOString(),
      };
      setNotes((value) => [note, ...value]);
      setSelectedNote(note);
      setDirty(true);
      persistDraft(note);
      await save(note, true);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to create note",
      );
    } finally {
      setBusy(false);
    }
  }
  async function saveNow(note: Note, automatic = false) {
    if (!selected) return;
    if (!automatic) setBusy(true);
    try {
      const payload: NotePayload = { title: note.title, body: note.body };
      const encrypted = await encryptNote(
        auth.authSecret,
        selected.id,
        payload,
      );
      const savedAt = new Date().toISOString();
      await putNote({
        id: note.id,
        containerID: selected.id,
        version: note.version,
        payload: encrypted,
        updatedAt: savedAt,
      });
      try {
        const result = await saveObject(
          note.id,
          encrypted,
          note.version,
          selected.keyGeneration,
        );
        await clearQueuedSave(note.id);
        setCommitToastAt(Date.now());
          setConflicted((value) => { const next = new Set(value); next.delete(note.id); return next; });
          setSyncStatus("saved");
        const saved = { ...note, version: result.version, updatedAt: savedAt };
        setLastSavedAt(savedAt);
        setSyncStatus("saved");
        setNotes((value) =>
          value.map((entry) =>
            entry.id === saved.id && entry.body === note.body && entry.title === note.title
              ? saved
              : entry,
          ),
        );
        setQueueEntries((entries) => entries.flatMap((entry) => {
          if (entry.note.id !== saved.id) return [entry];
          return openTaskNotes(indexNotes([saved])).length ? [{ ...entry, note: saved }] : [];
        }));
        // An edit may have landed while the request was in flight. Never let
        // an older response replace that newer document in memory.
        if (
          selectedNoteRef.current?.id === saved.id &&
          selectedNoteRef.current.title === note.title &&
          selectedNoteRef.current.body === note.body
        ) {
          setSelectedNote(saved);
          setDirty(false);
        } else if (selectedNoteRef.current?.id === saved.id) {
          // Carry the server's new version forward without replacing the
          // newer local document that is waiting to be saved next.
          setSelectedNote((current) =>
            current?.id === saved.id
              ? { ...current, version: saved.version, updatedAt: saved.updatedAt }
              : current,
          );
        }
      } catch (error) {
        if (error instanceof APIRequestError && error.code === "version_conflict") {
          setConflicted((value) => new Set(value).add(note.id));
          setSyncStatus("attention");
          setError("This note changed on another device. Your encrypted draft is preserved locally; review the conflict before saving again.");
        } else {
          await queueSave({ id: note.id, containerID: selected.id, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: selected.keyGeneration });
          syncChannel.current?.postMessage({ type: "queued", id: note.id });
          setSyncStatus("local");
          setError("Saved locally; encrypted change queued for the server.");
        }
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to save note");
    } finally {
      if (!automatic) setBusy(false);
    }
  }

  function save(note: Note, automatic = false) {
    const queued = saveChain.current.then(() => {
      const current = selectedNoteRef.current;
      if (!current || current.id !== note.id) return;
      // Use the latest in-memory note when an older autosave was waiting in
      // the chain. This keeps the server request/version aligned with the
      // document currently shown in the editor.
      return saveNow(current, automatic);
    });
    saveChain.current = queued.catch(() => {});
    return queued;
  }

  async function drainQueue() {
    if (draining.current) return;
    draining.current = true;
    try {
      const queued = await pendingSaves();
      if (!queued.length) return;
      setSyncStatus("syncing");
      let remaining = false;
      let attention = false;
      for (const item of queued) {
        try {
          const result = await saveObject(item.id, item.payload, item.version, item.keyGeneration ?? 1);
          await clearQueuedSave(item.id);
          setNotes((value) => value.map((note) => note.id === item.id ? { ...note, version: result.version, updatedAt: item.updatedAt } : note));
          if (selectedNoteRef.current?.id === item.id) {
            setSelectedNote((note) => note?.id === item.id ? { ...note, version: result.version, updatedAt: item.updatedAt } : note);
            setLastSavedAt(item.updatedAt);
            setDirty(false);
          }
        } catch (error) {
          if (error instanceof APIRequestError && error.code === "version_conflict") {
            await clearQueuedSave(item.id);
            setConflicted((value) => new Set(value).add(item.id));
            attention = true;
          } else {
            remaining = true;
          }
        }
      }
      setSyncStatus(attention ? "attention" : remaining ? "local" : "saved");
    } catch {
      setSyncStatus("local");
    } finally {
      draining.current = false;
    }
  }
  async function remove(note: Note) {
    if (!confirm("Delete this note?")) return;
    try {
      await deleteObject(note.id);
      await deleteCachedNote(note.id);
      setNotes((value) => value.filter((entry) => entry.id !== note.id));
      setSelectedNote(null);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to delete note",
      );
    }
  }
  function persistDraft(note: Note) {
    if (!selected) return;
    void encryptNote(auth.authSecret, selected.id, {
      title: note.title,
      body: note.body,
    })
      .then((payload) =>
        putNote({
          id: note.id,
          containerID: selected.id,
          version: note.version,
          payload,
          updatedAt: new Date().toISOString(),
        }),
      )
      .catch(() => {});
  }
  function editBody(value: string) {
    if (selectedNote) {
      const next = { ...selectedNote, body: value };
      setSelectedNote(next);
      setDirty(true);
      persistDraft(next);
    }
  }
  async function uploadPending(job: Awaited<ReturnType<typeof pendingUploads>>[number]) {
    const status = await uploadStatus(job.uploadId);
    let nextChunk = status.nextChunk;
    let offset = nextChunk * job.chunkBytes;
    setUploadProgress((value) => ({ ...value, [job.uploadId]: { name: job.name, uploaded: status.receivedBytes, total: job.payload.byteLength } }));
    while (offset < job.payload.byteLength) {
      if (cancelledUploads.current.has(job.uploadId)) throw new Error("Upload cancelled");
      const chunk = job.payload.slice(offset, offset + job.chunkBytes);
      const result = await uploadChunk(job.uploadId, nextChunk, chunk);
      nextChunk = result.nextChunk;
      offset += chunk.byteLength;
      await putUpload({ ...job, nextChunk });
      setUploadProgress((value) => ({ ...value, [job.uploadId]: { name: job.name, uploaded: result.receivedBytes, total: job.payload.byteLength } }));
    }
    const finalized = await finalizeUpload(job.uploadId, job.metadataCiphertext, job.keyGeneration);
    await attachToObject(job.objectID, finalized.attachmentId, job.objectVersion);
    await clearUpload(job.uploadId);
    setUploadProgress((value) => { const next = { ...value }; delete next[job.uploadId]; return next; });
    return finalized.attachmentId;
  }
  async function resumeUploads() {
    if (drainingUploads.current) return;
    drainingUploads.current = true;
    try {
      for (const job of await pendingUploads()) {
        try {
          await uploadPending(job);
          setError(`Attachment uploaded: ${job.name}`);
        } catch {
          setUploadProgress((value) => ({ ...value, [job.uploadId]: { name: job.name, uploaded: 0, total: job.payload.byteLength, failed: true } }));
          setError(`Attachment waiting to resume: ${job.name}`);
        }
      }
    } catch { /* IndexedDB is optional until the browser supports it. */ }
    finally { drainingUploads.current = false; }
  }
  async function cancelAttachmentUpload(uploadId: string) {
    cancelledUploads.current.add(uploadId);
    try { await deleteUpload(uploadId); } catch { /* The server may already have expired it. */ }
    await clearUpload(uploadId);
    setUploadProgress((value) => { const next = { ...value }; delete next[uploadId]; return next; });
  }
  async function retryAttachmentUpload(uploadId: string) {
    cancelledUploads.current.delete(uploadId);
    const job = (await pendingUploads()).find((entry) => entry.uploadId === uploadId);
    if (!job) return;
    try { await uploadPending(job); } catch { setError(`Attachment waiting to resume: ${job.name}`); }
  }
  async function uploadAttachment(file: File): Promise<PlainAttachment> {
    if (!selected || !selectedNote) throw new Error("Select a note first");
      const encrypted = await encryptAttachment(auth.authSecret, selected.id, new Uint8Array(await file.arrayBuffer()));
      const digest = await digestSha256Hex(encrypted);
      const upload = await createUpload(selected.id, encrypted.byteLength, digest);
      const metadata = await encryptAttachmentMetadata(auth.authSecret, selected.id, { name: file.name, type: file.type, size: file.size });
      const job = { uploadId: upload.uploadId, containerID: selected.id, objectID: selectedNote.id, objectVersion: selectedNote.version, keyGeneration: selected.keyGeneration, chunkBytes: upload.chunkBytes, nextChunk: upload.nextChunk, payload: encrypted, metadataCiphertext: btoa(String.fromCharCode(...metadata)), name: file.name, type: file.type, size: file.size };
      await putUpload(job);
      const attachmentID = await uploadPending(job);
      return { id: attachmentID, name: file.name, type: file.type, size: file.size };
  }
  async function addAttachment(file: File) {
    if (!selected || !selectedNote) return;
    setBusy(true);
    try {
      const attachment = await uploadAttachment(file);
      setAttachmentsForNote((value) => [...value, attachment]);
      setError("Attachment uploaded and encrypted.");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to upload attachment");
    } finally {
      setBusy(false);
    }
  }
  async function uploadInlineFile(file: File): Promise<string> {
    const attachment = await uploadAttachment(file);
    setAttachmentsForNote((value) => [...value, attachment]);
    return `attachment://${attachment.id}`;
  }
  async function resolveFileUrl(url: string): Promise<string> {
    if (!url.startsWith("attachment://") || !selected) return url;
    const attachmentID = url.slice("attachment://".length);
    const existing = attachmentSources[attachmentID];
    if (existing) return existing;
    const attachment = attachmentsForNote.find((value) => value.id === attachmentID);
    if (!attachment) return url;
    const encrypted = await downloadAttachment(attachment.id);
    const plaintext = await decryptAttachment(auth.authSecret, selected.id, encrypted);
    return URL.createObjectURL(new Blob([plaintext.slice().buffer as ArrayBuffer], { type: attachment.type }));
  }
  async function openAttachment(attachment: PlainAttachment) {
    if (!selected) return;
    try {
      const encrypted = await downloadAttachment(attachment.id);
      const plaintext = await decryptAttachment(auth.authSecret, selected.id, encrypted);
      const url = URL.createObjectURL(new Blob([plaintext.slice().buffer as ArrayBuffer], { type: attachment.type || "application/octet-stream" }));
      const link = document.createElement("a");
      link.href = url; link.download = attachment.name; link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to open attachment");
    }
  }
  async function addComment() {
    if (!selectedNote || !selected || !commentText.trim()) return;
    setBusy(true);
    try {
      const encrypted = await encryptComment(
        auth.authSecret,
        selected.id,
        commentText.trim(),
        commentSection.trim(),
      );
      await createComment(
        selectedNote.id,
        btoa(String.fromCharCode(...encrypted)),
        selected.keyGeneration,
      );
      setCommentText("");
      setCommentSection("");
      await selectNote(selectedNote);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to add comment",
      );
    } finally {
      setBusy(false);
    }
  }
  async function invite() {
    if (!selected) return;
    const userID = prompt("User ID to invite");
    if (!userID) return;
    try {
      const result = await inviteMember(selected.id, userID, "editor");
      setError(`Invitation created. Share token: ${result.token}`);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to invite member",
      );
    }
  }
  async function removeTeamMember(userID: string) {
    if (!selected || !confirm("Remove this person from the team?")) return;
    try {
      await removeMember(selected.id, userID);
      setMembersForTeam(await members(selected.id));
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to remove member",
      );
    }
  }
  async function shareNote() {
    if (!selectedNote) return;
    try {
      const sealed = await encryptSharePayload({
        title: selectedNote.title,
        body: selectedNote.body,
      });
      const link = await createSealedShareLink(
        sealed.ciphertext,
        new Date(Date.now() + 7 * 86400000).toISOString(),
      );
      await navigator.clipboard.writeText(
        `${location.origin}/share/${link.token}#${sealed.key}`,
      );
      setError(
        "Encrypted share link copied. The key is only in the URL fragment.",
      );
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Unable to create encrypted link",
      );
    }
  }
  const personal = items.filter((item) => item.kind !== "team" && !item.teamId);
  const personalWorkspaces = personal;
  const teams = items.filter((item) => item.kind === "team");
  const teamWorkspaces = (teamID: string) => items.filter((item) => item.teamId === teamID);
  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <img src="/app-icon.png" width={29} height={29} alt="" />
          <span>KyNotes</span>
        </div>
        <div className="top-actions">
          <span className={`sync-dot sync-${syncStatus}`}>
            ● {dirty ? "Unsaved changes" : syncStatus === "syncing" ? "Syncing…" : syncStatus === "local" ? "Saved locally" : syncStatus === "attention" ? "Needs attention" : "Saved to server"}
          </span>
          {selectedNote && (
            <button
              className="save-button"
              disabled={busy}
              onClick={() => void save(selectedNote)}
            >
              {busy ? "Saving…" : "Save"}
            </button>
          )}
          <button className="quiet" onClick={() => setView("settings")}>
            Settings
          </button>
          {auth.user.role === "admin" && (
            <button className="quiet" onClick={() => setView("admin")}>
              Admin
            </button>
          )}
          <button className="quiet" onClick={onLogout}>
            Lock
          </button>
        </div>
      </header>
      <>
        <div className={`workspace-view ${view !== "workspace" ? "workspace-view-hidden" : ""}`}>
          <div className="workspace">
          <aside className="sidebar">
            <div className="section-label">FOCUS</div>
            <button
              className={`ky-nav-item nav-item ${queueMode ? "selected" : ""}`}
              aria-current={queueMode ? "page" : undefined}
              disabled={busy}
              onClick={() => void openWorkQueue()}
            >
              <span className="nav-icon">✓</span>
              <span>Work queue</span>
            </button>
            <div className="section-label">PERSONAL</div>
            {personalWorkspaces.map((container) => (
              <button
                className={`ky-nav-item nav-item ${selected?.id === container.id ? "selected" : ""}`}
                aria-current={selected?.id === container.id ? "page" : undefined}
                key={container.id}
                onClick={() => void selectContainer(container)}
              >
                <span className="nav-icon">◈</span>
                <span>{nameOf(container)}</span>
              </button>
            ))}
            <div className="section-label team-label">TEAMS</div>
            {teams.map((container) => (
              <React.Fragment key={container.id}>
                <button
                  className={`ky-nav-item nav-item ${selected?.id === container.id ? "selected" : ""}`}
                  aria-current={selected?.id === container.id ? "page" : undefined}
                  onClick={() => void selectContainer(container)}
                >
                  <span className="nav-icon">◇</span>
                  <span>{nameOf(container)}</span>
                </button>
                {teamWorkspaces(container.id).map((workspace) => (
                  <button
                    className={`ky-nav-item nav-item nested-nav-item ${selected?.id === workspace.id ? "selected" : ""}`}
                    aria-current={selected?.id === workspace.id ? "page" : undefined}
                    key={workspace.id}
                    onClick={() => void selectContainer(workspace)}
                  >
                    <span className="nav-icon">◈</span>
                    <span>{nameOf(workspace)}</span>
                  </button>
                ))}
                {selected?.id === container.id && (
                  <button className="new-workspace" disabled={busy} onClick={() => void newTeamWorkspace(container)}>
                    ＋ New team workspace
                  </button>
                )}
              </React.Fragment>
            ))}
            <button
              className="new-workspace personal-create"
              disabled={busy}
              onClick={() => void newWorkspace()}
            >
              ＋ New personal workspace
            </button>
            {selected && (
              <button
                className="new-workspace"
                disabled={busy}
                onClick={() => void renameWorkspace()}
              >
                ✎ Rename workspace
              </button>
            )}
            {selected?.kind === "team" && (
              <>
                <button className="new-workspace" onClick={() => void invite()}>
                  ＋ Add person
                </button>
                {membersForTeam.map((member) => (
                  <div className="member-row" key={member.userId}>
                    <span>
                      {member.username} · {member.role}
                    </span>
                    {member.userId !== auth.user.id && (
                      <button
                        className="quiet"
                        onClick={() => void removeTeamMember(member.userId)}
                      >
                        Remove
                      </button>
                    )}
                  </div>
                ))}
              </>
            )}
            <div className="sidebar-bottom">
              <div className="section-label">ACCOUNT</div>
              <div className="account-chip">
                <span className="avatar">{auth.user.id.slice(-2)}</span>
                <span>{auth.username || auth.user.id.slice(0, 12)}</span>
              </div>
            </div>
          </aside>
          <section className="note-list">
            <div className="list-header">
              <div>
                <div className="section-label">
                  {selected ? nameOf(selected) : "WORKSPACE"}
                </div>
                <h2 className="workspace-title">{queueMode ? "Work queue" : selected ? nameOf(selected) : "Select a workspace"}</h2>
                {queueMode ? <div className="workspace-kind">Open tasks across personal workspaces</div> : selected && <div className="workspace-kind">{selected.kind === "team" ? "Team workspace" : "Personal workspace"}</div>}
                {selected && <h3 className="notes-heading">{queueMode ? `${listEntries.length} task note${listEntries.length === 1 ? "" : "s"}` : "Notes"}</h3>}
              </div>
              <div className="list-actions">
                <input
                  aria-label="Search notes"
                  className="note-search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search"
                />
                <select
                  value={sort}
                  onChange={(event) =>
                    setSort(event.target.value as "updated" | "title")
                  }
                >
                  <option value="updated">Recent</option>
                  <option value="title">Title</option>
                </select>
                <button
                  className="icon-button"
                  disabled={!selected || busy}
                  onClick={() => void newNote()}
                >
                  ＋
                </button>
              </div>
            </div>
            {listEntries.map(({ note, container }) => (
              <div
                className={`note-row-wrap ${selectedNote?.id === note.id ? "selected" : ""}`}
                key={note.id}
              >
                <button
                  className="note-row"
                  onClick={() => void (queueMode ? selectQueueNote({ note, container }) : selectNote(note))}
                >
                  <strong>{note.title || "Untitled note"}</strong>
                  <span>
                    {(queueMode ? noteTasks(indexNotes([note])[0]).slice(0, 2).join(" · ") : documentText(note.body).slice(0, 64)) ||
                      "Empty note"}
                  </span>
                </button>
                <button
                  className="pin-button"
                  title={pinned.has(note.id) ? "Unpin note" : "Pin note"}
                  onClick={() => togglePin(note)}
                >
                  {pinned.has(note.id) ? "★" : "☆"}
                </button>
              </div>
            ))}
            {selected && listEntries.length === 0 && (
              <div className="empty-list">
                {queueMode ? "No open tasks here." : "No notes yet."}
                <br />
                {queueMode ? "Tasks from note checklists appear here." : "Create the first one."}
              </div>
            )}
            {relatedNotes.length > 0 && (
              <div className="context-panel">
                <div className="section-label">RESURFACING</div>
                {relatedNotes.map((note) => (
                  <button
                    className="context-link"
                    key={note.id}
                    onClick={() => void selectNote(note)}
                  >
                    {note.title || "Untitled note"}
                  </button>
                ))}
              </div>
            )}
            {links.length > 0 && (
              <div className="context-panel">
                <div className="section-label">KNOWLEDGE GRAPH</div>
                <span className="config-muted">
                  {links.length} local link{links.length === 1 ? "" : "s"}
                </span>
              </div>
            )}
          </section>
          <section className="editor">
            <div className="editor-meta">
              <span>
                {selectedNote
                  ? `Version ${selectedNote.version || "draft"}`
                  : "Ready"}
              </span>
              <span className="encrypted">
                {dirty
                  ? "Autosaving…"
                  : syncStatus === "local"
                    ? "Encrypted locally · waiting to sync"
                    : syncStatus === "attention"
                      ? "Conflict needs attention"
                      : lastSavedAt
                        ? `Saved on server ${new Date(lastSavedAt).toLocaleTimeString()}`
                        : "Encrypted locally"}
              </span>
            </div>
            {selectedNote ? (
              <>
                {conflicted.has(selectedNote.id) && (
                  <div className="conflict-banner" role="alert">
                    This note has a newer encrypted version on the server. Your local draft is preserved; reload the note before saving again.
                  </div>
                )}
                <input
                  className="title-input"
                  value={selectedNote.title}
                  onChange={(event) => {
                    const next = { ...selectedNote, title: event.target.value };
                    setSelectedNote(next);
                    setDirty(true);
                    persistDraft(next);
                  }}
                />
                <div className="single-pane-editor">
                  <Suspense fallback={<div className="blocknote-editor editor-loading">Loading editor…</div>}>
                    <BlockNoteEditor
                      key={selectedNote.id}
                      noteID={selectedNote.id}
                      initialContent={parseNoteDocument(selectedNote.body).document}
                      legacyMarkdown={isStructuredNoteBody(selectedNote.body) ? undefined : selectedNote.body}
                      onChange={(document: Block[]) => editBody(stringifyNoteDocument(document))}
                      uploadFile={uploadInlineFile}
                      resolveFileUrl={resolveFileUrl}
                    />
                  </Suspense>
                </div>
                <div className="editor-actions">
                  <button
                    className="danger quiet"
                    onClick={() => void remove(selectedNote)}
                  >
                    Delete
                  </button>
                  <button
                    disabled={busy}
                    onClick={() => void save(selectedNote)}
                  >
                    {busy ? "Saving…" : dirty ? "Save now" : "Saved"}
                  </button>
                </div>
                <section className="comments">
                  <h3>Comments</h3>
                  {commentsForNote.map((comment) => (
                    <div className="comment" key={comment.id}>
                      <strong>
                        {comment.username}
                        {comment.section ? ` · § ${comment.section}` : ""}
                      </strong>
                      <span>{comment.body}</span>
                    </div>
                  ))}
                  <div className="comment-compose">
                    <input
                      value={commentSection}
                      onChange={(event) =>
                        setCommentSection(event.target.value)
                      }
                      placeholder="Section (optional)"
                    />
                    <input
                      value={commentText}
                      onChange={(event) => setCommentText(event.target.value)}
                      placeholder="Add a comment…"
                    />
                    <button disabled={busy} onClick={() => void addComment()}>
                      Comment
                    </button>
                  </div>
                </section>
                <section className="attachments">
                  <h3>Attachments</h3>
                  {Object.entries(uploadProgress).map(([uploadId, progress]) => (
                    <div className="upload-row" key={uploadId}>
                      <span>{progress.name} · {progress.failed ? "waiting to retry" : `${Math.round(progress.uploaded / Math.max(progress.total, 1) * 100)}%`}</span>
                      <div className="upload-actions">
                        {progress.failed && <button className="quiet" onClick={() => void retryAttachmentUpload(uploadId)}>Retry</button>}
                        <button className="quiet" onClick={() => void cancelAttachmentUpload(uploadId)}>Cancel</button>
                      </div>
                    </div>
                  ))}
                  {attachmentsForNote.map((attachment) => (
                    <button className="attachment-row" key={attachment.id} onClick={() => void openAttachment(attachment)}>
                      <strong>{attachment.name}</strong>
                      <span>{Math.ceil(attachment.size / 1024)} KB</span>
                    </button>
                  ))}
                  <label className="attachment-picker">
                    <span>＋ Add encrypted file</span>
                    <input type="file" disabled={busy} onChange={(event) => { const file = event.target.files?.[0]; if (file) void addAttachment(file); event.currentTarget.value = ""; }} />
                  </label>
                </section>
              </>
            ) : (
              <div className="empty-editor">
                <div className="empty-glyph">✦</div>
                <h2>Your private desk.</h2>
                <p>
                  Select a note or create one. The server receives ciphertext
                  only.
                </p>
                {selected && (
                  <button onClick={() => void newNote()}>Create a note</button>
                )}
              </div>
            )}
          </section>
          </div>
        </div>
        {view !== "workspace" && (
          <SettingsView
            admin={view === "admin"}
            authSecret={auth.authSecret}
            username={auth.username}
            onBack={() => setView("workspace")}
            onForgetDevice={onForgetDevice}
          />
        )}
      </>
      {commitToastAt && commitToastVisible(commitToastAt) && (
        <button className="toast commit-toast" onClick={() => setCommitToastAt(null)}>
          {commitToastLabel(commitToastAt)} ×
        </button>
      )}
      {error && (
        <button className="toast error" onClick={() => setError("")}>
          {error} ×
        </button>
      )}
    </main>
  );
}

function PasswordSettings({ username }: { username: string }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const confirmation = (
      (event.currentTarget as HTMLFormElement).elements.namedItem(
        "confirm",
      ) as HTMLInputElement
    )?.value;
    if (!next || next !== confirmation) {
      setStatus("New passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      const name = username || prompt("Username")?.trim();
      if (!name) throw new Error("Username is required");
      const oldParams = await loginParams(name);
      const currentAuthSecret = await deriveAuthSecret(
        current,
        oldParams.loginSalt,
        oldParams.iterations,
      );
      const newLoginSalt = randomLoginSalt();
      const newAuthSecret = await deriveAuthSecret(next, newLoginSalt, 600000);
      await changePassword({
        currentAuthSecret,
        newAuthSecret,
        newLoginSalt,
        iterations: 600000,
      });
      await storeDeviceKey(name, newAuthSecret);
      setCurrent("");
      setNext("");
      setStatus(
        "Password changed. Existing encrypted notes may require the device re-key flow.",
      );
    } catch (error) {
      setStatus(
        error instanceof Error ? error.message : "Unable to change password",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="config-card">
      <h2>Change password</h2>
      <p className="config-muted">
        Passwords are converted to client-derived secrets in this browser. They
        are never sent to the server.
      </p>
      <form onSubmit={submit}>
        <label className="field">
          <span>Current password</span>
          <input
            type="password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            required
          />
        </label>
        <label className="field">
          <span>New password</span>
          <input
            type="password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            required
          />
        </label>
        <label className="field">
          <span>Confirm new password</span>
          <input name="confirm" type="password" required />
        </label>
        <button disabled={busy}>
          {busy ? "Changing…" : "Change password"}
        </button>
      </form>
      {status && <p className="status-line">{status}</p>}
    </section>
  );
}

function AdminCreateUser({ onCreated }: { onCreated: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
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
        role,
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
      <select value={role} onChange={(event) => setRole(event.target.value)}>
        <option>user</option>
        <option>admin</option>
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
      alert("Password reset. All existing sessions were revoked.");
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

function AdminTeams({ users, authSecret }: { users: AdminUser[]; authSecret: string }) {
  const [teams, setTeams] = useState<AdminTeam[]>([]);
  const [teamNames, setTeamNames] = useState<Record<string, string>>({});
  const [team, setTeam] = useState("");
  const [user, setUser] = useState("");
  const [role, setRole] = useState("editor");
  async function reload() {
    try {
      const nextTeams = await adminTeams();
      const nextNames: Record<string, string> = {};
      for (const entry of nextTeams) {
        if (!entry.metaCiphertext) continue;
        try {
          nextNames[entry.id] = (
            await decryptContainerMeta(authSecret, entry.id, fromBase64(entry.metaCiphertext))
          ).name;
        } catch {
          /* Metadata encrypted by another account remains opaque. */
        }
      }
      setTeams(nextTeams);
      setTeamNames(nextNames);
    } catch {
      /* The admin page remains usable if the list refresh is unavailable. */
    }
  }
  useEffect(() => {
    void reload();
  }, [authSecret]);
  async function createTeam() {
    const name = prompt("Team name", "New team")?.trim();
    if (!name) return;
    try {
      // The server mints the container ID, which is part of the metadata key.
      // Create first, then immediately replace the empty metadata with ciphertext.
      const created = await createAdminTeam("");
      const encrypted = await encryptContainerMeta(authSecret, created.id, name);
      const encoded = btoa(String.fromCharCode(...encrypted));
      await updateContainer(created.id, encoded, created.metaVersion ?? 0);
      setTeam(created.id);
      await reload();
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to create team");
    }
  }
  async function renameTeam() {
    const selected = teams.find((entry) => entry.id === team);
    if (!selected) return;
    const name = prompt("Team name", teamNames[selected.id] ?? "Team")?.trim();
    if (!name) return;
    try {
      const encrypted = await encryptContainerMeta(authSecret, selected.id, name);
      const encoded = btoa(String.fromCharCode(...encrypted));
      await updateContainer(selected.id, encoded, selected.metaVersion ?? 0);
      await reload();
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to rename team");
    }
  }
  async function add() {
    if (!team || !user) return;
    try {
      await addAdminTeamMember(team, user, role);
      alert("Person added to team.");
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to add person");
    }
  }
  return (
    <section className="config-card">
      <h2>Teams</h2>
      <p className="config-muted">
        Create a team workspace, then add active users to it.
      </p>
      <button onClick={() => void createTeam()}>Create team</button>
      <label className="field">
        <span>Team</span>
        <select value={team} onChange={(event) => setTeam(event.target.value)}>
          <option value="">Select team</option>
          {teams.map((entry) => (
            <option key={entry.id} value={entry.id}>
              {teamNames[entry.id] ?? "Unnamed team"} · {entry.id}
            </option>
          ))}
        </select>
      </label>
      <button className="quiet" onClick={() => void renameTeam()} disabled={!team}>
        Rename team
      </button>
      <label className="field">
        <span>Person</span>
        <select value={user} onChange={(event) => setUser(event.target.value)}>
          <option value="">Select person</option>
          {users
            .filter((entry) => entry.status === "active")
            .map((entry) => (
              <option key={entry.id} value={entry.id}>
                {entry.username}
              </option>
            ))}
        </select>
      </label>
      <label className="field">
        <span>Role</span>
        <select value={role} onChange={(event) => setRole(event.target.value)}>
          <option>admin</option>
          <option>editor</option>
          <option>commenter</option>
          <option>viewer</option>
        </select>
      </label>
      <button onClick={() => void add()}>Add to team</button>
    </section>
  );
}

function AdminSSO() {
  const [settings, setSettings] = useState<SSOSettings | null>(null);
  const [pairingToken, setPairingToken] = useState("");
  const [pairingIssuer, setPairingIssuer] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);

  useEffect(() => {
    void adminSSO().then(setSettings).catch(() => {});
  }, []);

  async function handlePair(e: React.FormEvent) {
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

  async function handleSave(e: React.FormEvent) {
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
          <span>Client Secret (Optional for PKCE)</span>
          <input
            type="password"
            value={settings.clientSecret ?? ""}
            onChange={(e) => setSettings({ ...settings, clientSecret: e.target.value })}
            placeholder="••••••••"
          />
        </label>
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

function SettingsView({
  admin,
  authSecret,
  onBack,
  username,
  onForgetDevice,
}: {
  admin: boolean;
  authSecret: string;
  onBack: () => void;
  username: string;
  onForgetDevice?: () => void;
}) {
  const [theme, setTheme] = useState<ThemeName>(getStoredTheme());
  const [status, setStatus] = useState<{
    health: boolean;
    ready: boolean;
  } | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [audit, setAudit] = useState<Array<Record<string, string>>>([]);
  useEffect(() => {
    if (admin) {
      void Promise.all([adminUsers(), adminAudit(), serviceStatus()])
        .then(([nextUsers, nextAudit, nextStatus]) => {
          setUsers(nextUsers);
          setAudit(nextAudit);
          setStatus(nextStatus);
        })
        .catch(() => {});
    }
  }, [admin]);
  async function saveUser(user: AdminUser) {
    try {
      await updateAdminUser(user);
      setUsers((value) =>
        value.map((entry) => (entry.id === user.id ? user : entry)),
      );
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to update user");
    }
  }
  return (
    <section
      className={`settings-layout ${admin ? "admin-settings-layout" : ""}`}
    >
      <aside className="settings-sidebar">
        <button className="quiet" onClick={onBack}>
          ← Workspace
        </button>
        <div className="section-label">{admin ? "ADMIN" : "SETTINGS"}</div>
        {!admin && (
          <nav className="settings-nav">
            <a href="#appearance">Appearance</a>
            <a href="#password">Password</a>
            <a href="#device">Trusted Device</a>
          </nav>
        )}
      </aside>
      <div className="settings-content">
        <div className="settings-header">
          <div className="section-label">{admin ? "ADMIN" : "PREFERENCES"}</div>
          <h1>{admin ? "Administration" : "Settings"}</h1>
          <p>
            {admin
              ? "Manage people, teams, and metadata-only audit records."
              : "Your browser preferences and account security."}
          </p>
        </div>
        {admin && (
          <nav className="settings-nav admin-main-tabs" aria-label="Administration sections">
            <a href="#server">Server</a>
            <a href="#sso">Single Sign-On</a>
            <a href="#users">Users</a>
            <a href="#teams">Teams</a>
            <a href="#audit">Audit log</a>
 <a href="#backups">Backups</a>
          </nav>
        )}
        {!admin && (
          <>
            <section id="appearance" className="config-card">
              <h2>Appearance</h2>
              <p className="config-muted">
                Choose from the complete KyNotes color selection.
              </p>
              <label className="field">
                <span>Theme</span>
                <select
                  value={theme}
                  onChange={(event) =>
                    setTheme(event.target.value as ThemeName)
                  }
                >
                  {THEME_OPTIONS.map((option) => (
                    <option key={option}>{option}</option>
                  ))}
                </select>
              </label>
              <button onClick={() => applyTheme(theme)}>Apply theme</button>
            </section>
            <div id="password">
              <PasswordSettings username={username} />
            </div>
            <section id="device" className="config-card">
              <h2>Trusted Device & SSO</h2>
              <p className="config-muted">
                This browser holds your local zero-knowledge encryption key to allow instant 1-click SSO login without entering a password.
              </p>
              {onForgetDevice && (
                <button
                  type="button"
                  className="secondary danger"
                  onClick={onForgetDevice}
                >
                  Forget this device & sign out
                </button>
              )}
            </section>
          </>
        )}
        {admin && (
          <>
            <section id="server" className="config-card">
              <h2>Server status</h2>
              <p className="status-line">
                Health:{" "}
                {status ? (status.health ? "OK" : "failed") : "checking…"} ·
                Readiness:{" "}
                {status ? (status.ready ? "OK" : "failed") : "checking…"}
              </p>
            </section>
            <AdminSSO />
 <AdminBackup username={username} />
            <section id="users" className="config-card">
              <h2>Users</h2>
              <ConfirmPassword username={username} what="User creation and password resets" />
              <AdminCreateUser
                onCreated={() => void adminUsers().then(setUsers)}
              />
              {users.map((user) => (
                <div className="admin-user" key={user.id}>
                  <strong>{user.username}</strong>
                  <select
                    value={user.role}
                    onChange={(event) =>
                      void saveUser({ ...user, role: event.target.value })
                    }
                  >
                    <option>user</option>
                    <option>admin</option>
                  </select>
                  <select
                    value={user.status}
                    onChange={(event) =>
                      void saveUser({ ...user, status: event.target.value })
                    }
                  >
                    <option>active</option>
                    <option>disabled</option>
                  </select>
                  <AdminUserActions user={user} onReset={() => {}} />
                </div>
              ))}
            </section>
            <div id="teams">
              <AdminTeams users={users} authSecret={authSecret} />
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
          </>
        )}
      </div>
    </section>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
