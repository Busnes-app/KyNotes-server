import { AdminBackup } from "./components/AdminBackup";
import { ConfirmPassword } from "./components/ConfirmPassword";
import React, { lazy, Suspense, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
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
  conflictCiphertext,
  resolveConflict,
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
  identityAPI,
} from "./api";
import { ensureIdentity, rewrapIdentity, type IdentityRecord } from "./identity";
import { PASSWORD_CHANGE_WARNING, passwordChangeProblem } from "./passwordChange";
import {
  decryptComment,
  decryptAttachment,
  decryptAttachmentMetadata,
  decryptContainerMeta,
  decryptObject,
  decryptSharePayload,
  deriveAuthSecret,
  deriveLoginKeys,
  type LoginKeys,
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
import { QUICK_NOTES, SECTION_COLORS, compareOrdered, conflictCopy, groupConflicts, endOrder, formatRoute, pagesInSection, parseRoute, reorder, resolveSection, sortedSections, type Group, type ObjectPayload, type PagePayload, type Route, type Section, type SectionPayload } from "./pages";
import { PAGE_DRAG, SectionTabs } from "./components/SectionTabs";
import { carryAll, carrySaved, carryVersions, editEntry, editOpenEntry, flushUntilStable, newestCopy, notePayload, samePayload } from "./notes";
import { MAX_GROUP_DEPTH, ancestors, blockRange, displayLevels, dropBefore, groupMoveAllowed, groupOfSection, groupParents, groupPath, groupTargets, parseCollapsed, placeBlock, sectionGroup, sectionTargets, shiftLevel, siblingMove, visibleRows } from "./outline";
import { readChoice, saveChoice } from "./ky-ui/theme";
import {
  clearDeviceKey,
  clearQueuedSave,
  deleteNote as deleteCachedNote,
  getDeviceKey,
  getIdentityKey,
  getNote,
  clearUpload,
  pendingSaves,
  pendingUploads,
  putNote,
  putUpload,
  queueSave,
  rememberAfter,
  storeDeviceKey,
  storeIdentityKey,
} from "./storage";

/** Loads or creates the identity after a password sign-in. P1 has no consumer, so failures stay silent. */
function settleIdentity(username: string, userID: string, keys: LoginKeys, fromLogin?: IdentityRecord) {
  void ensureIdentity(identityAPI, userID, keys, fromLogin)
    .then((identity) => identity && storeIdentityKey(username, userID, identity))
    .catch(() => undefined);
}
import {
  applyStoredTheme,
  applyTheme,
  getStoredTheme,
  THEME_OPTIONS,
  type ThemeName,
} from "./theme";
import { contextualNotes, graphEdges, indexNotes, noteTasks, openTaskNotes, searchNotes } from "./knowledge";
import { documentText, emptyCanvasPage, stringifyCanvasPage } from "./document";
import { commitToastLabel, commitToastVisible, COMMIT_TOAST_DURATION_MS } from "./commitToast";
import "./styles.css";
import "./ky-ui/tokens.css";
import "./ky-ui/navigation.css";

const MAX_CHANGE_PAGES = 100;
const FLUSH_ROUNDS = 5;

const CanvasPage = lazy(() => import("./CanvasPage"));

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
      const keys = await deriveLoginKeys(password, salt, iterations);
      const authSecret = keys.authSecret;
      // The password stays in the browser; the server only ever sees authSecret.
      const result = await rememberAfter(() => setupInit(name, undefined, authSecret, salt, iterations), name, authSecret);
      sessionStorage.setItem("kynotes-last-username", name);
      onLogin({ username: name, authSecret, user: result.user });
      settleIdentity(name, result.user.id, keys);
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
      const keys = await deriveLoginKeys(password, params.loginSalt, params.iterations);
      const authSecret = keys.authSecret;
      if (sessionUser) {
        // If SSO session is active, verify credentials or enter directly
        try {
          const result = await rememberAfter(() => login(activeName, authSecret), activeName, authSecret);
          sessionStorage.setItem("kynotes-last-username", activeName);
          onLogin({ username: activeName, authSecret, user: result.user });
          settleIdentity(activeName, result.user.id, keys, result.identity);
        } catch {
          // If login endpoint failed but SSO session is valid, allow user entry with their derived key
          await storeDeviceKey(activeName, authSecret).catch(() => undefined);
          sessionStorage.setItem("kynotes-last-username", activeName);
          onLogin({ username: activeName, authSecret, user: sessionUser });
        }
      } else {
        const result = await rememberAfter(() => login(activeName, authSecret), activeName, authSecret);
        sessionStorage.setItem("kynotes-last-username", activeName);
        onLogin({ username: activeName, authSecret, user: result.user });
        settleIdentity(activeName, result.user.id, keys, result.identity);
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
  const notesRef = useRef<Note[]>([]);
  notesRef.current = notes;
  // Chained writes read notesRef before React renders, so they patch it directly.
  const patchNotes = (update: (value: Note[]) => Note[]) => {
    notesRef.current = update(notesRef.current);
    setNotes((value) => update(value));
  };
  const [sections, setSections] = useState<Section[]>([]);
  const sectionsRef = useRef<Section[]>([]);
  // Writes read sectionsRef synchronously, so every change goes through here.
  const patchSections = (update: (value: Section[]) => Section[]) => {
    sectionsRef.current = update(sectionsRef.current);
    setSections(sectionsRef.current);
  };
  const [groups, setGroups] = useState<Group[]>([]);
  const groupsRef = useRef<Group[]>([]);
  const patchGroups = (update: (value: Group[]) => Group[]) => {
    groupsRef.current = update(groupsRef.current);
    setGroups(groupsRef.current);
  };
  const parents = useMemo(() => groupParents(groups), [groups]);
  const [sectionID, setSectionID] = useState<string>(QUICK_NOTES);
  // The group whose tabs are shown; undefined is the notebook root.
  const [groupID, setGroupID] = useState<string | undefined>(undefined);
  const showSection = (id: string) => {
    setSectionID(id);
    setGroupID(groupOfSection(id, sectionsRef.current, groupParents(groupsRef.current)));
  };
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
  const selectedRef = useRef<Container | null>(null);
  selectedRef.current = selected;
  selectedNoteRef.current = selectedNote;
  const [notificationCount, setNotificationCount] = useState(0);
  const [membersForTeam, setMembersForTeam] = useState<
    Array<{ userId: string; username: string; role: string }>
  >([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  // Leave sites read dirtiness synchronously; a closure's `dirty` lags a save that just finished.
  const dirtyRef = useRef(false);
  const markDirty = (value: boolean) => { dirtyRef.current = value; setDirty(value); };
  // Bumped to remount the open page's editor on content it did not produce.
  const [editorRevision, setEditorRevision] = useState(0);
  // The page a conflict recovery is rewriting; it stays read-only until the run ends.
  const [recovering, setRecovering] = useState<string | null>(null);
  const recoveringRef = useRef(false);
  const [view, setView] = useState<"workspace" | "settings" | "admin">(
    "workspace",
  );
  const [queueMode, setQueueMode] = useState(false);
  const [loadingContainer, setLoadingContainer] = useState(false);
  const loadingContainerID = useRef<string | undefined>(undefined);
  // Versions saved while a load reads; the load's fresh list would otherwise drop them.
  const loadCarried = useRef(new Map<string, { version: number; updatedAt?: string }>());
  const carryDuringLoad = (id: string, saved: { version: number; updatedAt?: string }) => {
    if (loadingContainerID.current) loadCarried.current.set(id, saved);
  };
  // Cache writes apply in call order, so an older body never lands last.
  const cacheChain = useRef<Promise<unknown>>(Promise.resolve());
  const cacheWrite = (write: () => Promise<unknown>) => {
    const run = cacheChain.current.then(write);
    cacheChain.current = run.catch(() => {});
    return run;
  };
  const [query, setQuery] = useState("");
  const [commitToastAt, setCommitToastAt] = useState<number | null>(null);
  const [, setCommitToastTick] = useState(0);
  const nameOf = (container: Container) =>
    names[container.id] || `Notebook ${container.id.slice(4, 10)}`;
  // Every keystroke patches notes; the search/graph index catches up off the typing path.
  const settledNotes = useDeferredValue(notes);
  const orderedNotes = useMemo(() => [...settledNotes].sort(compareOrdered), [settledNotes]);
  const sectionPages = useMemo(() => pagesInSection(notes, sections, sectionID), [notes, sections, sectionID]);
  const sectionLevels = useMemo(() => displayLevels(sectionPages), [sectionPages]);
  const collapsedKey = selected ? `kynotes-collapsed-${auth.user.id}-${selected.id}` : "";
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  useEffect(() => {
    setCollapsed(parseCollapsed(collapsedKey ? readChoice(collapsedKey) : null));
  }, [collapsedKey]);
  function toggleCollapsed(id: string) {
    const ids = new Set(notesRef.current.map((note) => note.id));
    const next = [...collapsed].filter((entry) => entry !== id && ids.has(entry));
    if (!collapsed.has(id)) next.push(id);
    // Blocked storage just leaves collapse unpersisted.
    if (collapsedKey) saveChoice(collapsedKey, JSON.stringify(next));
    setCollapsed(new Set(next));
  }
  const revealPage = (list: Note[], id: string) => {
    const above = ancestors(list, id);
    setCollapsed((value) => above.some((entry) => value.has(entry)) ? new Set([...value].filter((entry) => !above.includes(entry))) : value);
  };
  // A page opened from search, resurfacing or a link is never hidden under a collapsed parent.
  useEffect(() => {
    const id = selectedNote?.id;
    if (id) revealPage(sectionPages, id);
    // Only on opening a page: collapsing the open page's parent afterwards is allowed.
  }, [selectedNote?.id, sectionID, collapsedKey]);
  const sectionTitle = (id?: string) => sections.find((entry) => entry.id === id)?.title ?? "Quick Notes";
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
    : (query.trim() ? visibleNotes : sectionPages)
        .map((note) => ({ note, container: selected }))
        .filter((entry): entry is QueueEntry => Boolean(entry.container));
  const reorderable = !queueMode && !query.trim();
  // An open group with no sections: the strip has no tab for sectionID, so no page list or new page.
  const sectionHidden = !queueMode && groupOfSection(sectionID, sections, parents) !== groupID;
  const groupEmpty = sectionHidden && reorderable;
  const listRows = reorderable && selected
    ? visibleRows(sectionHidden ? [] : sectionPages, collapsed).map((row) => ({ note: row.item, container: selected, row }))
    : listEntries.map((entry) => ({ ...entry, row: undefined }));
  const sectionIndex = (id: string) => sectionPages.findIndex((note) => note.id === id);
  const canShift = (id: string, delta: 1 | -1) => sectionIndex(id) >= 0 && shiftLevel(sectionPages, sectionIndex(id), delta) !== undefined;
  // Group menus ask for targets every render; recompute only when the groups change.
  const moveTargets = useMemo(() => {
    const cache = new Map<string, ReturnType<typeof groupTargets>>();
    return (kind: "section" | "group", id: string) => {
      const key = kind === "group" ? id : "";
      if (!cache.has(key)) cache.set(key, groupTargets(groups, parents, kind === "group" ? id : undefined));
      return cache.get(key)!;
    };
  }, [groups, parents]);
  const subpageCount = (id: string) => {
    const [start, end] = blockRange(sectionLevels, sectionIndex(id));
    return end - start - 1;
  };
  const beforeAt = (index: number | undefined) => index === undefined ? undefined : sectionPages[index]?.id ?? null;
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
    if (queueMode || loadingContainer || !selected) return;
    const next = formatRoute({ container: selected.id, section: sectionID, page: selectedNote?.id });
    if (location.hash === next) return;
    // Normalizing an empty or unparseable hash must not add a history entry.
    if (parseRoute(location.hash).container) location.hash = next;
    else history.replaceState(null, "", next);
  }, [queueMode, loadingContainer, selected?.id, sectionID, selectedNote?.id]);
  useEffect(() => {
    const follow = () => void (async () => {
      const route = parseRoute(location.hash);
      const container = items.find((item) => item.id === route.container);
      // Our own hash writes match the current state and stop here.
      if (!container || route.container === loadingContainerID.current || (container.id === selected?.id && route.section === sectionID && route.page === selectedNote?.id)) return;
      // A refused leave keeps the open page, so the URL goes back to it without a history entry.
      const stay = () => selected && history.replaceState(null, "", formatRoute({ container: selected.id, section: sectionID, page: selectedNoteRef.current?.id }));
      if (container.id !== selected?.id) { if (!(await selectContainer(container, route))) stay(); return; }
      const page = notes.find((note) => note.id === route.page);
      if (route.page !== selectedNoteRef.current?.id && !(await flushOpenPage())) { stay(); return; }
      showSection(resolveSection(route.section, sections));
      if (page) { if (!(await selectNote(page))) stay(); }
      else if (!parseRoute(location.hash).page) setSelectedNote(null);
    })();
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, [items, selected?.id, sectionID, selectedNote?.id, notes, sections]);
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
      const route = parseRoute(location.hash);
      const start = loaded.find((item) => item.id === route.container) ?? loaded[0];
      if (start) await selectContainer(start, start.id === route.container ? route : undefined);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to load notebooks",
      );
    }
  }
  async function readContainerObjects(container: Container): Promise<{ notes: Note[]; sections: Section[]; groups: Group[] }> {
    const loaded: Note[] = [];
    const found: Section[] = [];
    const foundGroups: Group[] = [];
    const add = (id: string, payload: ObjectPayload | undefined, version: number, updatedAt: string) => {
      if (!payload) return;
      if (payload.type === "section") found.push({ ...payload, id, version });
      else if (payload.type === "group") foundGroups.push({ ...payload, id, version });
      else loaded.push({ id, title: payload.title, body: payload.body, section: payload.section, order: payload.order, level: payload.level, version, updatedAt });
    };
    let since = 0;
    for (let page = 0; page < MAX_CHANGE_PAGES; page += 1) {
      const result = await changes(container.id, since);
      for (const change of result.changes.filter((entry) => entry.kind === "object" && !entry.deleted)) {
        try {
          const object = await readObject(change.id);
          const cached = await getNote(change.id);
          const useCache = Boolean(cached && cached.version >= object.version);
          const payload = await decryptObject(auth.authSecret, container.id, useCache ? cached!.payload : object.bytes);
          add(change.id, payload, useCache ? cached!.version : object.version, useCache ? cached!.updatedAt : new Date().toISOString());
        } catch {
          const cached = await getNote(change.id);
          if (cached) {
            try {
              add(change.id, await decryptObject(auth.authSecret, container.id, cached.payload), cached.version, cached.updatedAt);
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
    return { notes: loaded, sections: found, groups: foundGroups };
  }
  /** Null when the open page could not be flushed and stays open. */
  async function selectContainer(container: Container, route?: Route): Promise<Note[] | null> {
    loadingContainerID.current = container.id;
    setLoadingContainer(true);
    try {
      return await loadContainer(container, route);
    } finally {
      // A later switch owns the flag now.
      if (loadingContainerID.current === container.id) {
        loadingContainerID.current = undefined;
        setLoadingContainer(false);
      }
    }
  }
  async function loadContainer(container: Container, route?: Route): Promise<Note[] | null> {
    // Workspace navigation destroys the current editor. Finish its latest
    // encrypted save before replacing the note list so the next load cannot
    // fall back to an older plain document.
    if (!(await flushOpenPage())) return null;
    // Another switch started meanwhile: its results win.
    const superseded = () => loadingContainerID.current !== container.id;
    if (superseded()) return [];
    // Nothing from the previous notebook may stay editable under this one's key.
    setSelected(container);
    setQueueMode(false);
    selectedNoteRef.current = null;
    setSelectedNote(null);
    patchNotes(() => []);
    patchSections(() => []);
    patchGroups(() => []);
    setGroupID(undefined);
    setCommentsForNote([]);
    setAttachmentsForNote([]);
    loadCarried.current.clear();
    try {
      const objects = await readContainerObjects(container);
      if (superseded()) return [];
      const loaded = carryAll(objects.notes, loadCarried.current);
      const loadedSections = carryVersions(objects.sections, loadCarried.current);
      patchSections(() => loadedSections);
      patchGroups(() => carryVersions(objects.groups, loadCarried.current));
      loadCarried.current.clear();
      patchNotes(() => loaded);
      showSection(resolveSection(route?.section, loadedSections));
      const routed = route?.page ? loaded.find((note) => note.id === route.page) : undefined;
      if (routed) await selectNote(routed, container.id);
      const team = container.kind === "team" ? await members(container.id) : [];
      if (!superseded()) setMembersForTeam(team);
      return loaded;
    } catch (error) {
      if (!superseded()) setError(error instanceof Error ? error.message : "Unable to load notebook");
      return [];
    }
  }
  async function openWorkQueue() {
    setView("workspace");
    setQueueMode(true);
    setBusy(true);
    try {
      const personalContainers = items.filter((item) => item.kind !== "team" && !item.teamId);
      const results = await Promise.allSettled(personalContainers.map(async (container) => ({
        container,
        notes: (await readContainerObjects(container)).notes,
      })));
      if (results.some((result) => result.status === "rejected")) {
        setError("Some personal notebooks could not be loaded; the work queue may be incomplete.");
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
    if (!loaded) return;
    const note = loaded.find((candidate) => candidate.id === entry.note.id);
    if (note) await selectNote(note, entry.container.id);
    setQueueMode(true);
  }
  /** False when the open page could not be flushed and stays open. */
  async function selectNote(selection: Note, containerID = selected?.id): Promise<boolean> {
    const previous = selectedNoteRef.current;
    if (previous && previous.id !== selection.id && !(await flushOpenPage())) return false;
    // Search and resurfacing rows hold deferred copies; open the live entry.
    const note = notesRef.current.find((entry) => entry.id === selection.id) ?? selection;
    selectedNoteRef.current = note;
    setSelectedNote(note);
    markDirty(false);
    setLastSavedAt(note.version > 0 ? note.updatedAt : "");
    // A later selection or notebook switch owns the panels below.
    const current = () => selectedNoteRef.current?.id === note.id;
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
      if (current()) setCommentsForNote(decoded);
    } catch {
      if (current()) setCommentsForNote([]);
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
      if (current()) setAttachmentsForNote(decoded);
    } catch {
      if (current()) setAttachmentsForNote([]);
    }
    return true;
  }
  async function newWorkspace() {
    const name = prompt("Notebook name", "My notebook")?.trim();
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
        error instanceof Error ? error.message : "Unable to create notebook",
      );
    } finally {
      setBusy(false);
    }
  }
  async function newTeamWorkspace(teamContainer: Container) {
    const name = prompt("Notebook name", "New notebook")?.trim();
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
      setError(error instanceof Error ? error.message : "Unable to create team notebook");
    } finally {
      setBusy(false);
    }
  }
  async function renameWorkspace() {
    if (!selected) return;
    const name = prompt("Notebook name", nameOf(selected))?.trim();
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
        error instanceof Error ? error.message : "Unable to rename notebook",
      );
    } finally {
      setBusy(false);
    }
  }
  async function newNote() {
    if (!selected) return;
    setBusy(true);
    try {
      // Before createObject: an exhausted order key must not leave an empty object behind.
      const order = endOrder(pagesInSection(notesRef.current, sectionsRef.current, sectionID));
      const object = await createObject(selected.id);
      const note: Note = {
        id: object.id,
        title: "Untitled page",
        body: stringifyCanvasPage(emptyCanvasPage()),
        section: sectionID === QUICK_NOTES ? undefined : sectionID,
        order,
        version: 0,
        updatedAt: new Date().toISOString(),
      };
      patchNotes((value) => [note, ...value]);
      selectedNoteRef.current = note;
      setSelectedNote(note);
      markDirty(true);
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
  /** Returns the page it sent (saved, queued or kept as a conflict draft); undefined if nothing was. */
  async function saveNow(note: Note, automatic = false): Promise<Note | undefined> {
    if (!selected) return undefined;
    if (!automatic) setBusy(true);
    try {
      const payload = notePayload(note);
      const encrypted = await encryptNote(
        auth.authSecret,
        selected.id,
        payload,
      );
      const savedAt = new Date().toISOString();
      const containerID = selected.id;
      await cacheWrite(() => putNote({ id: note.id, containerID, version: note.version, payload: encrypted, updatedAt: savedAt }));
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
        const saved = { ...note, version: result.version, updatedAt: savedAt };
        setLastSavedAt(savedAt);
        setSyncStatus("saved");
        // Edits or a move may have landed while the request was in flight:
        // carry only the version forward, never the sent content.
        patchNotes((value) => carrySaved(value, saved.id, saved));
        carryDuringLoad(saved.id, saved);
        setQueueEntries((entries) => entries.flatMap((entry) => {
          if (entry.note.id !== saved.id) return [entry];
          return openTaskNotes(indexNotes([saved])).length ? [{ ...entry, note: saved }] : [];
        }));
        const open = selectedNoteRef.current;
        if (open?.id === saved.id) {
          const [carried] = carrySaved([open], saved.id, saved);
          selectedNoteRef.current = carried;
          setSelectedNote(carried);
          if (samePayload(open, note)) markDirty(false);
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
      return note;
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to save note");
      return undefined;
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
    saveChain.current = queued.then(() => {}, () => {});
    return queued;
  }

  /** Leaving the open page. False keeps it open and dirty; callers must not switch away then. */
  async function flushOpenPage(): Promise<boolean> {
    if (!dirtyRef.current) return true;
    const state = await flushUntilStable(() => selectedNoteRef.current, (open) => save(open, true), FLUSH_ROUNDS);
    // A failed save already reported why.
    if (state === "busy") setError("This page is still saving. Try again in a moment.");
    return state === "done";
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
          const saved = { version: result.version, updatedAt: item.updatedAt };
          patchNotes((value) => carrySaved(value, item.id, saved));
          carryDuringLoad(item.id, saved);
          patchSections((value) => value.map((entry) => entry.id === item.id ? { ...entry, version: result.version } : entry));
          patchGroups((value) => value.map((entry) => entry.id === item.id ? { ...entry, version: result.version } : entry));
          const open = selectedNoteRef.current;
          // The open page may hold newer edits than the queued payload, so it stays dirty.
          if (open?.id === item.id) {
            const [carried] = carrySaved([open], item.id, saved);
            selectedNoteRef.current = carried;
            setSelectedNote(carried);
            setLastSavedAt(item.updatedAt);
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
    if (!confirm("Delete this page?")) return;
    try {
      await deleteObject(note.id);
      await deleteCachedNote(note.id);
      patchNotes((value) => value.filter((entry) => entry.id !== note.id));
      setSelectedNote(null);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to delete note",
      );
    }
  }
  function persistDraft(note: Note) {
    if (!selected) return;
    const containerID = selected.id;
    void cacheWrite(async () => putNote({
      id: note.id,
      containerID,
      version: note.version,
      payload: await encryptNote(auth.authSecret, containerID, notePayload(note)),
      updatedAt: new Date().toISOString(),
    })).catch(() => {});
  }
  /** Encrypted write for an object that is not the open page (sections, moved pages). */
  async function writeObject(id: string, version: number, payload: ObjectPayload): Promise<number | null> {
    if (!selected) return null;
    const encrypted = await encryptNote(auth.authSecret, selected.id, payload);
    const updatedAt = new Date().toISOString();
    const containerID = selected.id;
    await cacheWrite(() => putNote({ id, containerID, version, payload: encrypted, updatedAt }));
    try {
      const result = await saveObject(id, encrypted, version, selected.keyGeneration);
      await clearQueuedSave(id);
      carryDuringLoad(id, { version: result.version, updatedAt });
      return result.version;
    } catch (error) {
      if (error instanceof APIRequestError && error.code === "version_conflict") {
        setConflicted((value) => new Set(value).add(id));
        setSyncStatus("attention");
        setError("This item changed on another device. Reopen the notebook before changing it again.");
      } else {
        await queueSave({ id, containerID: selected.id, version, payload: encrypted, updatedAt, keyGeneration: selected.keyGeneration });
        syncChannel.current?.postMessage({ type: "queued", id });
        setSyncStatus("local");
      }
      return null;
    }
  }

  /** Chained encrypted write of a section or group, from its newest local copy; resolves true once saved. */
  function updateStructure(kind: "section" | "group", id: string, change: Partial<Pick<SectionPayload, "title" | "color" | "order" | "group">>) {
    const patch = (update: <T extends Section | Group>(value: T[]) => T[]) => (kind === "section" ? patchSections(update) : patchGroups(update));
    patch((value) => value.map((entry) => (entry.id === id ? { ...entry, ...change } : entry)));
    const queued = saveChain.current.then(async () => {
      const current = kind === "section" ? sectionsRef.current.find((entry) => entry.id === id) : groupsRef.current.find((entry) => entry.id === id);
      if (!current) return false;
      const { id: _id, version, ...payload } = current;
      const saved = await writeObject(id, version, payload);
      if (saved !== null) patch((value) => value.map((entry) => (entry.id === id ? { ...entry, version: saved } : entry)));
      return saved !== null;
    });
    saveChain.current = queued.then(() => {}, () => {});
    return queued;
  }

  /** The shared cache's copy of a page; another tab may have written it. */
  async function otherTabDraft(id: string) {
    if (!selected) return undefined;
    const cached = await getNote(id).catch(() => undefined);
    if (!cached) return undefined;
    const payload = await decryptObject(auth.authSecret, selected.id, cached.payload).catch(() => undefined);
    return payload?.type === "page" ? { version: cached.version, title: payload.title, body: payload.body } : undefined;
  }

  async function placePage(id: string, placement: { section?: string; order?: string; level?: 0 | 1 | 2 }) {
    // An undefined level keeps the page's own; an undefined section means Quick Notes.
    const { level, ...rest } = placement;
    const change = level === undefined ? rest : placement;
    patchNotes((value) => editEntry(value, id, change));
    const open = selectedNoteRef.current;
    if (open?.id === id) {
      const next = { ...open, ...change };
      selectedNoteRef.current = next;
      setSelectedNote(next);
      // Dirty, so leaving the page before the queued save runs still flushes the move.
      markDirty(true);
      persistDraft(next);
      await save(next, true);
      return;
    }
    const entry = notesRef.current.find((note) => note.id === id);
    if (!entry) return;
    const next = newestCopy(entry, await otherTabDraft(id));
    patchNotes((value) => editEntry(value, id, { title: next.title, body: next.body }));
    const saved = await writeObject(id, next.version, notePayload(next));
    if (saved !== null) patchNotes((value) => carrySaved(value, id, { version: saved }));
  }
  const orderedSections = useMemo(() => sortedSections(sections), [sections]);
  const groupSections = useMemo(() => orderedSections.filter((entry) => sectionGroup(entry, parents) === groupID), [orderedSections, parents, groupID]);
  const childGroups = useMemo(() => groups.filter((entry) => parents.get(entry.id) === groupID).sort(compareOrdered), [groups, parents, groupID]);
  /** Sorted sections or groups directly inside `parent`, read at run time. */
  function siblings(kind: "section" | "group", parent: string | undefined): Array<Section | Group> {
    const current = groupParents(groupsRef.current);
    return kind === "section"
      ? sortedSections(sectionsRef.current).filter((entry) => sectionGroup(entry, current) === parent)
      : groupsRef.current.filter((entry) => current.get(entry.id) === parent).sort(compareOrdered);
  }
  async function newStructure(kind: "section" | "group") {
    if (!selected) return;
    setBusy(true);
    try {
      const parent = groupID;
      const order = endOrder(siblings(kind, parent));
      const object = await createObject(selected.id, "folder");
      const base = { id: object.id, version: object.version, order, group: parent };
      if (kind === "section") {
        patchSections((value) => [...value, { ...base, type: "section", title: "New section", color: SECTION_COLORS[value.length % SECTION_COLORS.length] }]);
        showSection(object.id);
      } else {
        patchGroups((value) => [...value, { ...base, type: "group", title: "New group", color: SECTION_COLORS[value.length % SECTION_COLORS.length] }]);
      }
      await updateStructure(kind, object.id, {});
    } catch (error) {
      setError(error instanceof Error ? error.message : `Unable to create ${kind}`);
    } finally {
      setBusy(false);
    }
  }
  const reportSection = (error: unknown) => setError(error instanceof Error ? error.message : "Unable to update section or group");
  function renameStructure(kind: "section" | "group", entry: Section | Group) {
    const title = prompt(kind === "section" ? "Section name" : "Group name", entry.title)?.trim();
    if (title) void updateStructure(kind, entry.id, { title }).catch(reportSection);
  }
  async function removeSection(section: Section) {
    const count = pagesInSection(notes, sections, section.id).length;
    if (!confirm(`Delete section "${section.title}"? Its ${count} page${count === 1 ? "" : "s"} will move to Quick Notes.`)) return;
    try {
      await deleteObject(section.id);
      await deleteCachedNote(section.id);
      patchSections((value) => value.filter((entry) => entry.id !== section.id));
      showSection(QUICK_NOTES);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to delete section");
    }
  }
  /** Children move up one level first; a failed write stops before the delete, so nothing is lost. */
  async function removeGroup(group: Group) {
    if (!confirm(`Delete group "${group.title || "Untitled group"}"? Its sections and groups move up one level.`)) return;
    setBusy(true);
    try {
      const parent = groupParents(groupsRef.current).get(group.id);
      for (const kind of ["section", "group"] as const) {
        for (const child of siblings(kind, group.id)) {
          if (!(await updateStructure(kind, child.id, { group: parent }))) {
            setError((value) => value || "Could not move everything out of the group, so it was kept. Try again.");
            return;
          }
        }
      }
      await deleteObject(group.id);
      await deleteCachedNote(group.id);
      patchGroups((value) => value.filter((entry) => entry.id !== group.id));
      setGroupID((value) => (value === group.id ? parent : value));
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to delete group");
    } finally {
      setBusy(false);
    }
  }
  async function moveStructure(kind: "section" | "group", id: string, index: number) {
    const entry = kind === "section" ? sectionsRef.current.find((item) => item.id === id) : groupsRef.current.find((item) => item.id === id);
    if (!entry) return;
    const parent = kind === "section" ? sectionGroup(entry, parents) : parents.get(id);
    for (const update of reorder(siblings(kind, parent), id, index)) await updateStructure(kind, update.id, { order: update.order }).catch(reportSection);
  }
  async function moveIntoGroup(kind: "section" | "group", id: string, target: string | undefined) {
    if (kind === "group" && !groupMoveAllowed(id, target, groupParents(groupsRef.current))) {
      setError(`A group cannot move into itself or its own groups, or nest deeper than ${MAX_GROUP_DEPTH} levels.`);
      return;
    }
    const order = endOrder(siblings(kind, target).filter((entry) => entry.id !== id));
    await updateStructure(kind, id, { group: target, order }).catch(reportSection);
    if (kind === "section" && id === sectionID) setGroupID(target);
  }
  async function selectSection(id: string) {
    // Leaving the open page: finish its save first, as selectNote does.
    if (id !== sectionID && !(await flushOpenPage())) return;
    if (id !== sectionID) setSelectedNote(null);
    showSection(id);
  }
  /** Shows a group's tabs and its first section; a group without sections shows no pages. */
  async function openGroup(id: string | undefined) {
    if (groupOfSection(sectionID, sections, parents) === id) return setGroupID(id);
    const first = orderedSections.find((entry) => sectionGroup(entry, parents) === id)?.id ?? (id === undefined ? QUICK_NOTES : undefined);
    if (first !== undefined) return selectSection(first);
    if (!(await flushOpenPage())) return;
    setSelectedNote(null);
    setGroupID(id);
  }
  const groupTrail = selected
    ? [{ id: undefined, title: nameOf(selected) }, ...groupPath(groupID, parents).map((id) => ({ id, title: groups.find((entry) => entry.id === id)?.title || "Untitled group" }))]
    : [];
  const moveChain = useRef(Promise.resolve());
  const pageSection = (page: { section?: string }) =>
    page.section && sectionsRef.current.some((entry) => entry.id === page.section) ? page.section : QUICK_NOTES;
  function onMoveChain(work: () => Promise<void>) {
    const run = moveChain.current.then(work);
    moveChain.current = run.catch(() => {});
    return run.catch((error) => setError(error instanceof Error ? error.message : "Unable to move page"));
  }
  /** Moves the block headed by `pageID` before page `beforeID` in `target`, or to its end. */
  function movePage(pageID: string, target: string, beforeID: string | null) {
    return onMoveChain(async () => {
      const page = notesRef.current.find((note) => note.id === pageID);
      if (!page) return;
      const source = pagesInSection(notesRef.current, sectionsRef.current, pageSection(page));
      const levels = displayLevels(source);
      const [start, end] = blockRange(levels, source.findIndex((note) => note.id === pageID));
      const block = source.slice(start, end);
      const inBlock = new Set(block.map((note) => note.id));
      const list = pagesInSection(notesRef.current, sectionsRef.current, target).filter((note) => !inBlock.has(note.id));
      const before = beforeID === null ? -1 : list.findIndex((note) => note.id === beforeID);
      const section = target === QUICK_NOTES ? undefined : target;
      for (const update of placeBlock(list, block, levels.slice(start, end), before < 0 ? list.length : before)) {
        const entry = notesRef.current.find((note) => note.id === update.id);
        await placePage(update.id, inBlock.has(update.id)
          ? { section, order: update.order, level: update.level }
          : { section: entry?.section, order: update.order });
      }
    });
  }
  function indentPage(pageID: string, delta: 1 | -1) {
    return onMoveChain(async () => {
      const page = notesRef.current.find((note) => note.id === pageID);
      if (!page) return;
      const list = pagesInSection(notesRef.current, sectionsRef.current, pageSection(page));
      const level = shiftLevel(list, list.findIndex((note) => note.id === pageID), delta);
      if (level === undefined) return;
      // Indenting under a collapsed parent must not hide the row being worked on.
      revealPage(list.map((note) => (note.id === pageID ? { ...note, level } : note)), pageID);
      await placePage(pageID, { section: page.section, order: page.order, level });
    });
  }
  /** OneNote model: the server version stays the page; every rejected version becomes a copy after it. */
  async function keepConflictCopies() {
    const open = selectedNoteRef.current;
    if (recoveringRef.current || !selected || !open) return;
    recoveringRef.current = true;
    setRecovering(open.id);
    const containerID = selected.id;
    // A notebook switch replaces notes[]: copies are on the server and appear on its next load.
    const sameNotebook = () => (loadingContainerID.current ?? selectedRef.current?.id) === containerID;
    try {
      // Unsent edits become one more rejected version instead of vanishing in the reload.
      if (dirty) await save(open, true);
      const latest = selectedNoteRef.current;
      if (latest?.id === open.id && !samePayload(latest, open)) await save(latest, true);
      // Reload before placing copies: they belong next to the server's placement, and a
      // renumber may have to write the original at its server version.
      const server = await readObject(open.id);
      const payload = await decryptObject(auth.authSecret, containerID, server.bytes);
      if (payload?.type !== "page") throw new Error("Unable to read the server version of this page.");
      const reloaded = { title: payload.title, body: payload.body, section: payload.section, order: payload.order, level: payload.level, version: server.version };
      if (sameNotebook()) patchNotes((value) => value.map((note) => (note.id === open.id ? { ...note, ...reloaded } : note)));
      if (selectedNoteRef.current?.id === open.id) {
        const next = { ...selectedNoteRef.current, ...reloaded };
        selectedNoteRef.current = next;
        setSelectedNote(next);
        markDirty(false);
        setEditorRevision((value) => value + 1);
      }
      setError("");
      let failed = 0;
      let unreadable = 0;
      const rejected: Array<{ id: string; createdAt: string; payload: PagePayload }> = [];
      for (const conflict of (await objectConflicts(open.id)).filter((item) => !item.resolved)) {
        try {
          const decrypted = await decryptObject(auth.authSecret, containerID, await conflictCiphertext(conflict.id)).catch(() => undefined);
          if (decrypted?.type === "page") rejected.push({ id: conflict.id, createdAt: conflict.createdAt, payload: decrypted });
          else unreadable += 1;
        } catch (error) {
          failed += 1;
          setError(error instanceof Error ? error.message : "Unable to read a conflicting version");
        }
      }
      // Retried offline saves leave one record per attempt: copy each distinct text once.
      const { resolveOnly, groups } = groupConflicts(reloaded, rejected);
      for (const id of resolveOnly) await resolveConflict(id).catch(() => { failed += 1; });
      for (const group of groups) {
        // Placement needs this notebook's page list; the rest stay on the server for a later run.
        if (!sameNotebook()) { failed += 1; continue; }
        try {
          const current = notesRef.current.find((note) => note.id === open.id) ?? { id: open.id, ...reloaded };
          const { page, moves } = conflictCopy(pagesInSection(notesRef.current, sectionsRef.current, pageSection(current)), current, group.payload);
          const object = await createObject(containerID);
          const copy: Note = { id: object.id, title: page.title, body: page.body, section: page.section, order: page.order, level: page.level, version: 0, updatedAt: new Date().toISOString() };
          if (sameNotebook()) patchNotes((value) => [...value, copy]);
          const saved = await writeObject(object.id, 0, page);
          if (saved === null) { failed += 1; continue; }
          if (sameNotebook()) patchNotes((value) => carrySaved(value, object.id, { version: saved }));
          const run = moveChain.current.then(async () => {
            for (const move of moves) await placePage(move.id, { section: notesRef.current.find((note) => note.id === move.id)?.section, order: move.order });
          });
          moveChain.current = run.catch(() => {});
          await run;
          // ponytail: records stay open until resolve succeeds, so a retry after a failed
          // resolve, or after a copy that was only queued locally, adds a duplicate copy.
          // Upgrade: record the source conflict IDs in the copy and skip records already copied.
          for (const id of group.ids) await resolveConflict(id);
        } catch (error) {
          failed += 1;
          setError(error instanceof Error ? error.message : "Unable to keep a conflicting version");
        }
      }
      // Another device may have moved the page: show the section that now holds it and its copies.
      const placed = notesRef.current.find((note) => note.id === open.id);
      if (placed && sameNotebook() && selectedNoteRef.current?.id === open.id) {
        showSection(pageSection(placed));
      }
      if (unreadable) setError(`${unreadable} version(s) could not be opened with this notebook's key and remain on the server.`);
      else if (failed) setError((value) => value || "Some conflicting versions could not be copied; try again.");
      if (!failed && !unreadable) {
        setConflicted((value) => { const next = new Set(value); next.delete(open.id); return next; });
        setSyncStatus("saved");
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to keep the conflicting version");
    } finally {
      recoveringRef.current = false;
      setRecovering(null);
    }
  }
  function editOpen(pageID: string, change: { title?: string; body?: string }) {
    const open = selectedNoteRef.current;
    // A late change from a page's editor after another page opened is dropped.
    if (open?.id !== pageID || recovering === pageID) return;
    const next = { ...open, ...change };
    selectedNoteRef.current = next;
    setSelectedNote(next);
    patchNotes((value) => editOpenEntry(value, open, next, change));
    markDirty(true);
    persistDraft(next);
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
            <div className="section-label">NOTEBOOKS</div>
            {personalWorkspaces.map((container) => (
              <button
                className={`ky-nav-item nav-item ${!queueMode && selected?.id === container.id ? "selected" : ""}`}
                aria-current={!queueMode && selected?.id === container.id ? "page" : undefined}
                key={container.id}
                onClick={() => void selectContainer(container)}
              >
                <span className="nav-icon">◈</span>
                <span>{nameOf(container)}</span>
              </button>
            ))}
            <div className="section-label team-label">TEAM NOTEBOOKS</div>
            {teams.map((container) => (
              <React.Fragment key={container.id}>
                <button
                  className={`ky-nav-item nav-item ${!queueMode && selected?.id === container.id ? "selected" : ""}`}
                  aria-current={!queueMode && selected?.id === container.id ? "page" : undefined}
                  onClick={() => void selectContainer(container)}
                >
                  <span className="nav-icon">◇</span>
                  <span>{nameOf(container)}</span>
                </button>
                {teamWorkspaces(container.id).map((workspace) => (
                  <button
                    className={`ky-nav-item nav-item nested-nav-item ${!queueMode && selected?.id === workspace.id ? "selected" : ""}`}
                    aria-current={!queueMode && selected?.id === workspace.id ? "page" : undefined}
                    key={workspace.id}
                    onClick={() => void selectContainer(workspace)}
                  >
                    <span className="nav-icon">◈</span>
                    <span>{nameOf(workspace)}</span>
                  </button>
                ))}
                {selected?.id === container.id && (
                  <button className="new-workspace" disabled={busy} onClick={() => void newTeamWorkspace(container)}>
                    ＋ New team notebook
                  </button>
                )}
              </React.Fragment>
            ))}
            <button
              className="new-workspace personal-create"
              disabled={busy}
              onClick={() => void newWorkspace()}
            >
              ＋ New notebook
            </button>
            {selected && (
              <button
                className="new-workspace"
                disabled={busy}
                onClick={() => void renameWorkspace()}
              >
                ✎ Rename notebook
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
          {selected && !queueMode && (
            <SectionTabs
              sections={groupSections}
              groups={childGroups}
              path={groupTrail}
              current={sectionID}
              busy={busy}
              canCreateGroup={groupPath(groupID, parents).length < MAX_GROUP_DEPTH}
              moveTargets={moveTargets}
              onSelect={(id) => void selectSection(id)}
              onCreate={(kind) => void newStructure(kind)}
              onRename={renameStructure}
              onColor={(kind, entry, color) => void updateStructure(kind, entry.id, { color }).catch(reportSection)}
              onDelete={(section) => void removeSection(section)}
              onDeleteGroup={(group) => void removeGroup(group)}
              onMove={(kind, id, index) => void moveStructure(kind, id, index)}
              onMoveIntoGroup={(kind, id, target) => void moveIntoGroup(kind, id, target)}
              onOpenGroup={(id) => void openGroup(id)}
              onDropPage={(pageID, target) => {
                // A drop on the page's own section tab is not a move.
                const page = notesRef.current.find((note) => note.id === pageID);
                if (page && pageSection(page) !== target) void movePage(pageID, target, null);
              }}
            />
          )}
          <section className="note-list">
            <div className="list-header">
              <div>
                <div className="section-label">
                  {selected ? nameOf(selected) : "NOTEBOOK"}
                </div>
                <h2 className="workspace-title">{queueMode ? "Work queue" : selected ? nameOf(selected) : "Select a notebook"}</h2>
                {queueMode ? <div className="workspace-kind">Open tasks across your personal notebooks</div> : selected && <div className="workspace-kind">{selected.kind === "team" ? "Team notebook" : "Notebook"}</div>}
                {selected && <h3 className="notes-heading">{queueMode ? `${listEntries.length} task note${listEntries.length === 1 ? "" : "s"}` : sectionHidden ? groupTrail[groupTrail.length - 1]?.title : sectionTitle(sectionID)}</h3>}
              </div>
              <div className="list-actions">
                <input
                  aria-label="Search this notebook"
                  className="note-search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search"
                />
                <button
                  className="icon-button"
                  disabled={!selected || busy || sectionHidden}
                  title={sectionHidden ? "Add a section to this group first" : "New page"}
                  aria-label="New page"
                  onClick={() => void newNote()}
                >
                  ＋
                </button>
              </div>
            </div>
            {listRows.map(({ note, container, row }) => {
              // Work queue rows are a snapshot; show the open page live there.
              const shown = queueMode && selectedNote?.id === note.id ? selectedNote : note;
              const title = shown.title || "Untitled page";
              return (
              <div
                className={`note-row-wrap ${selectedNote?.id === note.id ? "selected" : ""}`}
                key={note.id}
                style={row ? { paddingInlineStart: row.level * 16 } : undefined}
                onDragOver={(event) => { if (reorderable && event.dataTransfer.types.includes(PAGE_DRAG)) event.preventDefault(); }}
                onDrop={(event) => {
                  const pageID = event.dataTransfer.getData(PAGE_DRAG);
                  const from = sectionIndex(pageID);
                  if (!reorderable || from < 0) return;
                  const before = beforeAt(dropBefore(sectionLevels, from, sectionIndex(note.id)));
                  if (before !== undefined) void movePage(pageID, sectionID, before);
                }}
              >
                {row && !row.hasChildren && <span className="page-toggle-space" aria-hidden="true" />}
                {row?.hasChildren && (
                  <button
                    className="page-toggle quiet"
                    aria-expanded={!row.collapsed}
                    aria-label={`${row.collapsed ? "Expand" : "Collapse"} ${title}`}
                    onClick={() => toggleCollapsed(note.id)}
                  >
                    {row.collapsed ? "▸" : "▾"}
                  </button>
                )}
                <button
                  className="note-row"
                  data-page-id={note.id}
                  draggable={!queueMode}
                  onDragStart={(event) => { event.dataTransfer.effectAllowed = "move"; event.dataTransfer.setData(PAGE_DRAG, note.id); }}
                  onKeyDown={(event) => {
                    if (!reorderable) return;
                    const index = sectionIndex(note.id);
                    const bracket = event.ctrlKey && event.altKey
                      ? (event.key === "]" || event.code === "BracketRight" ? 1 : event.key === "[" || event.code === "BracketLeft" ? -1 : 0)
                      : 0;
                    if (bracket) {
                      const delta = bracket as 1 | -1;
                      if (!canShift(note.id, delta)) return;
                      event.preventDefault();
                      void indentPage(note.id, delta);
                      return;
                    }
                    if (!event.altKey || (event.key !== "ArrowUp" && event.key !== "ArrowDown")) return;
                    const before = beforeAt(siblingMove(sectionLevels, index, event.key === "ArrowUp" ? -1 : 1));
                    if (before === undefined) return;
                    event.preventDefault();
                    void movePage(note.id, sectionID, before).then(() =>
                      document.querySelector<HTMLElement>(`.note-row[data-page-id="${CSS.escape(note.id)}"]`)?.focus());
                  }}
                  aria-keyshortcuts={reorderable ? "Alt+ArrowUp Alt+ArrowDown Control+Alt+BracketRight Control+Alt+BracketLeft" : undefined}
                  onClick={() => void (queueMode ? selectQueueNote({ note, container }) : selectNote(note))}
                >
                  <strong>{title}</strong>
                  {row && (row.level > 0 || row.hasChildren) && (
                    <span className="visually-hidden">
                      {row.level > 0 ? `, subpage level ${row.level}` : ""}
                      {row.hasChildren ? (row.collapsed ? `, collapsed, ${subpageCount(note.id)} subpages hidden` : ", expanded") : ""}
                    </span>
                  )}
                  <span>
                    {query.trim() && !queueMode && <em className="page-section">{sectionTitle(note.section)} · </em>}
                    {(queueMode ? noteTasks(indexNotes([shown])[0]).slice(0, 2).join(" · ") : indexNotes([shown])[0].body.slice(0, 64)) || "Empty page"}
                  </span>
                </button>
              </div>
              );
            })}
            {selected && (listEntries.length === 0 || groupEmpty) && (
              <div className="empty-list">
                {queueMode ? "No open tasks here." : groupEmpty ? "This group has no sections." : "No pages in this section."}
                <br />
                {queueMode ? "Tasks from note checklists appear here." : groupEmpty ? "Add a section to this group to add pages." : "Add a page with ＋."}
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
                    {note.title || "Untitled page"}
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
                    {recovering === selectedNote.id
                      ? "Saving the other version as a copy…"
                      : "Another device saved this page first. Your version was kept separately; save it as a copy next to this page."}
                    <button disabled={recovering !== null} onClick={() => void keepConflictCopies()}>Keep the other version as a copy</button>
                  </div>
                )}
                <input
                  className="title-input"
                  readOnly={recovering === selectedNote.id}
                  value={selectedNote.title}
                  onChange={(event) => editOpen(selectedNote.id, { title: event.target.value })}
                />
                <div className="page-canvas">
                  <Suspense fallback={<div className="editor-loading">Loading page…</div>}>
                    <CanvasPage
                      key={`${selectedNote.id}:${editorRevision}`}
                      pageID={selectedNote.id}
                      body={selectedNote.body}
                      editable={recovering !== selectedNote.id}
                      onChange={(body) => editOpen(selectedNote.id, { body })}
                      onError={setError}
                      uploadFile={uploadInlineFile}
                      resolveFileUrl={resolveFileUrl}
                    />
                  </Suspense>
                </div>
                <div className="editor-actions">
                  <select
                    aria-label="Move page to section"
                    value={pagesInSection([selectedNote], sections, QUICK_NOTES).length ? QUICK_NOTES : selectedNote.section}
                    onChange={(event) => void movePage(selectedNote.id, event.target.value, null)}
                  >
                    {sectionTargets(sections, groups, parents).map((entry) => <option key={entry.id} value={entry.id}>{entry.label}</option>)}
                    <option value={QUICK_NOTES}>Quick Notes</option>
                  </select>
                  <button
                    className="quiet"
                    disabled={!canShift(selectedNote.id, 1)}
                    title="Indent page (Ctrl+Alt+])"
                    onClick={() => void indentPage(selectedNote.id, 1)}
                  >
                    Indent page
                  </button>
                  <button
                    className="quiet"
                    disabled={!canShift(selectedNote.id, -1)}
                    title="Outdent page (Ctrl+Alt+[)"
                    onClick={() => void indentPage(selectedNote.id, -1)}
                  >
                    Outdent page
                  </button>
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
            userID={auth.user.id}
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

function PasswordSettings({ username, userID }: { username: string; userID: string }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const confirmation = (
      (event.currentTarget as HTMLFormElement).elements.namedItem(
        "confirm",
      ) as HTMLInputElement
    )?.value;
    const problem = passwordChangeProblem(next, confirmation, acknowledged);
    if (problem) {
      setStatus(problem);
      return;
    }
    setBusy(true);
    try {
      const name = username || prompt("Username")?.trim();
      if (!name) throw new Error("Username is required");
      const oldParams = await loginParams(name);
      const currentKeys = await deriveLoginKeys(current, oldParams.loginSalt, oldParams.iterations);
      const newLoginSalt = randomLoginSalt();
      const newKeys = await deriveLoginKeys(next, newLoginSalt, 600000);
      const cached = await getIdentityKey(name, userID).catch(() => undefined);
      const rewrapped = await rewrapIdentity(identityAPI, userID, currentKeys, newKeys.userKEK, cached);
      await rememberAfter(() => changePassword({
        currentAuthSecret: currentKeys.authSecret,
        newAuthSecret: newKeys.authSecret,
        newLoginSalt,
        iterations: 600000,
        identityDeviceId: rewrapped?.identityDeviceId,
        wrappedIdentityKey: rewrapped?.wrappedIdentityKey,
      }), name, newKeys.authSecret, rewrapped && { userID, identity: rewrapped.identity });
      // No identity yet (e.g. an administrator set the old password): create it under the new one.
      if (!rewrapped) settleIdentity(name, userID, newKeys);
      setCurrent("");
      setNext("");
      setAcknowledged(false);
      setStatus("Password changed.");
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
        <p className="config-muted" role="alert">{PASSWORD_CHANGE_WARNING}</p>
        <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
            style={{ width: "18px", height: "18px" }}
            required
          />
          <span>I understand my existing notes will become unreadable.</span>
        </label>
        <button disabled={busy || !acknowledged}>
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
      alert("Password reset. All existing sessions were revoked. The account's encryption identity was deleted; it is recreated at the user's next sign-in.");
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
        Create a team, then add active users to it.
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
  userID,
  onForgetDevice,
}: {
  admin: boolean;
  authSecret: string;
  onBack: () => void;
  username: string;
  userID: string;
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
              <PasswordSettings username={username} userID={userID} />
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
