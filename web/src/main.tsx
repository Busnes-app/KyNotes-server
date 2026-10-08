import { AdminBackup } from "./components/AdminBackup";
import { ConfirmPassword } from "./components/ConfirmPassword";
import React, { lazy, Suspense, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  acceptInvitation,
  addAdminTeamMember,
  adminAudit,
  adminSSO,
  adminUsers,
  attachToObject,
  APIRequestError,
  changePassword,
  changes,
  checkSetup,
  comments,
  createAdminUser,
  createObject,
  deleteUpload,
  createSealedShareLink,
  deleteObject,
  downloadAttachment,
  fetchShareCiphertext,
  inviteMember,
  login,
  loginParams,
  logout,
  members,
  notifications,
  objectConflicts,
  conflictCiphertext,
  containerEnvelopes,
  putEnvelopes,
  rotateKeys,
  stepUp,
  userIdentity,
  resolveConflict,
  objectAttachments,
  pairAdminSSO,
  readObject,
  removeMember,
  resetAdminPassword,
  saveAdminSSO,
  serviceStatus,
  session,
  setupInit,
  ssoConfig,
  updateAdminUser,
  updatePresence,
  uploadStatus,
  type AdminTeam,
  type AdminUser,
  type Container,
  type Note,
  type Session,
  type SSOSettings,
  identityAPI,
} from "./api";
import { ensureIdentity, rewrapIdentity, type HeldIdentity, type IdentityRecord } from "./identity";
import { copyableConflicts, keysAllowed, legacyRow, memberKeyStatus, movesLabelledSubpage, NO_FLOOR, type KeyFloor, type MemberKeyStatus, openFirst, readKeys, WAITING_GENERATION, writeKey, type Keyring, type MemberKey, type ReportedContainer } from "./keyring";
import { inviteWithKeys, syncContainerKeys, type InviteKeys, type KeyAPI, type KeySync, type PinStore } from "./keyService";
import { attachmentStep, readyToSend, sealAttachment, type AttachmentFile } from "./drain";
import { KeysWaitingError, sendComment, sendContainerName, sendObject, sendUploadChunk, sendUploadFinal, sendUploadStart, setWriteKeySource } from "./outbound";
import { clearStashedInvite, inviteLink, keyRequestText, stashInviteLink, stashedInvite, takeInviteLink } from "./invitations";
import { PinnedKeys } from "./components/PinnedKeys";
import { UnsentEdits } from "./components/UnsentEdits";
import { clearFloors, floorOf, raiseFloorIn, useFloors } from "./floors";
import { listAdminTeams, listContainers, newAdminTeam, newContainer, type FloorSink } from "./observe";
import { displayName, fingerprint, type PinChange } from "./pins";
import { PASSWORD_CHANGE_WARNING, passwordChangeProblem, resealWaitingEdits } from "./passwordChange";
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
  encryptContainerMeta,
  encryptNote,
  encryptSharePayload,
  base64,
  fromBase64,
  legacyKeyRef,
  type KeyRef,
  randomLoginSalt,
  type NotePayload,
} from "./crypto";
import { QUICK_NOTES, SECTION_COLORS, compareOrdered, conflictCopy, groupConflicts, endOrder, formatRoute, pagesInSection, parseRoute, reorder, resolveSection, sortedSections, type Group, type ObjectPayload, type PagePayload, type Route, type Section, type SectionPayload } from "./pages";
import { PAGE_DRAG, SectionTabs } from "./components/SectionTabs";
import { carryAll, carrySaved, carryVersions, editEntry, editOpenEntry, flushUntilStable, newestCopy, notePayload, samePayload } from "./notes";
import { loadGate } from "./loadGate";
import { MAX_GROUP_DEPTH, ancestors, blockRange, displayLevels, dropBefore, groupMoveAllowed, groupOfSection, groupParents, groupPath, groupTargets, parseCollapsed, placeBlock, sectionGroup, sectionTargets, shiftLevel, siblingMove, visibleRows } from "./outline";
import { readChoice, saveChoice } from "./ky-ui/theme";
import {
  clearDeviceKey,
  clearQueuedSave,
  deleteNote as deleteCachedNote,
  getDeviceKey,
  getIdentityKey,
  getNote,
  getKeyState,
  getPins,
  clearUpload,
  pendingSaves,
  pendingUploads,
  putNote,
  putUpload,
  queueSave,
  rememberAfter,
  replaceQueuedSave,
  storeDeviceKey,
  storeIdentityKey,
  storeConfirmedPin,
  storeKeyState,
  storePins,
  type PendingSave,
  type PendingUpload,
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
import { drainable } from "./stuckEdits";
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
  /** A single sign-on session: it cannot prove the password, so it never wraps keys. */
  sso?: boolean;
};
type PlainComment = {
  id: string;
  username: string;
  body: string;
  section?: string;
  createdAt: string;
  /** Read with the login-derived key in a shared container (legacyRow). */
  unverified?: boolean;
};
type PlainAttachment = { id: string; name: string; type: string; size: number; keyGeneration?: number };
type QueueEntry = { note: Note; container: Container };
const ROLLBACK = "The server reported an older key state for this notebook than this device has seen; writes are paused.";
const UNVERIFIED = "Written before this notebook was shared; not end-to-end verified.";
const UNVERIFIED_SIDE_EFFECT = "A page, section or group written before this notebook was shared is not end-to-end verified, so it was not changed as part of another change. Edit or move it directly to share it.";
const UNVERIFIED_SUBPAGES = "This page has subpages written before this notebook was shared, which are not end-to-end verified. Move or edit those subpages on their own first.";
const KEY_STATUS: Record<MemberKeyStatus, string> = { "has-key": "has key", waiting: "waiting for key", "no-identity": "no encryption key yet" };
const INVITE_WITHOUT_KEYS: Record<Exclude<InviteKeys, "sealed">, string> = {
  "cannot-wrap": "The invitation carries no keys: this browser cannot share keys (sign in with your password).",
  rollback: "The invitation carries no keys: the server reports an older sharing state for this team than this browser has seen.",
  "no-keys": "The invitation carries no keys: this browser holds none for this team yet. A team owner's browser shares them after the person joins.",
  "no-identity": "The invitation carries no keys: you cannot see this person's encryption key yet. A team owner's browser shares them after they join.",
  "invalid-identity": "The invitation carries no keys: this person's encryption key could not be used. A team owner's browser shares them after they join.",
  untrusted: "The invitation carries no keys: you did not confirm this person's new encryption key.",
  "pins-unsaved": "The invitation carries no keys: this browser could not save this person's key. Allow site storage.",
  moved: "The invitation carries no keys: this team's key changed meanwhile. A team owner's browser shares the new one after the person joins.",
};

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
              sso: res.sso,
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
      onAuthSecret={(authSecret) => setAuth((value) => value && { ...value, authSecret })}
      onLogout={() => {
        void logout().finally(() => {
          clearFloors();
          setAuth(null);
          setSessionUser(null);
        });
      }}
      onForgetDevice={() => {
        void clearDeviceKey(auth.username).then(() => {
          void logout().finally(() => {
            clearFloors();
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
          onLogin({ username: activeName, authSecret, user: sessionUser, sso: true });
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
  onAuthSecret,
}: {
  auth: AuthState;
  onLogout: () => void;
  onForgetDevice?: () => void;
  /** A password change: the login-derived key moves with it. */
  onAuthSecret: (authSecret: string) => void;
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
  // Team keys. Content in a shared container is sealed with its container key at the
  // current generation; personal notebooks and every legacy row use the login-derived key.
  const legacy = useMemo(() => legacyKeyRef(auth.authSecret), [auth.authSecret]);
  const ringsRef = useRef<Record<string, Keyring>>({});
  const [rings, setRings] = useState(ringsRef.current);
  const putRing = (containerID: string, ring: Keyring) => { ringsRef.current = { ...ringsRef.current, [containerID]: ring }; setRings(ringsRef.current); };
  const noKeys: Keyring = new Map();
  // The sharing state this device has seen per team container (KeyState floor, persisted by the key
  // pass). Every key choice below goes through it, so a server cannot roll a shared notebook back to
  // the login key or an older generation. A team container whose floor is not loaded gets no key.
  // The tab-wide store (floors.ts): subscribed for re-rendering, read by floorFor at decision time.
  useFloors();
  // Add-only: a pass that raised the floor and then failed never leaves memory below storage.
  // A thin lookup for every container, personal ones included: kind and teamId are server claims.
  const floorFor = (container: Pick<Container, "id">): KeyFloor | undefined => floorOf(container.id);
  /** Loads this device's floor for a container before its first use (normally empty for a new one). */
  async function ensureFloor(container: Pick<Container, "id">): Promise<KeyFloor> {
    const known = floorFor(container);
    if (known) return known;
    const loaded = await pinStore.loadKeyState(container.id);
    raiseFloorIn(container.id, loaded);
    return loaded;
  }
  /** A key pass is needed when the server or this device says shared; kind may only add a pass, never skip one. */
  const needsKeyPass = (container: Container) => container.sharedGeneration > 0 || (floorFor(container)?.shared ?? 0) > 0 || container.kind === "team" || Boolean(container.teamId);
  /** Keys a row may be read with: always the row's own generation, never a default. */
  const readKeysFor = (container: Container, generation: number | undefined) => {
    const floor = floorFor(container);
    return floor ? readKeys(container, ringsRef.current[container.id] ?? noKeys, legacy, generation, floor) : [];
  };
  const legacyRowFor = (container: Container, generation: number | undefined) => legacyRow(container, generation, floorFor(container) ?? NO_FLOOR);
  const writeKeyFor = (container: ReportedContainer) => {
    const floor = floorFor(container);
    return floor && keysAllowed(container, floor) ? writeKey(container, ringsRef.current[container.id] ?? noKeys, legacy, floor) : undefined;
  };
  // The outbound gate (outbound.ts) re-checks every ciphertext upload against this at send time.
  useEffect(() => setWriteKeySource(writeKeyFor), [legacy]);
  /** Local copies: the write key, or the waiting seal that only this device can send later. */
  const localKeyFor = (container: Container) => writeKeyFor(container) ?? { key: legacy, generation: WAITING_GENERATION };
  /** The server reported an older sharing state than this device has seen: writes are paused. */
  const rolledBack = (container: Container) => { const floor = floorFor(container); return Boolean(floor && !keysAllowed(container, floor)); };
  /** Takes a container's new generations into the open notebook without dropping its other fields. */
  const adoptGenerations = (next: Container) => setSelected((value) => (value?.id === next.id ? { ...value, keyGeneration: next.keyGeneration, sharedGeneration: next.sharedGeneration } : value));
  // Read-only until a team owner shares this generation's key.
  // putRing and the floor store re-render this component, so this is recomputed when either changes.
  const keyWait = Boolean(selected && !writeKeyFor(selected));
  const rollback = Boolean(selected && rolledBack(selected));
  /** keyWait at run time, for handlers: true (and says why) when nothing may change in the open notebook. */
  const readOnlyForKeys = () => {
    const open = selectedRef.current;
    if (!open || writeKeyFor(open)) return false;
    setError(rolledBack(open) ? ROLLBACK : "This notebook is read-only until a team owner shares its keys.");
    return true;
  };
  // Rows read with the login-derived key in a shared container (legacyRow): labelled, and re-sealed
  // under the container key only by an explicit edit or move of that row, never as a side effect.
  const [unverified, setUnverified] = useState<ReadonlySet<string>>(new Set());
  const unverifiedRef = useRef(unverified);
  const markLegacy = (ids: Iterable<string>, legacyRead: boolean) => {
    const next = new Set(unverifiedRef.current);
    for (const id of ids) {
      if (legacyRead) next.add(id);
      else next.delete(id);
    }
    unverifiedRef.current = next;
    setUnverified(next);
  };
  const [keyNotice, setKeyNotice] = useState("");
  // The open notebook's members as its last key pass saw them, and what each holds (informational only).
  const [keyMembers, setKeyMembers] = useState<{ containerID: string; members: MemberKey[]; status: Record<string, MemberKeyStatus> } | undefined>(undefined);
  // Usernames seen in key passes this session, for Settings' colleague keys.
  const colleagueNames = useRef<Record<string, string>>({});
  const [invitation, setInvitation] = useState(() => { try { return stashedInvite(sessionStorage); } catch { return undefined; } });
  const namesRef = useRef(names);
  namesRef.current = names;
  // Changed colleague keys declined this session, by member and exact key: not asked again.
  const declinedKeys = useRef(new Set<string>());
  // Colleagues first pinned while the notebook was not open; announced when it opens.
  const unannounced = useRef<Record<string, MemberKey[]>>({});
  const identityRef = useRef<HeldIdentity | undefined>(undefined);
  async function heldIdentity() {
    // Created after the first password sign-in, possibly after this workspace mounted.
    if (!identityRef.current) identityRef.current = await getIdentityKey(auth.username, auth.user.id).catch(() => undefined);
    return identityRef.current;
  }
  async function currentContainer(id: string): Promise<Container> {
    const found = (await listContainers(floorSink)).find((entry) => entry.id === id);
    if (!found) throw new Error("Notebook not found");
    return found;
  }
  const keyAPI: KeyAPI = {
    container: currentContainer,
    envelopes: containerEnvelopes,
    members,
    userIdentity,
    stepUp: async () => { await stepUp(auth.authSecret); },
    putEnvelopes,
    rotate: rotateKeys,
  };
  // Reads are not caught: empty pins or key memory would make a swapped key look first-seen.
  const pinStore: PinStore = {
    load: () => getPins(auth.username, auth.user.id),
    addFresh: (pins) => storePins(auth.username, auth.user.id, pins),
    confirm: (confirmation) => storeConfirmedPin(auth.username, auth.user.id, confirmation),
    loadKeyState: (containerID) => getKeyState(auth.username, auth.user.id, containerID),
    saveKeyState: (containerID, state) => storeKeyState(auth.username, auth.user.id, containerID, state),
  };
  // Every server container read passes the observer (observe.ts), which raises the tab-wide floors.
  const floorSink: FloorSink = { load: pinStore.loadKeyState, save: pinStore.saveKeyState };
  const fingerprintOf = (publicKey: string) => fingerprint(publicKey).catch(() => "unreadable key");
  // Pins are per user, so a decline covers every notebook; a different new key asks again.
  const declineID = (change: PinChange) => `${change.member.userId}:${change.member.identity?.publicKey ?? ""}`;
  /** The only path to a pin replacement: an explicit yes in a dialog that shows the fingerprints. */
  function confirmChangedKeys(containerID: string) {
    return async (changes: PinChange[]) => {
      if (changes.some((change) => declinedKeys.current.has(declineID(change)))) return false;
      const lines = await Promise.all(changes.map(async (change) => `${displayName(change.member.username, change.member.userId)}: ${await fingerprintOf(change.member.identity!.publicKey)} (was ${await fingerprintOf(change.pinned)})`));
      const accepted = confirm(`The encryption key of ${changes.map((change) => displayName(change.member.username, change.member.userId)).join(", ")} changed since this browser last saw it. A password reset or account recovery does this; so would a server substituting its own key. Compare these fingerprints with the person (Settings shows theirs) before continuing:\n\n${lines.join("\n")}\n\nTrust the new key and exchange this notebook's keys with it?`);
      if (!accepted) for (const change of changes) declinedKeys.current.add(declineID(change));
      return accepted;
    };
  }
  async function keyNoticeFor(result: KeySync, fresh: MemberKey[], asked: boolean) {
    const notices: string[] = [];
    const plan = result.plan;
    if (plan.kind === "blocked") notices.push(`This notebook is not end-to-end shared yet: ${plan.waitingFor.join(", ")} must first sign in with a password to get an encryption key. Accounts that sign in only through single sign-on cannot hold one yet.`);
    else if (plan.kind === "untrusted") notices.push(asked ? `No keys were exchanged with ${plan.members.join(", ")}: you did not confirm their new encryption key.` : `The encryption key of ${plan.members.join(", ")} changed. Reopen this notebook to compare fingerprints.`);
    else if (plan.kind === "rollback") notices.push(ROLLBACK);
    else if (plan.kind === "pins-unsaved") notices.push("No keys were exchanged: this browser could not save the colleague keys it checked. Allow site storage and reopen the notebook.");
    if (result.conflicts.length) notices.push("A different key was offered for this notebook than the one this device already accepted; it was refused.");
    if (fresh.length) notices.push(`Now sharing with: ${(await Promise.all(fresh.map(async (member) => `${displayName(member.username, member.userId)} (fingerprint ${await fingerprintOf(member.identity!.publicKey)})`))).join(", ")}.`);
    if (!result.keyStateSaved) notices.push("This browser could not save its key memory; after a reload it cannot tell if this notebook's keys were swapped.");
    return notices.join(" ");
  }
  // One key pass per container at a time, so an older pass never replaces a newer ring.
  const keyPasses = useRef(new Map<string, Promise<unknown>>());
  function serialized<T>(containerID: string, run: () => Promise<T>): Promise<T> {
    const next = (keyPasses.current.get(containerID) ?? Promise.resolve()).catch(() => undefined).then(run);
    keyPasses.current.set(containerID, next.catch(() => undefined));
    return next;
  }
  /**
   * Loads this browser's keys for a team container and, as its owner or admin, shares them.
   * Returns it at its current generation. A background pass never opens a dialog: a changed
   * colleague key is only reported until the user opens the notebook. A superseded load's pass
   * (the user moved on) is treated as background from then on.
   */
  async function syncKeys(container: Container, background = false, superseded: () => boolean = () => false): Promise<Container> {
    // Every container's floor is loaded first. Personal notebooks keep the login key until P5,
    // unless the server or this device says shared.
    await ensureFloor(container);
    if (!needsKeyPass(container)) return container;
    return serialized(container.id, async () => {
      const confirmChanged = background ? () => false : (changes: PinChange[]) => !superseded() && confirmChangedKeys(container.id)(changes);
      const result = await syncContainerKeys(keyAPI, container.id, { userId: auth.user.id, identity: await heldIdentity(), canWrap: !auth.sso }, pinStore, confirmChanged, ringsRef.current[container.id], raiseFloorIn);
      putRing(container.id, result.ring);
      for (const member of result.members) colleagueNames.current[member.userId] = member.username;
      raiseFloorIn(container.id, result.known);
      let next = { ...container, keyGeneration: result.container.keyGeneration, sharedGeneration: result.container.sharedGeneration };
      setItems((value) => value.map((entry) => (entry.id === next.id ? { ...entry, keyGeneration: next.keyGeneration, sharedGeneration: next.sharedGeneration } : entry)));
      let renamed = "";
      if (result.minted) [next, renamed] = await resealName(next);
      // Pins a failed save did not keep are not announced.
      const fresh = [...(unannounced.current[container.id] ?? []), ...(result.plan.kind === "pins-unsaved" ? [] : result.fresh)];
      if (!superseded() && (loadingContainerID.current ?? selectedRef.current?.id) === container.id) {
        delete unannounced.current[container.id];
        // A rolled-back server's generations would mislabel every member; the rollback notice explains the pause.
        setKeyMembers({ containerID: container.id, members: result.members, status: result.plan.kind === "rollback" ? {} : memberKeyStatus(result.container, result.members, result.envelopes) });
        setKeyNotice([await keyNoticeFor(result, fresh, !background), renamed].filter(Boolean).join(" "));
      } else {
        unannounced.current[container.id] = fresh;
      }
      return next;
    });
  }
  /**
   * After a mint, the name this browser already shows is sealed again with the new key, so
   * members can read it. Only that trusted name is resealed, from the server's latest state.
   */
  async function resealName(container: Container): Promise<[Container, string]> {
    try {
      const latest = await currentContainer(container.id);
      // Never hand back the older generations: a newer one without its key must stay read-only.
      const current = { ...container, metaCiphertext: latest.metaCiphertext, metaVersion: latest.metaVersion, changeSeq: latest.changeSeq, keyGeneration: latest.keyGeneration, sharedGeneration: latest.sharedGeneration };
      const write = writeKeyFor(latest);
      if (!write || !latest.metaCiphertext) return [current, ""];
      const meta = fromBase64(latest.metaCiphertext);
      const opened = (keys: KeyRef[]) => openFirst(keys, (key) => decryptContainerMeta(key, container.id, meta)).then((value) => value.name, () => undefined);
      if ((await opened([write.key])) !== undefined) return [current, ""];
      const ring = ringsRef.current[container.id] ?? noKeys;
      let name = namesRef.current[container.id];
      if (name) {
        // Older keys, legacy included, are tried only to compare with the name already shown.
        if ((await opened([legacy, ...ring.values()])) !== name) return [current, "This notebook's name changed while its keys were shared. Rename it so every member can read it."];
      } else {
        // Not shown (the list could not open it: a re-mint another browser deferred). Only container
        // keys this browser accepted may supply it, newest first; the forgeable legacy key may not.
        const older = [...ring.entries()].filter(([generation]) => generation < write.generation).sort(([a], [b]) => b - a).map(([, key]) => key);
        name = (await opened(older)) ?? "";
        if (!name) return [current, "This notebook's name could not be shared with its members yet. Rename it so every member can read it."];
        const shown = name;
        setNames((value) => ({ ...value, [container.id]: shown }));
      }
      const encoded = base64(await encryptContainerMeta(write.key, container.id, name));
      const result = await sendContainerName({ container: latest, generation: write.generation }, encoded, latest.metaVersion);
      setItems((value) => value.map((entry) => (entry.id === container.id ? { ...entry, metaCiphertext: encoded, metaVersion: result.metaVersion, changeSeq: result.changeSeq } : entry)));
      // Visible on purpose: a name read with a key the server can derive now reaches every member (spec §6).
      return [{ ...current, metaCiphertext: encoded, metaVersion: result.metaVersion, changeSeq: result.changeSeq }, `Shared this notebook's name with members: ${name}.`];
    } catch {
      return [container, "This notebook's name could not be shared with its members yet. Rename it to try again."];
    }
  }
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
  const loads = useMemo(loadGate, []);
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
            const containerID = selected?.id ?? "";
            const plaintext = await openFirst(selected ? readKeysFor(selected, attachment.keyGeneration) : [], (key) => decryptAttachment(key, containerID, encrypted));
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
  }, [attachmentsForNote, rings, selected?.id, selected?.sharedGeneration]);
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
      // A pasted invitation link: out of the address bar, into the banner.
      const link = takeInviteLink(location, history, sessionStorage);
      if (link) { setInvitation(link); return; }
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
  // The open shared notebook's keys follow the 90-second foreground refresh, so a waiting banner clears.
  const refreshKeys = useRef<() => void>(() => undefined);
  refreshKeys.current = () => {
    const open = selectedRef.current;
    if (!open || !needsKeyPass(open) || loadingContainerID.current || document.visibilityState !== "visible") return;
    void syncKeys(open, true)
      .then((next) => {
        adoptGenerations(next);
        // Edits queued while keys were missing can go out now.
        if (writeKeyFor(next)) void drainQueue();
      })
      .catch(() => undefined);
  };
  useEffect(() => {
    const refresh = () => {
      void notifications()
        .then((value) => setNotificationCount(value.length))
        .catch(() => setNotificationCount(0));
      refreshKeys.current();
    };
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
      const value = await listContainers(floorSink);
      const loaded = value;
      const nextNames: Record<string, string> = {};
      const identity = await heldIdentity();
      // The list just fetched answers every pass, instead of one list fetch per container.
      const listed: KeyAPI = { ...keyAPI, container: async (id) => loaded.find((entry) => entry.id === id) ?? currentContainer(id) };
      for (const item of loaded) {
        try {
          let keyed: Container = item;
          // Team containers: this device's sharing floor first, so a server reporting "never shared" still gets the shared rules.
          const floor = await pinStore.loadKeyState(item.id);
          raiseFloorIn(item.id, floor);
          // Shared names need their keys. This pass only reads: it never steps up, wraps, rotates
          // or asks about a changed key. A steward's sharing waits until the notebook is opened.
          // ponytail: a full key pass per shared notebook on every list load (members, one identity
          // fetch per member, all envelopes). Upgrade: a batch route returning this user's envelopes
          // and member identities for every container in one call.
          if (item.sharedGeneration > 0 || (floor.shared ?? 0) > 0) {
            const result = await serialized(item.id, async () => {
              const pass = await syncContainerKeys(listed, item.id, { userId: auth.user.id, identity, canWrap: false }, pinStore, () => false, ringsRef.current[item.id], raiseFloorIn);
              putRing(item.id, pass.ring);
              for (const member of pass.members) colleagueNames.current[member.userId] = member.username;
              raiseFloorIn(item.id, pass.known);
              return pass;
            });
            if (result.plan.kind !== "pins-unsaved" && result.fresh.length) unannounced.current[item.id] = [...(unannounced.current[item.id] ?? []), ...result.fresh];
            keyed = { ...item, keyGeneration: result.container.keyGeneration, sharedGeneration: result.container.sharedGeneration };
          }
          // Container meta has no row generation: it is sealed with the current one.
          if (item.metaCiphertext)
            nextNames[item.id] = (await openFirst(readKeysFor(keyed, keyed.keyGeneration), (key) => decryptContainerMeta(key, item.id, fromBase64(item.metaCiphertext)))).name;
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
  async function readContainerObjects(container: Container): Promise<{ notes: Note[]; sections: Section[]; groups: Group[]; legacyRead: string[] }> {
    const loaded: Note[] = [];
    const found: Section[] = [];
    const foundGroups: Group[] = [];
    const legacyRead: string[] = [];
    const add = (id: string, payload: ObjectPayload | undefined, version: number, updatedAt: string, generation: number | undefined) => {
      if (!payload) return;
      if (legacyRowFor(container, generation)) legacyRead.push(id);
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
          // A cache entry without its generation cannot be read in a shared container: use the server copy.
          const useCache = Boolean(cached && cached.version >= object.version && (container.sharedGeneration === 0 || cached.keyGeneration !== undefined));
          const payload = await openFirst(readKeysFor(container, useCache ? cached!.keyGeneration : object.keyGeneration), (key) => decryptObject(key, container.id, useCache ? cached!.payload : object.bytes));
          add(change.id, payload, useCache ? cached!.version : object.version, useCache ? cached!.updatedAt : new Date().toISOString(), useCache ? cached!.keyGeneration : object.keyGeneration);
        } catch {
          const cached = await getNote(change.id);
          if (cached) {
            try {
              add(change.id, await openFirst(readKeysFor(container, cached.keyGeneration), (key) => decryptObject(key, container.id, cached.payload)), cached.version, cached.updatedAt, cached.keyGeneration);
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
    return { notes: loaded, sections: found, groups: foundGroups, legacyRead };
  }
  /** Null when the open page could not be flushed and stays open. */
  async function selectContainer(container: Container, route?: Route): Promise<Note[] | null> {
    // Every call supersedes the ones before it, a second load of the same notebook included.
    const load = loads.begin();
    loadingContainerID.current = container.id;
    setLoadingContainer(true);
    try {
      return await loadContainer(container, route, load.superseded);
    } finally {
      // A later load owns the flag now.
      if (!load.superseded()) {
        loadingContainerID.current = undefined;
        setLoadingContainer(false);
      }
    }
  }
  async function loadContainer(container: Container, route: Route | undefined, superseded: () => boolean): Promise<Note[] | null> {
    // Workspace navigation destroys the current editor. Finish its latest
    // encrypted save before replacing the note list so the next load cannot
    // fall back to an older plain document.
    if (!(await flushOpenPage())) return null;
    // Another load started meanwhile: its results win.
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
    markLegacy(unverifiedRef.current, false);
    setKeyNotice("");
    try {
      // Keys first: an owner may mint or re-mint here, and reads need the current generation.
      const keyed = await syncKeys(container, false, superseded).catch((error) => {
        if (!superseded()) setError(error instanceof Error ? `Unable to share this notebook's keys: ${error.message}` : "Unable to share this notebook's keys");
        return container;
      });
      if (superseded()) return [];
      setSelected(keyed);
      const objects = await readContainerObjects(keyed);
      if (superseded()) return [];
      const loaded = carryAll(objects.notes, loadCarried.current);
      const loadedSections = carryVersions(objects.sections, loadCarried.current);
      patchSections(() => loadedSections);
      patchGroups(() => carryVersions(objects.groups, loadCarried.current));
      markLegacy(objects.legacyRead, true);
      loadCarried.current.clear();
      patchNotes(() => loaded);
      showSection(resolveSection(route?.section, loadedSections));
      const routed = route?.page ? loaded.find((note) => note.id === route.page) : undefined;
      if (routed) await selectNote(routed, keyed);
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
    if (note) await selectNote(note, entry.container);
    setQueueMode(true);
  }
  /** False when the open page could not be flushed and stays open. */
  async function selectNote(selection: Note, container: Container | null = selected): Promise<boolean> {
    const containerID = container?.id ?? "";
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
          const decrypted = await openFirst(container ? readKeysFor(container, item.keyGeneration) : [], (key) => decryptComment(key, containerID, fromBase64(item.bodyCiphertext)));
          decoded.push({
            id: item.id,
            username: item.username,
            body: decrypted.body,
            section: decrypted.section,
            createdAt: item.createdAt,
            unverified: Boolean(container && legacyRowFor(container, item.keyGeneration)),
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
          const metadata = await openFirst(container ? readKeysFor(container, item.keyGeneration) : [], (key) => decryptAttachmentMetadata(key, containerID, fromBase64(item.metadataCiphertext)));
          decoded.push({ id: item.id, ...metadata, keyGeneration: item.keyGeneration });
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
      const container = await newContainer(floorSink, "workbook");
      // Its floor before first use: normally empty, but never skipped for an ID this device knows.
      await ensureFloor(container);
      const write = writeKeyFor(container);
      if (!write) throw new Error("This notebook is waiting for keys");
      const encrypted = await encryptContainerMeta(write.key, container.id, name);
      const encoded = btoa(String.fromCharCode(...encrypted));
      const result = await sendContainerName({ container, generation: write.generation }, encoded, container.metaVersion);
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
      // Mint the workspace's own key before naming it, so the name is shared too.
      const container = await syncKeys(await newContainer(floorSink, "workbook", "", teamContainer.id));
      const write = writeKeyFor(container);
      if (!write) throw new Error("This team notebook is waiting for keys");
      const encrypted = await encryptContainerMeta(write.key, container.id, name);
      const encoded = btoa(String.fromCharCode(...encrypted));
      const result = await sendContainerName({ container, generation: write.generation }, encoded, container.metaVersion);
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
      // Seal with the server's current generation, never this tab's possibly retired one.
      const fresh = await syncKeys(await currentContainer(selected.id));
      const write = writeKeyFor(fresh);
      if (!write) throw new Error("This notebook is waiting for a team owner to share its keys");
      const encrypted = await encryptContainerMeta(write.key, fresh.id, name);
      const encoded = base64(encrypted);
      // The tab's base version keeps a concurrent rename a conflict instead of overwriting it.
      const result = await sendContainerName({ container: fresh, generation: write.generation }, encoded, selected.metaVersion);
      const next = {
        ...fresh,
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
    if (!selected || keyWait) return;
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
      const write = localKeyFor(selected);
      const encrypted = await encryptNote(write.key, selected.id, notePayload(note));
      const savedAt = new Date().toISOString();
      const containerID = selected.id;
      await cacheWrite(() => putNote({ id: note.id, containerID, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: write.generation }));
      if (write.generation === WAITING_GENERATION) {
        // No key for the current generation: queue the edit; the drain re-seals it once keys arrive.
        await queueSave({ id: note.id, containerID, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: write.generation, owner: auth.user.id });
        setSyncStatus("local");
        setError("Saved on this device only. It is sent once a team owner shares this notebook's keys; until then, do not clear this browser's data.");
        return note;
      }
      try {
        const result = await sendObject({ container: selected, generation: write.generation }, note.id, encrypted, note.version);
        await clearQueuedSave(note.id);
        markLegacy([note.id], false);
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
          await queueSave({ id: note.id, containerID: selected.id, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: write.generation, owner: auth.user.id });
          syncChannel.current?.postMessage({ type: "queued", id: note.id });
          setSyncStatus("local");
          // The notebook's key generation moved on (or this tab's floor did): the queue re-encrypts the change for it.
          if ((error instanceof APIRequestError && error.code === "already_exists") || error instanceof KeysWaitingError) void drainQueue();
          else setError("Saved locally; encrypted change queued for the server.");
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
      // Only this account's edits: another account's entry could be sent, misattributed, to a notebook both share.
      const { drain: queued, stamp } = await drainable(await pendingSaves(), auth.user.id, (item) => decryptObject(legacy, item.containerID, item.payload).then(() => true));
      // This account's legacy key opened them: record the owner before any re-key removes that proof.
      for (const item of stamp) await replaceQueuedSave(item, { ...item, owner: auth.user.id }).catch(() => false);
      if (!queued.length) return;
      setSyncStatus("syncing");
      let remaining = false;
      let attention = false;
      // One key pass per container per drain.
      const synced = new Map<string, Promise<Container>>();
      for (const queuedItem of queued) {
        let item = queuedItem;
        try {
          // Only ciphertext sealed for the current write key ever leaves: anything else is re-sealed
          // first or stays queued (waiting for keys). An edit for a notebook this user lost waits here
          // until Settings → Unsent edits exports or discards it. ponytail: one sealed under a password
          // changed in another browser never opens (N3); P5 moves to identity-keyed storage.
          const ready = await sendable(item, synced).catch(() => undefined);
          if (!ready) {
            remaining = true;
            continue;
          }
          item = ready.item;
          const result = await sendObject({ container: ready.container, generation: item.keyGeneration! }, item.id, item.payload, item.version);
          // A newer save of the same page may have been queued while this one was in flight.
          await replaceQueuedSave(item);
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
            await replaceQueuedSave(item);
            setConflicted((value) => new Set(value).add(item.id));
            attention = true;
          } else {
            // A retired generation (already_exists): the next drain reads the container again and re-seals it.
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
  /**
   * A queued save as it may be sent now (readyToSend against the container's current state and
   * this tab's floor), re-sealed for the current write key if needed; undefined keeps it queued.
   * ponytail: an edit for a notebook this user lost, or sealed under a password changed in another
   * browser, never opens and waits here forever (N1). Upgrade: P3b key-status UI with discard/export.
   */
  async function sendable(item: PendingSave, synced: Map<string, Promise<Container>>): Promise<{ item: PendingSave; container: Container } | undefined> {
    // One background key pass per container per drain; it never opens a dialog.
    if (!synced.has(item.containerID)) synced.set(item.containerID, currentContainer(item.containerID).then((found) => syncKeys(found, true)));
    const container = await synced.get(item.containerID)!;
    adoptGenerations(container);
    const ready = await readyToSend(item, container, floorFor(container), writeKeyFor(container), ringsRef.current[container.id] ?? noKeys, legacy);
    if (!ready) return undefined;
    // Only drained (owned) entries reach here; a re-sealed copy carries the owner. It replaces the
    // entry only while it is still the one read: a newer save stays.
    const sealed = ready === item ? item : { ...ready, owner: auth.user.id };
    if (sealed === item || (await replaceQueuedSave(item, sealed))) return { item: sealed, container };
    return undefined;
  }
  async function remove(note: Note) {
    if (readOnlyForKeys() || !confirm("Delete this page?")) return;
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
    const write = localKeyFor(selected);
    void cacheWrite(async () => putNote({
      id: note.id,
      containerID,
      version: note.version,
      payload: await encryptNote(write.key, containerID, notePayload(note)),
      updatedAt: new Date().toISOString(),
      keyGeneration: write.generation,
    })).catch(() => {});
  }
  /** Encrypted write for an object that is not the open page (sections, moved pages). */
  async function writeObject(id: string, version: number, payload: ObjectPayload): Promise<number | null> {
    if (!selected) return null;
    const write = localKeyFor(selected);
    const encrypted = await encryptNote(write.key, selected.id, payload);
    const updatedAt = new Date().toISOString();
    const containerID = selected.id;
    await cacheWrite(() => putNote({ id, containerID, version, payload: encrypted, updatedAt, keyGeneration: write.generation }));
    if (write.generation === WAITING_GENERATION) {
      await queueSave({ id, containerID, version, payload: encrypted, updatedAt, keyGeneration: write.generation, owner: auth.user.id });
      setSyncStatus("local");
      setError("Saved on this device only. It is sent once a team owner shares this notebook's keys; until then, do not clear this browser's data.");
      return null;
    }
    try {
      const result = await sendObject({ container: selected, generation: write.generation }, id, encrypted, version);
      await clearQueuedSave(id);
      markLegacy([id], false);
      carryDuringLoad(id, { version: result.version, updatedAt });
      return result.version;
    } catch (error) {
      if (error instanceof APIRequestError && error.code === "version_conflict") {
        setConflicted((value) => new Set(value).add(id));
        setSyncStatus("attention");
        setError("This item changed on another device. Reopen the notebook before changing it again.");
      } else {
        await queueSave({ id, containerID: selected.id, version, payload: encrypted, updatedAt, keyGeneration: write.generation, owner: auth.user.id });
        syncChannel.current?.postMessage({ type: "queued", id });
        setSyncStatus("local");
        if ((error instanceof APIRequestError && error.code === "already_exists") || error instanceof KeysWaitingError) void drainQueue();
      }
      return null;
    }
  }

  /**
   * Chained encrypted write of a section or group, from its newest local copy; resolves true once saved.
   * explicit is false when the entry only moves because another one did: an unverified entry is then left alone.
   */
  function updateStructure(kind: "section" | "group", id: string, change: Partial<Pick<SectionPayload, "title" | "color" | "order" | "group">>, explicit = true) {
    if (readOnlyForKeys()) return Promise.resolve(false);
    if (!explicit && unverifiedRef.current.has(id)) {
      setError(UNVERIFIED_SIDE_EFFECT);
      return Promise.resolve(false);
    }
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
    const containerID = selected.id;
    const payload = await openFirst(readKeysFor(selected, cached.keyGeneration), (key) => decryptObject(key, containerID, cached.payload)).catch(() => undefined);
    return payload?.type === "page" ? { version: cached.version, title: payload.title, body: payload.body } : undefined;
  }

  /** explicit is false when the page only renumbers around another move: an unverified page is then left alone. */
  async function placePage(id: string, placement: { section?: string; order?: string; level?: 0 | 1 | 2 }, explicit = true) {
    if (readOnlyForKeys()) return;
    if (!explicit && unverifiedRef.current.has(id)) {
      setError(UNVERIFIED_SIDE_EFFECT);
      return;
    }
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
    // Before createObject: no empty object is left behind while keys are missing.
    if (!selected || readOnlyForKeys()) return;
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
    if (readOnlyForKeys()) return;
    const title = prompt(kind === "section" ? "Section name" : "Group name", entry.title)?.trim();
    if (title) void updateStructure(kind, entry.id, { title }).catch(reportSection);
  }
  async function removeSection(section: Section) {
    if (readOnlyForKeys()) return;
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
    if (readOnlyForKeys() || !confirm(`Delete group "${group.title || "Untitled group"}"? Its sections and groups move up one level.`)) return;
    setBusy(true);
    try {
      const parent = groupParents(groupsRef.current).get(group.id);
      for (const kind of ["section", "group"] as const) {
        for (const child of siblings(kind, group.id)) {
          if (!(await updateStructure(kind, child.id, { group: parent }, false))) {
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
    for (const update of reorder(siblings(kind, parent), id, index)) await updateStructure(kind, update.id, { order: update.order }, update.id === id).catch(reportSection);
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
      if (readOnlyForKeys()) return;
      const page = notesRef.current.find((note) => note.id === pageID);
      if (!page) return;
      const source = pagesInSection(notesRef.current, sectionsRef.current, pageSection(page));
      const levels = displayLevels(source);
      const [start, end] = blockRange(levels, source.findIndex((note) => note.id === pageID));
      const block = source.slice(start, end);
      // Moving the block would re-seal every subpage in it: refuse before writing anything.
      if (movesLabelledSubpage(block, pageID, unverifiedRef.current)) {
        setError(UNVERIFIED_SUBPAGES);
        return;
      }
      const inBlock = new Set(block.map((note) => note.id));
      const list = pagesInSection(notesRef.current, sectionsRef.current, target).filter((note) => !inBlock.has(note.id));
      const before = beforeID === null ? -1 : list.findIndex((note) => note.id === beforeID);
      const section = target === QUICK_NOTES ? undefined : target;
      for (const update of placeBlock(list, block, levels.slice(start, end), before < 0 ? list.length : before)) {
        const entry = notesRef.current.find((note) => note.id === update.id);
        await placePage(update.id, inBlock.has(update.id)
          ? { section, order: update.order, level: update.level }
          : { section: entry?.section, order: update.order }, inBlock.has(update.id));
      }
    });
  }
  function indentPage(pageID: string, delta: 1 | -1) {
    return onMoveChain(async () => {
      if (readOnlyForKeys()) return;
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
    if (recoveringRef.current || !selected || !open || readOnlyForKeys()) return;
    recoveringRef.current = true;
    setRecovering(open.id);
    const container = selected;
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
      const payload = await openFirst(readKeysFor(container, server.keyGeneration), (key) => decryptObject(key, containerID, server.bytes));
      if (payload?.type !== "page") throw new Error("Unable to read the server version of this page.");
      markLegacy([open.id], legacyRowFor(container, server.keyGeneration));
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
      // Copying a legacy-key version would re-seal it under the container key for every member, unseen.
      const { copy: copyable, kept: unverifiedKept } = copyableConflicts(container, (await objectConflicts(open.id)).filter((item) => !item.resolved), floorFor(container) ?? NO_FLOOR);
      for (const conflict of copyable) {
        try {
          const bytes = await conflictCiphertext(conflict.id);
          const decrypted = await openFirst(readKeysFor(container, conflict.keyGeneration), (key) => decryptObject(key, containerID, bytes)).catch(() => undefined);
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
        if (!sameNotebook() || readOnlyForKeys()) { failed += 1; continue; }
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
            for (const move of moves) await placePage(move.id, { section: notesRef.current.find((note) => note.id === move.id)?.section, order: move.order }, false);
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
      else if (unverifiedKept) setError(`${unverifiedKept} version(s) were written before this notebook was shared and are not end-to-end verified, so they were not copied. They remain on the server.`);
      else if (failed) setError((value) => value || "Some conflicting versions could not be copied; try again.");
      if (!failed && !unreadable && !unverifiedKept) {
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
  /** Encrypts a file for the container's current key and registers a resumable upload for it. */
  async function sealUpload(container: Container, objectID: string, objectVersion: number, plaintext: Uint8Array, file: AttachmentFile): Promise<PendingUpload> {
    const write = writeKeyFor(container);
    if (!write) throw new KeysWaitingError();
    const sealed = await sealAttachment(write, container.id, plaintext, file);
    const upload = await sendUploadStart({ container, generation: sealed.keyGeneration }, sealed.payload.byteLength, await digestSha256Hex(sealed.payload));
    const job = { uploadId: upload.uploadId, containerID: container.id, objectID, objectVersion, ...sealed, chunkBytes: upload.chunkBytes, nextChunk: upload.nextChunk, name: file.name, type: file.type, size: file.size };
    await putUpload(job);
    return job;
  }
  /** Replaces a pending upload sealed for a retired key with one sealed for the current key. */
  async function resealUpload(job: PendingUpload, container: Container, plaintext: Uint8Array, file: AttachmentFile): Promise<PendingUpload> {
    const next = await sealUpload(container, job.objectID, job.objectVersion, plaintext, file);
    await deleteUpload(job.uploadId).catch(() => undefined);
    await clearUpload(job.uploadId);
    setUploadProgress((value) => { const rest = { ...value }; delete rest[job.uploadId]; return rest; });
    return next;
  }
  async function uploadPending(job: PendingUpload, tries = 0): Promise<{ id: string; keyGeneration: number }> {
    if (tries > 1) throw new KeysWaitingError();
    // Before the first chunk: the job must still be sealed for this notebook's current key and floor.
    const container = await syncKeys(await currentContainer(job.containerID), true);
    const step = await attachmentStep(job, container, floorFor(container), writeKeyFor(container), ringsRef.current[container.id] ?? noKeys, legacy);
    if (step.kind === "wait") throw new KeysWaitingError();
    if (step.kind === "reseal") return uploadPending(await resealUpload(job, container, step.plaintext, step.file), tries + 1);
    const sealed = { container, generation: job.keyGeneration };
    const status = await uploadStatus(job.uploadId);
    let nextChunk = status.nextChunk;
    let offset = nextChunk * job.chunkBytes;
    setUploadProgress((value) => ({ ...value, [job.uploadId]: { name: job.name, uploaded: status.receivedBytes, total: job.payload.byteLength } }));
    while (offset < job.payload.byteLength) {
      if (cancelledUploads.current.has(job.uploadId)) throw new Error("Upload cancelled");
      const chunk = job.payload.slice(offset, offset + job.chunkBytes);
      const result = await sendUploadChunk(sealed, job.uploadId, nextChunk, chunk);
      nextChunk = result.nextChunk;
      offset += chunk.byteLength;
      await putUpload({ ...job, nextChunk });
      setUploadProgress((value) => ({ ...value, [job.uploadId]: { name: job.name, uploaded: result.receivedBytes, total: job.payload.byteLength } }));
    }
    let finalized: Awaited<ReturnType<typeof sendUploadFinal>>;
    try {
      finalized = await sendUploadFinal(sealed, job.uploadId, job.metadataCiphertext);
    } catch (error) {
      if (!(error instanceof APIRequestError && error.code === "already_exists")) throw error;
      // The key generation moved during the upload: the next attempt re-reads it and re-seals first.
      return uploadPending(job, tries + 1);
    }
    await attachToObject(job.objectID, finalized.attachmentId, job.objectVersion);
    await clearUpload(job.uploadId);
    setUploadProgress((value) => { const next = { ...value }; delete next[job.uploadId]; return next; });
    return { id: finalized.attachmentId, keyGeneration: job.keyGeneration };
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
      const job = await sealUpload(selected, selectedNote.id, selectedNote.version, new Uint8Array(await file.arrayBuffer()), { name: file.name, type: file.type, size: file.size });
      // A re-sealed upload reports the generation it was actually sent under.
      const uploaded = await uploadPending(job);
      return { id: uploaded.id, name: file.name, type: file.type, size: file.size, keyGeneration: uploaded.keyGeneration };
  }
  async function addAttachment(file: File) {
    if (!selected || !selectedNote || readOnlyForKeys()) return;
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
    const containerID = selected.id;
    const plaintext = await openFirst(readKeysFor(selected, attachment.keyGeneration), (key) => decryptAttachment(key, containerID, encrypted));
    return URL.createObjectURL(new Blob([plaintext.slice().buffer as ArrayBuffer], { type: attachment.type }));
  }
  async function openAttachment(attachment: PlainAttachment) {
    if (!selected) return;
    try {
      const encrypted = await downloadAttachment(attachment.id);
      const containerID = selected.id;
      const plaintext = await openFirst(readKeysFor(selected, attachment.keyGeneration), (key) => decryptAttachment(key, containerID, encrypted));
      const url = URL.createObjectURL(new Blob([plaintext.slice().buffer as ArrayBuffer], { type: attachment.type || "application/octet-stream" }));
      const link = document.createElement("a");
      link.href = url; link.download = attachment.name; link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to open attachment");
    }
  }
  async function addComment() {
    if (!selectedNote || !selected || !commentText.trim() || readOnlyForKeys()) return;
    setBusy(true);
    try {
      const write = writeKeyFor(selected);
      if (!write) throw new Error("This notebook is waiting for a team owner to share its keys");
      const encrypted = await encryptComment(write.key, selected.id, commentText.trim(), commentSection.trim());
      try {
        await sendComment({ container: selected, generation: write.generation }, selectedNote.id, base64(encrypted));
      } catch (error) {
        if (!(error instanceof APIRequestError && error.code === "already_exists")) throw error;
        // The notebook was re-keyed meanwhile: pick up the new key; the text stays in the box.
        setSelected(await syncKeys(selected));
        throw new Error("This notebook's keys just changed. Send the comment again.");
      }
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
    const team = selected;
    if (!team) return;
    const userID = prompt("User ID to invite (Settings shows each person's user ID)")?.trim();
    if (!userID) return;
    try {
      // Only the notebook the user chose: kind and teamId never pick which keys leave this browser.
      const target = { container: team, ring: ringsRef.current[team.id] ?? noKeys, floor: floorFor(team) };
      const invitee = { userId: userID, username: colleagueNames.current[userID] ?? "", role: "editor" };
      const caller = { userId: auth.user.id, identity: await heldIdentity(), canWrap: !auth.sso };
      const { invitation: made, keys, recipient } = await inviteWithKeys({ userIdentity, stepUp: keyAPI.stepUp, invite: inviteMember }, target, invitee, caller, pinStore, confirmChangedKeys(team.id));
      const carried = keys === "sealed"
        ? `The invitation carries this team's keys, sealed for the key with fingerprint ${await fingerprintOf(recipient.identity.publicKey)}; compare it with ${displayName(invitee.username, userID)} (their Settings shows it).`
        : INVITE_WITHOUT_KEYS[keys];
      prompt(`${carried} Send this link to the person you invited. It works once, only for their account, until ${new Date(made.expiresAt).toLocaleString()}.`, inviteLink(location.origin, made));
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to invite member");
    }
  }
  function dropInvitation() {
    setInvitation(undefined);
    try { clearStashedInvite(sessionStorage); } catch { /* nothing kept */ }
  }
  async function joinTeam() {
    const link = invitation;
    if (!link) return;
    // Hidden now so a second click cannot accept twice; the stash is cleared once accept settles.
    setInvitation(undefined);
    try {
      await acceptInvitation(link.id, link.token);
      setError("You joined the team.");
    } catch (error) {
      const code = error instanceof APIRequestError ? error.code : undefined;
      setError(code === "not_found"
        ? "This invitation is no longer valid: it expired, was already used, is for another account, or its sender can no longer invite."
        : code === "already_exists" ? "You are already a member of this team." : error instanceof Error ? error.message : "Unable to join the team");
    } finally {
      dropInvitation();
    }
    await loadContainers();
  }
  async function askForKeys() {
    const open = selectedRef.current;
    if (!open) return;
    const known = keyMembers?.containerID === open.id ? keyMembers.members : [];
    const stewards = known.filter((member) => (member.role === "owner" || member.role === "admin") && member.userId !== auth.user.id).map((member) => displayName(member.username, member.userId));
    const identity = await heldIdentity();
    const text = keyRequestText({ notebook: nameOf(open), stewards, fingerprint: identity ? await fingerprintOf(base64(identity.publicKey)) : "", link: `${location.origin}/${formatRoute({ container: open.id })}` });
    prompt(`Send this to ${stewards.join(" or ") || "a team owner"}. Their browser shares this notebook's key when they open it.`, text);
  }
  async function removeTeamMember(userID: string) {
    if (!selected || !confirm("Remove this person from the team?")) return;
    try {
      await removeMember(selected.id, userID);
      // Forward secrecy: the removal retired every key; mint new ones now rather than at the next open.
      for (const child of items.filter((entry) => entry.teamId === selected.id)) await syncKeys(child);
      setSelected(await syncKeys(selected));
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
                      {displayName(member.username, member.userId)} · {member.role}
                      {keyMembers?.containerID === selected.id && keyMembers.status[member.userId] && ` · ${KEY_STATUS[keyMembers.status[member.userId]]}`}
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
              busy={busy || keyWait}
              unverified={unverified}
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
          <section className="note-list" aria-busy={loadingContainer}>
            <div className="list-header">
              <div>
                <div className="section-label">
                  {selected ? nameOf(selected) : "NOTEBOOK"}
                </div>
                <h2 className="workspace-title">{queueMode ? "Work queue" : selected ? nameOf(selected) : "Select a notebook"}</h2>
                {queueMode ? <div className="workspace-kind">Open tasks across your personal notebooks</div> : selected && <div className="workspace-kind">{selected.kind === "team" ? "Team notebook" : "Notebook"}</div>}
                {!queueMode && keyWait && <div className="workspace-kind" role="status">{rollback ? ROLLBACK : <>Waiting for a team owner to share this notebook's keys. It is read-only until then. <button className="quiet" onClick={() => void askForKeys()}>Ask an owner</button></>}</div>}
                {!queueMode && keyNotice && <div className="workspace-kind" role="status">{keyNotice}</div>}
                {invitation && (
                  <div className="conflict-banner" role="status">
                    You were invited to a team notebook.{" "}
                    <button onClick={() => void joinTeam()}>Join team</button>{" "}
                    <button className="quiet" onClick={dropInvitation}>Not now</button>
                  </div>
                )}
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
                  disabled={!selected || busy || sectionHidden || keyWait}
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
                  {unverified.has(note.id) && <em className="page-section" title={UNVERIFIED}>Not verified</em>}
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
                    <button disabled={recovering !== null || keyWait} onClick={() => void keepConflictCopies()}>Keep the other version as a copy</button>
                  </div>
                )}
                {unverified.has(selectedNote.id) && (
                  <div className="conflict-banner" role="status">{UNVERIFIED} Editing or moving it shares it with every member under this notebook's key.</div>
                )}
                <input
                  className="title-input"
                  readOnly={recovering === selectedNote.id || keyWait}
                  value={selectedNote.title}
                  onChange={(event) => editOpen(selectedNote.id, { title: event.target.value })}
                />
                <div className="page-canvas">
                  <Suspense fallback={<div className="editor-loading">Loading page…</div>}>
                    <CanvasPage
                      key={`${selectedNote.id}:${editorRevision}`}
                      pageID={selectedNote.id}
                      body={selectedNote.body}
                      editable={recovering !== selectedNote.id && !keyWait}
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
                    disabled={keyWait}
                    value={pagesInSection([selectedNote], sections, QUICK_NOTES).length ? QUICK_NOTES : selectedNote.section}
                    onChange={(event) => void movePage(selectedNote.id, event.target.value, null)}
                  >
                    {sectionTargets(sections, groups, parents).map((entry) => <option key={entry.id} value={entry.id}>{entry.label}</option>)}
                    <option value={QUICK_NOTES}>Quick Notes</option>
                  </select>
                  <button
                    className="quiet"
                    disabled={keyWait || !canShift(selectedNote.id, 1)}
                    title="Indent page (Ctrl+Alt+])"
                    onClick={() => void indentPage(selectedNote.id, 1)}
                  >
                    Indent page
                  </button>
                  <button
                    className="quiet"
                    disabled={keyWait || !canShift(selectedNote.id, -1)}
                    title="Outdent page (Ctrl+Alt+[)"
                    onClick={() => void indentPage(selectedNote.id, -1)}
                  >
                    Outdent page
                  </button>
                  <button
                    className="danger quiet"
                    disabled={keyWait}
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
                        {comment.unverified ? " · not verified" : ""}
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
                    <button disabled={busy || keyWait} onClick={() => void addComment()}>
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
                      <span>{Math.ceil(attachment.size / 1024)} KB{selected && legacyRowFor(selected, attachment.keyGeneration) ? " · not verified" : ""}</span>
                    </button>
                  ))}
                  <label className="attachment-picker">
                    <span>＋ Add encrypted file</span>
                    <input type="file" disabled={busy || keyWait} onChange={(event) => { const file = event.target.files?.[0]; if (file) void addAttachment(file); event.currentTarget.value = ""; }} />
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
                  <button disabled={keyWait} onClick={() => void newNote()}>Create a note</button>
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
            legacyKey={legacy}
            colleagueNames={colleagueNames.current}
            teamKeys={(item) => { const container = items.find((entry) => entry.id === item.containerID); return container ? readKeysFor(container, item.keyGeneration) : []; }}
            onBack={() => setView("workspace")}
            onForgetDevice={onForgetDevice}
            onAuthSecret={onAuthSecret}
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

function PasswordSettings({ username, userID, onAuthSecret }: { username: string; userID: string; onAuthSecret: (authSecret: string) => void }) {
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
      onAuthSecret(newKeys.authSecret);
      const stranded = await resealWaitingEdits(currentKeys.authSecret, newKeys.authSecret).catch(() => -1);
      setCurrent("");
      setNext("");
      setAcknowledged(false);
      setStatus(stranded === 0 ? "Password changed." : "Password changed. Some team edits waiting on this browser for a notebook's keys could not be re-encrypted for the new password and will not be sent.");
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
          <span>I understand which notes become unreadable.</span>
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

function AdminTeams({ users, authSecret, username, userID }: { users: AdminUser[]; authSecret: string; username: string; userID: string }) {
  // Admin pages hold no team keys: only names still under this account's legacy key are readable here.
  const legacy = legacyKeyRef(authSecret);
  // Observed team floors go to the tab-wide store (floors.ts) the workspace reads; unknown means not named here.
  const floorSink: FloorSink = {
    load: (containerID) => getKeyState(username, userID, containerID),
    save: (containerID, state) => storeKeyState(username, userID, containerID, state),
  };
  const [teams, setTeams] = useState<AdminTeam[]>([]);
  const [teamNames, setTeamNames] = useState<Record<string, string>>({});
  const [team, setTeam] = useState("");
  const [user, setUser] = useState("");
  const [role, setRole] = useState("editor");
  async function reload() {
    try {
      const nextTeams = await listAdminTeams(floorSink);
      const nextNames: Record<string, string> = {};
      for (const entry of nextTeams) {
        if (!entry.metaCiphertext) continue;
        try {
          nextNames[entry.id] = (
            await decryptContainerMeta(legacy, entry.id, fromBase64(entry.metaCiphertext))
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
  /**
   * Admin pages hold no team keys, so they only name never-shared teams, with this account's
   * login key. The generation sent lets the server refuse it if the team was shared meanwhile.
   */
  async function nameUnsharedTeam(entry: AdminTeam, name: string) {
    const floor = floorOf(entry.id);
    if (!floor) throw new Error("This browser could not check whether this team is shared. Try again.");
    if (entry.sharedGeneration || floor.shared || entry.keyGeneration === undefined) throw new Error("Shared teams are renamed from the team notebook.");
    const encoded = base64(await encryptContainerMeta(legacy, entry.id, name));
    await sendContainerName({ container: { id: entry.id, kind: entry.kind, keyGeneration: entry.keyGeneration, sharedGeneration: entry.sharedGeneration ?? 0 }, generation: entry.keyGeneration }, encoded, entry.metaVersion ?? 0);
  }
  async function createTeam() {
    const name = prompt("Team name", "New team")?.trim();
    if (!name) return;
    try {
      // The server mints the container ID, which is part of the metadata key.
      // Create first, then immediately replace the empty metadata with ciphertext.
      const created = await newAdminTeam(floorSink, "");
      await nameUnsharedTeam(created, name);
      setTeam(created.id);
      await reload();
    } catch (error) {
      alert(error instanceof Error ? error.message : "Unable to create team");
    }
  }
  async function renameTeam() {
    const selected = teams.find((entry) => entry.id === team);
    // A shared team's name is sealed with its container key; a legacy-key name would be unreadable to members.
    if (!selected || selected.sharedGeneration) return;
    const name = prompt("Team name", teamNames[selected.id] ?? "Team")?.trim();
    if (!name) return;
    try {
      // Re-read: the team may have been shared since this list loaded.
      const latest = (await listAdminTeams(floorSink)).find((entry) => entry.id === selected.id);
      if (!latest) throw new Error("Team not found");
      await nameUnsharedTeam(latest, name);
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
      <button className="quiet" onClick={() => void renameTeam()} disabled={!team || Boolean(teams.find((entry) => entry.id === team)?.sharedGeneration)} title="Shared teams are renamed from the team notebook">
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
  onAuthSecret,
  legacyKey,
  colleagueNames,
  teamKeys,
}: {
  admin: boolean;
  authSecret: string;
  onBack: () => void;
  username: string;
  userID: string;
  /** The login-derived key, for exporting edits stranded on this device. */
  legacyKey: KeyRef;
  /** Usernames seen in key passes this session, for the colleague keys card. */
  colleagueNames: Record<string, string>;
  /** Keys this browser holds for a queued edit's notebook and generation. */
  teamKeys: (item: PendingSave) => KeyRef[];
  onForgetDevice?: () => void;
  onAuthSecret: (authSecret: string) => void;
}) {
  const [theme, setTheme] = useState<ThemeName>(getStoredTheme());
  const [status, setStatus] = useState<{
    health: boolean;
    ready: boolean;
  } | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [audit, setAudit] = useState<Array<Record<string, string>>>([]);
  const [ownFingerprint, setOwnFingerprint] = useState("");
  useEffect(() => {
    // From this browser's own copy of the key, so the server cannot show a different one.
    void getIdentityKey(username, userID)
      .then((identity) => (identity ? fingerprint(base64(identity.publicKey)) : ""))
      .then(setOwnFingerprint, () => setOwnFingerprint(""));
  }, [username, userID]);
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
            <a href="#colleague-keys">Colleague keys</a>
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
              <PasswordSettings username={username} userID={userID} onAuthSecret={onAuthSecret} />
            </div>
            <section id="device" className="config-card">
              <h2>Trusted Device & SSO</h2>
              <p className="config-muted">
                This browser holds your local zero-knowledge encryption key to allow instant 1-click SSO login without entering a password.
              </p>
              <p className="config-muted">Your user ID: <code>{userID}</code>. Team owners need it to invite you.</p>
              <p className="config-muted">
                {ownFingerprint
                  ? <>Your encryption key fingerprint: <code>{ownFingerprint}</code>. Team owners see it when your key changes; compare it with them in person.</>
                  : "This browser holds no encryption key for team notebooks. Sign in with your password to create or unlock it."}
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
            <PinnedKeys username={username} userID={userID} names={colleagueNames} />
            <UnsentEdits legacyKey={legacyKey} userID={userID} teamKeys={teamKeys} />
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
              <AdminTeams users={users} authSecret={authSecret} username={username} userID={userID} />
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

// An invitation link opens the app at #/invite/…: keep it in this tab for after sign-in, out of the address bar.
try { stashInviteLink(location, history, sessionStorage); } catch { /* session storage disabled: the link cannot be kept */ }
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
