import { AdminConsole } from "./components/AdminConsole";
import { Appearance, ThemeSwitcher } from "./components/Appearance";
import { AppFrame, NavItem, usePhone } from "./components/AppNav";
import { setupProblem } from "./setup";
import { IdentityReset, RECOVERY_MISSING, RECOVERY_RESTORED, RecoveryRestore, RecoverySetup, RESET_UNFINISHED } from "./components/RecoveryCode";
import { downloadFile } from "./download";
import { zip } from "./zip";
import { exportUnsent, retireWaiting } from "./stuckEdits";
import React, { lazy, Suspense, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  acceptInvitation,
  approveMember,
  attachToObject,
  APIRequestError,
  changePassword,
  changes,
  checkSetup,
  comments,
  createObject,
  deleteUpload,
  createSealedShareLink,
  deleteContainer,
  deleteObject,
  downloadAttachment,
  fetchShareCiphertext,
  inviteMember,
  login,
  loginParams,
  upgradeLoginIterations,
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
  readObject,
  removeMember,
  session,
  setupInit,
  ssoConfig,
  updatePresence,
  uploadStatus,
  type Container,
  type Note,
  type Session,
  type SetupAccount,
  identityAPI,
  myIdentity,
  putDeviceOnlyIdentity,
  serverReminders,
  putReminder,
  deleteReminder,
} from "./api";
import { currentCopy, identityStatus, recoverable, rewrapIdentity, settlePasswordIdentity, settleSSOIdentity, unfinishedReset, type HeldIdentity, type IdentityRecord, type IdentityStatus, type IdentityStore, type PublicIdentity } from "./identity";
import { LinkRequests, LinkStatus, LinkThisBrowser, type Status as LinkRefusal } from "./components/DeviceLink";
import { linkRefusal } from "./linkFlow";
import { keysAllowed, memberKeyStatus, NO_FLOOR, ownCopyKeys, type KeyFloor, type MemberKeyStatus, openFirst, readKeys, reminderIDKey, WAITING_GENERATION, waitingKey, writeKey, type Keyring, type Member, type MemberKey, type ReportedContainer } from "./keyring";
import { inviteWithKeys, syncContainerKeys, type InviteKeys, type KeyAPI, type KeySync, type PinStore } from "./keyService";
import { attachmentStep, noteConflictMessage, notSaved, readyToSend, sealAttachment, type AttachmentFile } from "./drain";
import { mentionedUserIDs } from "./mentions";
import { KeysWaitingError, sendComment, sendContainerName, sendObject, sendUploadChunk, sendUploadFinal, sendUploadStart, setWriteKeySource } from "./outbound";
import { dropInvite, finalRefusal, inviteLink, keyRequestText, pendingInvite, sessionStore, takeInviteLink } from "./invitations";
import { PinnedKeys } from "./components/PinnedKeys";
import { UnsentEdits } from "./components/UnsentEdits";
import { clearFloors, floorOf, raiseFloorIn, useFloors } from "./floors";
import { createKeyed, listContainers, newContainer, type FloorSink } from "./observe";
import { displayName, fingerprint, type PinChange } from "./pins";
import { passwordChangeProblem } from "./passwordChange";
import { queuedNotice, resetNotice, resetWhen, stewardOf, UNRECOVERABLE, WAITING, waitingNotice } from "./keyNotices";
import {
  decryptComment,
  decryptAttachment,
  decryptAttachmentMetadata,
  decryptContainerMeta,
  decryptObject,
  decryptSharePayload,
  legacyChildOpens,
  metaPin,
  openObject,
  deriveLoginKeys,
  LOGIN_ITERATIONS,
  type LoginKeys,
  digestSha256Hex,
  hasWebCrypto,
  NEEDS_HTTPS,
  encryptComment,
  encryptContainerMeta,
  encryptNote,
  encryptSharePayload,
  base64,
  fromBase64,
  type KeyRef,
  randomLoginSalt,
  type NotePayload,
} from "./crypto";
import { QUICK_NOTES, SECTION_COLORS, compareOrdered, conflictCopy, groupConflicts, endOrder, formatRoute, pagesInSection, parseRoute, reorder, resolveSection, SETTINGS_TABS, settingsHash, settingsTabOf, sortedSections, type Group, type Legacy, type ObjectPayload, type PagePayload, type Route, type Section, type SectionPayload, type SettingsTab } from "./pages";
import { migrateNotebook, type LoadedObject } from "./migrate";
import { PAGE_DRAG, SectionTabs } from "./components/SectionTabs";
import { AppMark, NavIcon } from "./NavIcon";
import { carryAll, carrySaved, carryVersions, editEntry, editOpenEntry, flushUntilStable, newestCopy, notePayload, samePayload, unreadableNotice } from "./notes";
import { loadGate } from "./loadGate";
import { relativeDate } from "./relativeDate";
import { MAX_GROUP_DEPTH, ancestors, blockRange, displayLevels, dropBefore, groupMoveAllowed, groupOfSection, groupParents, groupPath, groupTargets, parseCollapsed, placeBlock, sectionGroup, sectionTargets, shiftLevel, siblingMove, visibleRows } from "./outline";
import { readChoice, saveChoice } from "./ky-ui/theme";
import { stepUpAsking } from "./stepup";
import { loginFloor, pinLogin, upgradeLogin } from "./loginUpgrade";
import {
  clearDeviceKey,
  clearQueuedSave,
  deleteNote as deleteCachedNote,
  getIdentityKey,
  getNote,
  getKeyState,
  getPins,
  identityStorage,
  loadIdentityRecord,
  vaultReady,
  clearUpload,
  pendingSaves,
  pendingUploads,
  putNote,
  putUpload,
  queueSave,
  rememberAfter,
  replaceQueuedSave,
  noteResetSent,
  resetSentKey,
  openVault,
  storeIdentityKey,
  storeConfirmedPin,
  storeKeyState,
  storePins,
  type PendingSave,
  type PendingUpload,
} from "./storage";

/** An older account's sign-in upgrades it; best effort, so a failure keeps the old verifier and the next sign-in retries. */
async function upgradeOlderLogin(username: string, userID: string, password: string, keys: LoginKeys, identity?: IdentityRecord): Promise<{ keys: LoginKeys; identity?: IdentityRecord }> {
  try {
    const upgraded = await upgradeLogin(upgradeLoginIterations, userID, password, keys, identity);
    pinLogin(username);
    return upgraded;
  } catch {
    return { keys, identity };
  }
}

/** Opens or creates the identity after a password sign-in and keeps it on this browser; failures stay silent (the workspace offers linking). */
async function settleIdentity(username: string, userID: string, keys: LoginKeys, fromLogin?: IdentityRecord): Promise<void> {
  try {
    const store: IdentityStore = { load: () => loadIdentityRecord(username, userID), save: (identity, expected) => storeIdentityKey(username, userID, identity, expected) };
    await settlePasswordIdentity(identityAPI, store, userID, keys, fromLogin);
  } catch { /* the workspace shows what this browser can do instead */ }
}
import { applyStoredTheme } from "./theme";
import { contextualNotes, graphEdges, indexNotes, noteDatedTasks, openTaskNotes, searchNotes } from "./knowledge";
import { classifyTask, TASK_GROUPS } from "./taskDates";
import { dropPushSubscription, ensurePushSubscription, readReminderPrefs, ReminderSettings, useReminders, type ReminderPrefs } from "./reminders";
import { desiredReminders, planReconcile } from "./reminderPush";
import { documentText, emptyCanvasPage, stringifyCanvasPage } from "./document";
import { commitToastLabel, commitToastVisible, COMMIT_TOAST_DURATION_MS } from "./commitToast";
import "./styles.css";
import "./ky-ui/tokens.css";
import "./ky-ui/navigation.css";
import "./ky-ui/shell.css";
import "./ky-ui/appearance.css";
import "./ky-ui/appearance-themes.css";

const MAX_CHANGE_PAGES = 100;
const FLUSH_ROUNDS = 5;
const EXPORT_WARNING = "The export is not encrypted: anyone who gets the file can read these notes and attachments.";

const CanvasPage = lazy(() => import("./CanvasPage"));

type AuthState = {
  username: string;
  authSecret: string;
  user: Session["user"];
  /** A single sign-on session: it cannot prove the password, so it never wraps keys. */
  sso?: boolean;
  /** The password was set by someone else: nothing but the change runs until it is replaced. */
  passwordChangeRequired?: boolean;
};
type PlainComment = {
  id: string;
  username: string;
  body: string;
  section?: string;
  createdAt: string;
};
/** page: the page it was listed for and is bound to. */
type PlainAttachment = { id: string; name: string; type: string; size: number; keyGeneration?: number; page: string };
type QueueEntry = { note: Note; container: Container };
const ROLLBACK = "The server reported an older key state for this notebook than this device has seen; writes are paused.";
const OLDER_META = "The server sent an older copy of a notebook's encrypted name than this device has seen (from before its encryption upgrade); it is not shown. Rename the notebook to replace it.";
const NOT_KEYED = "The notebook was created, but its key is not set up yet. Open it again to finish.";
const NO_KEY_HERE = "This browser does not hold your encryption key, so it cannot create a notebook. Link it, or restore your key with your recovery code, in Settings.";
const UNCACHED = "Saved to the server, but this browser could not keep its local copy (site storage may be full or blocked).";
/** What Settings suggests without a key: only an action this browser can actually take from here. */
function noKeyHint(state: IdentityStatus | "unknown", sso: boolean): string {
  if (state === "link") return " Link it from a browser that does, under Phones & apps.";
  if (state === "create") return sso ? " Set up your encryption key from the notebook list." : " Sign in with your password to create it.";
  return "";
}
const FORGET_DEVICE = "Forget this device and sign out? This browser's copy of your encryption key and your colleague key pins are removed. To get the key back here, link this browser from another one or enter your recovery code (or sign in with your password, if it still unlocks your key; accounts that use KySignOn have no password copy). Unsent edits stay on this browser until they are sent, or until you discard them under Unsent edits.";
/** A password session's reset: its typed password gives the step-up and the new key's password copy (recovery.ts resetIdentity). */
const passwordReset = (username: string) => ({
  derive: async (password: string) => { const params = await loginParams(username); return deriveLoginKeys(password, params.loginSalt, params.iterations, loginFloor(username)); },
  stepUp: (authSecret: string) => stepUp(authSecret),
});
const KEY_STATUS: Record<MemberKeyStatus, string> = { "has-key": "has key", waiting: "waiting for key", "no-identity": "no encryption key yet", unapproved: "awaiting approval" };
const UNNAMED_TEAM = "An administrator created this team notebook for you. Name it so its members can find it.";
const approvalText = (name: string) => `${name} was added by an administrator. They get this notebook's keys only after you approve them.`;
const INVITE_WITHOUT_KEYS: Record<Exclude<InviteKeys, "sealed">, string> = {
  "cannot-wrap": "The invitation carries no keys: this browser cannot share keys at invitation time (it holds no encryption key, or you signed in with single sign-on). A team owner's browser shares them after the person joins.",
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
        if (!res.user?.username) return;
        // An administrator browser keeps no vault record, and a password someone else set unlocks nothing.
        if (res.user.accountKind === "admin" || res.passwordChangeRequired) {
          setAuth({ username: res.user.username, authSecret: "", user: res.user, sso: res.sso, passwordChangeRequired: res.passwordChangeRequired });
          return;
        }
        // A single sign-on session never asks for a password: nothing it unlocks comes from one (I1).
        if (res.sso) {
          await openVault(res.user.username).catch(() => undefined); // no IndexedDB: the identity cannot be kept
          setAuth({ username: res.user.username, authSecret: "", user: res.user, sso: true });
          return;
        }
        setSessionUser(res.user);
        // The vault keeps no login secret: this session reopens, and a step-up asks for the password.
        if (await vaultReady(res.user.username)) setAuth({ username: res.user.username, authSecret: "", user: res.user });
      })
      .catch(() => {
        setSessionUser(null);
      })
      .finally(() => setChecking(false));
  }, []);
  if (checking) return <main className="center">Loading KyNotes…</main>;
  if (location.pathname.startsWith("/share/")) return <SharedNote />;
  // A browser's push subscription belongs to the signed-in account: it ends with the session.
  const endSession = () => dropPushSubscription().catch(() => undefined).then(logout);
  const signOut = () => {
    void endSession().finally(() => {
      clearFloors();
      setAuth(null);
      setSessionUser(null);
    });
  };
  if (auth?.passwordChangeRequired)
    return <ChoosePassword auth={auth} onChanged={(authSecret) => setAuth({ ...auth, authSecret: auth.user.accountKind === "admin" ? "" : authSecret, passwordChangeRequired: false })} onLogout={signOut} />;
  if (auth?.user.accountKind === "admin")
    return <AdminConsole username={auth.username} sso={auth.sso === true} onLogout={signOut} password={<PasswordSettings username={auth.username} userID={auth.user.id} everyday={false} onAuthSecret={() => {}} onIdentityCreated={() => {}} />} />;
  return auth ? (
    <Workspace
      auth={auth}
      onAuthSecret={(authSecret) => setAuth((value) => value && { ...value, authSecret })}
      onLogout={signOut}
      onForgetDevice={() => {
        void clearDeviceKey(auth.username).then(() => {
          void endSession().finally(() => {
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
        void endSession().finally(() => setSessionUser(null));
      }}
      onForgetDevice={(username) => {
        void clearDeviceKey(username).then(() => {
          void endSession().finally(() => setSessionUser(null));
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
      <AuthScreen tagline="Private notes on your own server.">
        <div className="ky-auth-card">
          <h2>Encrypted link unavailable</h2>
          <p className="error">{state.error}</p>
        </div>
      </AuthScreen>
    );
  if (!state.note)
    return <main className="center">Decrypting encrypted note…</main>;
  return (
    <main className="shared-page">
      <article className="shared-note">
        <p className="shared-note-source">Shared from KyNotes · encrypted link</p>
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
  const [username, setUsername] = useState(() => sessionUser?.username ?? "");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [adminName, setAdminName] = useState("admin");
  const [everydayName, setEverydayName] = useState("");
  const [everydayPassword, setEverydayPassword] = useState("");
  const [everydayConfirm, setEverydayConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sso, setSSO] = useState<{ enabled: boolean; issuerUrl: string; clientId: string } | null>(null);

  useEffect(() => {
    void checkSetup().then((res) => {
      if (res.setupRequired) setSetupRequired(true);
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
    const problem = setupProblem({ admin: adminName, adminPassword: password, adminConfirm: confirmPassword, everyday: everydayName, everydayPassword, everydayConfirm });
    if (problem) {
      setError(problem);
      return;
    }
    setError("");
    setBusy(true);
    try {
      // Each password stays in this browser; the server sees only each account's authSecret.
      const account = async (name: string, secret: string): Promise<SetupAccount> => {
        const loginSalt = randomLoginSalt();
        return { username: name.trim(), authSecret: (await deriveLoginKeys(secret, loginSalt, 600000)).authSecret, loginSalt, iterations: 600000 };
      };
      const result = await setupInit(await account(adminName, password), await account(everydayName, everydayPassword));
      onLogin({ username: adminName.trim(), authSecret: "", user: result.user });
    } catch (error) {
      setError(error instanceof Error ? error.message : "Setup failed");
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
      const derived = await deriveLoginKeys(password, params.loginSalt, params.iterations, loginFloor(activeName));
      const authSecret = derived.authSecret;
      // A password the server refuses never lets anyone in.
      const result = await login(activeName, authSecret);
      if (params.iterations >= LOGIN_ITERATIONS) pinLogin(activeName);
      const { keys, identity } = params.iterations < LOGIN_ITERATIONS && !result.passwordChangeRequired
        ? await upgradeOlderLogin(activeName, result.user.id, password, derived, result.identity)
        : { keys: derived, identity: result.identity };
      const everyday = result.user.accountKind === "user";
      // Only an everyday account on its own password keeps a vault record, after the server accepted the password.
      if (everyday && !result.passwordChangeRequired) {
        await rememberAfter(async () => result, activeName);
        await settleIdentity(activeName, result.user.id, keys, identity);
      }
      onLogin({ username: activeName, authSecret: everyday ? keys.authSecret : "", user: result.user, passwordChangeRequired: result.passwordChangeRequired });
      setPassword("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to sign in");
    } finally {
      setBusy(false);
    }
  }

  if (setupRequired) {
    return (
      <AuthScreen tagline="Private notes on your own server." help="Each password stays in this browser. It derives that account's sign-in verifier and is never sent to or stored on the server.">
        <form className="ky-auth-card setup-form" onSubmit={submitSetup}>
          <h2>Set up KyNotes</h2>
          <p className="setup-lede">Create two accounts: one to run the server and one to write notes with.</p>
          <fieldset>
            <legend>Administrator login</legend>
            <p className="setup-hint">Manages users, teams, sign-on and backups. It cannot open notes.</p>
            <label>
              Administrator username
              <input autoComplete="username" value={adminName} onChange={(event) => setAdminName(event.target.value)} required />
            </label>
            <label>
              Administrator password
              <input type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} required />
            </label>
            <label>
              Confirm administrator password
              <input type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required />
            </label>
          </fieldset>
          <fieldset>
            <legend>Everyday login</legend>
            <p className="setup-hint">The account you write notes with.</p>
            <label>
              Everyday username
              <input autoComplete="off" value={everydayName} onChange={(event) => setEverydayName(event.target.value)} required />
            </label>
            <label>
              Everyday password
              <input type="password" autoComplete="new-password" value={everydayPassword} onChange={(event) => setEverydayPassword(event.target.value)} required />
            </label>
            <label>
              Confirm everyday password
              <input type="password" autoComplete="new-password" value={everydayConfirm} onChange={(event) => setEverydayConfirm(event.target.value)} required />
            </label>
          </fieldset>
          {error && <p className="error" role="alert">{error}</p>}
          <button className="ky-auth-submit" disabled={busy}>{busy ? "Initializing…" : "Initialize KyNotes"}</button>
        </form>
      </AuthScreen>
    );
  }
  return (
    <AuthScreen tagline="Private notes on your own server." help="Your notes are encrypted in this browser before they leave it, and your password never leaves it.">
      <div className="ky-auth-card">
        {sessionUser && (
          <p className="auth-session" role="status">
            Signed in as <strong>{sessionUser.username || sessionUser.id}</strong>. Enter your password to keep using KyNotes in this browser.
            {onClearSession && <button type="button" className="ky-auth-link" onClick={onClearSession}>Sign out</button>}
          </p>
        )}
        <form onSubmit={submit}>
          {!sessionUser && (
            <div className="ky-auth-field">
              <label htmlFor="login-username">Username</label>
              <input id="login-username" autoComplete="username" autoCapitalize="none" spellCheck={false} autoFocus value={username} onChange={(event) => setUsername(event.target.value)} required />
            </div>
          )}
          <div className="ky-auth-field">
            <label htmlFor="login-password">Password</label>
            <input id="login-password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required autoFocus={!!sessionUser} />
          </div>
          {error && <p className="error" role="alert">{error}</p>}
          {/* No browser check runs here: the empty line keeps the card's rhythm. */}
          <p className="ky-auth-check" />
          <button className="ky-auth-submit" disabled={busy}><NavIcon name="signin" />{busy ? "Signing in…" : "Sign in"}</button>
        </form>
        {!sessionUser && sso?.enabled && (
          <>
            <hr className="ky-auth-divider" />
            <a className="ky-auth-sso" href="/api/v1/auth/oidc/login">Continue with single sign-on</a>
          </>
        )}
      </div>
    </AuthScreen>
  );
}

/** The suite sign-in frame (ky-ui shell): theme picker, mark, name, one card and the help line. */
function AuthScreen({ tagline, help, children }: { tagline: string; help?: string; children: React.ReactNode }) {
  return (
    <main className="ky-auth">
      <div className="ky-auth-theme"><ThemeSwitcher /></div>
      <div className="ky-auth-body">
        <div className="ky-auth-brand">
          <AppMark size={56} />
          <h1>KyNotes</h1>
          <p>{tagline}</p>
        </div>
        {children}
        {help && <p className="ky-auth-help">{help}</p>}
      </div>
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
  /** A password change: the vault keeps the new auth secret. */
  onAuthSecret: (authSecret: string) => void;
}) {
  const [items, setItems] = useState<Container[]>([]);
  const [showNotebookNavigation, setShowNotebookNavigation] = useState(false);
  // Phones show the page list or the open page; the list's back target is the page.
  const [phoneList, setPhoneList] = useState(false);
  const focusTitleNext = useRef(false);
  const pageTitleRef = useRef<HTMLInputElement>(null);
  const phone = usePhone();
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
  const [reminderPrefs, setReminderPrefs] = useState<ReminderPrefs>(() => readReminderPrefs(auth.user.id));
  // The last work-queue load read every personal notebook, every object included.
  const [queueComplete, setQueueComplete] = useState(false);
  const [selectedNote, setSelectedNote] = useState<Note | null>(null);
  useEffect(() => {
    if (selectedNote && phone) {
      setShowNotebookNavigation(false);
      // Focus follows a phone page choice; opening a deep link leaves focus alone.
      if (focusTitleNext.current) {
        focusTitleNext.current = false;
        setPhoneList(false);
        // The page replaces the list; focus after it has rendered.
        const frame = requestAnimationFrame(() => pageTitleRef.current?.focus());
        return () => cancelAnimationFrame(frame);
      }
    }
  }, [selectedNote?.id]);
  const [commentsForNote, setCommentsForNote] = useState<PlainComment[]>([]);
  const [attachmentsForNote, setAttachmentsForNote] = useState<PlainAttachment[]>([]);
  // The page's comment and attachment panels open when they hold something and fold away when empty.
  const [commentsOpen, setCommentsOpen] = useState(false);
  const [recoveryDismissed, setRecoveryDismissed] = useState(false);
  const [attachmentsOpen, setAttachmentsOpen] = useState(false);
  const hasComments = commentsForNote.length > 0;
  const hasAttachments = attachmentsForNote.length > 0;
  useEffect(() => setCommentsOpen(hasComments), [selectedNote?.id, hasComments]);
  useEffect(() => setAttachmentsOpen(hasAttachments), [selectedNote?.id, hasAttachments]);
  const [attachmentSources, setAttachmentSources] = useState<Record<string, string>>({});
  // Object URLs resolveFileUrl made for the open page's editor, revoked when the page closes.
  const resolvedURLs = useRef<string[]>([]);
  const [uploadProgress, setUploadProgress] = useState<Record<string, { name: string; uploaded: number; total: number; failed?: boolean }>>({});
  const cancelledUploads = useRef(new Set<string>());
  const [commentText, setCommentText] = useState("");
  const [commentSection, setCommentSection] = useState("");
  const [conflicted, setConflicted] = useState<Set<string>>(new Set());
  const [lastSavedAt, setLastSavedAt] = useState("");
  const [syncStatus, setSyncStatus] = useState<"saved" | "local" | "syncing" | "attention">("saved");
  const draining = useRef(false);
  const drainingUploads = useRef(false);
  // Live saves, structure writes and the queue drain run one at a time, so no two send the same base version.
  const saveChain = useRef(Promise.resolve());
  // updatedAt of the last save this tab queued per object: only that entry is cleared once a later save lands.
  const ownQueued = useRef(new Map<string, string>());
  const syncChannel = useRef<BroadcastChannel | null>(null);
  const selectedNoteRef = useRef<Note | null>(null);
  const selectedRef = useRef<Container | null>(null);
  selectedRef.current = selected;
  selectedNoteRef.current = selectedNote;
  const [notificationCount, setNotificationCount] = useState(0);
  const [membersForTeam, setMembersForTeam] = useState<Member[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  // Leave sites read dirtiness synchronously; a closure's `dirty` lags a save that just finished.
  const dirtyRef = useRef(false);
  const markDirty = (value: boolean) => { dirtyRef.current = value; setDirty(value); };
  const ringsRef = useRef<Record<string, Keyring>>({});
  const [rings, setRings] = useState(ringsRef.current);
  const putRing = (containerID: string, ring: Keyring) => { ringsRef.current = { ...ringsRef.current, [containerID]: ring }; setRings(ringsRef.current); };
  const noKeys: Keyring = new Map();
  // The sharing state this device has seen per team container (KeyState floor, persisted by the key
  // pass). Every key choice below goes through it, so a server cannot roll a keyed notebook back to
  // unkeyed or an older generation. A team container whose floor is not loaded gets no key.
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
  /** Keys a server row may be read with: its own generation's container key, never a default. */
  const readKeysFor = (container: Container, generation: number | undefined) => {
    const floor = floorFor(container);
    return floor ? readKeys(container, ringsRef.current[container.id] ?? noKeys, generation, floor) : [];
  };
  /** Keys for a copy this browser stored itself (cache, queue): as readKeysFor, plus the waiting key for a waiting edit. A notebook no longer listed has no container key here. */
  const ownCopyKeysFor = (container: Container | undefined, generation: number | undefined): KeyRef[] => {
    const floor = container && floorFor(container);
    if (container && !floor) return [];
    return ownCopyKeys(container ?? { sharedGeneration: 0 }, (container && ringsRef.current[container.id]) ?? noKeys, generation, floor ?? NO_FLOOR, waitingRef.current);
  };
  const writeKeyFor = (container: ReportedContainer) => {
    const floor = floorFor(container);
    return floor && keysAllowed(container, floor) ? writeKey(container, ringsRef.current[container.id] ?? noKeys, floor) : undefined;
  };
  // The outbound gate (outbound.ts) re-checks every ciphertext upload against this at send time.
  useEffect(() => setWriteKeySource(writeKeyFor), []);
  // Notebooks whose migration marker (a v2 name carrying objects: 2) this device has seen, pinned in
  // its KeyState: their v1 objects, v1 names and unpinned v1 children are refused from then on.
  const migrated = useRef(new Set<string>());
  async function noteMigrated(containerID: string) {
    migrated.current.add(containerID);
    await pinStore.saveKeyState(containerID, { mark: 0, digests: {}, objects: 2 }).catch(() => false);
  }
  /** The listed name, opened (v1 too: callers refuse it after the marker); a marker found is pinned. */
  async function openMeta(container: Container) {
    // Container meta has no row generation: it is sealed with the current one.
    const meta = await openFirst(readKeysFor(container, container.keyGeneration), (key) => decryptContainerMeta(key, container.id, fromBase64(container.metaCiphertext), true));
    if (meta.objects === 2) await noteMigrated(container.id);
    return meta;
  }
  /** legacyChildOpens for a child of pageID as this tab holds the page. */
  const v1ChildOpens = (containerID: string, pageID: string, childID: string, ciphertext: Uint8Array) =>
    legacyChildOpens(notesRef.current.find((note) => note.id === pageID), migrated.current.has(containerID), childID, ciphertext);
  /**
   * Local copies: the write key, or the identity's waiting seal at generation 0 that only this device sends
   * later. Never the login key: with no identity held here, there is no local copy (undefined).
   */
  const localKeyFor = (container: Container) => writeKeyFor(container) ?? (waitingRef.current && { key: waitingRef.current, generation: WAITING_GENERATION });
  /** The server reported an older sharing state than this device has seen: writes are paused. */
  const rolledBack = (container: Container) => { const floor = floorFor(container); return Boolean(floor && !keysAllowed(container, floor)); };
  /** Takes a container's new generations into the open notebook without dropping its other fields. */
  const adoptGenerations = (next: Container) => setSelected((value) => (value?.id === next.id ? { ...value, keyGeneration: next.keyGeneration, sharedGeneration: next.sharedGeneration } : value));
  // Read-only until this generation's key reaches this browser.
  // putRing and the floor store re-render this component, so this is recomputed when either changes.
  const keyWait = Boolean(selected && !writeKeyFor(selected));
  /** Whether this user is an owner or admin of the container, from its loaded member list (keyNotices.ts). */
  // Member management and team notebooks: the server's member list says whether this user is a steward of the open team (M1).
  const teamSteward = stewardOf(membersForTeam, auth.user.id) === true;
  const stewardHere = (container: Container) => stewardOf(keyMembers?.containerID === container.id ? keyMembers.members : undefined, auth.user.id);
  const rollback = Boolean(selected && rolledBack(selected));
  /** keyWait at run time, for handlers: true (and says why) when nothing may change in the open notebook. */
  const readOnlyForKeys = () => {
    const open = selectedRef.current;
    if (!open || writeKeyFor(open)) return false;
    setError(rolledBack(open) ? ROLLBACK : WAITING);
    return true;
  };
  const [keyNotice, setKeyNotice] = useState("");
  // The open notebook's members wait for keys this SSO steward did not share on its own (KySync.deferred).
  const [keyDeferred, setKeyDeferred] = useState(false);
  /** The login secret this tab asked for (keyAPI.stepUp), shared by every caller; dropped when cancelled or refused. */
  const asked = useRef<Promise<string> | undefined>(undefined);
  // The open notebook's members as its last key pass saw them, and what each holds (informational only).
  const [keyMembers, setKeyMembers] = useState<{ containerID: string; members: MemberKey[]; status: Record<string, MemberKeyStatus> } | undefined>(undefined);
  // Usernames seen in key passes this session, for Settings' colleague keys.
  const colleagueNames = useRef<Record<string, string>>({});
  const [invitation, setInvitation] = useState(() => pendingInvite(sessionStore()));
  const namesRef = useRef(names);
  namesRef.current = names;
  // Changed colleague keys declined this session, by member and exact key: not asked again.
  const declinedKeys = useRef(new Set<string>());
  // Colleagues first pinned while the notebook was not open; announced when it opens.
  const unannounced = useRef<Record<string, MemberKey[]>>({});
  const identityRef = useRef<HeldIdentity | undefined>(undefined);
  // Seals edits waiting for a key (N3): set with the identity copy, so a password change never strands them.
  const waitingRef = useRef<KeyRef | undefined>(undefined);
  // Mirrors waitingRef for rendering, so Unsent edits re-checks once the identity loads.
  const [waitingHeld, setWaitingHeld] = useState(false);
  // The account's identity as the server lists it: recoverable() gates a notebook's first key, and Settings
  // shows the code state. null: checked, none (M5: key passes do not refetch; refreshIdentity re-checks
  // after an identity is created, restored or linked). undefined: not checked yet.
  const liveRef = useRef<PublicIdentity | null | undefined>(undefined);
  const [live, setLive] = useState<PublicIdentity | null>();
  // Settings opens the recovery code card right after an SSO key set-up.
  const [recoveryPrompt, setRecoveryPrompt] = useState(false);
  /** The vault copy, used only while the server lists it as this account's identity (or cannot be reached). */
  async function heldIdentity() {
    if (!identityRef.current) {
      const local = await getIdentityKey(auth.username, auth.user.id).catch(() => undefined);
      const live = local ? await myIdentity().catch(() => "unreachable" as const) : undefined;
      identityRef.current = currentCopy(local, live);
      waitingRef.current = identityRef.current && waitingKey(identityRef.current);
      setWaitingHeld(Boolean(waitingRef.current));
    }
    return identityRef.current;
  }
  // What this browser can do about the account's identity; "unknown" until checked.
  const [identityState, setIdentityState] = useState<IdentityStatus | "unknown">("unknown");
  // A reset from this browser committed but its answer never arrived: explained, nothing deleted (M4).
  const [resetUnfinished, setResetUnfinished] = useState(false);
  async function refreshIdentity() {
    identityRef.current = undefined;
    const [local, live, sent] = await Promise.all([loadIdentityRecord(auth.username, auth.user.id).catch(() => undefined), myIdentity(), resetSentKey(auth.username, auth.user.id)]);
    liveRef.current = live ?? null;
    setLive(live ?? null);
    setIdentityState(identityStatus(local, live));
    setResetUnfinished(unfinishedReset(local, live, sent));
    await heldIdentity();
  }
  /** After a reset here: edits waiting under the replaced key are never sent, and stay exportable when this browser held it (M5). */
  async function retireWaitingEdits(next: HeldIdentity) {
    const old = waitingRef.current;
    const fresh = waitingKey(next);
    await retireWaiting((await pendingSaves()).filter((item) => item.owner === auth.user.id), auth.user.id, async (item) => {
      const payload = old && (await decryptObject(old, item.containerID, item.id, item.payload, true));
      return payload ? encryptNote(fresh, item.containerID, item.id, payload) : undefined;
    }, replaceQueuedSave);
  }
  useEffect(() => { void refreshIdentity().catch(() => undefined); void heldIdentity().catch(() => undefined); }, []);
  /**
   * A created, restored, linked or reset identity: the notebook list and the open notebook are read
   * again, so names and items that could not be decrypted without it appear without a reload.
   */
  const afterIdentityChange = () => {
    setRecoveryPrompt(false);
    // The open notebook's "could not be read" notice is shown again if it still applies.
    setError("");
    void refreshIdentity().then(() => loadContainers(), () => undefined);
  };
  // A refused SSO key set-up or key share (an open KySignOn confirmation can be cancelled from it).
  const [identityRefusal, setIdentityRefusal] = useState<LinkRefusal>();
  const identityStore: IdentityStore = { load: () => loadIdentityRecord(auth.username, auth.user.id), save: (identity, expected) => storeIdentityKey(auth.username, auth.user.id, identity, expected), noteReset: (publicKey) => noteResetSent(auth.username, auth.user.id, publicKey) };
  /** A single sign-on account's key: created (or an orphan replaced) only on the user's click, confirmed with KySignOn. */
  async function setUpSSOIdentity(replace: boolean) {
    if (replace && !confirm("Replace this browser's encryption key with a new one? Team owners must share their notebooks' keys with you again, and colleagues are asked to trust your new key.")) return;
    setIdentityRefusal(undefined);
    try {
      const settled = await settleSSOIdentity({ myIdentity, putDeviceOnlyIdentity }, identityStore, replace);
      // The first browser shows the recovery code right away (§8 item 1).
      if (settled.kind === "held") { setRecoveryPrompt(true); openSettings("account"); }
      if (settled.kind === "unsaved") setIdentityRefusal({ message: "This browser cannot keep an encryption key (site storage is blocked or unavailable), so none was created." });
      await refreshIdentity();
    } catch (err) {
      setIdentityRefusal(linkRefusal(err, "set up an encryption key"));
    }
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
    // SSO sessions confirm each protected request with KySignOn (actionFetch); there is no session-wide step-up.
    // A reopened password session holds no login secret (the vault keeps none): every caller in this
    // tab shares one prompt, and its answer stays in memory only. A cancelled prompt asks again next time.
    stepUp: auth.sso ? async () => {} : async () => {
      if (auth.authSecret) return void (await stepUp(auth.authSecret));
      asked.current ??= stepUpAsking(auth.username).then((secret) => { onAuthSecret(secret); return secret; });
      try { await stepUp(await asked.current); } catch (error) { asked.current = undefined; throw error; }
    },
    putEnvelopes,
    rotate: rotateKeys,
  };
  // Reads are not caught: empty pins or key memory would make a swapped key look first-seen.
  const pinStore: PinStore = {
    load: () => getPins(auth.username, auth.user.id),
    addFresh: (pins) => storePins(auth.username, auth.user.id, pins),
    confirm: (confirmation, expected) => storeConfirmedPin(auth.username, auth.user.id, confirmation, expected),
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
    if (plan.kind === "unrecoverable") notices.push(UNRECOVERABLE);
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
  async function syncKeys(container: Container, background = false, superseded: () => boolean = () => false, share = false): Promise<Container> {
    // Every notebook gets a pass: its floor first, then its keys. A never-shared notebook the user owns is minted here.
    await ensureFloor(container);
    if (liveRef.current === undefined) await refreshIdentity().catch(() => undefined);
    return serialized(container.id, async () => {
      const confirmChanged = background ? () => false : (changes: PinChange[]) => !superseded() && confirmChangedKeys(container.id)(changes);
      const result = await syncContainerKeys(keyAPI, container.id, { userId: auth.user.id, identity: await heldIdentity(), canWrap: share || (!auth.sso && (!background || auth.authSecret !== "")), recoverable: recoverable(liveRef.current) }, pinStore, confirmChanged, ringsRef.current[container.id], raiseFloorIn);
      putRing(container.id, result.ring);
      for (const member of result.members) colleagueNames.current[member.userId] = member.username;
      raiseFloorIn(container.id, result.known);
      let next = { ...container, keyGeneration: result.container.keyGeneration, sharedGeneration: result.container.sharedGeneration };
      setItems((value) => value.map((entry) => (entry.id === next.id ? { ...entry, keyGeneration: next.keyGeneration, sharedGeneration: next.sharedGeneration } : entry)));
      let renamed = "";
      if (result.minted) [next, renamed] = await resealName(next, result.members.some((member) => member.userId !== auth.user.id));
      // Pins a failed save did not keep are not announced.
      const fresh = [...(unannounced.current[container.id] ?? []), ...(result.plan.kind === "pins-unsaved" ? [] : result.fresh)];
      if (!superseded() && (loadingContainerID.current ?? selectedRef.current?.id) === container.id) {
        delete unannounced.current[container.id];
        // A rolled-back server's generations would mislabel every member; the rollback notice explains the pause.
        setKeyMembers({ containerID: container.id, members: result.members, status: result.plan.kind === "rollback" ? {} : memberKeyStatus(result.container, result.members, result.envelopes) });
        setKeyDeferred(result.deferred);
        setKeyNotice([await keyNoticeFor(result, fresh, !background), renamed].filter(Boolean).join(" "));
      } else {
        unannounced.current[container.id] = fresh;
      }
      return next;
    });
  }
  /** An SSO steward's explicit "share keys": the same pass, allowed to write (each write asks KySignOn). */
  async function shareKeysNow() {
    const open = selectedRef.current;
    if (!open) return;
    setIdentityRefusal(undefined);
    try { adoptGenerations(await syncKeys(open, false, () => false, true)); } catch (err) { setIdentityRefusal(linkRefusal(err, "share keys")); }
  }
  /**
   * After a mint, the name this browser already shows is sealed again with the new key, so
   * members can read it. Only that trusted name is resealed, from the server's latest state.
   */
  async function resealName(container: Container, others: boolean): Promise<[Container, string]> {
    try {
      const latest = await currentContainer(container.id);
      // Never hand back the older generations: a newer one without its key must stay read-only.
      const current = { ...container, metaCiphertext: latest.metaCiphertext, metaVersion: latest.metaVersion, changeSeq: latest.changeSeq, keyGeneration: latest.keyGeneration, sharedGeneration: latest.sharedGeneration };
      const write = writeKeyFor(latest);
      if (!write || !latest.metaCiphertext) return [current, ""];
      const meta = fromBase64(latest.metaCiphertext);
      // A marker found here is kept: a reseal never drops it.
      const opened = (keys: KeyRef[]) => openFirst(keys, (key) => decryptContainerMeta(key, container.id, meta, !migrated.current.has(container.id))).then(async (value) => { if (value.objects === 2) await noteMigrated(container.id); return value.name; }, () => undefined);
      if ((await opened([write.key])) !== undefined) return [current, ""];
      const ring = ringsRef.current[container.id] ?? noKeys;
      let name = namesRef.current[container.id];
      if (name) {
        // Older container keys are tried only to compare with the name already shown.
        if ((await opened([...ring.values()])) !== name) return [current, "This notebook's name changed while its keys were shared. Rename it so every member can read it."];
      } else {
        // Not shown (the list could not open it: a re-mint another browser deferred). Only container
        // keys this browser accepted may supply it, newest first.
        const older = [...ring.entries()].filter(([generation]) => generation < write.generation).sort(([a], [b]) => b - a).map(([, key]) => key);
        name = (await opened(older)) ?? "";
        if (!name) return [current, others ? "This notebook's name could not be shared with its members yet. Rename it so every member can read it." : "This notebook's name could not be sealed with its key yet. Rename it to try again."];
        const shown = name;
        setNames((value) => ({ ...value, [container.id]: shown }));
      }
      const encoded = base64(await encryptContainerMeta(write.key, container.id, name, migrated.current.has(container.id)));
      const result = await sendContainerName({ container: latest, generation: write.generation }, encoded, latest.metaVersion);
      setItems((value) => value.map((entry) => (entry.id === container.id ? { ...entry, metaCiphertext: encoded, metaVersion: result.metaVersion, changeSeq: result.changeSeq } : entry)));
      // Visible on purpose: members see the name re-sealed under the new key.
      return [{ ...current, metaCiphertext: encoded, metaVersion: result.metaVersion, changeSeq: result.changeSeq }, others ? `Sealed this notebook's name with its key: ${name}.` : ""];
    } catch {
      return [container, others ? "This notebook's name could not be shared with its members yet. Rename it to try again." : "This notebook's name could not be sealed with its key yet. Rename it to try again."];
    }
  }
  // Bumped to remount the open page's editor on content it did not produce.
  const [editorRevision, setEditorRevision] = useState(0);
  // The page a conflict recovery is rewriting; it stays read-only until the run ends.
  const [recovering, setRecovering] = useState<string | null>(null);
  const recoveringRef = useRef(false);
  // Settings is #/settings/<tab>, so its tabs are links and Back leaves it; notebooks keep their own routes.
  const [settingsTab, setSettingsTab] = useState(() => settingsTabOf(location.hash));
  const [view, setView] = useState<"workspace" | "settings">(settingsTab ? "settings" : "workspace");
  function openSettings(tab: SettingsTab) { location.hash = settingsHash(tab); }
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
  /** The cache write's failure, if any: it never blocks the send, and the caller reports the missing local copy. */
  const cacheMiss = (write: () => Promise<unknown>) => cacheWrite(write).then(() => false, () => true);
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
            const v1 = await v1ChildOpens(containerID, attachment.page, attachment.id, encrypted);
            const plaintext = await openFirst(selected ? readKeysFor(selected, attachment.keyGeneration) : [], (key) => decryptAttachment(key, containerID, attachment.page, encrypted, v1));
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
  useEffect(() => () => {
    resolvedURLs.current.forEach((url) => URL.revokeObjectURL(url));
    resolvedURLs.current = [];
  }, [selectedNote?.id]);
  const visibleNotes = useMemo(() => {
    const filtered = searchNotes(searchableNotes, query);
    return filtered.map((match) => match.note);
  }, [searchableNotes, query]);
  // The queue snapshot with this tab's newer copies of its pages, plus the open personal notebook's other pages.
  const liveQueue = useMemo(() => {
    const live = new Map(notes.map((note) => [note.id, note]));
    if (selectedNote) live.set(selectedNote.id, selectedNote);
    const queued = new Set(queueEntries.map((entry) => entry.note.id));
    const added = selected && selected.kind !== "team" && !selected.teamId
      ? [...live.values()].filter((note) => !queued.has(note.id)).map((note) => ({ note, container: selected }))
      : [];
    return [...queueEntries.map((entry) => ({ ...entry, note: live.get(entry.note.id) ?? entry.note })), ...added];
  }, [queueEntries, notes, selectedNote, selected]);
  const visibleQueueEntries = useMemo(() => {
    const indexed = indexNotes(liveQueue.map((entry) => entry.note));
    const matches = openTaskNotes(searchNotes(indexed, query));
    const entriesByID = new Map(liveQueue.map((entry) => [entry.note.id, entry]));
    return matches.map((match) => entriesByID.get(match.note.id)).filter((entry): entry is QueueEntry => Boolean(entry));
  }, [liveQueue, query]);
  const queueTasks = useMemo(() => liveQueue.flatMap((entry) => noteDatedTasks(indexNotes([entry.note])[0])
    .map((task) => ({ ...task, entry, key: `${entry.note.id}\n${task.raw}` }))), [liveQueue]);
  const missedReminders = useReminders(queueTasks, reminderPrefs);
  // Reminders read the same personal notebooks as the work queue, loaded once they are on.
  // A queue opened before the notebook list arrived is reloaded with it.
  useEffect(() => {
    if ((reminderPrefs.enabled || reminderPrefs.push || queueMode) && items.length) void loadWorkQueue().catch(() => undefined);
  }, [reminderPrefs.enabled, reminderPrefs.push, items.length]);
  // On open: re-registers this browser for this account (a server that lost the subscription or replaced
  // its key), or, with push off for this account, drops whatever subscription another account left here.
  useEffect(() => { void (reminderPrefs.push ? ensurePushSubscription() : dropPushSubscription()).catch(() => undefined); }, []);
  // Push reminders: the server holds {id, at} for exactly the open push:yes tasks with a future time.
  const pushTasks = useMemo(() => queueTasks.filter((task) => task.push).map((task) => ({ noteID: task.entry.note.id, remind: task.remind, push: true })), [queueTasks]);
  const pushTaskKey = pushTasks.map((task) => `${task.noteID}\n${task.remind}`).sort().join("\n");
  const reconciling = useRef(Promise.resolve());
  useEffect(() => {
    if (!reminderPrefs.push || !queueComplete) return;
    reconciling.current = reconciling.current.then(async () => {
      const identity = await heldIdentity();
      if (!identity) return;
      const plan = planReconcile(desiredReminders(reminderIDKey(identity), pushTasks, Date.now()), await serverReminders(), queueComplete);
      for (const id of plan.deletes) await deleteReminder(id);
      for (const row of plan.puts) await putReminder(row.id, row.at);
    }).catch(() => undefined);
  }, [reminderPrefs.push, queueComplete, pushTaskKey]);
  const listEntries = queueMode
    ? visibleQueueEntries
    : (query.trim() ? visibleNotes : sectionPages)
        .map((note) => ({ note, container: selected }))
        .filter((entry): entry is QueueEntry => Boolean(entry.container));
  const reorderable = !queueMode && !query.trim();
  const queueShown = new Set(visibleQueueEntries.map((entry) => entry.note.id));
  const queueRows = queueMode ? queueTasks.filter((task) => queueShown.has(task.entry.note.id))
    .map((task) => ({ ...task, missed: missedReminders.has(task.key), group: classifyTask(task, new Date(), missedReminders.has(task.key)) }))
    .sort((a, b) => (a.due ?? "~").localeCompare(b.due ?? "~")) : [];
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
    const follow = () => {
      const tab = settingsTabOf(location.hash);
      // An old jump link (#password…) takes its tab's address without a history entry.
      if (tab && location.hash !== settingsHash(tab)) history.replaceState(null, "", settingsHash(tab));
      if (tab) { setShowNotebookNavigation(false); setSettingsTab(tab); }
      setView(tab ? "settings" : "workspace");
    };
    follow();
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, []);
  // Read, not a dependency: a hash change to another page also flips the view, and re-running then would write the old page back.
  const viewRef = useRef(view);
  viewRef.current = view;
  useEffect(() => {
    // Leaving Settings by a nav row adds an entry, so Back returns to the tab.
    if (view !== "workspace" || !settingsTabOf(location.hash)) return;
    if (queueMode || !selected) history.pushState(null, "", location.pathname + location.search);
    else location.hash = formatRoute({ container: selected.id, section: sectionID, page: selectedNote?.id });
  }, [view]);
  useEffect(() => {
    if (viewRef.current !== "workspace" || queueMode || loadingContainer || !selected) return;
    const next = formatRoute({ container: selected.id, section: sectionID, page: selectedNote?.id });
    if (location.hash === next) return;
    // Normalizing an empty or unparseable hash must not add a history entry.
    if (parseRoute(location.hash).container) location.hash = next;
    else history.replaceState(null, "", next);
  }, [queueMode, loadingContainer, selected?.id, sectionID, selectedNote?.id]);
  useEffect(() => {
    const follow = () => void (async () => {
      // A pasted invitation link: out of the address bar, into the banner.
      const link = takeInviteLink(location, history, sessionStore());
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
    if (!open || loadingContainerID.current || document.visibilityState !== "visible") return;
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
  // A page in conflict is not autosaved: each send would be refused and kept as one more conflict copy.
  const autosaving = dirty && selectedNote !== null && !conflicted.has(selectedNote.id);
  useEffect(() => {
    if (!autosaving) return;
    const timer = window.setTimeout(() => {
      void save(selectedNote!, true);
    }, 900);
    return () => window.clearTimeout(timer);
  }, [selectedNote?.title, selectedNote?.body, autosaving]);
  useEffect(() => {
    if (!autosaving) return;
    // save() sends the newest open page; keystrokes must not restart this timer.
    const timer = window.setInterval(() => {
      if (selectedNoteRef.current) void save(selectedNoteRef.current, true);
    }, 15000);
    return () => window.clearInterval(timer);
  }, [selectedNote?.id, autosaving]);
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
  /** pick: open the routed or first notebook afterwards. */
  async function loadContainers(pick = true) {
    const opened = loads.mark();
    try {
      const value = await listContainers(floorSink);
      const loaded = value;
      const nextNames: Record<string, string> = {};
      let olderMeta = false;
      const identity = await heldIdentity();
      // The list just fetched answers every pass, instead of one list fetch per container.
      const listed: KeyAPI = { ...keyAPI, container: async (id) => loaded.find((entry) => entry.id === id) ?? currentContainer(id) };
      for (const item of loaded) {
        try {
          let keyed: Container = item;
          // Team containers: this device's sharing floor first, so a server reporting "never shared" still gets the shared rules.
          const floor = await pinStore.loadKeyState(item.id);
          raiseFloorIn(item.id, floor);
          if (floor.objects === 2) migrated.current.add(item.id);
          // Shared names need their keys. This pass only reads: it never steps up, wraps, rotates
          // or asks about a changed key. A steward's sharing waits until the notebook is opened.
          // ponytail: a full key pass per shared notebook on every list load (members, one identity
          // fetch per member, all envelopes). Upgrade: a batch route returning this user's envelopes
          // and member identities for every container in one call.
          if (item.sharedGeneration > 0 || (floor.shared ?? 0) > 0) {
            const result = await serialized(item.id, async () => {
              const pass = await syncContainerKeys(listed, item.id, { userId: auth.user.id, identity, canWrap: false, recoverable: false }, pinStore, () => false, ringsRef.current[item.id], raiseFloorIn);
              putRing(item.id, pass.ring);
              for (const member of pass.members) colleagueNames.current[member.userId] = member.username;
              raiseFloorIn(item.id, pass.known);
              return pass;
            });
            if (result.plan.kind !== "pins-unsaved" && result.fresh.length) unannounced.current[item.id] = [...(unannounced.current[item.id] ?? []), ...result.fresh];
            keyed = { ...item, keyGeneration: result.container.keyGeneration, sharedGeneration: result.container.sharedGeneration };
          }
          if (item.metaCiphertext) {
            const meta = await openMeta(keyed);
            // After the marker, a name without it (v1 or an older v2 copy) is a rollback: refused.
            if (migrated.current.has(item.id) && meta.objects !== 2) olderMeta = true;
            else nextNames[item.id] = meta.name;
          }
        } catch {
          /* encrypted metadata may be unavailable in a session-only resume */
        }
      }
      // A notebook opened or created meanwhile outranks the pick and may be missing from this list.
      if (opened()) return await loadContainers(false);
      setNames(nextNames);
      setItems(loaded);
      if (olderMeta) setError(OLDER_META);
      const route = parseRoute(location.hash);
      const start = loaded.find((item) => item.id === route.container) ?? loaded[0];
      if (start && pick) await selectContainer(start, start.id === route.container ? route : undefined, false);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to load notebooks",
      );
    }
  }
  /** legacy: objects whose server copy is v1, or not proven v2 (a newer local copy was shown). */
  async function readContainerObjects(container: Container): Promise<{ notes: Note[]; sections: Section[]; groups: Group[]; unreadable: number; legacy: Set<string> }> {
    let unreadable = 0;
    const legacy = new Set<string>();
    // Server copies: v1 only before the notebook's migration marker. Local copies: this browser sealed them.
    const v1 = !migrated.current.has(container.id);
    const loaded: Note[] = [];
    const found: Section[] = [];
    const foundGroups: Group[] = [];
    const add = (id: string, payload: ObjectPayload | undefined, version: number, updatedAt: string) => {
      if (!payload) return;
      if (payload.type === "section") found.push({ ...payload, id, version });
      else if (payload.type === "group") foundGroups.push({ ...payload, id, version });
      else loaded.push({ id, title: payload.title, body: payload.body, section: payload.section, order: payload.order, level: payload.level, legacy: payload.legacy, version, updatedAt });
    };
    let since = 0;
    for (let page = 0; page < MAX_CHANGE_PAGES; page += 1) {
      const result = await changes(container.id, since);
      for (const change of result.changes.filter((entry) => entry.kind === "object" && !entry.deleted)) {
        try {
          const object = await readObject(change.id);
          const cached = await getNote(auth.user.id, change.id);
          const useCache = Boolean(cached && cached.version >= object.version);
          const server = (allowV1: boolean) => openFirst(readKeysFor(container, object.keyGeneration), (key) => openObject(key, container.id, change.id, object.bytes, allowV1));
          const payload = useCache
            ? await openFirst(ownCopyKeysFor(container, cached!.keyGeneration), (key) => decryptObject(key, container.id, change.id, cached!.payload, true))
            : await server(v1).then((opened) => { if (opened.v1) legacy.add(change.id); return opened.payload; });
          // The server copy's format still decides migration.
          if (useCache && (await server(false).then(() => false, () => true))) legacy.add(change.id);
          add(change.id, payload, useCache ? cached!.version : object.version, useCache ? cached!.updatedAt : object.savedAt);
        } catch {
          try {
            const cached = await getNote(auth.user.id, change.id);
            if (!cached) throw new Error("no local copy");
            add(change.id, await openFirst(ownCopyKeysFor(container, cached.keyGeneration), (key) => decryptObject(key, container.id, change.id, cached.payload, true)), cached.version, cached.updatedAt);
            legacy.add(change.id);
          } catch {
            unreadable += 1;
          }
        }
      }
      if (!result.hasMore) break;
      const next = Number(result.nextCursor);
      if (!Number.isSafeInteger(next) || next <= since) break;
      since = next;
    }
    return { notes: loaded, sections: found, groups: foundGroups, unreadable, legacy };
  }
  async function chooseNotebook(container: Container) {
    // Back from Settings to the open notebook: nothing to reload.
    const back = view !== "workspace" && selected?.id === container.id && !queueMode;
    setView("workspace");
    if (back) {
      setShowNotebookNavigation(false);
      return;
    }
    // On phones the menu stays open so a page can be picked next.
    await selectContainer(container);
  }
  /** Null when the open page could not be flushed and stays open. */
  /** leaveQueue false: an automatic load (sign-in, reload) that must not close a work queue opened meanwhile. */
  async function selectContainer(container: Container, route?: Route, leaveQueue = true): Promise<Note[] | null> {
    // Every call supersedes the ones before it, a second load of the same notebook included.
    const load = loads.begin();
    loadingContainerID.current = container.id;
    setLoadingContainer(true);
    try {
      return await loadContainer(container, route, load.superseded, leaveQueue);
    } finally {
      // A later load owns the flag now.
      if (!load.superseded()) {
        loadingContainerID.current = undefined;
        setLoadingContainer(false);
      }
    }
  }
  async function loadContainer(container: Container, route: Route | undefined, superseded: () => boolean, leaveQueue: boolean): Promise<Note[] | null> {
    // Workspace navigation destroys the current editor. Finish its latest
    // encrypted save before replacing the note list so the next load cannot
    // fall back to an older plain document.
    if (!(await flushOpenPage())) return null;
    // Another load started meanwhile: its results win.
    if (superseded()) return [];
    // Nothing from the previous notebook may stay editable under this one's key.
    setSelected(container);
    if (leaveQueue) setQueueMode(false);
    selectedNoteRef.current = null;
    setSelectedNote(null);
    patchNotes(() => []);
    patchSections(() => []);
    patchGroups(() => []);
    setGroupID(undefined);
    setCommentsForNote([]);
    setAttachmentsForNote([]);
    loadCarried.current.clear();
    setKeyNotice("");
    setKeyDeferred(false);
    try {
      // Keys first: an owner may mint or re-mint here, and reads need the current generation.
      const keyed = await syncKeys(container, false, superseded).catch((error) => {
        if (!superseded()) setError(error instanceof Error ? `Unable to share this notebook's keys: ${error.message}` : "Unable to share this notebook's keys");
        return container;
      });
      if (superseded()) return [];
      setSelected(keyed);
      if ((await pinStore.loadKeyState(keyed.id)).objects === 2) migrated.current.add(keyed.id);
      const objects = await readContainerObjects(keyed);
      if (superseded()) return [];
      if (objects.unreadable) setError(unreadableNotice(objects.unreadable));
      const loaded = carryAll(objects.notes, loadCarried.current);
      const loadedSections = carryVersions(objects.sections, loadCarried.current);
      patchSections(() => loadedSections);
      patchGroups(() => carryVersions(objects.groups, loadCarried.current));
      loadCarried.current.clear();
      patchNotes(() => loaded);
      showSection(resolveSection(route?.section, loadedSections));
      const routed = route?.page ? loaded.find((note) => note.id === route.page) : undefined;
      if (routed) await selectNote(routed, keyed);
      const team = container.kind === "team" ? await members(container.id) : [];
      if (!superseded()) setMembersForTeam(team);
      // Writers migrate in the background once this load has rendered (migrateOpen); viewers never do.
      const role = container.kind === "team" ? team.find((member) => member.userId === auth.user.id)?.role : "owner";
      if (!superseded() && (role === "owner" || role === "admin" || role === "editor")) {
        const kinds = [...loaded.map((note) => ({ id: note.id, type: "page" as const, legacy: note.legacy })), ...loadedSections.map(({ id }) => ({ id, type: "section" as const })), ...objects.groups.map(({ id }) => ({ id, type: "group" as const }))];
        migrationDue.current = { containerID: keyed.id, unreadable: objects.unreadable, objects: kinds.map((object) => ({ ...object, v1: objects.legacy.has(object.id) })) };
        setMigrationTick((value) => value + 1);
      }
      return loaded;
    } catch (error) {
      if (!superseded()) setError(error instanceof Error ? error.message : "Unable to load notebook");
      return [];
    }
  }
  async function loadWorkQueue() {
    const personalContainers = items.filter((item) => item.kind !== "team" && !item.teamId);
    const results = await Promise.allSettled(personalContainers.map(async (container) => {
      const { notes, unreadable } = await readContainerObjects(container);
      return { container, notes, unreadable };
    }));
    if (results.some((result) => result.status === "rejected")) {
      setError("Some personal notebooks could not be loaded; the work queue may be incomplete.");
    }
    setQueueComplete(results.every((result) => result.status === "fulfilled" && result.value.unreadable === 0));
    const entries = results.flatMap((result) => result.status === "fulfilled"
      ? result.value.notes.map((note) => ({ note, container: result.value.container }))
      : []);
    setQueueEntries(entries);
  }
  async function openWorkQueue() {
    setShowNotebookNavigation(false);
    setView("workspace");
    setQueueMode(true);
    setBusy(true);
    try {
      await loadWorkQueue();
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
    const note = previous?.id === selection.id ? previous : notesRef.current.find((entry) => entry.id === selection.id) ?? selection;
    selectedNoteRef.current = note;
    setSelectedNote(note);
    if (previous?.id !== note.id) {
      markDirty(false);
      setLastSavedAt(note.version > 0 ? note.updatedAt : "");
    }
    // A later selection or notebook switch owns the panels below.
    const current = () => selectedNoteRef.current?.id === note.id;
    try { const conflicts = await objectConflicts(note.id); setConflicted((value) => { const next = new Set(value); if (conflicts.some((item) => !item.resolved)) next.add(note.id); else next.delete(note.id); return next; }); } catch { /* conflict metadata is advisory */ }
    try {
      const remote = await comments(note.id);
      const decoded: PlainComment[] = [];
      for (const item of remote) {
        try {
          const bytes = fromBase64(item.bodyCiphertext);
          const v1 = await v1ChildOpens(containerID, note.id, item.id, bytes);
          const decrypted = await openFirst(container ? readKeysFor(container, item.keyGeneration) : [], (key) => decryptComment(key, containerID, note.id, bytes, v1));
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
          const meta = fromBase64(item.metadataCiphertext);
          const v1 = await v1ChildOpens(containerID, note.id, metaPin(item.id), meta);
          const metadata = await openFirst(container ? readKeysFor(container, item.keyGeneration) : [], (key) => decryptAttachmentMetadata(key, containerID, note.id, meta, v1));
          decoded.push({ id: item.id, ...metadata, keyGeneration: item.keyGeneration, page: note.id });
        } catch { /* Ignore metadata encrypted for another key. */ }
      }
      if (current()) setAttachmentsForNote(decoded);
    } catch {
      if (current()) setAttachmentsForNote([]);
    }
    return true;
  }
  /**
   * Creates a notebook, mints its first key before anything is written (the user's click is the consent;
   * an SSO session confirms the rotation with KySignOn) and seals its name with that key. The login key
   * never seals. A notebook whose mint or naming failed is deleted while still empty (createKeyed); if that
   * is refused it stays unnamed and read-only until its owner reopens it.
   */
  async function createNamed(create: () => Promise<Container>, name: string): Promise<Container> {
    // Checked before anything is created: a refused mint must not leave an unnamed notebook behind.
    if (!(await heldIdentity())) throw new Error(NO_KEY_HERE);
    if (liveRef.current === undefined) await refreshIdentity().catch(() => undefined);
    if (!recoverable(liveRef.current)) throw new Error(UNRECOVERABLE);
    const named = await createKeyed(create, async (created) => {
      const container = await syncKeys(created, false, () => false, true);
      const write = writeKeyFor(container);
      if (!write) throw new Error(NOT_KEYED);
      // Empty, so already migrated: its first name carries the marker.
      const encoded = base64(await encryptContainerMeta(write.key, container.id, name, true));
      const result = await sendContainerName({ container, generation: write.generation }, encoded, container.metaVersion);
      return { ...container, metaCiphertext: encoded, metaVersion: result.metaVersion, changeSeq: result.changeSeq };
    }, deleteContainer);
    await noteMigrated(named.id);
    setNames((value) => ({ ...value, [named.id]: name }));
    setItems((value) => [...value.filter((entry) => entry.id !== named.id), named]);
    return named;
  }
  async function newWorkspace() {
    const name = prompt("Notebook name", "My notebook")?.trim();
    if (!name) return;
    setBusy(true);
    try {
      await chooseNotebook(await createNamed(() => newContainer(floorSink, "workbook"), name));
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to create notebook");
    } finally {
      setBusy(false);
    }
  }
  async function newTeamWorkspace(teamContainer: Container) {
    const name = prompt("Notebook name", "New notebook")?.trim();
    if (!name) return;
    setBusy(true);
    try {
      await chooseNotebook(await createNamed(() => newContainer(floorSink, "workbook", teamContainer.id), name));
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
      if (!write) throw new Error(WAITING);
      // A marker another device wrote is kept.
      if (fresh.metaCiphertext) await openMeta(fresh).catch(() => undefined);
      const encrypted = await encryptContainerMeta(write.key, fresh.id, name, migrated.current.has(fresh.id));
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
  /** Decrypts the notebook here and downloads it as a plaintext zip; nothing new is sent to the server. */
  async function exportWorkspace() {
    if (!selected) return;
    const container = selected;
    const name = nameOf(container);
    if (!confirm(`${EXPORT_WARNING}\n\nExport "${name}"?`)) return;
    setBusy(true);
    try {
      const { blockNoteMarkdown, buildNotebookExport, safeName } = await import("./exportNotebook");
      const loaded = await readContainerObjects(container);
      const result = await buildNotebookExport({
        name, ...loaded, toMarkdown: await blockNoteMarkdown(),
        attachments: {
          list: async (pageID) => (await objectAttachments(pageID)).map((item) => ({ ...item, pageID })),
          open: async (item) => {
            const keys = readKeysFor(container, item.keyGeneration);
            const page = loaded.notes.find((note) => note.id === item.pageID);
            const done = migrated.current.has(container.id);
            const meta = fromBase64(item.metadataCiphertext);
            const metaV1 = await legacyChildOpens(page, done, metaPin(item.id), meta);
            const metadata = await openFirst(keys, (key) => decryptAttachmentMetadata(key, container.id, item.pageID, meta, metaV1));
            const encrypted = await downloadAttachment(item.id);
            const v1 = await legacyChildOpens(page, done, item.id, encrypted);
            return { id: item.id, ...metadata, bytes: await openFirst(keys, (key) => decryptAttachment(key, container.id, item.pageID, encrypted, v1)) };
          },
        },
      });
      downloadFile(`${safeName(name, "notebook")}.zip`, zip(result.entries), "application/zip");
      setError(`Exported ${result.pages} pages.${result.unreadable ? ` ${result.unreadable} items could not be read and are not in the file.` : ""}`);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to export notebook");
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
        legacy: {},
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
      const write = localKeyFor(selected) ?? notSaved();
      const encrypted = await encryptNote(write.key, selected.id, note.id, notePayload(note));
      const savedAt = new Date().toISOString();
      const containerID = selected.id;
      const uncached = await cacheMiss(() => putNote(auth.user.id, { id: note.id, containerID, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: write.generation }));
      if (write.generation === WAITING_GENERATION) {
        // No key for the current generation: queue the edit; the drain re-seals it once keys arrive.
        await queueOwn({ id: note.id, containerID, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: write.generation, owner: auth.user.id }).catch(notSaved);
        setSyncStatus("local");
        setError(queuedNotice(stewardHere(selected)));
        return note;
      }
      try {
        const result = await sendObject({ container: selected, generation: write.generation }, note.id, encrypted, note.version);
        await clearOwnQueued(note.id);
        setCommitToastAt(Date.now());
        setConflicted((value) => { const next = new Set(value); next.delete(note.id); return next; });
        const saved = { ...note, version: result.version, updatedAt: savedAt };
        setLastSavedAt(savedAt);
        setSyncStatus("saved");
        if (uncached) setError(UNCACHED);
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
          setError(noteConflictMessage(uncached));
        } else {
          await queueOwn({ id: note.id, containerID: selected.id, version: note.version, payload: encrypted, updatedAt: savedAt, keyGeneration: write.generation, owner: auth.user.id }).catch(notSaved);
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

  function chained<T>(task: () => T | Promise<T>): Promise<T> {
    const run = saveChain.current.then(task);
    saveChain.current = run.then(() => {}, () => {});
    return run;
  }
  function queueOwn(item: PendingSave) {
    ownQueued.current.set(item.id, item.updatedAt);
    return queueSave(item);
  }
  /** A save of id landed: this tab's older queued copy is obsolete; another tab's newer one is not. */
  async function clearOwnQueued(id: string) {
    const updatedAt = ownQueued.current.get(id);
    if (!updatedAt) return;
    ownQueued.current.delete(id);
    // ponytail: an entry queued before a reload is unknown here and stays; its later send is a
    // conflict the user keeps as a copy. Upgrade: record the queueing tab in the entry.
    await clearQueuedSave(auth.user.id, id, updatedAt);
  }

  function save(note: Note, automatic = false) {
    return chained(() => {
      const current = selectedNoteRef.current;
      if (!current || current.id !== note.id) return;
      // Use the latest in-memory note when an older autosave was waiting in
      // the chain. This keeps the server request/version aligned with the
      // document currently shown in the editor.
      return saveNow(current, automatic);
    });
  }

  /** Leaving the open page. False keeps it open and dirty; callers must not switch away then. */
  async function flushOpenPage(): Promise<boolean> {
    if (!dirtyRef.current) return true;
    const state = await flushUntilStable(() => selectedNoteRef.current, (open) => save(open, true), FLUSH_ROUNDS);
    // A failed save already reported why.
    if (state === "busy") setError("This page is still saving. Try again in a moment.");
    return state === "done";
  }

  /** Queues one drain behind pending saves; a drain already waiting there sees new entries. */
  function drainQueue() {
    if (draining.current) return;
    draining.current = true;
    void chained(drainNow);
  }
  async function drainNow() {
    try {
      // Only this account's edits: another account's entry could be sent, misattributed, to a notebook both share.
      // previousKey: sealed for a key a reset replaced; never sent (Settings → Unsent edits lists it).
      const queued = (await pendingSaves()).filter((item) => item.owner === auth.user.id).filter((item) => !item.previousKey);
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
          // until Settings → Unsent edits exports or discards it. Waiting edits are sealed with the identity's
          // waiting key.
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
   * Waiting edits are sealed with the identity's waiting key.
   */
  async function sendable(item: PendingSave, synced: Map<string, Promise<Container>>): Promise<{ item: PendingSave; container: Container } | undefined> {
    // One background key pass per container per drain; it never opens a dialog.
    if (!synced.has(item.containerID)) synced.set(item.containerID, currentContainer(item.containerID).then((found) => syncKeys(found, true)));
    const container = await synced.get(item.containerID)!;
    adoptGenerations(container);
    const ready = await readyToSend(item, container, floorFor(container), writeKeyFor(container), ringsRef.current[container.id] ?? noKeys, waitingRef.current);
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
      await deleteCachedNote(auth.user.id, note.id);
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
    if (!write) return;
    void cacheWrite(async () => putNote(auth.user.id, {
      id: note.id,
      containerID,
      version: note.version,
      payload: await encryptNote(write.key, containerID, note.id, notePayload(note)),
      updatedAt: new Date().toISOString(),
      keyGeneration: write.generation,
    })).catch(() => {});
  }
  /** Encrypted write for an object that is not the open page (sections, moved pages). */
  async function writeObject(id: string, version: number, payload: ObjectPayload): Promise<number | null> {
    if (!selected) return null;
    const write = localKeyFor(selected) ?? notSaved();
    const encrypted = await encryptNote(write.key, selected.id, id, payload);
    const updatedAt = new Date().toISOString();
    const containerID = selected.id;
    const uncached = await cacheMiss(() => putNote(auth.user.id, { id, containerID, version, payload: encrypted, updatedAt, keyGeneration: write.generation }));
    if (write.generation === WAITING_GENERATION) {
      await queueOwn({ id, containerID, version, payload: encrypted, updatedAt, keyGeneration: write.generation, owner: auth.user.id }).catch(notSaved);
      setSyncStatus("local");
      setError(queuedNotice(stewardHere(selected)));
      return null;
    }
    try {
      const result = await sendObject({ container: selected, generation: write.generation }, id, encrypted, version);
      await clearOwnQueued(id);
      carryDuringLoad(id, { version: result.version, updatedAt });
      if (uncached) setError(UNCACHED);
      return result.version;
    } catch (error) {
      if (error instanceof APIRequestError && error.code === "version_conflict") {
        setConflicted((value) => new Set(value).add(id));
        setSyncStatus("attention");
        setError("This item changed on another device. Reopen the notebook before changing it again.");
      } else {
        await queueOwn({ id, containerID: selected.id, version, payload: encrypted, updatedAt, keyGeneration: write.generation, owner: auth.user.id }).catch(notSaved);
        syncChannel.current?.postMessage({ type: "queued", id });
        setSyncStatus("local");
        if ((error instanceof APIRequestError && error.code === "already_exists") || error instanceof KeysWaitingError) void drainQueue();
      }
      return null;
    }
  }

  /**
   * Chained encrypted write of a section or group, from its newest local copy; resolves true once saved.
   */
  function updateStructure(kind: "section" | "group", id: string, change: Partial<Pick<SectionPayload, "title" | "color" | "order" | "group">>) {
    if (readOnlyForKeys()) return Promise.resolve(false);
    const patch = (update: <T extends Section | Group>(value: T[]) => T[]) => (kind === "section" ? patchSections(update) : patchGroups(update));
    patch((value) => value.map((entry) => (entry.id === id ? { ...entry, ...change } : entry)));
    return chained(async () => {
      const current = kind === "section" ? sectionsRef.current.find((entry) => entry.id === id) : groupsRef.current.find((entry) => entry.id === id);
      if (!current) return false;
      const { id: _id, version, ...payload } = current;
      const saved = await writeObject(id, version, payload);
      if (saved !== null) patch((value) => value.map((entry) => (entry.id === id ? { ...entry, version: saved } : entry)));
      return saved !== null;
    });
  }

  // A load queues one background migration pass; it runs once that load has rendered, so its writes use
  // the loaded notebook (writeObject reads this render's selected).
  const migrationDue = useRef<{ containerID: string; objects: LoadedObject[]; unreadable: number } | undefined>(undefined);
  const [migrationTick, setMigrationTick] = useState(0);
  const migrating = useRef(false);
  useEffect(() => {
    const due = migrationDue.current;
    migrationDue.current = undefined;
    if (!due || migrating.current || selected?.id !== due.containerID || !writeKeyFor(selected)) return;
    migrating.current = true;
    void migrateOpen(selected, due).catch(() => undefined).finally(() => { migrating.current = false; });
  }, [migrationTick]);
  /** migrate.ts on the open notebook; it stops writing once the user leaves it. */
  function migrateOpen(container: Container, due: { objects: LoadedObject[]; unreadable: number }) {
    const here = () => selectedRef.current?.id === container.id;
    return migrateNotebook(due.objects, due.unreadable, migrated.current.has(container.id), {
      pins: (pageID) => childPins(container, pageID),
      savePage: async (id, legacy) => here() && pinPage(id, legacy),
      saveStructure: async (kind, id) => here() && updateStructure(kind, id, {}),
      mark: async () => {
        const current = selectedRef.current;
        const name = namesRef.current[container.id];
        const write = current?.id === container.id ? writeKeyFor(current) : undefined;
        if (!current || !write || name === undefined) return false;
        const encoded = base64(await encryptContainerMeta(write.key, container.id, name, true));
        const result = await sendContainerName({ container: current, generation: write.generation }, encoded, current.metaVersion);
        await noteMigrated(container.id);
        const next = { metaCiphertext: encoded, metaVersion: result.metaVersion, changeSeq: result.changeSeq };
        setItems((value) => value.map((entry) => (entry.id === container.id ? { ...entry, ...next } : entry)));
        setSelected((value) => (value?.id === container.id ? { ...value, ...next } : value));
        return true;
      },
    });
  }
  /**
   * A page's v1 children that open with this notebook's keys, pinned by the SHA-256 of their ciphertext as
   * stored (attachment bytes downloaded and hashed here, never the server's digest). Children opening as
   * v2 need no pin; children that open in neither form are not pinned, and stay unreadable.
   */
  async function childPins(container: Container, pageID: string): Promise<Legacy> {
    const pins: Legacy = {};
    const opens = (generation: number | undefined, open: (key: KeyRef) => Promise<unknown>) => openFirst(readKeysFor(container, generation), open).then(() => true, () => false);
    const onlyV1 = async (generation: number | undefined, open: (key: KeyRef, v1: boolean) => Promise<unknown>) =>
      !(await opens(generation, (key) => open(key, false))) && opens(generation, (key) => open(key, true));
    for (const item of await comments(pageID)) {
      const bytes = fromBase64(item.bodyCiphertext);
      if (await onlyV1(item.keyGeneration, (key, v1) => decryptComment(key, container.id, pageID, bytes, v1))) pins[item.id] = await digestSha256Hex(bytes);
    }
    for (const item of await objectAttachments(pageID)) {
      const meta = fromBase64(item.metadataCiphertext);
      if (!(await onlyV1(item.keyGeneration, (key, v1) => decryptAttachmentMetadata(key, container.id, pageID, meta, v1)))) continue;
      // Bytes and metadata are pinned separately, so neither can be swapped in from another attachment.
      const bytes = await downloadAttachment(item.id);
      if (!(await opens(item.keyGeneration, (key) => decryptAttachment(key, container.id, pageID, bytes, true)))) continue;
      pins[item.id] = await digestSha256Hex(bytes);
      pins[metaPin(item.id)] = await digestSha256Hex(meta);
    }
    return pins;
  }
  /** A page re-saved v2 carrying its pins, from its newest local copy; true once saved on the server. */
  function pinPage(id: string, legacy: Legacy): Promise<boolean> {
    return chained(async () => {
      patchNotes((value) => editEntry(value, id, { legacy }));
      const open = selectedNoteRef.current;
      if (open?.id === id) {
        // The open page's own save carries the pins; the next load confirms it.
        const next = { ...open, legacy };
        selectedNoteRef.current = next;
        setSelectedNote(next);
        persistDraft(next);
        await saveNow(next, true);
        return false;
      }
      const entry = notesRef.current.find((note) => note.id === id);
      if (!entry) return false;
      const next = newestCopy(entry, await otherTabDraft(id));
      const saved = await writeObject(id, next.version, notePayload(next));
      if (saved !== null) patchNotes((value) => carrySaved(value, id, { version: saved }));
      return saved !== null;
    });
  }

  /** The shared cache's copy of a page; another tab may have written it. */
  async function otherTabDraft(id: string) {
    if (!selected) return undefined;
    const cached = await getNote(auth.user.id, id).catch(() => undefined);
    if (!cached) return undefined;
    const containerID = selected.id;
    const payload = await openFirst(ownCopyKeysFor(selected, cached.keyGeneration), (key) => decryptObject(key, containerID, id, cached.payload, true)).catch(() => undefined);
    return payload?.type === "page" ? { version: cached.version, title: payload.title, body: payload.body } : undefined;
  }

  async function placePage(id: string, placement: { section?: string; order?: string; level?: 0 | 1 | 2 }) {
    if (readOnlyForKeys()) return;
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
      await deleteCachedNote(auth.user.id, section.id);
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
          if (!(await updateStructure(kind, child.id, { group: parent }))) {
            setError((value) => value || "Could not move everything out of the group, so it was kept. Try again.");
            return;
          }
        }
      }
      await deleteObject(group.id);
      await deleteCachedNote(auth.user.id, group.id);
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
    if (id === sectionID) return showSection(id);
    // Leaving the open page: finish its save first, as selectNote does.
    if (!(await flushOpenPage())) return;
    selectedNoteRef.current = null;
    setSelectedNote(null);
    showSection(id);
    // As in OneNote, a section opens on its first page.
    const first = pagesInSection(notesRef.current, sectionsRef.current, id)[0];
    if (first) await selectNote(first);
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
  /**
   * Keeps one rejected version as a page next to original. True only once the copy is saved on the
   * server: writeObject returns null for a copy that was only queued or kept locally, and then this
   * is false, so the caller never resolves the record while the copy exists only in this browser.
   */
  async function placeConflictCopy(containerID: string, original: Pick<Note, "id" | "section" | "order" | "level">, payload: PagePayload, sameNotebook: () => boolean = () => true): Promise<boolean> {
    const { page, moves } = conflictCopy(pagesInSection(notesRef.current, sectionsRef.current, pageSection(original)), original, payload);
    const object = await createObject(containerID);
    const copy: Note = { id: object.id, title: page.title, body: page.body, section: page.section, order: page.order, level: page.level, legacy: page.legacy, version: 0, updatedAt: new Date().toISOString() };
    if (sameNotebook()) patchNotes((value) => [...value, copy]);
    const saved = await writeObject(object.id, 0, page);
    if (saved === null) return false;
    if (sameNotebook()) patchNotes((value) => carrySaved(value, object.id, { version: saved }));
    const run = moveChain.current.then(async () => {
      for (const move of moves) await placePage(move.id, { section: notesRef.current.find((note) => note.id === move.id)?.section, order: move.order });
    });
    moveChain.current = run.catch(() => {});
    await run;
    return true;
  }
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
      const v1 = !migrated.current.has(containerID);
      const payload = await openFirst(readKeysFor(container, server.keyGeneration), (key) => decryptObject(key, containerID, open.id, server.bytes, v1));
      if (payload?.type !== "page") throw new Error("Unable to read the server version of this page.");
      const reloaded = { title: payload.title, body: payload.body, section: payload.section, order: payload.order, level: payload.level, legacy: payload.legacy, version: server.version };
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
      const copyable = (await objectConflicts(open.id)).filter((item) => !item.resolved);
      for (const conflict of copyable) {
        try {
          const bytes = await conflictCiphertext(conflict.id);
          const decrypted = await openFirst(readKeysFor(container, conflict.keyGeneration), (key) => decryptObject(key, containerID, open.id, bytes, v1)).catch(() => undefined);
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
          if (!(await placeConflictCopy(containerID, current, group.payload, sameNotebook))) { failed += 1; continue; }
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
  /** Encrypts a file for the container's current key and registers a resumable upload for it. */
  async function sealUpload(container: Container, objectID: string, objectVersion: number, plaintext: Uint8Array, file: AttachmentFile): Promise<PendingUpload> {
    const write = writeKeyFor(container);
    if (!write) throw new KeysWaitingError();
    const sealed = await sealAttachment(write, container.id, objectID, plaintext, file);
    const upload = await sendUploadStart({ container, generation: sealed.keyGeneration }, sealed.payload.byteLength, await digestSha256Hex(sealed.payload));
    const job = { uploadId: upload.uploadId, owner: auth.user.id, containerID: container.id, objectID, objectVersion, ...sealed, chunkBytes: upload.chunkBytes, nextChunk: upload.nextChunk, name: file.name, type: file.type, size: file.size };
    await putUpload(job);
    return job;
  }
  /** Replaces a pending upload sealed for a retired key with one sealed for the current key. */
  async function resealUpload(job: PendingUpload, container: Container, plaintext: Uint8Array, file: AttachmentFile): Promise<PendingUpload> {
    const next = await sealUpload(container, job.objectID, job.objectVersion, plaintext, file);
    await deleteUpload(job.uploadId).catch(() => undefined);
    await clearUpload(auth.user.id, job.uploadId);
    setUploadProgress((value) => { const rest = { ...value }; delete rest[job.uploadId]; return rest; });
    return next;
  }
  async function uploadPending(job: PendingUpload, tries = 0): Promise<{ id: string; keyGeneration: number }> {
    if (tries > 1) throw new KeysWaitingError();
    // Only this account's own upload: another's could be finalized, misattributed, in a notebook both share.
    if (job.owner !== auth.user.id) throw new Error("This upload belongs to another account.");
    // Before the first chunk: the job must still be sealed for this notebook's current key and floor.
    const container = await syncKeys(await currentContainer(job.containerID), true);
    const step = await attachmentStep(job, container, floorFor(container), writeKeyFor(container), ringsRef.current[container.id] ?? noKeys, waitingRef.current);
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
    await clearUpload(auth.user.id, job.uploadId);
    setUploadProgress((value) => { const next = { ...value }; delete next[job.uploadId]; return next; });
    return { id: finalized.attachmentId, keyGeneration: job.keyGeneration };
  }
  async function resumeUploads() {
    if (drainingUploads.current) return;
    drainingUploads.current = true;
    try {
      for (const job of await pendingUploads(auth.user.id)) {
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
    await clearUpload(auth.user.id, uploadId);
    setUploadProgress((value) => { const next = { ...value }; delete next[uploadId]; return next; });
  }
  async function retryAttachmentUpload(uploadId: string) {
    cancelledUploads.current.delete(uploadId);
    const job = (await pendingUploads(auth.user.id)).find((entry) => entry.uploadId === uploadId);
    if (!job) return;
    try { await uploadPending(job); } catch { setError(`Attachment waiting to resume: ${job.name}`); }
  }
  async function uploadAttachment(file: File): Promise<PlainAttachment> {
    if (!selected || !selectedNote) throw new Error("Select a note first");
      const job = await sealUpload(selected, selectedNote.id, selectedNote.version, new Uint8Array(await file.arrayBuffer()), { name: file.name, type: file.type, size: file.size });
      // A re-sealed upload reports the generation it was actually sent under.
      const uploaded = await uploadPending(job);
      return { id: uploaded.id, name: file.name, type: file.type, size: file.size, keyGeneration: uploaded.keyGeneration, page: job.objectID };
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
    const v1 = await v1ChildOpens(containerID, attachment.page, attachment.id, encrypted);
    const plaintext = await openFirst(readKeysFor(selected, attachment.keyGeneration), (key) => decryptAttachment(key, containerID, attachment.page, encrypted, v1));
    const objectURL = URL.createObjectURL(new Blob([plaintext.slice().buffer as ArrayBuffer], { type: attachment.type }));
    resolvedURLs.current.push(objectURL);
    return objectURL;
  }
  async function openAttachment(attachment: PlainAttachment) {
    if (!selected) return;
    try {
      const encrypted = await downloadAttachment(attachment.id);
      const containerID = selected.id;
      const v1 = await v1ChildOpens(containerID, attachment.page, attachment.id, encrypted);
      const plaintext = await openFirst(readKeysFor(selected, attachment.keyGeneration), (key) => decryptAttachment(key, containerID, attachment.page, encrypted, v1));
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
      if (!write) throw new Error(WAITING);
      const encrypted = await encryptComment(write.key, selected.id, selectedNote.id, commentText.trim(), commentSection.trim());
      try {
        const mentionable = keyMembers?.containerID === selected.id ? keyMembers.members : membersForTeam;
        await sendComment({ container: selected, generation: write.generation }, selectedNote.id, base64(encrypted), mentionedUserIDs(commentText, mentionable, auth.user.id));
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
      const caller = { userId: auth.user.id, identity: await heldIdentity(), canWrap: !auth.sso, recoverable: recoverable(liveRef.current) };
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
    dropInvite(sessionStore());
  }
  async function joinTeam() {
    const link = invitation;
    if (!link) return;
    // Hidden now so a second click cannot accept twice; kept only if the failure may pass.
    setInvitation(undefined);
    try {
      await acceptInvitation(link.id, link.token);
      dropInvitation();
      setError("You joined the team.");
    } catch (error) {
      const api = error instanceof APIRequestError ? error : undefined;
      const message = error instanceof Error ? error.message : "Unable to join the team";
      if (finalRefusal(api?.status, api?.code)) {
        dropInvitation();
        setError(api?.code === "not_found"
          ? "This invitation is no longer valid: it expired, was already used, is for another account, or its sender can no longer invite."
          : api?.code === "already_exists" ? "You are already a member of this team." : message);
      } else {
        setInvitation(link);
        setError(`Could not join the team: ${message}. The invitation is kept; choose Join team to try again.`);
      }
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
      await reloadTeamMembers(selected);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Unable to remove member",
      );
    }
  }
  /** Re-reads the team's members and runs the key pass on it and its workspaces; `share` as in syncKeys. */
  async function reloadTeamMembers(team: Container, share = false) {
    for (const child of items.filter((entry) => entry.teamId === team.id)) await syncKeys(child, false, () => false, share);
    setSelected(await syncKeys(team, false, () => false, share));
    setMembersForTeam(await members(team.id));
  }
  async function approve(userID: string) {
    if (selected?.kind !== "team") return;
    setBusy(true);
    try {
      await approveMember(selected.id, userID);
      // "Approve and share keys" is explicit intent: an SSO steward wraps too (each write asks KySignOn).
      await reloadTeamMembers(selected, true);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to approve");
    } finally {
      setBusy(false);
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
  const teams = items.filter((item) => item.kind === "team");
  const teamWorkspaces = (teamID: string) => items.filter((item) => item.teamId === teamID);
  const inWorkspace = view === "workspace";
  // The open notebook, section and page are marked bold (aria-current="true"); only the current
  // destination (Notes or Work queue) carries the accent (aria-current="page"); on Settings, the footer's gear does.
  // As in OneNote, the open notebook's sections (and its ⋯ menu) sit right under it.
  const notebookItem = (container: Container, icon: "notebook" | "team", nested = false) => {
    const open = !queueMode && selected?.id === container.id;
    const row = (
      <button
        className={`ky-nav-item nav-item notebook-item${nested ? " nested-nav-item" : ""}`}
        aria-current={open ? "true" : undefined}
        data-open={selected?.id === container.id ? "true" : undefined}
        key={container.id}
        onClick={() => { setPhoneList(true); void chooseNotebook(container); }}
      >
        <NavIcon name={icon} />
        <span>{nameOf(container)}</span>
      </button>
    );
    if (!open || !selected) return row;
    return (
      <React.Fragment key={container.id}>
        <div className="notebook-row">
          {row}
          <button className="icon-button quiet menu-button" popoverTarget="notebook-menu" aria-label="Notebook options" style={{ anchorName: "--notebook-menu" }}><NavIcon name="more" /></button>
          <div className="section-menu anchored-menu" id="notebook-menu" popover="auto" style={{ positionAnchor: "--notebook-menu" } as React.CSSProperties}>
            <button className="quiet" disabled={busy} onClick={() => { closeMenu("notebook-menu"); void renameWorkspace(); }}>Rename notebook</button>
            <button className="quiet" disabled={busy} onClick={() => { closeMenu("notebook-menu"); void exportWorkspace(); }}>Export notebook</button>
            <button className="quiet" disabled={busy || keyWait} onClick={() => { closeMenu("notebook-menu"); void newStructure("section"); }}>New section</button>
            <button className="quiet" disabled={busy || keyWait || groupPath(groupID, parents).length >= MAX_GROUP_DEPTH} onClick={() => { closeMenu("notebook-menu"); void newStructure("group"); }}>New section group</button>
            {selected.kind === "team" && teamSteward && <button className="quiet" onClick={() => { closeMenu("notebook-menu"); void invite(); }}>Add person</button>}
            {selected.kind === "team" && teamSteward && <button className="quiet" disabled={busy} onClick={() => { closeMenu("notebook-menu"); void newTeamWorkspace(selected); }}>Create team notebook</button>}
          </div>
        </div>
        <div className="notebook-sections">
          <SectionTabs
            sections={groupSections}
            groups={childGroups}
            path={groupTrail}
            current={sectionID}
            busy={busy || keyWait}
            moveTargets={moveTargets}
            onSelect={(id) => { setView("workspace"); setShowNotebookNavigation(false); setPhoneList(true); void selectSection(id); }}
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
        </div>
      </React.Fragment>
    );
  };
  const closeMenu = (id: string) => document.getElementById(id)?.hidePopover();
  const saveStatus = dirty ? "Unsaved changes" : syncStatus === "syncing" ? "Syncing…" : syncStatus === "local" ? "Saved locally" : syncStatus === "attention" ? "Needs attention" : "Saved to server";
  const saveDetail = selectedNote && [
    autosaving ? "Autosaving…" : syncStatus === "local" ? "Encrypted, waiting to sync" : syncStatus !== "attention" && lastSavedAt ? new Date(lastSavedAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : "",
    selectedNote.version ? `Version ${selectedNote.version}` : "Draft",
  ].filter(Boolean).join(" · ");
  // Notes: back to the open notebook (from Settings or the work queue), reloading nothing it need not.
  // Only a notebook load leaves the work queue, so from the queue Notes opens a notebook.
  const notesTarget = selected ?? items[0];
  const goToNotes = () => {
    setShowNotebookNavigation(false);
    if (queueMode && notesTarget) void chooseNotebook(notesTarget);
    else setView("workspace");
  };
  // Security-relevant, so always shown until dismissed for this session; the detail opens over the page.
  const recoveryNudge = identityState === "held" && live && !live.recoveryId && !recoveryDismissed && (
    <div className="recovery-notice">
      <details>
        <summary><NavIcon name="sso" /><span>Save a recovery code</span><NavIcon name="chevron" /></summary>
        <div className="recovery-notice-body" role="status">{RECOVERY_MISSING} <button className="secondary" onClick={() => openSettings("account")}>Create recovery code</button></div>
      </details>
      <button type="button" className="icon-button quiet" aria-label="Dismiss the recovery code reminder for now" onClick={() => setRecoveryDismissed(true)}><NavIcon name="close" /></button>
    </div>
  );
  return (
    <AppFrame
      className={`workspace${queueMode ? " queue-mode" : ""}${inWorkspace ? " has-panes" : ""}`}
      label="Primary"
      onSignOut={onLogout}
      user={{ name: auth.username || auth.user.id.slice(0, 12), role: "Everyday account" }}
      settings={{ items: SETTINGS_TABS.map(([id, label]) => ({ href: settingsHash(id), label, current: view === "settings" && (settingsTab ?? "account") === id })), current: view === "settings" }}
      nav={<>
        {/* On phones the notebook tree folds under the tabs; Notes, once current, opens and closes it. */}
        <NavItem icon="notes" label="Notes" current={inWorkspace && !queueMode} disabled={queueMode && !notesTarget}
          expanded={phone && inWorkspace && !queueMode ? showNotebookNavigation : undefined} controls={phone ? "notebook-tree" : undefined}
          onClick={() => phone && inWorkspace && !queueMode ? setShowNotebookNavigation((open) => !open) : goToNotes()} />
        {/* Ignored while busy rather than disabled, so keyboard focus stays on the chosen tab. */}
        <NavItem icon="work" label="Work queue" current={inWorkspace && queueMode} onClick={() => { if (!busy) { setPhoneList(true); void openWorkQueue(); } }} />
      </>}
      tree={<div id="notebook-tree" className="notes-tree" data-open={showNotebookNavigation || undefined}>
        <nav id="notebook-navigation" className="sidebar" aria-label="Notebooks">
          <div className="section-label">Notebooks</div>
          {personal.map((container) => notebookItem(container, "notebook"))}
          {teams.length > 0 && <div className="section-label team-label">Team notebooks</div>}
          {teams.map((container) => (
            <React.Fragment key={container.id}>
              {notebookItem(container, "team")}
              {teamWorkspaces(container.id).map((workspace) => notebookItem(workspace, "notebook", true))}
            </React.Fragment>
          ))}
          <button className="new-workspace personal-create" aria-label="＋ New notebook" disabled={busy} onClick={() => void newWorkspace()}>
            <NavIcon name="plus" /> New notebook
          </button>
          {selected?.kind === "team" && membersForTeam.length > 0 && (
            <div className="member-list">
              <div className="section-label">People in {nameOf(selected)}</div>
              {membersForTeam.map((member) => (
                <div className="member-row" key={member.userId}>
                  <span>
                    {displayName(member.username, member.userId)} · {member.pendingRole ? `${member.pendingRole} once approved` : member.role}
                    {keyMembers?.containerID === selected.id && keyMembers.status[member.userId] && ` · ${KEY_STATUS[keyMembers.status[member.userId]]}`}
                    {member.keyResetAt && ` · reset their key ${resetWhen(member.keyResetAt)}`}
                  </span>
                  {teamSteward && member.userId !== auth.user.id && (
                    <button className="quiet" onClick={() => void removeTeamMember(member.userId)}>
                      Remove
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </nav>
      </div>}
    >
        {/* The page list and the editor stay mounted behind Settings, so an open page keeps its pending edits. */}
        <div className="notes-panes" hidden={!inWorkspace} data-phone-view={!selected && !queueMode ? undefined : !selectedNote || phoneList ? "list" : "page"}>
          <section id="page-navigation" className={`note-list${!selected && !queueMode ? " no-notebook" : ""}`} aria-busy={loadingContainer} aria-labelledby="page-navigation-title">
            {selected && !queueMode && <p className="workspace-title">{nameOf(selected)}</p>}
            <div className="pane-head">
              <h2 id="page-navigation-title" className="pane-title">{queueMode ? "Work queue" : query.trim() ? "Search results" : sectionTitle(sectionID)}</h2>
              {selected && !queueMode && (
                <button
                  className="icon-button quiet"
                  aria-label="New page"
                  title="New page"
                  disabled={busy || sectionHidden || keyWait}
                  onClick={() => { setView("workspace"); setShowNotebookNavigation(false); setPhoneList(false); void newNote(); }}
                >
                  <NavIcon name="plus" />
                </button>
              )}
            </div>
            {queueMode && <p className="workspace-kind">Open tasks across your personal notebooks · {queueRows.length} open task{queueRows.length === 1 ? "" : "s"}</p>}
            {(selected || queueMode) && <label className="note-search-field">
              <NavIcon name="search" />
              <input
                aria-label={queueMode ? "Search the work queue" : "Search this notebook"}
                className="note-search"
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search"
              />
            </label>}
            {queueMode && TASK_GROUPS.map(([group, label]) => {
              const rows = queueRows.filter((task) => task.group === group);
              return rows.length > 0 && (
                <div className="task-group" key={group} data-task-group={group}>
                  <h3 className="notes-heading">{label}</h3>
                  {rows.map((task, index) => (
                    <div className={`note-row-wrap ${selectedNote?.id === task.entry.note.id ? "selected" : ""}`} key={`${task.key}\n${index}`}>
                      <button className="note-row" onClick={() => { setView("workspace"); focusTitleNext.current = phone; void selectQueueNote(task.entry); }}>
                        <strong>{task.text || "Untitled task"}</strong>
                        <span>{[task.due && `Due ${task.due}`, task.repeat && "repeats", task.push && "push", task.missed && "missed reminder", task.entry.note.title || "Untitled page"].filter(Boolean).join(" · ")}</span>
                      </button>
                    </div>
                  ))}
                </div>
              );
            })}
            {!queueMode && listRows.map(({ note, row }) => {
              const title = note.title || "Untitled page";
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
                    <NavIcon name="chevron" />
                  </button>
                )}
                <button
                  className="note-row"
                  aria-current={inWorkspace && selectedNote?.id === note.id ? "page" : undefined}
                  data-page-id={note.id}
                  draggable
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
                  onClick={() => {
                    setView("workspace");
                    if (selectedNote?.id === note.id) {
                      setShowNotebookNavigation(false);
                      setPhoneList(false);
                      if (phone) requestAnimationFrame(() => pageTitleRef.current?.focus());
                      return;
                    }
                    focusTitleNext.current = phone;
                    void selectNote(note);
                  }}
                >
                  <span className="note-row-head">
                    <strong>{title}</strong>
                    <time dateTime={note.updatedAt} title={note.updatedAt ? new Date(note.updatedAt).toLocaleString() : undefined}>{relativeDate(note.updatedAt)}</time>
                  </span>
                  {row && (row.level > 0 || row.hasChildren) && (
                    <span className="visually-hidden">
                      {row.level > 0 ? `, subpage level ${row.level}` : ""}
                      {row.hasChildren ? (row.collapsed ? `, collapsed, ${subpageCount(note.id)} subpages hidden` : ", expanded") : ""}
                    </span>
                  )}
                  <span className="note-snippet">
                    {query.trim() && <em className="page-section">{sectionTitle(note.section)} · </em>}
                    {indexNotes([note])[0].body.slice(0, 160) || "Empty page"}
                  </span>
                </button>
              </div>
              );
            })}
            {selected && (listEntries.length === 0 || groupEmpty) && (
              <p className="empty-list">
                {queueMode ? "No open tasks here. Tasks from note checklists appear here." : groupEmpty ? "This group has no sections. Add one from the notebook menu to add pages." : "No pages in this section yet."}
              </p>
            )}
            {relatedNotes.length > 0 && (
              <div className="context-panel">
                <div className="section-label">Resurfacing</div>
                {relatedNotes.map((note) => (
                  <button className="context-link" key={note.id} onClick={() => { setView("workspace"); void selectNote(note); }}>
                    {note.title || "Untitled page"}
                  </button>
                ))}
              </div>
            )}
            {links.length > 0 && (
              <div className="context-panel">
                <div className="section-label">Knowledge graph</div>
                <span className="config-muted">
                  {links.length} local link{links.length === 1 ? "" : "s"}
                </span>
              </div>
            )}
          </section>
          <section className="editor">
            <div className="workspace-notices">
              {!queueMode && keyWait && selected && <p className="workspace-kind" role="status">{rollback ? ROLLBACK : (() => {
                const notice = waitingNotice({ steward: stewardHere(selected), held: identityState === "held", recoverable: recoverable(live), shared: Math.max(selected.sharedGeneration, floorFor(selected)?.shared ?? 0) > 0 });
                const reset = keyMembers?.containerID === selected.id ? resetNotice(keyMembers.members) : undefined;
                return <>{notice.text}{reset && <> {reset}</>}{notice.action === "ask" && <> <button className="quiet" onClick={() => void askForKeys()}>Ask an owner</button></>}{notice.action === "settings" && <> <button className="quiet" onClick={() => openSettings(identityState === "held" ? "account" : "devices")}>Open Settings</button></>}</>;
              })()}</p>}
              {!queueMode && keyNotice && <p className="workspace-kind" role="status">{keyNotice}</p>}
              {!queueMode && keyDeferred && <p className="workspace-kind" role="status">This notebook's keys are not set up or shared yet. <button className="quiet" onClick={() => void shareKeysNow()}>Set up keys (confirm with {auth.sso ? "KySignOn" : "your password"})</button></p>}
              {resetUnfinished && <div className="conflict-banner" role="status">{RESET_UNFINISHED} <button className="secondary" onClick={() => { if (confirm(FORGET_DEVICE)) onForgetDevice?.(); }}>Forget this device</button></div>}
              {identityState === "link" && !resetUnfinished && <div className="conflict-banner" role="status">This browser does not hold your encryption key, so your notebooks are read-only here. <button className="secondary" onClick={() => openSettings("devices")}>Link this browser</button></div>}
              {auth.sso && identityState === "create" && <div className="conflict-banner" role="status">Set up your encryption key so you can write in your notebooks and team owners can share theirs with you. <button className="secondary" onClick={() => void setUpSSOIdentity(false)}>Set up encryption key</button></div>}
              {auth.sso && identityState === "orphaned" && <div className="conflict-banner" role="status">The server no longer lists the encryption key this browser holds (a reset from another browser replaced it). <button className="secondary" onClick={() => void setUpSSOIdentity(true)}>Replace encryption key</button></div>}
              {(!selectedNote || (phone && phoneList)) && recoveryNudge}
              {selected && teamSteward && selected.metaVersion === 0 && writeKeyFor(selected) && (
                <div className="conflict-banner" role="status">{UNNAMED_TEAM} <button className="secondary" onClick={() => void renameWorkspace()}>Name notebook</button></div>
              )}
              {teamSteward && membersForTeam.filter((member) => member.approved === false).map((member) => (
                <div className="conflict-banner" role="status" key={member.userId}>
                  {approvalText(displayName(member.username, member.userId))} <button className="secondary" disabled={busy} onClick={() => void approve(member.userId)}>Approve and share keys</button>
                </div>
              ))}
              <LinkStatus status={identityRefusal} set={setIdentityRefusal} />
              {invitation && (
                <div className="conflict-banner" role="status">
                  You were invited to a team notebook.{" "}
                  <button className="secondary" onClick={() => void joinTeam()}>Join team</button>{" "}
                  <button className="quiet" onClick={dropInvitation}>Not now</button>
                </div>
              )}
            </div>
            {selectedNote ? (
              <>
                {conflicted.has(selectedNote.id) && (
                  <div className="conflict-banner" role="alert">
                    {recovering === selectedNote.id
                      ? "Saving the other version as a copy…"
                      : "Another device saved this page first. Your version was kept separately; save it as a copy next to this page."}
                    <button className="secondary" disabled={recovering !== null || keyWait} onClick={() => void keepConflictCopies()}>Keep the other version as a copy</button>
                  </div>
                )}
                <button type="button" className="quiet pane-back" onClick={() => { setPhoneList(true); requestAnimationFrame(() => document.querySelector<HTMLElement>(".note-list .note-row[aria-current]")?.focus()); }}>
                  <NavIcon name="back" /><span>{queueMode ? "Work queue" : sectionTitle(sectionID)}</span>
                </button>
                <div className="page-head">
                  <input
                    ref={pageTitleRef}
                    aria-label="Page title"
                    className="title-input"
                    readOnly={recovering === selectedNote.id || keyWait}
                    value={selectedNote.title}
                    onChange={(event) => editOpen(selectedNote.id, { title: event.target.value })}
                  />
                  <div className="page-head-actions">
                    {!(phone && phoneList) && recoveryNudge}
                    <p className="save-state" aria-live="polite">
                      <span className="ky-status" data-ky-status={dirty ? undefined : SYNC_TONE[syncStatus]}>{saveStatus}</span>
                      {saveDetail && <span className="save-detail">{saveDetail}</span>}
                    </p>
                    <button className="save-button secondary" disabled={busy} onClick={() => void save(selectedNote)}>
                      {busy ? "Saving…" : "Save"}
                    </button>
                    <button className="icon-button quiet menu-button" popoverTarget="page-menu" aria-label="Page options" style={{ anchorName: "--page-menu" }}><NavIcon name="more" /></button>
                    <div className="section-menu anchored-menu page-menu" id="page-menu" popover="auto" style={{ positionAnchor: "--page-menu" } as React.CSSProperties}>
                      <span className="menu-caption" aria-hidden="true">Section</span>
                      <div className="page-section-control">
                        <select
                          aria-label="Move page to section"
                          disabled={keyWait}
                          value={pagesInSection([selectedNote], sections, QUICK_NOTES).length ? QUICK_NOTES : selectedNote.section}
                          onChange={(event) => { closeMenu("page-menu"); void movePage(selectedNote.id, event.target.value, null); }}
                        >
                          {sectionTargets(sections, groups, parents).map((entry) => <option key={entry.id} value={entry.id}>{entry.label}</option>)}
                          <option value={QUICK_NOTES}>Quick Notes</option>
                        </select>
                        <NavIcon name="chevron" />
                      </div>
                      <button className="quiet" disabled={keyWait || !canShift(selectedNote.id, 1)} title="Ctrl+Alt+]" onClick={() => { closeMenu("page-menu"); void indentPage(selectedNote.id, 1); }}>Indent page</button>
                      <button className="quiet" disabled={keyWait || !canShift(selectedNote.id, -1)} title="Ctrl+Alt+[" onClick={() => { closeMenu("page-menu"); void indentPage(selectedNote.id, -1); }}>Outdent page</button>
                      <button className="quiet danger" disabled={keyWait} onClick={() => { closeMenu("page-menu"); void remove(selectedNote); }}>Delete page</button>
                    </div>
                  </div>
                </div>
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
                <details className="page-panel comments" open={commentsOpen} onToggle={(event) => setCommentsOpen(event.currentTarget.open)}>
                  <summary><span>Comments</span>{commentsForNote.length > 0 && <span className="page-panel-count">{commentsForNote.length}</span>}<NavIcon name="chevron" /></summary>
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
                    <input aria-label="Comment section (optional)" value={commentSection} onChange={(event) => setCommentSection(event.target.value)} placeholder="Section (optional)" />
                    <input aria-label="Comment" value={commentText} onChange={(event) => setCommentText(event.target.value)} placeholder="Add a comment…" />
                    <button className="secondary" disabled={busy || keyWait} onClick={() => void addComment()}>
                      Comment
                    </button>
                  </div>
                </details>
                <details className="page-panel attachments" open={attachmentsOpen} onToggle={(event) => setAttachmentsOpen(event.currentTarget.open)}>
                  <summary><span>Attachments</span>{attachmentsForNote.length > 0 && <span className="page-panel-count">{attachmentsForNote.length}</span>}<NavIcon name="chevron" /></summary>
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
                    <NavIcon name="plus" /><span>Add encrypted file</span>
                    <input type="file" disabled={busy || keyWait} onChange={(event) => { const file = event.target.files?.[0]; if (file) void addAttachment(file); event.currentTarget.value = ""; }} />
                  </label>
                </details>
              </>
            ) : (
              <div className="empty-editor">
                <h2>{!selected && !queueMode ? (items.length ? "Select a notebook" : "No notebooks yet") : "Your private desk"}</h2>
                <p>
                  {!selected && !queueMode ? "Start with a notebook to keep your notes together." : "Select a page or create one."} The server receives ciphertext only.
                </p>
                {!selected && !queueMode && (
                  <button disabled={busy} onClick={() => void newWorkspace()}>New notebook</button>
                )}
                {selected && (
                  <button disabled={keyWait} onClick={() => void newNote()}>Create a note</button>
                )}
              </div>
            )}
          </section>
        </div>
        {view === "settings" && (
          <SettingsView
            tab={settingsTab ?? "account"}
            username={auth.username}
            userID={auth.user.id}
            colleagueNames={colleagueNames.current}
            keysFor={(item) => ownCopyKeysFor(items.find((entry) => entry.id === item.containerID), item.keyGeneration)}
            onForgetDevice={onForgetDevice}
            onAuthSecret={onAuthSecret}
            identityState={identityState}
            sso={Boolean(auth.sso)}
            heldIdentity={heldIdentity}
            identityStore={identityStore}
            stepUp={keyAPI.stepUp}
            live={live}
            recoveryPrompt={recoveryPrompt}
            onIdentityChanged={afterIdentityChange}
            onReset={(next) => { void retireWaitingEdits(next).catch(() => undefined).finally(afterIdentityChange); }}
            resetUnfinished={resetUnfinished}
            waitingHeld={waitingHeld}
            reminders={reminderPrefs}
            onReminders={setReminderPrefs}
          />
        )}
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
    </AppFrame>
  );
}

/** everyday: the account holds an identity whose password copy is re-wrapped; an administrator account has none. */
function PasswordSettings({ username, userID, everyday, onAuthSecret, onIdentityCreated, onChanged }: { username: string; userID: string; everyday: boolean; onAuthSecret: (authSecret: string) => void; onIdentityCreated: () => void; onChanged?: (authSecret: string) => void }) {
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
    const problem = passwordChangeProblem(next, confirmation);
    if (problem) {
      setStatus(problem);
      return;
    }
    setBusy(true);
    try {
      const name = username || prompt("Username")?.trim();
      if (!name) throw new Error("Username is required");
      const oldParams = await loginParams(name);
      const currentKeys = await deriveLoginKeys(current, oldParams.loginSalt, oldParams.iterations, loginFloor(name));
      const newLoginSalt = randomLoginSalt();
      const newKeys = await deriveLoginKeys(next, newLoginSalt, 600000);
      if (!everyday) {
        await changePassword({ currentAuthSecret: currentKeys.authSecret, newAuthSecret: newKeys.authSecret, newLoginSalt, iterations: 600000 });
        pinLogin(name);
        setCurrent("");
        setNext("");
        setStatus("Password changed.");
        onChanged?.(newKeys.authSecret);
        return;
      }
      const cached = await getIdentityKey(name, userID).catch(() => undefined);
      const rewrapped = await rewrapIdentity(identityAPI, userID, currentKeys, newKeys, cached);
      await rememberAfter(() => changePassword({
        currentAuthSecret: currentKeys.authSecret,
        newAuthSecret: newKeys.authSecret,
        newLoginSalt,
        iterations: 600000,
        identityDeviceId: rewrapped?.identityDeviceId,
        wrappedIdentityKey: rewrapped?.wrappedIdentityKey,
      }), name, rewrapped && { userID, identity: rewrapped.identity });
      pinLogin(name);
      // No identity yet (e.g. an administrator set the old password): create it under the new one
      // before the workspace opens, so it never caches an absent identity.
      if (!rewrapped) {
        await settleIdentity(name, userID, newKeys);
        onIdentityCreated();
      }
      onAuthSecret(newKeys.authSecret);
      setCurrent("");
      setNext("");
      setStatus("Password changed.");
      onChanged?.(newKeys.authSecret);
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
        are never sent to the server. Changing it signs out your other browsers
        and unpairs your devices; this browser stays signed in.
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

// Only saved and failed are a state with a colour; unsaved, syncing and waiting to sync are neutral.
const SYNC_TONE: Record<string, "success" | "danger" | undefined> = { saved: "success", attention: "danger" };

const CHOOSE_PASSWORD = "An administrator set this account's password. Choose your own before you continue.";

/** Shown before anything else while the server reports passwordChangeRequired; nothing runs before the change. */
function ChoosePassword({ auth, onChanged, onLogout }: { auth: AuthState; onChanged: (authSecret: string) => void; onLogout: () => void }) {
  return (
    <AuthScreen tagline="Choose your own password.">
      <div className="ky-auth-card choose-password">
        <p role="status">{CHOOSE_PASSWORD}</p>
        <PasswordSettings username={auth.username} userID={auth.user.id} everyday={auth.user.accountKind === "user"} onAuthSecret={() => {}} onIdentityCreated={() => {}} onChanged={onChanged} />
        <button type="button" className="ky-auth-link" onClick={onLogout}>Sign out</button>
      </div>
    </AuthScreen>
  );
}

function SettingsView({
  tab,
  username,
  userID,
  onForgetDevice,
  onAuthSecret,
  colleagueNames,
  keysFor,
  identityState,
  sso,
  heldIdentity,
  identityStore,
  stepUp,
  onIdentityChanged,
  onReset,
  resetUnfinished,
  waitingHeld,
  live,
  recoveryPrompt,
  reminders,
  onReminders,
}: {
  tab: SettingsTab;
  username: string;
  userID: string;
  /** Usernames seen in key passes this session, for the colleague keys card. */
  colleagueNames: Record<string, string>;
  /** Keys this browser holds for a queued edit: its notebook's key for that generation, or the waiting key. */
  keysFor: (item: PendingSave) => KeyRef[];
  onForgetDevice?: () => void;
  onAuthSecret: (authSecret: string) => void;
  identityState: IdentityStatus | "unknown";
  /** A single sign-on session: it creates its key from the notebook list, not with a password. */
  sso: boolean;
  heldIdentity: () => Promise<HeldIdentity | undefined>;
  identityStore: IdentityStore;
  stepUp: () => Promise<void>;
  /** A link, restore, reset or new identity: re-reads the identity, the waiting key and the code state, then runs a key pass. */
  onIdentityChanged: () => void;
  /** A reset from this browser: retires the waiting edits, then as onIdentityChanged. */
  onReset: (identity: HeldIdentity) => void;
  /** This browser's reset committed without its answer (M4). */
  resetUnfinished: boolean;
  /** A waiting key is held: waiting edits it does not open are listed as sealed under a previous key. */
  waitingHeld: boolean;
  live: PublicIdentity | null | undefined;
  recoveryPrompt: boolean;
  reminders: ReminderPrefs;
  onReminders: (prefs: ReminderPrefs) => void;
}) {
  const [ownFingerprint, setOwnFingerprint] = useState("");
  const [justLinked, setJustLinked] = useState<"" | "linked" | "restored">("");
  /** Before a reset: downloads every edit this account queued on this browser, opened here (M4). */
  async function exportWaiting(): Promise<number> {
    const queued = (await pendingSaves()).filter((item) => item.owner === userID);
    if (!queued.length) return 0;
    const file = await exportUnsent(queued, (item) => openFirst(keysFor(item), (key) => decryptObject(key, item.containerID, item.id, item.payload, true)));
    downloadFile("kynotes-unsent-edits.json", file.json, "application/json");
    return queued.length - file.unreadable;
  }
  useEffect(() => {
    // From this browser's own copy of the key, so the server cannot show a different one.
    void getIdentityKey(username, userID)
      .then((identity) => (identity ? fingerprint(base64(identity.publicKey)) : ""))
      .then(setOwnFingerprint, () => setOwnFingerprint(""));
  }, [username, userID, identityState]);
  return (
    <section className="page-view settings-view" aria-labelledby="settings-heading">
      <header className="ky-page-head">
        <div>
          <h1 id="settings-heading" className="ky-page-title">Settings</h1>
          <p className="ky-page-lede">Your account, the browsers linked to it, how KyNotes looks, and your reminders and keys.</p>
        </div>
      </header>
      <nav className="ky-settings-tabs" aria-label="Settings sections">
        {SETTINGS_TABS.map(([id, label]) => <a key={id} className="ky-nav-item" href={settingsHash(id)} aria-current={tab === id ? "page" : undefined}>{label}</a>)}
      </nav>
      {/* Every tab stays mounted, so a recovery code or link code on screen survives a tab switch. */}
      {justLinked && <p role="status">{justLinked === "restored" ? RECOVERY_RESTORED : "Linked. This browser now holds your encryption key."}</p>}
      <div className="settings-content" hidden={tab !== "account"}>
        <div id="password">
          <PasswordSettings username={username} userID={userID} everyday onAuthSecret={onAuthSecret} onIdentityCreated={onIdentityChanged} />
        </div>
        <section id="device" className="config-card">
          <h2>Trusted Device & SSO</h2>
          <p className="config-muted">
            {ownFingerprint
              ? "This browser holds your encryption key, so your notes open here while you are signed in. It keeps nothing that can sign you in."
              : "This browser keeps nothing that can sign you in."}
          </p>
          <p className="config-muted">Your user ID: <code>{userID}</code>. Team owners need it to invite you.</p>
          <p className="config-muted">
            {ownFingerprint
              ? <>Your encryption key fingerprint: <code>{ownFingerprint}</code>. Team owners see it when your key changes; compare it with them in person.</>
              : `This browser holds no encryption key for team notebooks.${noKeyHint(identityState, sso)}`}
          </p>
          {ownFingerprint && <p className="config-muted">{identityStorage() === "wrapped"
            ? "This browser keeps it wrapped under a browser key that pages cannot export. That is not protection at rest: anyone who can read this browser's profile on disk can still recover it. Use \"Forget this device\" on shared computers."
            : "This site is not served over HTTPS, so this browser stores your key unwrapped in its site storage. Anyone who can read this browser's profile can copy it. Use \"Forget this device\" on shared computers."}</p>}
          {onForgetDevice && (
            <button
              type="button"
              className="secondary danger"
              onClick={() => { if (confirm(FORGET_DEVICE)) onForgetDevice(); }}
            >
              Forget this device & sign out
            </button>
          )}
        </section>
        {identityState === "held" && <RecoverySetup userID={userID} held={heldIdentity} live={live} sso={sso} stepUp={stepUp} autoStart={recoveryPrompt} onSaved={onIdentityChanged} />}
        {resetUnfinished && <p role="status">{RESET_UNFINISHED}</p>}
        {live && <IdentityReset userID={userID} store={identityStore} live={live} held={identityState === "held"} stepUp={stepUp} exportWaiting={exportWaiting} onReset={onReset} password={sso ? undefined : passwordReset(username)} />}
      </div>
      <div className="settings-content" hidden={tab !== "devices"}>
        {identityState === "link" && <LinkThisBrowser userID={userID} canKeep={() => vaultReady(username)} store={identityStore} onLinked={() => { setJustLinked("linked"); onIdentityChanged(); }} />}
        {identityState === "link" && <RecoveryRestore userID={userID} sso={sso} store={identityStore} stepUp={stepUp} onRestored={() => { setJustLinked("restored"); onIdentityChanged(); }} />}
        {identityState === "held" && <LinkRequests userID={userID} held={heldIdentity} stepUp={stepUp} />}
        {identityState !== "link" && identityState !== "held" && <p className="config-muted">{`This browser holds no encryption key to link another browser with.${noKeyHint(identityState, sso)}`}</p>}
      </div>
      <div hidden={tab !== "appearance"}><Appearance /></div>
      <div className="settings-content" hidden={tab !== "reminders"}>
        <ReminderSettings userID={userID} prefs={reminders} onChange={onReminders} />
      </div>
      <div className="settings-content" hidden={tab !== "colleague-keys"}>
        <PinnedKeys username={username} userID={userID} names={colleagueNames} />
      </div>
      <div className="settings-content" hidden={tab !== "unsent"}>
        <UnsentEdits username={username} userID={userID} keysFor={keysFor} waitingHeld={waitingHeld} />
      </div>
    </section>
  );
}

// An invitation link opens the app at #/invite/…: keep it in this tab for after sign-in, out of the address bar.
takeInviteLink(location, history, sessionStore());
createRoot(document.getElementById("root")!).render(
  hasWebCrypto() ? <React.StrictMode><App /></React.StrictMode> : <p role="alert">{NEEDS_HTTPS}</p>,
);
