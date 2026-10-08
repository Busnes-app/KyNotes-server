import { confirmSSOAction } from "./reauth";
import type { IdentityAPI, IdentityRecord, IdentityUpload, PublicIdentity } from "./identity";
import type { Envelope, InvitationEnvelope, Member } from "./keyring";
import type { RecoveryAPI, RecoveryCopy } from "./recovery";
export type User = { id: string; role: string; username?: string };
export type Session = { sso?: boolean; user: User; expiresAt: string; hardExpiresAt: string };
export type Container = { id: string; kind: string; teamId?: string; metaCiphertext: string; metaVersion: number; changeSeq: number; keyGeneration: number; sharedGeneration: number };
export type Comment = { id: string; authorUserId: string; username: string; bodyCiphertext: string; keyGeneration?: number; createdAt: string };
export type Invitation = { id: string; token: string; expiresAt: string };

/** A row generation from the server: a non-negative safe integer, else undefined, which readKeys never opens. */
export function serverGeneration(value: unknown): number | undefined {
  const parsed = typeof value === "string" ? (/^\d+$/.test(value) ? Number(value) : Number.NaN) : value;
  return typeof parsed === "number" && Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}
const withGeneration = <T extends { keyGeneration?: unknown }>(rows: T[]) => rows.map((row) => ({ ...row, keyGeneration: serverGeneration(row.keyGeneration) }));
export type AdminUser = { id: string; username: string; role: string; status: string; quotaBytes: number; createdAt: string };
export type AdminTeam = { id: string; kind: string; ownerUserId: string; metaCiphertext?: string; metaVersion?: number; changeSeq?: number; keyGeneration?: number; sharedGeneration?: number };
export type Change = { id: string; kind: string; changeSeq: number; deleted: boolean };
export type Note = { id: string; title: string; body: string; version: number; updatedAt: string; section?: string; order?: string; level?: 0 | 1 | 2 };

type APIError = { error?: { code?: string; message?: string; challenge?: string }; conflictId?: string; currentVersion?: number };
/** challenge: the open KySignOn confirmation a 409 step_up_pending names, so the caller can cancel it. */
export class APIRequestError extends Error { code?: string; challenge?: string; conflictId?: string; currentVersion?: number; status?: number; constructor(message: string, detail: APIError, status?: number) { super(message); this.name = "APIRequestError"; this.code = detail.error?.code; this.challenge = typeof detail.error?.challenge === "string" ? detail.error.challenge : undefined; this.conflictId = detail.conflictId; this.currentVersion = detail.currentVersion; this.status = status; } }

/** Marks writes from a bundle that seals shared containers with their container key; the server refuses shared-container writes without it. */
export const KEY_SCHEME = "shared-v2";

export function csrfToken(): string {
  return document.cookie.split("; ").find((v) => v.startsWith("csrf_token="))?.slice(11) ?? "";
}

// Both JSON operations and capsule downloads use this one bounded retry path.
export async function actionFetch(path: string, init: RequestInit = {}): Promise<Response> {
 const response = await fetch(path, init);
 if (response.status !== 403) return response;
 let detail: unknown;
 try { detail = await response.clone().json(); } catch { return response; }
 if (typeof detail !== "object" || detail === null || !("error" in detail) || typeof detail.error !== "object" || detail.error === null) return response;
 const error = detail.error;
 if (!("code" in error) || error.code !== "sso_step_up_required" || !("challenge" in error) || typeof error.challenge !== "string") return response;
 await confirmSSOAction(error.challenge, csrfToken());
 const headers = new Headers(init.headers); headers.set("X-Kynotes-Step-Up", error.challenge);
 return fetch(path, { ...init, headers });
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    headers.set("X-CSRF-Token", csrfToken());
    headers.set("X-Kynotes-Key-Scheme", KEY_SCHEME);
  }
  const response = await actionFetch(path, { ...init, headers, credentials: "include" });
  if (!response.ok) {
    let detail: APIError = {};
    try { detail = await response.json() as APIError; } catch { /* opaque server error */ }
    throw new APIRequestError(detail.error?.message ?? `Request failed (${response.status})`, detail, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function checkSetup() {
  return request<{ setupRequired: boolean }>("/api/v1/setup");
}

export async function setupInit(
  username: string,
  password?: string,
  authSecret?: string,
  loginSalt?: string,
  iterations?: number,
) {
  return request<{ ok: boolean; user: User; expiresAt: string; hardExpiresAt: string }>("/api/v1/setup", {
    method: "POST",
    body: JSON.stringify({ username, password, authSecret, loginSalt, iterations }),
  });
}

export async function loginParams(username: string) {
  return request<{ loginSalt: string; iterations: number }>("/api/v1/auth/login-params", {
    method: "POST", body: JSON.stringify({ username }),
  });
}

export async function login(username: string, authSecret: string) {
  return request<Session & { identity?: IdentityRecord }>("/api/v1/auth/login", {
    method: "POST", body: JSON.stringify({ username, authSecret }),
  });
}

/** Secrets are write-only: the server reports only whether each is set, and an empty field keeps it. */
export type SSOSettings = {
  enabled: boolean;
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  clientSecretSet?: boolean;
  redirectUri?: string;
  autoProvision: boolean;
  hmacSecretSet?: boolean;
};

export const ssoConfig = () => request<{ enabled: boolean; issuerUrl: string; clientId: string }>("/api/v1/auth/sso-config");
export const adminSSO = () => request<SSOSettings>("/api/v1/admin/sso");
export const saveAdminSSO = (settings: SSOSettings) => request<SSOSettings>("/api/v1/admin/sso", { method: "POST", body: JSON.stringify(settings) });
export const pairAdminSSO = (issuerUrl: string, pairingToken: string, callbackUrl?: string) => request<{ success: boolean; systemId: string; settings: SSOSettings }>("/api/v1/admin/sso/pair", { method: "POST", body: JSON.stringify({ issuerUrl, pairingToken, callbackUrl }) });

export const session = () => request<Session>("/api/v1/auth/session");
export const serverTheme = () => request<{ defaultTheme: string }>("/api/v1/theme");
export const logout = () => request<void>("/api/v1/auth/logout", { method: "POST" });
export const containers = () => request<Container[]>("/api/v1/containers");

/** Created without a name: the server refuses one, and the name is sealed only once the first key exists. */
export function createContainer(kind = "workbook", teamId = "") {
  return request<Container>("/api/v1/containers", {
    method: "POST", body: JSON.stringify({ kind, teamId }),
  });
}

/** keyGeneration is the generation the name was sealed with; a shared container refuses any but the current one. */
/** Owner only, and only within five minutes of sign-in (server rule); createKeyed's best-effort cleanup. */
export const deleteContainer = (id: string) => request<void>(`/api/v1/containers/${encodeURIComponent(id)}`, { method: "DELETE" });
export function updateContainer(id: string, metaCiphertext: string, baseVersion: number, keyGeneration: number) {
  return request<{ metaVersion: number; changeSeq: number }>(`/api/v1/containers/${encodeURIComponent(id)}`, {
    method: "PATCH", body: JSON.stringify({ metaCiphertext, baseVersion, keyGeneration }),
  });
}

export async function serviceStatus() {
  const [health, ready] = await Promise.all([fetch("/healthz"), fetch("/readyz")]);
  return { health: health.ok, ready: ready.ok };
}
export const adminUsers = () => request<AdminUser[]>("/api/v1/admin/users");
export const adminAudit = () => request<Array<Record<string, string>>>("/api/v1/admin/audit");
export const adminTeams = () => request<AdminTeam[]>("/api/v1/admin/teams");
/** Created without a name, like createContainer. */
export function createAdminTeam() { return request<AdminTeam>("/api/v1/admin/teams", { method: "POST", body: JSON.stringify({}) }); }
export function createAdminUser(input: { username: string; authSecret: string; loginSalt: string; iterations: number; role: string }) { return request<{ id: string }>("/api/v1/admin/users", { method: "POST", body: JSON.stringify(input) }); }
export function resetAdminPassword(id: string, input: { newAuthSecret: string; newLoginSalt: string; iterations: number }) { return request<void>(`/api/v1/admin/users/${encodeURIComponent(id)}/password`, { method: "POST", body: JSON.stringify(input) }); }
export function addAdminTeamMember(teamID: string, userID: string, role: string) { return request<void>(`/api/v1/admin/teams/${encodeURIComponent(teamID)}/members`, { method: "POST", body: JSON.stringify({ userId: userID, role }) }); }
export function removeAdminTeamMember(teamID: string, userID: string) { return request<void>(`/api/v1/admin/teams/${encodeURIComponent(teamID)}/members/${encodeURIComponent(userID)}`, { method: "DELETE" }); }
export const adminSettings = () => request<{ defaultTheme: string }>("/api/v1/admin/settings");
export function updateAdminSettings(defaultTheme: string) { return request<void>("/api/v1/admin/settings", { method: "PATCH", body: JSON.stringify({ defaultTheme }) }); }
export function updateAdminUser(user: AdminUser) { return request<void>(`/api/v1/admin/users/${encodeURIComponent(user.id)}`, { method: "PATCH", body: JSON.stringify(user) }); }
export function changePassword(input: { currentAuthSecret: string; newAuthSecret: string; newLoginSalt: string; iterations: number; identityDeviceId?: string; wrappedIdentityKey?: string }) { return request<void>("/api/v1/auth/password", { method: "POST", body: JSON.stringify(input) }); }
/** Re-proves the login secret for the current session; destructive admin routes answer step_up_required until this succeeds. */
export function stepUp(authSecret: string) { return request<{ identity: IdentityRecord } | undefined>("/api/v1/auth/step-up", { method: "POST", body: JSON.stringify({ authSecret }) }); }
export async function myIdentity(): Promise<PublicIdentity | undefined> {
  try { return await request<PublicIdentity>("/api/v1/me/identity"); }
  catch (error) { if (error instanceof APIRequestError && error.code === "not_found") return undefined; throw error; }
}
export const putMyIdentity = (input: IdentityUpload) => request<{ deviceId: string; fingerprint: string }>("/api/v1/me/identity", { method: "PUT", body: JSON.stringify(input) });
export const putDeviceOnlyIdentity = (publicKey: string) => request<{ deviceId: string; fingerprint: string }>("/api/v1/me/identity", { method: "PUT", body: JSON.stringify({ publicKey, wrapAlg: "none" }) });
/** Sets or replaces the recovery-code copy (compare-and-swap); recovery.ts saveRecovery is the only caller. */
export const putRecovery: RecoveryAPI["putRecovery"] = (input) => request<{ recoveryId: string }>("/api/v1/me/identity/recovery", { method: "PUT", body: JSON.stringify(input) });
/** Behind a user-action step-up; undefined when the account has no identity or no copy (one 404 for both). */
export async function fetchRecovery(): Promise<RecoveryCopy | undefined> {
  try { return await request<RecoveryCopy>("/api/v1/me/identity/recovery/fetch", { method: "POST" }); }
  catch (error) { if (error instanceof APIRequestError && error.code === "not_found") return undefined; throw error; }
}
/** The self-service reset: a new identity with its recovery copy, replacing the one named by expectedDeviceId. */
export const replaceIdentity: RecoveryAPI["replaceIdentity"] = (input) => request<{ deviceId: string; fingerprint: string }>("/api/v1/me/identity", { method: "PUT", body: JSON.stringify({ ...input, replace: true }) });
export const recoveryAPI: RecoveryAPI = { myIdentity, putRecovery, fetchRecovery, replaceIdentity };
/** A device-link request as the trusted side lists it; newcomerKey is "" until revealed to this session. */
export type LinkRequestRow = { id: string; commitment: string; createdAt: string; expiresAt: string; claimed: boolean; newcomerKey: string };
/** The newcomer's view of its request; bundle once, after approval. */
export type LinkState = { state: "pending" | "claimed" | "revealed" | "approved"; expiresAt: string; approverKey?: string; bundle?: string };
const linkURL = (id: string, suffix = "") => `/api/v1/me/link-requests/${encodeURIComponent(id)}${suffix}`;
export const createLinkRequest = (commitment: string) => request<{ id: string; expiresAt: string }>("/api/v1/me/link-requests", { method: "POST", body: JSON.stringify({ commitment }) });
export const linkRequests = () => request<LinkRequestRow[]>("/api/v1/me/link-requests");
export const claimLinkRequest = (id: string, approverKey: string) => request<void>(linkURL(id, "/claim"), { method: "POST", body: JSON.stringify({ approverKey }) });
export const revealLinkRequest = (id: string, newcomerKey: string) => request<void>(linkURL(id, "/reveal"), { method: "POST", body: JSON.stringify({ newcomerKey }) });
/** Only outbound.ts sendLinkBundle calls this (outbound.test.ts). */
export const approveLinkRequest = (id: string, bundle: string) => request<void>(linkURL(id, "/approve"), { method: "POST", body: JSON.stringify({ bundle }) });
/** A POST (CSRF, no-store): collecting deletes the approved bundle. Only outbound.ts collectLinkBundle calls this. */
export const collectLinkRequest = (id: string) => request<LinkState>(linkURL(id, "/collect"), { method: "POST" });
/** keepalive: sent from pagehide, so the request outlives the page (same-origin, custom headers allowed). */
export const cancelLinkRequest = (id: string, keepalive = false) => request<void>(linkURL(id), { method: "DELETE", keepalive });
/** Cancels an open KySignOn confirmation (the challenge a 409 step_up_pending names). */
export const cancelSSOStepUp = (challenge: string) => request<void>(`/api/v1/auth/oidc/step-up/${encodeURIComponent(challenge)}`, { method: "DELETE" });
export const identityAPI: IdentityAPI = { myIdentity, putMyIdentity, stepUp: async (authSecret) => (await stepUp(authSecret))?.identity };
export const containerEnvelopes = (containerID: string) => request<Envelope[]>(`/api/v1/containers/${encodeURIComponent(containerID)}/envelopes`);
export const putEnvelopes = (containerID: string, envelopes: Envelope[]) => request<void>(`/api/v1/containers/${encodeURIComponent(containerID)}/envelopes`, { method: "PUT", body: JSON.stringify({ envelopes }) });
export const rotateKeys = (containerID: string, expectedGeneration: number, envelopes: Envelope[]) => request<{ keyGeneration: number }>(`/api/v1/containers/${encodeURIComponent(containerID)}/key-rotations`, { method: "POST", body: JSON.stringify({ expectedGeneration, envelopes }) });
/** A colleague's public identity; undefined when they have none or the server will not show it. */
export async function userIdentity(userID: string): Promise<PublicIdentity | undefined> {
  try { return await request<PublicIdentity>(`/api/v1/users/${encodeURIComponent(userID)}/identity`); }
  catch (error) { if (error instanceof APIRequestError && error.code === "not_found") return undefined; throw error; }
}
export const members = (containerID: string) => request<Array<Member>>(`/api/v1/containers/${encodeURIComponent(containerID)}/members`);
export const notifications = () => request<Array<{ id: string; objectId: string; authorUserId: string; createdAt: string; kind: string }>>("/api/v1/notifications");
export const presence = (containerID: string) => request<Array<{ userId: string; state: string }>>(`/api/v1/presence?containerId=${encodeURIComponent(containerID)}`);
export function updatePresence(containerID: string, state: "editing" | "viewing" | "idle") { return request<void>("/api/v1/presence", { method: "POST", body: JSON.stringify({ containerId: containerID, state }) }); }
/** Envelopes need a fresh password step-up on the server, so a keyless invitation sends none. */
export function inviteMember(containerID: string, inviteeID: string, role: string, envelopes: InvitationEnvelope[] = []) {
  return request<Invitation>(`/api/v1/containers/${encodeURIComponent(containerID)}/invitations`, { method: "POST", body: JSON.stringify(envelopes.length ? { inviteeId: inviteeID, role, envelopes } : { inviteeId: inviteeID, role }) });
}
export const acceptInvitation = (id: string, token: string) => request<void>(`/api/v1/invitations/${encodeURIComponent(id)}/accept`, { method: "POST", body: JSON.stringify({ token }) });
export function removeMember(containerID: string, userID: string) { return request<void>(`/api/v1/containers/${encodeURIComponent(containerID)}/members/${encodeURIComponent(userID)}`, { method: "DELETE" }); }
export const comments = (objectID: string): Promise<Comment[]> => request<Comment[]>(`/api/v1/objects/${encodeURIComponent(objectID)}/comments`).then(withGeneration);
export function createComment(objectID: string, bodyCiphertext: string, keyGeneration: number) { return request<{ id: string }>(`/api/v1/objects/${encodeURIComponent(objectID)}/comments`, { method: "POST", body: JSON.stringify({ bodyCiphertext, keyGeneration, mentions: [] }) }); }

export async function changes(containerID: string, since = 0) {
  return request<{ changes: Change[]; nextCursor: string; hasMore: boolean }>(
    `/api/v1/containers/${encodeURIComponent(containerID)}/changes?since=${since}`,
  );
}

export async function createObject(containerID: string, kind: "note" | "folder" = "note") {
  return request<{ id: string; version: number; changeSeq: number }>(
    `/api/v1/containers/${encodeURIComponent(containerID)}/objects`, {
      method: "POST", body: JSON.stringify({ kind }),
    },
  );
}

export async function readObject(objectID: string, version?: number) {
  const response = await fetch(`/api/v1/objects/${encodeURIComponent(objectID)}${version ? `?version=${version}` : ""}`, {
    credentials: "include", headers: { Accept: "application/octet-stream" },
  });
  if (!response.ok) throw new Error(`Unable to read note (${response.status})`);
  // A missing or malformed generation stays undefined so readKeys finds no key.
  const keyGeneration = serverGeneration(response.headers.get("X-Kynotes-Key-Generation"));
  return { bytes: new Uint8Array(await response.arrayBuffer()), version: Number(response.headers.get("X-Kynotes-Version") ?? 0), keyGeneration };
}

export async function saveObject(objectID: string, bytes: Uint8Array, baseVersion: number, keyGeneration: number) {
  return request<{ version: number; resourceId?: string; commitReceipt?: string }>(`/api/v1/objects/${encodeURIComponent(objectID)}`, {
    method: "PUT",
    body: bytes as unknown as BodyInit,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Kynotes-Base-Version": String(baseVersion),
      "X-Kynotes-Key-Generation": String(keyGeneration),
      "Idempotency-Key": crypto.randomUUID(),
    },
  });
}

export function createUpload(containerID: string, declaredBytes: number, expectedDigest: string) { return request<{ uploadId: string; chunkBytes: number; nextChunk: number }>(`/api/v1/containers/${encodeURIComponent(containerID)}/uploads`, { method: "POST", body: JSON.stringify({ declaredBytes, expectedDigest, kind: "attachment" }) }); }
export const uploadStatus = (uploadID: string) => request<{ uploadId: string; status: string; receivedBytes: number; nextChunk: number }>(`/api/v1/uploads/${encodeURIComponent(uploadID)}`);
export const deleteUpload = (uploadID: string) => request<void>(`/api/v1/uploads/${encodeURIComponent(uploadID)}`, { method: "DELETE" });
export function uploadChunk(uploadID: string, index: number, bytes: Uint8Array) { return request<{ receivedBytes: number; nextChunk: number }>(`/api/v1/uploads/${encodeURIComponent(uploadID)}`, { method: "PATCH", body: bytes as unknown as BodyInit, headers: { "Content-Type": "application/octet-stream", "X-Kynotes-Chunk-Index": String(index) } }); }
export function finalizeUpload(uploadID: string, metadataCiphertext: string, keyGeneration: number) { return request<{ attachmentId: string; digest: string; bytes: number }>(`/api/v1/uploads/${encodeURIComponent(uploadID)}/finalize`, { method: "POST", body: JSON.stringify({ metadataCiphertext, keyGeneration }) }); }
export function attachToObject(objectID: string, attachmentID: string, objectVersion: number) { return request<void>(`/api/v1/objects/${encodeURIComponent(objectID)}/attachments`, { method: "POST", body: JSON.stringify({ attachmentId: attachmentID, objectVersion }) }); }
export const objectAttachments = (objectID: string) => request<Array<{ id: string; bytes: number; metadataCiphertext: string; keyGeneration?: number }>>(`/api/v1/objects/${encodeURIComponent(objectID)}/attachments`).then(withGeneration);
export async function downloadAttachment(attachmentID: string) { const response = await fetch(`/api/v1/attachments/${encodeURIComponent(attachmentID)}`, { credentials: "include", headers: { Accept: "application/octet-stream" } }); if (!response.ok) throw new Error("Unable to download attachment"); return new Uint8Array(await response.arrayBuffer()); }

export const objectConflicts = (objectID: string) => request<Array<{ id: string; baseVersion: number; currentVersion: number; keyGeneration?: number; createdAt: string; resolved: boolean }>>(`/api/v1/objects/${encodeURIComponent(objectID)}/conflicts`).then(withGeneration);
export async function conflictCiphertext(conflictID: string) { const response = await fetch(`/api/v1/conflicts/${encodeURIComponent(conflictID)}`, { credentials: "include", headers: { Accept: "application/octet-stream" } }); if (!response.ok) throw new Error(`Unable to read conflicting version (${response.status})`); return new Uint8Array(await response.arrayBuffer()); }
export const resolveConflict = (conflictID: string) => request<void>(`/api/v1/conflicts/${encodeURIComponent(conflictID)}/resolve`, { method: "POST" });

export function createSealedShareLink(ciphertext: Uint8Array, expiresAt: string) {
  let binary = ""; for (const byte of ciphertext) binary += String.fromCharCode(byte);
  return request<{ id: string; token: string; expiresAt: string }>("/api/v1/share-links", { method: "POST", body: JSON.stringify({ ciphertext: btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""), expiresAt }) });
}

export async function fetchShareCiphertext(token: string) {
  const response = await fetch(`/api/v1/share-links/${encodeURIComponent(token)}`, { headers: { Accept: "application/octet-stream" } });
  if (!response.ok) throw new Error("This encrypted link is invalid or expired.");
  return new Uint8Array(await response.arrayBuffer());
}

export const deleteObject = (objectID: string) => request<void>(`/api/v1/objects/${encodeURIComponent(objectID)}`, { method: "DELETE" });
