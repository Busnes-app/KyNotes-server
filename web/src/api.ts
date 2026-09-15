import { confirmSSOAction } from "./reauth";
export type User = { id: string; role: string; username?: string };
export type Session = { sso?: boolean; user: User; expiresAt: string; hardExpiresAt: string };
export type Container = { id: string; kind: string; teamId?: string; metaCiphertext: string; metaVersion: number; changeSeq: number; keyGeneration: number };
export type Comment = { id: string; authorUserId: string; username: string; bodyCiphertext: string; keyGeneration: number; createdAt: string };
export type AdminUser = { id: string; username: string; role: string; status: string; quotaBytes: number; createdAt: string };
export type AdminTeam = { id: string; kind: string; ownerUserId: string; metaCiphertext?: string; metaVersion?: number; changeSeq?: number; keyGeneration?: number };
export type Change = { id: string; kind: string; changeSeq: number; deleted: boolean };
export type Note = { id: string; title: string; body: string; version: number; updatedAt: string };

type APIError = { error?: { code?: string; message?: string }; conflictId?: string; currentVersion?: number };
export class APIRequestError extends Error { code?: string; conflictId?: string; currentVersion?: number; constructor(message: string, detail: APIError) { super(message); this.name = "APIRequestError"; this.code = detail.error?.code; this.conflictId = detail.conflictId; this.currentVersion = detail.currentVersion; } }

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
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) headers.set("X-CSRF-Token", csrfToken());
  const response = await actionFetch(path, { ...init, headers, credentials: "include" });
  if (!response.ok) {
    let detail: APIError = {};
    try { detail = await response.json() as APIError; } catch { /* opaque server error */ }
    throw new APIRequestError(detail.error?.message ?? `Request failed (${response.status})`, detail);
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
  return request<Session>("/api/v1/auth/login", {
    method: "POST", body: JSON.stringify({ username, authSecret }),
  });
}

export type SSOSettings = {
  enabled: boolean;
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  autoProvision: boolean;
  hmacSecret?: string;
};

export const ssoConfig = () => request<{ enabled: boolean; issuerUrl: string; clientId: string }>("/api/v1/auth/sso-config");
export const adminSSO = () => request<SSOSettings>("/api/v1/admin/sso");
export const saveAdminSSO = (settings: SSOSettings) => request<SSOSettings>("/api/v1/admin/sso", { method: "POST", body: JSON.stringify(settings) });
export const pairAdminSSO = (issuerUrl: string, pairingToken: string, callbackUrl?: string) => request<{ success: boolean; systemId: string; settings: SSOSettings }>("/api/v1/admin/sso/pair", { method: "POST", body: JSON.stringify({ issuerUrl, pairingToken, callbackUrl }) });

export const session = () => request<Session>("/api/v1/auth/session");
export const serverTheme = () => request<{ defaultTheme: string }>("/api/v1/theme");
export const logout = () => request<void>("/api/v1/auth/logout", { method: "POST" });
export const containers = () => request<Container[]>("/api/v1/containers");

export function createContainer(kind = "workbook", metaCiphertext = "", teamId = "") {
  return request<Container>("/api/v1/containers", {
    method: "POST", body: JSON.stringify({ kind, metaCiphertext, teamId }),
  });
}

export function updateContainer(id: string, metaCiphertext: string, baseVersion: number) {
  return request<{ metaVersion: number; changeSeq: number }>(`/api/v1/containers/${encodeURIComponent(id)}`, {
    method: "PATCH", body: JSON.stringify({ metaCiphertext, baseVersion }),
  });
}

export async function serviceStatus() {
  const [health, ready] = await Promise.all([fetch("/healthz"), fetch("/readyz")]);
  return { health: health.ok, ready: ready.ok };
}
export const adminUsers = () => request<AdminUser[]>("/api/v1/admin/users");
export const adminAudit = () => request<Array<Record<string, string>>>("/api/v1/admin/audit");
export const adminTeams = () => request<AdminTeam[]>("/api/v1/admin/teams");
export function createAdminTeam(metaCiphertext: string) { return request<AdminTeam>("/api/v1/admin/teams", { method: "POST", body: JSON.stringify({ metaCiphertext }) }); }
export function createAdminUser(input: { username: string; authSecret: string; loginSalt: string; iterations: number; role: string }) { return request<{ id: string }>("/api/v1/admin/users", { method: "POST", body: JSON.stringify(input) }); }
export function resetAdminPassword(id: string, input: { newAuthSecret: string; newLoginSalt: string; iterations: number }) { return request<void>(`/api/v1/admin/users/${encodeURIComponent(id)}/password`, { method: "POST", body: JSON.stringify(input) }); }
export function addAdminTeamMember(teamID: string, userID: string, role: string) { return request<void>(`/api/v1/admin/teams/${encodeURIComponent(teamID)}/members`, { method: "POST", body: JSON.stringify({ userId: userID, role }) }); }
export function removeAdminTeamMember(teamID: string, userID: string) { return request<void>(`/api/v1/admin/teams/${encodeURIComponent(teamID)}/members/${encodeURIComponent(userID)}`, { method: "DELETE" }); }
export const adminSettings = () => request<{ defaultTheme: string }>("/api/v1/admin/settings");
export function updateAdminSettings(defaultTheme: string) { return request<void>("/api/v1/admin/settings", { method: "PATCH", body: JSON.stringify({ defaultTheme }) }); }
export function updateAdminUser(user: AdminUser) { return request<void>(`/api/v1/admin/users/${encodeURIComponent(user.id)}`, { method: "PATCH", body: JSON.stringify(user) }); }
export function changePassword(input: { currentAuthSecret: string; newAuthSecret: string; newLoginSalt: string; iterations: number }) { return request<void>("/api/v1/auth/password", { method: "POST", body: JSON.stringify(input) }); }
/** Re-proves the login secret for the current session; destructive admin routes answer step_up_required until this succeeds. */
export function stepUp(authSecret: string) { return request<void>("/api/v1/auth/step-up", { method: "POST", body: JSON.stringify({ authSecret }) }); }
export const members = (containerID: string) => request<Array<{ userId: string; username: string; role: string }>>(`/api/v1/containers/${encodeURIComponent(containerID)}/members`);
export const notifications = () => request<Array<{ id: string; objectId: string; authorUserId: string; createdAt: string; kind: string }>>("/api/v1/notifications");
export const presence = (containerID: string) => request<Array<{ userId: string; state: string }>>(`/api/v1/presence?containerId=${encodeURIComponent(containerID)}`);
export function updatePresence(containerID: string, state: "editing" | "viewing" | "idle") { return request<void>("/api/v1/presence", { method: "POST", body: JSON.stringify({ containerId: containerID, state }) }); }
export function inviteMember(containerID: string, inviteeID: string, role: string) { return request<{ id: string; token: string }>(`/api/v1/containers/${encodeURIComponent(containerID)}/invitations`, { method: "POST", body: JSON.stringify({ inviteeId: inviteeID, role }) }); }
export function removeMember(containerID: string, userID: string) { return request<void>(`/api/v1/containers/${encodeURIComponent(containerID)}/members/${encodeURIComponent(userID)}`, { method: "DELETE" }); }
export const comments = (objectID: string) => request<Comment[]>(`/api/v1/objects/${encodeURIComponent(objectID)}/comments`);
export function createComment(objectID: string, bodyCiphertext: string, keyGeneration: number) { return request<{ id: string }>(`/api/v1/objects/${encodeURIComponent(objectID)}/comments`, { method: "POST", body: JSON.stringify({ bodyCiphertext, keyGeneration, mentions: [] }) }); }

export async function changes(containerID: string, since = 0) {
  return request<{ changes: Change[]; nextCursor: string; hasMore: boolean }>(
    `/api/v1/containers/${encodeURIComponent(containerID)}/changes?since=${since}`,
  );
}

export async function createObject(containerID: string) {
  return request<{ id: string; version: number; changeSeq: number }>(
    `/api/v1/containers/${encodeURIComponent(containerID)}/objects`, {
      method: "POST", body: JSON.stringify({ kind: "note" }),
    },
  );
}

export async function readObject(objectID: string, version?: number) {
  const response = await fetch(`/api/v1/objects/${encodeURIComponent(objectID)}${version ? `?version=${version}` : ""}`, {
    credentials: "include", headers: { Accept: "application/octet-stream" },
  });
  if (!response.ok) throw new Error(`Unable to read note (${response.status})`);
  return { bytes: new Uint8Array(await response.arrayBuffer()), version: Number(response.headers.get("X-Kynotes-Version") ?? 0) };
}

export async function saveObject(objectID: string, bytes: Uint8Array, baseVersion: number, keyGeneration = 1) {
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
export const objectAttachments = (objectID: string) => request<Array<{ id: string; bytes: number; metadataCiphertext: string; keyGeneration: number }>>(`/api/v1/objects/${encodeURIComponent(objectID)}/attachments`);
export async function downloadAttachment(attachmentID: string) { const response = await fetch(`/api/v1/attachments/${encodeURIComponent(attachmentID)}`, { credentials: "include", headers: { Accept: "application/octet-stream" } }); if (!response.ok) throw new Error("Unable to download attachment"); return new Uint8Array(await response.arrayBuffer()); }

export const objectConflicts = (objectID: string) => request<Array<{ id: string; baseVersion: number; currentVersion: number; createdAt: string; resolved: boolean }>>(`/api/v1/objects/${encodeURIComponent(objectID)}/conflicts`);

export function createShareLink(objectID: string, expiresAt: string, version = 0) {
  return request<{ id: string; token: string; objectId: string; version: number; expiresAt: string; commitReceipt: string }>(`/api/v1/objects/${encodeURIComponent(objectID)}/share-links`, {
    method: "POST", body: JSON.stringify({ version, expiresAt }),
  });
}

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
