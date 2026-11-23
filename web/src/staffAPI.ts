import { request, type AdminUser } from "./api";

export type StaffOrg = {
  id: string; status: string; homeRegion: string; enabled: boolean; revision: number;
  lastPoll: string; notesUsedBytes: number; poolBytes: number; orgUsedBytes: number;
  ceilingBytes: number; grantExpiresAt: string;
};
export type StaffUser = AdminUser & { usedBytes: number };

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
const count = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const text = (value: unknown): value is string => typeof value === "string";
const id = (value: unknown): value is string => text(value) && value.length > 0 && value.length <= 128;
function org(value: unknown): value is StaffOrg {
  return record(value) && id(value.id) && text(value.status) && text(value.homeRegion)
    && typeof value.enabled === "boolean" && count(value.revision) && text(value.lastPoll)
    && count(value.notesUsedBytes) && count(value.poolBytes) && count(value.orgUsedBytes)
    && count(value.ceilingBytes) && text(value.grantExpiresAt);
}
function user(value: unknown): value is StaffUser {
  return record(value) && id(value.id) && text(value.username) && text(value.role)
    && (value.accountKind === "user" || value.accountKind === "admin") && text(value.status)
    && count(value.quotaBytes) && text(value.createdAt) && count(value.usedBytes);
}
export async function staffOrgs(): Promise<StaffOrg[]> {
  const rows = await request<unknown>("/api/v1/admin/orgs");
  if (!Array.isArray(rows) || !rows.every(org)) throw new Error("Organization metadata could not be read. Refresh to try again.");
  return rows;
}
export async function staffUsers(orgID: string): Promise<StaffUser[]> {
  const rows = await request<unknown>(`/api/v1/admin/users?org=${encodeURIComponent(orgID)}`);
  if (!Array.isArray(rows) || !rows.every(user)) throw new Error("Account metadata could not be read. Refresh to try again.");
  return rows;
}
export async function staffAudit(orgID: string): Promise<Array<Record<string, string>>> {
  const rows = await request<unknown>(`/api/v1/admin/audit${orgID ? `?org=${encodeURIComponent(orgID)}` : ""}`);
  if (!Array.isArray(rows) || !rows.every((row): row is Record<string, string> => record(row) && Object.values(row).every(text))) throw new Error("Audit metadata could not be read. Refresh to try again.");
  return rows;
}
