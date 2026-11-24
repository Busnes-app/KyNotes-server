import { afterEach, describe, expect, it, vi } from "vitest";
import { staffAudit, staffOrgs, staffUsers } from "./staffAPI";

const org = { id: "org_a", status: "active", homeRegion: "local", enabled: true, revision: 1, lastPoll: "2026-11-23T12:00:00Z", notesUsedBytes: 26, poolBytes: 1024, orgUsedBytes: 33, ceilingBytes: 100, grantExpiresAt: "2026-11-23T12:15:00Z" };
const user = { id: "usr_a", username: "alice", role: "user", accountKind: "user", status: "active", quotaBytes: 1000, createdAt: "2026-11-23T12:00:00Z", usedBytes: 26 };
function reply(value: unknown) { const fetcher = vi.fn<typeof fetch>(async () => new Response(JSON.stringify(value), { status: 200 })); vi.stubGlobal("fetch", fetcher); return fetcher; }
afterEach(() => vi.unstubAllGlobals());
describe("staff metadata boundary", () => {
  it("reads org metadata and refuses malformed rows", async () => {
    reply([org]); await expect(staffOrgs()).resolves.toEqual([org]);
    for (const invalid of [null, {}, [{ ...org, id: "" }], [{ ...org, notesUsedBytes: -1 }], [{ ...org, enabled: "true" }], [{ ...org, poolBytes: Number.MAX_SAFE_INTEGER + 1 }]]) {
      reply(invalid); await expect(staffOrgs()).rejects.toThrow("Organization metadata");
    }
  });
  it("encodes the selected org and requires actual account usage", async () => {
    const fetcher = reply([user]); await expect(staffUsers("org/a?b")).resolves.toEqual([user]);
    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/v1/admin/users?org=org%2Fa%3Fb");
    reply([{ ...user, usedBytes: "26" }]); await expect(staffUsers("org_a")).rejects.toThrow("Account metadata");
  });
  it("keeps platform audit separate from an org and validates its rows", async () => {
    let fetcher = reply([{ event: "staff.read", outcome: "success" }]); await staffAudit("");
    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/v1/admin/audit");
    fetcher = reply([]); await staffAudit("org_b"); expect(fetcher.mock.calls[0]?.[0]).toBe("/api/v1/admin/audit?org=org_b");
    reply([{ event: 12 }]); await expect(staffAudit("org_b")).rejects.toThrow("Audit metadata");
  });
});
