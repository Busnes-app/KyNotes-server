import { describe, expect, it } from "vitest";

const sources = import.meta.glob<string>(["./main.tsx", "./components/AdminConsole.tsx", "./observe.ts"], { query: "?raw", import: "default", eager: true });
const main = sources["./main.tsx"];
const adminConsole = sources["./components/AdminConsole.tsx"];

describe("administrator accounts (sub-project A)", () => {
  it("the admin console imports no key, vault or content crypto module and seals nothing", () => {
    const imports = [...adminConsole.matchAll(/from "([^"]+)"/g)].map((match) => match[1]);
    expect(imports.filter((path) => /keyring|keyService|teamKeys|observe|storage|floors|pins|identity|recovery|linking|outbound|drain/.test(path))).toEqual([]);
    expect(adminConsole).not.toMatch(/\b(?:encrypt|decrypt|seal|unwrap|wrapEnvelope)\w*\(/);
    expect(adminConsole).toContain("ADMIN_ACCOUNT_NOTE");
  });

  it("routes change-required and administrator sessions before the workspace", () => {
    const app = main.slice(main.indexOf("function App("), main.indexOf("function SharedNote("));
    const change = app.indexOf("if (auth?.passwordChangeRequired)");
    const admin = app.indexOf('if (auth?.user.accountKind === "admin")');
    expect(change).toBeGreaterThan(-1);
    expect(admin).toBeGreaterThan(change);
    expect(app.indexOf("<Workspace")).toBeGreaterThan(admin);
  });

  it("the workspace has no administrator view and never creates an administrator's team", () => {
    expect(main).not.toMatch(/setView\("admin"\)|newAdminTeam|listAdminTeams|function AdminTeams|function AdminSSO|createAdminTeam/);
    expect(sources["./observe.ts"]).not.toMatch(/adminTeams|createAdminTeam/);
  });

  it("teams are created for an everyday owner picked from active everyday users", () => {
    expect(adminConsole).toContain('users.filter((entry) => entry.status === "active" && entry.accountKind === "user")');
    expect(adminConsole).toContain("await createAdminTeam(owner)");
    expect(adminConsole).not.toMatch(/prompt\("Team name"/);
  });
});
