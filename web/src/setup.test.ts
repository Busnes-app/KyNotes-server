import { describe, expect, it } from "vitest";
import { setupProblem } from "./setup";

const good = { admin: "admin", adminPassword: "admin horse battery", adminConfirm: "admin horse battery", everyday: "owner", everydayPassword: "owner horse battery", everydayConfirm: "owner horse battery" };

describe("setupProblem", () => {
  it("accepts two accounts with their own names and passwords", () => {
    expect(setupProblem(good)).toBeUndefined();
  });
  it("refuses equal passwords and equal usernames", () => {
    expect(setupProblem({ ...good, everydayPassword: good.adminPassword, everydayConfirm: good.adminPassword })).toBe("Use a different password for each account.");
    expect(setupProblem({ ...good, everyday: " Admin " })).toBe("Use a different username for each account.");
  });
  it("refuses empty names, unequal confirmations and short passwords", () => {
    expect(setupProblem({ ...good, everyday: "  " })).toBe("Both usernames are required.");
    expect(setupProblem({ ...good, adminConfirm: "x" })).toBe("Passwords do not match.");
    expect(setupProblem({ ...good, everydayPassword: "short", everydayConfirm: "short" })).toBe("Passwords must be at least 8 characters.");
  });
});
