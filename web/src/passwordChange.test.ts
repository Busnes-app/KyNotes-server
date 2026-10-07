import { describe, expect, it } from "vitest";
import { PASSWORD_CHANGE_WARNING, passwordChangeProblem } from "./passwordChange";

describe("password change confirmation", () => {
  it("warns that existing notes become unreadable", () => {
    expect(PASSWORD_CHANGE_WARNING).toMatch(/unreadable/i);
  });

  it("requires matching passwords and an explicit acknowledgement", () => {
    expect(passwordChangeProblem("", "", true)).toBeDefined();
    expect(passwordChangeProblem("a", "b", true)).toMatch(/do not match/);
    expect(passwordChangeProblem("a", "a", false)).toMatch(/confirm/i);
    expect(passwordChangeProblem("a", "a", true)).toBeUndefined();
  });
});
