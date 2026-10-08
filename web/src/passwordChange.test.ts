import { describe, expect, it } from "vitest";
import { passwordChangeProblem } from "./passwordChange";

describe("password change confirmation", () => {
  it("asks only that the new password is typed twice alike", () => {
    expect(passwordChangeProblem("a", "a")).toBeUndefined();
    expect(passwordChangeProblem("a", "b")).toMatch(/do not match/);
    expect(passwordChangeProblem("", "")).toBeDefined();
  });
});
