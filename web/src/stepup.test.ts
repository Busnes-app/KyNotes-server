import { describe, expect, it } from "vitest";
import { APIRequestError } from "./api";
import { withStepUp } from "./stepup";

const stepUpRequired = () => new APIRequestError("Confirm your password", { error: { code: "step_up_required" } }, 403);

describe("withStepUp", () => {
  it("asks for the password once and repeats the refused action", async () => {
    const asked: string[] = [];
    let calls = 0;
    const result = await withStepUp("admin", async () => { calls += 1; if (calls === 1) throw stepUpRequired(); return "done"; }, async (name) => { asked.push(name); });
    expect(result).toBe("done");
    expect(calls).toBe(2);
    expect(asked).toEqual(["admin"]);
  });

  it("does not ask when the action needs no step-up, and passes other errors through", async () => {
    let asked = false;
    const ask = async () => { asked = true; };
    expect(await withStepUp("admin", async () => 1, ask)).toBe(1);
    await expect(withStepUp("admin", async () => { throw new Error("nope"); }, ask)).rejects.toThrow("nope");
    expect(asked).toBe(false);
  });

  it("stops when the dialog is cancelled", async () => {
    let calls = 0;
    await expect(withStepUp("admin", async () => { calls += 1; throw stepUpRequired(); }, async () => { throw new Error("Password confirmation cancelled"); })).rejects.toThrow("cancelled");
    expect(calls).toBe(1);
  });
});
