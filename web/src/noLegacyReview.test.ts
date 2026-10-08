import { describe, expect, it } from "vitest";

const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./ky-ui/**"], { query: "?raw", import: "default", eager: true });

describe("the pre-sharing review is gone", () => {
  it("has no review, closure or reopen code left", () => {
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(["./main.tsx", "./keyring.ts"]));
    expect(sources["./migration.ts"]).toBeUndefined();
    expect(sources["./components/LegacyReview.tsx"]).toBeUndefined();
    for (const file of ["./main.tsx", "./keyring.ts", "./floors.ts", "./observe.ts", "./storage.ts", "./api.ts", "./outbound.ts"]) {
      expect(sources[file], file).not.toMatch(/closedOf|closeLegacy|reopenLegacy|ReopenConfirmation|setClosureReader|closeFloorIn|reopenFloorIn|legacyRows|rewriteComment|sendCommentRewrite|\/legacy\b/);
    }
  });
});
