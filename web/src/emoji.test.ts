import { describe, expect, it } from "vitest";
import { emojiQueryReady, emojiTriggerStartsWord } from "./emoji";

describe("emoji menu trigger", () => {
  it("opens only where ':' starts a word", () => {
    for (const before of ["", "lunch ", "a\t", "x "]) expect(emojiTriggerStartsWord(before)).toBe(true);
    for (const before of ["due", "10", "http", "("]) expect(emojiTriggerStartsWord(before)).toBe(false);
  });
  it("waits for two letters after ':'", () => {
    for (const query of ["sm", "smile", "ér"]) expect(emojiQueryReady(query)).toBe(true);
    for (const query of ["", "s", "30", "s1", " s", "-)"]) expect(emojiQueryReady(query)).toBe(false);
  });
});
