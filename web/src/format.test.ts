import { describe, expect, it } from "vitest";
import { safeLinkURL } from "./format";

describe("safeLinkURL", () => {
  it("keeps web and mail links and adds https to a bare host", () => {
    expect(safeLinkURL("https://example.com/a?b=1")).toBe("https://example.com/a?b=1");
    expect(safeLinkURL(" example.com ")).toBe("https://example.com/");
    expect(safeLinkURL("mailto:me@example.com")).toBe("mailto:me@example.com");
  });
  it("refuses script, data and file links, and an empty answer", () => {
    for (const bad of ["javascript:alert(1)", "JavaScript:alert(1)", "data:text/html,x", "file:///etc/passwd", "vbscript:x", "", "   ", null]) expect(safeLinkURL(bad)).toBeUndefined();
  });
});
