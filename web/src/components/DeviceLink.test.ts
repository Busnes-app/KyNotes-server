import { describe, expect, it } from "vitest";

const sources = import.meta.glob<string>(["../**/*.{ts,tsx}", "!../**/*.test.{ts,tsx}", "!../ky-ui/**"], { query: "?raw", import: "default", eager: true });
const screen = sources["./DeviceLink.tsx"] ?? sources["../components/DeviceLink.tsx"];
const calls = (text: string, name: string) => [...text.matchAll(new RegExp(`\\b${name}\\(([^)]*)\\)`, "g"))].map((match) => match[1]);

describe("link screens", () => {
  it("builds the approver's confirmation only from the typed input, never from the code it holds", () => {
    expect(screen).toBeDefined();
    const typedCalls = calls(screen, "confirmTypedCode");
    expect(typedCalls.length).toBeGreaterThan(0);
    for (const args of typedCalls) expect(args).toMatch(/^\w+, typed$/);
    // typed is the input field's value and nothing else.
    expect(screen).toContain("value={typed}");
    for (const args of calls(screen, "setTyped")) expect(["event.currentTarget.value", '""']).toContain(args);
    // The approver neither shows its own code nor offers a "Codes match" click.
    expect(screen).not.toMatch(/active\??\.code\}/);
    expect(screen).not.toContain("Codes match — send key");
    // Nothing may fill the code for the user: no OTP autofill, no password-manager fill.
    expect(screen).not.toContain("one-time-code");
    expect(screen).toMatch(/value=\{typed\}.*autoComplete="off"/);
  });

  it("mints the newcomer's confirmation in one place, from the code it shows", () => {
    expect(calls(screen, "confirmCheckCode")).toEqual(["link.id, link.code"]);
  });

  it("only the link screens and the link flow mint confirmations", () => {
    const minting = Object.entries(sources).filter(([, text]) => /\bconfirm(Typed)?(CheckCode|Code)\(/.test(text)).map(([name]) => name.replace(/^.*\//, "")).sort();
    expect(minting).toEqual(["DeviceLink.tsx", "linkFlow.ts", "linking.ts"]);
  });

  it("ties the approver's claim and send to the screen's lifetime", () => {
    // Claims go through keepClaim (tested in linkFlow.test.ts), wanted only while open and alone.
    expect(calls(screen, "claimLink")).toEqual(["{ claim: claimLinkRequest }, row, userID"]);
    expect(screen).toContain("await keepClaim(claimLink(");
    expect(screen).toContain("() => mounted.current && !activeRef.current, cancelLinkRequest)");
    expect(screen).toContain("<button disabled={claimPending}");
    // Leaving mid-send never deletes a bundle that may just have been stored.
    expect(screen).toContain("if (!sending.current) quietCancel(open.id, leaving);");
    // A reload or close ends both sides' attempts with a keepalive cancel.
    expect(screen.match(/addEventListener\("pagehide", leave\)/g)).toHaveLength(2);
    expect(screen.match(/removeEventListener\("pagehide", leave\)/g)).toHaveLength(2);
  });

  it("offers no Approve on a request another tab of this session claimed", () => {
    expect(screen).toMatch(/\{row\.claimed \? <span className="config-muted">Being approved in another tab<\/span> : <button disabled=\{claimPending\}/);
  });

  it("lets the link flow pace the newcomer's collect", () => {
    expect(screen).toContain("await awaitLinkBundle(api, attempt, userID, () => generation.current === mine, setLink)");
    expect(screen).not.toContain("pollNewcomerLink");
  });

  it("checks for another local copy before starting a link", () => {
    const check = screen.indexOf("await otherCopyHeld(");
    expect(check).toBeGreaterThan(-1);
    expect(check).toBeLessThan(screen.indexOf("await startNewcomerLink("));
  });
});
