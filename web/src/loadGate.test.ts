import { describe, expect, it } from "vitest";
import { loadGate } from "./loadGate";

describe("loadGate", () => {
  it("lets only the newest load finish, even for the same notebook", () => {
    const gate = loadGate();
    const first = gate.begin();
    expect(first.superseded()).toBe(false);
    const second = gate.begin();
    expect(first.superseded()).toBe(true);
    expect(second.superseded()).toBe(false);
  });

  it("marks whether a load began since, without superseding the one in flight", () => {
    const gate = loadGate();
    const inFlight = gate.begin();
    const opened = gate.mark();
    expect(opened()).toBe(false);
    expect(inFlight.superseded()).toBe(false);
    gate.begin();
    expect(opened()).toBe(true);
  });

  it("keeps gates apart", () => {
    const a = loadGate(), b = loadGate();
    const ticket = a.begin();
    b.begin();
    expect(ticket.superseded()).toBe(false);
  });
});

describe("main.tsx load wiring", () => {
  it("decides superseded loads by ticket, never by notebook ID", () => {
    const main = import.meta.glob<string>("./main.tsx", { query: "?raw", import: "default", eager: true })["./main.tsx"];
    expect(main).toMatch(/loads\.begin\(\)/);
    // A notebook opened while the list loaded discards that list and its automatic pick.
    expect(main).toMatch(/const opened = loads\.mark\(\);[\s\S]*?if \(opened\(\)\) return await loadContainers\(false\);\n\s+setNames\(nextNames\);/);
    // The key pass of a superseded load opens no fingerprint prompt and sets no error.
    expect(main).toMatch(/syncKeys\(container, false, superseded\)\.catch\(\(error\) => \{\n\s+if \(!superseded\(\)\) setError/);
    expect(main).not.toMatch(/loadingContainerID\.current !== container\.id/);
    expect(main).not.toMatch(/if \(loadingContainerID\.current === container\.id\)/);
  });
});
