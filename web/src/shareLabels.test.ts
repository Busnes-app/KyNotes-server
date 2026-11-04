import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { asContentKey } from "./crypto";
import { forgetShareLabel, keepShareLabel, readShareLabel } from "./shareLabels";
import { getNote, putNote } from "./storage";

const owner = "usr_0123456789abcdefghjkmnpqrs";
const key = asContentKey(new Uint8Array(32).fill(7));
const other = asContentKey(new Uint8Array(32).fill(9));

describe("share link labels", () => {
  it("names a link made here, sealed, and says when it was made elsewhere or cannot be read", async () => {
    await keepShareLabel(owner, "shl_one", "cnt_a", { key, generation: 1 }, { title: "Plans", notebook: "Work" });
    const stored = await getNote(owner, "share:shl_one");
    expect(new TextDecoder().decode(stored!.payload)).not.toContain("Plans");
    expect(stored).toMatchObject({ containerID: "cnt_a", keyGeneration: 1 });
    expect(await readShareLabel(owner, "shl_one", () => [key])).toEqual({ title: "Plans", notebook: "Work" });
    expect(await readShareLabel(owner, "shl_two", () => [key])).toBe("none");
    expect(await readShareLabel(owner, "shl_one", () => [other])).toBe("unreadable");
    expect(await readShareLabel(owner, "shl_one", () => [])).toBe("unreadable");
    // Bound to its link: a copy filed under another link's ID does not open.
    await putNote(owner, { ...stored!, id: "share:shl_three" });
    expect(await readShareLabel(owner, "shl_three", () => [key])).toBe("unreadable");
    // Another account in this browser does not see it.
    expect(await readShareLabel("usr_other0000000000000000000", "shl_one", () => [key])).toBe("none");
    await forgetShareLabel(owner, "shl_one");
    expect(await readShareLabel(owner, "shl_one", () => [key])).toBe("none");
  });
});
