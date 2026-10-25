import { createHash } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { adminConsole, heldKeys, OWNER, person, signIn, vaultOf, withDialog } from "./people";
import { base64, decryptContainerMeta, decryptObject, hkdfSha256, type KeyRef } from "../src/crypto";

const NOTEBOOK = "Migration E2E";
const OLD = "Page from an older build";
const INJECTED = `obj_${"v".repeat(26)}`;
// Copied from main.tsx: a changed string fails the run.
const OLDER_META = "The server sent an older copy of a notebook's encrypted name than this device has seen (from before its encryption upgrade); it is not shown. Rename the notebook to replace it.";

/** The unbound v1 form builds before content v2 wrote: nonce ‖ AES-256-GCM(HKDF(key, cid, label)), no AAD. */
async function sealV1(key: KeyRef, cid: string, label: string, value: unknown): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const subkey = await crypto.subtle.importKey("raw", hkdfSha256(key, 32, enc.encode(cid), enc.encode(label)).slice().buffer as ArrayBuffer, "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  return new Uint8Array([...nonce, ...new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, subkey, enc.encode(JSON.stringify(value))))]);
}

/** A request from page's session as an older build sent it; JSON body unless bytes. */
const send = (page: Page, method: string, path: string, body: unknown, headers: Record<string, string> = {}) => page.evaluate(async ({ method, path, body, headers }) => {
  const csrf = document.cookie.split("; ").find((value) => value.startsWith("csrf_token="))?.slice(11) ?? "";
  const raw = Array.isArray(body);
  const response = await fetch(path, { method, body: raw ? new Uint8Array(body as number[]) : JSON.stringify(body), headers: { "Content-Type": raw ? "application/octet-stream" : "application/json", "X-CSRF-Token": csrf, "X-Kynotes-Key-Scheme": "shared-v2", ...headers } });
  if (!response.ok) throw new Error(`${method} ${path}: ${response.status} ${await response.text()}`);
  return response.json().catch(() => undefined);
}, { method, path, body: body instanceof Uint8Array ? [...body] : body, headers });

const listing = (page: Page, cid: string) => page.evaluate(async (id) => ((await (await fetch("/api/v1/containers")).json()) as Array<{ id: string; metaCiphertext: string; metaVersion: number; keyGeneration: number }>).find((entry) => entry.id === id)!, cid);
const objectBytes = (page: Page, id: string) => page.evaluate(async (oid) => {
  const response = await fetch(`/api/v1/objects/${oid}`);
  return { version: Number(response.headers.get("X-Kynotes-Version")), bytes: [...new Uint8Array(await response.arrayBuffer())] };
}, id);

test("an older notebook migrates to bound content in the background, and older forms are refused after", async ({ browser }) => {
  const admin = await person(browser);
  const first = await person(browser);
  const second = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(first.page, OWNER.username, OWNER.password);
    const { page } = first;
    await withDialog(first, { type: "prompt", text: "Notebook name", answer: NOTEBOOK }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(page.locator(".workspace-title")).toHaveText(NOTEBOOK);
    await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
    const cid = /#\/(cnt_[0-9a-z]+)/.exec(page.url())![1];
    const own = (await vaultOf(page))!.identity!;
    const meta = await listing(page, cid);
    const key = (await heldKeys(page, cid, new Map([[own.deviceId, Uint8Array.from(own.publicKey)]]))).get(meta.keyGeneration)!;
    const generation = meta.keyGeneration;

    // Leave the notebook as a build before content v2 did: a v1 page with a v1 comment, a v1 name.
    const { id } = await send(page, "POST", `/api/v1/containers/${cid}/objects`, { kind: "note" }) as { id: string };
    await send(page, "PUT", `/api/v1/objects/${id}`, await sealV1(key, cid, "kynotes/object/v1", { type: "page", title: OLD, body: "[]" }), { "X-Kynotes-Base-Version": "0", "X-Kynotes-Key-Generation": String(generation) });
    const oldComment = await sealV1(key, cid, "kynotes/comment/v1", { body: "comment from an older build", section: "" });
    const comment = await send(page, "POST", `/api/v1/objects/${id}/comments`, { bodyCiphertext: base64(oldComment), keyGeneration: generation, mentions: [] }) as { id: string };
    const oldName = await sealV1(key, cid, "kynotes/container-meta/v1", { name: NOTEBOOK });
    await send(page, "PATCH", `/api/v1/containers/${cid}`, { metaCiphertext: base64(oldName), baseVersion: meta.metaVersion, keyGeneration: generation });

    // A browser that never saw this notebook reads the older forms, then migrates it on its own.
    await signIn(second.page, OWNER.username, OWNER.password);
    await second.page.goto(`/#/${cid}`);
    await expect(second.page.locator(".workspace-title")).toHaveText(NOTEBOOK);
    await expect(second.page.locator(".note-row", { hasText: OLD })).toBeVisible();
    const marked = async () => decryptContainerMeta(key, cid, Uint8Array.from(Buffer.from((await listing(page, cid)).metaCiphertext, "base64")), false).catch(() => undefined);
    await expect.poll(marked, { timeout: 30_000 }).toEqual({ name: NOTEBOOK, objects: 2 });
    // The page is now v2, bound to its ID, and pins the v1 comment by the digest of its stored ciphertext.
    const migrated = await objectBytes(page, id);
    expect(migrated.bytes[0]).toBe(2);
    expect(await decryptObject(key, cid, id, Uint8Array.from(migrated.bytes), false)).toEqual({ type: "page", title: OLD, body: "[]", legacy: { [comment.id]: createHash("sha256").update(oldComment).digest("hex") } });

    // The pinned v1 comment still shows; an unpinned v1 comment and a v1 page the server slips in do not.
    const slipped = await sealV1(key, cid, "kynotes/comment/v1", { body: "slipped in after the marker", section: "" });
    await second.page.route(`**/api/v1/objects/${id}/comments`, async (route) => {
      const response = await route.fetch();
      const rows = await response.json() as Array<Record<string, unknown>>;
      await route.fulfill({ response, json: [...rows, { ...rows[0], id: `cmt_${"s".repeat(26)}`, bodyCiphertext: base64(slipped) }] });
    });
    const injected = await sealV1(key, cid, "kynotes/object/v1", { type: "page", title: "Injected v1 page", body: "[]" });
    await second.page.route(`**/api/v1/objects/${INJECTED}`, (route) => route.fulfill({ status: 200, contentType: "application/octet-stream", headers: { "X-Kynotes-Version": "1", "X-Kynotes-Key-Generation": String(generation) }, body: Buffer.from(injected) }));
    await second.page.route(`**/api/v1/containers/${cid}/changes**`, async (route) => {
      const response = await route.fetch();
      const json = await response.json() as { changes: Array<Record<string, unknown>> };
      if (new URL(route.request().url()).searchParams.get("since") === "0") json.changes.push({ id: INJECTED, kind: "object", changeSeq: 1, deleted: false });
      await route.fulfill({ response, json });
    });
    await second.page.goto("about:blank");
    await second.page.goto(`/#/${cid}`);
    await expect(second.page.locator(".note-list")).toHaveAttribute("aria-busy", "false");
    await second.page.locator(".note-row", { hasText: OLD }).click();
    await expect(second.page.getByText("comment from an older build")).toBeVisible();
    await expect(second.page.getByText("slipped in after the marker")).toHaveCount(0);
    await expect(second.page.locator(".note-row", { hasText: "Injected v1 page" })).toHaveCount(0);
    await second.page.unrouteAll();

    // This browser pinned the marker: a server serving the older name again is refused, with a notice.
    await second.page.route("**/api/v1/containers", async (route) => {
      const response = await route.fetch();
      const rows = await response.json() as Array<Record<string, unknown>>;
      await route.fulfill({ response, json: rows.map((row) => (row.id === cid ? { ...row, metaCiphertext: base64(oldName) } : row)) });
    });
    await second.page.goto("about:blank");
    await second.page.goto(`/#/${cid}`);
    await expect(second.page.getByText(OLDER_META)).toBeVisible();
    await expect(second.page.locator(".workspace-title")).toHaveText(`Notebook ${cid.slice(4, 10)}`);
    await second.page.unrouteAll();
    expect([...first.unexpected, ...second.unexpected]).toEqual([]);
  } finally {
    for (const who of [admin, first, second]) await who.page.context().close();
  }
});
