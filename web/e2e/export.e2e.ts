import { readFile } from "node:fs/promises";
import { expect, test, type Page, type Request } from "@playwright/test";
import { adminConsole, OWNER, person, signIn, withDialog } from "./people";

const NOTEBOOK = "Export E2E";
const BODY = "Plaintext only in this browser";
const ATTACHED = "attached bytes ✓";
const INLINE = "inline-secret-name.png";
// A 1x1 PNG.
const PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=", "base64");
// Copied from main.tsx: a changed string fails the run.
const EXPORT_WARNING = "The export is not encrypted: anyone who gets the file can read these notes and attachments.";

const objectSave = (page: Page) => page.waitForResponse((response) => response.request().method() === "PUT" && /\/api\/v1\/objects\/obj_/.test(response.url()) && response.ok());

/** Entries of a stored zip, through its central directory. */
function unzip(bytes: Buffer): Map<string, Buffer> {
  const end = bytes.length - 22;
  expect(bytes.readUInt32LE(end)).toBe(0x06054b50);
  const files = new Map<string, Buffer>();
  let at = bytes.readUInt32LE(end + 16);
  for (let i = 0; i < bytes.readUInt16LE(end + 10); i += 1) {
    const size = bytes.readUInt32LE(at + 20), nameLength = bytes.readUInt16LE(at + 28), local = bytes.readUInt32LE(at + 42);
    const name = bytes.subarray(at + 46, at + 46 + nameLength).toString("utf8");
    files.set(name, bytes.subarray(local + 30 + nameLength, local + 30 + nameLength + size));
    at += 46 + nameLength;
  }
  return files;
}

test("a notebook exports as Markdown and attachments, decrypted only in the browser", async ({ browser }) => {
  const admin = await person(browser);
  const owner = await person(browser);
  try {
    await adminConsole(admin.page);
    await signIn(owner.page, OWNER.username, OWNER.password);
    const { page } = owner;
    await withDialog(owner, { type: "prompt", text: "Notebook name", answer: NOTEBOOK }, () => page.getByRole("button", { name: "＋ New notebook" }).click());
    await expect(page.locator(".workspace-title")).toHaveText(NOTEBOOK);
    await expect(page.locator(".note-list")).toHaveAttribute("aria-busy", "false");

    const created = objectSave(page);
    await page.getByRole("button", { name: "New page" }).click();
    await created;
    const titled = objectSave(page);
    await page.locator(".title-input").fill("Exported page");
    await titled;
    const written = objectSave(page);
    // New pages are canvas pages: a text box, then typing.
    await page.getByRole("button", { name: "Add text" }).click();
    await page.locator(".bn-editor").first().click();
    await page.keyboard.type(BODY);
    await written;
    // An inline image, through BlockNote's own upload panel.
    const pictured = objectSave(page);
    await page.keyboard.press("Enter");
    await page.keyboard.type("/image");
    await page.keyboard.press("Enter");
    const chooser = page.waitForEvent("filechooser");
    await page.locator('[data-test="upload-input"]').click();
    await (await chooser).setFiles({ name: INLINE, mimeType: "image/png", buffer: PNG });
    await expect(page.locator(".bn-editor img")).toBeVisible();
    await pictured;
    await page.locator(".attachment-picker input").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from(ATTACHED) });
    await expect(page.getByText("Attachment uploaded and encrypted.")).toBeVisible();

    // Export sends nothing: every request it makes is a read, and none names a decrypted file.
    const sent: string[] = [];
    const record = (request: Request) => {
      if (request.method() !== "GET" || decodeURIComponent(request.url()).includes("inline-secret")) sent.push(`${request.method()} ${request.url()}`);
    };
    page.on("request", record);
    const download = page.waitForEvent("download");
    await withDialog(owner, { type: "confirm", text: `${EXPORT_WARNING}\n\nExport "${NOTEBOOK}"?` }, () => page.getByRole("button", { name: "Export notebook", exact: true }).click());
    const file = await download;
    await expect(page.getByText("Exported 1 pages.")).toBeVisible();
    page.off("request", record);
    expect(sent).toEqual([]);
    expect(file.suggestedFilename()).toBe(`${NOTEBOOK}.zip`);

    const files = unzip(await readFile((await file.path())!));
    const manifest = JSON.parse(files.get(`${NOTEBOOK}/manifest.json`)!.toString());
    expect(manifest).toMatchObject({ format: "kynotes.export.v1", notebook: NOTEBOOK, unreadable: 0 });
    expect(manifest.pages).toHaveLength(1);
    const markdown = files.get(`${NOTEBOOK}/${manifest.pages[0].path}`)!.toString();
    expect(markdown).toContain("# Exported page");
    expect(markdown).toContain(BODY);
    expect(JSON.parse(files.get(`${NOTEBOOK}/${manifest.pages[0].canvas}`)!.toString())).toMatchObject({ format: "kynotes.canvas.v1" });
    const image = manifest.pages[0].attachments.find((entry: { name: string }) => entry.name === INLINE);
    expect(files.get(`${NOTEBOOK}/${image.path}`)!.equals(PNG)).toBe(true);
    expect(markdown).toContain(`(../attachments/${image.id}/${INLINE})`);
    const attachment = manifest.pages[0].attachments.find((entry: { name: string }) => entry.name === "notes.txt");
    expect(attachment).toMatchObject({ name: "notes.txt", type: "text/plain" });
    expect(files.get(`${NOTEBOOK}/${attachment.path}`)!.toString()).toBe(ATTACHED);
    expect(markdown).toContain(`](../attachments/${attachment.id}/notes.txt)`);
    expect(owner.unexpected).toEqual([]);
  } finally {
    await admin.page.context().close();
    await owner.page.context().close();
  }
});
