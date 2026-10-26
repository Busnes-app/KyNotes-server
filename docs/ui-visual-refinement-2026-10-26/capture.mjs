// KyNotes adapter for capture-core.mjs: the e2e throwaway server config on its own port,
// first-run setup through the UI (administrator + everyday owner), then the owner's
// workspace with one synthetic notebook and note.
import { spawn, spawnSync } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { here, main, waitReady } from './capture-core.mjs';

const repo = join(here(import.meta.url), '../..');
const PORT = '18091';
const baseURL = `http://127.0.0.1:${PORT}`;
const ADMIN = { username: 'admin', password: 'fleet admin horse battery staple' };
const OWNER = { username: 'owner', password: 'fleet owner horse battery staple' };
let seeded = false;

async function seed(page) {
  // Notebook names come from a prompt dialog.
  page.on('dialog', (d) => void d.accept(d.type() === 'prompt' ? 'Field notes' : undefined));
  await page.getByRole('button', { name: /New notebook/ }).first().click();
  await page.locator('.workspace-title', { hasText: 'Field notes' }).waitFor();
  await page.getByRole('button', { name: 'Create a note' }).click();
  // New pages open as a canvas; a click places a text box.
  const hint = await page.locator('.canvas-hint').boundingBox();
  await page.mouse.click(hint.x + 40, hint.y + 80);
  await page.keyboard.type('Garden plan: order seeds by Friday.');
  await page.getByRole('button', { name: 'Save', exact: true }).first().click();
  await page.waitForTimeout(2000);
}

async function openNote(page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Settings' }).waitFor();
  await page.locator('.note-row').first().click();
  await page.locator('.save-button').waitFor();
  await page.waitForTimeout(800);
}

await main({
  // Saved as the theme name, as the product writes it.
  crossTab: ['kynotes-theme', 'Sun', 'sun'],
  product: 'kynotes',
  repo,
  dist: join(repo, 'internal/web/dist/index.html'),
  fixture: 'fresh data dir (web/e2e/server.sh config on port 18091, dev_insecure_cookies on loopback); first-run setup through the UI creating administrator "admin" and everyday "owner"; owner creates notebook "Field notes" with one note typed "Garden plan: order seeds by Friday."; captures are the owner',
  async start(dir) {
    const binary = join(dir, 'kynotes-server');
    const build = spawnSync('go', ['build', '-o', binary, './cmd/kynotes-server'], { cwd: repo, stdio: 'inherit' });
    if (build.status !== 0) throw new Error('go build failed');
    await writeFile(join(dir, 'kynotes.yaml'), `server:\n  bind: "127.0.0.1:${PORT}"\n  dev_insecure_cookies: true\nsecrets:\n  pairing_secret: "12345678901234567890123456789012"\n  server_salt_key: "12345678901234567890123456789012"\ndata_dir: "${dir}"\nratelimit:\n  login_per_minute: 120\n`);
    const proc = spawn(binary, ['--config', join(dir, 'kynotes.yaml')], { cwd: dir, env: { PATH: process.env.PATH, HOME: dir }, stdio: ['ignore', 'ignore', 'inherit'] });
    await waitReady(`${baseURL}/readyz`);
    return { baseURL, binary, pid: proc.pid, stop: async () => { proc.kill('SIGTERM'); await new Promise((r) => proc.once('exit', r)); } };
  },
  async signIn(page) {
    await page.goto('/');
    const setup = await page.evaluate(async () => (await (await fetch('/api/v1/setup')).json()).setupRequired);
    if (setup) {
      await page.getByLabel('Administrator username').fill(ADMIN.username);
      await page.getByLabel('Administrator password', { exact: true }).fill(ADMIN.password);
      await page.getByLabel('Confirm administrator password').fill(ADMIN.password);
      await page.getByLabel('Everyday username').fill(OWNER.username);
      await page.getByLabel('Everyday password', { exact: true }).fill(OWNER.password);
      await page.getByLabel('Confirm everyday password').fill(OWNER.password);
      await page.getByRole('button', { name: 'Initialize KyNotes' }).click();
      await page.getByRole('heading', { name: 'Administration' }).waitFor();
      await page.context().clearCookies();
      await page.goto('/');
    }
    const stepUp = page.getByRole('dialog', { name: 'Confirm your password' });
    await page.addLocatorHandler(stepUp, async (dialog) => {
      await dialog.getByLabel('Password').fill(OWNER.password);
      await dialog.getByRole('button', { name: 'Confirm' }).click();
    });
    await page.getByLabel('Username').fill(OWNER.username);
    await page.getByLabel('Password', { exact: true }).fill(OWNER.password);
    await page.getByRole('button', { name: 'Unlock KyNotes' }).click();
    await page.getByRole('button', { name: 'Settings' }).waitFor();
    if (!seeded) { await seed(page); seeded = true; }
  },
  hoverTarget: (page) => page.getByRole('navigation', { name: 'Settings sections' }).getByRole('link', { name: 'Reminders' }),
  surfaces: {
    async workspace(page) {
      await page.goto('/');
      await page.getByRole('button', { name: 'Settings' }).waitFor();
      await page.waitForTimeout(1000);
    },
    // The seeded page open in the editor (header Save visible), then saved (commit toast).
    async note(page) { await openNote(page); },
    async 'note-committed'(page) {
      await openNote(page);
      await page.locator('.save-button').click();
      await page.locator('.commit-toast').waitFor({ timeout: 15000 });
    },
    async appearance(page, { device }) {
      if (device === 'mobile') await page.getByRole('button', { name: 'Notebooks and account' }).click();
      await page.getByRole('button', { name: 'Settings' }).click();
      await page.getByRole('heading', { name: 'Appearance' }).first().waitFor();
    },
  },
});
