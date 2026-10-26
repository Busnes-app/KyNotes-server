// KyNotes adapter for capture-core.mjs, review follow-up batch (R3): real-app captures of
// pre-existing .secondary controls the refinement's global button rule restyled. Same fixture
// as the visual-refinement batch: first-run setup through the UI, the everyday owner, one
// synthetic notebook and note.
// CAPTURE_SOURCE_COMMIT=<sha> builds the server from that commit, extracted with git archive into
// a scratch tree (its own embedded bundle); otherwise from this worktree.
// Usage: [CAPTURE_SOURCE_COMMIT=<sha>] node capture.mjs <prefix> [surface,...] | --verify <prefix>
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { here, main, waitReady } from './capture-core.mjs';

const repo = join(here(import.meta.url), '../..');
const PORT = '18091';
const baseURL = `http://127.0.0.1:${PORT}`;
const ADMIN = { username: 'admin', password: 'fleet admin horse battery staple' };
const OWNER = { username: 'owner', password: 'fleet owner horse battery staple' };
const COMMIT = process.env.CAPTURE_SOURCE_COMMIT;
const prefix = process.argv[2] === '--verify' ? process.argv[3] : process.argv[2];
let seeded = false;

// A pinned commit is built from its own tree: git archive, never another worktree.
const source = COMMIT ? join('/tmp', `kynotes-src-${COMMIT}`) : repo;
if (COMMIT && !existsSync(join(source, 'go.mod'))) {
  mkdirSync(source, { recursive: true });
  execFileSync('bash', ['-c', `git -C "${repo}" archive "${COMMIT}" | tar -x -C "${source}"`]);
}
const fact = (record) => { if (prefix) appendFileSync(join(here(import.meta.url), 'screenshots', `${prefix}-facts.jsonl`), JSON.stringify(record) + '\n'); };

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

async function openSettings(page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Settings' }).click();
  await page.getByRole('heading', { name: 'Settings', level: 1 }).waitFor();
}

// A second browser for the same owner; it stays open until the next surface.
let peer;
async function closePeer() { if (peer) { await peer.close(); peer = undefined; } }

await main({
  // Saved as the theme name, as the product writes it.
  crossTab: ['kynotes-theme', 'Sun', 'sun'],
  product: 'kynotes',
  repo,
  dist: join(source, 'internal/web/dist/index.html'),
  serverSource: COMMIT ? { kind: 'git archive', commit: COMMIT, tree: source } : { kind: 'worktree' },
  fixture: 'fresh data dir (web/e2e/server.sh config on port 18091, dev_insecure_cookies on loopback); first-run setup through the UI creating administrator "admin" and everyday "owner"; owner creates notebook "Field notes" with one note typed "Garden plan: order seeds by Friday."; captures are the owner; link-request adds a second browser context signed in as the same owner',
  async start(dir) {
    const binary = join(dir, 'kynotes-server');
    const build = spawnSync('go', ['build', '-o', binary, './cmd/kynotes-server'], { cwd: source, stdio: 'inherit' });
    if (build.status !== 0) throw new Error('go build failed');
    await writeFile(join(dir, 'kynotes.yaml'), `server:\n  bind: "127.0.0.1:${PORT}"\n  dev_insecure_cookies: true\nsecrets:\n  pairing_secret: "12345678901234567890123456789012"\n  server_salt_key: "12345678901234567890123456789012"\ndata_dir: "${dir}"\nratelimit:\n  login_per_minute: 120\n`);
    const proc = spawn(binary, ['--config', join(dir, 'kynotes.yaml')], { cwd: dir, env: { PATH: process.env.PATH, HOME: dir }, stdio: ['ignore', 'ignore', 'inherit'] });
    await waitReady(`${baseURL}/readyz`);
    return { baseURL, binary, pid: proc.pid, stop: async () => { await closePeer(); proc.kill('SIGTERM'); await new Promise((r) => proc.once('exit', r)); } };
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
    // Settings › Link another browser. A second browser for the same owner asks to link if it
    // is offered "Link this browser"; the facts file records whether it was.
    async 'link-request'(page, { device, theme }) {
      await closePeer();
      peer = await page.context().browser().newContext({ baseURL, viewport: page.viewportSize(), colorScheme: theme, deviceScaleFactor: 1 });
      const other = await peer.newPage();
      await other.goto('/');
      await other.getByLabel('Username').fill(OWNER.username);
      await other.getByLabel('Password', { exact: true }).fill(OWNER.password);
      await other.getByRole('button', { name: 'Unlock KyNotes' }).click();
      await other.getByRole('button', { name: 'Settings' }).click();
      await other.getByRole('heading', { name: 'Settings', level: 1 }).waitFor();
      const offer = other.locator('#link-this-browser').getByRole('button', { name: 'Link this browser' });
      const offered = (await offer.count()) > 0;
      if (offered) await offer.click();
      await openSettings(page);
      const card = page.locator('#link-devices');
      if (offered) await card.getByRole('button', { name: 'Not me' }).waitFor({ timeout: 30000 });
      await card.scrollIntoViewIfNeeded();
      fact({ surface: 'link-request', device, theme, secondBrowserOfferedLink: offered, notMeShown: (await card.getByRole('button', { name: 'Not me' }).count()) > 0 });
    },
    // Settings › Reset encryption key, opened: the warning and the disabled Continue. Nothing is typed.
    async 'recovery-reset'(page, { device, theme }) {
      await closePeer();
      await openSettings(page);
      const card = page.locator('#identity-reset');
      await card.getByRole('button', { name: 'Reset encryption key…' }).click();
      await card.getByRole('button', { name: 'Continue' }).waitFor();
      await card.scrollIntoViewIfNeeded();
      fact({ surface: 'recovery-reset', device, theme, continueDisabled: await card.getByRole('button', { name: 'Continue' }).isDisabled() });
    },
    // Settings › Trusted Device with "Forget this device & sign out" (shown, never clicked).
    async 'forget-device'(page, { device, theme }) {
      await closePeer();
      await openSettings(page);
      const button = page.getByRole('button', { name: 'Forget this device & sign out' });
      await button.scrollIntoViewIfNeeded();
      fact({ surface: 'forget-device', device, theme, shown: await button.isVisible() });
    },
    // Settings › Appearance, as in the earlier batches (the in-app --verify uses it).
    async appearance(page, { device }) {
      await closePeer();
      if (device === 'mobile') await page.getByRole('button', { name: 'Notebooks and account' }).click();
      await page.getByRole('button', { name: 'Settings' }).click();
      await page.getByRole('heading', { name: 'Appearance' }).first().waitFor();
    },
    // A live session without the device key: KyNotes asks for the password and offers Sign out
    // (shown, never clicked). On this loopback fixture the browser keeps a trusted device key, so a
    // plain reload auto-unlocks, and the header Lock ends the session (plain unlock form, no Sign
    // out). This state is modelled, not reached by UI: the origin's IndexedDB and local storage are
    // cleared through CDP, cookies kept, then the page reloads. Last: it drops the key.
    async 'locked-session'(page, { device, theme }) {
      await closePeer();
      await page.goto('/');
      await page.getByRole('button', { name: 'Settings' }).waitFor();
      const cdp = await page.context().newCDPSession(page);
      await cdp.send('Storage.clearDataForOrigin', { origin: baseURL, storageTypes: 'indexeddb,local_storage' });
      await page.reload();
      const signOut = page.getByRole('button', { name: 'Sign out' });
      await signOut.waitFor();
      fact({ surface: 'locked-session', device, theme, modelled: 'CDP Storage.clearDataForOrigin indexeddb,local_storage; cookies kept', signOutShown: await signOut.isVisible() });
    },
  },
});
