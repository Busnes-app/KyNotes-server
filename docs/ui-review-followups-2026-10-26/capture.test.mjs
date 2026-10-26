import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import test from 'node:test';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'kynotes-capture-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repo = join(root, 'repo');
  const docs = join(repo, 'docs/ui-review-followups-2026-10-26');
  const bin = join(root, 'bin');
  const runner = join(root, 'runner');
  for (const directory of [docs, bin, runner]) mkdirSync(directory, { recursive: true });
  const goMod = 'module example.test/capture\n';
  writeFileSync(join(repo, 'go.mod'), goMod);
  writeFileSync(join(repo, 'fixture.txt'), root);
  const git = (...args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
  git('init', '--quiet');
  git('add', 'go.mod', 'fixture.txt');
  git('-c', 'user.name=Capture test', '-c', 'user.email=capture@example.test', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'fixture');
  const commit = git('rev-parse', 'HEAD');
  // Exercise the actual adapter while replacing only its browser/server harness and Go compiler.
  writeFileSync(join(docs, 'capture.mjs'), readFileSync(new URL('./capture.mjs', import.meta.url)));
  writeFileSync(join(docs, 'capture-core.mjs'), `
    import { dirname } from 'node:path';
    import { fileURLToPath } from 'node:url';
    export const here = (url) => dirname(fileURLToPath(url));
    export const waitReady = async () => {};
    export const main = async (adapter) => adapter.start(process.env.CAPTURE_RUN_DIR);
  `);
  const log = join(root, 'build.json');
  writeFileSync(join(bin, 'go'), `#!/usr/bin/env node
    const fs = require('node:fs'), path = require('node:path');
    fs.writeFileSync(process.env.CAPTURE_BUILD_LOG, JSON.stringify({
      cwd: process.cwd(), goMod: fs.readFileSync('go.mod', 'utf8'),
      fixture: fs.readFileSync('fixture.txt', 'utf8'),
      parentMode: fs.statSync(path.dirname(process.cwd())).mode & 0o777
    }));
    process.exit(23);
  `, { mode: 0o700 });
  const run = (sourceCommit = commit) => spawnSync(process.execPath, [join(docs, 'capture.mjs'), 'test'], {
    cwd: repo, encoding: 'utf8', env: {
      ...process.env, PATH: [bin, dirname(process.execPath), process.env.PATH].join(delimiter),
      CAPTURE_SOURCE_COMMIT: sourceCommit, CAPTURE_BUILD_LOG: log, CAPTURE_RUN_DIR: runner,
    },
  });
  return { root, repo, commit, goMod, log, run };
}

test('ignores a planted commit-named directory and removes its fresh private source after failure', (t) => {
  const f = fixture(t);
  const planted = join(tmpdir(), `kynotes-src-${f.commit}`);
  // The committed fixture embeds its unique random root, so it cannot collide with another run.
  mkdirSync(planted, { mode: 0o700 });
  t.after(() => rmSync(planted, { recursive: true, force: true }));
  // Exclusive owner-only files keep the intentionally predictable fixture isolated.
  writeFileSync(join(planted, 'go.mod'), 'module attacker.test/planted\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(planted, 'fixture.txt'), 'planted source', { flag: 'wx', mode: 0o600 });
  assert.equal(statSync(join(planted, 'go.mod')).mode & 0o777, 0o600);
  assert.equal(statSync(join(planted, 'fixture.txt')).mode & 0o777, 0o600);
  const first = f.run();
  assert.notEqual(first.status, 0);
  assert.match(first.stderr, /go build failed/);
  const build = JSON.parse(readFileSync(f.log, 'utf8'));
  assert.notEqual(build.cwd, planted, 'must not build attacker-controlled cached sources');
  assert.equal(build.goMod, f.goMod);
  assert.equal(build.fixture, f.root);
  assert.equal(build.parentMode, 0o700);
  assert.equal(existsSync(build.cwd), false, 'remove archived sources when a build fails');
  assert.equal(existsSync(dirname(build.cwd)), false, 'remove the private source owner directory');
  assert.equal(readFileSync(join(planted, 'fixture.txt'), 'utf8'), 'planted source');
  f.run();
  assert.notEqual(JSON.parse(readFileSync(f.log, 'utf8')).cwd, build.cwd, 'each run gets a new directory');
});

test('rejects option-like or non-hex source revisions before building', (t) => {
  const f = fixture(t);
  const result = f.run(`--output=${join(f.root, 'unexpected.tar')}`);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /CAPTURE_SOURCE_COMMIT/);
  assert.equal(existsSync(f.log), false);
  assert.equal(existsSync(join(f.root, 'unexpected.tar')), false);
});

test('the current-worktree capture path never removes the repository', (t) => {
  const f = fixture(t);
  const result = f.run('');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /go build failed/);
  assert.equal(JSON.parse(readFileSync(f.log, 'utf8')).cwd, f.repo);
  assert.equal(readFileSync(join(f.repo, 'go.mod'), 'utf8'), f.goMod);
});
