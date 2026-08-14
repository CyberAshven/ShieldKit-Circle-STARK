import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import test from 'node:test';

const here = path.dirname(new URL(import.meta.url).pathname);
const helper = path.join(here, 'renameat2-helper');
const sha = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const mk = prefix => fs.mkdtempSync(path.join(os.tmpdir(), `cohort-commit-${prefix}-`));
const rm = directory => fs.rmSync(directory, { recursive: true, force: true });
const sorted = value => Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).map(key => [key, sorted(value[key])])) : value;
const canonical = value => Buffer.from(`${JSON.stringify(sorted(value), null, 2)}\n`, 'utf8');
const buildEnv = { LC_ALL: 'C', LANG: 'C', TZ: 'UTC', SOURCE_DATE_EPOCH: '0', PATH: '/usr/bin:/bin' };
const copyPackage = () => { const root = fs.mkdtempSync(path.join(path.dirname(here), '.cohort-commit-isolated-')); const copy = path.join(root, 'package'); fs.cpSync(here, copy, { recursive: true, preserveTimestamps: true }); return { root, copy }; };
const checkPackage = copy => execFileSync(process.execPath, ['build.mjs', '--check'], { cwd: copy, stdio: 'pipe', env: buildEnv });
const expectCheckReject = copy => assert.throws(() => checkPackage(copy));
function mutateBytes(name, mutation) {
  const { root, copy } = copyPackage(); const target = path.join(copy, name); const original = fs.readFileSync(target);
  try { fs.writeFileSync(target, mutation(original)); expectCheckReject(copy); } finally { rm(root); }
}
function mutateEntryType(name, createReplacement) {
  const { root, copy } = copyPackage(); const target = path.join(copy, name); fs.rmSync(target, { force: true, recursive: true });
  try { createReplacement(target); expectCheckReject(copy); } finally { rm(root); }
}
const packageSnapshot = () => Object.fromEntries(fs.readdirSync(here).sort().map(name => [name, sha(path.join(here, name))]));
const liveCheck = () => new Promise((resolve, reject) => { const child = spawn(process.execPath, ['build.mjs', '--check'], { cwd: here, env: buildEnv, stdio: ['ignore', 'pipe', 'pipe'] }); let stderr = ''; child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => { stderr += chunk; }); child.on('error', reject); child.on('close', status => status === 0 ? resolve() : reject(new Error(`live check failed ${status}: ${stderr}`))); });

function run(parentOld, parentNew, oldName, newName) {
  const oldFd = fs.openSync(parentOld, 'r');
  const newFd = fs.openSync(parentNew, 'r');
  const retainedPath = fs.existsSync(path.join(parentOld, oldName)) && fs.lstatSync(path.join(parentOld, oldName)).isDirectory() ? path.join(parentOld, oldName) : parentOld;
  const retainedFd = fs.openSync(retainedPath, 'r');
  try {
    const result = spawnSync(helper, [oldName, newName], { stdio: ['ignore', 'pipe', 'pipe', oldFd, newFd, retainedFd] });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.stdout.length, 0, 'helper stdout must be empty');
    assert.equal(result.stderr.length, 0, 'helper stderr must be empty');
    return result.status;
  } finally {
    fs.closeSync(oldFd);
    fs.closeSync(newFd);
    fs.closeSync(retainedFd);
  }
}

function setupSource(parent, name = 'source') {
  const source = path.join(parent, name);
  fs.mkdirSync(source);
  fs.writeFileSync(path.join(source, 'payload'), 'preserve');
  return source;
}

test('absent destination commits atomically and preserves payload', () => {
  const root = mk('absent');
  try {
    const oldParent = path.join(root, 'old'); const newParent = path.join(root, 'new');
    fs.mkdirSync(oldParent); fs.mkdirSync(newParent); setupSource(oldParent);
    assert.equal(run(oldParent, newParent, 'source', 'target'), 0);
    assert.equal(fs.readFileSync(path.join(newParent, 'target', 'payload'), 'utf8'), 'preserve');
    assert.equal(fs.existsSync(path.join(oldParent, 'source')), false);
  } finally { rm(root); }
});

test('source basename replacement against retained fd fails closed', () => {
  const root = mk('source-replacement');
  try {
    const oldParent = path.join(root, 'old'); const newParent = path.join(root, 'new');
    fs.mkdirSync(oldParent); fs.mkdirSync(newParent); setupSource(oldParent);
    const oldFd = fs.openSync(oldParent, 'r'); const newFd = fs.openSync(newParent, 'r'); const retainedFd = fs.openSync(path.join(oldParent, 'source'), 'r');
    fs.renameSync(path.join(oldParent, 'source'), path.join(oldParent, 'retained-original')); fs.mkdirSync(path.join(oldParent, 'source'));
    try {
      const result = spawnSync(helper, ['source', 'target'], { stdio: ['ignore', 'pipe', 'pipe', oldFd, newFd, retainedFd] });
      assert.equal(result.status, 111); assert.equal(result.stdout.length, 0); assert.equal(result.stderr.length, 0);
      assert.equal(fs.existsSync(path.join(oldParent, 'source')), true); assert.equal(fs.existsSync(path.join(newParent, 'target')), false); assert.equal(fs.existsSync(path.join(oldParent, 'retained-original')), true);
    } finally { fs.closeSync(oldFd); fs.closeSync(newFd); fs.closeSync(retainedFd); }
  } finally { rm(root); }
});

for (const [label, makeDestination] of [
  ['empty directory', (parent) => fs.mkdirSync(path.join(parent, 'target'))],
  ['nonempty directory', (parent) => { fs.mkdirSync(path.join(parent, 'target')); fs.writeFileSync(path.join(parent, 'target', 'keep'), 'keep'); }],
  ['regular file', (parent) => fs.writeFileSync(path.join(parent, 'target'), 'keep')],
  ['symlink', (parent) => { fs.mkdirSync(path.join(parent, 'other')); fs.symlinkSync('other', path.join(parent, 'target')); }],
]) test(`existing ${label} is never replaced`, () => {
  const root = mk(`existing-${label.replaceAll(' ', '-')}`);
  try {
    const oldParent = path.join(root, 'old'); const newParent = path.join(root, 'new');
    fs.mkdirSync(oldParent); fs.mkdirSync(newParent); setupSource(oldParent); makeDestination(newParent);
    assert.equal(run(oldParent, newParent, 'source', 'target'), 17);
    assert.equal(fs.existsSync(path.join(oldParent, 'source')), true);
    assert.equal(fs.lstatSync(path.join(newParent, 'target')).isSymbolicLink(), label === 'symlink');
  } finally { rm(root); }
});

test('invalid names return usage/name code without touching source', () => {
  const root = mk('invalid');
  try {
    const oldParent = path.join(root, 'old'); const newParent = path.join(root, 'new');
    fs.mkdirSync(oldParent); fs.mkdirSync(newParent); setupSource(oldParent);
    for (const [oldName, newName] of [['', 'target'], ['.', 'target'], ['..', 'target'], ['source', ''], ['source', '.'], ['source', '..'], ['source', 'a/b']]) {
      assert.equal(run(oldParent, newParent, oldName, newName), 64, `${oldName}/${newName}`);
      assert.equal(fs.existsSync(path.join(oldParent, 'source')), true);
    }
  } finally { rm(root); }
});

test('wrong argc and invalid inherited descriptors fail with other/usage codes', () => {
  const wrong = spawnSync(helper, ['only-one'], { stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(wrong.status, 64); assert.equal(wrong.stdout.length, 0); assert.equal(wrong.stderr.length, 0);
  const badFds = spawnSync(helper, ['source', 'target'], { stdio: ['ignore', 'pipe', 'pipe', 'ignore', 'ignore', 'ignore'] });
  assert.equal(badFds.status, 111); assert.equal(badFds.stdout.length, 0); assert.equal(badFds.stderr.length, 0);
});

test('two racers have exactly one winner and preserve the loser source', async () => {
  const root = mk('race');
  try {
    const oldParent = path.join(root, 'old'); const newParent = path.join(root, 'new');
    fs.mkdirSync(oldParent); fs.mkdirSync(newParent); setupSource(oldParent, 'left'); setupSource(oldParent, 'right');
    const start = (name) => {
      const oldFd = fs.openSync(oldParent, 'r'); const newFd = fs.openSync(newParent, 'r');
      const retainedFd = fs.openSync(path.join(oldParent, name), 'r');
      const child = spawn(helper, [name, 'target'], { stdio: ['ignore', 'pipe', 'pipe', oldFd, newFd, retainedFd] });
      fs.closeSync(oldFd); fs.closeSync(newFd);
      fs.closeSync(retainedFd);
      return once(child, 'close').then(([status, signal]) => { assert.equal(signal, null); assert.equal(child.stdout.read()?.length ?? 0, 0); assert.equal(child.stderr.read()?.length ?? 0, 0); return status; });
    };
    const statuses = await Promise.all([start('left'), start('right')]);
    assert.deepEqual([...statuses].sort((a, b) => a - b), [0, 17]);
    assert.equal(fs.existsSync(path.join(newParent, 'target', 'payload')), true);
    assert.equal(fs.existsSync(path.join(oldParent, 'left')) || fs.existsSync(path.join(oldParent, 'right')), true);
  } finally { rm(root); }
});

test('/dev/shm cross-device commit returns EXDEV without copying when available', { skip: !fs.existsSync('/dev/shm') }, () => {
  const root = mk('cross-device'); const shmRoot = fs.mkdtempSync('/dev/shm/cohort-commit-');
  try {
    if (fs.statSync(root).dev === fs.statSync(shmRoot).dev) return;
    const oldParent = path.join(root, 'old'); const newParent = path.join(shmRoot, 'new');
    fs.mkdirSync(oldParent); fs.mkdirSync(newParent); setupSource(oldParent);
    assert.equal(run(oldParent, newParent, 'source', 'target'), 18);
    assert.equal(fs.existsSync(path.join(oldParent, 'source')), true);
    assert.equal(fs.existsSync(path.join(newParent, 'target')), false);
  } finally { rm(root); rm(shmRoot); }
});

test('binary has no interpreter, dynamic section, or NEEDED library', () => {
  const program = execFileSync('/usr/bin/readelf', ['-l', helper], { encoding: 'utf8' });
  const dynamic = execFileSync('/usr/bin/readelf', ['-d', helper], { encoding: 'utf8' });
  assert.doesNotMatch(program, /^\s*INTERP\s/um); assert.match(dynamic, /no dynamic section/u); assert.doesNotMatch(dynamic, /NEEDED/u);
});

test('tool, command, source, output, digest, and envelope mutations fail closed', () => {
  const receiptMutation = (field, value) => mutateBytes('build-receipt.v1.json', body => { const receipt = JSON.parse(body); if (field === 'assembler') receipt.assembler.rawSha256 = value; else receipt.commands.assemble[1] = value; return canonical(receipt); });
  receiptMutation('assembler', '0'.repeat(64));
  receiptMutation('command', '--32');
  mutateBytes('renameat2-helper.S', body => Buffer.concat([body, Buffer.from('\n')]))
  mutateBytes('renameat2-helper', body => { const copy = Buffer.from(body); copy[copy.length - 1] ^= 1; return copy; });
  mutateBytes('helper-descriptor.v1.json', body => { const descriptor = JSON.parse(body); descriptor.contentDigest.value = `0${descriptor.contentDigest.value.slice(1)}`; return canonical(descriptor); });
  mutateBytes('build-receipt.v1.json', body => { const receipt = JSON.parse(body); receipt.contentDigest.value = `0${receipt.contentDigest.value.slice(1)}`; return canonical(receipt); });
  mutateBytes('MANIFEST.json', body => { const manifest = JSON.parse(body); manifest.contentDigest.value = `0${manifest.contentDigest.value.slice(1)}`; return canonical(manifest); });
  const extra = path.join(here, 'unexpected-extra'); fs.writeFileSync(extra, 'extra'); try { expectCheckReject(); } finally { fs.rmSync(extra, { force: true }); }
  mutateEntryType('README.md', target => fs.symlinkSync('build.mjs', target));
  mutateEntryType('README.md', target => fs.linkSync(path.join(here, 'build.mjs'), target));
  mutateEntryType('README.md', target => fs.mkdirSync(target));
  mutateEntryType('README.md', target => execFileSync('/usr/bin/mkfifo', [target]));
});

test('mutation tests are isolated and concurrent live checks remain byte-stable', async () => {
  const before = packageSnapshot();
  const liveChecks = Array.from({ length: 8 }, () => liveCheck());
  const isolated = copyPackage();
  try {
    const receipt = JSON.parse(fs.readFileSync(path.join(isolated.copy, 'build-receipt.v1.json')));
    receipt.assembler.rawSha256 = `0${receipt.assembler.rawSha256.slice(1)}`;
    fs.writeFileSync(path.join(isolated.copy, 'build-receipt.v1.json'), canonical(receipt));
    expectCheckReject(isolated.copy);
  } finally { rm(isolated.root); }
  await Promise.all(liveChecks);
  assert.deepEqual(packageSnapshot(), before, 'live package bytes changed during isolated mutations/checks');
});

test('rebuilding is byte-identical in an isolated copy and remains checkable', () => {
  const { root, copy } = copyPackage();
  try {
    const before = sha(path.join(copy, 'renameat2-helper'));
    execFileSync(process.execPath, ['build.mjs', '--write'], { cwd: copy, stdio: 'pipe', env: buildEnv });
    assert.equal(sha(path.join(copy, 'renameat2-helper')), before);
    checkPackage(copy);
  } finally { rm(root); }
});
