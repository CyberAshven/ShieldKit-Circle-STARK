import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  ENDPOINT_ORDER,
  EXTERNALS,
  MODULE_WORKERS,
  N_PINNED,
  PACKAGE,
  REPO,
  X_PINNED,
  buildExternalEndpoint,
  buildModuleEndpoint,
  validateEndpointBinding,
  validateEndpointUnion,
  validateDirectoryRoot,
  validatePackage
} from '../semantic-validator.mjs';

const E_ROOT = path.resolve(REPO, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-endpoint-modules-v1');
const X_ROOT = path.resolve(REPO, X_PINNED.packageRoot);

const concreteUnion = () => ({
  expectedRows: 4608,
  order: [...ENDPOINT_ORDER],
  entries: [
    buildModuleEndpoint(E_ROOT, 'engine:native'),
    buildModuleEndpoint(E_ROOT, 'engine:libauth'),
    buildExternalEndpoint(X_ROOT, 'engine:bchn'),
    buildExternalEndpoint(X_ROOT, 'engine:leanbch:primary'),
    buildExternalEndpoint(X_ROOT, 'engine:leanbch:secondary')
  ]
});

test('sealed R validates through the complete static leaf adapters', () => {
  const result = validatePackage();
  assert.equal(result.ok, true);
  assert.equal(result.sealed, true);
  assert.equal(result.leaves, 3);
  assert.equal(result.endpoints, 5);
  assert.equal(result.expectedRows, 4608);
});

test('the exact five-entry union accepts both external entries after the module prefix', () => {
  assert.doesNotThrow(() => validateEndpointUnion({ endpointUnion: concreteUnion() }));
});

test('the reviewed E adapter uses its exact five-schema native roster', () => {
  const binding = validateEndpointBinding();
  assert.equal(binding.leafId, 'E');
  assert.equal(binding.schemaBindings.length, 5);
  assert.equal(binding.nativeManifest.rosterDomain, 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/package-roster');
  assert.equal(binding.nativeManifest.contentDigest, 'e8b04f4e3decc6ee1d7972333e6a30afc28805b97cf038fe0f14de7192b3277a');
});

test('check is read-only when no build-state record exists', () => {
  const names = ['runtime-binding-root.v1.json', 'MANIFEST.json', 'SHA256SUMS'];
  const before = Object.fromEntries(names.map(name => [name, fs.readFileSync(path.join(PACKAGE, name))]));
  const child = spawnSync(process.execPath, ['generate.mjs', '--check'], { cwd: PACKAGE, encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
  assert.match(child.stdout, /"sealed":true/);
  for (const name of names) assert.deepEqual(fs.readFileSync(path.join(PACKAGE, name)), before[name]);
});

test('partial build-state fails closed without mutation', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-binding-state-kat-'));
  try {
    const state = {
      schema: 'shieldkit-labs/p2/gate-b/cohort-runtime-binding/v1/freeze-state',
      files: ['MANIFEST.json', 'SHA256SUMS', 'runtime-binding-root.v1.json'],
      stage: path.join(temp, 'stage'),
      phase: 'validated-stage-pending-publish'
    };
    const statePath = path.join(temp, '.freeze-state.v1.json');
    const stateBytes = Buffer.from(`${JSON.stringify(state, Object.keys(state).sort(), 2)}\n`);
    fs.writeFileSync(statePath, stateBytes, { mode: 0o600 });
    fs.writeFileSync(path.join(temp, 'MANIFEST.json'), Buffer.from('partial\n'));
    assert.throws(() => validatePackage(temp), /incomplete freeze state/);
    assert.deepEqual(fs.readFileSync(statePath), stateBytes);
    assert.equal(fs.readFileSync(path.join(temp, 'MANIFEST.json'), 'utf8'), 'partial\n');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('own and leaf roots require canonical components, real roots, and exact modes', () => {
  const nRoot = path.resolve(REPO, N_PINNED.packageRoot);
  const eRoot = E_ROOT;
  const xRoot = X_ROOT;
  assert.doesNotThrow(() => validateDirectoryRoot(PACKAGE, 0o755, REPO));
  assert.doesNotThrow(() => validateDirectoryRoot(nRoot, 0o755, REPO));
  assert.doesNotThrow(() => validateDirectoryRoot(eRoot, 0o555, REPO));
  assert.doesNotThrow(() => validateDirectoryRoot(xRoot, 0o755, REPO));

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-binding-root-kat-'));
  try {
    const target = path.join(temp, 'target');
    const nested = path.join(target, 'nested');
    const link = path.join(temp, 'link');
    fs.mkdirSync(nested, { recursive: true, mode: 0o755 });
    fs.chmodSync(target, 0o755);
    fs.symlinkSync(target, link);
    assert.throws(() => validateDirectoryRoot(link, 0o755), /real directory root/);
    assert.throws(() => validatePackage(link), /real directory root/);
    fs.chmodSync(target, 0o555);
    assert.throws(() => validateDirectoryRoot(target, 0o755), /directory mode/);
    assert.throws(() => validatePackage(target), /directory mode/);
    fs.chmodSync(target, 0o755);
    fs.symlinkSync(target, path.join(temp, 'component-link'));
    assert.throws(() => validateDirectoryRoot(path.join(temp, 'component-link', 'nested'), 0o755), /root realpath\/symlink/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
