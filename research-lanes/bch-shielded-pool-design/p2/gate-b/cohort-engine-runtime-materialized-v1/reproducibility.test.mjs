import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { packageDirectory, validateAll } from './semantic-validators.mjs';

const lockPath = path.join(os.tmpdir(), 'shieldkit-labs-materialized-v1-tests.lock');
const withLock = callback => { const cell = new Int32Array(new SharedArrayBuffer(4)); let acquired = false; for (let attempt = 0; attempt < 6000 && !acquired; attempt += 1) { try { fs.mkdirSync(lockPath); acquired = true; } catch { Atomics.wait(cell, 0, 0, 10); } } assert.equal(acquired, true, 'test lock acquisition'); try { return callback(); } finally { fs.rmdirSync(lockPath); } };

test('materialized package is statically reproducible and fail-closed', () => withLock(() => {
  const result = validateAll();
  assert.equal(result.materialization.ok, true);
  assert.equal(result.bundle.ok, true);
  assert.equal(result.image.ok, true);
  assert.equal(JSON.parse(fs.readFileSync(path.join(packageDirectory, 'libauth-bundle-receipt.v1.json'), 'utf8')).reproducibility.outputByteIdentical, true);
  assert.equal(JSON.parse(fs.readFileSync(path.join(packageDirectory, 'libauth-bundle-receipt.v1.json'), 'utf8')).reproducibility.canonicalMetafileByteIdentical, true);
  const output = execFileSync(process.execPath, ['generate.mjs', '--reproduce-check'], { cwd: packageDirectory, encoding: 'utf8' });
  assert.match(output, /"ok":true/);
}));
