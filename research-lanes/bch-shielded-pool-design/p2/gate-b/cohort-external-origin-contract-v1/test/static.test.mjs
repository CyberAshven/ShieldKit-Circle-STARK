import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { rawFileDigest, semanticDigest, validateStatic } from '../validate-static.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-external-origin-contract/v1/';
const kat = JSON.parse(readFileSync(join(ROOT, 'test/digest.kat.json'), 'utf8'));
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

assert.equal(validateStatic({ root: ROOT }), true);
for (const vector of kat.sha256) assert.equal(hash(Buffer.from(vector.bytesHex, 'hex')), vector.value);
for (const vector of kat.rawFile) {
  const bytes = Buffer.from(vector.bytesHex, 'hex');
  assert.equal(rawFileDigest(bytes), vector.value);
  assert.equal(rawFileDigest(bytes), hash(Buffer.concat([Buffer.from(PREFIX + 'file\u0000'), bytes])));
}
assert.equal(semanticDigest(kat.semantic.domain, kat.semantic.body), kat.semantic.value);
assert.equal(semanticDigest(kat.semantic.domain, kat.semantic.body), hash(Buffer.from(kat.semantic.domain + '\u0000{"a":["x"],"b":true}\n')));

const root = JSON.parse(readFileSync(join(ROOT, 'external-origin-contract-root.v1.json'), 'utf8'));
assert.equal(root.staticDependencies.entries.length, 29);
assert.deepEqual(root.externalOriginContracts.entries.map((entry) => entry.id), ['RETRY_PREDECESSOR', 'LIVE_F_CAPTURE', 'WORKER_ROWS_ROOT']);
assert.deepEqual(root.factContracts.entries.map((entry) => entry.id), ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D']);
assert.equal(root.externalOriginContracts.entries.every((entry) => entry.admissionAllowed === false && entry.grantsAuthority === false), true);
assert.equal(root.factContracts.entries.every((entry) => entry.admissionAllowed === false && entry.grantsAuthority === false), true);
assert.equal(root.workloadProjectionContract.targetWorkerRowCount, 5);
assert.equal(root.workloadProjectionContract.workloadTemplate.value, 4608);
assert.deepEqual(root.workloadProjectionContract.kWorkerRowBounds, { maximum: 4096, minimum: 1, unit: 'worker-rows-per-dispatch-plan' });

process.stdout.write('static tests: PASS\n');
