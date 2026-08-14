import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import test from 'node:test';
import { domainDigest } from './model.mjs';
import * as model from './model.mjs';
import * as snapshotBoundary from './snapshot-boundary.mjs';
import * as observationBoundary from './observation-boundary.mjs';
import * as stateMachine from './state-machine.mjs';

const ROOT = new URL('./', import.meta.url);
const CONTENT_ROSTER = [
  'README.md', 'COMMAND.txt', 'manifest.v1.schema.json', 'generate.mjs',
  'live-policy-authorization.v1.schema.json', 'snapshot-binding.v1.schema.json', 'live-claim.v1.schema.json',
  'attempt-join.v1.schema.json', 'journal-entry.v1.schema.json', 'journal-index.v1.schema.json',
  'observation-receipt.v1.schema.json', 'terminal-publication.v1.schema.json',
  'model.mjs', 'snapshot-boundary.mjs', 'observation-boundary.mjs', 'state-machine.mjs',
  'model.test.mjs', 'snapshot-boundary.test.mjs', 'observation-boundary.test.mjs', 'state-machine.test.mjs', 'package-boundary.test.mjs',
];
const ROSTER = ['MANIFEST.json', 'SHA256SUMS', ...CONTENT_ROSTER].sort();
const SCHEMAS = ROSTER.filter((name) => name.endsWith('.schema.json'));
const PURE_MODULES = ['model.mjs', 'snapshot-boundary.mjs', 'observation-boundary.mjs', 'state-machine.mjs'];
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const clone = (value) => JSON.parse(JSON.stringify(value));

async function actualRecord(path) {
  const [metadata, bytes] = await Promise.all([lstat(new URL(path, ROOT)), readFile(new URL(path, ROOT))]);
  const mode = (metadata.mode & 0o7777).toString(8).padStart(4, '0');
  assert.equal(metadata.isFile(), true, `${path} must be regular`);
  assert.equal(metadata.isSymbolicLink(), false, `${path} cannot be a link`);
  assert.equal(metadata.nlink, 1, `${path} must have one link`);
  assert.equal(mode, '0644', `${path} must be exact 0644`);
  const core = { path, sha256: sha256(bytes), byteLength: bytes.byteLength, mode, nlink: metadata.nlink, kind: 'regular' };
  return { ...core, contentDigest: domainDigest('manifest-file-content', core) };
}

async function assertExactManifest(manifest) {
  assert.deepEqual(Object.keys(manifest).sort(), ['contentDigest', 'executionAllowed', 'files', 'package', 'schemaVersion', 'staticOnly']);
  assert.equal(manifest.schemaVersion, 'live-executor-static-manifest-v1');
  assert.equal(manifest.package, 'cohort-live-executor-v1');
  assert.equal(manifest.staticOnly, true);
  assert.equal(manifest.executionAllowed, false);
  assert.deepEqual(manifest.files.map((record) => record.path), CONTENT_ROSTER);
  for (const [index, record] of manifest.files.entries()) {
    assert.deepEqual(Object.keys(record).sort(), ['byteLength', 'contentDigest', 'kind', 'mode', 'nlink', 'path', 'sha256']);
    assert.equal(record.mode, '0644');
    assert.equal(record.nlink, 1);
    assert.equal(record.kind, 'regular');
    assert.deepEqual(record, await actualRecord(CONTENT_ROSTER[index]));
  }
  const { contentDigest, ...core } = manifest;
  assert.equal(contentDigest, domainDigest('manifest-content', core));
}

function assertExactSums(sums, manifest, fileRecords) {
  const rows = sums.trimEnd().split('\n');
  const expected = [`${sha256(Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8'))}  MANIFEST.json`, ...fileRecords.map((record) => `${record.sha256}  ${record.path}`)];
  assert.deepEqual(rows, expected);
}

test('package has the exact static roster and pure imports expose no executor surface', async () => {
  const actual = (await readdir(ROOT)).sort();
  assert.deepEqual(actual, ROSTER);
  for (const namespace of [model, snapshotBoundary, observationBoundary, stateMachine]) assert.ok(Object.keys(namespace).length > 0);
  assert.equal('mintLiveObservation' in observationBoundary, false);
  assert.equal('writeClaim' in snapshotBoundary, false);
  assert.equal('publishTerminal' in model, false);
  assert.equal('acceptObservation' in observationBoundary, false);
  assert.equal('assertAcceptedObservation' in observationBoundary, false);
  assert.equal('assertFutureObservationContract' in model, false);
  assert.equal('projectDescriptorHistory' in snapshotBoundary, false);
  assert.equal('SUCCESS_TERMINAL' in stateMachine, false);
  assert.equal(['SUCCESS', 'COMMIT_NOREPLACE'].join('_') in stateMachine, false);
  assert.equal(Object.values(stateMachine).includes(['SUCCESS', 'COMMITTED_NOREPLACE'].join('_')), false);
});

test('all supplied schemas are strict containers with no extra root properties', async () => {
  for (const schemaFile of SCHEMAS) {
    const schema = JSON.parse(await readFile(new URL(schemaFile, ROOT), 'utf8'));
    assert.equal(schema.type, 'object', `${schemaFile} root type`);
    assert.equal(schema.additionalProperties, false, `${schemaFile} root strictness`);
    assert.ok(Array.isArray(schema.required) && schema.required.length > 0, `${schemaFile} required fields`);
  }
});

test('manifest has exact 21-file ordered closure, domain-separated records, regular 0644 modes, and exact SHA256SUMS', async () => {
  const manifest = JSON.parse(await readFile(new URL('MANIFEST.json', ROOT), 'utf8'));
  await assertExactManifest(manifest);
  const sums = await readFile(new URL('SHA256SUMS', ROOT), 'utf8');
  assertExactSums(sums, manifest, manifest.files);
  const extra = clone(manifest);
  extra.files.push(clone(extra.files[0]));
  await assert.rejects(() => assertExactManifest(extra));
  const reordered = clone(manifest);
  [reordered.files[0], reordered.files[1]] = [reordered.files[1], reordered.files[0]];
  await assert.rejects(() => assertExactManifest(reordered));
  const pathMutant = clone(manifest);
  pathMutant.files[0].path = 'other.md';
  await assert.rejects(() => assertExactManifest(pathMutant));
  const modeMutant = clone(manifest);
  modeMutant.files[0].mode = '0755';
  await assert.rejects(() => assertExactManifest(modeMutant));
  const contentMutant = clone(manifest);
  contentMutant.files[0].sha256 = 'a'.repeat(64);
  const { contentDigest, ...contentCore } = contentMutant.files[0];
  contentMutant.files[0].contentDigest = domainDigest('manifest-file-content', contentCore);
  await assert.rejects(() => assertExactManifest(contentMutant));
  const badSums = sums.replace('  MANIFEST.json', '  extra.json');
  assert.throws(() => assertExactSums(badSums, manifest, manifest.files));
});

test('pure import closure excludes process, VM, child-process, dynamic import, and filesystem writers', async () => {
  const forbidden = /child_process|\bimport\s*\(|\bprocess\b|node:vm|\b(?:writeFile|appendFile|mkdir|rename|unlink|rm)\b|node:fs/;
  for (const sourceFile of PURE_MODULES) {
    const source = await readFile(new URL(sourceFile, ROOT), 'utf8');
    assert.equal(forbidden.test(source), false, `${sourceFile} contains a forbidden operational surface`);
  }
  const generator = await readFile(new URL('generate.mjs', ROOT), 'utf8');
  assert.match(generator, /mode === '--write'/);
  assert.match(generator, /mode !== '--check' && mode !== '--write'/);
});
