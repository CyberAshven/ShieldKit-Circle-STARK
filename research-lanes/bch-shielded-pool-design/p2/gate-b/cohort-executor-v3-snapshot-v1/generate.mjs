import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { CANONICALIZATION, FRAME, canonicalBytes, unsafeDigestRecord as digestRecord, omit } from './snapshot-pure.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const workspace = path.resolve(here, '../../../../..');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const rel = file => path.relative(workspace, file).split(path.sep).join('/');
const sourceRoot = path.join(workspace, 'research-lanes/bch-shielded-pool-design/p2/source-set-v1');
const freezeRoot = path.join(workspace, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2');
const packagePrefix = rel(here);
const names = Object.freeze(['COMMAND.txt', 'README.md', 'authority-catalog.v1.schema.json', 'capture.v1.schema.json', 'generate.mjs', 'manifest.v1.schema.json', 'production-api.mjs', 'snapshot-pure.mjs', 'snapshot-open.mjs', 'snapshot.v1.schema.json', 'snapshot-pure.test.mjs', 'authority-catalog.v1.json']);
const read = file => fs.readFileSync(file);
const json = file => JSON.parse(read(file));
const contentBinding = (file, value = json(file)) => ({ path: rel(file), rawSha256: sha(read(file)), byteLength: read(file).length, contentDigest: value.contentDigest ?? null });
const write = (file, body) => fs.writeFileSync(file, Buffer.isBuffer(body) ? body : canonicalBytes(body));
const fail = message => { throw new Error(`cohort-executor-v3-snapshot-v1 generator: ${message}`); };
const assert = (condition, message) => { if (!condition) fail(message); };
const HEX64 = /^[0-9a-f]{64}$/u;
const schemaNames = Object.freeze(['authority-catalog.v1.schema.json', 'capture.v1.schema.json', 'manifest.v1.schema.json', 'snapshot.v1.schema.json']);
const EXPECTED_FILE_MODE = 0o644;
const EXPECTED_DIRECTORY_MODE = 0o755;
const PINNED_CATALOG_RAW_SHA256 = '0e60c0c215e2231a27c2677bf57930e6afd0f111b60313f07935ca7b15e0975f';
const PINNED_CATALOG_BYTE_LENGTH = 63967;

function exactDigest(digest, label, domain = null) {
  assert(digest && digest.algorithm === 'sha256' && digest.canonicalization === CANONICALIZATION && digest.frame === FRAME && typeof digest.domain === 'string' && digest.domain.length > 0 && HEX64.test(digest.value), `${label} digest metadata`);
  if (domain !== null) assert(digest.domain === domain, `${label} digest domain`);
  return digest;
}

function strictSchemas() {
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  return Object.fromEntries(schemaNames.map(name => [name, ajv.compile(json(path.join(here, name)))]));
}

function validateSchema(validate, value, label) {
  assert(validate(value), `${label} schema: ${JSON.stringify(validate.errors)}`);
}

function safePackagePath(value, label) {
  assert(typeof value === 'string' && value.length > 0 && !path.isAbsolute(value) && !value.includes('\\'), `${label} unsafe path`);
  const components = value.split('/'); assert(components.every(component => component.length > 0 && component !== '.' && component !== '..'), `${label} unsafe path components`);
  const resolved = path.resolve(workspace, value); const relative = path.relative(here, resolved);
  assert(relative && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative), `${label} escapes package`);
  return { resolved, relative: relative.split(path.sep).join('/') };
}

function assertRegularSingleLink(file, label) {
  const stat = fs.lstatSync(file); assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1, `${label} regular single-link file`); assert((stat.mode & 0o7777) === EXPECTED_FILE_MODE, `${label} exact file mode`); return stat;
}

function walkPackage() {
  const files = []; const directories = [];
  const visit = (directory, relative) => {
    const directoryStat = fs.lstatSync(directory); assert(directoryStat.isDirectory() && !directoryStat.isSymbolicLink() && (directoryStat.mode & 0o7777) === EXPECTED_DIRECTORY_MODE, `${relative || '.'} exact directory mode`);
    directories.push(relative);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)))) {
      const file = path.join(directory, entry.name); const child = relative ? `${relative}/${entry.name}` : entry.name; const stat = fs.lstatSync(file);
      assert(!stat.isSymbolicLink(), `${child} symlink`);
      if (stat.isDirectory()) visit(file, child);
      else { assertRegularSingleLink(file, `${child}`); files.push(child); }
    }
  };
  visit(here, '');
  return { files: files.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))), directories: directories.filter(Boolean).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))) };
}

function expectedDirectories(files) {
  const output = new Set();
  for (const relative of files) {
    const parts = relative.split('/');
    for (let index = 1; index < parts.length; index += 1) output.add(parts.slice(0, index).join('/'));
  }
  return [...output].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

function verifyCatalogDigests(catalog) {
  exactDigest(catalog.contentDigest, 'catalog content', 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog/root');
  for (const [index, binding] of [...catalog.frozen, ...catalog.source].entries()) if (binding.contentDigest !== null) exactDigest(binding.contentDigest, `catalog binding ${index}`);
  for (const [index, plan] of catalog.plans.entries()) exactDigest(plan.map.contentDigest, `catalog plan map ${index}`);
  exactDigest(catalog.corpusContentDigest, 'catalog corpus'); exactDigest(catalog.fixtureRosterContentDigest, 'catalog fixture roster'); exactDigest(catalog.workItemRosterContentDigest, 'catalog work roster');
  assert(catalog.contentDigest.value === digestRecord(omit(catalog), catalog.contentDigest.domain).value, 'catalog content digest value');
}

export function buildAuthorityCatalog() {
  const fixtureRoster = json(path.join(freezeRoot, 'fixture-roster.v2.json'));
  const workItemRoster = json(path.join(freezeRoot, 'work-item-roster.v2.json'));
  const corpus = json(path.join(freezeRoot, 'canonical-corpus.v2.json'));
  const sourceSet = json(path.join(sourceRoot, 'source-set.v1.json'));
  const frozen = ['execution-epoch.v2.json', 'campaign.v2.json', 'canonical-corpus.v2.json', 'fixture-roster.v2.json', 'work-item-roster.v2.json'].map(name => contentBinding(path.join(freezeRoot, name)));
  const source = [contentBinding(path.join(sourceRoot, 'source-set.v1.json'))];
  const plans = sourceSet.planIndex.map(plan => {
    const hexFile = path.join(sourceRoot, plan.hexPath); const mapFile = path.join(sourceRoot, plan.mapPath); const map = json(mapFile);
    return { planId: plan.planId, orderIndex: plan.orderIndex, hex: { path: rel(hexFile), rawSha256: sha(read(hexFile)), byteLength: read(hexFile).length, bytecodeSha256: plan.bytecodeSha256, bytecodeBytes: plan.bytecodeBytes }, map: { path: rel(mapFile), rawSha256: sha(read(mapFile)), byteLength: read(mapFile).length, contentDigest: map.contentDigest }, expectedOperandCount: Number(map.instructions[0].irTypedContract.transientStackContract.typedTransientItems[1].value) };
  });
  const catalog = { schema: 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog/v1', status: 'retained-byte-input-catalog', executionAllowed: false, metricsAllowed: false, counts: { fixtures: fixtureRoster.records.length, corpusCases: corpus.counts.total, workItems: workItemRoster.workItems.length, sourcePlans: sourceSet.planIndex.length, preflightFixtures: fixtureRoster.counts.preflightLimitViolations, eligiblePerEngine: 4608 }, frozen, source, plans, corpusContentDigest: corpus.contentDigest, fixtureRosterContentDigest: fixtureRoster.contentDigest, workItemRosterContentDigest: workItemRoster.contentDigest };
  catalog.contentDigest = digestRecord(omit(catalog), 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog/root');
  return catalog;
}

export function buildManifest() {
  const files = names.map(name => { const file = path.join(here, name); const body = read(file); return { path: rel(file), rawSha256: sha(body), byteLength: body.length }; }).sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  const manifest = { schema: 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/manifest/v1', status: 'reproducible-local-build', files, coverage: { listedPayloadCount: files.length, selfManifestExcluded: true, checksumsExcluded: true } };
  manifest.contentDigest = digestRecord(omit(manifest), 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/package-manifest/root'); return manifest;
}
export function writeStaticPackage() {
  write(path.join(here, 'authority-catalog.v1.json'), buildAuthorityCatalog());
  const manifest = buildManifest(); write(path.join(here, 'MANIFEST.json'), manifest);
  const rows = [[sha(read(path.join(here, 'MANIFEST.json'))), rel(path.join(here, 'MANIFEST.json'))], ...manifest.files.map(file => [file.rawSha256, file.path])];
  fs.writeFileSync(path.join(here, 'SHA256SUMS'), Buffer.from(`${rows.map(row => row.join('  ')).join('\n')}\n`, 'utf8'));
  return { catalogDigest: buildAuthorityCatalog().contentDigest.value, manifestDigest: manifest.contentDigest.value };
}
export function checkStaticPackage() {
  const validators = strictSchemas();
  const catalogPath = path.join(here, 'authority-catalog.v1.json'); const manifestPath = path.join(here, 'MANIFEST.json'); const sumsPath = path.join(here, 'SHA256SUMS');
  assertRegularSingleLink(catalogPath, 'authority catalog'); assertRegularSingleLink(manifestPath, 'manifest'); assertRegularSingleLink(sumsPath, 'SHA256SUMS');
  const catalogBytes = read(catalogPath); assert(catalogBytes.length === PINNED_CATALOG_BYTE_LENGTH && sha(catalogBytes) === PINNED_CATALOG_RAW_SHA256, 'authority catalog pinned raw bytes'); const catalog = JSON.parse(catalogBytes); validateSchema(validators['authority-catalog.v1.schema.json'], catalog, 'authority catalog'); verifyCatalogDigests(catalog);
  assert(catalogBytes.equals(canonicalBytes(buildAuthorityCatalog())), 'authority catalog regeneration mismatch');
  const manifestBytes = read(manifestPath); const manifest = JSON.parse(manifestBytes); validateSchema(validators['manifest.v1.schema.json'], manifest, 'manifest');
  exactDigest(manifest.contentDigest, 'manifest content', 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/package-manifest/root'); assert(manifest.contentDigest.value === digestRecord(omit(manifest), manifest.contentDigest.domain).value, 'manifest content digest value');
  assert(manifestBytes.equals(canonicalBytes(buildManifest())), 'manifest regeneration mismatch');
  assert(Array.isArray(manifest.files) && manifest.files.length === names.length, 'manifest payload closure count');
  const manifestRelative = []; const manifestItems = new Set();
  for (const item of manifest.files) {
    const safe = safePackagePath(item.path, `manifest ${item.path}`); assert(safe.resolved.startsWith(`${here}${path.sep}`), `manifest package boundary ${item.path}`); assert(!manifestItems.has(safe.relative), `manifest duplicate ${item.path}`); manifestItems.add(safe.relative); manifestRelative.push(safe.relative);
    const stat = assertRegularSingleLink(safe.resolved, `manifest ${item.path}`); const body = read(safe.resolved); assert(stat.size === item.byteLength && body.length === item.byteLength && sha(body) === item.rawSha256, `manifest bytes ${item.path}`);
  }
  const expectedPayloadRelative = names.slice().sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  assert(JSON.stringify(manifestRelative) === JSON.stringify(expectedPayloadRelative), 'manifest payload file closure');
  const tree = walkPackage(); const expectedFiles = [...expectedPayloadRelative.map(name => name), 'MANIFEST.json', 'SHA256SUMS'].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  assert(JSON.stringify(tree.files) === JSON.stringify(expectedFiles), 'package file closure'); assert(JSON.stringify(tree.directories) === JSON.stringify(expectedDirectories(expectedFiles)), 'package directory closure');
  const sumRows = [[sha(manifestBytes), rel(manifestPath)], ...manifest.files.map(item => [item.rawSha256, item.path])]; const expectedSums = `${sumRows.map(row => row.join('  ')).join('\n')}\n`; assert(read(sumsPath).equals(Buffer.from(expectedSums, 'utf8')), 'SHA256SUMS closure');
  return { status: 'PASS', packageFiles: manifest.files.length, catalogDigest: catalog.contentDigest.value, manifestDigest: manifest.contentDigest.value, checksums: sumRows.length };
}
if (import.meta.url === `file://${process.argv[1]}`) { if (process.argv[2] === '--write-static') console.log(JSON.stringify(writeStaticPackage())); else if (process.argv[2] === '--check') console.log(JSON.stringify(checkStaticPackage())); else throw new Error('use --write-static or --check'); }
