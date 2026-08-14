import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { rawFileDigest, validateStatic } from '../validate-static.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const TEMP = mkdtempSync('/tmp/cohort-external-origin-contract-v1-');
const COPY = join(TEMP, 'cohort-external-origin-contract-v1');
const UPSTREAM_TEMP = mkdtempSync('/tmp/cohort-external-origin-contract-v1-upstream-');
const UPSTREAM_REPOSITORY = join(UPSTREAM_TEMP, 'repository');
const UPSTREAM_GATE = join(UPSTREAM_REPOSITORY, 'research-lanes/bch-shielded-pool-design/p2/gate-b');
const UPSTREAM_COPY = join(UPSTREAM_GATE, 'cohort-external-origin-contract-v1');
const GATE = dirname(ROOT);
const WORKSPACE_NODE_MODULES = join(GATE, '../../../../node_modules');
const AUTHORED = [
  'COMMAND.txt','README.md','external-origin-contract-root.v1.json','validate-static.mjs',
  'schemas/causal-dag.v1.schema.json','schemas/dependency-catalog.v1.schema.json','schemas/ownership-catalog.v1.schema.json',
  'schemas/retry-predecessor-contract.v1.schema.json','schemas/live-f-capture-contract.v1.schema.json','schemas/worker-rows-root-contract.v1.schema.json',
  'schemas/workload-projection-contract.v1.schema.json','schemas/fact-contract-catalog.v1.schema.json','schemas/digest.v1.schema.json',
  'schemas/model-root.v1.schema.json','schemas/manifest.v1.schema.json','test/digest.kat.json','test/static.test.mjs','test/mutation.test.mjs','test/package-boundary.test.mjs',
];
const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-external-origin-contract/v1/';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const COMPONENT_DOMAINS = {
  staticDependencies: 'dependency-catalog',
  cabmAuthorityPrefix: 'cabm-authority-prefix',
  externalCausalDag: 'external-causal-dag',
  ownershipCatalog: 'ownership-catalog',
  externalOriginContracts: 'external-origin-contracts',
  factContracts: 'fact-contracts',
  rootDomainCatalog: 'root-domain-catalog',
  workloadProjectionContract: 'workload-projection-contract',
};
const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
const FRAME = 'utf8(domain)||0x00||canonical-json-utf8-lf-v1';

function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') return String(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

function reset() {
  rmSync(COPY, { force: true, recursive: true });
  if (!existsSync(join(TEMP, 'node_modules'))) symlinkSync(WORKSPACE_NODE_MODULES, join(TEMP, 'node_modules'), 'dir');
  cpSync(ROOT, COPY, { dereference: false, recursive: true });
  rmSync(join(COPY, 'MANIFEST.json'), { force: true });
  rmSync(join(COPY, 'SHA256SUMS'), { force: true });
}

function resetUpstreamFixture() {
  rmSync(UPSTREAM_REPOSITORY, { force: true, recursive: true });
  mkdirSync(UPSTREAM_GATE, { recursive: true });
  symlinkSync(WORKSPACE_NODE_MODULES, join(UPSTREAM_REPOSITORY, 'node_modules'), 'dir');
  cpSync(ROOT, UPSTREAM_COPY, { dereference: false, recursive: true });
  rmSync(join(UPSTREAM_COPY, 'MANIFEST.json'), { force: true });
  rmSync(join(UPSTREAM_COPY, 'SHA256SUMS'), { force: true });
  for (const dependency of ['cohort-runtime-binding-v1', 'cohort-runner-core-v1', 'cohort-frozen-inputs-v1', 'cohort-policy-authority-v1', 'cohort-live-executor-v2', 'cohort-authority-binding-model-v1']) {
    cpSync(join(GATE, dependency), join(UPSTREAM_GATE, dependency), { dereference: false, recursive: true });
  }
}

async function fixtureValidator() {
  return import(pathToFileURL(join(UPSTREAM_COPY, 'validate-static.mjs')).href + '?fixture=' + Math.random());
}

function readRoot(packageRoot = COPY) {
  return JSON.parse(readFileSync(join(packageRoot, 'external-origin-contract-root.v1.json'), 'utf8'));
}

function writeRoot(root, packageRoot = COPY) {
  writeFileSync(join(packageRoot, 'external-origin-contract-root.v1.json'), canonical(root) + '\n');
}

function semanticDigest(domain, body) {
  return hash(Buffer.from(domain + '\u0000' + canonical(body) + '\n', 'utf8'));
}

function descriptor(domain, value) {
  return { algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value };
}

function redigestRoot(root) {
  for (const [key, suffix] of Object.entries(COMPONENT_DOMAINS)) {
    const body = { ...root[key] };
    delete body.contentDigest;
    root[key].contentDigest = descriptor(PREFIX + suffix, semanticDigest(PREFIX + suffix, body));
  }
  const body = { ...root };
  delete body.contentDigest;
  root.contentDigest = descriptor(PREFIX + 'root', semanticDigest(PREFIX + 'root', body));
}

function patchValidatorRootDigest(path, value) {
  const source = readFileSync(path, 'utf8');
  const patched = source.replace(/const ROOT_DIGEST = '[0-9a-f]{64}';/, "const ROOT_DIGEST = '" + value + "';");
  assert.notEqual(patched, source, 'root digest pin must be present in fixture validator');
  writeFileSync(path, patched);
}

async function expectRedigestedSchemaReject(label, mutate) {
  resetUpstreamFixture();
  const root = readRoot(UPSTREAM_COPY);
  mutate(root);
  redigestRoot(root);
  writeRoot(root, UPSTREAM_COPY);
  const validatorPath = join(UPSTREAM_COPY, 'validate-static.mjs');
  patchValidatorRootDigest(validatorPath, root.contentDigest.value);
  assert.throws(() => validateStatic({ root: UPSTREAM_COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /externally pinned validator raw/, label + ' external validator pin');
  const replacement = await import(pathToFileURL(validatorPath).href + '?nested=' + Math.random());
  assert.throws(() => replacement.validateStatic({ root: UPSTREAM_COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /root schema/, label);
}

function expectRootReject(label, mutate) {
  reset();
  const root = readRoot();
  mutate(root);
  writeRoot(root);
  assert.throws(() => validateStatic({ root: COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /static validation/, label);
}

function sealTemp() {
  const entries = AUTHORED.map((locator) => {
    const bytes = readFileSync(join(COPY, locator));
    return { bytes: bytes.length, fileDigest: rawFileDigest(bytes), locator, sha256: hash(bytes) };
  });
  const manifest = {
    entries,
    entryCount: AUTHORED.length,
    format: PREFIX + 'manifest/1',
    package: 'cohort-external-origin-contract-v1',
    rosterDigest: hash(Buffer.from(PREFIX + 'manifest-roster\u0000' + canonical({ package: 'cohort-external-origin-contract-v1', entries }) + '\n')),
    schema: PREFIX + 'manifest/v1',
  };
  writeFileSync(join(COPY, 'MANIFEST.json'), canonical(manifest) + '\n');
  const sums = entries.concat([{ locator: 'MANIFEST.json', sha256: hash(readFileSync(join(COPY, 'MANIFEST.json'))) }]).map((entry) => entry.sha256 + '  ' + entry.locator).join('\n') + '\n';
  writeFileSync(join(COPY, 'SHA256SUMS'), sums);
}

try {
  reset();
  assert.equal(validateStatic({ root: COPY, allowTemporaryMetadata: true, allowUnsealed: true }), true);

  for (let index = 0; index < 29; index += 1) {
    expectRootReject('leaf raw pin ' + index, (root) => { root.staticDependencies.entries[index].rawSha256 = '0'.repeat(64); });
    expectRootReject('leaf role ' + index, (root) => { root.staticDependencies.entries[index].role = 'changed-role'; });
    expectRootReject('leaf locator ' + index, (root) => { root.staticDependencies.entries[index].locator += '-mutated'; });
  }
  expectRootReject('leaf order', (root) => { root.staticDependencies.entries.reverse(); });
  expectRootReject('CABM node', (root) => { root.cabmAuthorityPrefix.nodes.pop(); root.cabmAuthorityPrefix.nodeCount = 16; });
  expectRootReject('CABM node order', (root) => { root.cabmAuthorityPrefix.nodes.reverse(); });
  expectRootReject('CABM count', (root) => { root.cabmAuthorityPrefix.edgeCount = 21; });
  expectRootReject('CABM edge', (root) => { root.cabmAuthorityPrefix.edges.reverse(); });
  expectRootReject('CABM source field', (root) => { root.cabmAuthorityPrefix.sourceField = 'authorityDag'; });
  expectRootReject('CABM source digest', (root) => { root.cabmAuthorityPrefix.sourceSemanticDigest = '0'.repeat(64); });
  expectRootReject('external node', (root) => { root.externalCausalDag.nodes.pop(); root.externalCausalDag.nodeCount = 13; });
  expectRootReject('external node order', (root) => { root.externalCausalDag.nodes.reverse(); });
  expectRootReject('external count', (root) => { root.externalCausalDag.edgeCount = 13; });
  expectRootReject('external edge', (root) => { root.externalCausalDag.edges.pop(); root.externalCausalDag.edgeCount = 13; });
  expectRootReject('static dependency predecessor', (root) => { root.factContracts.entries[0].statePredecessors.initial = ['P']; });
  expectRootReject('owner class swap', (root) => { root.ownershipCatalog.entries[0].ownerClass = 'unavailable-private-capture-owner'; });
  expectRootReject('identity field', (root) => { root.ownershipCatalog.entries[0].identity = 'present'; });
  expectRootReject('capability field', (root) => { root.ownershipCatalog.entries[0].capability = null; });
  expectRootReject('instance field', (root) => { root.ownershipCatalog.entries[0].instance = 'forbidden'; });
  expectRootReject('root value field', (root) => { root.externalOriginContracts.entries[0].ownerBindingRoot = '0'.repeat(64); });
  expectRootReject('authority grant', (root) => { root.factContracts.entries[0].grantsAuthority = true; });
  expectRootReject('J owner', (root) => { root.ownershipCatalog.entries[8].ownerClass = 'inserted-owner'; });
  expectRootReject('J predecessor', (root) => { root.factContracts.entries[5].statePredecessors.initial = ['B']; });
  expectRootReject('J extra semantic field', (root) => { root.factContracts.entries[5].ownerBindingRoot = '0'.repeat(64); });
  expectRootReject('retry origin removal', (root) => { root.factContracts.entries[0].originRequirements.retry = []; });
  expectRootReject('retry unblock', (root) => { root.factContracts.entries[0].modelDispositionByVariant.retry = 'CATALOG_ONLY'; });
  expectRootReject('retry predecessor reuse', (root) => { root.externalOriginContracts.entries[0].futureValidationRules[7] = 'predecessorRoot-may-be-reusable'; });
  expectRootReject('retry ordinal nonincrement', (root) => { root.externalOriginContracts.entries[0].futureValidationRules[4] = 'retryOrdinal-may-equal-predecessorOrdinal'; });
  expectRootReject('retry target mismatch', (root) => { root.externalOriginContracts.entries[0].futureValidationRules[6] = 'targetRoot-is-unbound'; });
  expectRootReject('retry abort substitution', (root) => { root.externalOriginContracts.entries[0].futureValidationRules[8] = 'abort-close-satisfies-RETRY_PREDECESSOR'; });
  expectRootReject('retry automatic', (root) => { root.nonAuthorityBoundary.retryDisposition = 'CATALOG_ONLY'; });
  expectRootReject('live capture collapse', (root) => { root.factContracts.entries[2].originRequirements.initial = []; });
  expectRootReject('live static F substitution', (root) => { root.factContracts.entries[2].staticDependencyIds[0] = 'R'; });
  expectRootReject('live record path rule', (root) => { root.externalOriginContracts.entries[1].futurePreimageKeys[3] = 'records[].absolutePath'; });
  expectRootReject('live record order rule', (root) => { root.externalOriginContracts.entries[1].futureValidationRules[5] = 'records-order-is-unspecified'; });
  expectRootReject('live record nlink rule', (root) => { root.externalOriginContracts.entries[1].futureValidationRules[9] = 'nlink-is-any-positive-integer'; });
  expectRootReject('live stable stat rule', (root) => { root.externalOriginContracts.entries[1].futureValidationRules[14] = 'preStat-and-postStat-may-differ'; });
  expectRootReject('live raw hash rule', (root) => { root.externalOriginContracts.entries[1].futureValidationRules[11] = 'rawSha256-is-optional'; });
  expectRootReject('live post-B capture', (root) => { root.externalOriginContracts.entries[1].futureValidationRules[16] = 'capture-follows-B'; });
  expectRootReject('live capture private bytes', (root) => { root.externalOriginContracts.entries[1].privateBytes = 'forbidden'; });
  expectRootReject('K hash LF insertion', (root) => { root.rootDomainCatalog.entries[3].canonicalization = 'K-canonicalJson-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf'; });
  expectRootReject('K hash domain', (root) => { root.externalOriginContracts.entries[2].digestDomain = 'K/WORKER-ROWS-LF'; });
  expectRootReject('worker row count', (root) => { root.workloadProjectionContract.targetWorkerRowCount = 4096; });
  expectRootReject('endpoint order', (root) => { root.workloadProjectionContract.acceptedWorkerRowEndpointOrder.reverse(); });
  expectRootReject('endpoint duplicate', (root) => { root.workloadProjectionContract.acceptedWorkerRowEndpointOrder[1] = 'native'; });
  expectRootReject('alias engine interchange', (root) => { root.workloadProjectionContract.endpointAliasMap[0].alias = 'engine:native'; });
  expectRootReject('malformed byte authority', (root) => { root.externalOriginContracts.entries[2].futurePreimageKeys[4] = 'workerRows[].byteAuthority.invalid'; });
  expectRootReject('owner in K hash', (root) => { root.rootDomainCatalog.entries[3].futurePreimageKeys.unshift('ownerBindingRoot'); });
  expectRootReject('workload equality', (root) => { root.workloadProjectionContract.workloadTemplate.value = 4096; });
  expectRootReject('workload ratio', (root) => { root.workloadProjectionContract.futureValidationRules[12] = 'cardinality-ratio-is-one'; });
  expectRootReject('workload batching', (root) => { root.workloadProjectionContract.futureValidationRules[13] = 'batching-is-defined'; });
  expectRootReject('workload one-to-one', (root) => { root.workloadProjectionContract.futureValidationRules[14] = 'one-workload-per-worker-row'; });
  expectRootReject('projection material', (root) => { root.workloadProjectionContract.projectionDisposition = 'PRESENT'; });
  expectRootReject('projection bytes', (root) => { root.workloadProjectionContract.projectionBytes = 'forbidden'; });
  expectRootReject('projection encoding', (root) => { root.workloadProjectionContract.projectionEncodingId = 'present'; });
  expectRootReject('D admission', (root) => { root.factContracts.entries[6].admissionAllowed = true; });
  expectRootReject('D unblock', (root) => { root.factContracts.entries[6].modelDispositionByVariant.initial = 'CATALOG_ONLY'; });
  for (const predecessorIndex of [0, 1, 2, 3]) expectRootReject('D prerequisite ' + predecessorIndex, (root) => { root.factContracts.entries[6].statePredecessors.initial.splice(predecessorIndex, 1); });
  expectRootReject('D execution', (root) => { root.executionAllowed = true; });
  expectRootReject('D owner continuity', (root) => { root.factContracts.entries[6].futureValidationRules[3] = 'same-owner-class-proves-owner-continuity'; });
  expectRootReject('descriptor omitted', (root) => { delete root.factContracts.contentDigest; });
  expectRootReject('descriptor moved', (root) => { root.factContracts.movedContentDigest = root.factContracts.contentDigest; delete root.factContracts.contentDigest; });
  expectRootReject('descriptor duplicated', (root) => { root.factContracts.extraContentDigest = root.factContracts.contentDigest; });
  expectRootReject('descriptor domain', (root) => { root.factContracts.contentDigest.domain = PREFIX + 'root'; });
  expectRootReject('descriptor frame', (root) => { root.factContracts.contentDigest.frame = 'wrong-frame'; });

  await expectRedigestedSchemaReject('Q variant future key material', (root) => { root.factContracts.entries[0].futurePreimageKeys.ownerBindingRoot = { value: 'forbidden' }; });
  await expectRedigestedSchemaReject('initial variant future key material', (root) => { root.factContracts.entries[2].futurePreimageKeys.projectionBytes = { value: 'forbidden' }; });
  await expectRedigestedSchemaReject('Q variant disposition extra', (root) => { root.factContracts.entries[0].modelDispositionByVariant.unexpectedDisposition = 'CATALOG_ONLY'; });
  await expectRedigestedSchemaReject('initial variant disposition extra', (root) => { root.factContracts.entries[6].modelDispositionByVariant.unexpectedDisposition = 'CATALOG_ONLY'; });
  await expectRedigestedSchemaReject('workload future key material', (root) => { root.workloadProjectionContract.futurePreimageKeys.projectionBytes = ['forbidden']; });
  await expectRedigestedSchemaReject('leanbch expansion extra', (root) => { root.workloadProjectionContract.leanbchExpansion.unexpectedLabel = 'forbidden'; });
  await expectRedigestedSchemaReject('workload template extra', (root) => { root.workloadProjectionContract.workloadTemplate.unexpectedMeasurement = 1; });
  await expectRedigestedSchemaReject('Q root-domain future key material', (root) => { root.rootDomainCatalog.entries[6].futurePreimageKeys.ownerBindingRoot = { value: 'forbidden' }; });
  await expectRedigestedSchemaReject('array root-domain future key material', (root) => { root.rootDomainCatalog.entries[0].futurePreimageKeys = { ownerBindingRoot: 'forbidden' }; });

  reset();
  writeFileSync(join(COPY, 'validate-static.mjs'), readFileSync(join(COPY, 'validate-static.mjs'), 'utf8') + '\nexport const writer = true;\n');
  assert.throws(() => validateStatic({ root: COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /static validation/);
  reset();
  writeFileSync(join(COPY, 'src.mjs'), 'export const runtime = true;\n');
  assert.throws(() => validateStatic({ root: COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /static validation/);
  reset();
  writeFileSync(join(COPY, 'generator.mjs'), 'export const generator = true;\n');
  assert.throws(() => validateStatic({ root: COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /static validation/);

  reset();
  sealTemp();
  assert.equal(validateStatic({ root: COPY, allowTemporaryMetadata: true }), true);
  const manifest = JSON.parse(readFileSync(join(COPY, 'MANIFEST.json'), 'utf8'));
  manifest.entries[0].fileDigest = hash(Buffer.from(canonical(manifest.entries[0])));
  writeFileSync(join(COPY, 'MANIFEST.json'), canonical(manifest) + '\n');
  assert.throws(() => validateStatic({ root: COPY, allowTemporaryMetadata: true }), /static validation/);

  reset();
  sealTemp();
  const baseline = {
    manifest: hash(readFileSync(join(COPY, 'MANIFEST.json'))),
    root: hash(readFileSync(join(COPY, 'external-origin-contract-root.v1.json'))),
    sums: hash(readFileSync(join(COPY, 'SHA256SUMS'))),
    validator: hash(readFileSync(join(COPY, 'validate-static.mjs'))),
  };
  const mutated = readRoot();
  mutated.factContracts.entries[6].grantsAuthority = true;
  writeRoot(mutated);
  writeFileSync(join(COPY, 'schemas/fact-contract-catalog.v1.schema.json'), readFileSync(join(COPY, 'schemas/fact-contract-catalog.v1.schema.json'), 'utf8').replace('"const":false', '"type":"boolean"'));
  writeFileSync(join(COPY, 'validate-static.mjs'), 'export function validateStatic(){ return true; }\n');
  sealTemp();
  assert.notEqual(hash(readFileSync(join(COPY, 'validate-static.mjs'))), baseline.validator);
  assert.throws(() => validateStatic({ root: COPY, allowTemporaryMetadata: true }), /externally pinned validator raw/);
  const replacement = await import(pathToFileURL(join(COPY, 'validate-static.mjs')).href + '?replacement=1');
  assert.equal(replacement.validateStatic(), true);
  assert.notEqual(hash(readFileSync(join(COPY, 'external-origin-contract-root.v1.json'))), baseline.root);
  assert.notEqual(hash(readFileSync(join(COPY, 'MANIFEST.json'))), baseline.manifest);
  assert.notEqual(hash(readFileSync(join(COPY, 'SHA256SUMS'))), baseline.sums);

  resetUpstreamFixture();
  let fixture = await fixtureValidator();
  assert.equal(fixture.validateStatic({ root: UPSTREAM_COPY, allowTemporaryMetadata: true, allowUnsealed: true }), true);
  const rDirectory = join(UPSTREAM_GATE, 'cohort-runtime-binding-v1');
  const rDirectoryBackup = join(UPSTREAM_TEMP, 'runtime-binding-backup');
  cpSync(rDirectory, rDirectoryBackup, { dereference: false, recursive: true });
  rmSync(rDirectory, { force: true, recursive: true });
  symlinkSync(rDirectoryBackup, rDirectory, 'dir');
  assert.throws(() => fixture.validateStatic({ root: UPSTREAM_COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /upstream symlink component/);

  resetUpstreamFixture();
  fixture = await fixtureValidator();
  const rManifest = join(UPSTREAM_GATE, 'cohort-runtime-binding-v1/MANIFEST.json');
  const rManifestBackup = join(UPSTREAM_TEMP, 'runtime-binding-manifest-copy');
  writeFileSync(rManifestBackup, readFileSync(rManifest));
  rmSync(rManifest, { force: true });
  linkSync(rManifestBackup, rManifest);
  assert.throws(() => fixture.validateStatic({ root: UPSTREAM_COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /upstream leaf type\/containment/);

  resetUpstreamFixture();
  fixture = await fixtureValidator();
  const directStringManifest = JSON.parse(readFileSync(rManifest, 'utf8'));
  directStringManifest.contentDigest = { value: directStringManifest.contentDigest };
  writeFileSync(rManifest, JSON.stringify(directStringManifest) + '\n');
  assert.throws(() => fixture.validateStatic({ root: UPSTREAM_COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /upstream raw pin/);

  resetUpstreamFixture();
  const coordinatedManifestPath = join(UPSTREAM_GATE, 'cohort-runtime-binding-v1/MANIFEST.json');
  const coordinatedManifest = JSON.parse(readFileSync(coordinatedManifestPath, 'utf8'));
  coordinatedManifest.contentDigest = { value: coordinatedManifest.contentDigest };
  writeFileSync(coordinatedManifestPath, canonical(coordinatedManifest) + '\n');
  const coordinatedRoot = JSON.parse(readFileSync(join(UPSTREAM_COPY, 'external-origin-contract-root.v1.json'), 'utf8'));
  const coordinatedLeaf = coordinatedRoot.staticDependencies.entries.find((entry) => entry.dependencyId === 'R' && entry.role === 'manifest');
  assert.ok(coordinatedLeaf, 'R manifest leaf must exist');
  coordinatedLeaf.rawSha256 = hash(readFileSync(coordinatedManifestPath));
  redigestRoot(coordinatedRoot);
  writeFileSync(join(UPSTREAM_COPY, 'external-origin-contract-root.v1.json'), canonical(coordinatedRoot) + '\n');
  const coordinatedValidatorPath = join(UPSTREAM_COPY, 'validate-static.mjs');
  patchValidatorRootDigest(coordinatedValidatorPath, coordinatedRoot.contentDigest.value);
  assert.throws(() => validateStatic({ root: UPSTREAM_COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /externally pinned validator raw/);
  const coordinatedValidator = await import(pathToFileURL(coordinatedValidatorPath).href + '?r-manifest=' + Math.random());
  assert.throws(() => coordinatedValidator.validateStatic({ root: UPSTREAM_COPY, allowTemporaryMetadata: true, allowUnsealed: true }), /R manifest direct contentDigest/);
} finally {
  rmSync(TEMP, { force: true, recursive: true });
  rmSync(UPSTREAM_TEMP, { force: true, recursive: true });
}

assert.equal(existsSync(TEMP), false);
assert.equal(existsSync(UPSTREAM_TEMP), false);
process.stdout.write('mutation tests: PASS\n');
