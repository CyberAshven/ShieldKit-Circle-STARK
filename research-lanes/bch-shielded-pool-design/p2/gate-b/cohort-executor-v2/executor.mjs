#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import Ajv from 'ajv/dist/2020.js';
import { fileURLToPath } from 'node:url';
import { loadFrozenEpochArtifacts, verifyFrozenFixtureAuthority } from '../cohort-execution-v2/engine-adapters.mjs';
import { deriveExecutionFixture, loadSourceSetPlan, parseLowercaseEvenHex } from '../cohort-freeze-v2/execution-fixture.mjs';
import { buildArtifactPairs, materializeAttempt } from './materializer.mjs';
import { canonicalize, digestRecord, ENGINE_ORDER, validateEvidencePackage } from './validator.mjs';
import { assertDefaultRunnerOrder, defaultRunners } from './engine-runners.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const workspace = path.resolve(here, '../../../../..');
const contractDir = path.resolve(here, '../cohort-execution-v2');
const freezeDir = path.resolve(here, '../cohort-freeze-v2');
const authFile = path.join(here, 'authorization.v2.json');
const AUTH_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-executor-v2/authorization/v2/root';
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const sha = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const rawSha = (file) => sha(fs.readFileSync(file));
const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const rel = (file) => path.relative(workspace, file).split(path.sep).join('/');
const bytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const writeJson = (file, value) => fs.writeFileSync(file, bytes(value));
const value = (record) => record?.value ?? record;
const contractFile = path.join(contractDir, 'execution-contract.v2.json');
const outputBase = path.join(here, 'runs');
const binding = (file, contentDigest = null) => ({ path: rel(file), rawSha256: rawSha(file), contentDigest: contentDigest ?? rawSha(file), byteLength: fs.statSync(file).size });
const source = (relative) => path.resolve(workspace, relative);
const requireContainedFile = (root, file) => { const realRoot = fs.realpathSync(root); const realFile = fs.realpathSync(file); assert(realFile.startsWith(`${realRoot}${path.sep}`) || realFile === realRoot, `source path escapes pinned root: ${file}`); assert(!fs.lstatSync(file).isSymbolicLink(), `symlink source is forbidden: ${file}`); return realFile; };
const regularBinding = (file) => { const real = fs.realpathSync(file); assert(fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink(), `regular nonsymlink file required: ${file}`); return { realpath: real, rawSha256: rawSha(real), byteLength: fs.statSync(real).size }; };
const dependencyTree = (root) => {
  const realRoot = fs.realpathSync(root); assert(fs.lstatSync(root).isDirectory() && !fs.lstatSync(root).isSymbolicLink(), `runtime tree root must be a real directory: ${root}`);
  const files = []; const walk = (dir) => { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { const child = path.join(dir, entry.name); assert(!entry.isSymbolicLink(), `runtime tree symlink forbidden: ${child}`); if (entry.isDirectory()) walk(child); else if (entry.isFile()) files.push(regularBinding(child)); else throw new Error(`runtime tree nonregular input: ${child}`); } }; walk(realRoot);
  files.sort((a, b) => a.realpath.localeCompare(b.realpath)); const payload = { root: realRoot, files }; return { ...payload, treeDigest: digestRecord(payload, `shieldkit-labs/p2/gate-b/cohort-executor-v2/runtime-tree/${rel(realRoot)}`) };
};
const localLeanClosure = (record) => {
  const root = record.repositoryAuthority.find((x) => x.realpath.includes('/LeanBCH'))?.realpath; assert(root, 'LeanBCH authority root unavailable');
  const queue = [...record.sourceInputs, ...record.build.inputs, ...record.adapterInputs].map((x) => x.realpath).filter((file) => file.startsWith(`${root}${path.sep}`));
  queue.push(path.join(root, 'LeanBCH/Crypto/Native.lean'), path.join(root, 'ffi/secp256k1_shim.c'));
  const seen = new Set();
  while (queue.length) { const file = path.resolve(queue.pop()); if (seen.has(file)) continue; if (!fs.existsSync(file)) throw new Error(`Lean transitive source input missing: ${file}`); const real = fs.realpathSync(file); assert(real === file && real.startsWith(`${root}${path.sep}`), `Lean source path escapes authority: ${file}`); seen.add(real); if (!real.endsWith('.lean')) continue; const text = fs.readFileSync(real, 'utf8'); for (const match of text.matchAll(/^\s*import\s+([A-Za-z0-9_.]+)/gm)) { const candidate = path.join(root, `${match[1].replaceAll('.', '/')}.lean`); if (fs.existsSync(candidate)) queue.push(candidate); } }
  const files = [...seen].sort().map(regularBinding); const payload = { root, files }; return { ...payload, closureDigest: digestRecord(payload, 'shieldkit-labs/p2/gate-b/cohort-executor-v2/leanbch-reachable-source-closure/v1') };
};

const freezePaths = Object.freeze({ epoch: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/execution-epoch.v2.json', fixture: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/fixture-roster.v2.json', work: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/work-item-roster.v2.json', corpus: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.json', sourceSet: 'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.json' });
const contractSchemas = ['execution-root.v2.schema.json', 'evidence-root.v2.schema.json', 'evidence-manifest.v2.schema.json', 'raw-engine-observation.v2.schema.json', 'normalized-engine-result.v2.schema.json', 'cross-engine-summary.v2.schema.json', 'manifest.v1.schema.json'].map((name) => `research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2/contract/${name}`);
const engineRecordPath = (id) => `research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engines/${id.slice(7)}.v2.json`;
const engineSchemaPath = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engine.v2.schema.json';

const moduleGraph = (entryFiles) => {
  const seen = new Set(); const queue = [...entryFiles];
  while (queue.length) {
    const file = path.resolve(queue.pop()); if (seen.has(file)) continue;
    const real = requireContainedFile(workspace, file); seen.add(real);
    const text = fs.readFileSync(real, 'utf8');
    for (const match of text.matchAll(/^\s*(?:import|export)\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/gm)) {
      const specifier = match[1]; if (!specifier.startsWith('.')) continue;
      const candidate = path.resolve(path.dirname(real), specifier);
      const options = [candidate, `${candidate}.mjs`, `${candidate}.js`, path.join(candidate, 'index.mjs'), path.join(candidate, 'index.js')];
      const resolved = options.find((x) => fs.existsSync(x) && fs.statSync(x).isFile()); assert(resolved, `unresolved transitive implementation import: ${specifier} from ${real}`); queue.push(resolved);
    }
  }
  return [...seen].sort().map((file) => binding(file));
};
const runtime = () => { const executable = fs.realpathSync(process.execPath); assert(fs.lstatSync(executable).isFile() && !fs.lstatSync(executable).isSymbolicLink(), 'Node executable must be a regular realpath'); const shape = { nodeExecutable: executable, nodeExecutableRawSha256: rawSha(executable), nodeExecutableByteLength: fs.statSync(executable).size, nodeVersion: process.version, platform: process.platform, arch: process.arch }; return { ...shape, runtimeDigest: sha(bytes(canonicalize(shape))) }; };
const enginePin = (id, artifacts) => {
  const record = artifacts.engines[id]; const recordFile = source(engineRecordPath(id)); const repoRoots = record.repositoryAuthority.map((x) => x.realpath);
  const pinFile = (entry) => { const real = fs.realpathSync(entry.file.realpath); assert(real === entry.file.realpath && repoRoots.some((root) => real.startsWith(`${root}/`)), `engine entrypoint root/realpath drift: ${id}`); return regularBinding(real); };
  const primary = pinFile(record.entrypoint); const secondaryEntry = record.secondaryEntrypoints?.[0] ?? null; const secondary = secondaryEntry ? pinFile(secondaryEntry) : null;
  // A Libauth source input also names its package directory; that directory is
  // pinned separately as an exhaustive runtimeDependencyTree, never mistaken
  // for a raw regular-file input.
  const closureEntries = [...record.sourceInputs, ...record.build.inputs, ...record.adapterInputs].filter((item) => fs.statSync(item.realpath).isFile()).map((item) => regularBinding(item.realpath));
  const unique = [...new Map(closureEntries.map((item) => [item.realpath, item])).values()].sort((a, b) => a.realpath.localeCompare(b.realpath));
  const closureRoot = id === 'engine:bchn' ? '/home/toorik/Projects' : repoRoots[0];
  const sourceClosure = id === 'engine:leanbch' ? localLeanClosure(record) : { root: closureRoot, files: unique, closureDigest: digestRecord({ root: closureRoot, files: unique }, `shieldkit-labs/p2/gate-b/cohort-executor-v2/${id.slice(7)}-selected-build-source-closure/v1`) };
  const closureClassification = id === 'engine:bchn' ? 'selected-build-inputs-plus-static-library-bound-by-frozen-fresh-attestation-not-full-source-tree' : id === 'engine:libauth' ? 'package-tree-bound-runtime-dependencies' : id === 'engine:leanbch' ? 'reachable-local-lean-and-ffi-source-closure-plus-attested-binaries' : 'transitive-node-module-graph';
  return { engineId: id, ordinal: ENGINE_ORDER.indexOf(id), recordPath: engineRecordPath(id), recordRawSha256: rawSha(recordFile), recordContentDigest: value(record.contentDigest), recordSchemaPath: engineSchemaPath, recordSchemaSha256: rawSha(source(engineSchemaPath)), entrypoint: primary, entrypointArgv: record.entrypoint.argv ?? [], secondaryEntrypoint: secondary, secondaryEntrypointArgv: secondaryEntry?.argv ?? null, kind: record.entrypoint.kind, cwd: repoRoots.find((root) => primary.realpath.startsWith(`${root}/`)), environment: record.environment, engineRuntime: record.runtime, stdinCodec: record.stdinCodec, implementationDigest: sha(bytes({ adapterInputs: record.adapterInputs, sourceInputs: record.sourceInputs, build: record.build, entrypoint: primary, secondary, sourceClosure })), repositoryRoots: repoRoots, sourceClosure, closureClassification };
};

export const buildAuthorization = ({ artifacts = loadFrozenEpochArtifacts() } = {}) => {
  assert(fs.existsSync(outputBase) && fs.lstatSync(outputBase).isDirectory() && !fs.lstatSync(outputBase).isSymbolicLink(), 'authorized output base missing or symlinked');
  const implementationEntries = [path.join(here, 'executor.mjs'), path.join(here, 'materializer.mjs'), path.join(here, 'validator.mjs'), path.join(here, 'engine-runners.mjs'), path.join(contractDir, 'engine-adapters.mjs'), path.join(freezeDir, 'execution-fixture.mjs'), path.join(freezeDir, 'fixture-roster.mjs'), path.join(freezeDir, 'epoch.mjs'), path.join(workspace, 'research-lanes/bch-shielded-pool-design/p2/reference/direct-extension.mjs'), path.join(workspace, 'package.json'), path.join(workspace, 'package-lock.json')];
  const c = readJson(contractFile); const leanAttestation = artifacts.engines['engine:leanbch'].buildAttestation; const preflight = leanAttestation.logs.find((x) => x.name === 'preflight.txt'); const auth = { schema: 'shieldkit-labs/p2/gate-b/cohort-executor-v2/authorization/v2', authorizationId: 'authorization:cohort-executor-v2:attempt-000', status: 'authorized-unexecuted', executionAllowed: true, epochId: 'execution-epoch:gate-b-v2', contractBinding: binding(contractFile, c.contentDigest.value), attempt: { index: 0, retries: 0, warmups: 0 }, schedule: { engineOrder: ENGINE_ORDER, batchCount: 4, batchSize: 4732, timeoutMs: 600000, maxBufferBytes: 134217728, maxConcurrency: 1, serial: true }, outputPolicy: { basePath: rel(outputBase), baseRealpath: fs.realpathSync(outputBase), exactOutputPath: rel(path.join(outputBase, 'attempt-000')) }, executorStartup: { environment: { NODE_ENV: 'production' }, policy: 'env-i-exact-node-env-production', argv: [runtime().nodeExecutable, rel(path.join(here, 'executor.mjs'))] }, engines: ENGINE_ORDER.map((id) => enginePin(id, artifacts)), runtime: runtime(), runtimeDependencyTrees: ['ajv', 'fast-deep-equal', 'fast-uri', 'json-schema-traverse', 'require-from-string'].map((name) => dependencyTree(path.join(workspace, 'node_modules', name))), leanBuildToolchain: { declaredToolchain: 'leanprover/lean4:v4.31.0', commands: leanAttestation.commands, commandsDigest: sha(bytes(leanAttestation.commands)), hostDefaultPreflightDiagnostic: { classification: 'host-default-diagnostic-not-build-toolchain-proof', rawSha256: preflight.rawSha256 } }, sourceBindings: [...Object.values(freezePaths).map((x) => binding(source(x), value(readJson(source(x)).contentDigest))), ...moduleGraph(implementationEntries)], schemaBindings: [...contractSchemas.map((x) => binding(source(x))), binding(source(engineSchemaPath)), binding(path.join(here, 'authorization.v2.schema.json')), binding(path.join(here, 'manifest.v1.schema.json'))], evidenceManifestSchema: binding(source('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2/contract/evidence-manifest.v2.schema.json')), obligationAccounting: { total: 18928, preflightUnsupported: 496, executable: 18432, perEngine: 4732 }, ranking: null, selection: null };
  auth.contentDigest = digestRecord(auth, AUTH_DOMAIN); return auth;
};

export const validateAuthorization = (authorization = readJson(authFile)) => {
  const schema = readJson(path.join(here, 'authorization.v2.schema.json')); const validator = new Ajv({ allErrors: true, strict: true }).compile(schema); assert(validator(authorization), new Ajv({ allErrors: true }).errorsText(validator.errors));
  const expected = buildAuthorization(); assert(JSON.stringify(authorization) === JSON.stringify(expected), 'authorization differs from deterministic current pins'); assert(authorization.contentDigest.value === digestRecord({ ...authorization, contentDigest: undefined }, AUTH_DOMAIN).value || authorization.contentDigest.value === digestRecord(Object.fromEntries(Object.entries(authorization).filter(([k]) => k !== 'contentDigest')), AUTH_DOMAIN).value, 'authorization digest mismatch'); return { status: 'PASS', authorizationDigest: authorization.contentDigest.value };
};

export const buildVerifiedRows = (artifacts) => {
  const recordByKey = new Map(artifacts.fixtureRoster.records.map((x) => [x.fixtureKey, x]));
  const corpus = artifacts.corpus;
  const out = new Map(ENGINE_ORDER.map((id) => [id, []]));
  // Regenerate the full authority once (it caches the 42 source-set plans),
  // then derive each physical fixture once. The adapter codecs re-check the
  // exact work-item/fixture pair before every engine batch; this avoids 4x
  // repeated source-map reads without weakening byte/roster verification.
  verifyFrozenFixtureAuthority({ artifacts });
  const cases = new Map(corpus.constructions.flatMap((entry) => entry.cases).map((entry) => [entry.caseKey, entry]));
  const sourcePlans = new Map(); const bases = new Map();
  for (const record of artifacts.fixtureRoster.records) {
    const caseEntry = cases.get(record.epochIdentity.caseKey); assert(caseEntry && caseEntry.caseDigest.value === record.epochIdentity.caseDigest, `fixture corpus identity drift: ${record.fixtureKey}`);
    let plan = sourcePlans.get(record.planId); if (!plan) { plan = loadSourceSetPlan(record.planId); sourcePlans.set(record.planId, plan); }
    const fixture = deriveExecutionFixture({ sourcePlan: plan, operandsBottomToTop: caseEntry.stackArgsBottomToTop.map((raw, index) => parseLowercaseEvenHex(raw, `corpus operand ${index}`)) });
    assert(JSON.stringify(canonicalize(fixture.bindings)) === JSON.stringify(canonicalize(record.byteBindings)) && JSON.stringify(canonicalize(fixture.sourceBinding)) === JSON.stringify(canonicalize(record.sourceBinding)), `fixture byte/source re-derivation drift: ${record.fixtureKey}`);
    bases.set(record.fixtureKey, Object.freeze({ fixtureRecord: record, fixture, caseEntry, expected: caseEntry.expected }));
  }
  assert(bases.size === 4732 && sourcePlans.size === 42, 'fixture/source-plan cache cardinality drift');
  for (const item of artifacts.workItemRoster.workItems) { const record = recordByKey.get(item.fixtureKey); const base = bases.get(item.fixtureKey); assert(record && base, `work references unknown fixture ${item.fixtureKey}`); const row = Object.freeze({ ...base, workItem: item }); if (!record.preflightLimitViolation?.scriptSig && !record.preflightLimitViolation?.redeem) out.get(item.engineId).push(row); }
  for (const id of ENGINE_ORDER) assert(out.get(id).length === 4608, `ready-row count drift: ${id}`); return out;
};

export const executeAuthorized = async ({ authorizationPath = authFile, outputRoot } = {}) => {
  assert(path.resolve(authorizationPath) === path.resolve(authFile), 'only exact authorization bytes are executable'); const authorization = readJson(authorizationPath); validateAuthorization(authorization); assertDefaultRunnerOrder();
  // Native and Libauth run inside this process. Their recorded NODE_ENV is
  // therefore meaningful only when the executor itself was launched under
  // the closed env -i startup contract, never by mutating process.env here.
  assert(process.env.NODE_ENV === 'production' && JSON.stringify(Object.keys(process.env).sort()) === JSON.stringify(['NODE_ENV']), 'executor must be started with env -i NODE_ENV=production');
  assert(JSON.stringify(authorization.executorStartup.argv) === JSON.stringify([process.execPath, rel(path.join(here, 'executor.mjs'))]), 'executor startup argv/runtime pin drift');
  const exactOutput = path.resolve(workspace, authorization.outputPolicy.exactOutputPath); assert(path.resolve(outputRoot) === exactOutput && !fs.existsSync(exactOutput), 'only the explicit authorized absent output path is executable'); assert(fs.realpathSync(outputBase) === authorization.outputPolicy.baseRealpath, 'authorized output base drift');
  const artifacts = loadFrozenEpochArtifacts(); const rows = buildVerifiedRows(artifacts); const batches = new Map();
  try { for (const [ordinal, engineId] of ENGINE_ORDER.entries()) batches.set(engineId, await defaultRunners[engineId]({ engineId, ordinal, artifacts, authorization, rows: rows.get(engineId), timeoutMs: authorization.schedule.timeoutMs, maxBufferBytes: authorization.schedule.maxBufferBytes })); const streams = new Map([...batches.values()].flatMap((x) => [...x.streams])); const pair = buildArtifactPairs({ authorization, artifacts, batches, streamText: streams }); return materializeAttempt({ outputRoot: exactOutput, authorization, ...pair, streamText: streams }); } catch (error) { assert(!fs.existsSync(exactOutput), 'failed execution must not leave evidence output'); throw error; }
};

const staticFiles = () => ['README.md', 'COMMAND.txt', 'authorization.v2.schema.json', 'manifest.v1.schema.json', 'executor.mjs', 'materializer.mjs', 'validator.mjs', 'engine-runners.mjs', 'executor.test.mjs', 'authorization.v2.json', 'runs/.gitkeep'].map((x) => path.join(here, x));
const buildStaticManifest = () => { const files = staticFiles().map((file) => binding(file)); const manifest = { schema: 'shieldkit-labs/p2/gate-b/cohort-executor-v2/manifest/v1', status: 'authorized-unexecuted', files, schemaBinding: binding(path.join(here, 'manifest.v1.schema.json')) }; manifest.contentDigest = digestRecord(manifest, 'shieldkit-labs/p2/gate-b/cohort-executor-v2/manifest/v1/root'); return manifest; };
const writeStatic = () => { assert(!fs.existsSync(path.join(outputBase, 'attempt-000')), 'refusing to regenerate authorization after attempt-000 exists'); writeJson(authFile, buildAuthorization()); const manifest = buildStaticManifest(); writeJson(path.join(here, 'MANIFEST.json'), manifest); const all = [...manifest.files, { path: rel(path.join(here, 'MANIFEST.json')), rawSha256: rawSha(path.join(here, 'MANIFEST.json')) }]; fs.writeFileSync(path.join(here, 'SHA256SUMS'), `${all.map((x) => `${x.rawSha256}  ${x.path}`).join('\n')}\n`); };
export const validateStatic = () => { validateAuthorization(); const manifest = readJson(path.join(here, 'MANIFEST.json')); const schema = readJson(path.join(here, 'manifest.v1.schema.json')); const validator = new Ajv({ allErrors: true, strict: true }).compile(schema); assert(validator(manifest), new Ajv({ allErrors: true }).errorsText(validator.errors)); assert(JSON.stringify(manifest) === JSON.stringify(buildStaticManifest()), 'static manifest differs from current authority'); return { status: 'PASS', authorizationDigest: readJson(authFile).contentDigest.value, packageFiles: manifest.files.length }; };
const main = async () => {
  if (process.argv.includes('--authorize')) { writeStatic(); console.log(JSON.stringify({ status: 'PASS', mode: 'authorize', authorizationDigest: readJson(authFile).contentDigest.value }, null, 2)); return; }
  if (process.argv.includes('--check')) { console.log(JSON.stringify(validateStatic(), null, 2)); return; }
  if (process.argv.includes('--execute')) { const i = process.argv.indexOf('--output'); assert(i >= 0 && process.argv.includes('--authorization'), 'explicit --authorization and --output are required'); const authArg = process.argv[process.argv.indexOf('--authorization') + 1]; assert(authArg === rel(authFile), 'exact authorization path required'); await executeAuthorized({ authorizationPath: authArg, outputRoot: process.argv[i + 1] }); return; }
  console.log(JSON.stringify({ status: 'PASS', execution: 'closed-until-explicit---execute-and-exact-authorization', authorization: rel(authFile) }, null, 2));
};
if (import.meta.url === `file://${process.argv[1]}`) await main();
