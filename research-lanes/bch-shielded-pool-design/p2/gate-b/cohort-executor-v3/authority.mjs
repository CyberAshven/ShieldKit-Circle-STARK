import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { CANONICALIZATION, FRAME, ROOT_DOMAIN, buildContract, canonicalBytes, canonicalize, contractPaths, digestRecord, omit, validateContract, validateManifest as validateContractManifest } from '../cohort-execution-v3/contract.mjs';
import { validateFailureStructureNonAuthoritative } from '../cohort-attempt-accounting-v1/validator.mjs';
import { readRegularFileNoFollow } from './durable-io.mjs';
import { currentCommitHelperBinding } from './commit-helper.mjs';

export const AUTHORIZATION_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-executor-v3/authorization/v3/root';
export const AUTHORIZATION_REL = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-authorizations-v3/attempt-001.authorization.v3.json';
export const CLAIM_REL = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-authorizations-v3/attempt-001.execution-claim.v3.json';
export const OUTPUT_REL = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-runs-v3/attempt-001';
export const FAILURE_REL = `${OUTPUT_REL}/failure`;
export const SUCCESS_REL = `${OUTPUT_REL}/success`;
export const V3_FREEZE_REL = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-v3-freeze.v1.json';
export const V3_FREEZE_SCHEMA_REL = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-v3-freeze.v1.schema.json';
const LANE_REL = 'research-lanes/bch-shielded-pool-design/lane.json';
const V3_FREEZE_LANE_REL = 'p2/gate-b/cohort-v3-freeze.v1.json';
const V3_FREEZE_SCHEMA_LANE_REL = 'p2/gate-b/cohort-v3-freeze.v1.schema.json';
const here = path.dirname(new URL(import.meta.url).pathname);
const workspace = contractPaths.workspace;
const packageRel = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3';
const sha = body => crypto.createHash('sha256').update(body).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(`cohort-executor-v3 authority: ${message}`); };
const byteSort = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const abs = rel => path.resolve(workspace, rel);
const rel = file => path.relative(workspace, file).split(path.sep).join('/');
const json = file => JSON.parse(fs.readFileSync(file, 'utf8'));
function strictCanonicalJson(bytes, label) {
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Error(`cohort-executor-v3 authority: ${label} invalid canonical UTF-8 JSON`); }
  assert(canonicalBytes(value).equals(bytes), `${label} noncanonical JSON`); return value;
}
const forbiddenStaticExecutionFragments = Object.freeze(['node' + ':child' + '_process', 'sp' + 'awn' + 'Sync(', 'sp' + 'awn(', 'exec' + 'File(', 'exec' + 'Sync(', 'process' + '-runner']);

function safeWorkspaceFile(relative) {
  assert(typeof relative === 'string' && relative.length > 0 && !path.isAbsolute(relative) && !relative.includes('\\') && !relative.split('/').includes('..'), `unsafe workspace path ${relative}`);
  const root = fs.realpathSync(workspace); let cursor = root;
  for (const part of relative.split('/')) { cursor = path.join(cursor, part); const st = fs.lstatSync(cursor); assert(!st.isSymbolicLink(), `symlink component ${relative}`); }
  const real = fs.realpathSync(cursor); const final = fs.statSync(real); assert(real.startsWith(`${root}${path.sep}`) && final.isFile() && (!Number.isInteger(final.nlink) || final.nlink === 1), `workspace file escapes ${relative}`); return real;
}
function safeAbsoluteFile(file) {
  assert(path.isAbsolute(file), 'absolute file required'); const root = path.parse(file).root; let cursor = root;
  for (const part of file.slice(root.length).split('/').filter(Boolean)) { cursor = path.join(cursor, part); const st = fs.lstatSync(cursor); assert(!st.isSymbolicLink(), `absolute symlink component ${file}`); }
  const real = fs.realpathSync(cursor); const final = fs.statSync(real); assert(real === file && final.isFile() && (!Number.isInteger(final.nlink) || final.nlink === 1), `absolute regular-file realpath ${file}`); return real;
}
function exact(left, right, label) { assert(JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right)), `${label} mismatch`); }
function bindingFromFile(file, { artifactId = null, content = null } = {}) {
  const real = path.isAbsolute(file) ? safeAbsoluteFile(file) : safeWorkspaceFile(file); const body = fs.readFileSync(real);
  return { ...(artifactId === null ? {} : { artifactId }), path: path.isAbsolute(file) ? file : file, realpath: real, rawSha256: sha(body), byteLength: body.length, ...(content === null ? {} : { contentDigest: content }) };
}
function contractBinding() {
  const file = `${contractPaths.packageRel}/execution-contract.v3.json`; const value = json(abs(file)); return bindingFromFile(file, { artifactId: 'execution-contract:gate-b-v3:attempt-001', content: value.contentDigest });
}
function strictJsonContentBinding(binding, expectedSchema, expectedDomain) {
  assert(binding && typeof binding === 'object' && typeof binding.path === 'string' && typeof binding.rawSha256 === 'string' && binding.contentDigest, 'content binding shape');
  const file = safeWorkspaceFile(binding.path); const body = fs.readFileSync(file); const value = json(file);
  assert(value.schema === expectedSchema && value.contentDigest?.domain === expectedDomain, `content binding schema/domain ${binding.path}`);
  assert(binding.rawSha256 === sha(body) && binding.byteLength === body.length && binding.realpath === file, `content binding bytes ${binding.path}`);
  assert(binding.contentDigest.value === value.contentDigest.value && value.contentDigest.value === digestRecord(omit(value), expectedDomain).value, `content binding digest ${binding.path}`);
  return value;
}
function fileBindingFromContract(entry) {
  const file = safeWorkspaceFile(entry.path); const body = fs.readFileSync(file); const parsed = entry.path.endsWith('.json') ? json(file) : null;
  assert(entry.rawSha256 === sha(body) && entry.byteLength === body.length, `contract authority bytes ${entry.path}`);
  if (entry.contentDigest) assert(parsed?.contentDigest?.value === entry.contentDigest.value, `contract authority content ${entry.path}`);
  return { path: entry.path, rawSha256: entry.rawSha256, contentDigest: entry.contentDigest };
}
function endpointDescriptor(record, engineBinding, endpointRole, endpointOrdinal, expectedRowCount) {
  const entry = endpointRole === 'primary' ? record.entrypoint : record.secondaryEntrypoints?.[0];
  assert(entry && (endpointRole === 'primary' || record.engineId === 'engine:leanbch'), `missing frozen endpoint ${record.engineId}/${endpointRole}`);
  const file = safeAbsoluteFile(entry.file.realpath); const bytes = fs.readFileSync(file);
  assert(entry.file.rawSha256 === sha(bytes) && entry.file.byteLength === bytes.length, `frozen endpoint bytes ${record.engineId}/${endpointRole}`);
  const root = record.repositoryAuthority.find(candidate => file === candidate.realpath || file.startsWith(`${candidate.realpath}${path.sep}`));
  assert(root, `frozen endpoint containment ${record.engineId}/${endpointRole}`);
  const adapterFile = safeWorkspaceFile(`${contractPaths.packageRel}/adapters.mjs`);
  const stdinCodec = endpointRole === 'secondary'
    ? 'expected-id-transaction-sourceOutputs-inputIndex-lines-v2-with-KERNEL-expected-token'
    : record.stdinCodec;
  return {
    endpointOrdinal, engineId: record.engineId, engineOrdinal: ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'].indexOf(record.engineId), endpointRole,
    endpointKind: entry.kind === 'module' ? 'module-ndjson' : 'external-process', expectedRowCount,
    invocation: {
      argv: entry.argv,
      cwd: root.realpath,
      environment: record.environment,
      runtime: record.runtime,
      engineBinding,
      entrypointBinding: { path: entry.file.path, realpath: file, rawSha256: sha(bytes), byteLength: bytes.length },
      entrypointKind: entry.kind,
      stdinCodec,
      implementationDigest: sha(fs.readFileSync(adapterFile)),
    },
  };
}
export function expectedEndpoints(contract = buildContract()) {
  const entries = contract.authorityBindings.engines;
  const records = entries.map(entry => {
    const value = strictJsonContentBinding({ ...entry, realpath: safeWorkspaceFile(entry.path) }, 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/engine-artifact/v2', `shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/${entry.artifactId.slice('engine-record:'.length)}`);
    return [value, fileBindingFromContract(entry)];
  });
  const byId = new Map(records.map(([record, source]) => [record.engineId, [record, source]]));
  return Object.freeze([
    endpointDescriptor(...byId.get('engine:native'), 'primary', 0, 4608),
    endpointDescriptor(...byId.get('engine:libauth'), 'primary', 1, 4608),
    endpointDescriptor(...byId.get('engine:bchn'), 'primary', 2, 4608),
    endpointDescriptor(...byId.get('engine:leanbch'), 'primary', 3, 4608),
    endpointDescriptor(...byId.get('engine:leanbch'), 'secondary', 4, 4608),
  ]);
}
function resolveLocal(from, specifier) {
  const base = path.resolve(path.dirname(from), specifier); const options = [base, `${base}.mjs`, `${base}.js`, path.join(base, 'index.mjs')];
  const found = options.find(candidate => fs.existsSync(candidate) && fs.lstatSync(candidate).isFile()); assert(found, `unresolved static import ${specifier} from ${from}`); return found;
}
function sourceClosure(entries, { processFree }) {
  const seen = new Set(); const queue = [...entries];
  while (queue.length) {
    const file = queue.pop(); const real = safeAbsoluteFile(file); if (seen.has(real)) continue; seen.add(real);
    const source = fs.readFileSync(real, 'utf8');
    if (processFree) assert(!forbiddenStaticExecutionFragments.some(fragment => source.includes(fragment)), `process reachability in static source ${real}`);
    for (const match of source.matchAll(/^\s*(?:import|export)\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/gmu)) if (match[1].startsWith('.')) queue.push(resolveLocal(real, match[1]));
  }
  return [...seen].sort(byteSort).map(real => { const body = fs.readFileSync(real); return { path: rel(real), realpath: real, rawSha256: sha(body), byteLength: body.length }; });
}
const staticEntries = () => [path.join(here, 'authority.mjs'), path.join(here, 'static-executor.mjs'), path.join(here, 'evidence-validator.mjs'), path.join(here, 'materializer.mjs'), path.join(here, 'cli.mjs'), path.resolve(contractPaths.workspace, `${contractPaths.packageRel}/contract.mjs`), path.resolve(contractPaths.workspace, `${contractPaths.packageRel}/lean-aggregate.mjs`), path.resolve(contractPaths.workspace, `${contractPaths.packageRel}/fixtures.mjs`), path.resolve(contractPaths.workspace, `${contractPaths.packageRel}/adapters.mjs`)];
/** Pure default/check closure: no child process primitive is reachable. */
export function staticSourceClosure() { return sourceClosure(staticEntries(), { processFree: true }); }
/** Future authorization closure includes the execute-only runner implementation. */
export function executionSourceClosure() { return sourceClosure([...staticEntries(), path.join(here, 'runner-open.mjs')], { processFree: false }); }
function dependencyTree(packageName) {
  const root = path.join(workspace, 'node_modules', packageName); const realRoot = fs.realpathSync(root); assert(fs.lstatSync(root).isDirectory() && !fs.lstatSync(root).isSymbolicLink(), `runtime dependency root ${packageName}`);
  const files = []; const walk = dir => { for (const name of fs.readdirSync(dir).sort(byteSort)) { const file = path.join(dir, name); const st = fs.lstatSync(file); assert(!st.isSymbolicLink(), `runtime dependency symlink ${file}`); if (st.isDirectory()) walk(file); else { assert(st.isFile() && (!Number.isInteger(st.nlink) || st.nlink === 1), `runtime dependency nonregular ${file}`); const body = fs.readFileSync(file); files.push({ path: rel(file), realpath: file, rawSha256: sha(body), byteLength: body.length }); } } };
  walk(realRoot); files.sort((a, b) => byteSort(a.path, b.path)); const value = { packageName, realpath: realRoot, files };
  return { ...value, treeDigest: digestRecord(value, `shieldkit-labs/p2/gate-b/cohort-executor-v3/runtime-tree/${packageName}`) };
}
export function runtimeDependencies() { return Object.freeze(['ajv', 'fast-deep-equal', 'fast-uri', 'json-schema-traverse', 'require-from-string'].map(dependencyTree)); }
export function currentRuntime() {
  const executable = safeAbsoluteFile(fs.realpathSync(process.execPath)); const body = fs.readFileSync(executable); const value = { executable, rawSha256: sha(body), byteLength: body.length, version: process.version, platform: process.platform, arch: process.arch };
  return Object.freeze({ ...value, runtimeDigest: digestRecord(value, 'shieldkit-labs/p2/gate-b/cohort-executor-v3/node-runtime/v1') });
}
function schemaBindings() {
  const rels = [
    `${packageRel}/authorization.v3.schema.json`, `${packageRel}/manifest.v1.schema.json`, `${packageRel}/evidence-manifest.v3.schema.json`, `${packageRel}/evidence-root.v3.schema.json`, `${packageRel}/raw-engine-observation.v3.schema.json`, `${packageRel}/normalized-engine-result.v3.schema.json`, `${packageRel}/cross-engine-summary.v3.schema.json`,
    `${contractPaths.packageRel}/execution-contract.v3.schema.json`, `${contractPaths.packageRel}/evidence-shape.v3.schema.json`, `${contractPaths.packageRel}/manifest.v1.schema.json`,
    'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-attempt-accounting-v1/future-endpoint.v1.schema.json', 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-attempt-accounting-v1/endpoint-stream-binding.v1.schema.json', 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-attempt-accounting-v1/failure-root.v1.schema.json', 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-attempt-accounting-v1/failure-receipt.v1.schema.json', 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-attempt-accounting-v1/failure-manifest.v1.schema.json', 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-attempt-accounting-v1/causal-batch-state.v1.schema.json',
    'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-commit-helper-v1/helper-descriptor.v1.schema.json', 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-commit-helper-v1/build-receipt.v1.schema.json', 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-commit-helper-v1/manifest.v1.schema.json'
  ];
  return rels.sort(byteSort).map(relative => bindingFromFile(relative));
}
function packageRootBindings() {
  const freezePath = safeWorkspaceFile(V3_FREEZE_REL); const freezeBytes = fs.readFileSync(freezePath); const freeze = JSON.parse(freezeBytes);
  assert(freeze.schema === 'shieldkit-labs/p2/gate-b/cohort-v3-freeze/v1' && freeze.status === 'frozen-unexecuted' && freeze.executionAllowed === false, 'independent v3 freeze gate');
  assert(canonicalBytes(freeze).equals(freezeBytes), 'independent v3 freeze canonical bytes');
  assert(freeze.contentDigest?.domain === 'shieldkit-labs/p2/gate-b/cohort-v3-freeze/v1/root' && freeze.contentDigest.value === digestRecord(omit(freeze), freeze.contentDigest.domain).value, 'independent v3 freeze content digest');
  const freezeSchemaPath = safeWorkspaceFile(V3_FREEZE_SCHEMA_REL);
  const lane = json(abs(LANE_REL)); const laneBinding = lane.p2FieldCheckpoint?.cohortV3FreezeBinding;
  assert(laneBinding?.path === V3_FREEZE_LANE_REL && laneBinding.schemaPath === V3_FREEZE_SCHEMA_LANE_REL && laneBinding.rawSha256 === sha(freezeBytes) && laneBinding.schemaSha256 === sha(fs.readFileSync(freezeSchemaPath)) && laneBinding.contentDigest === freeze.contentDigest.value && laneBinding.status === freeze.status && laneBinding.executionAllowed === false, 'independent v3 freeze lane pin');
  assert(Array.isArray(freeze.packageRoots) && freeze.packageRoots.length === 3, 'independent v3 package-root pins');
  const expectedRoots = ['research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v3', 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3', 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-commit-helper-v1'];
  const expectedDomains = ['shieldkit-labs/p2/gate-b/cohort-execution-v3/package-manifest/root', 'shieldkit-labs/p2/gate-b/cohort-executor-v3/package-manifest/root', 'shieldkit-labs/p2/gate-b/cohort-commit-helper-v1/package-manifest/root'];
  return Object.freeze(freeze.packageRoots.map((binding, index) => {
    assert(binding.packageRoot === expectedRoots[index] && binding.manifestPath === `${expectedRoots[index]}/MANIFEST.json` && binding.manifestSchemaPath === `${expectedRoots[index]}/manifest.v1.schema.json` && binding.checksumsPath === `${expectedRoots[index]}/SHA256SUMS`, `independent v3 package-root path ${index}`);
    const manifestBytes = fs.readFileSync(safeWorkspaceFile(binding.manifestPath)); const schemaBytes = fs.readFileSync(safeWorkspaceFile(binding.manifestSchemaPath)); const sumsBytes = fs.readFileSync(safeWorkspaceFile(binding.checksumsPath)); const manifest = JSON.parse(manifestBytes);
    const domain = expectedDomains[index];
    assert(binding.manifestRawSha256 === sha(manifestBytes) && binding.manifestByteLength === manifestBytes.length && binding.manifestSchemaRawSha256 === sha(schemaBytes) && binding.checksumsRawSha256 === sha(sumsBytes) && binding.checksumsByteLength === sumsBytes.length && binding.listedPayloadCount === manifest.files.length, `independent v3 package-root bytes ${index}`);
    assert(manifest.contentDigest?.domain === domain && manifest.contentDigest.value === digestRecord(omit(manifest), domain).value && JSON.stringify(binding.manifestContentDigest) === JSON.stringify(manifest.contentDigest), `independent v3 package-root digest ${index}`);
    return Object.freeze(structuredClone(binding));
  }));
}
function narrowBinding(entry) { return { path: entry.path, rawSha256: entry.rawSha256, contentDigest: entry.contentDigest }; }
function commitHelperBinding() {
  const helper = currentCommitHelperBinding();
  return Object.freeze({
    descriptor: { artifactId: 'commit-helper-descriptor:renameat2-noreplace-dir-commit-x86_64-linux-v1', ...helper.descriptor },
    binary: helper.binary,
    source: helper.source,
    buildReceipt: { artifactId: 'commit-helper-build-receipt:renameat2-noreplace-dir-commit-x86_64-linux-v1', ...helper.buildReceipt },
    manifest: { artifactId: 'commit-helper-manifest:renameat2-noreplace-dir-commit-x86_64-linux-v1', ...helper.manifest },
    checksums: helper.checksums,
    interface: helper.interface,
    syscall: helper.syscall,
  });
}
export function buildAuthorizationTemplate() {
  validateContract(); const contract = buildContract(); const bindings = contract.authorityBindings;
  const authorization = {
    schema: 'shieldkit-labs/p2/gate-b/cohort-executor-v3/authorization/v3', authorizationId: 'authorization:cohort-executor-v3:attempt-001', status: 'authorized-unexecuted', executionAllowed: true,
    attempt: { index: 1, priorAttemptIndex: 0, retriesWithinAttempt: 0, authorizationPath: AUTHORIZATION_REL, claimPath: CLAIM_REL, outputRoot: OUTPUT_REL, successRoot: SUCCESS_REL, failureRoot: FAILURE_REL },
    contractBinding: contractBinding(), epochBinding: narrowBinding(bindings.epoch), retryBinding: narrowBinding(bindings.retry), accountingBinding: narrowBinding(bindings.accountingRoot), packageRootBindings: packageRootBindings(),
    engineBindings: bindings.engines.map(narrowBinding), schedule: contract.schedule, endpoints: expectedEndpoints(contract), limits: { externalCombinedOutputBytes: 134217728, leanAggregateDeadlineMilliseconds: 600000, terminationGraceMilliseconds: 5000 }, commitHelper: commitHelperBinding(),
    runtime: currentRuntime(), sourceBindings: executionSourceClosure(), schemaBindings: schemaBindings(), runtimeDependencyTrees: runtimeDependencies(),
    ranking: null, selection: null, resultReuse: null,
  };
  authorization.contentDigest = digestRecord(omit(authorization), AUTHORIZATION_DOMAIN);
  return authorization;
}
function schemaCheck(value) { const ajv = new Ajv2020({ allErrors: true, strict: true }); const validate = ajv.compile(json(path.join(here, 'authorization.v3.schema.json'))); assert(validate(value), `authorization schema: ${ajv.errorsText(validate.errors)}`); }
export function validateAuthorizationObject(value) {
  schemaCheck(value); const expected = buildAuthorizationTemplate(); exact(value, expected, 'authorization deterministic current pins');
  assert(value.contentDigest.value === digestRecord(omit(value), AUTHORIZATION_DOMAIN).value, 'authorization content digest');
  return Object.freeze({ status: 'PASS', authorizationDigest: value.contentDigest.value });
}
/** Keep claim validation here to avoid a reverse authority↔evidence-validator
 * import. The bytes passed in have already been read from one no-follow inode. */
export function validateExecutionClaimObject(claim, authorization, authorizationBinding) {
  const ajv = new Ajv2020({ allErrors: true, strict: true }); const validate = ajv.compile(json(path.join(here, 'execution-claim.v3.schema.json')));
  assert(validate(claim), `claim schema: ${ajv.errorsText(validate.errors)}`);
  assert(claim.contentDigest?.domain === 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3/root' && claim.contentDigest.value === digestRecord(omit(claim), claim.contentDigest.domain).value, 'claim content digest');
  assert(claim.attemptIndex === 1 && claim.status === 'claimed-unexecuted' && claim.outputRoot === OUTPUT_REL, 'claim identity');
  exact(claim.authorizationBinding, authorizationBinding, 'claim authorization binding'); exact(claim.contractBinding, authorization.contractBinding, 'claim contract binding'); exact(claim.runtime, authorization.runtime, 'claim runtime');
  return claim;
}
export function readExecutionClaimByDescriptor({ authorization, authorizationBinding }) {
  const read = readRegularFileNoFollow(workspace, CLAIM_REL); const claim = strictCanonicalJson(read.bytes, 'execution claim');
  const binding = Object.freeze({ path: CLAIM_REL, rawSha256: read.rawSha256, byteLength: read.byteLength, contentDigest: claim.contentDigest });
  validateExecutionClaimObject(claim, authorization, authorizationBinding);
  return Object.freeze({ claim, bytes: read.bytes, binding, descriptor: read });
}
export function buildAccountingProjection(authorization, authorizationBinding, claimBinding) {
  assert(authorizationBinding?.path === AUTHORIZATION_REL && /^[0-9a-f]{64}$/u.test(authorizationBinding.rawSha256) && authorizationBinding.contentDigest?.value === authorization.contentDigest.value, 'authorization byte binding');
  assert(claimBinding?.path === CLAIM_REL && /^[0-9a-f]{64}$/u.test(claimBinding.rawSha256) && claimBinding.contentDigest?.domain === 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3/root', 'claim byte binding');
  const projectInvocation = (invocation, endpointKind) => ({
    argv: invocation.argv,
    cwd: invocation.cwd,
    environment: invocation.environment,
    runtime: endpointKind === 'module-ndjson'
      ? { executable: authorization.runtime.executable, version: authorization.runtime.version, platform: authorization.runtime.platform, arch: authorization.runtime.arch }
      : { executable: invocation.entrypointBinding.realpath, version: invocation.runtime.version ?? invocation.runtime.declaredToolchain ?? invocation.runtime.runtime, platform: invocation.runtime.platform, arch: invocation.runtime.arch },
    engineBinding: invocation.engineBinding,
    entrypointBinding: { path: invocation.entrypointBinding.path, rawSha256: invocation.entrypointBinding.rawSha256 },
    entrypointKind: invocation.entrypointKind,
  });
  return Object.freeze({ attemptIndex: 1, authorization: narrowBinding(authorizationBinding), claim: narrowBinding(claimBinding), contract: narrowBinding(authorization.contractBinding), epoch: authorization.epochBinding, retry: authorization.retryBinding, outputPaths: { failureRoot: abs(FAILURE_REL), successRoot: abs(SUCCESS_REL) }, limits: authorization.limits, endpoints: authorization.endpoints.map(({ endpointOrdinal, ...endpoint }) => ({ ...endpoint, invocation: projectInvocation(endpoint.invocation, endpoint.endpointKind) })) });
}
/**
 * Canonical full authority entry point. It authenticates the one-use external
 * transport before optionally delegating a durable failure package to the
 * accounting package's intentionally non-authoritative structural core.
 */
export function validateSealedV3Authority({ authorizationPath = abs(AUTHORIZATION_REL), failureRoot = null } = {}) {
  assert(typeof authorizationPath === 'string' && path.isAbsolute(authorizationPath) && authorizationPath === abs(AUTHORIZATION_REL), 'only exact authorization transport path');
  const opened = readRegularFileNoFollow(workspace, AUTHORIZATION_REL); const body = opened.bytes; const value = strictCanonicalJson(body, 'authorization'); const checked = validateAuthorizationObject(value);
  assert(opened.realpath === abs(AUTHORIZATION_REL) && opened.rawSha256 === sha(body) && opened.byteLength === body.length, 'descriptor authorization identity');
  const authorizationBinding = { path: AUTHORIZATION_REL, rawSha256: sha(body), byteLength: body.length, contentDigest: value.contentDigest };
  const claim = readExecutionClaimByDescriptor({ authorization: value, authorizationBinding });
  const projection = buildAccountingProjection(value, authorizationBinding, claim.binding);
  if (failureRoot !== null) {
    assert(failureRoot === abs(FAILURE_REL), 'only exact attempt-one failure root');
    validateFailureStructureNonAuthoritative(failureRoot, projection);
  }
  return Object.freeze({ ...checked, projection });
}
function validateStaticExecutorEnvelope() {
  const manifestPath = `${packageRel}/MANIFEST.json`; const sumsPath = `${packageRel}/SHA256SUMS`;
  const manifestBody = fs.readFileSync(safeWorkspaceFile(manifestPath)); const manifest = json(abs(manifestPath));
  const ajv = new Ajv2020({ allErrors: true, strict: true }); const schema = json(path.join(here, 'manifest.v1.schema.json')); const validate = ajv.compile(schema);
  assert(validate(manifest), `executor manifest schema: ${ajv.errorsText(validate.errors)}`);
  assert(manifest.contentDigest?.domain === 'shieldkit-labs/p2/gate-b/cohort-executor-v3/package-manifest/root' && manifest.contentDigest.value === digestRecord(omit(manifest), manifest.contentDigest.domain).value, 'executor manifest digest');
  assert(manifest.coverage?.listedPayloadCount === manifest.files.length && manifest.files.every((entry, index) => index === 0 || byteSort(manifest.files[index - 1].path, entry.path) < 0), 'executor manifest coverage/order');
  for (const entry of manifest.files) { const body = fs.readFileSync(safeWorkspaceFile(entry.path)); assert(entry.rawSha256 === sha(body) && entry.byteLength === body.length, `executor manifest bytes ${entry.path}`); }
  const actualFiles = []; const actualDirs = []; const walk = (folder, prefix = '') => {
    for (const name of fs.readdirSync(folder).sort(byteSort)) {
      const child = path.join(folder, name); const next = prefix ? `${prefix}/${name}` : name; const st = fs.lstatSync(child);
      assert(!st.isSymbolicLink(), `executor package symlink ${next}`);
      if (st.isDirectory()) { actualDirs.push(next); walk(child, next); }
      else { assert(st.isFile() && (!Number.isInteger(st.nlink) || st.nlink === 1), `executor package nonregular ${next}`); actualFiles.push(next); }
    }
  };
  walk(here); actualFiles.sort(byteSort); actualDirs.sort(byteSort);
  const prefix = `${packageRel}/`; const expectedFiles = ['MANIFEST.json', 'SHA256SUMS', ...manifest.files.map(entry => entry.path.slice(prefix.length))].sort(byteSort);
  const expectedDirs = new Set(); for (const name of expectedFiles) { const parts = name.split('/'); for (let index = 1; index < parts.length; index += 1) expectedDirs.add(parts.slice(0, index).join('/')); }
  exact(actualFiles, expectedFiles, 'executor package file closure'); exact(actualDirs, [...expectedDirs].sort(byteSort), 'executor package directory closure');
  const rows = [[sha(manifestBody), manifestPath], ...manifest.files.map(entry => [entry.rawSha256, entry.path])];
  const expected = Buffer.from(`${rows.map(row => row.join('  ')).join('\n')}\n`, 'utf8');
  assert(fs.readFileSync(safeWorkspaceFile(sumsPath)).equals(expected), 'executor checksum envelope');
}
export function validateStaticExecutor() {
  validateContract(); validateContractManifest(); validateStaticExecutorEnvelope(); assert(!fs.existsSync(abs(AUTHORIZATION_REL)) && !fs.existsSync(abs(CLAIM_REL)), 'authorization namespace must remain absent before explicit authorization'); assert(!fs.existsSync(abs(OUTPUT_REL)), 'run output must remain absent before explicit execution');
  for (const source of staticSourceClosure()) assert(source.path.startsWith('research-lanes/'), 'static closure outside workspace');
  return Object.freeze({ status: 'PASS', mode: 'static-no-authorization-no-execution', authorizationPath: AUTHORIZATION_REL, claimPath: CLAIM_REL, outputRoot: OUTPUT_REL });
}
