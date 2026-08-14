import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const ROOT = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(ROOT, '../../../../../');
const GATE_B_ROOT = resolve(REPOSITORY_ROOT, 'research-lanes/bch-shielded-pool-design/p2/gate-b');
const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/';
const IDENTIFIER = 'cohort-upstream-origin-provider-contract-v1';
const STATUS = 'static-upstream-origin-provider-contract-catalog-no-providers-no-owner-roots-no-material-non-authorizing-unavailable-unqualified';
const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
const FRAME = 'utf8(domain)||0x00||canonical-json-utf8-lf-v1';
const ROOT_DIGEST = 'e76b1c35b47fac325b0e2750495ce4fabc8f1d9145974cdbbae95b63f2699020';
const DIRECTORIES = Object.freeze(['.', 'schemas', 'test']);
const AUTHORED_FILES = Object.freeze([
  'COMMAND.txt',
  'README.md',
  'schemas/dependency-catalog.v1.schema.json',
  'schemas/digest.v1.schema.json',
  'schemas/external-origin-provider-catalog.v1.schema.json',
  'schemas/fact-provider-catalog.v1.schema.json',
  'schemas/manifest.v1.schema.json',
  'schemas/model-root.v1.schema.json',
  'schemas/order-provider-catalog.v1.schema.json',
  'schemas/owner-provider-catalog.v1.schema.json',
  'schemas/projection-provider-catalog.v1.schema.json',
  'schemas/provider-dag.v1.schema.json',
  'schemas/root-provider-catalog.v1.schema.json',
  'test/digest.kat.json',
  'test/mutation.test.mjs',
  'test/package-boundary.test.mjs',
  'test/static.test.mjs',
  'upstream-origin-provider-contract-root.v1.json',
  'validate-static.mjs',
]);
const COMPONENTS = Object.freeze([
  ['staticDependencies', 'dependency-catalog', '6ae947df810501fe09748609d40053322e32d8e83dfda27d25fd278eddca72b5'],
  ['ecocContractPrefix', 'ecoc-contract-prefix', 'f4f1911fee07dbbdaea2dd45e54068de3f1642a3b5f77737c8d00079bd0dafc5'],
  ['providerCausalDag', 'provider-causal-dag', '8c80d46922c05700f3d9bbd999e5a780201a09d42da1604dbc22f7a15bda585d'],
  ['ownerProviderCatalog', 'owner-provider-catalog', '6e5565820ac94affdc6714b918f7ba0a4bd4b3e3b1ad6cbbe8498d5e3e87dbc3'],
  ['rootProviderCatalog', 'root-provider-catalog', 'bc16611643a28371fa2aa415cc9966663e1c1cabef3d2ac19dbc88afd12f5374'],
  ['orderProviderCatalog', 'order-provider-catalog', '8ae28f4abe35055dfa8432c12215e951c741ff40442c6e137bbebd6ebbfe23cb'],
  ['projectionProviderCatalog', 'projection-provider-catalog', '47996eb6e89d17242dab686efa67c21676bc047dde3a27c6ec2cee0393e418a6'],
  ['externalOriginProviderCatalog', 'external-origin-provider-catalog', '9f06806900954fd7312e56031aafd085f08851237de46e0db32a2cbf6835b228'],
  ['factProviderCatalog', 'fact-provider-catalog', 'd4138fc9d1e8aad3a8f2fd5c800b7f7a50615e9fa07ce9d6b5e6b13051eed114'],
  ['nonAuthorityBoundary', 'non-authority-boundary', 'da1b12e3df9f843e2336700f28bb14cb276937883bfe8c9e60d18519203194c1'],
]);
const PROVIDER_NODES = Object.freeze([
  'RECOVERY_CHAIN_OWNER_PROVIDER', 'REQUEST_OWNER_PROVIDER', 'ACTIVATION_OWNER_PROVIDER', 'PRIVATE_CAPTURE_OWNER_PROVIDER', 'PRIVATE_DESCRIPTOR_OWNER_PROVIDER', 'EXCLUSIVE_C_OWNER_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER', 'RETRY_ORDER_PROVIDER', 'LIVE_F_RECORD_ORDER_PROVIDER', 'FROZEN_SURFACE_ORDER_PROVIDER', 'ENDPOINT_CONTROL_ORDER_PROVIDER', 'WORKLOAD_ROOT_ORDER_PROVIDER', 'WORKLOAD_PROJECTION_PROVIDER', 'ENDPOINT_BYTE_AUTHORITY_PROVIDER', 'RETRY_PREDECESSOR_PROVIDER', 'LIVE_F_CAPTURE_PROVIDER', 'WORKER_ROWS_ROOT_PROVIDER', 'Q_INITIAL_PROVIDER', 'Q_RETRY_PROVIDER', 'Q_ABORT_PROVIDER', 'A_INITIAL_PROVIDER', 'A_RETRY_PROVIDER', 'A_ABORT_PROVIDER', 'LIVE_F_PROVIDER', 'B_SUBJECT_ROOT_TYPE', 'B_PROVIDER', 'C_PROVIDER', 'J_ROOT_TYPE', 'DISPATCH_PLAN_PROVIDER', 'D_PROVIDER',
]);
const PROVIDER_EDGES = Object.freeze([
  'RECOVERY_CHAIN_OWNER_PROVIDER→RETRY_PREDECESSOR_PROVIDER', 'RETRY_ORDER_PROVIDER→RETRY_PREDECESSOR_PROVIDER', 'RETRY_PREDECESSOR_PROVIDER→Q_RETRY_PROVIDER', 'REQUEST_OWNER_PROVIDER→Q_INITIAL_PROVIDER', 'REQUEST_OWNER_PROVIDER→Q_RETRY_PROVIDER', 'REQUEST_OWNER_PROVIDER→Q_ABORT_PROVIDER', 'Q_INITIAL_PROVIDER→A_INITIAL_PROVIDER', 'Q_RETRY_PROVIDER→A_RETRY_PROVIDER', 'Q_ABORT_PROVIDER→A_ABORT_PROVIDER', 'ACTIVATION_OWNER_PROVIDER→A_INITIAL_PROVIDER', 'ACTIVATION_OWNER_PROVIDER→A_RETRY_PROVIDER', 'ACTIVATION_OWNER_PROVIDER→A_ABORT_PROVIDER', 'PRIVATE_CAPTURE_OWNER_PROVIDER→LIVE_F_CAPTURE_PROVIDER', 'LIVE_F_RECORD_ORDER_PROVIDER→LIVE_F_CAPTURE_PROVIDER', 'LIVE_F_CAPTURE_PROVIDER→LIVE_F_PROVIDER', 'PRIVATE_CAPTURE_OWNER_PROVIDER→LIVE_F_PROVIDER', 'A_INITIAL_PROVIDER→B_SUBJECT_ROOT_TYPE', 'B_SUBJECT_ROOT_TYPE→B_PROVIDER', 'LIVE_F_PROVIDER→B_PROVIDER', 'PRIVATE_DESCRIPTOR_OWNER_PROVIDER→B_PROVIDER', 'B_PROVIDER→C_PROVIDER', 'EXCLUSIVE_C_OWNER_PROVIDER→C_PROVIDER', 'B_PROVIDER→J_ROOT_TYPE', 'C_PROVIDER→J_ROOT_TYPE', 'FROZEN_SURFACE_ORDER_PROVIDER→WORKLOAD_PROJECTION_PROVIDER', 'ENDPOINT_CONTROL_ORDER_PROVIDER→WORKLOAD_PROJECTION_PROVIDER', 'WORKLOAD_ROOT_ORDER_PROVIDER→WORKLOAD_PROJECTION_PROVIDER', 'WORKLOAD_PROJECTION_PROVIDER→ENDPOINT_BYTE_AUTHORITY_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER→ENDPOINT_BYTE_AUTHORITY_PROVIDER', 'ENDPOINT_BYTE_AUTHORITY_PROVIDER→WORKER_ROWS_ROOT_PROVIDER', 'ENDPOINT_CONTROL_ORDER_PROVIDER→WORKER_ROWS_ROOT_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER→WORKER_ROWS_ROOT_PROVIDER', 'WORKER_ROWS_ROOT_PROVIDER→DISPATCH_PLAN_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER→DISPATCH_PLAN_PROVIDER', 'B_PROVIDER→D_PROVIDER', 'C_PROVIDER→D_PROVIDER', 'J_ROOT_TYPE→D_PROVIDER', 'WORKER_ROWS_ROOT_PROVIDER→D_PROVIDER', 'DISPATCH_PLAN_PROVIDER→D_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER→D_PROVIDER',
]);
const OWNER_IDS = Object.freeze(['RECOVERY_CHAIN_OWNER_PROVIDER', 'REQUEST_OWNER_PROVIDER', 'ACTIVATION_OWNER_PROVIDER', 'PRIVATE_CAPTURE_OWNER_PROVIDER', 'PRIVATE_DESCRIPTOR_OWNER_PROVIDER', 'EXCLUSIVE_C_OWNER_PROVIDER', 'PRIVATE_DISPATCH_OWNER_PROVIDER']);
const ROOT_IDS = Object.freeze(['UPSTREAM_OWNER_CONTRACT_ROOT', 'OWNER_BINDING', 'RETRY_TARGET_ROOT', 'RETRY_TERMINAL_PREDECESSOR_ROOT', 'RETRY_PREDECESSOR', 'LIVE_F_CAPTURE', 'WORKLOAD_ROOT', 'ENDPOINT_BYTE_AUTHORITY', 'WORKER_ROWS_ROOT', 'DISPATCH_PLAN', 'Q', 'A', 'LIVE_F', 'B_SUBJECT', 'B', 'C', 'J', 'D']);
const ORDER_IDS = Object.freeze(['RETRY_ORDER_PROVIDER', 'LIVE_F_RECORD_ORDER_PROVIDER', 'FROZEN_SURFACE_ORDER_PROVIDER', 'ENDPOINT_CONTROL_ORDER_PROVIDER', 'WORKLOAD_ROOT_ORDER_PROVIDER']);
const PROJECTION_IDS = Object.freeze(['WORKLOAD_PROJECTION_PROVIDER', 'ENDPOINT_BYTE_AUTHORITY_PROVIDER', 'DISPATCH_PLAN_PROVIDER']);
const ORIGIN_IDS = Object.freeze(['RETRY_PREDECESSOR_PROVIDER', 'LIVE_F_CAPTURE_PROVIDER', 'WORKER_ROWS_ROOT_PROVIDER']);
const FACT_IDS = Object.freeze(['Q_PROVIDER', 'A_PROVIDER', 'LIVE_F_PROVIDER', 'B_PROVIDER', 'C_PROVIDER', 'J_PROVIDER', 'D_PROVIDER']);
const EC0C_BINDING = Object.freeze({
  path: 'p2/gate-b/cohort-external-origin-contract-v1',
  root: { path: 'p2/gate-b/cohort-external-origin-contract-v1/external-origin-contract-root.v1.json', rawSha256: '63b8f0312fc5da429f66ce7ccfcc9c213edc52f9ce8ec671c7e0223207ac4f7d', contentDigest: '6aab36a2a185207da03c364066f9f791cf2710408798b1d93ef61618177f6e60' },
  dependencyCatalogDigest: '5f1462db4dc63600721d8da95578b3ff94c2a929173f81c19c9d0db94f9089b8',
  cabmAuthorityPrefixDigest: 'f487c232fd574853ac1039d54ff2d6218579234ff753df55e5b724c1647771e0',
  externalCausalDagDigest: '6227fd5d52dfc9e4b2879ce58c0bc45ea150dd5bde5719e476bd004073da5e45',
  ownershipCatalogDigest: '68d517dde6d5de8e5d5f8b7ece6509174039a5fbe72e9e0cef1250e7edf13e41',
  externalOriginContractsDigest: '1836a1038698ee6809f03b870a1b1b4c4d1c8855603cc1ce5b402287a844db96',
  factContractsDigest: '48824ca660ced0da245066bef687bac22ff25d4d30a344bb474cfceaa02ac823',
  rootDomainCatalogDigest: 'f6dc6604a33d227f07fb7101f9669be23a503eaa11d656c1a6b306c3a71d4284',
  workloadProjectionContractDigest: 'bb4de79eaf432b595ce19ca02c86180ccd0259789ddf95f0ba834b6f657497c0',
  manifest: { path: 'p2/gate-b/cohort-external-origin-contract-v1/MANIFEST.json', rawSha256: 'de386b8758b75c5a92fafdadcb9fe0dcd769ab7385afae8d8642c66df8608bc6', rosterDigest: 'd5dd2d964b0feb87ca367e300c450ca78afe7ebafc0e22ffad0118476d9a01ec', entryCount: 19 },
  checksums: { path: 'p2/gate-b/cohort-external-origin-contract-v1/SHA256SUMS', rawSha256: 'ec1b8bcee3a8e9835f4ed2b97b784fefe14000ee6e7df3f6a8cc4cd59671a5ea' },
  validator: { path: 'p2/gate-b/cohort-external-origin-contract-v1/validate-static.mjs', rawSha256: '0f37cf65905409c9a0bf26b8d98ad50fb228ae9500e6ff4647efa88b31a5f8de' },
  status: 'sol-regated-static-external-origin-contract-catalog-no-instances-non-authorizing-origins-unavailable-unqualified',
});

function fail(message) { throw new Error('cohort-upstream-origin-provider-contract-v1 static validation: ' + message); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function loneSurrogate(text) { return /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF]))|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(text); }
function exactRecord(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(label + ' must be a plain record');
  const actual = Reflect.ownKeys(value);
  for (const key of actual) {
    if (typeof key !== 'string') fail(label + ' has symbol key');
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) fail(label + ' has non-data member');
  }
  const wanted = keys.slice().sort();
  if (actual.length !== wanted.length || actual.slice().sort().some((key, index) => key !== wanted[index])) fail(label + ' key set differs');
  return value;
}
function canonicalJson(value, stack = new Set()) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') { if (loneSurrogate(value)) fail('canonical JSON rejects lone surrogate'); return JSON.stringify(value); }
  if (typeof value === 'number') { if (!Number.isFinite(value) || Object.is(value, -0)) fail('canonical JSON rejects number'); return String(value); }
  if (typeof value !== 'object' || stack.has(value)) fail('canonical JSON rejects value');
  stack.add(value);
  let text;
  if (Array.isArray(value)) {
    const own = Reflect.ownKeys(value);
    if (own.length !== value.length + 1 || !own.includes('length')) fail('canonical JSON rejects sparse array');
    text = '[' + value.map((item) => canonicalJson(item, stack)).join(',') + ']';
  } else {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) fail('canonical JSON rejects prototype');
    const keys = Reflect.ownKeys(value);
    for (const key of keys) { if (typeof key !== 'string') fail('canonical JSON rejects symbol'); const d = Object.getOwnPropertyDescriptor(value, key); if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) fail('canonical JSON rejects member'); }
    text = '{' + keys.sort().map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key], stack)).join(',') + '}';
  }
  stack.delete(value);
  return text;
}
function semanticDigest(domain, value) { return sha256(Buffer.from(domain + '\u0000' + canonicalJson(value) + '\n', 'utf8')); }
function rawFileDigest(bytes) { return sha256(Buffer.concat([Buffer.from(PREFIX + 'file\u0000', 'utf8'), bytes])); }
function descriptor(domain, value) { return { algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value }; }
function omit(object, member) { const copy = {}; for (const [key, value] of Object.entries(object)) if (key !== member) copy[key] = value; return copy; }
function equal(actual, expected, label) { if (canonicalJson(actual) !== canonicalJson(expected)) fail(label + ' differs'); }
function parseCanonical(bytes, label) { const text = bytes.toString('utf8'); if (!text.endsWith('\n') || text.endsWith('\n\n')) fail(label + ' final LF'); let value; try { value = JSON.parse(text); } catch { fail(label + ' JSON parse'); } if (text !== canonicalJson(value) + '\n') fail(label + ' canonical JSON'); return value; }
function localPath(root, locator) { if (typeof locator !== 'string' || locator.length === 0 || isAbsolute(locator) || locator.includes('\\') || locator.split('/').includes('..')) fail('unsafe local locator'); const target = resolve(root, locator); const rel = relative(root, target); if (!rel || rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) fail('local locator escapes'); return target; }
function readLocal(root, locator) { const target = localPath(root, locator); const info = lstatSync(target); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) fail(locator + ' regular single-link file'); return readFileSync(target); }
function jsonLocal(root, locator) { return parseCanonical(readLocal(root, locator), locator); }
function collect(root, current, found) { const target = current === '.' ? root : localPath(root, current); const info = lstatSync(target); if (!info.isDirectory() || info.isSymbolicLink()) fail(current + ' directory'); found.dirs.push(current); for (const name of readdirSync(target).sort()) { const locator = current === '.' ? name : current + '/' + name; const child = localPath(root, locator); const childInfo = lstatSync(child); if (childInfo.isSymbolicLink()) fail(locator + ' link'); if (childInfo.isDirectory()) collect(root, locator, found); else if (childInfo.isFile()) found.files.push(locator); else fail(locator + ' filesystem type'); } }
function checkFilesystem(root, allowUnsealed = false, allowTemporaryMetadata = false) {
  const info = lstatSync(root); if (!info.isDirectory() || info.isSymbolicLink() || realpathSync(root) !== resolve(root)) fail('package root');
  if (!allowTemporaryMetadata && ((info.mode & 0o777) !== 0o755 || info.nlink !== 1)) fail('package root mode/nlink');
  const found = { dirs: [], files: [] }; collect(root, '.', found);
  equal(found.dirs.slice().sort(), DIRECTORIES.slice().sort(), 'directory closure');
  const expected = allowUnsealed ? AUTHORED_FILES : AUTHORED_FILES.concat(['MANIFEST.json', 'SHA256SUMS']); equal(found.files.slice().sort(), expected.slice().sort(), 'file closure');
  for (const dir of found.dirs) { const d = lstatSync(dir === '.' ? root : localPath(root, dir)); if (!allowTemporaryMetadata && ((d.mode & 0o777) !== 0o755 || d.nlink !== 1)) fail(dir + ' directory mode/nlink'); }
  for (const file of found.files) { const f = lstatSync(localPath(root, file)); if (!allowTemporaryMetadata && ((f.mode & 0o777) !== 0o644 || f.nlink !== 1)) fail(file + ' file mode/nlink'); }
  if (allowUnsealed && (found.files.includes('MANIFEST.json') || found.files.includes('SHA256SUMS'))) fail('partial envelope');
}
function readUpstream(locator, repositoryRoot = REPOSITORY_ROOT) {
  if (typeof locator !== 'string' || !locator.startsWith('research-lanes/bch-shielded-pool-design/p2/gate-b/') || locator.includes('\\') || locator.split('/').includes('..')) fail('unsafe upstream locator');
  const gateBRoot = resolve(repositoryRoot, 'research-lanes/bch-shielded-pool-design/p2/gate-b'); const target = resolve(repositoryRoot, locator); const rel = relative(gateBRoot, target); if (!rel || rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) fail('upstream containment');
  let cursor = gateBRoot;
  for (const part of rel.split(sep)) { cursor = join(cursor, part); const info = lstatSync(cursor); if (info.isSymbolicLink()) fail('upstream symlink component ' + locator); }
  if (realpathSync(target) !== target) fail('upstream realpath ' + locator);
  const info = lstatSync(target); if (!info.isFile() || info.nlink !== 1) fail('upstream regular single-link leaf ' + locator);
  return readFileSync(target);
}
function checkDescriptor(component, domain, expected, label) { exactRecord(component, ['algorithm', 'canonicalization', 'domain', 'frame', 'value'], label); equal(component, descriptor(domain, expected), label); }
function checkComponent(component, suffix, expected, label) { exactRecord(component, Object.keys(component), label); const actual = semanticDigest(PREFIX + suffix, omit(component, 'contentDigest')); checkDescriptor(component.contentDigest, PREFIX + suffix, actual, label + ' descriptor'); if (actual !== expected) fail(label + ' external semantic pin'); }
function assertArrayIds(catalog, expected, label) { if (!Array.isArray(catalog.entries)) fail(label + ' entries'); equal(catalog.entries.map((entry) => entry.id), expected, label + ' identifier order'); }
function checkNoMaterial(value, where = '$', protectedNames = false) {
  if (value === null) fail('null forbidden at ' + where);
  if (Array.isArray(value)) { value.forEach((item, index) => checkNoMaterial(item, where + '/' + index, protectedNames)); return; }
  if (typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    if (['futurePreimageKeys', 'futureProviderFields', 'futureValidationRules', 'rules'].includes(key)) { if (!Array.isArray(item) && (item === null || typeof item !== 'object')) fail('future field names at ' + where + '/' + key); continue; }
    if (['ownerBindingRoot', 'upstreamOwnerContractRoot', 'targetRoot', 'predecessorRoot', 'retryPredecessorRoot', 'liveFCaptureRoot', 'workerRowsRoot', 'dispatchPlanRoot', 'privateBytes', 'projectionBytes', 'identity', 'capability', 'instance', 'workerId', 'workloadRoot', 'orderedWorkloadRoots', 'projectionEncodingId', 'projectedByteCount', 'rootValue'].includes(key)) fail('material member forbidden at ' + where + '/' + key);
    checkNoMaterial(item, where + '/' + key, protectedNames);
  }
}
function checkDag(dag) { exactRecord(dag, ['contentDigest', 'edgeCount', 'edges', 'nodeCount', 'nodes', 'staticDependencyEdgesAllowed', 'status'], 'provider DAG'); equal(dag.nodes, PROVIDER_NODES, 'provider DAG nodes'); equal(dag.edges, PROVIDER_EDGES, 'provider DAG edges'); if (dag.nodeCount !== 30 || dag.edgeCount !== 40 || dag.staticDependencyEdgesAllowed !== false || dag.status !== 'type-only-provider-prerequisite-overlay') fail('provider DAG metadata'); const seen = new Set(); const graph = new Map(PROVIDER_NODES.map((node) => [node, []])); for (const edge of dag.edges) { const [from, to] = edge.split('→'); if (!graph.has(from) || !graph.has(to) || from === to || seen.has(edge)) fail('provider DAG edge'); seen.add(edge); graph.get(from).push(to); } const visiting = new Set(); const done = new Set(); const visit = (node) => { if (visiting.has(node)) fail('provider DAG cycle'); if (done.has(node)) return; visiting.add(node); graph.get(node).forEach(visit); visiting.delete(node); done.add(node); }; PROVIDER_NODES.forEach(visit); }
function checkStaticDependencies(deps, repositoryRoot) {
  exactRecord(deps, ['contentDigest', 'entries', 'identifier', 'schema', 'validationMode'], 'dependency catalog');
  if (deps.identifier !== IDENTIFIER || deps.schema !== PREFIX + 'dependency-catalog/v1' || deps.validationMode !== 'read-regular-file-bytes-only-no-import-no-evaluation' || !Array.isArray(deps.entries) || deps.entries.length !== 33) fail('dependency catalog metadata');
  const seen = new Set(); for (const [index, entry] of deps.entries.entries()) { exactRecord(entry, ['dependencyId', 'locator', 'rawSha256', 'role'], 'dependency ' + index); if (!/^[a-f0-9]{64}$/.test(entry.rawSha256) || seen.has(entry.dependencyId + '\u0000' + entry.locator) || sha256(readUpstream(entry.locator, repositoryRoot)) !== entry.rawSha256) fail('dependency leaf ' + index); seen.add(entry.dependencyId + '\u0000' + entry.locator); }
  const tail = deps.entries.slice(29); equal(tail.map((entry) => [entry.dependencyId, entry.role]), [['ECOC', 'primary-root'], ['ECOC', 'manifest'], ['ECOC', 'checksum-list'], ['ECOC', 'static-validator']], 'ECOC dependency tail');
  const rManifest = JSON.parse(readUpstream(deps.entries[1].locator, repositoryRoot).toString('utf8')); if (typeof rManifest.contentDigest !== 'string') fail('R manifest contentDigest direct string');
  const dispatchLeaf = deps.entries.find((entry) => entry.dependencyId === 'K' && entry.role === 'dispatch-plan-schema');
  if (!dispatchLeaf) fail('K dispatch-plan schema leaf');
  const dispatchSchema = JSON.parse(readUpstream(dispatchLeaf.locator, repositoryRoot).toString('utf8'));
  const workerRows = dispatchSchema?.properties?.workerRows;
  if (!workerRows || workerRows.minItems !== 1 || workerRows.maxItems !== 4096 || workerRows.minItems > 5 || workerRows.maxItems < 5) fail('K worker row bounds');
  return { minimum: workerRows.minItems, maximum: workerRows.maxItems };
}
function checkECOC(prefix, repositoryRoot) {
  exactRecord(prefix, ['binding', 'contentDigest', 'identifier', 'schema', 'sourceDependencyId', 'sourceRootField', 'status'], 'ECOC contract prefix');
  if (prefix.identifier !== IDENTIFIER || prefix.schema !== PREFIX + 'ecoc-contract-prefix/v1' || prefix.sourceDependencyId !== 'ECOC' || prefix.sourceRootField !== 'external-origin-contract-root.v1.json' || prefix.status !== 'exact-static-prefix-only-no-provider-instantiation') fail('ECOC prefix metadata'); equal(prefix.binding, EC0C_BINDING, 'ECOC external binding');
  const externalRoot = JSON.parse(readUpstream('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-external-origin-contract-v1/external-origin-contract-root.v1.json', repositoryRoot).toString('utf8'));
  if (externalRoot.contentDigest?.value !== EC0C_BINDING.root.contentDigest) fail('ECOC root content pin');
  const map = [['staticDependencies', 'dependencyCatalogDigest'], ['cabmAuthorityPrefix', 'cabmAuthorityPrefixDigest'], ['externalCausalDag', 'externalCausalDagDigest'], ['ownershipCatalog', 'ownershipCatalogDigest'], ['externalOriginContracts', 'externalOriginContractsDigest'], ['factContracts', 'factContractsDigest'], ['rootDomainCatalog', 'rootDomainCatalogDigest'], ['workloadProjectionContract', 'workloadProjectionContractDigest']];
  for (const [component, bindingKey] of map) if (externalRoot[component]?.contentDigest?.value !== EC0C_BINDING[bindingKey]) fail('ECOC semantic pin ' + component);
}
function checkCatalogs(root, kWorkerRowBounds) {
  const owners = root.ownerProviderCatalog; exactRecord(owners, ['contentDigest', 'entries', 'identifier', 'schema'], 'owner catalog'); assertArrayIds(owners, OWNER_IDS, 'owner catalog');
  const expectedScopes = [['RETRY_PREDECESSOR'], ['Q'], ['A'], ['LIVE_F_CAPTURE', 'LIVE_F'], ['B'], ['C'], ['WORKER_ROWS_ROOT', 'D']];
  owners.entries.forEach((entry, index) => { const continuity = index === 3 || index === 6; exactRecord(entry, continuity ? ['admissionAllowed', 'capabilityDisposition', 'futurePreimageKeys', 'grantsAuthority', 'id', 'identityDisposition', 'instanceDisposition', 'ownerBindingContinuity', 'ownerBindingRootDisposition', 'ownerClass', 'ownerContractDisposition', 'providerDisposition', 'scope'] : ['admissionAllowed', 'capabilityDisposition', 'futurePreimageKeys', 'grantsAuthority', 'id', 'identityDisposition', 'instanceDisposition', 'ownerBindingRootDisposition', 'ownerClass', 'ownerContractDisposition', 'providerDisposition', 'scope'], 'owner ' + index); if (entry.admissionAllowed || entry.grantsAuthority || entry.providerDisposition !== 'TYPE_ONLY_UNAVAILABLE_EXTERNAL' || entry.ownerContractDisposition !== 'UNAVAILABLE_EXTERNAL' || entry.ownerBindingRootDisposition !== 'UNAVAILABLE_EXTERNAL' || entry.identityDisposition !== 'NOT_REPRESENTED' || entry.capabilityDisposition !== 'FORBIDDEN' || entry.instanceDisposition !== 'FORBIDDEN') fail('owner disposition ' + index); if (continuity && entry.ownerBindingContinuity !== 'EXACT_FUTURE_OWNER_BINDING_ROOT_EQUALITY_ACROSS_SCOPE') fail('owner continuity ' + index); equal(entry.scope, expectedScopes[index], 'owner scope ' + index); equal(entry.futurePreimageKeys, ['ownerClass', 'upstreamOwnerContractRoot'], 'owner preimage ' + index); });
  const roots = root.rootProviderCatalog; exactRecord(roots, ['contentDigest', 'entries', 'identifier', 'schema'], 'root provider catalog'); assertArrayIds(roots, ROOT_IDS, 'root provider catalog'); const unknown = new Set(['UPSTREAM_OWNER_CONTRACT_ROOT', 'RETRY_TARGET_ROOT', 'RETRY_TERMINAL_PREDECESSOR_ROOT', 'WORKLOAD_ROOT']); roots.entries.forEach((entry) => { if (entry.rootValueDisposition !== 'OMITTED_UNAVAILABLE_EXTERNAL') fail('root provider omission'); if (unknown.has(entry.id)) { exactRecord(entry, ['domainDisposition', 'futureProviderFields', 'id', 'rootValueDisposition'], 'unknown root ' + entry.id); if (entry.domainDisposition !== 'UNAVAILABLE_EXTERNAL') fail('unknown root disposition'); equal(entry.futureProviderFields, ['digestDomain', 'canonicalization', 'frame', 'futurePreimageKeys', 'futureValidationRules'], 'unknown root fields'); } else { exactRecord(entry, ['canonicalization', 'domain', 'domainDisposition', 'frame', 'futurePreimageKeys', 'id', 'rootValueDisposition'], 'known root ' + entry.id); if (!entry.domain || !entry.canonicalization || !entry.frame || !['RESERVED_TYPE_ONLY', 'INHERITED_STATIC_TYPE_ONLY'].includes(entry.domainDisposition)) fail('known root metadata'); } });
  const orders = root.orderProviderCatalog; exactRecord(orders, ['contentDigest', 'entries', 'identifier', 'schema'], 'order catalog'); assertArrayIds(orders, ORDER_IDS, 'order catalog'); equal(orders.entries[2].order, ['native', 'libauth', 'bchn', 'leanbch'], 'frozen surface order'); equal(orders.entries[3].order, ['native', 'libauth', 'bchn', 'leanbch-primary', 'leanbch-secondary'], 'endpoint control order'); if (orders.entries[4].expectedRootsPerEndpoint !== 4608) fail('workload root cardinality');
  const projections = root.projectionProviderCatalog; exactRecord(projections, ['contentDigest', 'entries', 'identifier', 'schema'], 'projection catalog'); assertArrayIds(projections, PROJECTION_IDS, 'projection catalog'); const workload = projections.entries[0]; exactRecord(workload, ['admissionAllowed', 'futurePreimageKeys', 'grantsAuthority', 'id', 'kWorkerRowBounds', 'projectionDisposition', 'rules', 'targetWorkerRowCount', 'targetWorkerRowCountRelation', 'templates'], 'workload projection'); if (workload.targetWorkerRowCount !== 5 || workload.targetWorkerRowCountRelation !== 'WITHIN_K_WORKER_ROW_BOUNDS' || workload.admissionAllowed || workload.grantsAuthority || workload.projectionDisposition !== 'UNAVAILABLE_EXTERNAL') fail('workload projection disposition'); equal(workload.kWorkerRowBounds, { minimum: 1, maximum: 4096, unit: 'worker-rows-per-dispatch-plan' }, 'workload K bounds'); equal(workload.kWorkerRowBounds, { minimum: kWorkerRowBounds.minimum, maximum: kWorkerRowBounds.maximum, unit: 'worker-rows-per-dispatch-plan' }, 'workload K schema bounds'); equal(workload.rules, ['future-worker-row-count-is-exactly-five', 'K-worker-row-bounds-are-1-through-4096-per-dispatch-plan', 'target-worker-row-count-five-is-within-K-worker-row-bounds', 'each-row-is-one-endpoint-control-row', 'orderedWorkloadRoots-has-exactly-4608-roots-per-endpoint', 'projection-order-encoding-and-material-are-unavailable-external', '4608-workloads-per-endpoint-is-not-4096-worker-rows', 'no-equality-ratio-batching-or-one-workload-per-row'], 'workload projection rules'); equal(workload.templates.map((entry) => [entry.alias, entry.engineLabel, entry.workloadCount]), [['native', 'engine:native', 4608], ['libauth', 'engine:libauth', 4608], ['bchn', 'engine:bchn', 4608], ['leanbch-primary', 'engine:leanbch:primary', 4608], ['leanbch-secondary', 'engine:leanbch:secondary', 4608]], 'projection aliases'); if (projections.entries[2].dispatchOwnerProviderId !== 'PRIVATE_DISPATCH_OWNER_PROVIDER' || projections.entries[2].executionAllowed !== false) fail('dispatch attribution');
  const origins = root.externalOriginProviderCatalog; exactRecord(origins, ['contentDigest', 'entries', 'identifier', 'schema'], 'origin provider catalog'); assertArrayIds(origins, ORIGIN_IDS, 'origin provider catalog'); equal(origins.entries.map((entry) => [entry.originId, entry.ownerProviderId, entry.modelDisposition]), [['RETRY_PREDECESSOR', 'RECOVERY_CHAIN_OWNER_PROVIDER', 'BLOCKED_EXTERNAL'], ['LIVE_F_CAPTURE', 'PRIVATE_CAPTURE_OWNER_PROVIDER', 'UNAVAILABLE_EXTERNAL'], ['WORKER_ROWS_ROOT', 'PRIVATE_DISPATCH_OWNER_PROVIDER', 'BLOCKED_EXTERNAL']], 'origin mappings');
  const facts = root.factProviderCatalog; exactRecord(facts, ['contentDigest', 'entries', 'identifier', 'schema'], 'fact provider catalog'); assertArrayIds(facts, FACT_IDS, 'fact provider catalog'); const byFact = new Map(facts.entries.map((entry) => [entry.factId, entry])); equal(byFact.get('Q').modelDispositionByVariant, { initial: 'CATALOG_ONLY', retry: 'BLOCKED_EXTERNAL', abort: 'CATALOG_ONLY' }, 'Q disposition'); equal(byFact.get('A').modelDispositionByVariant, { initial: 'CATALOG_ONLY', retry: 'DENY_PREREQUISITE', abort: 'CATALOG_ONLY' }, 'A disposition'); equal(byFact.get('LIVE_F').futureValidationRules, ['liveFCaptureRoot-is-an-authenticated-LIVE_F_CAPTURE-root', 'LIVE_F_CAPTURE-and-LIVE_F-require-exact-future-ownerBindingRoot-equality', 'same-owner-class-alone-does-not-prove-owner-continuity', 'LIVE_F-may-precede-Q-or-follow-A', 'LIVE_F-must-precede-B', 'B-does-not-authenticate-LIVE_F_CAPTURE'], 'LIVE_F continuity rules'); equal(byFact.get('D').futureValidationRules, ['state-predecessor-order-is-B-C-J-WORKER_ROWS_ROOT', 'dispatchPlanRoot-binds-workerRowsRoot-and-executionAllowed-false', 'WORKER_ROWS_ROOT-and-D-require-exact-future-ownerBindingRoot-equality', 'same-owner-class-alone-does-not-prove-owner-continuity', 'D-is-never-admitted', 'D-remains-BLOCKED_EXTERNAL', 'D-does-not-satisfy-RETRY_PREDECESSOR'], 'D continuity rules'); equal(byFact.get('J').statePredecessors.initial, ['B', 'C'], 'J predecessors'); if (Object.hasOwn(byFact.get('J'), 'ownerProviderId') || byFact.get('J').ownerDisposition !== 'OWNERLESS' || byFact.get('J').grantsAuthority || byFact.get('D').admissionAllowed || byFact.get('D').modelDispositionByVariant.initial !== 'BLOCKED_EXTERNAL') fail('J/D boundary');
}
function checkBoundary(boundary) { exactRecord(boundary, ['admissionAllowed', 'authorityGrantAllowed', 'capabilityAllowed', 'catalogDigestMaySatisfyFactRoot', 'catalogDigestMaySatisfyOriginRoot', 'catalogDigestMaySatisfyOwnerRoot', 'constructionSurface', 'contentDigest', 'dDisposition', 'endpointImportAllowed', 'executionAllowed', 'factMaterialAllowed', 'guardLiftAllowed', 'j', 'nullPlaceholderAllowed', 'originMaterialAllowed', 'ownerIdentityAllowed', 'ownerInstancesAllowed', 'privateBytesAllowed', 'projectionMaterialAllowed', 'providerInstancesAllowed', 'retryDisposition', 'rootValuesAllowed', 'runtimeImportAllowed', 'unavailableRepresentation', 'writerSurface'], 'non-authority boundary'); for (const key of ['providerInstancesAllowed', 'ownerInstancesAllowed', 'ownerIdentityAllowed', 'capabilityAllowed', 'rootValuesAllowed', 'originMaterialAllowed', 'factMaterialAllowed', 'projectionMaterialAllowed', 'privateBytesAllowed', 'runtimeImportAllowed', 'endpointImportAllowed', 'executionAllowed', 'authorityGrantAllowed', 'admissionAllowed', 'guardLiftAllowed', 'nullPlaceholderAllowed', 'catalogDigestMaySatisfyOwnerRoot', 'catalogDigestMaySatisfyOriginRoot', 'catalogDigestMaySatisfyFactRoot']) if (boundary[key] !== false) fail('boundary ' + key); if (boundary.constructionSurface !== 'none' || boundary.writerSurface !== 'none' || boundary.retryDisposition !== 'BLOCKED_EXTERNAL' || boundary.dDisposition !== 'BLOCKED_EXTERNAL') fail('boundary disposition'); equal(boundary.j, { ownerClass: 'none', ownerProviderAllowed: false, grantsAuthority: false, predecessors: ['B', 'C'] }, 'boundary J'); }
function checkRoot(root, repositoryRoot) {
  exactRecord(root, ['schema', 'identifier', 'status', 'executionAllowed', 'staticDependencies', 'ecocContractPrefix', 'providerCausalDag', 'ownerProviderCatalog', 'rootProviderCatalog', 'orderProviderCatalog', 'projectionProviderCatalog', 'externalOriginProviderCatalog', 'factProviderCatalog', 'nonAuthorityBoundary', 'contentDigest'], 'root');
  if (root.schema !== PREFIX + 'model-root/v1' || root.identifier !== IDENTIFIER || root.status !== STATUS || root.executionAllowed !== false) fail('root identity/status');
  for (const [field, suffix, expected] of COMPONENTS) checkComponent(root[field], suffix, expected, field);
  const actual = semanticDigest(PREFIX + 'model-root', omit(root, 'contentDigest')); checkDescriptor(root.contentDigest, PREFIX + 'model-root', actual, 'root descriptor'); if (actual !== ROOT_DIGEST) fail('root external semantic pin');
  const kWorkerRowBounds = checkStaticDependencies(root.staticDependencies, repositoryRoot); checkECOC(root.ecocContractPrefix, repositoryRoot); checkDag(root.providerCausalDag); checkCatalogs(root, kWorkerRowBounds); checkBoundary(root.nonAuthorityBoundary); checkNoMaterial(root);
}
function checkSchemas(root, packageRoot) {
  const ajv = new Ajv2020({ allErrors: true, strictSchema: true, strictTypes: false });
  const schemas = AUTHORED_FILES.filter((file) => file.startsWith('schemas/')).map((file) => jsonLocal(packageRoot, file));
  schemas.forEach((schema) => ajv.addSchema(schema)); const validate = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/cohort-upstream-origin-provider-contract/v1/model-root.v1.schema.json'); if (!validate || !validate(root)) fail('root schema ' + (validate?.errors ? JSON.stringify(validate.errors) : 'missing'));
}
function checkEnvelope(packageRoot) {
  const manifest = jsonLocal(packageRoot, 'MANIFEST.json'); exactRecord(manifest, ['entries', 'entryCount', 'format', 'package', 'rosterDigest', 'schema'], 'manifest'); if (manifest.entryCount !== 19 || manifest.format !== PREFIX + 'manifest/1' || manifest.package !== IDENTIFIER || manifest.schema !== PREFIX + 'manifest/v1') fail('manifest metadata'); equal(manifest.entries.map((entry) => entry.locator), AUTHORED_FILES, 'manifest roster'); const roster = semanticDigest(PREFIX + 'manifest-roster', AUTHORED_FILES); if (manifest.rosterDigest !== roster) fail('manifest roster digest'); for (const entry of manifest.entries) { exactRecord(entry, ['bytes', 'fileDigest', 'locator', 'sha256'], 'manifest entry ' + entry.locator); const bytes = readLocal(packageRoot, entry.locator); if (entry.bytes !== bytes.length || entry.sha256 !== sha256(bytes) || entry.fileDigest !== rawFileDigest(bytes)) fail('manifest entry ' + entry.locator); }
  const sums = readLocal(packageRoot, 'SHA256SUMS').toString('utf8'); const expected = manifest.entries.map((entry) => entry.sha256 + '  ' + entry.locator).concat([sha256(readLocal(packageRoot, 'MANIFEST.json')) + '  MANIFEST.json']).join('\n') + '\n'; if (sums !== expected) fail('checksum list');
}
function checkSourceBoundary(packageRoot) { const source = readLocal(packageRoot, 'validate-static.mjs').toString('utf8'); if (!source.includes("from 'node:crypto'") || !source.includes("from 'node:fs'") || !source.includes("from 'node:path'") || !source.includes("from 'node:url'") || !source.includes("from 'ajv/dist/2020.js'")) fail('validator import set'); const start = source.indexOf('function checkSourceBoundary'); const end = source.indexOf('\nfunction validateStatic('); const checked = source.slice(0, start) + source.slice(end); if (start < 0 || end < start || /\b(?:child_process|worker_threads|node:vm|WebAssembly|Deno|Bun|fetch|WebSocket|XMLHttpRequest|eval|Function)\b/.test(checked)) fail('validator activation surface'); }
function validateStatic(options = {}) { const packageRoot = options.root ? resolve(options.root) : ROOT; const repositoryRoot = options.repositoryRoot ? resolve(options.repositoryRoot) : REPOSITORY_ROOT; const allowUnsealed = options.allowUnsealed === true; checkFilesystem(packageRoot, allowUnsealed, options.allowTemporaryMetadata === true); const root = jsonLocal(packageRoot, 'upstream-origin-provider-contract-root.v1.json'); checkSchemas(root, packageRoot); checkRoot(root, repositoryRoot); checkSourceBoundary(packageRoot); if (!allowUnsealed) checkEnvelope(packageRoot); return { identifier: IDENTIFIER, rootDigest: ROOT_DIGEST, sealed: !allowUnsealed, files: allowUnsealed ? 19 : 21 }; }

export { AUTHORED_FILES, PREFIX, canonicalJson, rawFileDigest, semanticDigest, validateStatic };

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) { validateStatic(); process.stdout.write('cohort-upstream-origin-provider-contract-v1 static validation: PASS\n'); }
