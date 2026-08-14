import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const ROOT = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(ROOT, '../../../../../');
const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-external-origin-contract/v1/';
const IDENTIFIER = 'cohort-external-origin-contract-v1';
const STATUS = 'static-external-origin-contract-catalog-no-instances-non-authorizing-origins-unavailable-unqualified';
const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
const FRAME = 'utf8(domain)||0x00||canonical-json-utf8-lf-v1';
const ROOT_DIGEST = '6aab36a2a185207da03c364066f9f791cf2710408798b1d93ef61618177f6e60';
const DIRECTORIES = Object.freeze(['.', 'schemas', 'test']);
const AUTHORED_FILES = Object.freeze([
  'COMMAND.txt',
  'README.md',
  'external-origin-contract-root.v1.json',
  'validate-static.mjs',
  'schemas/causal-dag.v1.schema.json',
  'schemas/dependency-catalog.v1.schema.json',
  'schemas/ownership-catalog.v1.schema.json',
  'schemas/retry-predecessor-contract.v1.schema.json',
  'schemas/live-f-capture-contract.v1.schema.json',
  'schemas/worker-rows-root-contract.v1.schema.json',
  'schemas/workload-projection-contract.v1.schema.json',
  'schemas/fact-contract-catalog.v1.schema.json',
  'schemas/digest.v1.schema.json',
  'schemas/model-root.v1.schema.json',
  'schemas/manifest.v1.schema.json',
  'test/digest.kat.json',
  'test/static.test.mjs',
  'test/mutation.test.mjs',
  'test/package-boundary.test.mjs',
]);
const SCHEMA_SHA256 = Object.freeze({
  'schemas/causal-dag.v1.schema.json': '7e007119b5f6ac8c9a96b9671c23ac1b6583ddff8f4eafc6f1bdbba5d9dbc9a7',
  'schemas/dependency-catalog.v1.schema.json': '58922f244814cb5fc8b7157656e819df848f4a3952e5d4e7fe327adfca549113',
  'schemas/ownership-catalog.v1.schema.json': '849ae289e78ece3bc7c3af2a622d871405005281568ecf5becf88a4f0028bdea',
  'schemas/retry-predecessor-contract.v1.schema.json': '6ea4c9d02f7fda279ddc2133f16b3ad9c6ab9d64b2161d17c8d9c415532eadbb',
  'schemas/live-f-capture-contract.v1.schema.json': '5e67dcea8d5c1b237adef0d5ca24f26504478bed378e784ae53b6ed6bd859818',
  'schemas/worker-rows-root-contract.v1.schema.json': 'bef9d705540dc92f1df06d9bd072dec3846f99801a85dbc804abb47621a36cdd',
  'schemas/workload-projection-contract.v1.schema.json': '62b81bdffda0c00351601fa17ceaf01424a41f89a11c307f487a1c1cb84657d4',
  'schemas/fact-contract-catalog.v1.schema.json': 'bbc59c8a04574512193a7aac74313545ecc8511b9fcf49fe47bb73d8770c867f',
  'schemas/digest.v1.schema.json': 'f018b61a2fc9403a02174fc064e30fd307fbe11a7ac240af0a1e0b6f5b36c5b7',
  'schemas/model-root.v1.schema.json': 'd3e14130f8d495249e52b1dee8dff9d0cf601314295a64084ac7af94332a7a81',
  'schemas/manifest.v1.schema.json': '09739a2223bb50995bcc12e2c741f9c8d9be7c03a063d611665787f87be47e06',
});
const CABM_NODES = Object.freeze(['N', 'E', 'X', 'SOURCE', 'COHORT', 'R', 'K', 'F', 'P', 'Q', 'A', 'B', 'C', 'J', 'D', 'LIVE_F', 'WORKER_ROWS_ROOT']);
const CABM_EDGES = Object.freeze(['N→R', 'E→R', 'X→R', 'SOURCE→F', 'COHORT→F', 'R→P', 'K→P', 'F→P', 'Q→A', 'P→A', 'A→B', 'P→B', 'R→B', 'K→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D']);
const EXTERNAL_NODES = Object.freeze(['RETRY_PREDECESSOR', 'LIVE_F_CAPTURE', 'WORKER_ROWS_ROOT', 'Q_INITIAL', 'Q_RETRY', 'Q_ABORT', 'A_INITIAL', 'A_RETRY', 'A_ABORT', 'LIVE_F', 'B', 'C', 'J', 'D']);
const EXTERNAL_EDGES = Object.freeze(['RETRY_PREDECESSOR→Q_RETRY', 'Q_INITIAL→A_INITIAL', 'Q_RETRY→A_RETRY', 'Q_ABORT→A_ABORT', 'LIVE_F_CAPTURE→LIVE_F', 'A_INITIAL→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D']);

function fail(message) {
  throw new Error('cohort-external-origin-contract-v1 static validation: ' + message);
}

function exactRecord(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(label + ' must be a plain record');
  const actual = Reflect.ownKeys(value);
  for (const key of actual) {
    if (typeof key !== 'string') fail(label + ' has a symbol key');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail(label + ' has a non-data key');
  }
  const left = actual.slice().sort();
  const right = keys.slice().sort();
  if (left.length !== right.length || left.some((key, index) => key !== right[index])) fail(label + ' key set differs');
  return value;
}

function canonicalJson(value, stack = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail('canonical JSON rejects number');
    return String(value);
  }
  if (value === null || typeof value !== 'object') fail('canonical JSON rejects value');
  if (stack.has(value)) fail('canonical JSON rejects cycle');
  stack.add(value);
  let encoded;
  if (Array.isArray(value)) {
    const own = Reflect.ownKeys(value);
    if (own.length !== value.length + 1 || !own.includes('length')) fail('canonical JSON rejects array shape');
    encoded = '[' + value.map((item) => canonicalJson(item, stack)).join(',') + ']';
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail('canonical JSON rejects prototype');
    const keys = Reflect.ownKeys(value);
    for (const key of keys) {
      if (typeof key !== 'string') fail('canonical JSON rejects symbol');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('canonical JSON rejects record shape');
    }
    encoded = '{' + keys.sort().map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key], stack)).join(',') + '}';
  }
  stack.delete(value);
  return encoded;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const TRUSTED_VALIDATOR_RAW = sha256(readFileSync(fileURLToPath(import.meta.url)));

function semanticDigest(domain, value) {
  return sha256(Buffer.from(domain + '\u0000' + canonicalJson(value) + '\n', 'utf8'));
}

function rawFileDigest(bytes) {
  return sha256(Buffer.concat([Buffer.from(PREFIX + 'file\u0000', 'utf8'), bytes]));
}

function descriptor(domain, value) {
  return { algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value };
}

function without(object, key) {
  const copy = {};
  for (const name of Object.keys(object)) if (name !== key) copy[name] = object[name];
  return copy;
}

function equal(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) fail(label + ' differs');
}

function parseCanonical(bytes, locator) {
  const text = bytes.toString('utf8');
  if (!text.endsWith('\n') || text.endsWith('\n\n')) fail(locator + ' final LF');
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail(locator + ' JSON parse');
  }
  if (text !== canonicalJson(value) + '\n') fail(locator + ' canonical JSON');
  return value;
}

function parseUpstreamJson(bytes, locator) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(locator + ' upstream JSON parse');
  }
}

function localPath(root, locator) {
  if (typeof locator !== 'string' || locator.length === 0 || isAbsolute(locator) || locator.includes('\\') || locator.split('/').includes('..')) fail('unsafe local locator');
  const target = resolve(root, locator);
  const rel = relative(root, target);
  if (rel === '' || rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) fail('local locator escapes');
  return target;
}

function readLocal(root, locator) {
  const target = localPath(root, locator);
  const info = lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) fail(locator + ' regular file/nlink');
  return readFileSync(target);
}

function jsonLocal(root, locator) {
  return parseCanonical(readLocal(root, locator), locator);
}

function collect(root, current, found) {
  const target = current === '.' ? root : localPath(root, current);
  const info = lstatSync(target);
  if (!info.isDirectory() || info.isSymbolicLink()) fail(current + ' directory');
  found.dirs.push(current);
  for (const name of readdirSync(target).sort()) {
    const locator = current === '.' ? name : current + '/' + name;
    const child = localPath(root, locator);
    const childInfo = lstatSync(child);
    if (childInfo.isSymbolicLink()) fail(locator + ' link');
    if (childInfo.isDirectory()) collect(root, locator, found);
    else if (childInfo.isFile()) found.files.push(locator);
    else fail(locator + ' filesystem type');
  }
}

function checkFilesystem(root, allowUnsealed, allowTemporaryMetadata) {
  const rootInfo = lstatSync(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || realpathSync(root) !== resolve(root)) fail('package root');
  if (!allowTemporaryMetadata && (rootInfo.nlink !== 1 || (rootInfo.mode & 0o777) !== 0o755)) fail('package root metadata');
  const found = { dirs: [], files: [] };
  collect(root, '.', found);
  const expected = allowUnsealed ? AUTHORED_FILES.slice() : AUTHORED_FILES.concat(['MANIFEST.json', 'SHA256SUMS']);
  equal(found.dirs.slice().sort(), DIRECTORIES.slice().sort(), 'directory closure');
  equal(found.files.slice().sort(), expected.slice().sort(), 'file closure');
  for (const locator of found.dirs) {
    const info = lstatSync(locator === '.' ? root : localPath(root, locator));
    if (!allowTemporaryMetadata && (info.nlink !== 1 || (info.mode & 0o777) !== 0o755)) fail(locator + ' directory mode/nlink');
  }
  for (const locator of found.files) {
    const info = lstatSync(localPath(root, locator));
    if (!allowTemporaryMetadata && (info.nlink !== 1 || (info.mode & 0o777) !== 0o644)) fail(locator + ' file mode/nlink');
  }
  if (allowUnsealed && (found.files.includes('MANIFEST.json') || found.files.includes('SHA256SUMS'))) fail('partial envelope');
}

function checkComponent(component, domain, label) {
  if (component === null || typeof component !== 'object' || Array.isArray(component) || !Object.hasOwn(component, 'contentDigest')) fail(label + ' contentDigest missing');
  equal(component.contentDigest, descriptor(domain, semanticDigest(domain, without(component, 'contentDigest'))), label + ' contentDigest');
}

function checkNoMaterial(value, context) {
  if (value === null) fail('null forbidden at ' + context);
  if (Array.isArray(value)) {
    value.forEach((item, index) => checkNoMaterial(item, context + '/' + index));
    return;
  }
  if (typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    if (key === 'futurePreimageKeys') continue;
    if (['ownerBindingRoot', 'targetRoot', 'predecessorRoot', 'retryPredecessorRoot', 'liveFCaptureRoot', 'workerRowsRoot', 'dispatchPlanRoot', 'privateBytes', 'projectionBytes', 'identity', 'capability', 'instance'].includes(key)) fail('value material forbidden at ' + context + '/' + key);
    checkNoMaterial(item, context + '/' + key);
  }
}

function checkSemantic(root) {
  exactRecord(root, ['cabmAuthorityPrefix', 'contentDigest', 'executionAllowed', 'externalCausalDag', 'externalOriginContracts', 'factContracts', 'identifier', 'nonAuthorityBoundary', 'ownershipCatalog', 'rootDomainCatalog', 'schema', 'staticDependencies', 'status', 'workloadProjectionContract'], 'root');
  if (root.identifier !== IDENTIFIER || root.schema !== PREFIX + 'model-root/v1' || root.status !== STATUS || root.executionAllowed !== false) fail('root identity');
  checkNoMaterial(root, '');
  checkComponent(root.staticDependencies, PREFIX + 'dependency-catalog', 'staticDependencies');
  checkComponent(root.cabmAuthorityPrefix, PREFIX + 'cabm-authority-prefix', 'cabmAuthorityPrefix');
  checkComponent(root.externalCausalDag, PREFIX + 'external-causal-dag', 'externalCausalDag');
  checkComponent(root.ownershipCatalog, PREFIX + 'ownership-catalog', 'ownershipCatalog');
  checkComponent(root.externalOriginContracts, PREFIX + 'external-origin-contracts', 'externalOriginContracts');
  checkComponent(root.factContracts, PREFIX + 'fact-contracts', 'factContracts');
  checkComponent(root.rootDomainCatalog, PREFIX + 'root-domain-catalog', 'rootDomainCatalog');
  checkComponent(root.workloadProjectionContract, PREFIX + 'workload-projection-contract', 'workloadProjectionContract');
  equal(root.contentDigest, descriptor(PREFIX + 'root', semanticDigest(PREFIX + 'root', without(root, 'contentDigest'))), 'root contentDigest');
  if (root.contentDigest.value !== ROOT_DIGEST) fail('root semantic digest pin');
  if (root.cabmAuthorityPrefix.nodeCount !== 17 || root.cabmAuthorityPrefix.edgeCount !== 22 || canonicalJson(root.cabmAuthorityPrefix.nodes) !== canonicalJson(CABM_NODES) || canonicalJson(root.cabmAuthorityPrefix.edges) !== canonicalJson(CABM_EDGES) || root.cabmAuthorityPrefix.sourceDependencyId !== 'CABM' || root.cabmAuthorityPrefix.sourceField !== 'pinnedAuthorityDag' || root.cabmAuthorityPrefix.sourceSemanticDigest !== '66559720074ff58ce80f13fd031d4e5cb807e4bf8adff69690b1c3d91dd284d1') fail('CABM prefix');
  if (root.externalCausalDag.nodeCount !== 14 || root.externalCausalDag.edgeCount !== 14 || canonicalJson(root.externalCausalDag.nodes) !== canonicalJson(EXTERNAL_NODES) || canonicalJson(root.externalCausalDag.edges) !== canonicalJson(EXTERNAL_EDGES) || root.externalCausalDag.staticDependencyEdgesAllowed !== false) fail('external causal DAG');
  if (root.staticDependencies.entries.length !== 29 || root.externalOriginContracts.entries.length !== 3 || root.factContracts.entries.length !== 7 || root.ownershipCatalog.entries.length !== 10 || root.rootDomainCatalog.entries.length !== 14) fail('catalog count');
  if (root.externalOriginContracts.entries.some((entry) => entry.availability !== 'unavailable' || entry.admissionAllowed !== false || entry.grantsAuthority !== false) || root.factContracts.entries.some((entry) => entry.admissionAllowed !== false || entry.grantsAuthority !== false) || root.ownershipCatalog.entries.some((entry) => entry.grantsAuthority !== false)) fail('grant/admission');
  if (root.workloadProjectionContract.targetWorkerRowCount !== 5 || root.workloadProjectionContract.workloadTemplate.value !== 4608 || root.workloadProjectionContract.kWorkerRowBounds.minimum !== 1 || root.workloadProjectionContract.kWorkerRowBounds.maximum !== 4096 || root.workloadProjectionContract.projectionDisposition !== 'UNAVAILABLE_EXTERNAL' || root.workloadProjectionContract.grantsAuthority !== false) fail('workload projection');
  if (root.nonAuthorityBoundary.admissionAllowed !== false || root.nonAuthorityBoundary.authorityGrantAllowed !== false || root.nonAuthorityBoundary.executionAllowed !== false || root.nonAuthorityBoundary.runtimeImportAllowed !== false || root.nonAuthorityBoundary.externalOriginMaterialAllowed !== false || root.nonAuthorityBoundary.factMaterialAllowed !== false || root.nonAuthorityBoundary.nullPlaceholderAllowed !== false || root.nonAuthorityBoundary.omittedValueMembersRequired !== true) fail('non-authority boundary');
}

function safeUpstreamRead(repositoryRoot, locator) {
  const required = 'research-lanes/bch-shielded-pool-design/p2/gate-b/';
  if (typeof locator !== 'string' || !locator.startsWith(required) || isAbsolute(locator) || locator.includes('\\') || locator.split('/').includes('..')) fail('unsafe upstream locator');
  const gate = resolve(repositoryRoot, 'research-lanes/bch-shielded-pool-design/p2/gate-b');
  const target = resolve(repositoryRoot, locator);
  const containment = relative(gate, target);
  if (containment === '' || containment === '..' || containment.startsWith('..' + sep) || isAbsolute(containment)) fail('upstream containment');
  let current = repositoryRoot;
  for (const part of relative(repositoryRoot, target).split(sep)) {
    if (!part) continue;
    current = join(current, part);
    if (lstatSync(current).isSymbolicLink()) fail('upstream symlink component');
  }
  const info = lstatSync(target);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || realpathSync(target) !== target || realpathSync(gate) !== gate) fail('upstream leaf type/containment');
  return readFileSync(target);
}

function primaryRoot(root, dependencyId) {
  const entry = root.staticDependencies.entries.find((item) => item.dependencyId === dependencyId && item.role === 'primary-root');
  if (!entry) fail('missing primary root ' + dependencyId);
  return parseUpstreamJson(safeUpstreamRead(REPOSITORY_ROOT, entry.locator), entry.locator);
}

function checkUpstream(root) {
  exactRecord(root.staticDependencies, ['contentDigest', 'entries', 'identifier', 'schema', 'validationMode'], 'staticDependencies');
  if (root.staticDependencies.identifier !== IDENTIFIER || root.staticDependencies.schema !== PREFIX + 'dependency-catalog/v1' || root.staticDependencies.validationMode !== 'read-regular-file-bytes-only-no-import-no-evaluation') fail('static dependency identity');
  const locators = new Set();
  for (const entry of root.staticDependencies.entries) {
    exactRecord(entry, ['dependencyId', 'locator', 'rawSha256', 'role'], 'static dependency leaf');
    if (locators.has(entry.locator)) fail('duplicate upstream locator');
    locators.add(entry.locator);
    if (sha256(safeUpstreamRead(REPOSITORY_ROOT, entry.locator)) !== entry.rawSha256) fail('upstream raw pin ' + entry.locator);
  }
  const r = primaryRoot(root, 'R');
  const rManifestEntry = root.staticDependencies.entries.find((entry) => entry.dependencyId === 'R' && entry.role === 'manifest');
  const f = primaryRoot(root, 'F');
  const p = primaryRoot(root, 'P');
  const v2 = primaryRoot(root, 'V2');
  const cabm = primaryRoot(root, 'CABM');
  const workerEntry = root.staticDependencies.entries.find((entry) => entry.role === 'worker-row-schema');
  const dispatchEntry = root.staticDependencies.entries.find((entry) => entry.role === 'dispatch-plan-schema');
  if (!rManifestEntry || !workerEntry || !dispatchEntry) fail('required upstream leaf missing');
  const rManifest = parseUpstreamJson(safeUpstreamRead(REPOSITORY_ROOT, rManifestEntry.locator), rManifestEntry.locator);
  const worker = parseUpstreamJson(safeUpstreamRead(REPOSITORY_ROOT, workerEntry.locator), workerEntry.locator);
  const dispatch = parseUpstreamJson(safeUpstreamRead(REPOSITORY_ROOT, dispatchEntry.locator), dispatchEntry.locator);
  const engineOrder = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch:primary', 'engine:leanbch:secondary'];
  if (r.runtimeAuthority?.common?.expectedRows !== 4608 || canonicalJson(r.runtimeAuthority?.common?.endpointOrder) !== canonicalJson(engineOrder) || typeof r.contentDigest?.value !== 'string') fail('R projection');
  if (typeof rManifest.contentDigest !== 'string') fail('R manifest direct contentDigest');
  if (worker.properties?.endpointId?.pattern !== '^[a-z][a-z0-9-]{2,63}$' || dispatch.properties?.workerRows?.minItems !== 1 || dispatch.properties?.workerRows?.maxItems !== 4096 || dispatch.properties?.executionAllowed?.const !== false) fail('K schema projection');
  if (f.contentDigest?.value !== '7f00510e5c4b8b4959b572c9c9ece8e97ca95174b5715c2ee0852ef79f28b08f' || f.executionAllowed !== false) fail('F projection');
  const expectedAliases = { native: 'engine:native', libauth: 'engine:libauth', bchn: 'engine:bchn', 'leanbch-primary': 'engine:leanbch:primary', 'leanbch-secondary': 'engine:leanbch:secondary' };
  if (canonicalJson(p.policy?.aliasMap) !== canonicalJson(expectedAliases) || !Array.isArray(p.policy?.kLaunchAuthority) || p.policy.kLaunchAuthority.length !== 5 || p.policy.kLaunchAuthority.some((item) => item.workloads !== 4608) || p.policy?.liveF?.contentDigest?.value !== '083b7679437170c36083612d108206ed47329f432011439f8e4b38c61b5616be') fail('P projection');
  if (canonicalJson(v2.authorityDag?.nodes) !== canonicalJson(CABM_NODES) || canonicalJson(v2.authorityDag?.edges) !== canonicalJson(CABM_EDGES) || v2.transitionGrammar?.externalGuards?.retryQ !== 'RETRY_PREDECESSOR' || v2.transitionGrammar?.externalGuards?.d !== 'WORKER_ROWS_ROOT') fail('V2 projection');
  if (canonicalJson(cabm.pinnedAuthorityDag?.nodes) !== canonicalJson(CABM_NODES) || canonicalJson(cabm.pinnedAuthorityDag?.edges) !== canonicalJson(CABM_EDGES) || cabm.externalOrigins?.entries?.length !== 3 || cabm.facts?.entries?.length !== 7 || cabm.externalOrigins.entries.some((entry) => entry.grantsAuthority !== false) || cabm.facts.entries.some((entry) => entry.grantsAuthority !== false) || cabm.stateGrammar?.retry?.qDisposition !== 'BLOCKED_EXTERNAL' || cabm.stateGrammar?.d?.disposition !== 'BLOCKED_EXTERNAL') fail('CABM projection');
}

function checkSchemas(root, document, sealed) {
  const schemas = {};
  for (const [locator, expected] of Object.entries(SCHEMA_SHA256)) {
    const bytes = readLocal(root, locator);
    if (sha256(bytes) !== expected) fail('schema raw pin ' + locator);
    schemas[locator] = parseCanonical(bytes, locator);
  }
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const schema of Object.values(schemas)) ajv.addSchema(schema);
  const validateRoot = ajv.getSchema(schemas['schemas/model-root.v1.schema.json'].$id);
  if (!validateRoot || !validateRoot(document)) fail('root schema ' + ajv.errorsText(validateRoot?.errors));
  if (sealed) {
    const manifest = jsonLocal(root, 'MANIFEST.json');
    const validateManifest = ajv.getSchema(schemas['schemas/manifest.v1.schema.json'].$id);
    if (!validateManifest || !validateManifest(manifest)) fail('manifest schema ' + ajv.errorsText(validateManifest?.errors));
  }
}

function checkCodeBoundary(root) {
  const source = readLocal(root, 'validate-static.mjs').toString('utf8');
  if (sha256(Buffer.from(source, 'utf8')) !== TRUSTED_VALIDATOR_RAW) fail('externally pinned validator raw');
  const imports = [...source.matchAll(/(?:^|\n)import\s+(?:[^'"\n]+\s+from\s+)?['"]([^'"]+)['"]/g)].map((match) => match[1]).sort();
  equal(imports, ['ajv/dist/2020.js', 'node:crypto', 'node:fs', 'node:path', 'node:url'], 'validator imports');
  const exportToken = ['ex', 'port'].join('');
  const terminalExport = exportToken + ' { rawFileDigest, semanticDigest, validateStatic };';
  if (new RegExp('\\b' + exportToken + '\\b').test(source.replace(terminalExport, ''))) fail('validator public surface');
  if (/\bimport\s*\(|\brequire\s*\(|\bwriteFile|\bappendFile|\bmkdir|\brmSync|\bspawn|\bexec\b|\bfork\b|\bworker_threads\b|\bchild_process\b|\bnode:vm\b|\bnode:net\b|\bnode:http\b|\bnode:https\b|\bWebSocket\b|\bXMLHttpRequest\b|\bWebAssembly\b/.test(source)) fail('validator activation surface');
}

function checkManifest(root) {
  const manifest = jsonLocal(root, 'MANIFEST.json');
  const entries = AUTHORED_FILES.map((locator) => {
    const bytes = readLocal(root, locator);
    return { bytes: bytes.length, fileDigest: rawFileDigest(bytes), locator, sha256: sha256(bytes) };
  });
  const expected = { entries, entryCount: AUTHORED_FILES.length, format: PREFIX + 'manifest/1', package: IDENTIFIER, rosterDigest: semanticDigest(PREFIX + 'manifest-roster', { package: IDENTIFIER, entries }), schema: PREFIX + 'manifest/v1' };
  equal(manifest, expected, 'manifest');
  const lines = entries.concat([{ locator: 'MANIFEST.json', sha256: sha256(readLocal(root, 'MANIFEST.json')) }]).map((entry) => entry.sha256 + '  ' + entry.locator);
  if (readLocal(root, 'SHA256SUMS').toString('utf8') !== lines.join('\n') + '\n') fail('SHA256SUMS');
}

function validateStatic({ root = ROOT, allowTemporaryMetadata = false, allowUnsealed = false } = {}) {
  checkFilesystem(root, allowUnsealed, allowTemporaryMetadata);
  checkCodeBoundary(root);
  const document = jsonLocal(root, 'external-origin-contract-root.v1.json');
  checkSemantic(document);
  checkUpstream(document);
  checkSchemas(root, document, !allowUnsealed);
  if (!allowUnsealed) checkManifest(root);
  return true;
}

function cliOptions() {
  const args = process.argv.slice(2);
  if (args.length === 0) return { allowUnsealed: false };
  if (args.length === 1 && args[0] === '--unsealed') return { allowUnsealed: true };
  fail('usage: node validate-static.mjs [--unsealed]');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    validateStatic(cliOptions());
    process.stdout.write('static validation: PASS\n');
  } catch (error) {
    process.stderr.write(error.message + '\n');
    process.exitCode = 1;
  }
}

export { rawFileDigest, semanticDigest, validateStatic };
