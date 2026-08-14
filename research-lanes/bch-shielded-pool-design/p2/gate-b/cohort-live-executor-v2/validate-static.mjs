import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const ROOT = dirname(fileURLToPath(import.meta.url));
const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-live-executor/v2/';
const FRAME = 'utf8(domain)||0x00||canonical-json-utf8-lf-v1';
const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
const P_ROOT_PATH = resolve(ROOT, '..', 'cohort-policy-authority-v1', 'policy-authority-root.v1.json');
const P_RAW_SHA256 = 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e';
const P_DOWNSTREAM = Object.freeze(['J→JOURNAL', 'D→JOURNAL', 'J→OBSERVATION', 'D→OBSERVATION', 'J→TERMINAL', 'D→TERMINAL']);
const NODES = Object.freeze(['N', 'E', 'X', 'SOURCE', 'COHORT', 'R', 'K', 'F', 'P', 'Q', 'A', 'B', 'C', 'J', 'D', 'LIVE_F', 'WORKER_ROWS_ROOT']);
const EDGES = Object.freeze(['N→R', 'E→R', 'X→R', 'SOURCE→F', 'COHORT→F', 'R→P', 'K→P', 'F→P', 'Q→A', 'P→A', 'A→B', 'P→B', 'R→B', 'K→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D']);
const DIRECTORIES = Object.freeze(['.', 'schemas', 'src', 'test']);
const FILES = Object.freeze([
  'COMMAND.txt', 'README.md', 'model-root.v2.json', 'validate-static.mjs',
  'schemas/authority-dag.v2.schema.json', 'schemas/digest.v2.schema.json', 'schemas/manifest.v1.schema.json', 'schemas/model-root.v2.schema.json', 'schemas/state.v2.schema.json', 'schemas/transition-grammar.v2.schema.json',
  'src/canonical.mjs', 'src/model.mjs', 'src/sha256.mjs', 'src/state-machine.mjs',
  'test/digest.kat.json', 'test/digest.test.mjs', 'test/model.test.mjs', 'test/mutation.test.mjs', 'test/package-boundary.test.mjs', 'test/state-machine.test.mjs',
]);
const SCHEMA_SHA256 = Object.freeze({
  'schemas/authority-dag.v2.schema.json': 'af86c57dec3ef24f74d9c6c97c1a3d8fcf8349e3dc8e4809a011c0e784fa184f',
  'schemas/digest.v2.schema.json': 'dd6973b97e84c5ac71fa19e2403c0f0e3f2bfadc53d5198194b1c1aa65daed00',
  'schemas/manifest.v1.schema.json': '71c4730d391dfe8f2313dd94254c80d35ce01fcffebe9645548d0151023dc584',
  'schemas/model-root.v2.schema.json': '8bdaa575e011cbcbfbcf4bfce33c48a3338202010108bdbf6fa280c24039c4f1',
  'schemas/state.v2.schema.json': '2b25381aae0344a66dda8f846c1262e29e943f75a136a10dff666175c2df8950',
  'schemas/transition-grammar.v2.schema.json': 'f64bfe0606074f3a21fdeaa58503376ac95501eb51caf2a9b53e30c701d9777d',
});

function fail(message) { throw new Error(`static validation failed: ${message}`); }
function scalar(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) fail('lone surrogate in JSON');
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) fail('lone surrogate in JSON');
  }
}
function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') { scalar(value); return JSON.stringify(value); }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail('noncanonical number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value !== 'object' || value === null || Object.getPrototypeOf(value) !== Object.prototype) fail('nonplain JSON record');
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
function rawSha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function framedDigest(domain, value) {
  return createHash('sha256').update(Buffer.from(`${domain}\u0000${canonical(value)}\n`, 'utf8')).digest('hex');
}
function rawFileDigest(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('raw file digest input must be bytes');
  return createHash('sha256').update(Buffer.from(`${PREFIX}file\u0000`, 'utf8')).update(bytes).digest('hex');
}
function read(root, locator) { return readFileSync(resolve(root, locator)); }
function json(root, locator) {
  const bytes = read(root, locator);
  if (bytes.includes(0x0d)) fail(`${locator} has CR bytes`);
  const text = bytes.toString('utf8');
  let value;
  try { value = JSON.parse(text); } catch { fail(`${locator} is not JSON`); }
  if (text !== `${canonical(value)}\n`) fail(`${locator} is not canonical JSON plus one final LF`);
  return value;
}
function equal(left, right, label) { if (canonical(left) !== canonical(right)) fail(`${label} differs`); }
function descriptor(domain, value) {
  return { algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value };
}
function collect(root, directory = root, prefix = '') {
  const files = [];
  const directories = [prefix || '.'];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const locator = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = resolve(directory, entry.name);
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) fail(`${locator} is a link`);
    if (stat.isDirectory()) {
      const nested = collect(root, absolute, locator);
      files.push(...nested.files);
      directories.push(...nested.directories);
    } else if (stat.isFile()) files.push(locator);
    else fail(`${locator} is not a regular file or directory`);
  }
  return { files, directories };
}
function checkFilesystem(root) {
  const found = collect(root);
  equal(found.directories.sort(), [...DIRECTORIES].sort(), 'package directories');
  const expected = [...FILES, 'MANIFEST.json', 'SHA256SUMS'].sort();
  equal(found.files.sort(), expected, 'package closure');
  for (const locator of DIRECTORIES) {
    const stat = lstatSync(resolve(root, locator));
    if (!stat.isDirectory() || (stat.mode & 0o7777) !== 0o755) fail(`${locator} has wrong directory mode`);
  }
  for (const locator of expected) {
    const stat = lstatSync(resolve(root, locator));
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o7777) !== 0o644) fail(`${locator} is not a 0644 single-link regular file`);
    if (read(root, locator).includes(0x0d)) fail(`${locator} has CR bytes`);
  }
}
function checkPureClosure(root) {
  const imports = {
    'src/canonical.mjs': [],
    'src/sha256.mjs': [],
    'src/model.mjs': ['./canonical.mjs', './sha256.mjs'],
    'src/state-machine.mjs': ['./model.mjs'],
  };
  const exports = {
    'src/canonical.mjs': ['canonicalJson', 'utf8Encode'],
    'src/sha256.mjs': ['sha256Hex'],
    'src/model.mjs': ['AUTHORITY_DAG', 'TRANSITION_GRAMMAR', 'VARIANTS', 'FACTS', 'EVENTS', 'VERDICTS', 'assertAuthorityDag', 'assertTransitionGrammar', 'requiredPredecessors', 'authorityDagDigest', 'transitionGrammarDigest', 'modelRootDigest', 'stateDigest'],
    'src/state-machine.mjs': ['emptyState', 'assertState', 'guardTransition', 'transition', 'replay'],
  };
  const forbidden = /node:|\bimport\.meta\b|\bimport\s*\(|\brequire\s*\(|\b(?:eval|Function|globalThis|WebAssembly|Deno|Bun|Worker|SharedWorker|process|setTimeout|setInterval|queueMicrotask|fetch|WebSocket|XMLHttpRequest|child_process|vm|net|http|https)\b/;
  for (const [locator, expected] of Object.entries(imports)) {
    const source = read(root, locator).toString('utf8');
    if (forbidden.test(source)) fail(`${locator} has a forbidden pure-surface token`);
    const actual = [
      ...source.matchAll(/\bimport\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/g),
      ...source.matchAll(/\bexport\s+(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/g),
    ].map((match) => match[1]);
    if (actual.some((specifier) => !specifier.startsWith('./'))) fail(`${locator} has a nonrelative specifier`);
    equal(actual, expected, `${locator} imports`);
    const match = source.match(/export\s*\{([\s\S]*?)\};\s*$/);
    if (!match) fail(`${locator} lacks a terminal exact export list`);
    if (/\bexport\b/.test(source.slice(0, match.index))) fail(`${locator} has an additional export surface`);
    const actualExports = match[1].split(',').map((name) => name.trim()).filter(Boolean);
    equal(actualExports, exports[locator], `${locator} exports`);
  }
}
function expectedGrammar() {
  return {
    schema: `${PREFIX}transition-grammar/v2`, identifier: 'cohort-live-executor-v2',
    variants: ['initial', 'retry', 'abort'], facts: ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D'],
    events: ['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F', 'MATCH_B', 'MATCH_C', 'MATCH_J', 'MATCH_D', 'CLOSE_ABORT'],
    verdicts: ['ALLOW', 'BLOCKED_EXTERNAL', 'DENY_VARIANT', 'DENY_PREREQUISITE', 'DENY_DUPLICATE', 'DENY_CLOSED', 'DENY_UNKNOWN'],
    state: { schema: `${PREFIX}state/v2`, keys: ['schema', 'identifier', 'variant', 'facts', 'phase'], phases: ['open', 'abort-closed'], orderedUniqueFacts: true, neverAdmitted: ['D'] },
    externalGuards: { retryQ: 'RETRY_PREDECESSOR', d: 'WORKER_ROWS_ROOT' },
    admission: {
      initial: { allowedEvents: ['MATCH_Q', 'MATCH_A', 'MATCH_LIVE_F', 'MATCH_B', 'MATCH_C', 'MATCH_J', 'MATCH_D'], initialFacts: ['Q', 'LIVE_F'] },
      retry: { allowedEvents: ['MATCH_Q', 'MATCH_A'], retryQ: 'BLOCKED_EXTERNAL', stateAlwaysEmpty: true },
      abort: { allowedEvents: ['MATCH_Q', 'MATCH_A', 'CLOSE_ABORT'], allowedFacts: ['Q', 'A'], close: 'abort-closed' },
    },
    j: { grantsAuthority: false, predecessors: ['B', 'C'] },
    predecessors: { Q: [], A: ['Q'], LIVE_F: [], B: ['A', 'LIVE_F'], C: ['B'], J: ['B', 'C'], D: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'] },
  };
}
function checkAuthority(rootDocument, pRootPath) {
  const pBytes = readFileSync(pRootPath);
  if (rawSha256(pBytes) !== P_RAW_SHA256) fail('P raw SHA-256 pin changed');
  const p = JSON.parse(pBytes.toString('utf8'));
  const pBinding = {
    schema: p.schema, artifactId: p.artifactId,
    path: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-policy-authority-v1/policy-authority-root.v1.json',
    rawSha256: P_RAW_SHA256, contentDigest: p.contentDigest?.value, bindingDigest: p.bindingRoot?.value,
    policyDigest: p.policy?.contentDigest?.value, authorityDagDigest: p.causalDagRoot?.value, liveFDigest: p.policy?.liveF?.contentDigest?.value,
  };
  const pins = ['schema', 'artifactId', 'path', 'rawSha256', 'contentDigest', 'bindingDigest', 'policyDigest', 'authorityDagDigest', 'liveFDigest'];
  if (pins.some((pin) => typeof pBinding[pin] !== 'string')) fail('P semantic pin projection is incomplete');
  equal(p.causalDag?.nodes?.slice(0, NODES.length), NODES, 'P node prefix');
  equal(p.causalDag?.edges?.slice(0, EDGES.length), EDGES, 'P edge prefix');
  equal(p.causalDag?.edges?.slice(EDGES.length), P_DOWNSTREAM, 'P downstream six edges');
  equal(rootDocument.authority?.pRoot, pBinding, 'root P binding');
  if (rootDocument.authority.semanticBindingDigest !== framedDigest(`${PREFIX}policy-authority-binding`, pBinding)) fail('P semantic binding digest');
  equal(rootDocument.authorityDag, { nodes: NODES, edges: EDGES }, 'bounded authority DAG');
  equal(rootDocument.transitionGrammar, expectedGrammar(), 'transition grammar');
}
function checkSchemas(root, rootDocument, manifest) {
  const documents = Object.fromEntries(Object.keys(SCHEMA_SHA256).map((locator) => [locator, json(root, locator)]));
  for (const [locator, expectedHash] of Object.entries(SCHEMA_SHA256)) {
    if (rawSha256(read(root, locator)) !== expectedHash) fail(`${locator} differs from its sealed schema`);
  }
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const document of Object.values(documents)) ajv.addSchema(document);
  const validateRoot = ajv.getSchema(documents['schemas/model-root.v2.schema.json'].$id);
  const validateManifest = ajv.getSchema(documents['schemas/manifest.v1.schema.json'].$id);
  const validateState = ajv.getSchema(documents['schemas/state.v2.schema.json'].$id);
  if (!validateRoot?.(rootDocument)) fail(`model-root schema: ${ajv.errorsText(validateRoot?.errors)}`);
  if (!validateManifest?.(manifest)) fail(`manifest schema: ${ajv.errorsText(validateManifest?.errors)}`);
  const base = { schema: `${PREFIX}state/v2`, identifier: 'cohort-live-executor-v2' };
  for (const value of [
    { ...base, variant: 'initial', facts: ['LIVE_F'], phase: 'open' },
    { ...base, variant: 'initial', facts: ['Q', 'A', 'LIVE_F', 'B', 'C', 'J'], phase: 'open' },
    { ...base, variant: 'retry', facts: [], phase: 'open' },
    { ...base, variant: 'abort', facts: ['Q', 'A'], phase: 'abort-closed' },
  ]) if (!validateState?.(value)) fail('state schema rejects an admitted state');
  for (const value of [
    { ...base, variant: 'initial', facts: ['D'], phase: 'open' },
    { ...base, variant: 'initial', facts: ['Q', 'LIVE_F', 'A'], phase: 'open' },
    { ...base, variant: 'retry', facts: ['Q'], phase: 'open' },
  ]) if (validateState?.(value)) fail('state schema admits a forbidden state');
}
function checkEnvelope(root, rootDocument, manifest) {
  const payload = { authority: rootDocument.authority, authorityDag: rootDocument.authorityDag, identifier: rootDocument.identifier, schema: rootDocument.schema, transitionGrammar: rootDocument.transitionGrammar };
  const expectedRootDigest = framedDigest(`${PREFIX}root`, payload);
  equal(rootDocument.contentDigest, descriptor(`${PREFIX}root`, expectedRootDigest), 'model root digest descriptor');
  const entries = FILES.map((locator) => {
    const bytes = read(root, locator);
    const sha256 = rawSha256(bytes);
    return { locator, bytes: bytes.length, sha256, fileDigest: rawFileDigest(bytes) };
  });
  equal(manifest, { schema: `${PREFIX}manifest/v1`, format: `${PREFIX}manifest/1`, package: 'cohort-live-executor-v2', entryCount: FILES.length, entries, rosterDigest: framedDigest(`${PREFIX}manifest-roster`, { package: 'cohort-live-executor-v2', entries }) }, 'manifest');
  const sums = [...entries, { locator: 'MANIFEST.json', sha256: rawSha256(read(root, 'MANIFEST.json')) }]
    .map((entry) => `${entry.sha256}  ${entry.locator}`).join('\n');
  if (read(root, 'SHA256SUMS').toString('utf8') !== `${sums}\n`) fail('SHA256SUMS differs');
}
function validateStatic({ root = ROOT, pRootPath = P_ROOT_PATH } = {}) {
  checkFilesystem(root);
  const rootDocument = json(root, 'model-root.v2.json');
  const manifest = json(root, 'MANIFEST.json');
  checkAuthority(rootDocument, pRootPath);
  checkSchemas(root, rootDocument, manifest);
  checkPureClosure(root);
  checkEnvelope(root, rootDocument, manifest);
  return true;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { validateStatic(); process.stdout.write('static validation: PASS\n'); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}

export { rawFileDigest, validateStatic };
