import assert from 'node:assert/strict';
import { existsSync, lstatSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const DIRECTORIES = ['.', 'schemas', 'test'];
const FILES = [
  'COMMAND.txt','README.md','external-origin-contract-root.v1.json','validate-static.mjs',
  'schemas/causal-dag.v1.schema.json','schemas/dependency-catalog.v1.schema.json','schemas/ownership-catalog.v1.schema.json',
  'schemas/retry-predecessor-contract.v1.schema.json','schemas/live-f-capture-contract.v1.schema.json','schemas/worker-rows-root-contract.v1.schema.json',
  'schemas/workload-projection-contract.v1.schema.json','schemas/fact-contract-catalog.v1.schema.json','schemas/digest.v1.schema.json',
  'schemas/model-root.v1.schema.json','schemas/manifest.v1.schema.json','test/digest.kat.json','test/static.test.mjs','test/mutation.test.mjs','test/package-boundary.test.mjs',
  'MANIFEST.json','SHA256SUMS',
].sort();

function collect(current, prefix, result) {
  result.dirs.push(prefix || '.');
  for (const name of readdirSync(current).sort()) {
    const locator = prefix ? prefix + '/' + name : name;
    const path = join(current, name);
    const info = lstatSync(path);
    assert.equal(info.isSymbolicLink(), false, locator + ' must not be a link');
    if (info.isDirectory()) collect(path, locator, result);
    else if (info.isFile()) result.files.push(locator);
    else assert.fail(locator + ' has unsupported type');
  }
}

const result = { dirs: [], files: [] };
collect(ROOT, '', result);
assert.deepEqual(result.dirs.sort(), DIRECTORIES.slice().sort());
assert.deepEqual(result.files.sort(), FILES);
assert.equal(existsSync(join(ROOT, 'MANIFEST.json')), true);
assert.equal(existsSync(join(ROOT, 'SHA256SUMS')), true);
for (const locator of result.dirs) {
  const info = lstatSync(locator === '.' ? ROOT : join(ROOT, locator));
  assert.equal(info.nlink, 1, locator + ' nlink');
  assert.equal(info.mode & 0o777, 0o755, locator + ' mode');
}
for (const locator of result.files) {
  const info = lstatSync(join(ROOT, locator));
  assert.equal(info.nlink, 1, locator + ' nlink');
  assert.equal(info.mode & 0o777, 0o644, locator + ' mode');
}

const validator = readFileSync(join(ROOT, 'validate-static.mjs'), 'utf8');
const imports = [...validator.matchAll(/(?:^|\n)import\s+(?:[^'"\n]+\s+from\s+)?['"]([^'"]+)['"]/g)].map((match) => match[1]).sort();
assert.deepEqual(imports, ['ajv/dist/2020.js', 'node:crypto', 'node:fs', 'node:path', 'node:url']);
assert.equal(/\bimport\s*\(|\brequire\s*\(|\bwriteFile|\bappendFile|\bmkdir|\brmSync|\bspawn|\bexec\b|\bfork\b|\bworker_threads\b|\bchild_process\b|\bnode:vm\b|\bnode:net\b|\bnode:http\b|\bnode:https\b|\bWebSocket\b|\bXMLHttpRequest\b|\bWebAssembly\b/.test(validator), false);
assert.equal(/\bexport\b/.test(validator.replace('export { rawFileDigest, semanticDigest, validateStatic };', '')), false);

const root = JSON.parse(readFileSync(join(ROOT, 'external-origin-contract-root.v1.json'), 'utf8'));
function assertNoNull(value, locator = '$') {
  if (value === null) assert.fail(locator + ' must omit unavailable values rather than use null');
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoNull(entry, locator + '[' + index + ']'));
  } else if (typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) assertNoNull(entry, locator + '.' + key);
  }
}

assertNoNull(root);
assert.equal(root.nonAuthorityBoundary.constructionSurface, 'none');
assert.equal(root.nonAuthorityBoundary.writerSurface, 'none');
assert.equal(root.nonAuthorityBoundary.runtimeImportAllowed, false);
assert.equal(root.externalOriginContracts.entries.every((entry) => entry.availability === 'unavailable' && entry.admissionAllowed === false && entry.grantsAuthority === false), true);
assert.equal(root.ownershipCatalog.entries.every((entry) => entry.capabilityDisposition === 'FORBIDDEN' && entry.instanceDisposition === 'FORBIDDEN' && entry.grantsAuthority === false), true);
assert.equal(root.rootDomainCatalog.entries.every((entry) => !Object.hasOwn(entry, 'value')), true);
assert.equal(root.workloadProjectionContract.futurePreimageKeys.dispatchPlan.includes('workerRowsRoot'), true);
assert.equal(root.workloadProjectionContract.futurePreimageKeys.endpointByteAuthority.includes('projectionEncodingId'), true);

process.stdout.write('package boundary tests: PASS\n');
