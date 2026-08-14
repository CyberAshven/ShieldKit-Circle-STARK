/* Mutation KATs copy and inspect bytes only; they never import endpoints. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { assertClosedEndpointSource, assertLibauthControllerSuffix, validatePackage } from '../semantic-validator.mjs';

const original = new URL('..', import.meta.url).pathname;
const FILE_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/file-content';
const ROOT_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/root';
const PACKAGE_ROSTER_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/package-roster';
const ROOT_FILE = 'cohort-endpoint-modules.v1.json';
const packagePrefix = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-endpoint-modules-v1/';
const sha256 = value => createHash('sha256').update(value).digest('hex');
const contentDigest = value => sha256(Buffer.concat([Buffer.from(FILE_DOMAIN), Buffer.of(0), value]));
const canonicalize = value => Array.isArray(value) ? value.map(canonicalize) : value !== null && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])])) : value;
const rootContentDigest = value => sha256(Buffer.concat([Buffer.from(ROOT_DOMAIN), Buffer.of(0), Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8')]));
const immutableDependencies = Object.freeze([
  [new URL('../../cohort-freeze-v2/execution-epoch.v2.json', import.meta.url), 'cohort-freeze-v2/execution-epoch.v2.json'],
  [new URL('../../cohort-engine-runtime-v1/native-evaluator.mjs', import.meta.url), 'cohort-engine-runtime-v1/native-evaluator.mjs'],
  [new URL('../../cohort-engine-runtime-materialized-v1/bundle/libauth-bundle.mjs', import.meta.url), 'cohort-engine-runtime-materialized-v1/bundle/libauth-bundle.mjs'],
  [new URL('../../cohort-execution-v3/execution-contract.v3.json', import.meta.url), 'cohort-execution-v3/execution-contract.v3.json'],
]);
const seal = path => {
  const stat = statSync(path);
  if (stat.isDirectory()) { for (const entry of readdirSync(path)) seal(join(path, entry)); chmodSync(path, 0o555); }
  else chmodSync(path, 0o444);
};
const unseal = path => {
  const stat = statSync(path);
  if (stat.isDirectory()) { for (const entry of readdirSync(path)) unseal(join(path, entry)); chmodSync(path, 0o755); }
  else chmodSync(path, 0o644);
};
const rewrite = (path, value) => { chmodSync(path, 0o644); writeFileSync(path, value); chmodSync(path, 0o444); };
const packageWalk = (root, directory = '') => {
  const files = []; const directories = [];
  for (const entry of readdirSync(join(root, directory), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const path = directory ? `${directory}/${entry.name}` : entry.name;
    if (entry.isDirectory()) { directories.push(path); const nested = packageWalk(root, path); files.push(...nested.files); directories.push(...nested.directories); }
    else files.push(path);
  }
  return { files, directories };
};
const rebuildAcyclicEnvelope = root => {
  const walked = packageWalk(root); const files = walked.files.filter(path => ![ROOT_FILE, 'MANIFEST.json', 'SHA256SUMS'].includes(path)).map(path => {
    const raw = readFileSync(join(root, path)); return { path, bytes: raw.length, rawSha256: sha256(raw), contentDigest: contentDigest(raw), mode: 0o444, nlink: 1 };
  });
  const manifest = { directoryCount: walked.directories.length, directoryMode: 0o555, domainSeparator: FILE_DOMAIN, fileCount: files.length, fileMode: 0o444, files, packageRoot: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-endpoint-modules-v1', schema: 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/manifest', status: 'static-content-addressed' };
  rewrite(join(root, 'MANIFEST.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  const names = ['MANIFEST.json', ...files.map(file => file.path)];
  rewrite(join(root, 'SHA256SUMS'), `${names.map(path => `${sha256(readFileSync(join(root, path)))}  ${packagePrefix}${path}`).join('\n')}\n`);
};
const endpointBinding = (root, endpointId, descriptorPath, modulePath) => {
  const descriptorRaw = readFileSync(join(root, descriptorPath)); const descriptor = JSON.parse(descriptorRaw);
  const module = readFileSync(join(root, modulePath));
  return {
    controller: descriptor.controller,
    descriptor: { bytes: descriptorRaw.length, path: descriptorPath, rawSha256: sha256(descriptorRaw) },
    endpointId,
    module: { bytes: module.length, contentDigest: contentDigest(module), path: modulePath, rawSha256: sha256(module) },
  };
};
/* This stages a coordinated root refresh so a mutation can reach the specific
 * downstream invariant under test. It never touches the authoritative package. */
const refreshRootPackageClosure = root => {
  const rootPath = join(root, ROOT_FILE); const value = JSON.parse(readFileSync(rootPath, 'utf8'));
  const manifestRaw = readFileSync(join(root, 'MANIFEST.json')); const manifest = JSON.parse(manifestRaw);
  const sumsRaw = readFileSync(join(root, 'SHA256SUMS'));
  value.packageClosure.manifest = {
    bytes: manifestRaw.length,
    contentDigest: { algorithm: 'sha256', domain: FILE_DOMAIN, value: contentDigest(manifestRaw) },
    path: 'MANIFEST.json',
    rawSha256: sha256(manifestRaw),
    rosterDigest: { algorithm: 'sha256', domain: PACKAGE_ROSTER_DOMAIN, value: sha256(Buffer.concat([Buffer.from(PACKAGE_ROSTER_DOMAIN), Buffer.of(0), Buffer.from(`${JSON.stringify(canonicalize(manifest.files), null, 2)}\n`, 'utf8')])) },
    schemaRawSha256: '22943eee4bd80d1025c479002c9b93c3bc3b0b60e757c7d6d7248f1785af7d6a',
  };
  value.packageClosure.sha256sums = { bytes: sumsRaw.length, path: 'SHA256SUMS', rawSha256: sha256(sumsRaw) };
  const validatorRaw = readFileSync(join(root, 'semantic-validator.mjs'));
  value.packageClosure.validator = { bytes: validatorRaw.length, contentDigest: contentDigest(validatorRaw), path: 'semantic-validator.mjs', rawSha256: sha256(validatorRaw) };
  value.packageClosure.endpointBindings = [
    endpointBinding(root, 'engine:native', 'endpoints/native-endpoint.v1.json', 'endpoints/native-endpoint.mjs'),
    endpointBinding(root, 'engine:libauth', 'endpoints/libauth-endpoint.v1.json', 'endpoints/libauth-endpoint.mjs'),
  ];
  const projection = { ...value }; delete projection.contentDigest;
  value.contentDigest.value = rootContentDigest(projection);
  rewrite(rootPath, `${JSON.stringify(value, null, 2)}\n`);
};
const mutateLibauthAndRebuildNonrootEnvelope = root => {
  const modulePath = join(root, 'endpoints/libauth-endpoint.mjs'); const descriptorPath = join(root, 'endpoints/libauth-endpoint.v1.json');
  rewrite(modulePath, `${readFileSync(modulePath, 'utf8')}\n`);
  const raw = readFileSync(modulePath); const descriptor = JSON.parse(readFileSync(descriptorPath, 'utf8')); const suffix = raw.subarray(descriptor.controller.startOffset);
  descriptor.file.bytes = raw.length; descriptor.file.rawSha256 = sha256(raw); descriptor.controller.bytes = suffix.length; descriptor.controller.rawSha256 = sha256(suffix); descriptor.controller.contentDigest = contentDigest(suffix);
  rewrite(descriptorPath, `${JSON.stringify(descriptor, null, 2)}\n`); rebuildAcyclicEnvelope(root);
};
const stagingRoot = () => {
  const staging = mkdtempSync(join(tmpdir(), 'cohort-endpoint-modules-v1-')); const root = join(staging, 'cohort-endpoint-modules-v1');
  cpSync(original, root, { recursive: true, dereference: false });
  for (const [source, target] of immutableDependencies) { const destination = join(staging, target); mkdirSync(dirname(destination), { recursive: true }); copyFileSync(source, destination); }
  seal(root); return { root, staging };
};
const probe = (name, mutate, matcher, { refreshRoot = false } = {}) => {
  const { root, staging } = stagingRoot();
  try { assert.doesNotThrow(() => validatePackage(root), `${name} immutable-dependency preflight`); mutate(root); if (refreshRoot) refreshRootPackageClosure(root); assert.throws(() => validatePackage(root), matcher, `${name} rejection cause`); } finally { unseal(staging); rmSync(staging, { recursive: true, force: true }); }
};
probe('module-bytes', root => rewrite(join(root, 'endpoints/native-endpoint.mjs'), `${readFileSync(join(root, 'endpoints/native-endpoint.mjs'), 'utf8')}\n`), /fixed reviewed engine:native controller suffix identity/, { refreshRoot: true });
probe('extra-dependency', root => rewrite(
  join(root, 'endpoints/native-endpoint.v1.json'),
  readFileSync(join(root, 'endpoints/native-endpoint.v1.json'), 'utf8').replace('"moduleEdges": []', '"moduleEdges": ["node:fs"]'),
), /native closed dependency closure/, { refreshRoot: true });
probe('writable-input', root => chmodSync(join(root, 'endpoints/native-endpoint.mjs'), 0o644), /regular readonly single-link module/);
probe('writable-package-root', root => chmodSync(root, 0o755), /package root readonly directory/);
probe('writable-tests-directory', root => chmodSync(join(root, 'tests'), 0o755), /writable package directory: tests/);
probe('writable-manifest', root => chmodSync(join(root, 'MANIFEST.json'), 0o644), /manifest readonly regular single-link file/);
probe('writable-readme', root => chmodSync(join(root, 'README.md'), 0o644), /writable or linked package file: README.md/);
probe('package-link', root => { chmodSync(root, 0o755); symlinkSync('README.md', join(root, 'z-forbidden-link')); chmodSync(root, 0o555); }, /link forbidden: z-forbidden-link/);
probe('wrong-empty-stdin', root => rewrite(join(root, 'endpoint-contract.v1.json'), readFileSync(join(root, 'endpoint-contract.v1.json'), 'utf8').replace('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')), /emptyStderr.sha256 schema const/);
probe('checksum-drift', root => rewrite(join(root, 'SHA256SUMS'), `${readFileSync(join(root, 'SHA256SUMS'), 'utf8')}0\n`), /checksum coverage/, { refreshRoot: true });
probe('schema-drift', root => rewrite(join(root, 'schemas/root.v1.schema.json'), `${readFileSync(join(root, 'schemas/root.v1.schema.json'), 'utf8')}\n`), /pinned schema raw identity/);
probe('coordinated-libauth-descriptor-manifest-checksum-with-stale-root', mutateLibauthAndRebuildNonrootEnvelope, /root package closure manifest binding/);
probe('coordinated-libauth-descriptor-manifest-checksum-and-root-cannot-replace-reviewed-source', mutateLibauthAndRebuildNonrootEnvelope, /fixed reviewed engine:libauth controller suffix identity/, { refreshRoot: true });
probe('validator-identity-stale-root', root => rewrite(join(root, 'semantic-validator.mjs'), `${readFileSync(join(root, 'semantic-validator.mjs'), 'utf8')}\n`), /root package closure validator binding/);
assert.throws(() => assertClosedEndpointSource("import('node:fs')", 'dynamic-host-import'), /import capability/);
assert.throws(() => assertClosedEndpointSource('export { value } from "node:fs"', 'export-from'), /export-from capability/);
assert.throws(() => assertClosedEndpointSource('eval("x")', 'dynamic-eval'), /forbidden capability: eval/);
assert.throws(() => assertClosedEndpointSource('new Function("return 1")', 'dynamic-function'), /forbidden capability: Function/);
assert.throws(() => assertClosedEndpointSource('require("node:fs")', 'commonjs-host-import'), /forbidden capability: require/);
assert.throws(() => assertClosedEndpointSource('globalThis.process', 'global-host-access'), /forbidden capability: globalThis/);
assert.throws(() => assertClosedEndpointSource('\\u0065val("x")', 'escaped-eval'), /escaped identifier/);
const libauth = readFileSync(join(original, 'endpoints/libauth-endpoint.mjs')).subarray(593066).toString('utf8');
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('vm.stateSuccess(state)', 'vm.stateFailure(state)')), /vm escape or forbidden verify/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('vm.stateSuccess(state)', 'vm.verify(program)')), /vm escape or forbidden verify/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('const program = endpointProgramFromWorkerRow(row);', "Object['constructor']('return globalThis')(); const program = endpointProgramFromWorkerRow(row);")), /sensitive string literal/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('const program = endpointProgramFromWorkerRow(row);', "const forged = row['expected']; const program = endpointProgramFromWorkerRow(row);")), /computed or dynamic property access/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('vm.stateSuccess(state)', "vm['verify'](program)")), /computed or dynamic property access/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('const state = vm.evaluate(program);', 'const state = null; if (false) vm.evaluate(program);')), /unconditional decode-to-stateSuccess dataflow/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('vm.stateSuccess(state)', 'vm[`verify`](program)')), /computed or dynamic property access/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('const program = endpointProgramFromWorkerRow(row);', "Object[`constructor`]('return globalThis')(); const program = endpointProgramFromWorkerRow(row);")), /sensitive string literal/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('const accepted = success === true;', 'const accepted = success === true; vm /* comment */ . verify(program);')), /vm escape or forbidden verify/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('const program = endpointProgramFromWorkerRow(row);', "const forged = row /* comment */ ['expected']; const program = endpointProgramFromWorkerRow(row);")), /computed or dynamic property access/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('const program = endpointProgramFromWorkerRow(row);', 'const forged = row.caseEntry; const program = endpointProgramFromWorkerRow(row);')), /forbidden WorkerRow authority: caseEntry/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('const program = endpointProgramFromWorkerRow(row);', "Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Object),'constructor').value('return process'); const program = endpointProgramFromWorkerRow(row);")), /reflection API: getOwnPropertyDescriptor/);
assert.throws(() => assertLibauthControllerSuffix(libauth.replace('const program = endpointProgramFromWorkerRow(row);', "const forged = 'return process'; const program = endpointProgramFromWorkerRow(row);")), /sensitive string literal/);
console.log(JSON.stringify({ status: 'PASS', kats: 33, mode: 'static-mutation-only-with-immutable-reviewed-source-authority-root-closure-and-controller-grammar-defense-in-depth' }));
