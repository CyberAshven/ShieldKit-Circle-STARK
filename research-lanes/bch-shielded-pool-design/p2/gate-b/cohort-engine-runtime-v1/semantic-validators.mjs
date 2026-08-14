import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const PACKAGE_DIR = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-engine-runtime-v1';
const ROOT_FILES = Object.freeze([
  'README.md',
  'external-runtime-closure.v1.json',
  'libauth-bundle-receipt.v1.json',
  'libauth-bundle-receipt.v1.schema.json',
  'libauth-input-graph.v1.json',
  'libauth-input-graph.v1.schema.json',
  'manifest.v1.schema.json',
  'native-descriptor.v1.json',
  'native-descriptor.v1.schema.json',
  'native-evaluator.mjs',
  'runtime-closure.v1.schema.json',
  'semantic-validators.mjs',
  'structural-mutation.test.mjs',
]);
const ENDPOINT_IDS = Object.freeze([
  'engine:bchn',
  'engine:leanbch:vmbconf',
  'engine:leanbch:costprobe',
]);
const BANNED_LIBAUTH_IMPORTS = /(?:from|import)\s*["'](?:node:)?(?:fs|net|http|https|child_process|dgram|tls)["']/u;
const SHA256 = /^[0-9a-f]{64}$/u;

const json = name => JSON.parse(fs.readFileSync(path.join(PACKAGE_DIR, name), 'utf8'));
const canonicalRuntime = () => json('external-runtime-closure.v1.json');
const canonicalNative = () => json('native-descriptor.v1.json');
const canonicalGraph = () => json('libauth-input-graph.v1.json');
const canonicalReceipt = () => json('libauth-bundle-receipt.v1.json');

export class SemanticValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SemanticValidationError';
  }
}

const fail = message => { throw new SemanticValidationError(message); };
const requireCondition = (condition, message) => { if (!condition) fail(message); };
const stable = value => JSON.stringify(value);
const exact = (actual, expected, label) => requireCondition(stable(actual) === stable(expected), `${label} is not exact`);
const keys = (value, expected, label) => {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  exact(Object.keys(value).sort(), [...expected].sort(), `${label} keys`);
};
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const readHash = filename => sha256(fs.readFileSync(filename));
const assertSha256 = (value, label) => requireCondition(typeof value === 'string' && SHA256.test(value), `${label} must be a lowercase SHA-256`);
const statRegularSingleLink = (filename, label) => {
  const stat = fs.lstatSync(filename);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1, `${label} must be a regular single-link file`);
  return stat;
};
const assertFileIdentity = (entry, label, allowSymlinkPath = true) => {
  keys(entry, ['path', 'realpath', 'bytes', 'sha256'], label);
  requireCondition(path.isAbsolute(entry.path) && path.isAbsolute(entry.realpath), `${label} paths must be absolute`);
  assertSha256(entry.sha256, `${label}.sha256`);
  const resolved = fs.realpathSync(entry.path);
  requireCondition(resolved === entry.realpath, `${label}.realpath does not resolve from path`);
  const stat = allowSymlinkPath ? fs.statSync(entry.realpath) : statRegularSingleLink(entry.realpath, label);
  requireCondition(stat.isFile() && stat.nlink === 1, `${label}.realpath must target a regular single-link file`);
  requireCondition(stat.size === entry.bytes, `${label}.bytes does not match target`);
  requireCondition(readHash(entry.realpath) === entry.sha256, `${label}.sha256 does not match target`);
};

export function validateExternalRuntimeClosure(candidate) {
  const expected = canonicalRuntime();
  keys(candidate, ['schema', 'status', 'executionAllowed', 'materializedPackageLocalImage', 'architecture', 'launch', 'loader', 'executables', 'dsos', 'blocker'], 'runtime closure');
  exact(candidate.schema, expected.schema, 'runtime schema identifier');
  exact(candidate.status, 'host-pinned-unmaterialized', 'runtime status');
  exact(candidate.executionAllowed, false, 'runtime executionAllowed');
  exact(candidate.materializedPackageLocalImage, false, 'runtime materializedPackageLocalImage');
  exact(candidate.architecture, { platform: 'linux', arch: 'x64' }, 'runtime architecture');

  keys(candidate.launch, ['shell', 'stdio', 'extraInheritedFds', 'argv0Policy', 'environmentPolicy', 'externalCombinedOutputCapBytes', 'terminationGraceMilliseconds', 'bchnDeadlineMilliseconds', 'leanSharedDeadlineMilliseconds', 'leanRemainingConversion'], 'runtime launch');
  exact(candidate.launch.shell, false, 'launch.shell');
  exact(candidate.launch.stdio, { '0': 'captured-stdin', '1': 'captured-stdout', '2': 'captured-stderr' }, 'launch.stdio');
  exact(candidate.launch.extraInheritedFds, [], 'launch.extraInheritedFds');
  exact(candidate.launch.argv0Policy, 'argv[0] equals absolute executable path', 'launch.argv0Policy');
  exact(candidate.launch.environmentPolicy, 'exact replacement map; no inherited variables', 'launch.environmentPolicy');
  exact(candidate.launch.externalCombinedOutputCapBytes, 134217728, 'launch output cap');
  exact(candidate.launch.terminationGraceMilliseconds, 5000, 'launch termination grace');
  exact(candidate.launch.bchnDeadlineMilliseconds, null, 'BCHN deadline');
  exact(candidate.launch.leanSharedDeadlineMilliseconds, 600000, 'Lean shared deadline');
  exact(candidate.launch.leanRemainingConversion, 'ceil(remainingNanoseconds / 1000000), checked positive before each process; one monotonic deadline shared by vmbconf and CostProbe', 'Lean remaining conversion');

  exact(candidate.loader, expected.loader, 'runtime loader descriptor');
  assertFileIdentity({ path: candidate.loader.requestedPath, realpath: candidate.loader.realpath, bytes: candidate.loader.bytes, sha256: candidate.loader.sha256 }, 'loader');
  requireCondition(Array.isArray(candidate.executables) && candidate.executables.length === ENDPOINT_IDS.length, 'runtime executable count');
  const seenIds = new Set();
  for (let i = 0; i < candidate.executables.length; i += 1) {
    const endpoint = candidate.executables[i];
    const expectedEndpoint = expected.executables[i];
    keys(endpoint, ['id', 'path', 'realpath', 'bytes', 'sha256', 'argv', 'argv0', 'cwd', 'environment', 'deadlineMilliseconds'], `endpoint ${i}`);
    exact(endpoint, expectedEndpoint, `endpoint ${i} pinned descriptor`);
    requireCondition(!seenIds.has(endpoint.id) && ENDPOINT_IDS.includes(endpoint.id), `endpoint ${i} id must be unique and known`);
    seenIds.add(endpoint.id);
    requireCondition(endpoint.path === endpoint.realpath, `${endpoint.id} path/realpath mismatch`);
    requireCondition(endpoint.argv[0] === endpoint.path && endpoint.argv0 === endpoint.path, `${endpoint.id} argv0 relation failed`);
    requireCondition(path.isAbsolute(endpoint.path) && path.isAbsolute(endpoint.cwd), `${endpoint.id} path/cwd must be absolute`);
    keys(endpoint.environment, endpoint.id === 'engine:bchn' ? ['BCHN_DEBUG'] : ['LEANBCH_SECP'], `${endpoint.id} environment`);
    requireCondition(endpoint.id === 'engine:bchn' ? endpoint.deadlineMilliseconds === null : endpoint.deadlineMilliseconds === 'shared-600000', `${endpoint.id} deadline relation failed`);
    assertFileIdentity({ path: endpoint.path, realpath: endpoint.realpath, bytes: endpoint.bytes, sha256: endpoint.sha256 }, `${endpoint.id} executable`);
  }
  exact([...seenIds], ENDPOINT_IDS, 'runtime endpoint ordering');

  requireCondition(Array.isArray(candidate.dsos) && candidate.dsos.length === expected.dsos.length, 'runtime DSO count');
  const seenSonames = new Set();
  const seenRealpaths = new Set();
  for (let i = 0; i < candidate.dsos.length; i += 1) {
    const dso = candidate.dsos[i];
    const expectedDso = expected.dsos[i];
    keys(dso, ['soname', 'path', 'realpath', 'bytes', 'sha256', 'usedBy'], `DSO ${i}`);
    exact(dso, expectedDso, `DSO ${i} pinned descriptor`);
    requireCondition(!seenSonames.has(dso.soname) && !seenRealpaths.has(dso.realpath), `DSO ${i} identity must be unique`);
    seenSonames.add(dso.soname); seenRealpaths.add(dso.realpath);
    requireCondition(dso.path !== dso.realpath || fs.realpathSync(dso.path) === dso.realpath, `DSO ${dso.soname} path/realpath relation failed`);
    requireCondition(dso.usedBy.length > 0 && dso.usedBy.every(id => ENDPOINT_IDS.includes(id)), `DSO ${dso.soname} has an unknown consumer`);
    assertFileIdentity({ path: dso.path, realpath: dso.realpath, bytes: dso.bytes, sha256: dso.sha256 }, `DSO ${dso.soname}`);
  }
  exact(candidate.blocker, expected.blocker, 'runtime blocker');
  return { ok: true, endpoints: candidate.executables.length, dsos: candidate.dsos.length };
}

export function validateNativeDescriptor(candidate) {
  const expected = canonicalNative();
  keys(candidate, ['schema', 'evaluatorId', 'status', 'executionAllowed', 'expectedCorpusValues', 'hostCapabilities', 'input', 'relations', 'constructions'], 'Native descriptor');
  exact(candidate, expected, 'Native descriptor pinned values');
  exact(candidate.schema, 'shieldkit-labs/p2/gate-b/cohort-engine-runtime/v1/native-descriptor', 'Native schema identifier');
  exact(candidate.status, 'static-source-unexecuted', 'Native status');
  exact(candidate.executionAllowed, false, 'Native executionAllowed');
  exact(candidate.expectedCorpusValues, 'forbidden', 'Native expected/corpus policy');
  exact(candidate.hostCapabilities, { imports: false, dynamicImports: false, require: false, fs: false, network: false, nativeAddon: false }, 'Native host capabilities');
  exact(candidate.input, 'constructionId|relationId|workItemId|operandsBottomToTop-Uint8Array-only-v1', 'Native input ABI');
  const relationNames = Object.keys(candidate.relations);
  exact(relationNames, ['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check'], 'Native relation IDs');
  for (const [id, operands] of Object.entries(candidate.relations)) {
    requireCondition(Array.isArray(operands) && operands.length > 0 && new Set(operands).size === operands.length, `${id} operands must be unique`);
    requireCondition(operands.every(name => /^[A-Z]$/u.test(name)), `${id} operand names must be canonical`);
  }
  const constructionNames = Object.keys(candidate.constructions);
  exact(constructionNames, ['algebra-component:m89-d2-x2-plus-1-v2', 'algebra-component:m61-d3-x3-minus-5-v2', 'algebra-component:m31-d5-x5-plus-2x-minus-1-v2', 'algebra-component:m31-d6-x6-minus-5-v2'], 'Native construction IDs');
  for (const [id, config] of Object.entries(candidate.constructions)) {
    keys(config, ['p', 'degree', 'limbBytes', 'polynomialAscending'], `${id} construction`);
    requireCondition(/^\d+$/u.test(config.p) && Number.isInteger(config.degree) && config.degree > 0 && Number.isInteger(config.limbBytes) && config.limbBytes > 0, `${id} construction numerics`);
    requireCondition(Array.isArray(config.polynomialAscending) && config.polynomialAscending.length === config.degree + 1, `${id} polynomial degree relation failed`);
    requireCondition(config.polynomialAscending.every(coefficient => /^\d+$/u.test(coefficient)), `${id} polynomial coefficients must be decimal strings`);
    requireCondition(config.polynomialAscending.at(-1) === '1', `${id} polynomial must be monic`);
  }
  return { ok: true, relations: relationNames.length, constructions: constructionNames.length };
}

const locateWorkspaceRoot = start => {
  let current = path.resolve(start);
  while (current !== path.dirname(current)) {
    if (fs.existsSync(path.join(current, 'package-lock.json'))) return current;
    current = path.dirname(current);
  }
  fail('workspace package-lock.json not found');
};

const resolveLibauthRoot = () => {
  const packageJson = createRequire(import.meta.url).resolve('@bitauth/libauth/package.json');
  return path.join(path.dirname(packageJson), 'build', 'lib');
};

const scanLibauthSource = (filename, source, graphPaths) => {
  const unresolved = [];
  const external = [];
  const staticPatterns = [
    /(?:^|\n)\s*import\s+(?:[^'";]*?\sfrom\s+)?['"]([^'"]+)['"]/gu,
    /(?:^|\n)\s*export\s+(?:[^'";]*?\sfrom\s+)?['"]([^'"]+)['"]/gu,
  ];
  for (const expression of staticPatterns) {
    let match;
    while ((match = expression.exec(source)) !== null) {
      const specifier = match[1];
      if (!specifier.startsWith('.')) { external.push({ filename, specifier }); continue; }
      const base = path.posix.normalize(path.posix.join(path.posix.dirname(filename), specifier));
      const candidates = [base, `${base}.js`, `${base}/index.js`];
      if (!candidates.some(candidate => graphPaths.has(candidate))) unresolved.push({ filename, specifier, candidates });
    }
  }
  return {
    unresolvedStaticImports: [...unresolved, ...external],
    dynamicImports: [...source.matchAll(/\bimport\s*\(/gu)].map(() => filename),
    requireCalls: [...source.matchAll(/\brequire\s*\(/gu)].map(() => filename),
    hostImports: BANNED_LIBAUTH_IMPORTS.test(source) ? [filename] : [],
    nativeAddons: /\.node\b/u.test(source) ? [filename] : [],
    networkCalls: /\bfetch\s*\(/u.test(source) ? [filename] : [],
  };
};

export function validateLibauthInputGraph(candidate) {
  const expected = canonicalGraph();
  keys(candidate, ['schema', 'status', 'executionAllowed', 'package', 'entrypoints', 'fileCount', 'totalBytes', 'sortedPathSizeSha256ListDigest', 'files'], 'Libauth graph');
  exact(candidate.schema, expected.schema, 'Libauth graph schema identifier');
  exact(candidate.status, 'graph-bound-bundle-unmaterialized', 'Libauth graph status');
  exact(candidate.executionAllowed, false, 'Libauth graph executionAllowed');
  exact(candidate.package, { name: '@bitauth/libauth', version: '3.1.0-next.8', packageJsonRawSha256: '6b4e3b7f062b80782c62cb7732ed01571c5f163fd786af877c0ae5fdc33ec65e', packageLockRawSha256: 'a8cbdaa33b94b73edb051a675387cb87171efd3f544ad2b5c5a68f8679026004' }, 'Libauth package pin');
  exact(candidate.entrypoints, ['vm/instruction-sets/bch/2026/bch-2026-vm.js', 'message/transaction-encoding.js'], 'Libauth entrypoints');
  exact(candidate.fileCount, 80, 'Libauth fileCount');
  exact(candidate.totalBytes, 808913, 'Libauth totalBytes');
  exact(candidate.sortedPathSizeSha256ListDigest, 'c957412296b6ddb5493a1fe44b8e50b2daceec89c8f5e12f660a7eb4ad222b92', 'Libauth graph digest');
  requireCondition(Array.isArray(candidate.files) && candidate.files.length === candidate.fileCount, 'Libauth graph file array length');
  const paths = candidate.files.map(file => file.path);
  exact(paths, [...paths].sort((a, b) => a.localeCompare(b)), 'Libauth graph path order');
  requireCondition(new Set(paths).size === paths.length, 'Libauth graph paths must be unique');
  const graphPaths = new Set(paths);
  const libauthRoot = resolveLibauthRoot();
  const workspaceRoot = locateWorkspaceRoot(PACKAGE_DIR);
  const packageJson = path.join(libauthRoot, '..', '..', 'package.json');
  const packageLock = path.join(workspaceRoot, 'package-lock.json');
  requireCondition(readHash(packageJson) === candidate.package.packageJsonRawSha256, 'Libauth package.json hash mismatch');
  requireCondition(readHash(packageLock) === candidate.package.packageLockRawSha256, 'Libauth package-lock hash mismatch');
  let totalBytes = 0;
  const scan = { unresolvedStaticImports: [], dynamicImports: [], requireCalls: [], hostImports: [], nativeAddons: [], networkCalls: [] };
  for (const file of candidate.files) {
    keys(file, ['path', 'bytes', 'sha256'], `Libauth graph file ${file.path}`);
    requireCondition(!path.isAbsolute(file.path) && !file.path.includes('..'), `Libauth graph path ${file.path} must be package-relative`);
    assertSha256(file.sha256, `Libauth graph ${file.path}`);
    const filename = path.join(libauthRoot, file.path);
    const stat = statRegularSingleLink(filename, `Libauth graph ${file.path}`);
    requireCondition(stat.size === file.bytes, `Libauth graph ${file.path} byte mismatch`);
    requireCondition(readHash(filename) === file.sha256, `Libauth graph ${file.path} hash mismatch`);
    totalBytes += file.bytes;
    const findings = scanLibauthSource(file.path, fs.readFileSync(filename, 'utf8'), graphPaths);
    for (const key of Object.keys(scan)) scan[key].push(...findings[key]);
  }
  exact(totalBytes, candidate.totalBytes, 'Libauth graph byte total');
  exact(sha256(Buffer.from(JSON.stringify(candidate.files.map(({ path: filePath, bytes, sha256: digest }) => ({ path: filePath, bytes, sha256: digest }))))), candidate.sortedPathSizeSha256ListDigest, 'Libauth graph list digest');
  for (const [name, findings] of Object.entries(scan)) exact(findings, [], `Libauth graph static scan ${name}`);
  return { ok: true, files: candidate.fileCount, bytes: totalBytes, staticScan: scan };
}

export function validateLibauthBundleReceipt(candidate) {
  const expected = canonicalReceipt();
  keys(candidate, ['schema', 'status', 'executionAllowed', 'bundleMaterialized', 'inputGraph', 'requiredExports', 'requiredSemantics', 'bundlerSurvey', 'inputGraphStaticScan', 'recipe', 'output', 'blocker'], 'Libauth receipt');
  exact(candidate, expected, 'Libauth receipt pinned fail-closed contract');
  exact(candidate.schema, expected.schema, 'Libauth receipt schema identifier');
  exact(candidate.status, 'fail-closed-no-installed-deterministic-bundler', 'Libauth receipt status');
  exact(candidate.executionAllowed, false, 'Libauth receipt executionAllowed');
  exact(candidate.bundleMaterialized, false, 'Libauth receipt bundleMaterialized');
  exact(candidate.inputGraph, 'libauth-input-graph.v1.json', 'Libauth receipt graph reference');
  exact(candidate.requiredExports, ['decodeTransaction', 'decodeTransactionOutputs', 'createVirtualMachineBch2026', 'vm.evaluate', 'vm.stateSuccess'], 'Libauth required exports');
  exact(candidate.requiredSemantics, { standard: true, verifyCall: false, expectedCorpusInput: false, exactFixtureTransactionAndSourceOutputs: true }, 'Libauth required semantics');
  exact(candidate.bundlerSurvey, [{ tool: 'esbuild', status: 'absent' }, { tool: 'rollup', status: 'absent' }, { tool: 'webpack', status: 'absent' }], 'Libauth bundler survey');
  exact(candidate.inputGraphStaticScan, { status: 'passed', unresolvedStaticImports: [], dynamicImports: [], requireCalls: [], hostImports: [], nativeAddons: [], networkCalls: [] }, 'Libauth graph scan receipt');
  exact(candidate.recipe, expected.recipe, 'Libauth bundle recipe');
  exact(candidate.output, null, 'Libauth bundle output');
  exact(candidate.blocker, expected.blocker, 'Libauth bundle blocker');
  return { ok: true, bundleMaterialized: false, executionAllowed: false };
}

const manifestEntry = (entry, label) => {
  keys(entry, ['path', 'bytes', 'sha256'], label);
  requireCondition(entry.path.startsWith(`${PACKAGE_ROOT}/`) && !entry.path.endsWith('/'), `${label}.path must remain under package root`);
  requireCondition(Number.isInteger(entry.bytes) && entry.bytes > 0, `${label}.bytes must be positive`);
  assertSha256(entry.sha256, `${label}.sha256`);
};

const walkPackage = packageDir => {
  const found = [];
  const visit = (directory, prefix) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const stat = fs.lstatSync(filename);
      requireCondition(!stat.isSymbolicLink(), `package contains symlink ${relative}`);
      if (entry.isDirectory()) {
        found.push(`${relative}/`);
        visit(filename, relative);
        continue;
      }
      requireCondition(entry.isFile() && stat.nlink === 1, `package entry ${relative} must be a regular single-link file`);
      found.push(relative);
    }
  };
  visit(packageDir, '');
  return found.sort((a, b) => a.localeCompare(b));
};

export function validateManifestPackage(candidate, packageDir = PACKAGE_DIR) {
  keys(candidate, ['schema', 'status', 'executionAllowed', 'packageRoot', 'files'], 'manifest');
  exact(candidate.schema, 'shieldkit-labs/p2/gate-b/cohort-engine-runtime/v1/manifest', 'manifest schema identifier');
  exact(candidate.status, 'static-preflight-unexecuted', 'manifest status');
  exact(candidate.executionAllowed, false, 'manifest executionAllowed');
  exact(candidate.packageRoot, PACKAGE_ROOT, 'manifest packageRoot');
  requireCondition(Array.isArray(candidate.files) && candidate.files.length === ROOT_FILES.length, 'manifest file count');
  exact(candidate.files.map(entry => entry.path), ROOT_FILES.map(name => `${PACKAGE_ROOT}/${name}`), 'manifest full paths');
  const names = candidate.files.map(entry => path.posix.basename(entry.path));
  exact(names, ROOT_FILES, 'manifest path coverage/order');
  requireCondition(new Set(candidate.files.map(entry => entry.path)).size === candidate.files.length, 'manifest paths must be unique');
  for (let i = 0; i < candidate.files.length; i += 1) {
    const entry = candidate.files[i];
    manifestEntry(entry, `manifest file ${i}`);
    const local = path.join(packageDir, names[i]);
    const stat = statRegularSingleLink(local, `manifest file ${names[i]}`);
    requireCondition(stat.size === entry.bytes, `manifest byte mismatch for ${names[i]}`);
    requireCondition(readHash(local) === entry.sha256, `manifest hash mismatch for ${names[i]}`);
  }
  const walked = walkPackage(packageDir);
  exact(walked, [...ROOT_FILES, 'MANIFEST.json', 'SHA256SUMS'].sort((a, b) => a.localeCompare(b)), 'full package directory coverage');
  const checksumPath = path.join(packageDir, 'SHA256SUMS');
  const checksumLines = fs.readFileSync(checksumPath, 'utf8').trimEnd().split('\n');
  const checksumNames = ['MANIFEST.json', ...ROOT_FILES];
  exact(checksumLines.map(line => line.replace(/^[0-9a-f]{64}  /u, '')), checksumNames.map(name => `${PACKAGE_ROOT}/${name}`), 'SHA256SUMS path coverage/order');
  for (let i = 0; i < checksumLines.length; i += 1) {
    const match = /^([0-9a-f]{64})  (.+)$/u.exec(checksumLines[i]);
    requireCondition(match !== null, `invalid SHA256SUMS line ${i}`);
    const localName = checksumNames[i];
    requireCondition(match[1] === readHash(path.join(packageDir, localName)), `SHA256SUMS hash mismatch for ${localName}`);
  }
  return { ok: true, manifestFiles: ROOT_FILES.length, excluded: ['MANIFEST.json', 'SHA256SUMS'] };
}

export const packageDirectory = PACKAGE_DIR;
export const packageRoot = PACKAGE_ROOT;
