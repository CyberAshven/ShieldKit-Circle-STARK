import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PACKAGE_DIR = path.dirname(fileURLToPath(import.meta.url));
const GATE_DIR = path.dirname(PACKAGE_DIR);
const V1_DIR = path.join(GATE_DIR, 'cohort-engine-runtime-v1');
const WORKSPACE_ROOT = path.resolve(GATE_DIR, '../../../..');
const LIBAUTH_ROOT = path.join(WORKSPACE_ROOT, 'node_modules/@bitauth/libauth/build/lib');
const LIBAUTH_PACKAGE = path.join(WORKSPACE_ROOT, 'node_modules/@bitauth/libauth');
const ESBUILD_ROOT = '/home/toorik/Projects/ZK-Proofs/verifier.cash/harness/node_modules/.pnpm/esbuild@0.28.1/node_modules/esbuild';
const ESBUILD_PLATFORM_ROOT = '/home/toorik/Projects/ZK-Proofs/verifier.cash/harness/node_modules/.pnpm/@esbuild+linux-x64@0.28.1/node_modules/@esbuild/linux-x64';
const ESBUILD_LOCK_SOURCE = '/home/toorik/Projects/ZK-Proofs/verifier.cash/harness/pnpm-lock.yaml';
const ESBUILD_LOCK_SHA256 = '123bfd3aa1497c01c40c71367a188efc7d435125d4d3539d5f7175d1e09eed01';
const ESBUILD_INTEGRITY = Object.freeze({ package: 'sha512-HrJrvZv5ayxBzPfwphOoNzkzOIIlifzk0KJrGK2c8R4+LKpMtpYLQeUdjnwjWv/LZlkH2laZk+4w78pi99D4Vw==', platform: 'sha512-u/anNYF2mmVOEDwLtnQ1wOr3EZ9sTNGLWrsYGYwHWzGA3Si84IOkHXlbWTD1NB+9/1lcnweYKO54uhxZydNzfA==' });
const READELF = Object.freeze({ path: '/usr/bin/readelf', realpath: '/usr/bin/readelf', bytes: 801752, sha256: '355fe7960d103964e6dfb141237bd51627943ff94218928addb42bed570246bb', version: 'GNU readelf (GNU Binutils) 2.46.1' });
const FROZEN_GRAPH_RAW = Object.freeze({ path: 'source/libauth-input-graph.v1.json', bytes: 14040, sha256: '7da5740246da6938eaee95f7845a2e20a6f92810029f7845b79c09e78c78db6f' });
const FROZEN_RUNTIME_RAW = Object.freeze({ path: 'source/external-runtime-closure.v1.json', bytes: 8580, sha256: '4a66addc21b8aacad170c301340293dbefe29f226318fd10660a1592dc931de5' });
const ESBUILD_SOURCE = Object.freeze({
  name: 'esbuild', version: '0.28.1', license: 'MIT', repository: 'git+https://github.com/evanw/esbuild.git',
  package: Object.freeze({
    'package.json': 'd55d1d19fcc5b6079e4a71dd4111340c79c682bc36835ac7058a0c364c7db58a',
    'LICENSE.md': 'b40ec5baec7bb34fa5b1c09521fa3cd52d5fad7adafed74932a2010d3612a681',
    'README.md': '6d481cd60ec3c679e5e395f547ab4221147f35642894f6b95a8df38fd25c87bd',
    'install.js': '612294e278914443bdcf81cb17f54afec34dbdd2ebd999a6ee187912320cc315',
    'lib/main.d.ts': '161c8e0690c46021506e32fda85956d785b70f309ae97011fd27374c065cac9b',
    'lib/main.js': '8331fe1d8b3a07381f33cc425fcfaa94776e263113653f80ec3ba433e9657e73',
    'bin/esbuild': 'fe9a7b65a540d8df1a0f59941d52e7c1260c36fed9a2af3dd966f15381b6eb76',
  }),
  platform: Object.freeze({
    'package.json': '2332dc7d04175b16730f136b5bf32b31203eecea5be03b66e9453a4658b3d971',
    'README.md': '3b0ebdffe92e5b77c948c4ac0bf4bc4a38803b15405d0425b517705221c27a2f',
    'bin/esbuild': '0c6588b092a2c291a72bab90659f3c9e0e25e0fe59c9ac12b4dae4d945e5548c',
  }),
});
const BUNDLE_EXPORTS = Object.freeze(['createVirtualMachineBch2026', 'decodeTransaction', 'decodeTransactionOutputs']);
const FROZEN_BUNDLE = Object.freeze({ path: 'bundle/libauth-bundle.mjs', bytes: 593066, sha256: 'ffbee87e074d6df03a03a2068a8f77fe6776f8139cd9bd2cb5e3ac70091bf68f' });
const FROZEN_METAFILE = Object.freeze({ path: 'bundle/libauth-bundle.metafile.json', bytes: 50248, sha256: '4c8bf5b2418edb3e49bf41a31dc527df64cbb88a2c8675083cfd6dbef883afd4' });
const GRAPH_CONTENT_DOMAIN = 'shieldkit-labs/p2/gate-b/libauth-graph-content/v1';
const RUNTIME_CONTENT_DOMAIN = 'shieldkit-labs/p2/gate-b/runtime-source-closure-content/v1';
const MANIFEST_CONTENT_DOMAIN = 'shieldkit-labs/p2/gate-b/manifest-content/v1';
const MANIFEST_ROSTER_DOMAIN = 'shieldkit-labs/p2/gate-b/manifest-roster/v1';
const RUNTIME_MODES = Object.freeze({ loader: 493, executables: Object.freeze([493, 493, 493]), dsos: Object.freeze([493, 493, 493, 493, 493, 493, 493, 420, 493, 493, 493, 493, 493, 493, 493, 493, 493]) });
const ARTIFACT_ROSTER = Object.freeze([
  'bundle/libauth-bundle.mjs', 'bundle/libauth-bundle.metafile.json', 'libauth-bundle-receipt.v1.json',
  'runtime-image.v1.json', 'licenses/provenance.v1.json', 'source/libauth-input-graph.v1.json',
  'source/libauth/**', 'source/external-runtime-closure.v1.json', 'toolchain/pnpm-lock.yaml', 'MANIFEST.json', 'SHA256SUMS',
]);
const KAT_ROSTER = Object.freeze(['reproducibility.test.mjs', 'mutation.test.mjs']);
const SCHEMA_ROSTER = Object.freeze(['libauth-bundle-receipt.v1.schema.json', 'license-provenance.v1.schema.json', 'manifest.v1.schema.json', 'materialization.v1.schema.json', 'runtime-image.v1.schema.json']);
const IMAGE = Object.freeze({
  loader: Object.freeze({ requestedPath: '/lib64/ld-linux-x86-64.so.2', source: '/usr/lib/ld-linux-x86-64.so.2', destination: 'image/root/lib64/ld-linux-x86-64.so.2', soname: 'ld-linux-x86-64.so.2' }),
  executables: Object.freeze([
    Object.freeze({ id: 'engine:bchn', source: '/home/toorik/Projects/BCH/bch-conformance/legs/bchn/bchn-leg', destination: 'image/root/engines/bchn-leg', workdir: 'image/workdirs/bchn', licenseSource: '/home/toorik/Projects/BCH/bch-conformance/LICENSE-MIT', licenseSource2: '/home/toorik/Projects/BCH/bch-conformance/LICENSE-APACHE' }),
    Object.freeze({ id: 'engine:leanbch:vmbconf', source: '/home/toorik/Projects/ZK-Proofs/LeanBCH/.lake/build/bin/vmbconf', destination: 'image/root/engines/vmbconf', workdir: 'image/workdirs/leanbch', licenseSource: '/home/toorik/Projects/ZK-Proofs/LeanBCH/LICENSE' }),
    Object.freeze({ id: 'engine:leanbch:costprobe', source: '/home/toorik/Projects/ZK-Proofs/LeanBCH/.lake/build/bin/costprobe', destination: 'image/root/engines/costprobe', workdir: 'image/workdirs/leanbch', licenseSource: '/home/toorik/Projects/ZK-Proofs/LeanBCH/LICENSE' }),
  ]),
  dsos: Object.freeze([
    ['libcrypto.so.3', '/usr/lib/libcrypto.so.3', 'openssl', 'Apache-2.0'],
    ['libboost_chrono.so.1.91.0', '/usr/lib/libboost_chrono.so.1.91.0', 'boost-libs', 'BSL-1.0'],
    ['libboost_filesystem.so.1.91.0', '/usr/lib/libboost_filesystem.so.1.91.0', 'boost-libs', 'BSL-1.0'],
    ['libgmpxx.so.4', '/usr/lib/libgmpxx.so.4.7.0', 'gmp', 'GPL-2.0-or-later; LGPL-3.0-or-later'],
    ['libgmp.so.10', '/usr/lib/libgmp.so.10.5.0', 'gmp', 'GPL-2.0-or-later; LGPL-3.0-or-later'],
    ['libstdc++.so.6', '/usr/lib/libstdc++.so.6.0.35', 'libstdc++', 'GPL-3.0-or-later WITH GCC-exception-3.1; GFDL-1.3-or-later'],
    ['libm.so.6', '/usr/lib/libm.so.6', 'glibc', 'GPL-2.0-or-later; LGPL-2.1-or-later'],
    ['libgcc_s.so.1', '/usr/lib/libgcc_s.so.1', 'libgcc', 'GPL-3.0-or-later WITH GCC-exception-3.1; GFDL-1.3-or-later'],
    ['libc.so.6', '/usr/lib/libc.so.6', 'glibc', 'GPL-2.0-or-later; LGPL-2.1-or-later'],
    ['libz.so.1', '/usr/lib/libz.so.1.3.2', 'zlib', 'Zlib'],
    ['libbrotlienc.so.1', '/usr/lib/libbrotlienc.so.1.2.0', 'brotli', 'MIT'],
    ['libbrotlidec.so.1', '/usr/lib/libbrotlidec.so.1.2.0', 'brotli', 'MIT'],
    ['libbrotlicommon.so.1', '/usr/lib/libbrotlicommon.so.1.2.0', 'brotli', 'MIT'],
    ['libzstd.so.1', '/usr/lib/libzstd.so.1.5.7', 'zstd', 'BSD-3-Clause; GPL-2.0-only'],
    ['libpthread.so.0', '/usr/lib/libpthread.so.0', 'glibc', 'GPL-2.0-or-later; LGPL-2.1-or-later'],
    ['libdl.so.2', '/usr/lib/libdl.so.2', 'glibc', 'GPL-2.0-or-later; LGPL-2.1-or-later'],
    ['librt.so.1', '/usr/lib/librt.so.1', 'glibc', 'GPL-2.0-or-later; LGPL-2.1-or-later'],
  ]),
});
const LICENSE_FILES = Object.freeze([
  ['/home/toorik/Projects/BCH/bch-conformance/LICENSE-MIT', 'licenses/bch-conformance/LICENSE-MIT'],
  ['/home/toorik/Projects/BCH/bch-conformance/LICENSE-APACHE', 'licenses/bch-conformance/LICENSE-APACHE'],
  ['/home/toorik/Projects/ZK-Proofs/LeanBCH/LICENSE', 'licenses/LeanBCH/LICENSE'],
  [path.join(LIBAUTH_PACKAGE, 'LICENSE'), 'licenses/libauth/LICENSE'],
  [path.join(ESBUILD_ROOT, 'LICENSE.md'), 'licenses/esbuild/LICENSE.md'],
  ['/usr/share/licenses/openssl/LICENSE.txt', 'licenses/host/openssl/LICENSE.txt'],
  ['/usr/share/licenses/libstdc++/RUNTIME.LIBRARY.EXCEPTION', 'licenses/host/libstdc++/RUNTIME.LIBRARY.EXCEPTION'],
  ['/usr/share/licenses/libgcc/RUNTIME.LIBRARY.EXCEPTION', 'licenses/host/libgcc/RUNTIME.LIBRARY.EXCEPTION'],
  ['/usr/share/licenses/zlib/LICENSE', 'licenses/host/zlib/LICENSE'],
  ['/usr/share/licenses/brotli/LICENSE', 'licenses/host/brotli/LICENSE'],
  ['/usr/share/licenses/zstd/LICENSE', 'licenses/host/zstd/LICENSE'],
]);
const PACKAGE_RELATIVE = file => path.relative(PACKAGE_DIR, file).split(path.sep).join('/');
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hashFile = file => sha256(fs.readFileSync(file));
const domainDigest = (domain, bytes) => sha256(Buffer.concat([Buffer.from(`${domain}\0`, 'utf8'), Buffer.from(bytes)]));
const stable = value => JSON.stringify(value, (key, item) => {
  if (item && typeof item === 'object' && !Array.isArray(item)) return Object.fromEntries(Object.keys(item).sort().map(k => [k, item[k]]));
  return item;
}, 2) + '\n';
const manifestRosterDigest = (files, directories) => domainDigest(MANIFEST_ROSTER_DOMAIN, Buffer.from(stable({ files: files.map(item => ({ path: item.path, mode: item.mode })), directories: directories.map(item => ({ path: item.path, mode: item.mode })) }), 'utf8'));
const ensureDir = dir => fs.mkdirSync(dir, { recursive: true });
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const writeJson = (file, value) => { ensureDir(path.dirname(file)); fs.writeFileSync(file, stable(value)); };
const fail = message => { throw new Error(message); };
const requireCondition = (condition, message) => { if (!condition) fail(message); };
const statMode = file => fs.statSync(file).mode & 0o777;
const sourceRealpath = file => fs.realpathSync(file);
const copyRegular = (source, destination, expectedHash = null) => {
  const real = sourceRealpath(source);
  const stat = fs.statSync(real);
  requireCondition(stat.isFile(), `source is not regular: ${source}`);
  if (expectedHash !== null) requireCondition(hashFile(real) === expectedHash, `source hash mismatch: ${source}`);
  ensureDir(path.dirname(destination));
  fs.copyFileSync(real, destination);
  fs.chmodSync(destination, stat.mode & 0o777);
  requireCondition(hashFile(destination) === hashFile(real), `copy hash mismatch: ${destination}`);
  return { source: source, sourceRealpath: real, bytes: stat.size, sha256: hashFile(real), mode: stat.mode & 0o777 };
};
const run = (file, args, options = {}) => {
  const result = spawnSync(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options });
  if (result.status !== 0) fail(`${file} failed (${result.status}): ${result.stderr}`);
  return result.stdout;
};
const verifyReadelfTool = () => {
  requireCondition(fs.realpathSync(READELF.path) === READELF.realpath, 'readelf realpath drift');
  requireCondition(fs.statSync(READELF.path).size === READELF.bytes && hashFile(READELF.path) === READELF.sha256, 'readelf bytes drift');
  const version = spawnSync(READELF.path, ['--version'], { encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' } });
  requireCondition(version.status === 0 && version.stdout.split('\n')[0] === READELF.version, 'readelf version drift');
};
const readelf = file => {
  verifyReadelfTool();
  const text = run(READELF.path, ['-lW', '-dW', file], { env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' } });
  requireCondition(/^ELF Header:/mu.test(run(READELF.path, ['-h', file], { env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' } })), `non-ELF image: ${file}`);
  const interp = text.match(/Requesting program interpreter: ([^\]]+)\]/u)?.[1] ?? null;
  const soname = text.match(/\(SONAME\).*?\[([^\]]+)\]/u)?.[1] ?? null;
  const needed = [...text.matchAll(/\(NEEDED\).*?\[([^\]]+)\]/gu)].map(match => match[1]);
  const rpath = text.match(/\(RPATH\).*?\[([^\]]+)\]/u)?.[1] ?? null;
  const runpath = text.match(/\(RUNPATH\).*?\[([^\]]+)\]/u)?.[1] ?? null;
  return { ptInterp: interp, soname, dtNeeded: needed, rpath, runpath };
};
const recursiveFiles = directory => {
  const result = [];
  const walk = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else { requireCondition(entry.isFile() && !entry.isSymbolicLink(), `package entry must be regular: ${full}`); result.push(full); }
    }
  };
  walk(directory);
  return result;
};
const recursiveStructure = directory => {
  const files = []; const dirs = [];
  const walk = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(current, entry.name); const stat = fs.lstatSync(full); const relative = PACKAGE_RELATIVE(full);
      requireCondition((stat.mode & 0o7000) === 0, `unsafe special mode: ${relative}`);
      requireCondition(!stat.isSymbolicLink() && stat.nlink === 1, `link forbidden: ${relative}`);
      if (entry.isDirectory()) { dirs.push({ path: relative, mode: stat.mode & 0o777 }); walk(full); continue; }
      requireCondition(entry.isFile(), `special file forbidden: ${relative}`); files.push(full);
    }
  };
  walk(directory); return { files, dirs };
};
const graph = readJson(path.join(V1_DIR, 'libauth-input-graph.v1.json'));
const oldRuntime = readJson(path.join(V1_DIR, 'external-runtime-closure.v1.json'));
const graphSourceFiles = () => graph.files.map(entry => ({ ...entry, source: path.join(LIBAUTH_ROOT, entry.path) }));
const verifyGraph = () => {
  requireCondition(graph.package.version === '3.1.0-next.8', 'unexpected Libauth version');
  requireCondition(graph.fileCount === 80 && graph.files.length === 80, 'unexpected Libauth graph count');
  requireCondition(hashFile(path.join(V1_DIR, 'libauth-input-graph.v1.json')) === FROZEN_GRAPH_RAW.sha256, 'frozen graph raw hash drift');
  for (const entry of graphSourceFiles()) { const real = sourceRealpath(entry.source); requireCondition(real === entry.source, `Libauth source realpath drift ${entry.path}`); requireCondition(fs.statSync(real).size === entry.bytes, `graph byte mismatch ${entry.path}`); requireCondition(hashFile(real) === entry.sha256, `graph hash mismatch ${entry.path}`); }
};
const materializeToolchain = () => {
  const output = [];
  for (const [relative, digest] of Object.entries(ESBUILD_SOURCE.package)) output.push({ package: 'esbuild', path: relative, ...copyRegular(path.join(ESBUILD_ROOT, relative), path.join(PACKAGE_DIR, 'toolchain/esbuild', relative), digest) });
  for (const [relative, digest] of Object.entries(ESBUILD_SOURCE.platform)) output.push({ package: '@esbuild/linux-x64', path: relative, ...copyRegular(path.join(ESBUILD_PLATFORM_ROOT, relative), path.join(PACKAGE_DIR, 'toolchain/esbuild-linux-x64', relative), digest) });
  copyRegular(ESBUILD_LOCK_SOURCE, path.join(PACKAGE_DIR, 'toolchain/pnpm-lock.yaml'), ESBUILD_LOCK_SHA256);
  return output;
};
const materializeLibauthGraph = () => {
  ensureDir(path.join(PACKAGE_DIR, 'source/libauth'));
  for (const entry of graph.files) copyRegular(path.join(LIBAUTH_ROOT, entry.path), path.join(PACKAGE_DIR, 'source/libauth', entry.path), entry.sha256);
};
const copyGraphToBuildRoot = root => {
  for (const entry of graph.files) copyRegular(path.join(PACKAGE_DIR, 'source/libauth', entry.path), path.join(root, 'src/libauth', entry.path), entry.sha256);
};
const endpointDestination = id => ({
  'engine:bchn': 'image/root/engines/bchn-leg',
  'engine:leanbch:vmbconf': 'image/root/engines/vmbconf',
  'engine:leanbch:costprobe': 'image/root/engines/costprobe',
}[id]);
const packageCwd = id => id === 'engine:bchn' ? 'image/workdirs/bchn' : 'image/workdirs/leanbch';
const packageEndpoint = endpoint => ({
  id: endpoint.id,
  path: endpointDestination(endpoint.id),
  source: endpoint.path,
  sourceRealpath: endpoint.realpath,
  bytes: endpoint.bytes,
  sha256: endpoint.sha256,
  argv: [endpointDestination(endpoint.id), ...endpoint.argv.slice(1).map(arg => arg === endpoint.path ? endpointDestination(endpoint.id) : arg)],
  argv0: endpointDestination(endpoint.id),
  cwd: packageCwd(endpoint.id),
  environment: endpoint.environment,
  deadlineMilliseconds: endpoint.deadlineMilliseconds,
});
const verifyFrozenRuntimeClosure = () => {
  requireCondition(hashFile(path.join(V1_DIR, 'external-runtime-closure.v1.json')) === FROZEN_RUNTIME_RAW.sha256, 'frozen runtime closure raw hash drift');
  requireCondition(oldRuntime.architecture.platform === 'linux' && oldRuntime.architecture.arch === 'x64', 'runtime architecture drift');
  const all = [oldRuntime.loader, ...oldRuntime.executables, ...oldRuntime.dsos];
  requireCondition(oldRuntime.executables.length === 3 && oldRuntime.dsos.length === 17, 'runtime roster count drift');
  for (const [index, entry] of all.entries()) { const requested = entry.path ?? entry.requestedPath; const real = sourceRealpath(requested); requireCondition(real === entry.realpath, `runtime source realpath drift ${requested}`); const stat = fs.statSync(real); requireCondition(stat.isFile() && stat.nlink === 1, `runtime source type drift ${requested}`); requireCondition(stat.size === entry.bytes && hashFile(real) === entry.sha256, `runtime source hash drift ${requested}`); requireCondition((stat.mode & 0o7000) === 0, `runtime source unsafe mode ${requested}`); const expectedMode = index === 0 ? RUNTIME_MODES.loader : index <= 3 ? RUNTIME_MODES.executables[index - 1] : RUNTIME_MODES.dsos[index - 4]; requireCondition((stat.mode & 0o777) === expectedMode, `runtime source mode drift ${requested}`); }
  verifyReadelfTool();
};
const makeShim = directory => {
  const shim = path.join(directory, 'entry-shim.mjs');
  const source = `import { decodeTransaction, decodeTransactionOutputs } from './libauth/message/transaction-encoding.js';\nimport { createVirtualMachineBch2026 } from './libauth/vm/instruction-sets/bch/2026/bch-2026-vm.js';\nexport { createVirtualMachineBch2026, decodeTransaction, decodeTransactionOutputs };\n`;
  fs.writeFileSync(shim, source);
  return shim;
};
const canonicalMetafile = (raw, shim, output) => {
  const normalize = value => value.replaceAll('\\\\', '/');
  const buildRoot = path.dirname(path.dirname(shim));
  const sourceRoot = normalize(path.join(buildRoot, 'src/libauth'));
  const canonicalPath = value => {
    const normalized = normalize(value);
    const resolved = normalize(path.resolve(buildRoot, normalized));
    if (resolved.startsWith(`${sourceRoot}/`)) return `libauth/${resolved.slice(sourceRoot.length + 1)}`;
    if (resolved === normalize(shim)) return 'entry-shim.mjs';
    return normalized;
  };
  const inputs = Object.fromEntries(Object.entries(raw.inputs ?? {}).map(([key, value]) => {
    const normalized = normalize(key);
    const relative = canonicalPath(normalized);
    const canonicalValue = { ...value, imports: (value.imports ?? []).map(item => ({ ...item, original: item.original.startsWith('/') ? canonicalPath(item.original) : item.original, path: canonicalPath(item.path) })) };
    return [relative, canonicalValue];
  }).sort(([a], [b]) => a.localeCompare(b)));
  const outputs = Object.fromEntries(Object.entries(raw.outputs ?? {}).map(([, value]) => ['bundle/libauth-bundle.mjs', { ...value, entryPoint: value.entryPoint ? 'entry-shim.mjs' : undefined, inputs: Object.fromEntries(Object.entries(value.inputs ?? {}).map(([key, item]) => [canonicalPath(key), item]).sort(([a], [b]) => a.localeCompare(b))) }]).map(([key, value]) => [key, JSON.parse(JSON.stringify(value, (_, item) => item === undefined ? undefined : item))]));
  return { inputs, outputs };
};
const maskJavaScript = source => {
  const chars = [...source]; const masked = [...source]; let state = 'code'; let quote = '';
  const blank = index => { if (masked[index] !== '\n' && masked[index] !== '\r') masked[index] = ' '; };
  for (let index = 0; index < chars.length; index += 1) {
    const current = chars[index]; const next = chars[index + 1];
    if (state === 'code') {
      if (current === '/' && next === '/') { blank(index); blank(index + 1); index += 1; state = 'line'; continue; }
      if (current === '/' && next === '*') { blank(index); blank(index + 1); index += 1; state = 'block'; continue; }
      if (current === "'" || current === '"' || current === '`') { quote = current; blank(index); state = 'string'; continue; }
      continue;
    }
    if (state === 'line') { if (current === '\n' || current === '\r') state = 'code'; else blank(index); continue; }
    if (state === 'block') { if (current === '*' && next === '/') { blank(index); blank(index + 1); index += 1; state = 'code'; } else blank(index); continue; }
    if (current === '\\') { blank(index); if (index + 1 < chars.length) blank(index + 1); index += 1; continue; }
    if (current === quote) { blank(index); state = 'code'; } else blank(index);
  }
  return masked.join('');
};
const stringLiterals = source => {
  const result = []; let state = 'code'; let quote = ''; let value = ''; let start = -1;
  for (let index = 0; index < source.length; index += 1) {
    const current = source[index]; const next = source[index + 1];
    if (state === 'code') {
      if (current === '/' && next === '/') { state = 'line'; index += 1; continue; }
      if (current === '/' && next === '*') { state = 'block'; index += 1; continue; }
      if (current === "'" || current === '"') { state = 'string'; quote = current; value = ''; start = index; }
      continue;
    }
    if (state === 'line') { if (current === '\n' || current === '\r') state = 'code'; continue; }
    if (state === 'block') { if (current === '*' && next === '/') { state = 'code'; index += 1; } continue; }
    if (current === '\\') { value += current + (source[index + 1] ?? ''); index += 1; continue; }
    if (current === quote) { result.push({ value, start }); state = 'code'; } else value += current;
  }
  return result;
};
const approvedEmbeddedWasm = () => graph.files.filter(entry => entry.path.endsWith('.base64.js')).sort((a, b) => a.path.localeCompare(b.path)).map(entry => {
  const text = fs.readFileSync(path.join(PACKAGE_DIR, 'source/libauth', entry.path), 'utf8');
  const match = text.match(/export const (\w+) = '([^']+)'/u); requireCondition(match !== null, `embedded WASM source grammar ${entry.path}`);
  const payload = match[2]; const decoded = Buffer.from(payload, 'base64'); requireCondition(decoded.toString('base64') === payload, `embedded WASM base64 grammar ${entry.path}`);
  return { sourcePath: `libauth/${entry.path}`, sourceSha256: entry.sha256, sourceBytes: entry.bytes, symbol: match[1], base64Chars: payload.length, decodedBytes: decoded.length, decodedSha256: sha256(decoded) };
});
const localBundleSource = sourcePath => path.join(PACKAGE_DIR, 'source', sourcePath);
const extractEmbeddedPayload = sourcePath => {
  const text = fs.readFileSync(localBundleSource(sourcePath), 'utf8'); const match = text.match(/export const \w+ = '([^']+)'/u);
  requireCondition(match !== null, `embedded WASM source missing ${sourcePath}`); return match[1];
};
const staticBundleChecks = source => {
  const code = maskJavaScript(source); const isCode = match => code[match.index] !== ' ' && code[match.index] !== '\n' && code[match.index] !== '\r';
  const codeMatches = expression => [...code.matchAll(expression)];
  const literals = stringLiterals(source);
  const staticImportMatches = [...source.matchAll(/\b(?:import|export)\s+(?:(?:[^;\n]*?)\s+from\s+)?(['"])([^'"]+)\1/gu)].filter(isCode);
  const imports = staticImportMatches.map(match => match[2]);
  const dynamicImports = codeMatches(/\bimport\s*\(/gu).map(match => match[0]);
  const requireCalls = codeMatches(/\brequire\s*\(/gu).map(match => match[0]);
  const evalCalls = codeMatches(/\beval\s*\(/gu).map(match => match[0]);
  const functionConstructors = codeMatches(/\bFunction\s*\(/gu).map(match => match[0]);
  const hostImports = imports.filter(item => /^(?:node:)?(?:fs|net|http|https|child_process|dgram|tls|worker_threads|vm)$/u.test(item) || item.startsWith('node:'));
  const externalWasm = imports.filter(item => /\.wasm(?:$|[?#])/u.test(item));
  const nativeAddons = literals.filter(item => /\.node(?:$|[?#])/u.test(item.value)).map(item => item.value);
  const webAssemblyOperations = codeMatches(/\bWebAssembly\s*\.\s*([A-Za-z_$][\w$]*)/gu).map(match => match[1]);
  const webAssemblyStreaming = webAssemblyOperations.filter(item => /Streaming$/u.test(item));
  const urlCalls = codeMatches(/\b(?:fetch|URL\.createObjectURL|URL\.revokeObjectURL|new\s+URL)\s*\(/gu).map(match => match[0]);
  const absoluteHostPaths = literals.filter(item => /^\/(?:home|tmp|usr|proc|sys|dev|var|etc)(?:\/|$)/u.test(item.value)).map(item => item.value);
  const urls = literals.filter(item => /^(?:https?|file|ws|wss):\/\//u.test(item.value)).map(item => item.value);
  const dataUrls = literals.filter(item => /^data:/u.test(item.value)).map(item => item.value);
  for (const url of dataUrls) requireCondition(/^data:[a-z0-9.+-]+;base64,[A-Za-z0-9+/]+=*$/u.test(url), `invalid data URL: ${url.slice(0, 64)}`);
  const dataUrlDecoded = dataUrls.map(url => { const payload = url.slice(url.indexOf(',') + 1); const bytes = Buffer.from(payload, 'base64'); requireCondition(bytes.toString('base64') === payload, `non-canonical data URL base64: ${url.slice(0, 64)}`); return { url, bytes: bytes.length, sha256: sha256(bytes) }; });
  const allowedWasm = new Set(['Memory', 'Table', 'instantiate']); requireCondition(webAssemblyOperations.every(item => allowedWasm.has(item)), `unapproved WebAssembly operation: ${webAssemblyOperations.join(',')}`);
  requireCondition(dynamicImports.length === 0 && requireCalls.length === 0 && evalCalls.length === 0 && functionConstructors.length === 0 && hostImports.length === 0 && externalWasm.length === 0 && nativeAddons.length === 0 && webAssemblyStreaming.length === 0 && urlCalls.length === 0 && absoluteHostPaths.length === 0 && urls.length === 0 && dataUrls.length === 0, 'bundle forbidden dynamic/host capability');
  const wasm = approvedEmbeddedWasm(); for (const item of wasm) { const text = fs.readFileSync(localBundleSource(item.sourcePath), 'utf8'); requireCondition(text.includes(extractEmbeddedPayload(item.sourcePath)), `embedded WASM payload missing ${item.sourcePath}`); }
  const exportMatches = codeMatches(/export\s*\{([^}]+)\}/gu); requireCondition(exportMatches.length === 1, 'bundle must contain exactly one textual export surface');
  const names = exportMatches[0][1].split(',').map(value => value.trim().split(/\s+as\s+/u)[0]).filter(Boolean).sort(); requireCondition(JSON.stringify(names) === JSON.stringify([...BUNDLE_EXPORTS].sort()), `bundle export surface mismatch: ${names.join(',')}`);
  return { imports, dynamicImports, requireCalls, evalCalls, functionConstructors, hostImports, nativeAddons, externalWasm, webAssemblyStreaming, urlCalls, absoluteHostPaths, urls, dataUrls, dataUrlDecoded, webAssemblyOperations, approvedEmbeddedWasm: wasm, approvedEmbeddedSecpWasm: wasm.find(item => item.sourcePath === 'libauth/bin/secp256k1/secp256k1.base64.js'), exportSurface: names };
};
const touchTree = (directory, seconds) => { for (const file of recursiveFiles(directory)) fs.utimesSync(file, seconds, seconds); };
const buildOnce = (root, label) => {
  const source = path.join(root, 'src'); const output = path.join(root, 'out/libauth-bundle.mjs'); const metafile = path.join(root, 'out/meta.json');
  ensureDir(source); ensureDir(path.dirname(output)); copyGraphToBuildRoot(root);
  const shim = makeShim(source); const mtime = label === 'a' ? 0 : 1; touchTree(source, mtime); fs.utimesSync(shim, mtime, mtime);
  const args = ['--bundle', '--format=esm', '--platform=node', '--target=node22.23', '--tree-shaking=true', '--minify=false', '--legal-comments=none', '--loader:.wasm=base64', '--log-level=warning', `--outfile=${output}`, `--metafile=${metafile}`, shim];
  const env = { LANG: 'C', LC_ALL: 'C', TZ: label === 'a' ? 'UTC' : 'Etc/UTC', SOURCE_DATE_EPOCH: '0' };
  const executable = path.join(PACKAGE_DIR, 'toolchain/esbuild-linux-x64/bin/esbuild');
  requireCondition(hashFile(executable) === ESBUILD_SOURCE.platform['bin/esbuild'], 'vendored native esbuild drift');
  run(executable, args, { cwd: root, env });
  const bundle = fs.readFileSync(output); const rawMeta = readJson(metafile); const meta = canonicalMetafile(rawMeta, shim, output); const sourceText = bundle.toString('utf8');
  const template = value => value === executable ? 'toolchain/esbuild-linux-x64/bin/esbuild' : value.replaceAll(root, '<temp-root>');
  return { label, bytes: bundle.length, sha256: sha256(bundle), output: bundle, static: staticBundleChecks(sourceText), metafile: meta, metafileBytes: Buffer.from(stable(meta)), metafileSha256: sha256(Buffer.from(stable(meta))), execution: { executable: 'toolchain/esbuild-linux-x64/bin/esbuild', argv: [executable, ...args].map(template), cwd: '<temp-root>', environment: env, platform: 'linux', arch: 'x64' } };
};
const materializeBundle = () => {
  verifyGraph();
  const rootA = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldkit-materialized-a-')); const rootB = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldkit-materialized-b-'));
  try {
    const a = buildOnce(rootA, 'a'); const b = buildOnce(rootB, 'b');
    requireCondition(a.sha256 === b.sha256 && a.bytes === b.bytes, 'bundle reproducibility mismatch');
    requireCondition(a.metafileSha256 === b.metafileSha256 && a.metafileBytes.equals(b.metafileBytes), 'canonical metafile reproducibility mismatch');
    requireCondition(a.sha256 === FROZEN_BUNDLE.sha256 && a.bytes === FROZEN_BUNDLE.bytes, 'bundle differs from frozen reproduction authority');
    requireCondition(a.metafileSha256 === FROZEN_METAFILE.sha256 && a.metafileBytes.length === FROZEN_METAFILE.bytes, 'metafile differs from frozen reproduction authority');
    const bundlePath = path.join(PACKAGE_DIR, 'bundle/libauth-bundle.mjs'); const metaPath = path.join(PACKAGE_DIR, 'bundle/libauth-bundle.metafile.json'); ensureDir(path.dirname(bundlePath));
    fs.writeFileSync(bundlePath, a.output); fs.chmodSync(bundlePath, 0o644); fs.writeFileSync(metaPath, a.metafileBytes); fs.chmodSync(metaPath, 0o644);
    return { output: { path: 'bundle/libauth-bundle.mjs', bytes: a.bytes, sha256: a.sha256 }, metafile: { path: 'bundle/libauth-bundle.metafile.json', bytes: a.metafileBytes.length, sha256: a.metafileSha256 }, reproducible: true, buildRoots: ['distinct-temp-root-a', 'distinct-temp-root-b'], executions: [a.execution, b.execution], static: a.static };
  } finally { fs.rmSync(rootA, { recursive: true, force: true }); fs.rmSync(rootB, { recursive: true, force: true }); }
};
const materializeImage = () => {
  verifyFrozenRuntimeClosure();
  const files = []; const copy = (entry, destination, role, licenseRefs, extra = {}) => {
    const source = entry.path ?? entry.realpath; const real = sourceRealpath(source); requireCondition(real === entry.realpath, `source closure realpath mismatch ${source}`);
    const item = copyRegular(source, path.join(PACKAGE_DIR, destination), entry.sha256); const sourceStat = fs.statSync(real); const imageFile = path.join(PACKAGE_DIR, destination); const imageStat = fs.statSync(imageFile); const elf = readelf(imageFile);
    requireCondition(sourceStat.size === entry.bytes && hashFile(real) === entry.sha256, `source closure changed before copy ${source}`);
    files.push({ ...extra, role, path: destination, source, sourceRealpath: real, sourceBytes: sourceStat.size, sourceSha256: hashFile(real), sourceMode: sourceStat.mode & 0o777, imageBytes: imageStat.size, imageSha256: hashFile(imageFile), imageMode: imageStat.mode & 0o777, bytes: item.bytes, sha256: item.sha256, mode: item.mode, elf, licenseRefs }); return files.at(-1);
  };
  const loaderSource = oldRuntime.loader; const loader = copy(loaderSource, 'image/root/lib64/ld-linux-x86-64.so.2', 'loader', ['package:glibc'], { id: 'loader', requestedPath: loaderSource.requestedPath, soname: 'ld-linux-x86-64.so.2' });
  const executables = oldRuntime.executables.map(endpoint => { const projection = packageEndpoint(endpoint); return copy(endpoint, projection.path, 'executable', [endpoint.id === 'engine:bchn' ? 'source:bch-conformance' : 'source:LeanBCH'], { id: endpoint.id, sourceArgv: endpoint.argv, sourceArgv0: endpoint.argv0, sourceCwd: endpoint.cwd }); });
  const dsos = oldRuntime.dsos.map(dso => copy(dso, `image/root/usr/lib/${dso.soname}`, 'dso', [`package:${dso.soname === 'libcrypto.so.3' ? 'openssl' : dso.soname.startsWith('libboost_') ? 'boost-libs' : dso.soname.startsWith('libgmp') ? 'gmp' : dso.soname.startsWith('libstdc++') ? 'libstdc++' : dso.soname === 'libgcc_s.so.1' ? 'libgcc' : dso.soname === 'libz.so.1' ? 'zlib' : dso.soname.startsWith('libbrotli') ? 'brotli' : dso.soname === 'libzstd.so.1' ? 'zstd' : 'glibc'}`], { id: `dso:${dso.soname}`, soname: dso.soname, usedBy: dso.usedBy }));
  for (const workdir of ['image/workdirs/bchn/.keep', 'image/workdirs/leanbch/.keep']) { ensureDir(path.join(PACKAGE_DIR, path.dirname(workdir))); fs.chmodSync(path.join(PACKAGE_DIR, path.dirname(workdir)), 0o755); if (fs.existsSync(path.join(PACKAGE_DIR, workdir))) fs.chmodSync(path.join(PACKAGE_DIR, workdir), 0o644); fs.writeFileSync(path.join(PACKAGE_DIR, workdir), 'sealed-cwd-template\n'); fs.chmodSync(path.join(PACKAGE_DIR, workdir), 0o444); fs.chmodSync(path.join(PACKAGE_DIR, path.dirname(workdir)), 0o555); }
  const launch = oldRuntime.launch; const endpoints = oldRuntime.executables.map(packageEndpoint); return { architecture: { platform: 'linux', arch: 'x64' }, root: 'image/root', sourceClosure: { path: FROZEN_RUNTIME_RAW.path, bytes: FROZEN_RUNTIME_RAW.bytes, rawSha256: FROZEN_RUNTIME_RAW.sha256, contentSha256: domainDigest(RUNTIME_CONTENT_DOMAIN, fs.readFileSync(path.join(V1_DIR, 'external-runtime-closure.v1.json'))) }, readelf: READELF, loader, executables, dsos, cwdTemplates: ['image/workdirs/bchn', 'image/workdirs/leanbch'], cwdTemplatePolicy: 'sealed package templates; future launch must create a separate per-attempt uid-owned 0700 fsynced cwd and must not write the package tree', imageLaunchQualification: false, executionAllowed: false, downstreamAuthorization: null, launch: { shell: launch.shell, stdio: launch.stdio, inheritedEnvironment: false, packageLocalRoot: true, argv0EqualsImageExecutable: true, extraInheritedFds: launch.extraInheritedFds, externalCombinedOutputCapBytes: launch.externalCombinedOutputCapBytes, terminationGraceMilliseconds: launch.terminationGraceMilliseconds, bchnDeadlineMilliseconds: launch.bchnDeadlineMilliseconds, leanSharedDeadlineMilliseconds: launch.leanSharedDeadlineMilliseconds, leanRemainingConversion: launch.leanRemainingConversion, endpoints, loaderInvocation: { mode: 'direct-loader-inhibit-cache', loaderPath: 'image/root/lib64/ld-linux-x86-64.so.2', argvTemplate: ['<package-absolute-root>/image/root/lib64/ld-linux-x86-64.so.2', '--inhibit-cache', '--library-path', '<package-absolute-root>/image/root/usr/lib'], argsTemplate: ['--inhibit-cache', '--library-path', '<package-absolute-root>/image/root/usr/lib'], libraryPathPolicy: 'absolute package-root-derived path; no host fallback', executed: false }, loaderEnvironmentPolicy: 'exact replacement; no LD_LIBRARY_PATH, LD_PRELOAD, or inherited loader variables', hostFallbackCheck: 'not-run', dlopenClaim: 'unqualified' }, blocker: 'Image is byte-materialized but launch is not qualified; no engine or VM was launched.' };
};
const materializeLicenses = () => {
  const copied = []; for (const [source, destination] of LICENSE_FILES) if (fs.existsSync(source)) { const item = copyRegular(source, path.join(PACKAGE_DIR, destination)); copied.push({ path: destination, source: item.sourceRealpath, bytes: item.bytes, sha256: item.sha256, mode: item.mode }); }
  const packages = [
    ['glibc', '2.43+r37+gfdf10644d6ee-1', ['GPL-2.0-or-later', 'LGPL-2.1-or-later']], ['openssl', '3.6.3-1', ['Apache-2.0']], ['boost-libs', '1.91.0-1', ['BSL-1.0']], ['gmp', '6.3.0-3', ['GPL-2.0-or-later', 'LGPL-3.0-or-later']], ['libstdc++', '16.1.1+r346+g4e03491b401d-4', ['GPL-3.0-or-later WITH GCC-exception-3.1', 'GFDL-1.3-or-later']], ['libgcc', '16.1.1+r346+g4e03491b401d-4', ['GPL-3.0-or-later WITH GCC-exception-3.1', 'GFDL-1.3-or-later']], ['zlib', '1:1.3.2-3', ['Zlib']], ['brotli', '1.2.0-1', ['MIT']], ['zstd', '1.5.7-3', ['BSD-3-Clause', 'GPL-2.0-only']], ['esbuild', '0.28.1', ['MIT']], ['libauth', '3.1.0-next.8', ['MIT']], ['bch-conformance', 'workspace-pinned', ['MIT', 'Apache-2.0']], ['LeanBCH', 'workspace-pinned', ['Apache-2.0']],
  ].map(([name, version, licenses]) => { const id = ['bch-conformance', 'LeanBCH'].includes(name) ? `source:${name}` : `package:${name}`; return { id, name, version, licenses, noticeFiles: copied.filter(item => item.path.includes(`/host/${name}/`) || (item.path.includes('/esbuild/') && name === 'esbuild') || (item.path.includes('/libauth/') && name === 'libauth') || (item.path.includes('/bch-conformance/') && name === 'bch-conformance') || (item.path.includes('/LeanBCH/') && name === 'LeanBCH')).map(item => item.path), distributionStatus: ['glibc', 'boost-libs', 'gmp'].includes(name) ? 'incomplete-metadata-only' : 'notice-materialized', licenseRefs: [id] }; });
  const provenance = { schema: 'shieldkit-labs/p2/gate-b/cohort-engine-runtime-materialized/v1/license-provenance', status: 'notice-mapping-fail-closed', executionAllowed: false, distributionLicenseClosure: 'incomplete-metadata-only-for-glibc-boost-gmp', packages, copiedNoticeFiles: copied, sourceLicenses: copied.filter(item => !item.path.startsWith('licenses/host/')), referencePolicy: 'every image licenseRef resolves to exactly one package id or source license id; metadata-only packages are not distribution-complete' };
  writeJson(path.join(PACKAGE_DIR, 'licenses/provenance.v1.json'), provenance); return provenance;
};
const generatorNodeProvenance = () => ({ role: 'informational-only', executable: process.execPath, realpath: fs.realpathSync(process.execPath), sha256: hashFile(process.execPath), version: process.version, v8: process.versions.v8, platform: process.platform, arch: process.arch });
const writeDescriptors = (bundle, image, licenses) => {
  const copiedGraphPath = path.join(PACKAGE_DIR, FROZEN_GRAPH_RAW.path); const graphBinding = { path: FROZEN_GRAPH_RAW.path, bytes: fs.statSync(copiedGraphPath).size, rawSha256: hashFile(copiedGraphPath), contentSha256: domainDigest(GRAPH_CONTENT_DOMAIN, fs.readFileSync(copiedGraphPath)), package: graph.package, entrypoints: graph.entrypoints, fileCount: graph.fileCount, totalBytes: graph.totalBytes, sortedPathSizeSha256ListDigest: graph.sortedPathSizeSha256ListDigest };
  const nativePath = path.join(PACKAGE_DIR, 'toolchain/esbuild-linux-x64/bin/esbuild'); const wrapperPath = path.join(PACKAGE_DIR, 'toolchain/esbuild/bin/esbuild');
  const artifactRosterSha256 = domainDigest('shieldkit-labs/p2/gate-b/artifact-roster/v1', Buffer.from(stable(ARTIFACT_ROSTER), 'utf8'));
  const receipt = { schema: 'shieldkit-labs/p2/gate-b/cohort-engine-runtime-materialized/v1/libauth-bundle-receipt', status: 'materialized-unqualified', executionAllowed: false, bundleMaterialized: true, bundleSemanticQualification: false, inputGraph: 'source/libauth-input-graph.v1.json', inputGraphBinding: graphBinding, generatorNode: generatorNodeProvenance(), bundler: { name: ESBUILD_SOURCE.name, version: ESBUILD_SOURCE.version, license: ESBUILD_SOURCE.license, sourceRoot: 'toolchain/esbuild', sourceRootHost: ESBUILD_ROOT, sourceRootHostRole: 'informational-only', launcher: 'toolchain/esbuild-linux-x64/bin/esbuild', launcherArgv0: 'toolchain/esbuild-linux-x64/bin/esbuild', nativeBinary: 'toolchain/esbuild-linux-x64/bin/esbuild', nativeBinarySha256: hashFile(nativePath), nativeBinaryBytes: fs.statSync(nativePath).size, wrapper: 'toolchain/esbuild/bin/esbuild', wrapperSha256: hashFile(wrapperPath), packageJsonSha256: ESBUILD_SOURCE.package['package.json'], platformPackageJsonSha256: ESBUILD_SOURCE.platform['package.json'], packageIntegrity: ESBUILD_INTEGRITY.package, platformIntegrity: ESBUILD_INTEGRITY.platform, lockPath: 'toolchain/pnpm-lock.yaml', lockSha256: ESBUILD_LOCK_SHA256, platform: 'linux', arch: 'x64', argvPolicy: 'direct package-local native esbuild; no node launcher, wrapper execution, npx, or PATH lookup', environmentReplacement: bundle.executions[0].environment, execution: bundle.executions[0], reproducibilityExecution: bundle.executions, cwdPolicy: 'distinct temporary roots; canonical cwd is <temp-root>; no absolute cwd in metafile' }, requiredExports: BUNDLE_EXPORTS, requiredSemantics: { standard: true, verifyCall: false, expectedCorpusInput: false, exactFixtureTransactionAndSourceOutputs: true }, authority: { bundle: FROZEN_BUNDLE, metafile: FROZEN_METAFILE, canonicalMetafile: { encoding: 'stable-json-v1', lexicographicObjectKeys: true, trailingNewline: true, bytes: FROZEN_METAFILE.bytes, sha256: FROZEN_METAFILE.sha256 }, graphContentSha256: graphBinding.contentSha256, artifactRosterSha256 }, output: FROZEN_BUNDLE, metafile: FROZEN_METAFILE, reproducibility: { distinctTempRoots: true, distinctMtimeAndEnvironment: true, outputByteIdentical: bundle.reproducible, canonicalMetafileByteIdentical: bundle.reproducible, comparedToFrozenPackage: false, reproductionCommand: 'node generate.mjs --reproduce-check' }, staticChecks: bundle.static, blocker: 'Bundle is byte-materialized and statically checked but not imported/evaluated; semantic qualification remains false.' };
  const materialization = { schema: 'shieldkit-labs/p2/gate-b/cohort-engine-runtime-materialized/v1/materialization', status: 'materialized-static-unqualified', executionAllowed: false, bundleSemanticQualification: false, imageLaunchQualification: false, downstreamAuthorization: null, artifacts: { bundleReceipt: 'libauth-bundle-receipt.v1.json', runtimeImage: 'runtime-image.v1.json', licenseProvenance: 'licenses/provenance.v1.json', sourceGraph: 'source/libauth-input-graph.v1.json', sourceClosure: 'source/external-runtime-closure.v1.json' }, bindings: { graphRawSha256: graphBinding.rawSha256, graphContentSha256: graphBinding.contentSha256, runtimeClosureRawSha256: image.sourceClosure.rawSha256, runtimeClosureContentSha256: image.sourceClosure.contentSha256 }, roster: { artifacts: [...ARTIFACT_ROSTER], artifactRosterSha256, kats: [...KAT_ROSTER], schemas: [...SCHEMA_ROSTER] }, blockers: ['Bundle was not imported or evaluated.', 'No engine or VM was launched.', 'Dynamic loader behavior and process launch remain unqualified.', 'Distribution license closure is incomplete for glibc, Boost, and GMP metadata-only entries.', 'Downstream authorization is null.'] };
  writeJson(path.join(PACKAGE_DIR, 'libauth-bundle-receipt.v1.json'), receipt); writeJson(path.join(PACKAGE_DIR, 'runtime-image.v1.json'), image); writeJson(path.join(PACKAGE_DIR, 'materialization.v1.json'), materialization);
};
const buildManifest = () => {
  const excluded = new Set(['MANIFEST.json', 'SHA256SUMS']); const structure = recursiveStructure(PACKAGE_DIR); const files = structure.files.filter(file => !excluded.has(path.basename(file))).map(file => ({ path: PACKAGE_RELATIVE(file), bytes: fs.statSync(file).size, sha256: hashFile(file), contentDigest: domainDigest(MANIFEST_CONTENT_DOMAIN, fs.readFileSync(file)), mode: statMode(file) }));
  const directories = structure.dirs.filter(item => item.path !== '').sort((a, b) => a.path.localeCompare(b.path)); const manifest = { schema: 'shieldkit-labs/p2/gate-b/cohort-engine-runtime-materialized/v1/manifest', status: 'materialized-static-unqualified', executionAllowed: false, packageRoot: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-engine-runtime-materialized-v1', fileCount: files.length, files, directoryCount: directories.length, directories, rosterDigest: manifestRosterDigest(files, directories), allowedAncestors: ['.'], domainSeparator: MANIFEST_CONTENT_DOMAIN, checksumEnvelope: { algorithm: 'SHA-256', format: '<hex64>  <root>/<relative-path>\\n', root: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-engine-runtime-materialized-v1', manifestFirst: true, includes: 'MANIFEST.json plus every manifest.files entry', contentDigestField: 'sha256(domainSeparator + NUL + fileBytes)' } };
  writeJson(path.join(PACKAGE_DIR, 'MANIFEST.json'), manifest); const checksumNames = ['MANIFEST.json', ...files.map(item => item.path)]; fs.writeFileSync(path.join(PACKAGE_DIR, 'SHA256SUMS'), checksumNames.map(name => `${hashFile(path.join(PACKAGE_DIR, name))}  ${'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-engine-runtime-materialized-v1/' + name}\n`).join('')); return manifest;
};
const check = () => {
  const manifest = readJson(path.join(PACKAGE_DIR, 'MANIFEST.json')); requireCondition(manifest.executionAllowed === false && manifest.fileCount === 145 && manifest.directoryCount === 49, 'manifest roster count drift'); requireCondition(manifest.rosterDigest === manifestRosterDigest(manifest.files, manifest.directories), 'manifest roster digest drift');
  for (const file of manifest.files) { const local = path.join(PACKAGE_DIR, file.path); requireCondition(fs.statSync(local).size === file.bytes, `manifest bytes mismatch ${file.path}`); requireCondition(hashFile(local) === file.sha256, `manifest hash mismatch ${file.path}`); requireCondition(domainDigest(MANIFEST_CONTENT_DOMAIN, fs.readFileSync(local)) === file.contentDigest, `manifest content digest mismatch ${file.path}`); requireCondition(statMode(local) === file.mode && (fs.lstatSync(local).mode & 0o7000) === 0, `manifest mode mismatch ${file.path}`); }
  const checks = fs.readFileSync(path.join(PACKAGE_DIR, 'SHA256SUMS'), 'utf8').trimEnd().split('\n'); const names = ['MANIFEST.json', ...manifest.files.map(item => item.path)]; requireCondition(checks.length === names.length, 'checksum roster mismatch'); for (let i = 0; i < checks.length; i += 1) { const [digest, ...rest] = checks[i].split('  '); requireCondition(digest === hashFile(path.join(PACKAGE_DIR, names[i])), `checksum mismatch ${names[i]}`); requireCondition(rest.join('  ') === `research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-engine-runtime-materialized-v1/${names[i]}`, `checksum path mismatch ${names[i]}`); }
  for (const [relative, digest] of Object.entries(ESBUILD_SOURCE.package)) requireCondition(hashFile(path.join(PACKAGE_DIR, 'toolchain/esbuild', relative)) === digest, `vendored esbuild mismatch ${relative}`);
  for (const [relative, digest] of Object.entries(ESBUILD_SOURCE.platform)) requireCondition(hashFile(path.join(PACKAGE_DIR, 'toolchain/esbuild-linux-x64', relative)) === digest, `vendored platform mismatch ${relative}`);
  const receipt = readJson(path.join(PACKAGE_DIR, 'libauth-bundle-receipt.v1.json')); requireCondition(receipt.executionAllowed === false && receipt.bundleSemanticQualification === false, 'bundle qualification drift'); requireCondition(receipt.reproducibility.outputByteIdentical && receipt.reproducibility.canonicalMetafileByteIdentical, 'reproducibility was not recorded');
  const image = readJson(path.join(PACKAGE_DIR, 'runtime-image.v1.json')); requireCondition(image.executionAllowed === false && image.imageLaunchQualification === false && image.downstreamAuthorization === null, 'image qualification drift'); for (const file of [image.loader, ...image.executables, ...image.dsos]) { const local = path.join(PACKAGE_DIR, file.path); requireCondition(hashFile(local) === file.sha256 && fs.statSync(local).size === file.bytes, `image file mismatch ${file.path}`); }
  return { ok: true, files: manifest.fileCount, bundle: receipt.output.sha256, imageFiles: 1 + image.executables.length + image.dsos.length };
};
const reproduceCheck = () => {
  verifyGraph(); verifyFrozenRuntimeClosure();
  const rootA = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldkit-reproduce-check-a-')); const rootB = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldkit-reproduce-check-b-'));
  try { const a = buildOnce(rootA, 'a'); const b = buildOnce(rootB, 'b'); const frozenBundle = readJson(path.join(PACKAGE_DIR, 'libauth-bundle-receipt.v1.json')); const frozenMeta = fs.readFileSync(path.join(PACKAGE_DIR, frozenBundle.metafile.path)); const frozenOutput = fs.readFileSync(path.join(PACKAGE_DIR, frozenBundle.output.path)); requireCondition(a.output.equals(frozenOutput) && b.output.equals(frozenOutput), 'reproduce-check bundle differs from frozen package'); requireCondition(a.metafileBytes.equals(frozenMeta) && b.metafileBytes.equals(frozenMeta), 'reproduce-check metafile differs from frozen package'); return { ok: true, outputSha256: sha256(frozenOutput), metafileSha256: sha256(frozenMeta), distinctRoots: true }; } finally { fs.rmSync(rootA, { recursive: true, force: true }); fs.rmSync(rootB, { recursive: true, force: true }); }
};
if (process.argv.includes('--check')) console.log(JSON.stringify(check()));
else if (process.argv.includes('--reproduce-check')) console.log(JSON.stringify(reproduceCheck()));
else { verifyGraph(); materializeToolchain(); materializeLibauthGraph(); ensureDir(path.join(PACKAGE_DIR, 'source')); copyRegular(path.join(V1_DIR, 'libauth-input-graph.v1.json'), path.join(PACKAGE_DIR, 'source/libauth-input-graph.v1.json'), FROZEN_GRAPH_RAW.sha256); copyRegular(path.join(V1_DIR, 'external-runtime-closure.v1.json'), path.join(PACKAGE_DIR, 'source/external-runtime-closure.v1.json'), FROZEN_RUNTIME_RAW.sha256); const bundle = materializeBundle(); const image = materializeImage(); const licenses = materializeLicenses(); writeDescriptors(bundle, image, licenses); buildManifest(); console.log(JSON.stringify(check())); }
