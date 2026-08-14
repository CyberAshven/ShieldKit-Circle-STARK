import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

export const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-node-runtime-materialized-v1';
export const CONTENT_DOMAIN = 'shieldkit-labs/p2/gate-b/node-runtime-manifest-content/v1';
export const ROSTER_DOMAIN = 'shieldkit-labs/p2/gate-b/node-runtime-manifest-roster/v1';
export const SOURCE_DOMAIN = 'shieldkit-labs/p2/gate-b/node-runtime-source-content/v1';

export const EXPECTED_FILES = [
  'COMMAND.txt', 'MANIFEST.json', 'README.md', 'SHA256SUMS', 'generate.mjs',
  'licenses/host/libgcc/RUNTIME.LIBRARY.EXCEPTION',
  'licenses/host/libstdc++/RUNTIME.LIBRARY.EXCEPTION', 'licenses/node/LICENSE',
  'licenses/provenance.v1.json', 'licenses/provenance.v1.schema.json',
  'materialization.v1.json', 'materialization.v1.schema.json',
  'mutation.test.mjs', 'reproducibility.test.mjs', 'runtime-image.v1.json',
  'runtime-image.v1.schema.json', 'semantic-validators.mjs', 'source/node-runtime-closure.v1.json',
  'source/node-runtime-closure.v1.schema.json', 'validate.mjs', 'manifest.v1.schema.json',
  'image/root/bin/node', 'image/root/lib64/ld-linux-x86-64.so.2',
  'image/root/usr/lib/libc.so.6', 'image/root/usr/lib/libdl.so.2',
  'image/root/usr/lib/libgcc_s.so.1', 'image/root/usr/lib/libm.so.6',
  'image/root/usr/lib/libpthread.so.0', 'image/root/usr/lib/libstdc++.so.6'
].sort((a, b) => a.localeCompare(b));
export const EXPECTED_DIRS = [
  'image', 'image/root', 'image/root/bin', 'image/root/lib64', 'image/root/usr',
  'image/root/usr/lib', 'licenses', 'licenses/host', 'licenses/host/libgcc',
  'licenses/host/libstdc++', 'licenses/node', 'source'
].map(relative => ({ path: relative, mode: 0o755 }));

const SOURCE_NODE = '/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node';
const SOURCE_LOADER = '/usr/lib/ld-linux-x86-64.so.2';
const DSO_NAMES = ['libdl.so.2', 'libstdc++.so.6', 'libm.so.6', 'libgcc_s.so.1', 'libpthread.so.0', 'libc.so.6'];
const DSO_SOURCES = Object.fromEntries(DSO_NAMES.map(name => [name, `/usr/lib/${name}`]));
const SOURCE_REALPATHS = { node: SOURCE_NODE, loader: SOURCE_LOADER, 'libdl.so.2': '/usr/lib/libdl.so.2', 'libstdc++.so.6': '/usr/lib/libstdc++.so.6.0.35', 'libm.so.6': '/usr/lib/libm.so.6', 'libgcc_s.so.1': '/usr/lib/libgcc_s.so.1', 'libpthread.so.0': '/usr/lib/libpthread.so.0', 'libc.so.6': '/usr/lib/libc.so.6' };
const DSO_MODES = Object.fromEntries(DSO_NAMES.map(name => [name, name === 'libgcc_s.so.1' ? 0o644 : 0o755]));
const NODE_SHA256 = '93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068';
const FORBIDDEN_ENVIRONMENT = ['NODE_OPTIONS', 'PATH', 'LD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_AUDIT', 'LD_DEBUG', 'LD_ASSUME_KERNEL', 'NODE_PATH'];
const REPLACEMENT_ENVIRONMENT = { LANG: 'C', LC_ALL: 'C', TZ: 'UTC', NODE_ENV: 'production' };
const DIRECT_LOADER_ARGV = ['<package-absolute-root>/image/root/lib64/ld-linux-x86-64.so.2', '--inhibit-cache', '--library-path', '<package-absolute-root>/image/root/usr/lib', '<package-absolute-root>/image/root/bin/node', '--no-addons', '<exact-reviewed-controller>', '--authorization-fd=3'];
const DIRECT_LOADER_RECIPE = 'loader --inhibit-cache --library-path <absolute-package-node-libdir> node --no-addons <exact-reviewed-controller> --authorization-fd=3';
const DIRECT_LOADER_COMMAND = '<package-absolute-root>/image/root/lib64/ld-linux-x86-64.so.2 --inhibit-cache --library-path <absolute-package-node-libdir> <package-absolute-root>/image/root/bin/node --no-addons <exact-reviewed-controller> --authorization-fd=3';
const LICENSE_NOTICES = [
  { path: 'licenses/node/LICENSE', source: `${SOURCE_NODE.replace('/bin/node', '')}/LICENSE`, bytes: 145485, mode: 0o644, nlink: 1, sha256: 'c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4' },
  { path: 'licenses/host/libgcc/RUNTIME.LIBRARY.EXCEPTION', source: '/usr/share/licenses/libgcc/RUNTIME.LIBRARY.EXCEPTION', bytes: 3324, mode: 0o644, nlink: 1, sha256: '9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74' },
  { path: 'licenses/host/libstdc++/RUNTIME.LIBRARY.EXCEPTION', source: '/usr/share/licenses/libstdc++/RUNTIME.LIBRARY.EXCEPTION', bytes: 3324, mode: 0o644, nlink: 1, sha256: '9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74' }
];
const LICENSE_PACKAGES = [
  { id: 'package:node', name: 'node', version: '22.23.1', licenses: ['MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ICU', 'MIT-0'], licenseRefs: ['package:node'], noticeFiles: ['licenses/node/LICENSE'], distributionStatus: 'notice-materialized' },
  { id: 'package:glibc', name: 'glibc', version: '2.43+r37+gfdf10644d6ee-1', licenses: ['GPL-2.0-or-later', 'LGPL-2.1-or-later'], licenseRefs: ['package:glibc'], noticeFiles: [], distributionStatus: 'incomplete-metadata-only' },
  { id: 'package:libstdc++', name: 'libstdc++', version: '16.1.1+r346+g4e03491b401d-4', licenses: ['GPL-3.0-or-later WITH GCC-exception-3.1', 'GFDL-1.3-or-later'], licenseRefs: ['package:libstdc++'], noticeFiles: ['licenses/host/libstdc++/RUNTIME.LIBRARY.EXCEPTION'], distributionStatus: 'notice-materialized' },
  { id: 'package:libgcc', name: 'libgcc', version: '16.1.1+r346+g4e03491b401d-4', licenses: ['GPL-3.0-or-later WITH GCC-exception-3.1', 'GFDL-1.3-or-later'], licenseRefs: ['package:libgcc'], noticeFiles: ['licenses/host/libgcc/RUNTIME.LIBRARY.EXCEPTION'], distributionStatus: 'notice-materialized' }
];
const FIXED_ELF = {
  loader: { ptInterp: null, soname: 'ld-linux-x86-64.so.2', dtNeeded: [], rpath: null, runpath: null },
  node: { ptInterp: '/lib64/ld-linux-x86-64.so.2', soname: null, dtNeeded: [...DSO_NAMES, 'ld-linux-x86-64.so.2'], rpath: null, runpath: null },
  'libdl.so.2': { ptInterp: null, soname: 'libdl.so.2', dtNeeded: ['libc.so.6'], rpath: null, runpath: null },
  'libstdc++.so.6': { ptInterp: null, soname: 'libstdc++.so.6', dtNeeded: ['libm.so.6', 'libc.so.6', 'ld-linux-x86-64.so.2', 'libgcc_s.so.1'], rpath: null, runpath: null },
  'libm.so.6': { ptInterp: null, soname: 'libm.so.6', dtNeeded: ['libc.so.6', 'ld-linux-x86-64.so.2'], rpath: null, runpath: null },
  'libgcc_s.so.1': { ptInterp: null, soname: 'libgcc_s.so.1', dtNeeded: ['libc.so.6', 'ld-linux-x86-64.so.2'], rpath: null, runpath: null },
  'libpthread.so.0': { ptInterp: null, soname: 'libpthread.so.0', dtNeeded: ['libc.so.6'], rpath: null, runpath: null },
  'libc.so.6': { ptInterp: '/usr/lib/ld-linux-x86-64.so.2', soname: 'libc.so.6', dtNeeded: ['ld-linux-x86-64.so.2'], rpath: null, runpath: null }
};
const FIXED_HASHES = { loader: 'd52fe2ff87fff536ed5c5eae8e954cb50655884e4709fedd24cf57f9ec98ad80', node: NODE_SHA256, 'libdl.so.2': '20160c529bfd255fd820273cfed23698f4a70e5d80e4d9ad1f580ab9ce5e2463', 'libstdc++.so.6': '2c0ec5cdcaa4a044329ad19ba40b73e3e61c16b3f00f5c8184b0d72816480614', 'libm.so.6': '8f85ea3a02885cda4ecff8758e6e758c69ccaa25b6580cb97b5713ac512f0a1b', 'libgcc_s.so.1': '0c6c78d4632bf37a274e053fea871f35b06f0578644593a291ca1ee0f12dffbb', 'libpthread.so.0': 'efd89a5cf95482cd92f1230320e95c3ab5f1f27bbf099fd166db36e2122a2882', 'libc.so.6': '9bf40a540836d90c7d46c95eeb222a217597834eea29ab9e537428317c021c3a' };
const FIXED_BYTES = { loader: 246760, node: 124835376, 'libdl.so.2': 14352, 'libstdc++.so.6': 2935832, 'libm.so.6': 1251952, 'libgcc_s.so.1': 182512, 'libpthread.so.0': 14360, 'libc.so.6': 2186528 };
const deepFreeze = value => { if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child); } return value; };
deepFreeze(EXPECTED_FILES); deepFreeze(EXPECTED_DIRS);
export const FIXED_IMAGE_IDENTITIES = deepFreeze(['loader', 'node', ...DSO_NAMES].map(id => ({ id, path: id === 'node' ? 'image/root/bin/node' : id === 'loader' ? 'image/root/lib64/ld-linux-x86-64.so.2' : `image/root/usr/lib/${id}`, bytes: FIXED_BYTES[id], sha256: FIXED_HASHES[id], mode: id === 'node' || id === 'loader' || id !== 'libgcc_s.so.1' ? 0o755 : 0o644, elf: FIXED_ELF[id] })));
export const FIXED_FILE_MODES = deepFreeze(Object.fromEntries(EXPECTED_FILES.map(relative => [relative, relative.startsWith('image/root/bin/') || relative.startsWith('image/root/lib64/') || (relative.startsWith('image/root/usr/lib/') && !relative.endsWith('libgcc_s.so.1')) ? 0o755 : relative === 'image/root/usr/lib/libgcc_s.so.1' ? 0o644 : 0o644])));

export const imagePath = relative => path.join(packageDirectory, relative);
const json = name => JSON.parse(fs.readFileSync(imagePath(name), 'utf8'));
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const rawHash = relative => sha256(fs.readFileSync(imagePath(relative)));
export const stable = value => JSON.stringify(value, (key, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.keys(item).sort().map(k => [k, item[k]])) : item);
export const pretty = value => `${stable(value)}\n`;
export const domainDigest = (domain, bytes) => sha256(Buffer.concat([Buffer.from(`${domain}\0`), Buffer.from(bytes)]));
const fail = message => { throw new Error(message); };
const requireCondition = (condition, message) => { if (!condition) fail(message); };
const validateSchema = (name, value) => { const validator = new Ajv2020({ strict: true, allErrors: true }).compile(json(name)); requireCondition(validator(value), `${name}: ${JSON.stringify(validator.errors)}`); };

const canonicalRelativePath = (value, label) => {
  requireCondition(typeof value === 'string' && value.length > 0 && !value.startsWith('/') && !value.includes('\\') && !value.includes('//'), `${label}: non-canonical path`);
  const parts = value.split('/'); requireCondition(parts.every(part => part.length > 0 && part !== '.' && part !== '..'), `${label}: dot path`);
  requireCondition(path.posix.normalize(value) === value && !value.endsWith('/'), `${label}: normalization drift`);
  return value;
};
const assertPackagePath = (relative, label) => {
  canonicalRelativePath(relative, label); const root = fs.realpathSync(packageDirectory); const absolute = path.join(packageDirectory, ...relative.split('/')); let current = packageDirectory;
  for (const component of relative.split('/')) { current = path.join(current, component); const stat = fs.lstatSync(current); requireCondition(!stat.isSymbolicLink(), `${label}: symlink intermediate`); const real = fs.realpathSync(current); const rel = path.relative(root, real); requireCondition(rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel), `${label}: outside package`); }
  return absolute;
};
const assertHostPath = (value, expected, label) => { requireCondition(value === expected && path.isAbsolute(value), `${label}: source path pin`); };
const statFile = (relative, label = relative) => { const absolute = assertPackagePath(relative, label); const stat = fs.lstatSync(absolute); requireCondition(stat.isFile() && stat.nlink === 1 && (stat.mode & 0o7000) === 0, `${label}: regular single-link file`); return stat; };

// Pure ELF64 little-endian parser. --check uses no readelf, ldd, loader, or subprocess.
const parseElfBytes = (bytes, relative) => {
  requireCondition(bytes.length >= 64 && bytes.subarray(0, 4).equals(Buffer.from('\x7fELF')), `ELF magic ${relative}`); requireCondition(bytes[4] === 2 && bytes[5] === 1 && bytes.readUInt16LE(18) === 62, `ELF class/machine ${relative}`);
  const phoff = Number(bytes.readBigUInt64LE(32)); const phentsize = bytes.readUInt16LE(54); const phnum = bytes.readUInt16LE(56); const loads = []; let interp = null; let dynamicOffset = null; let dynamicSize = null;
  for (let i = 0; i < phnum; i += 1) { const off = phoff + i * phentsize; requireCondition(off + phentsize <= bytes.length, `ELF program header ${relative}`); const type = bytes.readUInt32LE(off); const fileOffset = Number(bytes.readBigUInt64LE(off + 8)); const vaddr = Number(bytes.readBigUInt64LE(off + 16)); const fileSize = Number(bytes.readBigUInt64LE(off + 32)); const memSize = Number(bytes.readBigUInt64LE(off + 40)); requireCondition(fileOffset + fileSize <= bytes.length, `ELF bounds ${relative}`); if (type === 1) loads.push({ vaddr, fileOffset, memSize }); if (type === 3) interp = bytes.subarray(fileOffset, fileOffset + fileSize - 1).toString('utf8'); if (type === 2) { dynamicOffset = fileOffset; dynamicSize = fileSize; } }
  const vaddrToOffset = address => { const load = loads.find(item => address >= item.vaddr && address < item.vaddr + item.memSize); requireCondition(load, `ELF virtual address ${relative}`); return load.fileOffset + address - load.vaddr; }; const tags = new Map();
  if (dynamicOffset !== null) { requireCondition(dynamicOffset + dynamicSize <= bytes.length, `ELF dynamic bounds ${relative}`); for (let off = dynamicOffset; off < dynamicOffset + dynamicSize; off += 16) { const tag = Number(bytes.readBigInt64LE(off)); const value = Number(bytes.readBigUInt64LE(off + 8)); if (tag === 0) break; if (!tags.has(tag)) tags.set(tag, []); tags.get(tag).push(value); } }
  const strtab = tags.has(5) ? vaddrToOffset(tags.get(5)[0]) : null; const textAt = offset => { if (strtab === null || offset < 0) return null; const end = bytes.indexOf(0, strtab + offset); requireCondition(end >= 0, `ELF string table ${relative}`); return bytes.subarray(strtab + offset, end).toString('utf8'); };
  return { ptInterp: interp, soname: textAt(tags.get(14)?.[0] ?? -1), dtNeeded: (tags.get(1) ?? []).map(textAt), rpath: textAt(tags.get(15)?.[0] ?? -1), runpath: textAt(tags.get(29)?.[0] ?? -1) };
};
export const parseElf = relative => parseElfBytes(fs.readFileSync(imagePath(relative)), relative);

const expectedHostSource = name => name === 'node' ? SOURCE_NODE : name === 'loader' ? SOURCE_LOADER : DSO_SOURCES[name];
const expectedMode = name => name === 'node' || name === 'loader' ? 0o755 : DSO_MODES[name];
const expectedImagePath = name => name === 'node' ? 'image/root/bin/node' : name === 'loader' ? 'image/root/lib64/ld-linux-x86-64.so.2' : `image/root/usr/lib/${name}`;
const expectedLicenseRef = name => name === 'node' ? ['package:node'] : name === 'libstdc++.so.6' ? ['package:libstdc++'] : name === 'libgcc_s.so.1' ? ['package:libgcc'] : ['package:glibc'];
const reverseEdges = (records, soname) => records.filter(record => record.elf.dtNeeded.includes(soname)).map(record => record.id === 'node' ? 'node' : record.soname);
const fixedIdentityForPath = relative => FIXED_IMAGE_IDENTITIES.find(identity => identity.path === relative);
export const validateFixedBinaryIdentity = (relative, bytes = fs.readFileSync(imagePath(relative)), mode = fs.statSync(imagePath(relative)).mode & 0o777) => {
  const fixed = fixedIdentityForPath(relative); requireCondition(fixed, `fixed binary identity roster ${relative}`); requireCondition(bytes.length === fixed.bytes && sha256(bytes) === fixed.sha256 && mode === fixed.mode, `fixed binary identity ${relative}`); requireCondition(stable(parseElfBytes(bytes, relative)) === stable(fixed.elf), `fixed ELF identity ${relative}`); return { ok: true, id: fixed.id };
};

export function validateImage(value = json('runtime-image.v1.json')) {
  validateSchema('runtime-image.v1.schema.json', value);
  requireCondition(value.executionAllowed === false && value.imageLaunchQualification === false && value.semanticQualification === false && value.distributionLicenseClosure === false, 'qualification flags');
  requireCondition(value.nlinkPolicy === 'every image and notice file is a regular file with nlink exactly 1; symlink and hardlink substitution forbidden', 'nlink policy');
  requireCondition(stable(value.runtime) === stable({ runtime: 'node', version: 'v22.23.1', platform: 'linux', arch: 'x64' }) && stable(value.architecture) === stable({ platform: 'linux', arch: 'x64' }), 'runtime pin');
  requireCondition(value.dsos.length === DSO_NAMES.length && stable(value.dsos.map(item => item.soname)) === stable(DSO_NAMES) && value.loader.id === 'loader' && value.executable.id === 'node', 'image roster count/order/id');
  const records = [value.executable, ...value.dsos]; const all = [value.loader, ...records]; const sonames = new Set(['ld-linux-x86-64.so.2']); const bySoname = new Map([['ld-linux-x86-64.so.2', value.loader]]); const paths = new Set();
  for (const item of all) {
    canonicalRelativePath(item.path, `image.${item.id}.path`); requireCondition(!paths.has(item.path), `duplicate image path ${item.path}`); paths.add(item.path); statFile(item.path, `image.${item.id}.path`);
    const expectedName = item.id === 'node' ? 'node' : item.id === 'loader' ? 'loader' : item.soname; requireCondition(item.path === expectedImagePath(expectedName), `image path ${item.id}`); const source = expectedHostSource(expectedName); assertHostPath(item.source, source, `image.${item.id}.source`); requireCondition(item.sourceRealpath === SOURCE_REALPATHS[expectedName], `image.${item.id}.sourceRealpath`);
    requireCondition(item.nlink === 1 && item.bytes === item.sourceBytes && item.sha256 === item.sourceSha256 && item.imageSha256 === item.sha256 && item.mode === expectedMode(expectedName) && item.imageMode === item.mode, `image ${item.id} byte/mode authority`);
    const fixed = fixedIdentityForPath(item.path); requireCondition(fixed && item.bytes === fixed.bytes && item.sha256 === fixed.sha256 && item.mode === fixed.mode && stable(item.elf) === stable(fixed.elf), `fixed binary metadata ${item.id}`); const bytes = fs.readFileSync(imagePath(item.path)); validateFixedBinaryIdentity(item.path, bytes, statFile(item.path, `image.${item.id}.path`).mode & 0o777); requireCondition(bytes.length === item.bytes && sha256(bytes) === item.sha256, `image ${item.id} bytes/hash`);
    const elf = parseElf(item.path); requireCondition(stable(elf) === stable(item.elf), `image ${item.id} ELF metadata`); requireCondition(item.elf.rpath === null && item.elf.runpath === null, `image ${item.id} RPATH/RUNPATH`);
    requireCondition(stable(item.licenseRefs) === stable(expectedLicenseRef(expectedName)), `image ${item.id} license refs`);
    if (item.role === 'dso') { requireCondition(!sonames.has(item.soname), `duplicate SONAME ${item.soname}`); sonames.add(item.soname); bySoname.set(item.soname, item); requireCondition(item.soname === expectedName && item.elf.soname === item.soname, `DSO SONAME ${item.id}`); }
  }
  requireCondition(value.loader.path === expectedImagePath('loader') && value.loader.soname === 'ld-linux-x86-64.so.2' && value.loader.elf.soname === value.loader.soname, 'loader identity');
  requireCondition(value.executable.path === expectedImagePath('node') && value.executable.version === 'v22.23.1' && value.executable.elf.ptInterp === '/lib64/ld-linux-x86-64.so.2', 'Node identity/PT_INTERP');
  const direct = [...DSO_NAMES, 'ld-linux-x86-64.so.2']; requireCondition(stable(value.executable.elf.dtNeeded) === stable(direct), 'Node DT_NEEDED');
  for (const item of all) { for (const needed of item.elf.dtNeeded) requireCondition(bySoname.has(needed), `unclosed dependency ${item.id}:${needed}`); requireCondition(stable(item.usedBy ?? []) === stable(reverseEdges(records, item.soname)), `reverse dependency ${item.id}`); }
  const expectedEnvironment = REPLACEMENT_ENVIRONMENT; requireCondition(stable(value.launch.environment) === stable(expectedEnvironment), 'launch replacement environment'); const invocation = value.launch.loaderInvocation;
  requireCondition(invocation.mode === 'direct-loader-inhibit-cache' && invocation.recipeTemplate === DIRECT_LOADER_RECIPE && stable(invocation.argvTemplate) === stable(DIRECT_LOADER_ARGV) && invocation.commandTemplate === DIRECT_LOADER_COMMAND && invocation.loaderPath === expectedImagePath('loader') && invocation.libraryPath === '<package-absolute-root>/image/root/usr/lib' && invocation.controller === '<exact-reviewed-controller>' && invocation.authorizationFd === 3 && invocation.executed === false, 'direct-loader argv template');
  requireCondition(stable(invocation.environment) === stable(expectedEnvironment) && stable(invocation.forbiddenEnvironment) === stable(FORBIDDEN_ENVIRONMENT) && invocation.inheritedEnvironment === false && invocation.nativeAddons === 'forbidden' && invocation.unlistedDescriptors === 'forbidden', 'exact launch isolation roster'); requireCondition(value.launch.hostFallback === 'forbidden' && value.launch.packageLocalLibraryPath === 'absolute package-root-derived image/root/usr/lib; no host fallback', 'host fallback policy');
  return { ok: true, imageFiles: all.length, dsos: value.dsos.length, bytes: all.reduce((sum, item) => sum + item.bytes, 0) };
}

const sourceRecord = (value, name) => name === 'loader' ? value.loader : name === 'node' ? value.node : value.dsos.find(item => item.soname === name);
export function validateSource(value = json('source/node-runtime-closure.v1.json')) {
  validateSchema('source/node-runtime-closure.v1.schema.json', value); requireCondition(stable(value.runtime) === stable({ runtime: 'node', version: 'v22.23.1', platform: 'linux', arch: 'x64' }) && value.materialized === true && value.noHostFallback === true && value.nativeAddons === false, 'source closure status/pin'); requireCondition(stable(value.fixedIdentity) === stable(FIXED_IMAGE_IDENTITIES.map(identity => ({ id: identity.id, path: identity.path, bytes: identity.bytes, sha256: identity.sha256, mode: identity.mode, elf: identity.elf }))), 'source fixed identity authority');
  const image = json('runtime-image.v1.json'); validateImage(image); const imageMap = new Map([['loader', image.loader], ['node', image.executable], ...image.dsos.map(item => [item.soname, item])]);
  const names = ['loader', 'node', ...DSO_NAMES]; requireCondition(value.dsos.length === DSO_NAMES.length && stable(value.dsos.map(item => item.soname)) === stable(DSO_NAMES), 'source DSO count/order');
  for (const name of names) { const imageItem = imageMap.get(name); const sourceItem = sourceRecord(value, name); requireCondition(sourceItem && sourceItem.id === (name === 'node' ? 'node' : name === 'loader' ? 'loader' : `dso:${name}`), `source ${name} identity`); assertHostPath(sourceItem.path, expectedHostSource(name), `source ${name}.path`); assertHostPath(sourceItem.realpath, SOURCE_REALPATHS[name], `source ${name}.realpath`); requireCondition(sourceItem.bytes === imageItem.sourceBytes && sourceItem.sha256 === imageItem.sourceSha256 && sourceItem.mode === expectedMode(name) && sourceItem.nlink === 1 && stable(sourceItem.elf) === stable(imageItem.elf), `source ${name} image join`); if (name === 'loader') requireCondition(stable(sourceItem.usedBy) === stable(imageItem.usedBy) && stable(sourceItem.usedBy) === stable(reverseEdges([image.executable, ...image.dsos], imageItem.soname)), `source ${name} edge join`); else if (name !== 'node') requireCondition(sourceItem.soname === name && stable(sourceItem.usedBy) === stable(imageItem.usedBy) && stable(sourceItem.usedBy) === stable(reverseEdges([image.executable, ...image.dsos], name)), `source ${name} edge join`); else requireCondition(stable(sourceItem.elf.dtNeeded) === stable(imageItem.elf.dtNeeded), 'source node dependency join'); }
  return { ok: true, dsos: value.dsos.length };
}

export function validateLicenses(value = json('licenses/provenance.v1.json'), image = json('runtime-image.v1.json')) {
  validateSchema('licenses/provenance.v1.schema.json', value); requireCondition(value.distributionLicenseClosure === 'incomplete-metadata-only-for-glibc', 'license closure state'); requireCondition(stable(value.copiedNoticeFiles) === stable(LICENSE_NOTICES), 'exact notice roster'); requireCondition(stable(value.packages) === stable(LICENSE_PACKAGES), 'exact package license roster');
  for (const notice of value.copiedNoticeFiles) { canonicalRelativePath(notice.path, `license.${notice.path}`); const expectedNotice = LICENSE_NOTICES.find(item => item.path === notice.path); requireCondition(expectedNotice, `license ${notice.path} roster`); const stat = statFile(notice.path, `license.${notice.path}`); assertHostPath(notice.source, expectedNotice.source, `license.${notice.path}.source`); requireCondition(notice.nlink === 1 && stat.size === notice.bytes && stat.nlink === 1 && notice.bytes === expectedNotice.bytes && rawHash(notice.path) === notice.sha256 && notice.sha256 === expectedNotice.sha256 && (stat.mode & 0o777) === notice.mode && notice.mode === expectedNotice.mode, `license ${notice.path} identity`); }
  const refs = new Set(value.packages.map(item => item.id)); const imageItems = [image.loader, image.executable, ...image.dsos]; for (const item of imageItems) { requireCondition(stable(item.licenseRefs) === stable(expectedLicenseRef(item.id === 'node' ? 'node' : item.id === 'loader' ? 'loader' : item.soname)), `license ref authority ${item.id}`); for (const ref of item.licenseRefs) requireCondition(refs.has(ref), `unmapped license ref ${ref}`); } requireCondition(image.distributionLicenseClosure === false, 'image license flag'); return { ok: true, packages: value.packages.length, notices: value.copiedNoticeFiles.length };
}

function walk(rootDirectory = packageDirectory) {
  const root = path.resolve(rootDirectory); const files = []; const dirs = []; const visit = current => { for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) { const full = path.join(current, entry.name); const relative = path.relative(root, full).split(path.sep).join('/'); const stat = fs.lstatSync(full); canonicalRelativePath(relative, `walk.${relative}`); requireCondition((stat.mode & 0o7000) === 0 && !stat.isSymbolicLink(), `unsafe entry ${relative}`); if (entry.isDirectory()) { dirs.push({ path: relative, mode: stat.mode & 0o777 }); visit(full); } else { requireCondition(entry.isFile() && stat.nlink === 1, `special or linked entry ${relative}`); files.push({ path: relative, mode: stat.mode & 0o777, bytes: stat.size, sha256: sha256(fs.readFileSync(full)), contentDigest: domainDigest(CONTENT_DOMAIN, fs.readFileSync(full)) }); } } }; visit(root); return { files, dirs }; }
export const validateDirectoryRoster = (rootDirectory = packageDirectory) => { const walked = walk(rootDirectory); requireCondition(stable(walked.dirs) === stable(EXPECTED_DIRS), 'immutable walked directory roster'); return { ok: true, directories: walked.dirs.length }; };
export const parseChecksumLine = line => { const fields = line.split('  '); requireCondition(fields.length === 2 && /^[0-9a-f]{64}$/.test(fields[0]) && fields[1].length > 0 && !line.includes('\r') && !line.endsWith(' '), 'checksum line syntax'); return { digest: fields[0], printed: fields[1] }; };
export function validateManifest(value = json('MANIFEST.json')) {
  validateSchema('manifest.v1.schema.json', value); const walked = walk(); const sealedFiles = walked.files.filter(item => item.path !== 'MANIFEST.json' && item.path !== 'SHA256SUMS'); const expectedFiles = EXPECTED_FILES.filter(item => item !== 'MANIFEST.json' && item !== 'SHA256SUMS');
  requireCondition(!value.files.some(item => item.path === 'MANIFEST.json' || item.path === 'SHA256SUMS'), 'manifest self/reverse edge forbidden');
  requireCondition(stable(sealedFiles.map(item => item.path)) === stable(expectedFiles), 'exact walked file path closure'); requireCondition(stable(walked.dirs) === stable(EXPECTED_DIRS), 'immutable walked directory roster'); requireCondition(stable(value.files) === stable(sealedFiles), 'manifest file authority exact'); requireCondition(stable(value.directories) === stable(walked.dirs), 'manifest directory authority exact'); requireCondition(value.fileCount === value.files.length && value.fileCount === sealedFiles.length && value.directoryCount === value.directories.length && value.directoryCount === walked.dirs.length, 'manifest counts exact');
  for (const envelope of ['MANIFEST.json', 'SHA256SUMS']) { const envelopeStat = statFile(envelope, `manifest envelope ${envelope}`); requireCondition((envelopeStat.mode & 0o777) === FIXED_FILE_MODES[envelope], `fixed envelope mode ${envelope}`); }
  for (const item of value.files) { canonicalRelativePath(item.path, `manifest.${item.path}`); requireCondition(FIXED_FILE_MODES[item.path] === item.mode, `fixed envelope mode ${item.path}`); statFile(item.path, `manifest.${item.path}`); } for (const item of value.directories) canonicalRelativePath(item.path, `manifest.dir.${item.path}`);
  const roster = { files: value.files.map(item => ({ path: item.path, mode: item.mode })), directories: value.directories.map(item => ({ path: item.path, mode: item.mode })) }; requireCondition(value.rosterDigest === domainDigest(ROSTER_DOMAIN, Buffer.from(pretty(roster))), 'manifest roster digest'); const { contentDigest, ...withoutContentDigest } = value; requireCondition(contentDigest === domainDigest(CONTENT_DOMAIN, Buffer.from(pretty(withoutContentDigest))), 'manifest content digest');
  const checksumText = fs.readFileSync(imagePath('SHA256SUMS'), 'utf8'); requireCondition(checksumText.endsWith('\n') && !checksumText.endsWith('\n\n'), 'checksum envelope newline'); const lines = checksumText.slice(0, -1).split('\n'); const names = ['MANIFEST.json', ...value.files.map(item => item.path)]; requireCondition(lines.length === names.length, 'checksum count'); for (let i = 0; i < lines.length; i += 1) { const parsed = parseChecksumLine(lines[i]); requireCondition(parsed.digest === rawHash(names[i]) && parsed.printed === `${ROOT}/${names[i]}`, `checksum ${names[i]}`); }
  return { ok: true, files: value.fileCount, directories: value.directoryCount };
}
export function validateMaterialization(value = json('materialization.v1.json')) { validateSchema('materialization.v1.schema.json', value); requireCondition(value.executionAllowed === false && value.imageLaunchQualification === false && value.semanticQualification === false && value.distributionLicenseClosure === false, 'materialization flags'); requireCondition(value.runtimeImage === 'runtime-image.v1.json' && value.sourceClosure === 'source/node-runtime-closure.v1.json', 'materialization artifacts'); return { ok: true }; }
export function validateAll() { return { materialization: validateMaterialization(), image: validateImage(), source: validateSource(), licenses: validateLicenses(), manifest: validateManifest() }; }
