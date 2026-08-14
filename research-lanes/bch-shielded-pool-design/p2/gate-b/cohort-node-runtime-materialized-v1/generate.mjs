import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EXPECTED_DIRS, EXPECTED_FILES, FIXED_IMAGE_IDENTITIES, CONTENT_DOMAIN, ROSTER_DOMAIN, SOURCE_DOMAIN, domainDigest, pretty, validateAll } from './semantic-validators.mjs';

const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const sourceNode = '/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node';
const sourceLoader = '/usr/lib/ld-linux-x86-64.so.2';
const dsoNames = ['libdl.so.2', 'libstdc++.so.6', 'libm.so.6', 'libgcc_s.so.1', 'libpthread.so.0', 'libc.so.6'];
const nodeSha256 = '93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068';
const loaderSha256 = 'd52fe2ff87fff536ed5c5eae8e954cb50655884e4709fedd24cf57f9ec98ad80';
const forbiddenEnvironment = ['NODE_OPTIONS', 'PATH', 'LD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_AUDIT', 'LD_DEBUG', 'LD_ASSUME_KERNEL', 'NODE_PATH'];
const directLoaderArgv = ['<package-absolute-root>/image/root/lib64/ld-linux-x86-64.so.2', '--inhibit-cache', '--library-path', '<package-absolute-root>/image/root/usr/lib', '<package-absolute-root>/image/root/bin/node', '--no-addons', '<exact-reviewed-controller>', '--authorization-fd=3'];
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const local = relative => path.join(packageDirectory, relative);
const ensureDir = relative => { let current = packageDirectory; for (const component of relative.split('/')) { current = path.join(current, component); if (fs.existsSync(current)) { const stat = fs.lstatSync(current); requireCondition(stat.isDirectory() && !stat.isSymbolicLink() && stat.nlink === 1, `materialization directory substitution ${relative}`); } else fs.mkdirSync(current, { mode: 0o755 }); } };
const writeJson = (relative, value) => fs.writeFileSync(local(relative), pretty(value), { mode: 0o644 });
const fail = message => { throw new Error(message); };
const requireCondition = (condition, message) => { if (!condition) fail(message); };

// The materializer uses only byte reads/copies and this bounded ELF parser.
// It never invokes Node, the loader, a controller, ldd, readelf, a compiler,
// a package manager, or an engine.
const parseElfBytes = (bytes, label) => {
  requireCondition(bytes.length >= 64 && bytes.subarray(0, 4).equals(Buffer.from('\x7fELF')) && bytes[4] === 2 && bytes[5] === 1 && bytes.readUInt16LE(18) === 62, `not x86-64 ELF ${label}`);
  const phoff = Number(bytes.readBigUInt64LE(32)); const phentsize = bytes.readUInt16LE(54); const phnum = bytes.readUInt16LE(56); const loads = []; let interp = null; let dyn = null;
  for (let i = 0; i < phnum; i += 1) { const o = phoff + i * phentsize; const t = bytes.readUInt32LE(o); const fo = Number(bytes.readBigUInt64LE(o + 8)); const va = Number(bytes.readBigUInt64LE(o + 16)); const fsiz = Number(bytes.readBigUInt64LE(o + 32)); const msiz = Number(bytes.readBigUInt64LE(o + 40)); if (t === 1) loads.push({ va, fo, msiz }); if (t === 3) interp = bytes.subarray(fo, fo + fsiz - 1).toString(); if (t === 2) dyn = { fo, size: fsiz }; }
  const toOffset = va => { const load = loads.find(item => va >= item.va && va < item.va + item.msiz); requireCondition(load, `unmapped ELF address ${label}`); return load.fo + va - load.va; }; const tags = new Map();
  if (dyn) for (let o = dyn.fo; o < dyn.fo + dyn.size; o += 16) { const tag = Number(bytes.readBigInt64LE(o)); const value = Number(bytes.readBigUInt64LE(o + 8)); if (tag === 0) break; if (!tags.has(tag)) tags.set(tag, []); tags.get(tag).push(value); }
  const strtab = tags.has(5) ? toOffset(tags.get(5)[0]) : null; const textAt = n => { if (n < 0 || strtab === null) return null; const end = bytes.indexOf(0, strtab + n); requireCondition(end >= 0, `bad ELF string ${label}`); return bytes.subarray(strtab + n, end).toString(); };
  return { ptInterp: interp, soname: textAt(tags.get(14)?.[0] ?? -1), dtNeeded: (tags.get(1) ?? []).map(textAt), rpath: textAt(tags.get(15)?.[0] ?? -1), runpath: textAt(tags.get(29)?.[0] ?? -1) };
};
const materializeFile = (source, target, mode) => { const sourceRealpath = fs.realpathSync(source); const sourceStat = fs.statSync(sourceRealpath); requireCondition(sourceStat.isFile() && sourceStat.nlink === 1, `source regular file ${source}`); const targetPath = local(target); if (fs.existsSync(targetPath)) { const previous = fs.lstatSync(targetPath); requireCondition(previous.isFile() && !previous.isSymbolicLink() && previous.nlink === 1, `target substitution ${target}`); } const bytes = fs.readFileSync(sourceRealpath); fs.writeFileSync(targetPath, bytes, { mode }); fs.chmodSync(targetPath, mode); const targetStat = fs.lstatSync(targetPath); requireCondition(targetStat.isFile() && targetStat.nlink === 1 && targetStat.size === bytes.length && sha256(bytes) === sha256(fs.readFileSync(targetPath)), `materialized identity ${target}`); return { source, sourceRealpath, sourceBytes: bytes.length, sourceMode: sourceStat.mode & 0o777, sourceSha256: sha256(bytes), bytes: bytes.length, mode, sha256: sha256(bytes) }; };

function materialize() {
  for (const directory of EXPECTED_DIRS.map(item => item.path)) ensureDir(directory);
  const loader = materializeFile(sourceLoader, 'image/root/lib64/ld-linux-x86-64.so.2', 0o755); const node = materializeFile(sourceNode, 'image/root/bin/node', 0o755);
  requireCondition(node.sourceSha256 === nodeSha256 && loader.sourceSha256 === loaderSha256, 'pinned source hash');
  const nodeElf = parseElfBytes(fs.readFileSync(local('image/root/bin/node')), 'node'); requireCondition(nodeElf.ptInterp === '/lib64/ld-linux-x86-64.so.2', 'Node interpreter');
  const needed = nodeElf.dtNeeded.filter(name => name !== 'ld-linux-x86-64.so.2'); requireCondition(JSON.stringify(needed) === JSON.stringify(dsoNames), 'Node direct dependency order');
  const dsos = dsoNames.map(name => { const item = materializeFile(`/usr/lib/${name}`, `image/root/usr/lib/${name}`, name === 'libgcc_s.so.1' ? 0o644 : 0o755); const elf = parseElfBytes(fs.readFileSync(local(item.path ?? `image/root/usr/lib/${name}`)), name); return { ...item, id: `dso:${name}`, role: 'dso', path: `image/root/usr/lib/${name}`, soname: elf.soname, elf, usedBy: [name === 'libdl.so.2' || name === 'libstdc++.so.6' || name === 'libm.so.6' || name === 'libgcc_s.so.1' || name === 'libpthread.so.0' || name === 'libc.so.6' ? 'node' : 'node'], licenseRefs: [name === 'libstdc++.so.6' ? 'package:libstdc++' : name === 'libgcc_s.so.1' ? 'package:libgcc' : 'package:glibc'] }; });
  const executable = { ...node, id: 'node', role: 'executable', path: 'image/root/bin/node', version: 'v22.23.1', elf: nodeElf, licenseRefs: ['package:node'] };
  const loaderRecord = { ...loader, id: 'loader', role: 'loader', path: 'image/root/lib64/ld-linux-x86-64.so.2', soname: 'ld-linux-x86-64.so.2', elf: parseElfBytes(fs.readFileSync(local('image/root/lib64/ld-linux-x86-64.so.2')), 'loader'), usedBy: [], licenseRefs: ['package:glibc'] };
  const sourceModes = { loader: loader.sourceMode, node: node.sourceMode, ...Object.fromEntries(dsos.map(item => [item.soname, item.sourceMode])) };
  for (const item of [loaderRecord, executable, ...dsos]) { item.imageMode = item.mode; item.imageSha256 = item.sha256; item.nlink = 1; delete item.sourceMode; }
  const allConsumers = [executable, ...dsos]; for (const dso of dsos) dso.usedBy = allConsumers.filter(consumer => consumer.elf.dtNeeded.includes(dso.soname)).map(consumer => consumer.id === 'node' ? 'node' : consumer.soname); loaderRecord.usedBy = allConsumers.filter(consumer => consumer.elf.dtNeeded.includes(loaderRecord.soname)).map(consumer => consumer.id === 'node' ? 'node' : consumer.soname);
  const launch = { loaderInvocation: { mode: 'direct-loader-inhibit-cache', recipeTemplate: 'loader --inhibit-cache --library-path <absolute-package-node-libdir> node --no-addons <exact-reviewed-controller> --authorization-fd=3', argvTemplate: directLoaderArgv, commandTemplate: '<package-absolute-root>/image/root/lib64/ld-linux-x86-64.so.2 --inhibit-cache --library-path <absolute-package-node-libdir> <package-absolute-root>/image/root/bin/node --no-addons <exact-reviewed-controller> --authorization-fd=3', loaderPath: 'image/root/lib64/ld-linux-x86-64.so.2', libraryPath: '<package-absolute-root>/image/root/usr/lib', controller: '<exact-reviewed-controller>', authorizationFd: 3, executed: false, environment: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC', NODE_ENV: 'production' }, forbiddenEnvironment, inheritedEnvironment: false, nativeAddons: 'forbidden', unlistedDescriptors: 'forbidden' }, hostFallback: 'forbidden', packageLocalLibraryPath: 'absolute package-root-derived image/root/usr/lib; no host fallback', environment: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC', NODE_ENV: 'production' } };
  const runtimeImage = { schema: 'shieldkit-labs/p2/gate-b/cohort-node-runtime-materialized/v1/runtime-image', status: 'materialized-static-unqualified', runtime: { runtime: 'node', version: 'v22.23.1', platform: 'linux', arch: 'x64' }, architecture: { platform: 'linux', arch: 'x64' }, nlinkPolicy: 'every image and notice file is a regular file with nlink exactly 1; symlink and hardlink substitution forbidden', loader: loaderRecord, executable, dsos, launch, executionAllowed: false, imageLaunchQualification: false, semanticQualification: false, distributionLicenseClosure: false, blockers: ['No Node, loader, controller, engine, VM, authorization, claim, run, or evidence was launched.', 'Distribution license closure is incomplete for glibc metadata; this is independent of semantic and launch qualification.', 'The reviewed controller remains a typed placeholder.'] };
  writeJson('runtime-image.v1.json', runtimeImage);
  const sourceClosure = { schema: 'shieldkit-labs/p2/gate-b/cohort-node-runtime-materialized/v1/source', status: 'materialized-package-local', materialized: true, noHostFallback: true, nativeAddons: false, runtime: runtimeImage.runtime, fixedIdentity: FIXED_IMAGE_IDENTITIES.map(identity => ({ id: identity.id, path: identity.path, bytes: identity.bytes, sha256: identity.sha256, mode: identity.mode, elf: identity.elf })), loader: { id: 'loader', path: sourceLoader, realpath: fs.realpathSync(sourceLoader), bytes: loader.sourceBytes, sha256: loader.sourceSha256, mode: sourceModes.loader, nlink: 1, elf: loaderRecord.elf, usedBy: loaderRecord.usedBy }, node: { id: 'node', path: sourceNode, realpath: fs.realpathSync(sourceNode), bytes: node.sourceBytes, sha256: node.sourceSha256, mode: sourceModes.node, nlink: 1, elf: nodeElf }, dsos: dsos.map(item => ({ id: item.id, soname: item.soname, path: item.source, realpath: item.sourceRealpath, bytes: item.sourceBytes, sha256: item.sourceSha256, mode: sourceModes[item.soname], nlink: 1, elf: item.elf, usedBy: item.usedBy })) };
  writeJson('source/node-runtime-closure.v1.json', sourceClosure);
  materializeFile(`${sourceNode.replace('/bin/node', '')}/LICENSE`, 'licenses/node/LICENSE', 0o644);
  materializeFile('/usr/share/licenses/libgcc/RUNTIME.LIBRARY.EXCEPTION', 'licenses/host/libgcc/RUNTIME.LIBRARY.EXCEPTION', 0o644);
  materializeFile('/usr/share/licenses/libstdc++/RUNTIME.LIBRARY.EXCEPTION', 'licenses/host/libstdc++/RUNTIME.LIBRARY.EXCEPTION', 0o644);
  const licenseNotices = [{ path: 'licenses/node/LICENSE', source: `${sourceNode.replace('/bin/node', '')}/LICENSE`, bytes: fs.statSync(local('licenses/node/LICENSE')).size, mode: 0o644, nlink: 1, sha256: sha256(fs.readFileSync(local('licenses/node/LICENSE'))) }, ...['libgcc', 'libstdc++'].map(name => ({ path: `licenses/host/${name}/RUNTIME.LIBRARY.EXCEPTION`, source: `/usr/share/licenses/${name}/RUNTIME.LIBRARY.EXCEPTION`, bytes: fs.statSync(local(`licenses/host/${name}/RUNTIME.LIBRARY.EXCEPTION`)).size, mode: 0o644, nlink: 1, sha256: sha256(fs.readFileSync(local(`licenses/host/${name}/RUNTIME.LIBRARY.EXCEPTION`))) }))];
  writeJson('licenses/provenance.v1.json', { schema: 'shieldkit-labs/p2/gate-b/cohort-node-runtime-materialized/v1/license-provenance', distributionLicenseClosure: 'incomplete-metadata-only-for-glibc', packages: [
    { id: 'package:node', name: 'node', version: '22.23.1', licenses: ['MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ICU', 'MIT-0'], licenseRefs: ['package:node'], noticeFiles: ['licenses/node/LICENSE'], distributionStatus: 'notice-materialized' },
    { id: 'package:glibc', name: 'glibc', version: '2.43+r37+gfdf10644d6ee-1', licenses: ['GPL-2.0-or-later', 'LGPL-2.1-or-later'], licenseRefs: ['package:glibc'], noticeFiles: [], distributionStatus: 'incomplete-metadata-only' },
    { id: 'package:libstdc++', name: 'libstdc++', version: '16.1.1+r346+g4e03491b401d-4', licenses: ['GPL-3.0-or-later WITH GCC-exception-3.1', 'GFDL-1.3-or-later'], licenseRefs: ['package:libstdc++'], noticeFiles: ['licenses/host/libstdc++/RUNTIME.LIBRARY.EXCEPTION'], distributionStatus: 'notice-materialized' },
    { id: 'package:libgcc', name: 'libgcc', version: '16.1.1+r346+g4e03491b401d-4', licenses: ['GPL-3.0-or-later WITH GCC-exception-3.1', 'GFDL-1.3-or-later'], licenseRefs: ['package:libgcc'], noticeFiles: ['licenses/host/libgcc/RUNTIME.LIBRARY.EXCEPTION'], distributionStatus: 'notice-materialized' }
  ], copiedNoticeFiles: licenseNotices });
  writeJson('materialization.v1.json', { schema: 'shieldkit-labs/p2/gate-b/cohort-node-runtime-materialized/v1/materialization', status: 'materialized-static-unqualified', executionAllowed: false, imageLaunchQualification: false, semanticQualification: false, distributionLicenseClosure: false, runtimeImage: 'runtime-image.v1.json', sourceClosure: 'source/node-runtime-closure.v1.json', blockers: ['No execution or semantic qualification is claimed.', 'glibc distribution notice metadata remains incomplete.', 'Controller path is intentionally unbound.'] });
  sealEnvelope();
  console.log(JSON.stringify({ ok: true, mode: 'materialize', imageFiles: 8, dsos: 6, bytes: [loaderRecord, executable, ...dsos].reduce((sum, item) => sum + item.bytes, 0) }));
}

function sealEnvelope() {
  const files = EXPECTED_FILES.filter(item => !['MANIFEST.json', 'SHA256SUMS'].includes(item)).map(relative => { const bytes = fs.readFileSync(local(relative)); return { path: relative, mode: fs.statSync(local(relative)).mode & 0o777, bytes: bytes.length, sha256: sha256(bytes), contentDigest: domainDigest(CONTENT_DOMAIN, bytes) }; });
  const directories = EXPECTED_DIRS; const roster = { files: files.map(item => ({ path: item.path, mode: item.mode })), directories: directories.map(item => ({ path: item.path, mode: item.mode })) }; const rosterDigest = domainDigest(ROSTER_DOMAIN, Buffer.from(pretty(roster)));
  const withoutRoot = { schema: 'shieldkit-labs/p2/gate-b/cohort-node-runtime-materialized/v1/manifest', domainSeparator: CONTENT_DOMAIN, rosterDomain: ROSTER_DOMAIN, fileCount: files.length, directoryCount: directories.length, executionAllowed: false, files, directories, rosterDigest }; const contentDigest = domainDigest(CONTENT_DOMAIN, Buffer.from(pretty(withoutRoot)));
  writeJson('MANIFEST.json', { ...withoutRoot, contentDigest });
  const names = ['MANIFEST.json', ...files.map(item => item.path)]; fs.writeFileSync(local('SHA256SUMS'), `${names.map(name => `${sha256(fs.readFileSync(local(name)))}  ${'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-node-runtime-materialized-v1'}/${name}`).join('\n')}\n`, { mode: 0o644 });
}

const mode = process.argv[2];
if (mode === '--materialize') materialize();
else if (mode === '--check') { const result = validateAll(); console.log(JSON.stringify({ ok: true, mode: 'check', result })); }
else { console.error('usage: node generate.mjs --materialize | --check'); process.exitCode = 2; }
