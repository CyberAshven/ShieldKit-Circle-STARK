import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { packageDirectory, validateBundle, validateImage, validateLicenses, validateManifest, validateMaterialization } from './semantic-validators.mjs';

const read = name => JSON.parse(fs.readFileSync(path.join(packageDirectory, name), 'utf8'));
const clone = value => structuredClone(value);
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const local = name => path.join(packageDirectory, name);
const lockPath = path.join(os.tmpdir(), 'shieldkit-labs-materialized-v1-tests.lock');
const withLock = callback => { const cell = new Int32Array(new SharedArrayBuffer(4)); let acquired = false; for (let attempt = 0; attempt < 6000 && !acquired; attempt += 1) { try { fs.mkdirSync(lockPath); acquired = true; } catch { Atomics.wait(cell, 0, 0, 10); } } assert.equal(acquired, true, 'test lock acquisition'); try { return callback(); } finally { fs.rmdirSync(lockPath); } };
const withBytes = (name, bytes, callback) => { const file = local(name); const original = fs.readFileSync(file); try { fs.writeFileSync(file, bytes); return callback(); } finally { fs.writeFileSync(file, original); } };
const forgedBundle = bytes => { const receipt = read('libauth-bundle-receipt.v1.json'); receipt.output = { path: 'bundle/libauth-bundle.mjs', bytes: bytes.length, sha256: hash(bytes) }; return receipt; };
const forgedMetafile = bytes => { const receipt = read('libauth-bundle-receipt.v1.json'); receipt.metafile = { path: 'bundle/libauth-bundle.metafile.json', bytes: bytes.length, sha256: hash(bytes) }; return receipt; };

test('bundle authority rejects static/host/dynamic/WASM/URL/path injection', () => withLock(() => {
  const original = fs.readFileSync(local('bundle/libauth-bundle.mjs'));
  const mutants = [
    "\nimport 'mutant';\n", "\nimport 'node:fs';\n", "\nawait import('mutant');\n", "\nrequire('mutant');\n", "\neval('mutant');\n", "\nFunction('return 1');\n", "\nWebAssembly.compileStreaming(mutant);\n", "\nfetch('https://mutant.invalid');\n", "\nnew URL('https://mutant.invalid');\n", "\nconst hostPath = '/home/mutant';\n", "\nimport 'mutant.wasm';\n",
  ];
  for (const suffix of mutants) { const mutant = Buffer.concat([original, Buffer.from(suffix)]); withBytes('bundle/libauth-bundle.mjs', mutant, () => assert.throws(() => validateBundle(forgedBundle(mutant)))); }
}));

test('metafile authority rejects ordering, edge, bytesInOutput, contributor, and self-consistent receipt mutants', () => withLock(() => {
  const original = fs.readFileSync(local('bundle/libauth-bundle.metafile.json')); const base = JSON.parse(original.toString('utf8'));
  const mutants = [
    value => { value.inputs = Object.fromEntries(Object.entries(value.inputs).reverse()); },
    value => { const key = Object.keys(value.inputs).find(item => value.inputs[item].imports?.length); value.inputs[key].imports[0].path = 'mutant.js'; },
    value => { const output = value.outputs['bundle/libauth-bundle.mjs']; const key = Object.keys(output.inputs)[0]; output.inputs[key].bytesInOutput += 1; },
    value => { value.outputs['bundle/libauth-bundle.mjs'].inputs['mutant.js'] = { bytesInOutput: 1 }; },
  ];
  for (const mutate of mutants) { const value = clone(base); mutate(value); const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n'); withBytes('bundle/libauth-bundle.metafile.json', bytes, () => assert.throws(() => validateBundle(forgedMetafile(bytes)))); }
}));

test('exact toolchain and graph bindings reject substitution while informational provenance is non-authoritative', () => withLock(() => {
  const receipt = read('libauth-bundle-receipt.v1.json');
  for (const mutate of [
    value => { value.bundler.nativeBinarySha256 = '0'.repeat(64); }, value => { value.bundler.nativeBinaryBytes += 1; },
    value => { value.bundler.wrapperSha256 = '0'.repeat(64); }, value => { value.bundler.packageJsonSha256 = '0'.repeat(64); },
    value => { value.bundler.platformPackageJsonSha256 = '0'.repeat(64); }, value => { value.bundler.packageIntegrity = 'sha512-mutant'; },
    value => { value.bundler.platformIntegrity = 'sha512-mutant'; }, value => { value.bundler.launcher = value.bundler.wrapper; },
    value => { value.bundler.sourceRoot = 'host/esbuild'; }, value => { value.bundler.reproducibilityExecution[0].argv[1] = '--mutant'; },
    value => { value.bundler.reproducibilityExecution[1].environment.TZ = 'mutant'; }, value => { value.inputGraphBinding.contentSha256 = '0'.repeat(64); },
  ]) assert.throws(() => validateBundle((() => { const copy = clone(receipt); mutate(copy); return copy; })()));
  const informational = clone(receipt); informational.bundler.sourceRootHost = '/informational/source-root'; informational.generatorNode.executable = '/informational/node'; informational.generatorNode.realpath = '/informational/node'; informational.generatorNode.sha256 = '0'.repeat(64); informational.generatorNode.version = 'informational'; informational.generatorNode.v8 = 'informational'; assert.doesNotThrow(() => validateBundle(informational));
  const native = local('toolchain/esbuild-linux-x64/bin/esbuild'); const nativeBytes = fs.readFileSync(native); withBytes('toolchain/esbuild-linux-x64/bin/esbuild', Buffer.concat([nativeBytes, Buffer.from([0])]), () => assert.throws(() => validateBundle(receipt)));
  const graphFile = local('source/libauth/address/address.js'); const graphBytes = fs.readFileSync(graphFile); withBytes('source/libauth/address/address.js', Buffer.concat([graphBytes, Buffer.from('\n// mutant\n')]), () => assert.throws(() => validateBundle(receipt)));
}));

test('graphContentSha/artifact roster/reproducibility and copied-graph mutants fail closed', () => withLock(() => {
  const materialization = read('materialization.v1.json');
  for (const mutate of [value => { value.bindings.graphContentSha256 = '0'.repeat(64); }, value => { value.roster.artifacts = [...value.roster.artifacts, 'mutant']; }, value => { value.roster.artifactRosterSha256 = '0'.repeat(64); }]) assert.throws(() => validateMaterialization((() => { const copy = clone(materialization); mutate(copy); return copy; })()));
  const receipt = read('libauth-bundle-receipt.v1.json'); for (const mutate of [value => { value.reproducibility.outputByteIdentical = false; }, value => { value.reproducibility.comparedToFrozenPackage = true; }, value => { value.authority.metafile.sha256 = '0'.repeat(64); }]) assert.throws(() => validateBundle((() => { const copy = clone(receipt); mutate(copy); return copy; })()));
  const graphMeta = local('source/libauth-input-graph.v1.json'); const original = fs.readFileSync(graphMeta); withBytes('source/libauth-input-graph.v1.json', Buffer.concat([original, Buffer.from('\n')]), () => assert.throws(() => validateBundle(receipt)));
  const omitted = local('source/libauth/address/address.js'); const moved = `${omitted}.mutant`; fs.renameSync(omitted, moved); try { assert.throws(() => validateBundle(receipt)); } finally { fs.renameSync(moved, omitted); }
}));

test('image substitution, duplicate/missing roster, source decouple, ELF lie, non-ELF, and endpoint mutants fail closed', () => withLock(() => {
  const base = read('runtime-image.v1.json');
  for (const mutate of [
    value => { value.executables[0].sha256 = '0'.repeat(64); }, value => { value.dsos[0] = clone(value.dsos[1]); }, value => { value.dsos.pop(); },
    value => { value.executables[0].sourceSha256 = '0'.repeat(64); }, value => { value.executables[0].elf.ptInterp = '/lib64/mutant.so'; },
    value => { value.dsos[0].elf.soname = 'libmutant.so.0'; }, value => { value.dsos[0].elf.dtNeeded = ['libmutant.so.0']; },
    value => { value.dsos[0].path = 'image/root/engines/bchn-leg'; }, value => { value.loader.path = 'README.md'; },
    value => { value.launch.endpoints[0].argv0 = 'mutant'; }, value => { value.executables[0].argv = ['mutant']; },
  ]) assert.throws(() => validateImage((() => { const copy = clone(base); mutate(copy); return copy; })()));
  const nonElf = 'image/root/usr/lib/libcrypto.so.3'; const original = fs.readFileSync(local(nonElf)); withBytes(nonElf, Buffer.from('not-elf'), () => assert.throws(() => validateImage(base)));
  const license = read('licenses/provenance.v1.json'); const image = clone(base); image.loader.licenseRefs = ['package:unknown']; assert.throws(() => validateLicenses(license, image));
}));

test('license package/version/ref/notice mutants fail closed', () => withLock(() => {
  const base = read('licenses/provenance.v1.json'); for (const mutate of [value => { value.packages[0].version = 'mutant'; }, value => { value.packages[1].licenseRefs = ['package:mutant']; }, value => { value.packages[2].noticeFiles = ['licenses/host/boost/LICENSE']; }, value => { value.copiedNoticeFiles[0].sha256 = '0'.repeat(64); }, value => { value.sourceLicenses.pop(); }]) assert.throws(() => validateLicenses((() => { const copy = clone(base); mutate(copy); return copy; })()));
}));

test('manifest exact roster/order/mode/link boundaries fail closed', () => withLock(() => {
  const manifest = read('MANIFEST.json'); const extra = local('mutant-empty-directory'); fs.mkdirSync(extra); try { assert.throws(() => validateManifest(manifest)); } finally { fs.rmdirSync(extra); }
  for (const mutate of [value => { value.files.reverse(); }, value => { value.directories.reverse(); }, value => { value.fileCount = 144; }, value => { value.rosterDigest = '0'.repeat(64); }]) assert.throws(() => validateManifest((() => { const copy = clone(manifest); mutate(copy); return copy; })()));
  const file = local('README.md'); const originalMode = fs.statSync(file).mode & 0o777; try { fs.chmodSync(file, 0o4755); assert.throws(() => validateManifest(read('MANIFEST.json'))); } finally { fs.chmodSync(file, originalMode); }
  const forged = clone(manifest); forged.files[0].contentDigest = '0'.repeat(64); assert.throws(() => validateManifest(forged));
}));

test('explicit reproduction command is exercised; static check itself remains non-building', () => withLock(() => {
  const check = execFileSync(process.execPath, ['generate.mjs', '--check'], { cwd: packageDirectory, encoding: 'utf8' }); assert.match(check, /"ok":true/);
  const output = execFileSync(process.execPath, ['generate.mjs', '--reproduce-check'], { cwd: packageDirectory, encoding: 'utf8' }); assert.match(output, /"ok":true/);
}));
