import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EXPECTED_DIRS, FIXED_IMAGE_IDENTITIES, imagePath, parseChecksumLine, validateDirectoryRoster, validateFixedBinaryIdentity, validateImage, validateLicenses, validateManifest, validateMaterialization, validateSource } from './semantic-validators.mjs';

const clone = value => structuredClone(value);
const read = name => JSON.parse(fs.readFileSync(imagePath(name), 'utf8'));
const rejectsEach = (base, validator, mutations) => { for (const mutate of mutations) { const mutant = clone(base); mutate(mutant); assert.throws(() => validator(mutant)); } };

test('runtime image identity, ELF, dependency, environment, and argv mutants fail closed', () => {
  const base = read('runtime-image.v1.json');
  rejectsEach(base, validateImage, [
    value => { value.executable.sha256 = '0'.repeat(64); },
    value => { value.dsos.pop(); },
    value => { value.dsos.reverse(); },
    value => { value.executable.elf.ptInterp = '/host/ld.so'; },
    value => { value.dsos[0].elf.dtNeeded = ['libmissing.so.0']; },
    value => { value.loader.usedBy.reverse(); },
    value => { value.dsos[0].usedBy.push('mutant'); },
    value => { value.executable.sourceRealpath = '/tmp/node'; },
    value => { value.executable.nlink = 2; },
    value => { value.launch.loaderInvocation.forbiddenEnvironment.reverse(); },
    value => { value.launch.loaderInvocation.environment.NODE_OPTIONS = 'x'; },
    value => { value.launch.loaderInvocation.argvTemplate[1] = '--cache'; },
    value => { value.launch.loaderInvocation.commandTemplate += ' mutant'; },
    value => { value.launch.loaderInvocation.executed = true; },
    value => { value.executionAllowed = true; }
  ]);
});

test('source closure joins and path mutants fail closed', () => {
  const base = read('source/node-runtime-closure.v1.json');
  rejectsEach(base, validateSource, [
    value => { value.node.bytes += 1; },
    value => { value.loader.elf.soname = 'mutant.so'; },
    value => { value.dsos.reverse(); },
    value => { value.dsos[0].usedBy.push('mutant'); },
    value => { value.dsos[0].path = '../libc.so.6'; },
    value => { value.dsos[0].mode = 0o777; },
    value => { value.dsos[0].sha256 = '0'.repeat(64); }
  ]);
});

test('license package, notice, and source mutants fail closed', () => {
  const base = read('licenses/provenance.v1.json'); const image = read('runtime-image.v1.json');
  for (const mutate of [
    value => { value.packages[0].version = '22.23.0'; },
    value => { value.packages.reverse(); },
    value => { value.copiedNoticeFiles[0].path = '../LICENSE'; },
    value => { value.copiedNoticeFiles[0].sha256 = '0'.repeat(64); },
    value => { value.copiedNoticeFiles[0].nlink = 2; },
    value => { value.copiedNoticeFiles[0].source = '/tmp/LICENSE'; }
  ]) { const mutant = clone(base); mutate(mutant); assert.throws(() => validateLicenses(mutant, image)); }
  const imageMutant = clone(image); imageMutant.executable.licenseRefs = ['package:glibc']; assert.throws(() => validateLicenses(base, imageMutant));
});

test('manifest path, roster, record, order, and count mutants fail closed', () => {
  const base = read('MANIFEST.json');
  rejectsEach(base, validateManifest, [
    value => { value.files.reverse(); },
    value => { value.files[0].path = '../README.md'; },
    value => { value.files[0].bytes += 1; },
    value => { value.files[0].sha256 = '0'.repeat(64); },
    value => { value.files[0].contentDigest = '0'.repeat(64); },
    value => { value.files.push(clone(value.files[0])); },
    value => { value.fileCount += 1; },
    value => { value.directories.reverse(); },
    value => { value.directories[0].path = '../image'; },
    value => { value.directories[0].mode = 0o777; },
    value => { value.directoryCount += 1; },
    value => { value.rosterDigest = '0'.repeat(64); },
    value => { value.contentDigest = '0'.repeat(64); }
  ]);
});

test('filesystem directory roster rejects extra empty directories and mode drift', () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldkit-node-roster-'));
  try {
    for (const directory of EXPECTED_DIRS) {
      const absolute = path.join(temporaryRoot, ...directory.path.split('/'));
      fs.mkdirSync(absolute, { recursive: true });
      fs.chmodSync(absolute, directory.mode);
    }
    assert.doesNotThrow(() => validateDirectoryRoster(temporaryRoot));

    const extra = path.join(temporaryRoot, 'extra-empty');
    fs.mkdirSync(extra);
    assert.throws(() => validateDirectoryRoster(temporaryRoot), /immutable walked directory roster/);
    fs.rmdirSync(extra);

    const modeMutant = path.join(temporaryRoot, EXPECTED_DIRS[0].path);
    fs.chmodSync(modeMutant, 0o700);
    assert.throws(() => validateDirectoryRoster(temporaryRoot), /immutable walked directory roster/);
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('qualification flag mutant fails closed', () => {
  const materialization = read('materialization.v1.json'); materialization.executionAllowed = true; assert.throws(() => validateMaterialization(materialization));
});

test('fixed binary identity rejects sealed-copy mutants for Node, loader, and every DSO', () => {
  for (const identity of FIXED_IMAGE_IDENTITIES) {
    const mutant = Buffer.from(fs.readFileSync(imagePath(identity.path))); mutant[0x200 % mutant.length] ^= 0x01;
    assert.throws(() => validateFixedBinaryIdentity(identity.path, mutant, identity.mode), /fixed binary identity/);
  }
});

test('checksum parser rejects trailing fields and malformed line endings', () => {
  const digest = '0'.repeat(64);
  assert.throws(() => parseChecksumLine(`${digest}  path  trailing`));
  assert.throws(() => parseChecksumLine(`${digest}  path\r`));
  assert.throws(() => parseChecksumLine(`${digest} path`));
});
