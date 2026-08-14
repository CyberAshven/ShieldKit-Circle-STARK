import assert from 'node:assert/strict';
import { existsSync, lstatSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AUTHORED_FILES, DIRECTORIES, SEALED_FILES, parseValidationCliArgs, validateStatic } from '../validate-static.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const options = parseValidationCliArgs(process.argv.slice(2));
const walk = (dir, prefix = '') => readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? [`${prefix}${entry.name}/`, ...walk(resolve(dir, entry.name), `${prefix}${entry.name}/`)] : [`${prefix}${entry.name}`]);
const entries = walk(root);
const files = entries.filter(locator => !locator.endsWith('/')).sort();
const dirs = ['.', ...entries.filter(locator => locator.endsWith('/')).map(locator => locator.slice(0, -1))].sort();
const sealed = options.mode === 'sealed';
const expectedFiles = sealed ? SEALED_FILES : AUTHORED_FILES;
assert.deepEqual(files, [...expectedFiles].sort());
assert.deepEqual(dirs, [...DIRECTORIES].sort());
assert.equal(existsSync(resolve(root, 'MANIFEST.json')), sealed);
assert.equal(existsSync(resolve(root, 'SHA256SUMS')), sealed);
for (const locator of files) {
  const stat = lstatSync(resolve(root, locator));
  assert.equal(stat.isFile(), true);
  assert.equal(stat.nlink, 1);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.mode & 0o777, 0o644);
}
for (const locator of dirs) {
  const stat = lstatSync(resolve(root, locator));
  assert.equal(stat.isDirectory(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.mode & 0o777, 0o755);
}
const result = validateStatic({ packageRoot: root, repositoryRoot: resolve(root, '../../../../..'), mode: options.mode, reviewAnchorPin: options.reviewAnchorPin });
assert.equal(result.files, expectedFiles.length);
assert.equal(result.unsealed, !sealed);
console.log(`PASS package boundary mode=${options.mode}`);
