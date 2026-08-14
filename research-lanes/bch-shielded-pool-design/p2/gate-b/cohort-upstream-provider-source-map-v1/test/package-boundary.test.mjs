import assert from 'node:assert/strict';
import { lstatSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const authored = ['COMMAND.txt','README.md','upstream-provider-source-map-root.v1.json','schemas/b1-reentry-boundary.v1.schema.json','schemas/dependency-catalog.v1.schema.json','schemas/digest.v1.schema.json','schemas/interface-source-map.v1.schema.json','schemas/manifest.v1.schema.json','schemas/mapping-dag.v1.schema.json','schemas/model-root.v1.schema.json','schemas/non-authority-boundary.v1.schema.json','schemas/source-reference-catalog.v1.schema.json','schemas/uopc-contract-prefix.v1.schema.json','validate-static.mjs','test/digest.kat.json','test/mutation.test.mjs','test/package-boundary.test.mjs','test/static.test.mjs'];
const walk = (dir, prefix = '') => readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(join(dir, entry.name), `${prefix}${entry.name}/`) : [`${prefix}${entry.name}`]);
const files = walk(root).sort();
assert.deepEqual(files, [...authored, 'MANIFEST.json', 'SHA256SUMS'].sort());
for (const locator of files) {
  const stat = lstatSync(join(root, locator));
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.nlink, 1);
  assert.equal(stat.mode & 0o777, 0o644);
}
for (const locator of ['', 'schemas', 'test']) {
  const stat = lstatSync(join(root, locator));
  assert.equal(stat.isDirectory(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.nlink, 1);
  assert.equal(stat.mode & 0o777, 0o755);
}
