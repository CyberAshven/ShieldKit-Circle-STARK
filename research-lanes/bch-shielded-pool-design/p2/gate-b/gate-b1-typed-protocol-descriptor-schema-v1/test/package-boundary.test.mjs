import assert from 'node:assert/strict';
import { cpSync, existsSync, linkSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AUTHORED_FILES, validateStatic } from '../validate-static.mjs';

const root = new URL('..', import.meta.url);
const walk = (dir, prefix = '') => readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(new URL(`${entry.name}/`, dir), `${prefix}${entry.name}/`) : [`${prefix}${entry.name}`]);
assert.deepEqual(walk(root).sort(), [...AUTHORED_FILES].sort());
assert.equal(existsSync(new URL('../MANIFEST.json', import.meta.url)), false);
assert.equal(existsSync(new URL('../SHA256SUMS', import.meta.url)), false);
for (const locator of AUTHORED_FILES) assert.equal(/(?:candidate|tuple|proof|transaction|deployment)\.json$/u.test(locator), false, locator);
const repositoryRoot = new URL('../../../../../..', import.meta.url);
const rootPath = fileURLToPath(root);
const sandbox = mkdtempSync(join(rootPath, '.boundary-'));
const copy = join(sandbox, 'package');
const expectBoundaryFailure = (mutate, pattern) => {
  const caseRoot = join(sandbox, `case-${Math.random().toString(16).slice(2)}`);
  cpSync(copy, caseRoot, { recursive: true });
  mutate(caseRoot);
  assert.throws(() => validateStatic({ packageRoot: caseRoot, repositoryRoot: new URL(repositoryRoot).pathname }), pattern);
};
try {
  for (const locator of AUTHORED_FILES) {
    const target = join(copy, locator);
    mkdirSync(dirname(target), { recursive: true });
    cpSync(join(rootPath, locator), target);
  }
  expectBoundaryFailure(caseRoot => writeFileSync(join(caseRoot, 'extra-descriptor.json'), '{}\n'), /UNSEALED_FILE_CLOSURE/);
  expectBoundaryFailure(caseRoot => writeFileSync(join(caseRoot, 'MANIFEST.json'), '{}\n'), /UNSEALED_FILE_CLOSURE|PACKAGE_MUST_REMAIN_UNSEALED/);
  expectBoundaryFailure(caseRoot => writeFileSync(join(caseRoot, 'SHA256SUMS'), 'x\n'), /UNSEALED_FILE_CLOSURE|PACKAGE_MUST_REMAIN_UNSEALED/);
  expectBoundaryFailure(caseRoot => { unlinkSync(join(caseRoot, 'README.md')); symlinkSync('../README.md', join(caseRoot, 'README.md')); }, /PACKAGE_METADATA|UNSEALED_FILE_CLOSURE/);
  expectBoundaryFailure(caseRoot => { const external = join(sandbox, `external-${Math.random().toString(16).slice(2)}.md`); writeFileSync(external, 'external\n'); unlinkSync(join(caseRoot, 'README.md')); linkSync(external, join(caseRoot, 'README.md')); }, /PACKAGE_METADATA/);
} finally {
  rmSync(sandbox, { recursive: true, force: true });
}
