import assert from 'node:assert/strict';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { AUTHORED_FILES } from '../validate-static.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const FORBIDDEN = /\b(?:src|package\.json|generator|writer|sealer|binder|transition|reducer|constructor|endpoint|runtime|child_process|worker_threads|node:vm|WebAssembly|fetch|WebSocket|XMLHttpRequest)\b/;
function collect(dir, prefix = '') { const out = []; for (const name of readdirSync(dir).sort()) { const locator = prefix ? prefix + '/' + name : name; const file = join(dir, name); const info = lstatSync(file); if (info.isDirectory()) out.push(...collect(file, locator)); else out.push(locator); } return out; }

test('sealed package has exact 21-file and three-directory closure', () => {
  assert.deepEqual(collect(ROOT), AUTHORED_FILES.concat(['MANIFEST.json', 'SHA256SUMS']).sort());
  for (const dir of ['.', 'schemas', 'test']) { const info = lstatSync(dir === '.' ? ROOT : join(ROOT, dir)); assert.equal(info.isDirectory(), true); assert.equal(info.isSymbolicLink(), false); assert.equal(info.nlink, 1); assert.equal(info.mode & 0o777, 0o755); }
  for (const locator of AUTHORED_FILES.concat(['MANIFEST.json', 'SHA256SUMS'])) { const info = lstatSync(join(ROOT, locator)); assert.equal(info.isFile(), true); assert.equal(info.isSymbolicLink(), false); assert.equal(info.nlink, 1); assert.equal(info.mode & 0o777, 0o644); }
});

test('catalog contains no package implementation or activation surface', () => {
  const files = collect(ROOT); assert.equal(files.some((file) => /^(?:src\/|package\.json$|index\.mjs$|main\.mjs$)/u.test(file)), false);
  const validator = readFileSync(join(ROOT, 'validate-static.mjs'), 'utf8');
  const checked = validator.slice(0, validator.indexOf('function checkSourceBoundary')) + validator.slice(validator.indexOf('\nfunction validateStatic('));
  assert.deepEqual([...validator.matchAll(/^import\s+.+?\s+from\s+['"]([^'"]+)['"];?$/gmu)].map((match) => match[1]), ['node:crypto', 'node:fs', 'node:path', 'node:url', 'ajv/dist/2020.js']);
  assert.equal(/\b(?:child_process|worker_threads|node:vm|WebAssembly|fetch|WebSocket|XMLHttpRequest|eval|Function)\b/.test(checked), false);
});
