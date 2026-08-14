import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {canonicalBytes, findRepoRoot, makeRoot, sha256, validatePackage, validateRootObject} from '../validate.mjs';

const packageDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const repoRoot = process.env.SHIELDKIT_LABS_ROOT || findRepoRoot(packageDir);
const result = validatePackage(packageDir, repoRoot);
const root = JSON.parse(fs.readFileSync(path.join(packageDir, 'frozen-inputs-root.v1.json')));
assert.deepEqual(root, makeRoot(repoRoot, packageDir));
assert.equal(sha256(fs.readFileSync(path.join(repoRoot, 'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.json'))), '53e9acc311a123ad26908b84cf73149913781c1fe72253cc6cd28fef644751b5');
assert.equal(root.leafClosure.leaves[0].nativeSemanticDigest.value, '58e7765b066b1917b1fa0b4b96182010ad7f5c8ce8bce601c083bc764845482e');
assert.equal(root.leafClosure.leaves[1].wrapper.root.rawSha256, '84ff8f6a85244b65d5d4f6e80c38b516223641ee444a133a67eb5794311d2dbc');
assert.equal(root.leafClosure.leaves[1].artifactSemanticDigest.value, '6fcbaba3bb52d5e1eb9c6f1cb04b1d46cb65e2c91eba20ca38356dc323ebb11e');
assert.ok(!Object.hasOwn(root.leafClosure.leaves[1], 'nativeSemanticDigest'));
assert.equal(Buffer.compare(fs.readFileSync(path.join(packageDir, 'frozen-inputs-root.v1.json')), canonicalBytes(root)), 0);
assert.equal(result.files, 11); assert.equal(result.directories, 3);
const inventory = () => fs.readdirSync(packageDir, {recursive:true,withFileTypes:true}).map((entry) => {
  const full = path.join(entry.parentPath ?? entry.path, entry.name); const stat = fs.lstatSync(full);
  return [path.relative(packageDir, full), stat.mode, stat.nlink, stat.size, stat.mtimeNs?.toString() ?? String(stat.mtimeMs), entry.isFile() ? sha256(fs.readFileSync(full)) : null];
}).sort((a,b) => a[0].localeCompare(b[0]));
const before = inventory(); const check = spawnSync(process.execPath, ['generate.mjs', '--check'], {cwd:packageDir, encoding:'utf8'});
assert.equal(check.status, 0, check.stderr); assert.deepEqual(inventory(), before, '--check must not mutate bytes or stat inventory');
console.log(`static KAT passed: ${result.root}`);
