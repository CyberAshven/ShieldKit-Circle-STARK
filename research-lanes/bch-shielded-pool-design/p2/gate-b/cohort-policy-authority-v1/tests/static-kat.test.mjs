import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {KAT_ROSTER, canonicalBytes, findRepoRoot, makeManifest, makeRoot, validatePackage, validateRootObject} from '../validate.mjs';

const packageDir = path.dirname(path.dirname(new URL(import.meta.url).pathname));
const repoRoot = findRepoRoot(packageDir);
const inventory = root => {
  const rows = [];
  const visit = current => {
    for (const entry of fs.readdirSync(current,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))) {
      const file = path.join(current,entry.name), stat = fs.lstatSync(file), relative = path.relative(root,file).split(path.sep).join('/');
      rows.push({path:relative,type:stat.isDirectory()?'directory':stat.isFile()?'file':stat.isSymbolicLink()?'symlink':'other',mode:stat.mode & 0o777,nlink:stat.nlink,size:stat.size,mtimeMs:stat.mtimeMs,rawSha256:stat.isFile()?crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'):null});
      if (stat.isDirectory()) visit(file);
    }
  };
  visit(root); return rows;
};
const before = inventory(packageDir);
const check = spawnSync(process.execPath,['generate.mjs','--check'],{cwd:packageDir,encoding:'utf8'});
assert.equal(check.status,0,check.stderr);
assert.deepEqual(inventory(packageDir),before,'--check changed recursive path/type/mode/nlink/size/mtime/raw-byte inventory');
const root = makeRoot(repoRoot,packageDir);
assert.doesNotThrow(() => validateRootObject(root,repoRoot,packageDir));
assert.equal(root.causalDag.edges.length,28);
assert.equal(KAT_ROSTER.length,27);
assert.deepEqual(root.policy.kLaunchAuthority.map(row=>row.workloads),[4608,4608,4608,4608,4608]);
assert.equal(root.policy.a.forbiddenFields.includes('consumptionState'),true);
assert.equal(root.policy.j.grantsAuthority,false);
assert.equal(root.runtimeBoundary.runtimeEntrypoint,null);
assert.equal(makeManifest(packageDir,canonicalBytes(root)).fileCount,15);
if (fs.existsSync(path.join(packageDir,'policy-authority-root.v1.json'))) assert.equal(validatePackage(packageDir,repoRoot).sealed,true);
console.log(`static KAT passed: ${KAT_ROSTER.length} KAT names, recursive check inventory unchanged`);
