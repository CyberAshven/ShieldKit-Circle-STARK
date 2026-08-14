import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {assertDirectoryChain, findRepoRoot, validateLeafClosure, validatePackage, validateRootObject} from '../validate.mjs';

const packageDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const repoRoot = process.env.SHIELDKIT_LABS_ROOT || findRepoRoot(packageDir);
const root = () => JSON.parse(fs.readFileSync(path.join(packageDir, 'frozen-inputs-root.v1.json')));
const rejectRoot = (mutate, label) => { const value = root(); mutate(value); assert.throws(() => validateRootObject(value, repoRoot), /FAIL-CLOSED/, label); };
rejectRoot((x) => { x.leafClosure.leaves.reverse(); }, 'leaf swap');
rejectRoot((x) => { x.leafClosure.leaves[1] = structuredClone(x.leafClosure.leaves[0]); }, 'duplicate leaf');
rejectRoot((x) => { x.leafClosure.leaves[0].nativeSemanticDigest.value = x.leafClosure.leaves[0].wrapper.root.rawSha256; }, 'raw/native domain confusion');
rejectRoot((x) => { x.leafClosure.leaves[0].wrapper.root.fileContentDigest.frame = 'utf8(domain)||0x00||canonical-json-utf8'; }, 'file digest domain confusion');
rejectRoot((x) => { x.leafClosure.leaves[1].nativeSemanticDigest = structuredClone(x.leafClosure.leaves[0].nativeSemanticDigest); }, 'native digest presence on freeze');
rejectRoot((x) => { x.leafClosure.leaves[0].wrapper.manifest.rawSha256 = x.leafClosure.leaves[0].wrapper.sums.rawSha256; }, 'manifest substitution');
rejectRoot((x) => { x.executionAllowed = true; }, 'execution permission');
rejectRoot((x) => { x.status = `static-cohort-${'execution-v3'}-reference`; }, 'forbidden lineage');
rejectRoot((x) => { x.contentDigest.value = '0'.repeat(64); }, 'root substitution');
const mutatePackage = (mutate, label) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'frozen-inputs-v1-'));
  const copy = path.join(tmp, 'package'); fs.cpSync(packageDir, copy, {recursive:true, dereference:false});
  try { mutate(copy); assert.throws(() => validatePackage(copy, repoRoot, {allowDetachedForTest:true}), /FAIL-CLOSED/, label); } finally { fs.rmSync(tmp, {recursive:true, force:true}); }
};
mutatePackage((p) => fs.appendFileSync(path.join(p, 'MANIFEST.json'), ' '), 'manifest raw substitution');
mutatePackage((p) => fs.appendFileSync(path.join(p, 'SHA256SUMS'), '0'.repeat(64) + '  injected\n'), 'checksum substitution');
mutatePackage((p) => fs.writeFileSync(path.join(p, 'extra.txt'), 'x'), 'extra file');
mutatePackage((p) => fs.mkdirSync(path.join(p, 'extra-dir')), 'extra directory');
mutatePackage((p) => fs.symlinkSync('README.md', path.join(p, 'link')), 'symlink');
mutatePackage((p) => { fs.unlinkSync(path.join(p, 'README.md')); fs.linkSync(path.join(p, 'COMMAND.txt'), path.join(p, 'README.md')); }, 'hardlink');
mutatePackage((p) => fs.appendFileSync(path.join(p, 'README.md'), `${'snap'}${'shot'}`), 'forbidden documentation reference');
mutatePackage((p) => fs.appendFileSync(path.join(p, 'schemas/manifest.v1.schema.json'), `${'live-'}${'executor'}`), 'forbidden schema reference');
rejectRoot((x) => { x.leafClosure.leaves[0].wrapper.root.path = '../escape'; }, 'path traversal');
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const writeSyntheticLeaf = (base) => {
  const leaf = path.join(base, 'leaf'); fs.mkdirSync(leaf); fs.writeFileSync(path.join(leaf, 'root.json'), '{"fixed":true}\n');
  const rootBytes = fs.readFileSync(path.join(leaf, 'root.json'));
  const manifest = {files:[{byteCount:rootBytes.length,fileDigest:{algorithm:'sha256',preimage:'exact-file-bytes',value:sha256(rootBytes)},orderIndex:0,path:'root.json'}]};
  fs.writeFileSync(path.join(leaf, 'MANIFEST.json'), JSON.stringify(manifest));
  const sums = ['root.json','MANIFEST.json'].map((name) => `${sha256(fs.readFileSync(path.join(leaf, name)))}  ${name}`).join('\n') + '\n'; fs.writeFileSync(path.join(leaf, 'SHA256SUMS'), sums);
  return {id:'synthetic',packageRoot:'leaf',root:'root.json',rawRoot:sha256(rootBytes),manifest:sha256(fs.readFileSync(path.join(leaf, 'MANIFEST.json'))),sums:sha256(fs.readFileSync(path.join(leaf, 'SHA256SUMS')))};
};
const mutateSyntheticLeaf = (mutate, label) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'frozen-leaf-v1-'));
  try { fs.chmodSync(tmp, 0o755); const spec = writeSyntheticLeaf(tmp); validateLeafClosure(tmp, spec); mutate(path.join(tmp, 'leaf')); assert.throws(() => validateLeafClosure(tmp, spec), /FAIL-CLOSED/, label); } finally { fs.rmSync(tmp, {recursive:true, force:true}); }
};
mutateSyntheticLeaf((p) => fs.writeFileSync(path.join(p, 'extra'), 'x'), 'leaf extra file');
mutateSyntheticLeaf((p) => fs.mkdirSync(path.join(p, 'empty')), 'leaf empty directory');
mutateSyntheticLeaf((p) => fs.symlinkSync('root.json', path.join(p, 'link')), 'leaf symlink');
mutateSyntheticLeaf((p) => { fs.unlinkSync(path.join(p, 'root.json')); fs.linkSync(path.join(p, 'MANIFEST.json'), path.join(p, 'root.json')); }, 'leaf hardlink');
mutateSyntheticLeaf((p) => fs.appendFileSync(path.join(p, 'SHA256SUMS'), '0'.repeat(64) + '  bogus\n'), 'leaf checksum mutation');
mutateSyntheticLeaf((p) => fs.appendFileSync(path.join(p, 'MANIFEST.json'), ' '), 'leaf manifest mutation');
const packageLinkRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'frozen-own-link-v1-'));
try { const link = path.join(packageLinkRoot, 'package-link'); fs.symlinkSync(packageDir, link); assert.throws(() => validatePackage(link, repoRoot), /FAIL-CLOSED/, 'symlinked own package root'); } finally { fs.rmSync(packageLinkRoot, {recursive:true, force:true}); }
const externalChainRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'frozen-external-chain-v1-'));
try {
  const repo = path.join(externalChainRoot, 'repo'); const target = path.join(repo, 'target'); fs.mkdirSync(path.join(repo, 'outer', 'leaf'), {recursive:true}); fs.mkdirSync(target); fs.rmSync(path.join(repo, 'outer'), {recursive:true, force:true}); fs.symlinkSync(target, path.join(repo, 'outer'));
  assert.throws(() => assertDirectoryChain(repo, 'outer/leaf', 'external leaf'), /FAIL-CLOSED/, 'symlinked intermediate external leaf directory');
} finally { fs.rmSync(externalChainRoot, {recursive:true, force:true}); }
console.log('mutation KAT passed: 26 causal fail-closed mutations');
