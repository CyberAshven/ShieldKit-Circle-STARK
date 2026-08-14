import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {DOMAIN_PREFIX, assertDirectoryChain, assertLiveFRecordList, assertOwnClosure, canonicalBytes, domainDigest, findRepoRoot, makeManifest, makeRoot, validateRootObject, validateSchemas} from '../validate.mjs';

const packageDir = path.dirname(path.dirname(new URL(import.meta.url).pathname));
const repoRoot = findRepoRoot(packageDir);
const base = makeRoot(repoRoot,packageDir);
let rejected = 0, positiveControls = 0;
const reject = (label, edit) => { const value = structuredClone(base); edit(value); assert.throws(() => validateRootObject(value,repoRoot,packageDir),/FAIL-CLOSED/,label); rejected += 1; };
const mutations = [
  ['missing-edge',x=>x.causalDag.edges.pop()],['extra-edge',x=>x.causalDag.edges.push('P→TERMINAL')],['cycle',x=>x.causalDag.edges[0]='R→N'],
  ['R-pin',x=>x.dependencyBindings[0].runtimeAuthorityDigest='0'.repeat(64)],['K-identity',x=>x.dependencyBindings[1].entriesRoot='0'.repeat(64)],['F-order',x=>x.dependencyBindings[2].orderedLeafIds.reverse()],
  ['nonexecution',x=>x.executionAllowed=true],['runtime-entrypoint',x=>x.runtimeBoundary.runtimeEntrypoint='src/contracts.mjs'],['manifest-domain',x=>x.policy.contentDigest.domain='shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/manifest'],
  ['initial-target',x=>x.policy.q.variants.initial.target='full-cohort'],['retry-ordinal',x=>x.policy.q.variants.retry.restartEngineOrdinal=1],['abort-recovery',x=>x.policy.q.variants.abort.recovery='automatic'],
  ['A-consumption',x=>x.policy.a.forbiddenFields=[]],['C-consumer',x=>x.policy.c.soleDurableConsumer='P'],['live-F-retain',x=>x.policy.liveF.kRetainsDescriptor=true],
  ['B-frame',x=>x.policy.b.subject.frame='raw'],['five-launch-rows',x=>x.policy.kLaunchAuthority.pop()],['workload-not-row-count',x=>x.policy.kLaunchAuthority[0].workloads=1],
  ['alias-colon',x=>x.policy.aliasMap.native='native'],['J-authority',x=>x.policy.j.grantsAuthority=true],['D-chain',x=>x.policy.d.plannedRows.maximum=4608],['root-key',x=>x.extra=true],
  ['q-domain-swap',x=>x.policy.q.variants.initial.contentDigest.domain=x.policy.q.variants.retry.contentDigest.domain],['q-nested-extra',x=>x.policy.q.variants.initial.extra=true],
  ['dependency-order',x=>[x.dependencyBindings[0],x.dependencyBindings[1]]=[x.dependencyBindings[1],x.dependencyBindings[0]]],['schema-id',x=>x.schemaBindings[0].schemaId='wrong-schema-id']
];
for (const [label,edit] of mutations) reject(label,edit);
const schemaReject = (label, edit) => { const value = structuredClone(base); edit(value); assert.throws(() => validateSchemas(packageDir,value,makeManifest(packageDir,canonicalBytes(base))),/FAIL-CLOSED/,label); rejected += 1; };
schemaReject('schema-q-domain-swap',x=>x.policy.q.variants.initial.contentDigest.domain=x.policy.q.variants.retry.contentDigest.domain);
schemaReject('schema-q-extra-key',x=>x.policy.q.variants.initial.extra=true);
schemaReject('schema-dependency-order',x=>[x.dependencyBindings[0],x.dependencyBindings[1]]=[x.dependencyBindings[1],x.dependencyBindings[0]]);
schemaReject('schema-binding-id',x=>x.schemaBindings[0].schemaId='wrong-schema-id');
schemaReject('schema-R-with-K-field',x=>x.dependencyBindings[0].manifestRoot='0'.repeat(64));
schemaReject('schema-K-with-R-field',x=>x.dependencyBindings[1].runtimeAuthorityDigest='0'.repeat(64));
schemaReject('schema-F-with-K-field',x=>x.dependencyBindings[2].entriesRoot='0'.repeat(64));
schemaReject('schema-policy-domain-swap',x=>x.policy.contentDigest.domain='shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/root');
const record = logicalPath => ({logicalPath,dev:1,ino:1,mode:0o644,nlink:1,byteCount:1,rawSha256:'0'.repeat(64)});
assert.doesNotThrow(() => assertLiveFRecordList([record('alpha'),record('beta')])); positiveControls += 1;
assert.doesNotThrow(() => assertLiveFRecordList([record('alpha/😀')])); positiveControls += 1;
const recordReject = (label, records) => { assert.throws(() => assertLiveFRecordList(records),/FAIL-CLOSED/,label); rejected += 1; };
recordReject('swapped logical paths',[record('beta'),record('alpha')]);
recordReject('permuted logical paths',[record('alpha'),record('charlie'),record('beta')]);
recordReject('duplicate logical paths',[record('alpha'),record('alpha')]);
recordReject('noncanonical logical path',[record('alpha'),record('../beta')]);
recordReject('non-NFC logical path',[record('a'),record('e\u0301')]);
recordReject('lone high surrogate',[record('\uD800')]);
recordReject('lone low surrogate',[record('\uDC00')]);
recordReject('malformed surrogate pair',[record('\uD800\uD800')]);
const rehash = (value, suffix) => { const body = structuredClone(value); delete body.contentDigest; value.contentDigest.value = domainDigest(`${DOMAIN_PREFIX}${suffix}`,body); };
const coordinated = structuredClone(base); coordinated.policy.liveF.recordOrdering.sort = 'insertion-order'; rehash(coordinated.policy.liveF,'live-f'); rehash(coordinated.policy,'policy'); rehash(coordinated,'root'); assert.throws(() => validateRootObject(coordinated,repoRoot,packageDir),/FAIL-CLOSED/,'coordinated live-F rehash'); rejected += 1;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(),'policy-authority-chain-'));
try { fs.chmodSync(tmp,0o755); fs.mkdirSync(path.join(tmp,'root'),{mode:0o755}); fs.symlinkSync(path.join(tmp,'root'),path.join(tmp,'link')); assert.throws(() => assertDirectoryChain(tmp,'link',0o755,'mutant'),/FAIL-CLOSED/); rejected += 1; fs.chmodSync(path.join(tmp,'root'),0o700); assert.throws(() => assertDirectoryChain(tmp,'root',0o755,'mutant'),/FAIL-CLOSED/); rejected += 1; assert.throws(() => assertDirectoryChain(tmp,'../root',0o755,'mutant'),/FAIL-CLOSED/); rejected += 1; } finally { fs.rmSync(tmp,{recursive:true,force:true}); }
const closureTmp = fs.mkdtempSync(path.join(os.tmpdir(),'policy-authority-closure-'));
try {
  const copy = path.join(closureTmp,'copy'); fs.cpSync(packageDir,copy,{recursive:true,dereference:false}); const sealed = fs.existsSync(path.join(copy,'SHA256SUMS'));
  assert.doesNotThrow(() => assertOwnClosure(copy,sealed)); positiveControls += 1;
  fs.linkSync(path.join(copy,'README.md'),path.join(copy,'README-copy.md')); assert.throws(() => assertOwnClosure(copy,sealed),/FAIL-CLOSED/,'hardlink/extra rejected'); rejected += 1; fs.unlinkSync(path.join(copy,'README-copy.md'));
  fs.writeFileSync(path.join(copy,'extra.txt'),'x'); assert.throws(() => assertOwnClosure(copy,sealed),/FAIL-CLOSED/,'extra file rejected'); rejected += 1; fs.unlinkSync(path.join(copy,'extra.txt'));
  fs.mkdirSync(path.join(copy,'empty')); assert.throws(() => assertOwnClosure(copy,sealed),/FAIL-CLOSED/,'empty directory rejected'); rejected += 1; fs.rmdirSync(path.join(copy,'empty'));
  fs.symlinkSync('README.md',path.join(copy,'link')); assert.throws(() => assertOwnClosure(copy,sealed),/FAIL-CLOSED/,'link rejected'); rejected += 1;
} finally { fs.rmSync(closureTmp,{recursive:true,force:true}); }
console.log(`mutation KAT passed: ${rejected} fail-closed mutants; ${positiveControls} positive controls; roster=${base.katRoster.length}`);
