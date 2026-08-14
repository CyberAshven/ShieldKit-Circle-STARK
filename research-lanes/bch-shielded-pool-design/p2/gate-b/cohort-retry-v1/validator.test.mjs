import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateRetry,digestRecord,validateRetryPackageEnvelope} from './validator.mjs';
const here=path.dirname(fileURLToPath(import.meta.url));
const base=()=>JSON.parse(fs.readFileSync(path.join(here,'attempt-001.retry-wrapper.v1.json'),'utf8'));
const rehash=x=>{delete x.contentDigest;x.contentDigest=digestRecord('shieldkit-labs/p2/gate-b/cohort-retry/v1/attempt-001',Object.fromEntries(Object.entries(x).filter(([k])=>k!=='contentDigest')));return x};
function withRestoredBytes(file,mutate,verify){const original=fs.readFileSync(file);try{fs.writeFileSync(file,mutate(original));assert.throws(verify)}finally{fs.writeFileSync(file,original)}}
test('retry is exact manual 0 to 1 planning-only transition',()=>{assert.equal(validateRetry(),true);assert.equal(validateRetryPackageEnvelope(),true)});
for(const [name,mutate] of [
 ['entrypoint hash',x=>{x.bindings.enginePins[2].entrypointRawSha256='0'.repeat(64)}],
 ['secondary entrypoint hash',x=>{x.bindings.enginePins[3].secondaryEntrypointRawSha256='0'.repeat(64)}],
 ['execution manifest hash',x=>{x.bindings.executionManifest.rawSha256='0'.repeat(64)}],
 ['executor manifest hash',x=>{x.bindings.executorManifest.rawSha256='0'.repeat(64)}],
 ['executor checksum hash',x=>{x.bindings.executorChecksums.rawSha256='0'.repeat(64)}],
 ['sealed accounting receipt pin',x=>{x.bindings.priorReceipt.rawSha256='0'.repeat(64)}],
 ['sealed accounting root pin',x=>{x.bindings.accountingRoot.contentDigest.value='0'.repeat(64)}],
 ['sealed accounting attempt manifest pin',x=>{x.bindings.attemptManifest.rawSha256='0'.repeat(64)}],
 ['sealed accounting package manifest pin',x=>{x.bindings.packageManifest.contentDigest.value='0'.repeat(64)}],
 ['sealed accounting checksum pin',x=>{x.bindings.packageChecksums.rawSha256='0'.repeat(64)}],
 ['attempt reuse',x=>{x.attempt.reusePriorResults=true}],
 ['schedule drift',x=>{x.bindings.schedule.rawSha256='0'.repeat(64)}],
 ['new authorization',x=>{x.attempt.authorizationForNextAttempt={forged:true}}],
 ['result reuse',x=>{x.resultReusePolicy.priorMetrics=[]}],
 ['injected wrapper exitCode',x=>{x.exitCode=1}],
 ['injected wrapper observedExitCode',x=>{x.observedExitCode=1}]
]) test(`retry rejects ${name}`,()=>{const x=base();mutate(x);rehash(x);assert.throws(()=>validateRetry(x))});

test('retry manifest has exact deterministic listed coverage',()=>{
 const m=JSON.parse(fs.readFileSync(path.join(here,'MANIFEST.json'),'utf8'));
 assert.equal(m.coverage.listedPayloadCount,m.files.length);
 assert.deepEqual(m.files.map(x=>x.path),[...m.files.map(x=>x.path)].sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))));
});
test('retry envelope rejects an empty unlisted directory',()=>{const d=path.join(here,'.empty-retry');fs.mkdirSync(d);try{assert.throws(()=>validateRetryPackageEnvelope())}finally{fs.rmdirSync(d)}});
test('retry envelope rejects a broken unlisted symlink',()=>{const p=path.join(here,'.broken-retry');fs.symlinkSync('/definitely-missing',p);try{assert.throws(()=>validateRetryPackageEnvelope())}finally{fs.unlinkSync(p)}});
for(const [name,mutate] of [['extra LF',b=>Buffer.concat([b,Buffer.from('\n')])],['extra space',b=>Buffer.from(b.toString('utf8').replace('  ','   '),'utf8')],['CR',b=>Buffer.from(b.toString('utf8').replace('\n','\r\n'),'utf8')]])test(`retry checksum rejects ${name}`,()=>withRestoredBytes(path.join(here,'SHA256SUMS'),mutate,()=>validateRetryPackageEnvelope()));
