import assert from 'node:assert/strict';
import test from 'node:test';
import { chmodSync, cpSync, linkSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, deriveSealEnvelope, digestRecord, validateStatic } from '../validate-static.mjs';

const sourceRoot=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const prefix='gate-b0-static-source-authority-v1:';
const clone=()=>{const t=mkdtempSync(resolve(tmpdir(),'ssa-boundary-'));const p=resolve(t,'gate-b','gate-b0-static-source-authority-v1');mkdirSync(resolve(t,'gate-b'),{recursive:true});cpSync(sourceRoot,p,{recursive:true});for(const locator of ['MANIFEST.json','SHA256SUMS'])rmSync(resolve(p,locator),{force:true});return {p,t};};
const root=JSON.parse(readFileSync(resolve(sourceRoot,'static-source-authority-root.v1.json'))),sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const seal=p=>{const envelope=deriveSealEnvelope(p);writeFileSync(resolve(p,'MANIFEST.json'),envelope.manifestBytes);writeFileSync(resolve(p,'SHA256SUMS'),envelope.sumsBytes);return envelope;};
const anchor=(p,envelope)=>({
  artifactId:'artifact:gate-b:gate-b0-static-source-authority-review-anchor-v1',
  componentDigests:root.componentDigests,
  directDependencyBinding:root.dependencyPins[0],
  entryCount:24,
  manifestRawSha256:sha(envelope.manifestBytes),
  nonAuthorityBoundary:root.nonAuthorityBoundary,
  orderedClosure:envelope.entries,
  package:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-static-source-authority-v1',
  packageId:'gate-b0-static-source-authority-v1',
  rootContentDigest:root.contentDigest,
  rootRawSha256:sha(readFileSync(resolve(p,'static-source-authority-root.v1.json'))),
  rosterDigest:envelope.manifest.rosterDigest,
  schema:'shieldkit-labs/p2/gate-b/gate-b0-static-source-authority/v1/external-review-anchor/v1',
  schemaBindingTableDigest:digestRecord('shieldkit-labs/p2/gate-b/gate-b0-static-source-authority/v1/schema-bindings',root.schemaBindings),
  schemaBindings:root.schemaBindings,
  sha256SumsRawSha256:sha(envelope.sumsBytes),
  status:'sealed-static-source-contract-authority-review-anchor-no-provider-or-state-instances-no-io-no-execution-no-admission-unqualified',
  transitiveSourcePinTableDigest:digestRecord('shieldkit-labs/p2/gate-b/gate-b0-static-source-authority/v1/transitive-source-pins',root.transitiveSourcePins),
  validatorRawSha256:sha(readFileSync(resolve(p,'validate-static.mjs'))),
});
const exactError=token=>error=>error instanceof Error&&error.message===`${prefix}${token}`;
const pinAnchor=(p,t,envelope,mutate=()=>{})=>{const external=resolve(t,'external'),locator='review-anchor.v1.json',value=anchor(p,envelope);mkdirSync(external,{recursive:true});mutate(value);const bytes=Buffer.from(`${canonicalJson(value)}\n`);writeFileSync(resolve(external,locator),bytes);return {reviewAnchorPin:{reviewAnchorBytes:bytes.length,reviewAnchorLocator:locator,reviewAnchorRawSha256:sha(bytes),reviewAnchorRoot:external},repositoryRoot:resolve(sourceRoot,'../../../../..')};};
const expect=(label,mutate,token,mode='unsealed')=>test(label,()=>{const {p,t}=clone();try{const options=mutate(p,t)||{};assert.throws(()=>validateStatic({packageRoot:p,mode,...options}),exactError(token));}finally{rmSync(t,{recursive:true,force:true});}});

expect('missing-file',p=>rmSync(resolve(p,'README.md')),'PACKAGE_CLOSURE:unsealed');
expect('extra-file',p=>writeFileSync(resolve(p,'extra.txt'),'x'),'PACKAGE_CLOSURE:unsealed');
expect('partial-manifest',p=>writeFileSync(resolve(p,'MANIFEST.json'),'{}\n'),'PACKAGE_CLOSURE:unsealed');
expect('partial-sums',p=>writeFileSync(resolve(p,'SHA256SUMS'),'x'),'PACKAGE_CLOSURE:unsealed');
expect('embedded-anchor',p=>writeFileSync(resolve(p,'review-anchor.json'),'{}\n'),'PACKAGE_CLOSURE:unsealed');
expect('file-symlink',p=>{rmSync(resolve(p,'README.md'));symlinkSync('COMMAND.txt',resolve(p,'README.md'));},'PACKAGE_LINK_OR_SPECIAL_FILE');
expect('directory-symlink',(p,t)=>{rmSync(resolve(p,'test'),{recursive:true});mkdirSync(resolve(t,'elsewhere'));symlinkSync(resolve(t,'elsewhere'),resolve(p,'test'),'dir');},'PACKAGE_LINK_OR_SPECIAL_FILE');
expect('hardlink',(p,t)=>{const basis=resolve(t,'hardlink-basis');writeFileSync(basis,'x');rmSync(resolve(p,'README.md'));linkSync(basis,resolve(p,'README.md'));},'PACKAGE_FILE_METADATA:README.md');
expect('extra-directory',p=>mkdirSync(resolve(p,'extra-dir'),{mode:0o755}),'PACKAGE_DIRECTORY_ROSTER');
expect('file-mode',p=>chmodSync(resolve(p,'README.md'),0o600),'PACKAGE_FILE_METADATA:README.md');
expect('directory-mode',p=>chmodSync(resolve(p,'schemas'),0o700),'DIRECTORY_METADATA:schemas');
expect('root-mode',p=>chmodSync(p,0o700),'PACKAGE_ROOT_METADATA');
expect('noncanonical-name',p=>writeFileSync(resolve(p,'e\u0301.txt'),'x'),'PACKAGE_CLOSURE:unsealed');
test('traversal-locator rejects',()=>{const {p,t}=clone();try{seal(p);assert.throws(()=>validateStatic({packageRoot:p,repositoryRoot:resolve(sourceRoot,'../../../../..'),mode:'sealed',reviewAnchorPin:{reviewAnchorBytes:1,reviewAnchorLocator:'../lane.json',reviewAnchorRawSha256:'0'.repeat(64),reviewAnchorRoot:resolve(t,'external')}}),exactError('SEALED_ANCHOR_LOCATOR'));}finally{rmSync(t,{recursive:true,force:true});}});
expect('duplicate-roster',(p,t)=>{const envelope=seal(p),options=pinAnchor(p,t,envelope,value=>{value.orderedClosure[1]=value.orderedClosure[0];});return options;},'SEALED_ANCHOR_ORDERED_CLOSURE','sealed');
expect('reordered-roster',(p,t)=>{const envelope=seal(p),options=pinAnchor(p,t,envelope,value=>{[value.orderedClosure[0],value.orderedClosure[1]]=[value.orderedClosure[1],value.orderedClosure[0]];});return options;},'SEALED_ANCHOR_ORDERED_CLOSURE','sealed');
expect('wrong-mode-closure',()=>{},'PACKAGE_CLOSURE:sealed','sealed');
test('source-clone-depth',()=>{const {p,t}=clone();try{const q=resolve(t,'gate-b0-static-source-authority-v1');cpSync(p,q,{recursive:true});assert.throws(()=>validateStatic({packageRoot:q,mode:'unsealed'}),exactError('PACKAGE_ROOT'));}finally{rmSync(t,{recursive:true,force:true});}});
