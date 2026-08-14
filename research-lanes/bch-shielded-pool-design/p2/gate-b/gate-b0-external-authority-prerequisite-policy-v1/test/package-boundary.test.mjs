import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { chmodSync, copyFileSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AUTHORED_FILES, canonicalJson, deriveReviewAnchor, deriveSealEnvelope, parseValidationCliArgs, validateStatic } from '../validate-static.mjs';

const here=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const gateRoot=dirname(here);
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const expectToken=(action,token)=>assert.throws(action,error=>error instanceof Error&&error.message===`EAPP_${token}`);
const sourceClone=({shortPath=false}={})=>{
  const clone=mkdtempSync(shortPath?resolve(tmpdir(),'eapp-b-'):resolve(gateRoot,'.eapp-boundary-'),{encoding:'utf8'});
  chmodSync(clone,0o755);
  mkdirSync(resolve(clone,'schemas'),{mode:0o755});
  mkdirSync(resolve(clone,'test'),{mode:0o755});
  for(const locator of AUTHORED_FILES){
    copyFileSync(resolve(here,locator),resolve(clone,locator));
    chmodSync(resolve(clone,locator),0o644);
  }
  return clone;
};
const sealClone=clone=>{
  const envelope=deriveSealEnvelope(clone);
  writeFileSync(resolve(clone,'MANIFEST.json'),envelope.manifestBytes,{mode:0o644});
  writeFileSync(resolve(clone,'SHA256SUMS'),envelope.sumsBytes,{mode:0o644});
  const root=JSON.parse(readFileSync(resolve(clone,'external-authority-prerequisite-policy-root.v1.json')));
  const anchor=deriveReviewAnchor({root,validatorRawSha256:sha256(readFileSync(resolve(clone,'validate-static.mjs'))),manifestRawSha256:sha256(envelope.manifestBytes),sha256SumsRawSha256:sha256(envelope.sumsBytes),entries:envelope.entries,rosterDigest:envelope.manifest.rosterDigest});
  const anchorBytes=Buffer.from(`${canonicalJson(anchor)}\n`);
  const anchorRoot=mkdtempSync(resolve(gateRoot,'.eapp-anchor-'),{encoding:'utf8'});
  chmodSync(anchorRoot,0o755);
  const locator='review-anchor.json';
  writeFileSync(resolve(anchorRoot,locator),anchorBytes,{mode:0o644});
  return {anchorRoot,locator,anchorBytes,pin:{reviewAnchorRoot:anchorRoot,reviewAnchorLocator:locator,reviewAnchorBytes:anchorBytes.length,reviewAnchorRawSha256:sha256(anchorBytes)}};
};
const withClone=async(action,{shortPath=false}={})=>{
  const clone=sourceClone({shortPath});
  const cleanups=[];
  try{return await action(clone,cleanups);}
  finally{for(const path of cleanups.reverse())rmSync(path,{recursive:true,force:true});rmSync(clone,{recursive:true,force:true});}
};

const boundaryFixtures=[
  ['extra-file','PACKAGE_CLOSURE',clone=>writeFileSync(resolve(clone,'extra.txt'),'x',{mode:0o644})],
  ['missing-authored','PACKAGE_CLOSURE',clone=>unlinkSync(resolve(clone,'README.md'))],
  ['file-mode','FILE_MODE',clone=>chmodSync(resolve(clone,'README.md'),0o600)],
  ['dir-mode','DIR_MODE',clone=>chmodSync(resolve(clone,'schemas'),0o700)],
  ['package-root-symlink','PACKAGE_CLOSURE',(clone,cleanup)=>{const link=`${clone}-link`;symlinkSync(clone,link,'dir');cleanup.push(link);return {packageRoot:link};}],
  ['authored-symlink','SPECIAL_FILE',clone=>{unlinkSync(resolve(clone,'README.md'));symlinkSync('COMMAND.txt',resolve(clone,'README.md'));}],
  ['hardlink','LINK',clone=>{unlinkSync(resolve(clone,'README.md'));linkSync(resolve(clone,'COMMAND.txt'),resolve(clone,'README.md'));}],
  ['unix-socket-special-file','SPECIAL_FILE',async clone=>{const socket=resolve(clone,'s');assert.equal(Buffer.byteLength(socket)<100,true,'Unix socket fixture path is below sun_path limit');rmSync(socket,{force:true});const server=net.createServer();await new Promise((done,reject)=>{server.once('error',reject);server.listen(socket,done);});return {after:()=>new Promise((done,reject)=>{if(!server.listening){rmSync(socket,{force:true});done();return;}server.close(error=>{rmSync(socket,{force:true});if(error)reject(error);else done();});})};},{shortPath:true}],
  ['traversal-locator','PATH',()=>({parse:['--mode','sealed','--review-anchor-root','/tmp','--review-anchor-locator','../anchor','--review-anchor-bytes','1','--review-anchor-raw-sha256','0'.repeat(64)]})],
  ['nfd-locator','PATH',()=>({parse:['--mode','sealed','--review-anchor-root','/tmp','--review-anchor-locator','e\u0301.json','--review-anchor-bytes','1','--review-anchor-raw-sha256','0'.repeat(64)]})],
  ['unsealed-unexpected-manifest','PACKAGE_CLOSURE',clone=>writeFileSync(resolve(clone,'MANIFEST.json'),'{}\n',{mode:0o644})],
  ['unsealed-unexpected-sums','PACKAGE_CLOSURE',clone=>writeFileSync(resolve(clone,'SHA256SUMS'),'x\n',{mode:0o644})],
  ['sealed-missing-manifest','PACKAGE_CLOSURE',clone=>{writeFileSync(resolve(clone,'SHA256SUMS'),'x\n',{mode:0o644});return {mode:'sealed',reviewAnchorPin:{}};}],
  ['sealed-missing-sums','PACKAGE_CLOSURE',clone=>{writeFileSync(resolve(clone,'MANIFEST.json'),'{}\n',{mode:0o644});return {mode:'sealed',reviewAnchorPin:{}};}],
  ['anchor-inside-package','ANCHOR_PIN',clone=>{const sealed=sealClone(clone);rmSync(sealed.anchorRoot,{recursive:true,force:true});const bytes=readFileSync(resolve(clone,'README.md'));return {mode:'sealed',reviewAnchorPin:{reviewAnchorRoot:clone,reviewAnchorLocator:'README.md',reviewAnchorBytes:bytes.length,reviewAnchorRawSha256:sha256(bytes)}};}],
  ['anchor-symlink','ANCHOR_PIN',(clone,cleanup)=>{const sealed=sealClone(clone);cleanup.push(sealed.anchorRoot);const link='anchor-link.json';symlinkSync(sealed.locator,resolve(sealed.anchorRoot,link));return {mode:'sealed',reviewAnchorPin:{...sealed.pin,reviewAnchorLocator:link}};}],
  ['anchor-hardlink','ANCHOR_PIN',(clone,cleanup)=>{const sealed=sealClone(clone);cleanup.push(sealed.anchorRoot);const link='anchor-hardlink.json';linkSync(resolve(sealed.anchorRoot,sealed.locator),resolve(sealed.anchorRoot,link));return {mode:'sealed',reviewAnchorPin:{...sealed.pin,reviewAnchorLocator:link}};}],
  ['stale-anchor-raw','ANCHOR_RAW',(clone,cleanup)=>{const sealed=sealClone(clone);cleanup.push(sealed.anchorRoot);return {mode:'sealed',reviewAnchorPin:{...sealed.pin,reviewAnchorRawSha256:'0'.repeat(64)}};}]
];
assert.equal(boundaryFixtures.length,18);
assert.equal(new Set(boundaryFixtures.map(([label])=>label)).size,18);

for(const [label,token,mutate,options={}] of boundaryFixtures)test(label,async()=>{
  await withClone(async(clone,cleanup)=>{
    const result=await mutate(clone,cleanup)??{};
    try{
      if(result.parse)expectToken(()=>parseValidationCliArgs(result.parse),token);
      else expectToken(()=>validateStatic({packageRoot:result.packageRoot??clone,mode:result.mode??'unsealed',reviewAnchorPin:result.reviewAnchorPin??null}),token);
    }finally{if(result.after)await result.after();}
  },options);
});

const goodHash='0'.repeat(64),base=['--mode','sealed','--review-anchor-root','/tmp','--review-anchor-locator','anchor.json','--review-anchor-bytes','1','--review-anchor-raw-sha256',goodHash];
const cliFixtures=[
  ['missing-mode',[],'PACKAGE_MODE'],
  ['duplicate-mode',['--mode','unsealed','--mode','unsealed'],'CLI_ARGS'],
  ['unknown-flag',['--wat','x'],'CLI_ARGS'],
  ['unsealed-with-anchor',['--mode','unsealed','--review-anchor-root','/tmp'],'CLI_ARGS'],
  ['sealed-missing-root',base.filter((_,i)=>!([2,3].includes(i))),'ANCHOR_REQUIRED'],
  ['sealed-missing-locator',base.filter((_,i)=>!([4,5].includes(i))),'ANCHOR_REQUIRED'],
  ['sealed-missing-bytes',base.filter((_,i)=>!([6,7].includes(i))),'ANCHOR_REQUIRED'],
  ['sealed-missing-raw',base.slice(0,-2),'ANCHOR_REQUIRED'],
  ['nonabsolute-root',base.map((x,i)=>i===3?'relative':x),'ANCHOR_PIN'],
  ['noncanonical-locator',base.map((x,i)=>i===5?'e\u0301.json':x),'PATH'],
  ['traversal-locator',base.map((x,i)=>i===5?'../anchor':x),'PATH'],
  ['nonpositive-bytes',base.map((x,i)=>i===7?'0':x),'ANCHOR_PIN'],
  ['nondecimal-bytes',base.map((x,i)=>i===7?'1x':x),'ANCHOR_PIN'],
  ['uppercase-hash',base.map((x,i)=>i===9?'A'.repeat(64):x),'ANCHOR_PIN'],
  ['wrong-length-hash',base.map((x,i)=>i===9?'0'.repeat(63):x),'ANCHOR_PIN'],
  ['extra-positional',[...base,'extra'],'CLI_ARGS']
];
test('exact 16 CLI causal fixtures',()=>{
  assert.equal(cliFixtures.length,16);
  assert.equal(new Set(cliFixtures.map(([label])=>label)).size,16);
  for(const [,argv,token] of cliFixtures)expectToken(()=>parseValidationCliArgs(argv),token);
});
test('CLI unsealed positive shape',()=>assert.deepEqual(parseValidationCliArgs(['--mode','unsealed']),{mode:'unsealed',reviewAnchorPin:null}));
