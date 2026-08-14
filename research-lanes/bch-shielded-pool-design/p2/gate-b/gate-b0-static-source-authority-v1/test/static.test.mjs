import assert from 'node:assert/strict';
import test from 'node:test';
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseValidationCliArgs, validateStatic } from '../validate-static.mjs';

const packageRoot=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const envelopeLocators=['MANIFEST.json','SHA256SUMS'];
const sealedEnvironment=[
  ['--review-anchor-root','SSA_REVIEW_ANCHOR_ROOT'],
  ['--review-anchor-locator','SSA_REVIEW_ANCHOR_LOCATOR'],
  ['--review-anchor-bytes','SSA_REVIEW_ANCHOR_BYTES'],
  ['--review-anchor-raw-sha256','SSA_REVIEW_ANCHOR_RAW_SHA256'],
];
const lifecycleArgs=()=>{
  const present=envelopeLocators.map(locator=>existsSync(resolve(packageRoot,locator)));
  assert.equal(present[0],present[1],'MANIFEST.json and SHA256SUMS must be paired');
  if(!present[0])return ['--mode','unsealed'];
  const args=['--mode','sealed'];
  for(const [flag,name] of sealedEnvironment){const value=process.env[name];assert.ok(value,`sealed package validation requires external ${name}`);args.push(flag,value);}
  return args;
};

test('actual static package lifecycle validates without authority or evaluation',()=>{
  const options=parseValidationCliArgs(lifecycleArgs()),result=validateStatic({packageRoot,...options}),unsealed=options.mode==='unsealed';
  assert.deepEqual(result,{files:unsealed?24:26,rootDigest:result.rootDigest,sourceContracts:19,unsealed});
});

test('static package exports no runtime, endpoint, result-validator, authority, or instance constructors',async()=>{
  const mod=await import('../validate-static.mjs');
  assert.deepEqual(Object.keys(mod).sort(),['assertRootSemantics','canonicalJson','deriveSealEnvelope','digestRecord','fileDigestRecord','parseValidationCliArgs','validateStatic']);
});

test('static source boundary rejects a bare activation call without evaluating it',()=>{
  const temp=mkdtempSync(resolve(tmpdir(),'ssa-source-boundary-')),gate=resolve(temp,'gate-b'),candidate=resolve(gate,'gate-b0-static-source-authority-v1');
  try{
    mkdirSync(gate,{recursive:true});cpSync(packageRoot,candidate,{recursive:true});
    for(const locator of envelopeLocators)rmSync(resolve(candidate,locator),{force:true});
    const locator=resolve(candidate,'test/source-resolution.test.mjs'),bareCall=`${['ex','ec'].join('')}('x');`;
    writeFileSync(locator,`${readFileSync(locator,'utf8')}\n${bareCall}\n`);
    assert.throws(()=>validateStatic({mode:'unsealed',packageRoot:candidate}),error=>error instanceof Error&&error.message==='gate-b0-static-source-authority-v1:LOCAL_IMPORT_BOUNDARY');
  }finally{rmSync(temp,{recursive:true,force:true});}
});
