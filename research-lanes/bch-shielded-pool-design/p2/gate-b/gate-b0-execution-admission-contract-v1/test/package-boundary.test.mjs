import { chmodSync, cpSync, existsSync, linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { AUTHORED_FILES, SEALED_FILES, checkPackage, parseValidationCliArgs, safeExternalRead, validateStatic } from '../validate-static.mjs';

const here=dirname(fileURLToPath(import.meta.url));
const packageRoot=resolve(here,'..');
const repositoryRoot=resolve(packageRoot,'../../../../..');
const options=parseValidationCliArgs(process.argv.slice(2));
if(options.mode!=='sealed')throw new Error('PRODUCTION_SEALED_MODE_REQUIRED');
const expect=(name,run,prefix)=>{let error='';try{run();}catch(caught){error=String(caught.message);}if(!error.startsWith(prefix))throw new Error(`${name}: ${error}`);};
const copyPackage=target=>{mkdirSync(target,{recursive:true});for(const file of AUTHORED_FILES){const destination=resolve(target,file);mkdirSync(dirname(destination),{recursive:true});cpSync(resolve(packageRoot,file),destination);}};

if(!existsSync(resolve(packageRoot,'MANIFEST.json'))||!existsSync(resolve(packageRoot,'SHA256SUMS')))throw new Error('PRODUCTION_SEALED_ENVELOPES_REQUIRED');
checkPackage(packageRoot,options.mode);
const production=validateStatic({packageRoot,repositoryRoot,mode:options.mode,reviewAnchorPin:options.reviewAnchorPin});
if(production.files!==SEALED_FILES.length||production.unsealed||production.sourcePins!==64)throw new Error('PRODUCTION_SEALED_RESULT');
const temp=mkdtempSync(resolve(tmpdir(),'gb0eac-boundary-'));
let negativeCount=0;
let externalSafeWalkCount=0;
try{
  const clean=resolve(temp,'clean');copyPackage(clean);checkPackage(clean,'unsealed');const sourceClone=validateStatic({packageRoot:clean,repositoryRoot,mode:'unsealed'});if(sourceClone.files!==AUTHORED_FILES.length||!sourceClone.unsealed||sourceClone.sourcePins!==64)throw new Error('SOURCE_CLONE_UNSEALED_RESULT');
  const cases=[
    ['extra-file',work=>writeFileSync(resolve(work,'extra.txt'),'x'),'PACKAGE_CLOSURE:unsealed'],
    ['missing-file',work=>rmSync(resolve(work,'README.md')),'PACKAGE_CLOSURE:unsealed'],
    ['file-mode',work=>chmodSync(resolve(work,'README.md'),0o600),'PACKAGE_FILE:README.md'],
    ['file-symlink',work=>{rmSync(resolve(work,'README.md'));symlinkSync('COMMAND.txt',resolve(work,'README.md'));},'PACKAGE_LINK:README.md'],
    ['file-hardlink',work=>{rmSync(resolve(work,'README.md'));linkSync(resolve(work,'COMMAND.txt'),resolve(work,'README.md'));},'PACKAGE_FILE:'],
    ['dir-mode',work=>chmodSync(resolve(work,'schemas'),0o700),'DIRECTORY:schemas'],
    ['dir-symlink',work=>{rmSync(resolve(work,'schemas'),{recursive:true});symlinkSync('test',resolve(work,'schemas'));},'PACKAGE_LINK:schemas'],
    ['extra-empty-dir',work=>mkdirSync(resolve(work,'empty')),'PACKAGE_DIRECTORY_ROSTER'],
    ['nested-dir',work=>mkdirSync(resolve(work,'schemas','nested')),'PACKAGE_DIRECTORY_ROSTER'],
    ['embedded-anchor',work=>writeFileSync(resolve(work,'review-anchor.json'),'{}\n'),'PACKAGE_CLOSURE:unsealed'],
    ['partial-envelope',work=>writeFileSync(resolve(work,'MANIFEST.json'),'{}\n'),'PACKAGE_CLOSURE:unsealed'],
  ];
  for(const [name,mutate,prefix] of cases){const work=resolve(temp,name);cpSync(clean,work,{recursive:true});mutate(work);expect(`PACKAGE:${name}`,()=>checkPackage(work,'unsealed'),prefix);}
  const external=resolve(temp,'external');mkdirSync(resolve(external,'safe'),{recursive:true});const leaf=resolve(external,'safe','leaf');writeFileSync(leaf,'abc',{mode:0o644});const expected={bytes:3,rawSha256:'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'};if(!safeExternalRead(external,'safe/leaf',expected,'EXTERNAL_OK').equals(Buffer.from('abc')))throw new Error('EXTERNAL_OK');
  const externalCases=[
    ['traversal',()=>safeExternalRead(external,'../leaf',{bytes:3,rawSha256:expected.rawSha256},'EXTERNAL_TRAVERSAL'),'EXTERNAL_TRAVERSAL:LOCATOR:SEGMENT'],
    ['leaf-symlink',()=>{symlinkSync('leaf',resolve(external,'safe','link'));try{return safeExternalRead(external,'safe/link',expected,'EXTERNAL_LEAF_LINK');}finally{rmSync(resolve(external,'safe','link'));}},'EXTERNAL_LEAF_LINK:SYMLINK'],
    ['hardlink',()=>{linkSync(leaf,resolve(external,'safe','hard'));try{return safeExternalRead(external,'safe/hard',expected,'EXTERNAL_HARDLINK');}finally{rmSync(resolve(external,'safe','hard'));}},'EXTERNAL_HARDLINK:FILE'],
    ['mode',()=>{chmodSync(leaf,0o640);try{return safeExternalRead(external,'safe/leaf',expected,'EXTERNAL_MODE');}finally{chmodSync(leaf,0o644);}},'EXTERNAL_MODE:MODE'],
    ['raw',()=>safeExternalRead(external,'safe/leaf',{bytes:3,rawSha256:'0'.repeat(64)},'EXTERNAL_RAW'),'EXTERNAL_RAW:RAW'],
    ['ancestor-symlink',()=>{symlinkSync('safe',resolve(external,'ancestor'));try{return safeExternalRead(external,'ancestor/leaf',expected,'EXTERNAL_ANCESTOR_LINK');}finally{rmSync(resolve(external,'ancestor'));}},'EXTERNAL_ANCESTOR_LINK:SYMLINK'],
  ];
  for(const [name,run,prefix] of externalCases)expect(`EXTERNAL:${name}`,run,prefix);
  negativeCount=cases.length+externalCases.length;
  externalSafeWalkCount=externalCases.length;
  if(negativeCount!==17)throw new Error(`NEGATIVE_COUNT:${negativeCount}`);
}finally{rmSync(temp,{recursive:true,force:true});}
console.log(`PASS package-boundary production=sealed sourceClone=unsealed authored=${AUTHORED_FILES.length} dirs=3 negatives=${negativeCount} externalSafeWalk=${externalSafeWalkCount}`);
