import { chmodSync, cpSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { AUTHORED_FILES, canonicalJson, componentDigest, deriveReviewAnchor, deriveSealEnvelope, safeExternalRead, sha256, validateStatic } from '../validate-static.mjs';

const here=dirname(fileURLToPath(import.meta.url));
const packageRoot=resolve(here,'..');
const repositoryRoot=resolve(packageRoot,'../../../../..');
const baseline=JSON.parse(readFileSync(resolve(packageRoot,'execution-admission-contract-root.v1.json'),'utf8'));
const clone=value=>JSON.parse(JSON.stringify(value));
const components=[['parentBinding','parent-binding'],['sourcePins','source-pins'],['historicalDisposition','historical-disposition'],['endpointProjectionContract','endpoint-projection-contract'],['externalRequirements','external-requirements'],['futureStateGrammar','future-state-grammar'],['futureArtifactMapContract','future-artifact-map-contract'],['futureResultAdmissionContract','future-result-admission-contract'],['crashRecoveryContract','crash-recovery-contract'],['nonAuthorityBoundary','nonauthority-boundary']];
const prefix='shieldkit-labs/p2/gate-b/gate-b0-execution-admission-contract/v1';
const refresh=value=>{value.componentDigests=components.map(([component,suffix])=>({component,digest:{algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain:`${prefix}/${suffix}`,frame:'utf8(domain)||0x00||canonical-json-utf8||0x0a',value:componentDigest(`${prefix}/${suffix}`,value[component])}}));const copy=clone(value);delete copy.contentDigest;value.contentDigest={algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain:`${prefix}/root`,frame:'utf8(domain)||0x00||canonical-json-utf8||0x0a',value:componentDigest(`${prefix}/root`,copy)};return value;};
const writeCanonical=(path,value)=>writeFileSync(path,`${canonicalJson(value)}\n`,{mode:0o644});
const copySource=target=>{mkdirSync(target,{recursive:true});for(const locator of AUTHORED_FILES){const destination=resolve(target,locator);mkdirSync(dirname(destination),{recursive:true});cpSync(resolve(packageRoot,locator),destination);}};
const seal=(target,root)=>{const envelope=deriveSealEnvelope(target);writeFileSync(resolve(target,'MANIFEST.json'),envelope.manifestBytes,{mode:0o644});writeFileSync(resolve(target,'SHA256SUMS'),envelope.sumsBytes,{mode:0o644});const outside=resolve(dirname(target),'outside');mkdirSync(outside,{recursive:true});const anchor=deriveReviewAnchor(target,envelope,root);const locator='review-anchor.json';const bytes=Buffer.from(`${canonicalJson(anchor)}\n`);writeFileSync(resolve(outside,locator),bytes,{mode:0o644});return {envelope,outside,locator,bytes,anchor,pin:{reviewAnchorRoot:outside,reviewAnchorLocator:locator,reviewAnchorBytes:bytes.length,reviewAnchorRawSha256:sha256(bytes)}};};
const rewriteAnchor=(fixture,transform)=>{const anchor=transform(clone(fixture.anchor));const bytes=Buffer.from(`${canonicalJson(anchor)}\n`);writeFileSync(resolve(fixture.outside,fixture.locator),bytes,{mode:0o644});fixture.anchor=anchor;fixture.bytes=bytes;fixture.pin.reviewAnchorBytes=bytes.length;fixture.pin.reviewAnchorRawSha256=sha256(bytes);};
const refreshSealedFixture=(fixture,target,semanticRoot,preserve={})=>{const envelope=deriveSealEnvelope(target);writeFileSync(resolve(target,'MANIFEST.json'),envelope.manifestBytes,{mode:0o644});writeFileSync(resolve(target,'SHA256SUMS'),envelope.sumsBytes,{mode:0o644});rewriteAnchor(fixture,()=>({...deriveReviewAnchor(target,envelope,semanticRoot),...preserve}));};
const expectError=(name,action,prefix,target=null)=>{let error='';try{action();}catch(caught){error=String(caught.message);}if(!error.startsWith(prefix)||(target!==null&&!error.includes(target)))throw new Error(`${name}: expected ${prefix}${target?` containing ${target}`:''}, got ${error}`);};
const mutateRoot=(root,fn)=>{fn(root);return refresh(root);};
const fullCase=(name,{expected,target=null,mutateRoot:rootMutation=null,mutateFiles=null,sealed=false,postSeal=null,pinMutation=null,preflight=null,direct=null})=>{
  const temp=mkdtempSync(resolve(tmpdir(),'gb0eac-mutation-'));
  try{
    if(expected==='ROOT_SCHEMA'&&target===null)throw new Error(`${name}: ROOT_SCHEMA target required`);
    if(preflight)preflight();
    if(direct){expectError(name,direct,expected,target);return;}
    const work=resolve(temp,'package');copySource(work);
    const root=clone(baseline);
    if(rootMutation)mutateRoot(root,rootMutation);
    writeCanonical(resolve(work,'execution-admission-contract-root.v1.json'),refresh(root));
    if(mutateFiles)mutateFiles(work,root);
    if(!sealed){expectError(name,()=>validateStatic({packageRoot:work,repositoryRoot,mode:'unsealed'}),expected,target);return;}
    const fixture=seal(work,root);
    if(postSeal)postSeal(work,fixture,root);
    const pin=pinMutation?pinMutation(fixture.pin,work,fixture):fixture.pin;
    expectError(name,()=>validateStatic({packageRoot:work,repositoryRoot,mode:'sealed',reviewAnchorPin:pin}),expected,target);
  }finally{rmSync(temp,{recursive:true,force:true});}
};
const cases=[];
const add=(name,config)=>cases.push([name,config]);

add('lifecycle-missing-authored',{expected:'PACKAGE_CLOSURE:unsealed',mutateFiles:work=>rmSync(resolve(work,'README.md'))});
add('lifecycle-extra-authored',{expected:'PACKAGE_CLOSURE:unsealed',mutateFiles:work=>writeFileSync(resolve(work,'extra.txt'),'x')});
add('lifecycle-envelope-unsealed',{expected:'PACKAGE_CLOSURE:unsealed',mutateFiles:work=>writeFileSync(resolve(work,'MANIFEST.json'),'{}\n')});
add('lifecycle-envelope-missing-sealed',{sealed:true,expected:'PACKAGE_CLOSURE:sealed',postSeal:work=>rmSync(resolve(work,'SHA256SUMS'))});
add('lifecycle-file-symlink',{expected:'PACKAGE_LINK:README.md',mutateFiles:work=>{rmSync(resolve(work,'README.md'));symlinkSync('COMMAND.txt',resolve(work,'README.md'));}});
add('lifecycle-file-hardlink',{expected:'PACKAGE_FILE:',mutateFiles:work=>{rmSync(resolve(work,'README.md'));linkSync(resolve(work,'COMMAND.txt'),resolve(work,'README.md'));}});
add('lifecycle-file-mode',{expected:'PACKAGE_FILE:README.md',mutateFiles:work=>chmodSync(resolve(work,'README.md'),0o600)});
add('lifecycle-dir-mode-or-extra-dir',{expected:'PACKAGE_DIRECTORY_ROSTER',mutateFiles:work=>mkdirSync(resolve(work,'empty'))});

add('anchor-root-raw',{sealed:true,expected:'SEALED_ANCHOR_ROOT_RAW',postSeal:(work,fixture,root)=>{const rootRawSha256=fixture.anchor.rootRawSha256;writeFileSync(resolve(work,'execution-admission-contract-root.v1.json'),'{}\n');refreshSealedFixture(fixture,work,root,{rootRawSha256});}});
add('anchor-root-semantic',{sealed:true,expected:'SEALED_ANCHOR_PARENT',mutateRoot:root=>{root.parentBinding.rootSemanticDigest='0'.repeat(64);}});
add('anchor-validator-raw',{sealed:true,expected:'SEALED_ANCHOR_VALIDATOR_RAW',postSeal:(work,fixture,root)=>{const validatorRawSha256=fixture.anchor.validatorRawSha256;writeFileSync(resolve(work,'validate-static.mjs'),`${readFileSync(resolve(work,'validate-static.mjs'),'utf8')}\n`);refreshSealedFixture(fixture,work,root,{validatorRawSha256});}});
add('anchor-manifest-raw',{sealed:true,expected:'SEALED_ANCHOR_MANIFEST_RAW',postSeal:work=>writeFileSync(resolve(work,'MANIFEST.json'),'{}\n')});
add('anchor-sums-raw',{sealed:true,expected:'SEALED_ANCHOR_SUMS_RAW',postSeal:work=>writeFileSync(resolve(work,'SHA256SUMS'),'x\n')});
add('anchor-caller-raw',{sealed:true,expected:'SEALED_ANCHOR_PIN:RAW',pinMutation:pin=>({...pin,reviewAnchorRawSha256:'0'.repeat(64)})});
add('anchor-inside-package',{sealed:true,expected:'SEALED_ANCHOR_INSIDE_PACKAGE',pinMutation:(pin,work)=>{const bytes=readFileSync(resolve(work,'MANIFEST.json'));return {reviewAnchorRoot:work,reviewAnchorLocator:'MANIFEST.json',reviewAnchorBytes:bytes.length,reviewAnchorRawSha256:sha256(bytes)};}});
add('anchor-ordered-closure-substitution',{sealed:true,expected:'SEALED_ANCHOR_ORDERED_CLOSURE',postSeal:(work,fixture)=>{const altered=clone(fixture.anchor);[altered.orderedClosure[0],altered.orderedClosure[1]]=[altered.orderedClosure[1],altered.orderedClosure[0]];const bytes=Buffer.from(`${canonicalJson(altered)}\n`);writeFileSync(resolve(fixture.outside,fixture.locator),bytes);fixture.pin.reviewAnchorBytes=bytes.length;fixture.pin.reviewAnchorRawSha256=sha256(bytes);}});

add('source-missing-row',{expected:'ROOT_SCHEMA',target:'data/sourcePins must NOT have fewer',mutateRoot:root=>root.sourcePins.pop()});
add('source-extra-row',{expected:'ROOT_SCHEMA',target:'data/sourcePins must NOT have more',mutateRoot:root=>root.sourcePins.push(clone(root.sourcePins[0]))});
add('source-reorder',{expected:'SOURCE_PIN_ID_ROSTER',mutateRoot:root=>root.sourcePins.reverse()});
add('source-duplicate-pin-id',{expected:'SOURCE_PIN_DUPLICATE',mutateRoot:root=>{root.sourcePins[1].pinId=root.sourcePins[0].pinId;}});
add('source-duplicate-locator',{expected:'SOURCE_PIN_DUPLICATE',mutateRoot:root=>{root.sourcePins[1].locator=root.sourcePins[0].locator;}});
add('source-bytes',{expected:'SOURCE_PIN_LITERAL_TABLE',mutateRoot:root=>{root.sourcePins[0].bytes+=1;}});
add('source-raw',{expected:'SOURCE_PIN_LITERAL_TABLE',mutateRoot:root=>{root.sourcePins[0].rawSha256='0'.repeat(64);}});
add('source-semantic',{expected:'SOURCE_PIN_LITERAL_TABLE',mutateRoot:root=>{root.sourcePins[0].semanticBindings[0].value='0'.repeat(64);}});
add('source-traversal',{expected:'SOURCE_PIN_LITERAL_TABLE',preflight:()=>expectError('source-traversal-safe-walker',()=>safeExternalRead(repositoryRoot,'../escape',{bytes:1,rawSha256:'0'.repeat(64)},'SOURCE_TRAVERSAL'),'SOURCE_TRAVERSAL:LOCATOR:SEGMENT'),mutateRoot:root=>{root.sourcePins[0].locator='research-lanes/bch-shielded-pool-design/spec/pool-config-fv1.json';}});
add('source-coordinated-leaf-pin-root',{expected:'SOURCE_PIN_LITERAL_TABLE',mutateRoot:root=>{root.sourcePins[0].bytes+=1;root.sourcePins[0].rawSha256='1'.repeat(64);}});

for(const [name,key,value] of [
  ['history-attempt000-current','attempt000','CURRENT_STATIC_RETRY_INTENT_TEMPLATE_NOT_AUTHORIZED_NOT_REQUESTED'],
  ['history-attempt000-reusable','attempt001Retry','STALE_CONSUMED_ABORTED_AUTHORITY_REUSABLE'],
  ['history-attempt000-evidence','v3','STALE_CONSUMED_ABORTED_AUTHORITY_EVIDENCE'],
])add(name,{expected:'ROOT_SCHEMA',target:`data/historicalDisposition/${key}`,mutateRoot:root=>{root.historicalDisposition[key]=value;}});
for(const [name,key] of [['history-retry-authorized','activationAllowed'],['history-automatic-retry','automaticRetryAllowed'],['history-stream-reuse','streamReuseAllowed'],['history-result-reuse','resultReuseAllowed'],['history-evidence-reuse','evidenceReuseAllowed']])add(name,{expected:'ROOT_SCHEMA',target:`data/futureStateGrammar/futureRetry/${key}`,mutateRoot:root=>{root.futureStateGrammar.futureRetry[key]=true;}});

add('projection-endpoint-omit',{expected:'ROOT_SCHEMA',target:'data/endpointProjectionContract/endpoints must NOT have fewer',mutateRoot:root=>root.endpointProjectionContract.endpoints.pop()});
add('projection-endpoint-insert',{expected:'ROOT_SCHEMA',target:'data/endpointProjectionContract/endpoints must NOT have more',mutateRoot:root=>root.endpointProjectionContract.endpoints.push(clone(root.endpointProjectionContract.endpoints[0]))});
add('projection-endpoint-reorder',{expected:'ENDPOINT_PROJECTION',mutateRoot:root=>root.endpointProjectionContract.endpoints.reverse()});
add('projection-endpoint-alias',{expected:'ENDPOINT_PROJECTION',mutateRoot:root=>{root.endpointProjectionContract.endpoints[1].alias=root.endpointProjectionContract.endpoints[0].alias;}});
add('projection-frozen-role',{expected:'ENDPOINT_PROJECTION',mutateRoot:root=>{root.endpointProjectionContract.endpoints[0].frozenRole='engine:libauth';}});
for(const [name,key,value] of [['projection-4732-launched','frozenFixtureRows',4733],['projection-4607','rowsPerEndpoint',4607],['projection-4609','rowsPerEndpoint',4609],['projection-preflight-launch','launchAuthorityRows',6],['projection-lean-collapse','leanPairComparisonRoles',0],['projection-lean-double-weight','legacyEngineRoles',5]])add(name,{expected:'ROOT_SCHEMA',target:`data/endpointProjectionContract/${key}`,mutateRoot:root=>{root.endpointProjectionContract[key]=value;}});
add('projection-4608-as-worker-row-count',{expected:'ROOT_SCHEMA',target:'data/futureStateGrammar/futureD/workerRowCount',mutateRoot:root=>{root.futureStateGrammar.futureD.workerRowCount=4608;}});

add('requirements-omit',{expected:'ROOT_SCHEMA',target:'data/externalRequirements must NOT have fewer',mutateRoot:root=>root.externalRequirements.pop()});
add('requirements-insert',{expected:'ROOT_SCHEMA',target:'data/externalRequirements must NOT have more',mutateRoot:root=>root.externalRequirements.push(clone(root.externalRequirements[0]))});
add('requirements-reorder',{expected:'EXTERNAL_REQUIREMENT_ROSTER',mutateRoot:root=>root.externalRequirements.reverse()});
add('requirements-instance',{expected:'ROOT_SCHEMA',target:'data/externalRequirements/0/instanceCount',mutateRoot:root=>{root.externalRequirements[0].instanceCount=1;}});
add('requirements-grant',{expected:'ROOT_SCHEMA',target:'data/externalRequirements/0/authorityGranted',mutateRoot:root=>{root.externalRequirements[0].authorityGranted=true;}});
add('requirements-admission',{expected:'ROOT_SCHEMA',target:'data/externalRequirements/0/admissionGranted',mutateRoot:root=>{root.externalRequirements[0].admissionGranted=true;}});
add('requirements-null-disposition',{expected:'ROOT_SCHEMA',target:'data/externalRequirements/0/disposition',mutateRoot:root=>{root.externalRequirements[0].disposition=null;}});
add('requirements-catalog-digest-as-root',{expected:'ROOT_SCHEMA',target:'data/externalRequirements/0/sourceContractRef',mutateRoot:root=>{root.externalRequirements[0].sourceContractRef='catalog-digest-as-root';}});
add('dag-edge-omit',{expected:'ROOT_SCHEMA',target:'data/futureStateGrammar/edges must NOT have fewer',mutateRoot:root=>root.futureStateGrammar.edges.pop()});
add('dag-edge-insert',{expected:'ROOT_SCHEMA',target:'data/futureStateGrammar/edges must NOT have more',mutateRoot:root=>root.futureStateGrammar.edges.push(clone(root.futureStateGrammar.edges[0]))});
add('dag-edge-reorder',{expected:'RETRY_EDGE_ROSTER',mutateRoot:root=>root.futureStateGrammar.edges.reverse()});
add('dag-cycle',{expected:'RETRY_EDGE_ROSTER',mutateRoot:root=>{root.futureStateGrammar.edges[0]={from:'D_PROVIDER',to:'B_PROVIDER'};}});
add('dag-b-preimage-substitution',{expected:'ROOT_SCHEMA',target:'data/futureStateGrammar/futureB/subjectPreimageOrder',mutateRoot:root=>{root.futureStateGrammar.futureB.subjectPreimageOrder[0]='kPackageRoot';}});
add('dag-d-predecessor-omission',{expected:'ROOT_SCHEMA',target:'data/futureStateGrammar/futureD/predecessorOrder',mutateRoot:root=>root.futureStateGrammar.futureD.predecessorOrder.pop()});

for(const [name,section,key,value,expected] of [
  ['artifact-authority','futureArtifactMapContract','authorityCreationAllowed',true,'ROOT_SCHEMA'],
  ['artifact-map-instance','futureArtifactMapContract','instanceCount',1,'ROOT_SCHEMA'],
  ['artifact-self-attest','futureArtifactMapContract','selfAttestedMapAccepted',true,'ROOT_SCHEMA'],
  ['artifact-result-derived','futureArtifactMapContract','resultDerivedAuthorityAccepted',true,'ROOT_SCHEMA'],
  ['result-partial','futureResultAdmissionContract','partialResultsAccepted',true,'ROOT_SCHEMA'],
  ['result-incomplete-count','futureResultAdmissionContract','requiredRawEndpointRows',1,'ROOT_SCHEMA'],
  ['crash-reuse','crashRecoveryContract','afterCReuseAllowed',true,'ROOT_SCHEMA'],
  ['result-fallback','futureResultAdmissionContract','fallbackAccepted',true,'ROOT_SCHEMA'],
])add(name,{expected,target:`data/${section}/${key}`,mutateRoot:root=>{root[section][key]=value;}});

for(const [name,section,key,value,expected] of [
  ['boundary-top-execution','root','executionAllowed',true,'ROOT_SCHEMA'],
  ['boundary-true-measurement','root','measurementAdmissionAllowed',true,'ROOT_SCHEMA'],
  ['boundary-nonzero-instance','nonAuthorityBoundary','providerInstanceCount',1,'ROOT_SCHEMA'],
  ['boundary-runtime-module','runtimeBoundary','runtimeModules',['runtime.mjs'],'ROOT_SCHEMA'],
])add(name,{expected,target:section==='root'?`data/${key}`:`data/${section}/${key}`,mutateRoot:root=>{if(section==='root')root[key]=value;else root[section][key]=value;}});

if(cases.length!==72)throw new Error(`MUTATION_CASE_ROSTER:${cases.length}`);
for(const [name,config] of cases)fullCase(name,config);
console.log(`PASS mutation negatives=${cases.length} fullValidation=72 groups=8+8+10+8+12+14+8+4`);
