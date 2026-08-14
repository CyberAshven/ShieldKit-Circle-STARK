import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { AUTHORED_FILES, assertRequirementJoins, assertSourceCollision, canonicalJson, digestRecord, validateStatic } from '../validate-static.mjs';

const root=JSON.parse(readFileSync(new URL('../external-authority-prerequisite-policy-root.v1.json',import.meta.url)));
const gateRoot=resolve(new URL('../../',import.meta.url).pathname);
const uopc=JSON.parse(readFileSync(resolve(gateRoot,'cohort-upstream-origin-provider-contract-v1/upstream-origin-provider-contract-root.v1.json')));
const eac=JSON.parse(readFileSync(resolve(gateRoot,'gate-b0-execution-admission-contract-v1/execution-admission-contract-root.v1.json')));
const ssa=JSON.parse(readFileSync(resolve(gateRoot,'gate-b0-static-source-authority-v1/static-source-authority-root.v1.json')));
const spm=JSON.parse(readFileSync(resolve(gateRoot,'cohort-upstream-provider-source-map-v1/upstream-provider-source-map-root.v1.json')));
const exact=(token)=>error=>error instanceof Error&&error.message===`EAPP_${token}`;
const withSourceClone=(mutate,token)=>{const packageRoot=mkdtempSync(resolve(gateRoot,'.eapp-collision-'));chmodSync(packageRoot,0o755);mkdirSync(resolve(packageRoot,'schemas'),{mode:0o755});mkdirSync(resolve(packageRoot,'test'),{mode:0o755});try{for(const locator of AUTHORED_FILES){copyFileSync(new URL(`../${locator}`,import.meta.url),resolve(packageRoot,locator));chmodSync(resolve(packageRoot,locator),0o644);}const cloned=structuredClone(root);mutate(cloned);const entry=cloned.sourceCollisions.entries[0];if(entry){const body={...entry};delete body.contentDigest;entry.contentDigest=digestRecord('shieldkit-labs/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1/source-collision/UOPC_EAC_FUTURE_PROVIDER_DAG_DIVERGENCE',body);}const collisionBody={...cloned.sourceCollisions};delete collisionBody.contentDigest;cloned.sourceCollisions.contentDigest=digestRecord('shieldkit-labs/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1/source-collisions',collisionBody);cloned.componentDigests=cloned.componentDigests.map(row=>row.component==='sourceCollisions'?{component:'sourceCollisions',digest:digestRecord('shieldkit-labs/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1/source-collisions',cloned.sourceCollisions)}:row);const rootBody={...cloned};delete rootBody.contentDigest;cloned.contentDigest=digestRecord('shieldkit-labs/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1/root',rootBody);writeFileSync(resolve(packageRoot,'external-authority-prerequisite-policy-root.v1.json'),`${canonicalJson(cloned)}\n`,{mode:0o644});assert.throws(()=>validateStatic({packageRoot,mode:'unsealed'}),exact(token));}finally{rmSync(packageRoot,{recursive:true,force:true});}};

test('exact collision source intersection and differences',()=>assert.equal(assertSourceCollision({},root,uopc,eac).counts,'40/37/33/7/4'));
test('selectedDag mutation rejected through source clone',()=>withSourceClone(value=>{value.sourceCollisions.entries[0].selectedDag='UOPC';},'COLLISION_SELECTION'));
test('UOPC-only edge omission rejected through source clone',()=>withSourceClone(value=>{value.sourceCollisions.entries[0].uopcOnlyEdges.pop();},'COLLISION_EDGES'));
test('EAC-only edge omission rejected through source clone',()=>withSourceClone(value=>{value.sourceCollisions.entries[0].eacOnlyEdges.pop();},'COLLISION_EDGES'));
test('exact J derived mapping normalization rejects isolated source-map mutations',()=>{
  const cases=[
    ['interface-ids',value=>{value.interfaceSourceMap.entries[14].interfaceIds=['MUTANT'];},'J_ROOT_TYPE:interface-ids'],
    ['incoming-b',value=>{value.mappingDag.edges=value.mappingDag.edges.filter(edge=>edge!=='B_MAP→J_MAP');},'J_ROOT_TYPE:incoming-map-edges'],
    ['incoming-c',value=>{value.mappingDag.edges=value.mappingDag.edges.filter(edge=>edge!=='C_MAP→J_MAP');},'J_ROOT_TYPE:incoming-map-edges'],
    ['outgoing-d',value=>{value.mappingDag.edges=value.mappingDag.edges.filter(edge=>edge!=='J_MAP→D_MAP');},'J_ROOT_TYPE:outgoing-map-edges']
  ];
  for(const [label,mutate,detail] of cases){const isolated=structuredClone(spm);mutate(isolated);assert.throws(()=>assertRequirementJoins({root,ssa,eac,uopc,spm:isolated}),error=>error instanceof Error&&error.message===`EAPP_REQUIREMENT_JOIN:${detail}`,label);}
});
