import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = JSON.parse(readFileSync(resolve(here,'../static-source-authority-root.v1.json')));
const SOURCE_KINDS = Object.freeze(["UPSTREAM_OWNER_CONTRACT_SCHEMA","RETRY_TARGET_SOURCE_SCHEMA","RETRY_TERMINAL_PREDECESSOR_SOURCE_SCHEMA","LIVE_F_PRIVATE_CAPTURE_SOURCE_SCHEMA","ENDPOINT_BYTE_AUTHORITY_SOURCE_SCHEMA","ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA","PRIVATE_DISPATCH_PLAN_SOURCE_SCHEMA","WORKER_ROWS_OWNER_BINDING_SOURCE_SCHEMA","WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE","WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE","WORKLOAD_ROOT_SOURCE_SCHEMA","OWNER_BOUND_A_FACT_SOURCE_SCHEMA","OWNER_BOUND_B_FACT_SOURCE_SCHEMA","OWNER_BOUND_C_FACT_SOURCE_SCHEMA","OWNER_BOUND_D_FACT_SOURCE_SCHEMA","OWNER_BOUND_LIVE_F_FACT_SOURCE_SCHEMA","OWNER_BOUND_Q_FACT_SOURCE_SCHEMA"]);
const REQUIREMENT_IDS = Object.freeze(["RECOVERY_CHAIN_OWNER_PROVIDER","REQUEST_OWNER_PROVIDER","ACTIVATION_OWNER_PROVIDER","PRIVATE_CAPTURE_OWNER_PROVIDER","PRIVATE_DESCRIPTOR_OWNER_PROVIDER","EXCLUSIVE_C_OWNER_PROVIDER","PRIVATE_DISPATCH_OWNER_PROVIDER","RETRY_ORDER_PROVIDER","LIVE_F_RECORD_ORDER_PROVIDER","FROZEN_SURFACE_ORDER_PROVIDER","ENDPOINT_CONTROL_ORDER_PROVIDER","WORKLOAD_ROOT_ORDER_PROVIDER","WORKLOAD_PROJECTION_PROVIDER","ENDPOINT_BYTE_AUTHORITY_PROVIDER","RETRY_PREDECESSOR_PROVIDER","LIVE_F_CAPTURE_PROVIDER","WORKER_ROWS_ROOT_PROVIDER","Q_INITIAL_PROVIDER","Q_RETRY_PROVIDER","Q_ABORT_PROVIDER","A_INITIAL_PROVIDER","A_RETRY_PROVIDER","A_ABORT_PROVIDER","LIVE_F_PROVIDER","B_SUBJECT_ROOT_TYPE","B_PROVIDER","C_PROVIDER","J_ROOT_TYPE","DISPATCH_PLAN_PROVIDER","D_PROVIDER"]);

test('exact static source-resolution rosters remain non-authorizing', () => {
  const records=[...root.ownerContractSourceCatalog.entries,...root.retryLineageSourceCatalog.entries,...root.privateCaptureSourceCatalog.entries,...root.workloadProjectionSourceCatalog.entries,...root.stateFactSourceCatalog.entries];
  assert.deepEqual(records.map(row=>row.sourceKind),SOURCE_KINDS);
  assert.deepEqual([root.ownerContractSourceCatalog.entryCount,root.retryLineageSourceCatalog.entryCount,root.privateCaptureSourceCatalog.entryCount,root.workloadProjectionSourceCatalog.entryCount,root.stateFactSourceCatalog.entryCount],[1,2,1,7,6]);
  assert.equal(records.length+root.supplementalContracts.length,19);
  assert.deepEqual(root.requirementResolutions.map(row=>row.requirementId),REQUIREMENT_IDS);
  const counts=Object.fromEntries(['STATIC_SOURCE','FUTURE_INSTANCE','TYPE_ONLY','DERIVED'].map(kind=>[kind,root.requirementResolutions.filter(row=>row.classification===kind).length]));
  assert.deepEqual(counts,{STATIC_SOURCE:11,FUTURE_INSTANCE:4,TYPE_ONLY:6,DERIVED:9});
  for(const row of [...records,...root.requirementResolutions]){assert.equal(row.authorityGranted,false);assert.equal(row.admissionGranted,false);assert.equal(row.instanceCount,0);}
  assert.deepEqual(root.supplementalContracts.map(row=>row.contractId),['RAW_ARTIFACT_MAP_AUTHORITY_SOURCE_CONTRACT','INDEPENDENT_RESULT_VALIDATOR_SOURCE_CONTRACT']);
  assert.equal(root.nonAuthorityBoundary.sourceContractCount,19);assert.equal(root.nonAuthorityBoundary.requirementResolutionCount,30);
});

test('requirement predecessors retain exact 37-edge EAC containment and supplemental edges stay symbolic', () => {
  const edges=root.requirementResolutions.flatMap(row=>row.predecessorNodeIds.map(from=>[from,row.requirementId]));assert.equal(edges.length,37);
  assert.deepEqual(root.supplementalContracts[0].mustPrecedeFutureNodes,['Q_RETRY_PROVIDER','WORKLOAD_PROJECTION_PROVIDER','RAW_ARTIFACT_MAP_INSTANCE']);
  assert.deepEqual(root.supplementalContracts[1].mustPrecedeFutureNodes,['RESULT_ADMISSION']);
  assert.equal(JSON.stringify(root).includes('runtimeStateDefinition'),false);
});
