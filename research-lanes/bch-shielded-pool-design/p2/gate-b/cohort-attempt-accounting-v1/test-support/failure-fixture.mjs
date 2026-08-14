import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {digestRecord} from '../validator.mjs';

const here=path.dirname(new URL(import.meta.url).pathname);
export const packageRoot=path.resolve(here,'..');
export const repo=path.resolve(packageRoot,'../../../../../');
export const specs=[['engine:native',0,'primary','module-ndjson'],['engine:libauth',1,'primary','module-ndjson'],['engine:bchn',2,'primary','external-process'],['engine:leanbch',3,'primary','external-process'],['engine:leanbch',3,'secondary','external-process']];
export const endpointOrder=specs.map(([id,,role])=>`${id}/${role}`);
export const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const omit=x=>Object.fromEntries(Object.entries(x).filter(([k])=>k!=='contentDigest'));
const sort=(a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b));
const canonicalize=value=>Array.isArray(value)?value.map(canonicalize):(value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonicalize(value[key])])):value);
const canonicalBytes=value=>Buffer.from(`${JSON.stringify(canonicalize(value),null,2)}\n`,'utf8');
export const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
export const write=(p,x)=>{fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,Buffer.isBuffer(x)?x:`${JSON.stringify(x,null,2)}\n`)};
export const redigest=(x,domain)=>{x.contentDigest=digestRecord(domain,omit(x));return x};
export const rel=p=>path.relative(repo,p);
export const bindJson=p=>{const b=fs.readFileSync(p),x=read(p);return {path:rel(p),rawSha256:sha(b),contentDigest:x.contentDigest}};
export const opaque=p=>({path:path.isAbsolute(p)?p:rel(p),rawSha256:sha(fs.readFileSync(p))});
export const endpointFile=(f,i)=>{const [id,,role]=specs[i];return path.join(f.root,`endpoints/${String(i).padStart(2,'0')}-${id.slice(7)}-${role}.endpoint.v1.json`)};
const empty=Buffer.alloc(0);
const rawEmpty=sha(empty);
function stream(root,index,id,role,streamRole,bytes,captureStatus='complete',lineAligned=true){
  if(captureStatus==='unavailable')return {streamRole,path:null,byteLength:null,rawSha256:null,captureStatus,lineAligned:false,fsynced:false};
  const p=`streams/${String(index).padStart(2,'0')}-${id.slice(7)}-${role}.${streamRole}.bin`;write(path.join(root,p),bytes);return {streamRole,path:p,byteLength:bytes.length,rawSha256:sha(bytes),captureStatus,lineAligned,fsynced:true};
}
function modulePrefix(bytes){
  const last=bytes.lastIndexOf(0x0a),prefix=last<0?empty:bytes.subarray(0,last+1),trailing=last<0?bytes:bytes.subarray(last+1);
  const n=prefix.length?prefix.toString('utf8').slice(0,-1).split('\n').length:0;
  return {byteLength:prefix.length,rawSha256:sha(prefix),completedRowCount:n,trailingFragmentByteLength:trailing.length,trailingFragmentRawSha256:sha(trailing)};
}
function lifecycle(kind,closure){
  const base={kind,spawnAttempted:false,spawnSucceeded:false,startObserved:false,exitEventObserved:false,closeEventObserved:false,stdoutEndObserved:false,stderrEndObserved:false,observedExitCode:null,observedSignal:null,killAttempts:[],capExceeded:false,spawnError:null,stdinWriteError:null,transportError:null,controllerError:null,streamsFsynced:false,terminationKind:closure,invocationStarted:false,returned:false,threw:false,moduleErrorClass:null,moduleErrorMessageDigest:null,captureClosed:false};
  if(closure==='not-started')return base;
  if(kind==='module-ndjson'){Object.assign(base,{invocationStarted:true,captureClosed:true,streamsFsynced:true,returned:closure!=='module-error',threw:closure==='module-error'});if(closure==='module-error'){base.moduleErrorClass='SyntheticError';base.moduleErrorMessageDigest=sha(Buffer.from('synthetic'))}return base}
  Object.assign(base,{spawnAttempted:true,spawnSucceeded:true,startObserved:true,invocationStarted:true,exitEventObserved:true,closeEventObserved:true,stdoutEndObserved:true,stderrEndObserved:true,streamsFsynced:true,captureClosed:true});
  if(closure==='exit'||closure==='parser-after-complete')base.observedExitCode=0;
  if(closure==='timeout'){Object.assign(base,{observedExitCode:0,killAttempts:[kill('timeout')]})}
  if(closure==='capture-limit'){Object.assign(base,{observedSignal:'SIGTERM',killAttempts:[kill('capture-limit')],capExceeded:true})}
  if(closure==='signal')base.observedSignal='SIGHUP';
  if(closure==='executor-abort'){Object.assign(base,{observedExitCode:0,killAttempts:[kill('executor-abort')],controllerError:{name:'SyntheticControllerError',code:'EIO',messageRawSha256:sha(Buffer.from('synthetic controller error'))}})}
  if(closure==='spawn-error'){Object.assign(base,{spawnSucceeded:false,startObserved:false,invocationStarted:false,exitEventObserved:false,closeEventObserved:false,stdoutEndObserved:false,stderrEndObserved:false,streamsFsynced:false,captureClosed:false,spawnError:{name:'Error',code:'ENOENT',messageRawSha256:sha(Buffer.from('synthetic spawn error'))}})}
  return base;
}
function returned(value){return {kind:'returned',value,error:null}}
function threw(code='ESYNTHETIC'){return {kind:'threw',value:null,error:{name:'SyntheticDispatchError',code,messageRawSha256:sha(Buffer.from(`synthetic dispatch ${code}`))}}}
function kill(reason,ordinal=0,dispatchResult=returned(true),requestedAtMonotonicNanoseconds=ordinal===0?'10000000000':'15000000000'){
  return {ordinal,reason,signal:ordinal===0?'SIGTERM':'SIGKILL',graceMilliseconds:ordinal===0?5000:0,requestedAtMonotonicNanoseconds,closeObservedBeforeRequest:false,dispatchResult};
}
export const controllerKill=kill;
export const dispatchReturned=returned;
export const dispatchThrew=threw;
function outcome(kind,closure){
  const none={observedExitCode:null,observedSignal:null,observedCloseAtMonotonicNanoseconds:null,observedOutcomeAttribution:null,terminalClosure:closure};
  if(closure==='not-started'||kind==='module-ndjson'||closure==='spawn-error'||closure==='abrupt-unobserved')return none;
  if(closure==='exit'||closure==='parser-after-complete')return {...none,observedExitCode:0,observedCloseAtMonotonicNanoseconds:'20000000000'};
  if(closure==='timeout')return {...none,observedExitCode:0,observedCloseAtMonotonicNanoseconds:'12000000000',observedOutcomeAttribution:'not-attributed-to-requested-signal'};
  if(closure==='capture-limit')return {...none,observedSignal:'SIGTERM',observedCloseAtMonotonicNanoseconds:'12000000000',observedOutcomeAttribution:'not-attributed-to-requested-signal'};
  if(closure==='signal')return {...none,observedSignal:'SIGHUP',observedCloseAtMonotonicNanoseconds:'20000000000'};
  if(closure==='executor-abort')return {...none,observedExitCode:0,observedCloseAtMonotonicNanoseconds:'12000000000',observedOutcomeAttribution:'not-attributed-to-requested-signal'};
  return none;
}
function endpoint(root,i,invocation,started,closure,bytes=empty,capture='complete'){
  const [engineId,engineOrdinal,endpointRole,endpointKind]=specs[i];const streams=started?[stream(root,i,engineId,endpointRole,'stdin',empty),stream(root,i,engineId,endpointRole,'stdout',bytes,capture,endpointKind==='module-ndjson'&&capture==='complete'),stream(root,i,engineId,endpointRole,'stderr',empty)]:[];
  const x={schema:'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/endpoint-stream-binding/v1',attemptIndex:1,engineId,engineOrdinal,endpointRole,endpointKind,invocation,status:started?'started':'not-started',outcome:outcome(endpointKind,closure),lifecycle:lifecycle(endpointKind,closure),streams,combinedOutputBytes:started?bytes.length:0,fsyncOnClose:started&&closure!=='spawn-error',moduleNdjsonPrefix:started&&endpointKind==='module-ndjson'?modulePrefix(bytes):null,rowPrefixCardinality:started&&endpointKind==='module-ndjson'?modulePrefix(bytes).completedRowCount:0,fsyncPerCompletedRow:started&&endpointKind==='module-ndjson'};
  redigest(x,`shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/endpoint/attempt-001/${engineId}/${endpointRole}`);write(endpointFile({root},i),x);return x;
}
export function buildFailureFixture(){
  const parent=fs.mkdtempSync(path.join(repo,'.failure-test-')),root=path.join(parent,'cohort-executor-v3/runs/attempt-001/failure'),success=path.join(parent,'cohort-executor-v3/runs/attempt-001/success');fs.mkdirSync(root,{recursive:true});
  const docs=path.join(parent,'authority'),authPath=path.join(docs,'authorization.v3.json'),contractPath=path.join(docs,'contract.v3.json'),claimPath=path.join(docs,'execution-claim.v3.json');
  const auth={schema:'shieldkit-labs/p2/gate-b/cohort-executor-v3/authorization/v3',outputPaths:{failureRoot:root,successRoot:success}};redigest(auth,'shieldkit-labs/p2/gate-b/cohort-executor-v3/authorization/v3/root');write(authPath,auth);
  const contract={schema:'shieldkit-labs/p2/gate-b/cohort-execution-v3/execution-contract/v3',contractId:'synthetic'};redigest(contract,'shieldkit-labs/p2/gate-b/cohort-execution-v3/contract/v3/root');write(contractPath,contract);
  const claim={schema:'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3',claimId:'synthetic-claim'};redigest(claim,'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3/root');write(claimPath,canonicalBytes(claim));write(path.join(root,'execution-claim.json'),fs.readFileSync(claimPath));
  const engineDir=path.join(repo,'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engines'),engines=['native','libauth','bchn','leanbch'].map(n=>read(path.join(engineDir,`${n}.v2.json`)));const invocations=specs.map((s,i)=>{const e=engines[s[1]],entry=i===4?e.secondaryEntrypoints[0]:e.entrypoint;return {argv:entry.argv,cwd:repo,environment:{},runtime:{executable:'synthetic-node',version:'synthetic',platform:'linux',arch:'x64'},engineBinding:bindJson(path.join(engineDir,`${s[0].slice(7)}.v2.json`)),entrypointBinding:opaque(entry.file.realpath),entrypointKind:entry.kind}});
  const authority={attemptIndex:1,authorization:bindJson(authPath),claim:bindJson(claimPath),contract:bindJson(contractPath),epoch:bindJson(path.join(repo,'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/execution-epoch.v2.json')),retry:bindJson(path.join(repo,'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-retry-v1/attempt-001.retry-wrapper.v1.json')),outputPaths:{failureRoot:root,successRoot:success},limits:{externalCombinedOutputBytes:134217728,leanAggregateDeadlineMilliseconds:600000,terminationGraceMilliseconds:5000},endpoints:specs.map(([engineId,engineOrdinal,endpointRole,endpointKind],i)=>({engineId,engineOrdinal,endpointRole,endpointKind,expectedRowCount:4608,invocation:invocations[i]}))};
  const rows=Buffer.from(Array.from({length:4608},(_,i)=>`{"row":${i}}\n`).join(''));const endpoints=[endpoint(root,0,invocations[0],true,'module-complete',rows),endpoint(root,1,invocations[1],true,'module-complete',rows),endpoint(root,2,invocations[2],true,'timeout',Buffer.from([0xff,0x00,0x0a]),'partial'),endpoint(root,3,invocations[3],false,'not-started'),endpoint(root,4,invocations[4],false,'not-started')];
  const states=specs.map(([engineId,engineOrdinal,endpointRole],i)=>({causalOrdinal:i,engineId,engineOrdinal,endpointRole,state:i<2?'complete-captured-unpublished':i===2?'incomplete':'not-started',basis:i<2?'durable-capture':i===2?'durable-endpoint-outcome':'control-flow-inference',failureStage:i===2?'timeout':null,endpointObservedExitCode:i===2?0:null,streams:null,observations:null,verdicts:null,metrics:null,agreementEligible:false,reusable:false}));
  const causal={schema:'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/causal-batch-state/v1',attemptIndex:1,engineOrder:['engine:native','engine:libauth','engine:bchn','engine:leanbch'],states,agreementEligible:false,reusable:false,normalized:null,crossEngine:null,ranking:null,selection:null,status:'failure-causal-record-only'};redigest(causal,'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/causal/attempt-001');write(path.join(root,'causal-batch-state.v1.json'),causal);
  const claimCopy={path:'execution-claim.json',rawSha256:sha(fs.readFileSync(path.join(root,'execution-claim.json'))),contentDigest:read(path.join(root,'execution-claim.json')).contentDigest};const receipt={schema:'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-receipt/v1',receiptId:'failure-receipt:execution-epoch-gate-b-v2:attempt-001:v1',attemptIndex:1,status:'incomplete',authorizationBinding:authority.authorization,contractBinding:authority.contract,epochBinding:authority.epoch,retryBinding:authority.retry,claimBinding:claimCopy,endpointOrder,endpoints,causalStates:states,observedExitCode:0,observedSignal:null,observedCloseAtMonotonicNanoseconds:'12000000000',observedOutcomeAttribution:'not-attributed-to-requested-signal',terminalClosure:'timeout',cap:{maxBytesPerExternalEndpoint:134217728,leanAggregateDeadlineMilliseconds:600000,terminationGraceMilliseconds:5000,externalEndpointObservedBytes:[2,3,4].map(i=>({endpoint:endpointOrder[i],byteLength:endpoints[i].combinedOutputBytes})),leanAggregateObservedMilliseconds:0},parser:{status:'not-reached',stage:'none',error:null},agreementEligible:false,reusableByLaterAttempt:false,normalized:null,crossEngine:null,ranking:null,selection:null};redigest(receipt,'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-receipt/attempt-001');write(path.join(root,'failure-receipt.v1.json'),receipt);
  const f={parent,root,authority};resealFailureFixture(f);return f;
}
export function resealFailureFixture(f){
  const endpoints=specs.map(([id,,role],i)=>{const p=endpointFile(f,i),x=read(p);redigest(x,`shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/endpoint/attempt-001/${id}/${role}`);write(p,x);return x});
  const causal=read(path.join(f.root,'causal-batch-state.v1.json'));redigest(causal,'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/causal/attempt-001');write(path.join(f.root,'causal-batch-state.v1.json'),causal);const terminal=causal.states.find(x=>x.state==='failed'||x.state==='incomplete'),te=endpoints[terminal.causalOrdinal];
  const claimCopy={path:'execution-claim.json',rawSha256:sha(fs.readFileSync(path.join(f.root,'execution-claim.json'))),contentDigest:read(path.join(f.root,'execution-claim.json')).contentDigest};const receiptPath=path.join(f.root,'failure-receipt.v1.json'),receipt=read(receiptPath);Object.assign(receipt,{endpoints,causalStates:causal.states,status:terminal.state,claimBinding:claimCopy,observedExitCode:te.outcome.observedExitCode,observedSignal:te.outcome.observedSignal,observedCloseAtMonotonicNanoseconds:te.outcome.observedCloseAtMonotonicNanoseconds,observedOutcomeAttribution:te.outcome.observedOutcomeAttribution,terminalClosure:te.outcome.terminalClosure});receipt.cap.externalEndpointObservedBytes=[2,3,4].map(i=>({endpoint:endpointOrder[i],byteLength:endpoints[i].combinedOutputBytes}));redigest(receipt,'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-receipt/attempt-001');write(receiptPath,receipt);
  const inventory=endpoints.flatMap((e,i)=>e.streams.map(s=>({...s,engineId:specs[i][0],engineOrdinal:specs[i][1],endpointRole:specs[i][2]})));const filePaths=['causal-batch-state.v1.json','execution-claim.json','failure-receipt.v1.json',...endpoints.map((e,i)=>path.relative(f.root,endpointFile(f,i))),...inventory.filter(x=>x.path!==null).map(x=>x.path)].sort(sort);const files=filePaths.map(p=>{const b=fs.readFileSync(path.join(f.root,p));return {path:p,byteLength:b.length,rawSha256:sha(b)}});
  const manifestPath=path.join(f.root,'failure-manifest.v1.json'),manifest={schema:'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-manifest/v1',manifestId:'failure-manifest:execution-epoch-gate-b-v2:attempt-001:v1',attemptIndex:1,status:terminal.state,endpointOrder,endpoints,streamInventory:inventory,files,receiptPath:'failure-receipt.v1.json',claimPath:'execution-claim.json',normalized:null,crossEngine:null,ranking:null,selection:null};redigest(manifest,'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-manifest/attempt-001');write(manifestPath,manifest);
  const rootPath=path.join(f.root,'failure-root.v1.json'),root={schema:'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-root/v1',failureId:'failure-root:execution-epoch-gate-b-v2:attempt-001:v1',attemptIndex:1,status:terminal.state,evidenceClassification:'failure-accounting-not-success-evidence',executionAllowed:false,metricsAllowed:false,authorizationBinding:f.authority.authorization,contractBinding:f.authority.contract,epochBinding:f.authority.epoch,retryBinding:f.authority.retry,claimBinding:claimCopy,failureManifestBinding:{path:'failure-manifest.v1.json',rawSha256:sha(fs.readFileSync(manifestPath)),contentDigest:manifest.contentDigest},failureReceiptBinding:{path:'failure-receipt.v1.json',rawSha256:sha(fs.readFileSync(receiptPath)),contentDigest:receipt.contentDigest},inventoryDigest:digestRecord('shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-inventory/attempt-001',files),normalized:null,crossEngine:null,ranking:null,selection:null};redigest(root,'shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-root/attempt-001');write(rootPath,root);
}
export function setState(f,index,patch){const p=path.join(f.root,'causal-batch-state.v1.json'),x=read(p);Object.assign(x.states[index],patch);write(p,x)}
export function markNotStarted(f,index){const p=endpointFile(f,index),x=read(p);for(const s of x.streams)if(s.path)fs.rmSync(path.join(f.root,s.path),{force:true});x.status='not-started';x.outcome=outcome(x.endpointKind,'not-started');x.lifecycle=lifecycle(x.endpointKind,'not-started');x.streams=[];x.combinedOutputBytes=0;x.fsyncOnClose=false;x.moduleNdjsonPrefix=null;x.rowPrefixCardinality=0;x.fsyncPerCompletedRow=false;write(p,x)}
export function setExternal(f,index,closure,bytes=Buffer.from([0xff,0x00]),capture='partial'){const p=endpointFile(f,index),x=read(p),[id,,role]=specs[index];for(const s of x.streams)if(s.path)fs.rmSync(path.join(f.root,s.path),{force:true});x.status='started';x.outcome=outcome('external-process',closure);x.lifecycle=lifecycle('external-process',closure);x.streams=[stream(f.root,index,id,role,'stdin',empty),stream(f.root,index,id,role,'stdout',bytes,capture,false),stream(f.root,index,id,role,'stderr',empty)];x.combinedOutputBytes=bytes.length;x.fsyncOnClose=closure!=='spawn-error';x.moduleNdjsonPrefix=null;x.rowPrefixCardinality=0;x.fsyncPerCompletedRow=false;write(p,x)}
export function setModule(f,index,closure,bytes=empty,capture='complete'){const p=endpointFile(f,index),x=read(p),[id,,role]=specs[index];for(const s of x.streams)if(s.path)fs.rmSync(path.join(f.root,s.path),{force:true});x.status='started';x.outcome=outcome('module-ndjson',closure);x.lifecycle=lifecycle('module-ndjson',closure);x.streams=[stream(f.root,index,id,role,'stdin',empty),stream(f.root,index,id,role,'stdout',bytes,capture,capture==='complete'),stream(f.root,index,id,role,'stderr',empty)];x.combinedOutputBytes=bytes.length;x.fsyncOnClose=true;x.moduleNdjsonPrefix=modulePrefix(bytes);x.rowPrefixCardinality=x.moduleNdjsonPrefix.completedRowCount;x.fsyncPerCompletedRow=true;write(p,x)}
export function removeFixture(f){fs.rmSync(f.parent,{recursive:true,force:true})}
