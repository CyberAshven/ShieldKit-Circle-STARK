import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';

export const CANONICALIZATION='recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
export const FRAME='utf8(domain)||0x00||canonical-json-utf8';
const here=path.dirname(new URL(import.meta.url).pathname);
const repoRoot=path.resolve(here,'../../../../../');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
export const rawDigest=sha;
export const canonicalize=v=>Array.isArray(v)?v.map(canonicalize):(v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonicalize(v[k])])):v);
export const digestRecord=(domain,value)=>({algorithm:'sha256',canonicalization:CANONICALIZATION,domain,frame:FRAME,value:sha(Buffer.from(`${domain}\0${JSON.stringify(canonicalize(value),null,2)}\n`))});
const assert=(ok,msg)=>{if(!ok)throw new Error(msg)};
const json=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const omitDigest=x=>Object.fromEntries(Object.entries(x).filter(([k])=>k!=='contentDigest'));
const byteSort=(a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b));
const exact=(a,b,msg)=>assert(JSON.stringify(a)===JSON.stringify(b),msg);

function safeRel(rel){assert(typeof rel==='string'&&rel.length>0&&!path.isAbsolute(rel)&&!rel.includes('\\')&&!rel.split('/').includes('..'),'unsafe relative path');return rel}
function checkedPath(root,rel,kind='file'){
  safeRel(rel); const base=fs.realpathSync(root); let cur=base;
  for(const part of rel.split('/')){cur=path.join(cur,part);const st=fs.lstatSync(cur);assert(!st.isSymbolicLink(),`symlink forbidden: ${rel}`)}
  const real=fs.realpathSync(cur);assert(real===base||real.startsWith(base+path.sep),`path escapes root: ${rel}`);
  if(kind==='file')assert(fs.statSync(real).isFile(),`not regular file: ${rel}`);
  if(kind==='dir')assert(fs.statSync(real).isDirectory(),`not directory: ${rel}`);
  return real;
}
function safeFile(rel){return checkedPath(repoRoot,rel)}
function safeDir(rel){return checkedPath(repoRoot,rel,'dir')}
function safeAbsoluteFile(expected){
  assert(path.isAbsolute(expected),'absolute path required');const parsed=path.parse(expected);let cur=parsed.root;
  for(const part of expected.slice(parsed.root.length).split('/').filter(Boolean)){cur=path.join(cur,part);const st=fs.lstatSync(cur);assert(!st.isSymbolicLink(),`absolute symlink forbidden: ${expected}`)}
  const real=fs.realpathSync(expected);assert(real===expected&&fs.statSync(real).isFile(),`absolute file mismatch: ${expected}`);return real;
}
function regular(st,label){assert(st.isFile(),`non-regular entry: ${label}`);if(Number.isInteger(st.nlink))assert(st.nlink===1,`hard-linked regular file: ${label}`)}
function walkFiles(root,relativePrefix=''){
  const out=[];const go=(dir,rel)=>{for(const name of fs.readdirSync(dir).sort(byteSort)){
    const full=path.join(dir,name), child=rel?`${rel}/${name}`:name, st=fs.lstatSync(full);
    assert(!st.isSymbolicLink(),`symlink forbidden: ${relativePrefix}${child}`);
    if(st.isDirectory())go(full,child);else {regular(st,`${relativePrefix}${child}`);out.push(child)}
  }};go(root,'');return out.sort(byteSort);
}
function completeEntryClosure(root,listedFiles,label){
  const wantedFiles=[...listedFiles].sort(byteSort);assert(new Set(wantedFiles).size===wantedFiles.length,`${label} duplicate listed file`);
  const wantedDirs=new Set();for(const rel of wantedFiles){safeRel(rel);const parts=rel.split('/');for(let i=1;i<parts.length;i++)wantedDirs.add(parts.slice(0,i).join('/'))}
  const actualFiles=[],actualDirs=[];const go=(dir,rel='')=>{for(const name of fs.readdirSync(dir).sort(byteSort)){
    const full=path.join(dir,name),child=rel?`${rel}/${name}`:name,st=fs.lstatSync(full);assert(!st.isSymbolicLink(),`${label} symlink: ${child}`);
    if(st.isDirectory()){actualDirs.push(child);go(full,child)}else{regular(st,`${label} ${child}`);actualFiles.push(child)}
  }};go(root);actualFiles.sort(byteSort);actualDirs.sort(byteSort);exact(actualFiles,wantedFiles,`${label} file closure`);exact(actualDirs,[...wantedDirs].sort(byteSort),`${label} directory closure`);return {files:actualFiles,dirs:actualDirs};
}
function schemaCheck(file,value){const schema=json(path.join(here,file));const ajv=new Ajv2020({strict:true});ajv.addSchema(json(path.join(here,'future-endpoint.v1.schema.json')));const f=ajv.compile(schema);assert(f(value),`${file}: ${ajv.errorsText(f.errors)}`)}
function checkDigest(d,domain,value){assert(d?.algorithm==='sha256'&&d.canonicalization===CANONICALIZATION&&d.frame===FRAME&&d.domain===domain,'content digest metadata mismatch');assert(d.value===digestRecord(domain,value).value,`content digest mismatch: ${domain}`)}
function rawAndContent(rel,domain,schema){const p=safeFile(rel), bytes=fs.readFileSync(p), x=JSON.parse(bytes);assert(x.schema===schema,`${rel} schema`);checkDigest(x.contentDigest,domain,omitDigest(x));return {path:rel,rawSha256:sha(bytes),byteLength:bytes.length,contentDigest:x.contentDigest,value:x}}

export const TREE_AGGREGATE_ALGORITHM='sha256-sorted-raw-file-sha256-two-space-repo-relative-path-lf-v1';
const aggregateExpected={
  execution:['research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2','73ffe359ffe30f09442481462c0208692e72b281e664b86656ab882dbf043b7b'],
  executor:['research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2','a5d28bb619fc47667e9a40bbeb5fe76bba1a60f9305c41d56465624de0f1530a'],
  freeze:['research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2','b0f4f16cc0b3d0a703336af44c7ad7d6cff4da34515008ae71b06c3a9ce54920']
};
export function treeAggregate(relRoot){
  const root=safeDir(relRoot);const files=walkFiles(root).map(x=>`${relRoot}/${x}`).sort(byteSort);
  return sha(Buffer.concat(files.map(rel=>Buffer.from(`${sha(fs.readFileSync(safeFile(rel)))}  ${rel}\n`,'utf8'))));
}
export function validateV2Aggregates(){for(const [name,[root,want]] of Object.entries(aggregateExpected))assert(treeAggregate(root)===want,`${name} tree aggregate`);return true}

function validateEnvelope(packageRel,manifestSchema,manifestDomain){
  const dir=safeDir(packageRel), manifestRel=`${packageRel}/MANIFEST.json`, sumsRel=`${packageRel}/SHA256SUMS`;
  const m=json(safeFile(manifestRel));const schema=json(path.join(dir,manifestSchema));const ajv=new Ajv2020({strict:true}), f=ajv.compile(schema);assert(f(m),`${manifestSchema}: ${ajv.errorsText(f.errors)}`);
  checkDigest(m.contentDigest,manifestDomain,omitDigest(m));
  const prefix=`${packageRel}/`;const listed=m.files.map(x=>x.path);assert(m.coverage.listedPayloadCount===listed.length,'manifest listed payload count');assert(new Set(listed).size===listed.length,'duplicate manifest path');
  const actual=walkFiles(dir).filter(x=>x!=='MANIFEST.json'&&x!=='SHA256SUMS').map(x=>`${prefix}${x}`);
  exact(listed,actual,'manifest deterministic inventory order');
  completeEntryClosure(dir,['MANIFEST.json','SHA256SUMS',...m.files.map(x=>x.path.slice(prefix.length))],'package');
  for(const entry of m.files){assert(entry.path.startsWith(prefix),'manifest outside package');const bytes=fs.readFileSync(safeFile(entry.path));assert(bytes.length===entry.byteLength&&sha(bytes)===entry.rawSha256,`manifest bytes ${entry.path}`)}
  const want=Buffer.from([[sha(fs.readFileSync(safeFile(manifestRel))),manifestRel],...m.files.map(x=>[x.rawSha256,x.path])].map(x=>x.join('  ')).join('\n')+'\n','utf8');
  assert(fs.readFileSync(safeFile(sumsRel)).equals(want),'checksum bytes');return m;
}
function validateV2Envelopes(){
  // execution-v2 and freeze-v2 use distinct frozen manifest grammars; their
  // full regular-file closure is bound by the independently recomputed tree digest.
  const execution=json(safeFile('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2/MANIFEST.json'));
  const executor=json(safeFile('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/MANIFEST.json'));
  const freeze=json(safeFile('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/MANIFEST.json'));
  assert(sha(fs.readFileSync(safeFile('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2/MANIFEST.json')))==='1720ebc610441c58ddaecc445a8ccd1792a6a8b656d54d2e3db05f597dd9bf7f','execution manifest raw');
  assert(sha(fs.readFileSync(safeFile('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/MANIFEST.json')))==='0e8e1ceac80d1b0fe5602b3a56877da7d2e54d870110afb4d663fa9b0133c5ee','executor manifest raw');
  assert(sha(fs.readFileSync(safeFile('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/SHA256SUMS')))==='cee230ed681bab0b9fe9e7154e0819b50b2d5221b17950bceb2a64ef6d7515f8','executor sums raw');
  return {execution,executor,freeze};
}

const engines=['engine:native','engine:libauth','engine:bchn','engine:leanbch'];
const engineRecords=['7af55f7225c500a80b83411e7b7c191bbe4613236bf14d6db3e8062fd486f7e8','24d3e09426a32683782f4216c2dc1ba9ed1cb8c97c8e65fe44d0bf68cdaa9680','ae1de738dbae6892e3f29b2b6a8443316382736144bbdb1108184b6bea0a044b','50e8d31ed6987436a6dff3f4818c6304a64036559e780285895f27c15cb5a4c7'];
const engineContents=['0d376b79b874e893fe0ff4dfc2aabd4d3c5a48ac3ebd5d5303d3e84bc179cc65','d61b185fa2df2c7b57a05357de0d5a62b24bfa42092682add59b545af2698ef5','761f4d9b8840e8578413824e764766cdbb45f3a3148aa9533fb8c35cc031a8d0','45c2e93d444231645347fd2c7fc78dc08098fb399c39639f75094d370fe696f2'];
const recordPaths=engines.map(x=>`research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engines/${x.slice(7)}.v2.json`);
const entryHashes=['1ead86eb3bee0cd4e0d78ce6a03146d4d92e5bc4f6de646947a8c2fb5ca21faf','27ca6028f3073802324983a2df3763af65f49c3a12369b6463a4f9e188563fcf','92dce8fbf31fb8dd5d6853aeb16fb6b6ee26bbbce50a4cafc5feeb89d2f72a26','7ffb0aef41ccea6df8b31cb8588cc4cdcb9b6caae8696c37caebec23f3ac1604'];
const secondaryHashes=[null,null,null,'c5847f22da2a057410be91474f7b142716cd18b8e2ba8e6e7b3c1717e4cbbe88'];
const engineSchemaPath='research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engine.v2.schema.json';
const engineSchemaRaw='d8da247cc44f7aa1ebadb75554f41492488ecaf5385e85f3725a6b477a3c0e47';
const bindingExpected={
  authorization:['research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/authorization.v2.json','d0ed6a22ef0cdbba80c87bc14650872f2242b7369960ffc6beafb153e5404564','f1628af741dcab6caca956bbe5ae73ffaa25ac54ff255ce96d5db75c4ac59352','shieldkit-labs/p2/gate-b/cohort-executor-v2/authorization/v2/root','shieldkit-labs/p2/gate-b/cohort-executor-v2/authorization/v2'],
  contract:['research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2/execution-contract.v2.json','1feb52caca316282beb5cccf00dd9bf477570a2b382b54b4691a87e9e5928437','f1851be65326365d9bce7b6deb06085f5e0e94d404dcadbdd227df716cb76d9d','shieldkit-labs/p2/gate-b/execution-contract/v2/root','shieldkit-labs/p2/gate-b/cohort-execution/v2'],
  epoch:['research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/execution-epoch.v2.json','84ff8f6a85244b65d5d4f6e80c38b516223641ee444a133a67eb5794311d2dbc','6fcbaba3bb52d5e1eb9c6f1cb04b1d46cb65e2c91eba20ca38356dc323ebb11e','shieldkit-labs/p2/gate-b/execution-epoch/v2/root','shieldkit-labs/p2/gate-b/execution-epoch/v2']
};
function validateBinding(b,key){const [rel,raw,content,domain,schema]=bindingExpected[key];assert(b.path===rel&&b.rawSha256===raw&&b.contentDigest?.value===content,`${key} binding`);const a=rawAndContent(rel,domain,schema);assert(a.rawSha256===raw&&a.contentDigest.value===content,`${key} source bytes`)}
function externalFile(root,rel){safeRel(rel);const base=fs.realpathSync(root);let cur=base;for(const part of rel.split('/')){cur=path.join(cur,part);const st=fs.lstatSync(cur);assert(!st.isSymbolicLink(),`external symlink: ${rel}`)}const real=fs.realpathSync(cur);assert(real.startsWith(base+path.sep)&&fs.statSync(real).isFile(),`external escape: ${rel}`);return real}
export function validateEnginePins(pins){
  assert(Array.isArray(pins)&&pins.length===4,'engine pin cardinality');
  for(let i=0;i<4;i++){const pin=pins[i];assert(pin.engineId===engines[i]&&pin.ordinal===i&&pin.recordPath===recordPaths[i]&&pin.recordRawSha256===engineRecords[i]&&pin.recordContentDigest===engineContents[i]&&pin.recordSchemaPath===engineSchemaPath&&pin.recordSchemaSha256===engineSchemaRaw&&pin.entrypointRawSha256===entryHashes[i]&&pin.secondaryEntrypointRawSha256===secondaryHashes[i],`engine pin ${i}`);
    assert(sha(fs.readFileSync(safeFile(pin.recordPath)))===engineRecords[i],'engine record bytes');assert(sha(fs.readFileSync(safeFile(engineSchemaPath)))===engineSchemaRaw,'engine schema bytes');
    const record=json(safeFile(pin.recordPath));checkDigest(record.contentDigest,`shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/${engines[i]}`,omitDigest(record));
    const root=i===2?'/home/toorik/Projects/BCH/bch-conformance':i===3?'/home/toorik/Projects/ZK-Proofs/LeanBCH':repoRoot;
    assert(sha(fs.readFileSync(externalFile(root,record.entrypoint.file.path)))===entryHashes[i],`entrypoint ${i}`);
    if(i===3)assert(sha(fs.readFileSync(externalFile('/home/toorik/Projects/ZK-Proofs/LeanBCH','.lake/build/bin/costprobe')))===secondaryHashes[i],'lean secondary entrypoint');
  } return true;
}

const invocationExpected={
  command:{cwd:'/home/toorik/Projects/ShieldKit-LABS',argv:['/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node','research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/executor.mjs','--execute','--authorization','research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/authorization.v2.json','--output','research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/runs/attempt-000'],shellCommand:'env -i NODE_ENV=production /home/toorik/.local/share/mise/installs/node/22.23.1/bin/node research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/executor.mjs --execute --authorization research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/authorization.v2.json --output research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/runs/attempt-000'},
  node:{executable:'/home/toorik/.local/share/mise/installs/node/22.23.1/bin/node',rawSha256:'93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068',byteLength:124835376,version:'v22.23.1',platform:'linux',arch:'x64',runtimeDigest:'dd37763669af21f4ccb9bbe6b8d3c6d5148b15285a93bba90ea33ffc1ee4d4d2'},environment:{NODE_ENV:'production'},exitCode:1,
  failure:{engineId:'engine:leanbch',batchOrdinal:3,endpointRole:'primary',stage:'parser',error:'Lean standard true must be JSON string list'},invocationStartedAt:null,invocationEndedAt:null
};
const causalExpected=[
  [0,'engine:native',0,'primary','inferred-completed-in-memory-not-durable','control-flow-inference',null,null],
  [1,'engine:libauth',1,'primary','inferred-completed-in-memory-not-durable','control-flow-inference',null,null],
  [2,'engine:bchn',2,'primary','inferred-completed-in-memory-not-durable','control-flow-inference',null,null],
  [3,'engine:leanbch',3,'primary','process-exit-zero-observed-no-durable-stream','operator-observation',null,0],
  [4,'engine:leanbch',3,'primary','failed-parser','operator-observation','parser',null],
  [5,'engine:leanbch',3,'secondary','not-started','control-flow-inference',null,null]
];
function validateInvocation(invocation){exact(invocation,invocationExpected,'exact invocation');const node=safeAbsoluteFile(invocation.node.executable), b=fs.readFileSync(node);assert(b.length===invocation.node.byteLength&&sha(b)===invocation.node.rawSha256,'node byte pin');return true}
function validateCausal(rows){assert(rows.length===6,'causal count');for(let i=0;i<6;i++){const r=rows[i],e=causalExpected[i];exact([r.causalOrdinal,r.engineId,r.engineOrdinal,r.endpointRole,r.state,r.basis,r.failureStage,r.endpointExitCode],e,`causal tuple ${i}`);assert(r.streams===null&&r.observations===null&&r.verdicts===null&&r.metrics===null&&r.agreementEligible===false&&r.reusable===false,`causal boundary ${i}`)}return true}
export function validateReceipt(receipt){
  schemaCheck('abort-receipt.v1.schema.json',receipt);checkDigest(receipt.contentDigest,'shieldkit-labs/p2/gate-b/cohort-attempt-accounting/v1/receipt/attempt-000',omitDigest(receipt));
  assert(receipt.operatorRecordAuthoredAt==='2026-08-09T16:30:31Z','operator-authored timestamp');exact(receipt.v2TreeAggregates,{algorithm:TREE_AGGREGATE_ALGORITHM,execution:aggregateExpected.execution[1],executor:aggregateExpected.executor[1],freeze:aggregateExpected.freeze[1]},'v2 tree aggregate artifact');validateInvocation(receipt.invocation);validateCausal(receipt.causalBatches);
  validateBinding(receipt.bindings.authorization,'authorization');validateBinding(receipt.bindings.contract,'contract');validateBinding(receipt.bindings.epoch,'epoch');
  assert(receipt.bindings.executionManifest.path==='research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2/MANIFEST.json'&&receipt.bindings.executionManifest.rawSha256==='1720ebc610441c58ddaecc445a8ccd1792a6a8b656d54d2e3db05f597dd9bf7f'&&receipt.bindings.executionManifest.contentDigest.value==='f1851be65326365d9bce7b6deb06085f5e0e94d404dcadbdd227df716cb76d9d','execution manifest binding');
  assert(receipt.bindings.executorManifest.path==='research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/MANIFEST.json'&&receipt.bindings.executorManifest.rawSha256==='0e8e1ceac80d1b0fe5602b3a56877da7d2e54d870110afb4d663fa9b0133c5ee'&&receipt.bindings.executorManifest.contentDigest.value==='98e12c0bdb1ce086ff75adb682980d2e67bb5a7d37ace2e86160d4f9e41d3249','executor manifest binding');
  assert(receipt.bindings.executorChecksums.path==='research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/SHA256SUMS'&&receipt.bindings.executorChecksums.rawSha256==='cee230ed681bab0b9fe9e7154e0819b50b2d5221b17950bceb2a64ef6d7515f8','executor checksum binding');
  validateEnginePins(receipt.bindings.enginePins);validateV2Aggregates();validateV2Envelopes();
  exact(receipt.cleanup,{outputPath:'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/runs/attempt-000',status:'absent',entries:['.gitkeep'],evidencePackageCreated:false,partialMerge:false},'cleanup');
  completeEntryClosure(safeDir('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v2/runs'),['.gitkeep'],'v2 executor runs');
  return true;
}

const staticSchemas=['abort-receipt.v1.schema.json','attempt-accounting-root.v1.schema.json','attempt-manifest.v1.schema.json','causal-batch-state.v1.schema.json','endpoint-stream-binding.v1.schema.json','failure-manifest.v1.schema.json','failure-receipt.v1.schema.json','failure-root.v1.schema.json','future-endpoint.v1.schema.json','manifest.v1.schema.json'];
function schemaPins(){return staticSchemas.map(name=>({path:name,rawSha256:sha(fs.readFileSync(path.join(here,name))),schemaIdentity:name}))}
export function validateRoot(root,receipt,receiptBytes){schemaCheck('attempt-accounting-root.v1.schema.json',root);checkDigest(root.contentDigest,'shieldkit-labs/p2/gate-b/cohort-attempt-accounting/v1/root/attempt-000',omitDigest(root));assert(root.receiptBinding.path==='receipts/attempt-000.posthoc-abort-receipt.v1.json'&&root.receiptBinding.rawSha256===sha(receiptBytes)&&root.receiptBinding.contentDigest.value===receipt.contentDigest.value,'root receipt');exact(root.schemaSet,schemaPins(),'root schema set');return true}
export function validateAttemptManifest(m,root,receipt,rootBytes,receiptBytes){schemaCheck('attempt-manifest.v1.schema.json',m);checkDigest(m.contentDigest,'shieldkit-labs/p2/gate-b/cohort-attempt-accounting/v1/manifest/root',omitDigest(m));assert(m.rootBinding.path==='attempt-accounting-root.v1.json'&&m.rootBinding.rawSha256===sha(rootBytes)&&m.rootBinding.contentDigest.value===root.contentDigest.value,'manifest root');assert(m.receiptBinding.path==='receipts/attempt-000.posthoc-abort-receipt.v1.json'&&m.receiptBinding.rawSha256===sha(receiptBytes)&&m.receiptBinding.contentDigest.value===receipt.contentDigest.value,'manifest receipt');exact(m.schemaSet,schemaPins(),'manifest schema set');return true}
export function validatePackageEnvelope(){return validateEnvelope('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-attempt-accounting-v1','manifest.v1.schema.json','shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/package-manifest/root')}
export function validateAttemptAccounting(){const receiptBytes=fs.readFileSync(path.join(here,'receipts/attempt-000.posthoc-abort-receipt.v1.json')),rootBytes=fs.readFileSync(path.join(here,'attempt-accounting-root.v1.json'));const receipt=JSON.parse(receiptBytes),root=JSON.parse(rootBytes),m=json(path.join(here,'attempt-manifest.v1.json'));validateReceipt(receipt);validateRoot(root,receipt,receiptBytes);validateAttemptManifest(m,root,receipt,rootBytes,receiptBytes);validatePackageEnvelope();return true}

const endpointOrder=['engine:native/primary','engine:libauth/primary','engine:bchn/primary','engine:leanbch/primary','engine:leanbch/secondary'];
const endpointSpecs=[['engine:native',0,'primary','module-ndjson'],['engine:libauth',1,'primary','module-ndjson'],['engine:bchn',2,'primary','external-process'],['engine:leanbch',3,'primary','external-process'],['engine:leanbch',3,'secondary','external-process']];
const tag=i=>`attempt-${String(i).padStart(3,'0')}`;
const EXTERNAL_OUTPUT_CAP=134217728;
const LEAN_AGGREGATE_DEADLINE_MS=600000;
const TERMINATION_GRACE_MS=5000;
const TERMINATION_GRACE_NS=5000000000n;
const OBSERVED_SIGNALS=new Set(['SIGABRT','SIGALRM','SIGBUS','SIGCHLD','SIGCONT','SIGFPE','SIGHUP','SIGILL','SIGINT','SIGIO','SIGIOT','SIGKILL','SIGPIPE','SIGPOLL','SIGPROF','SIGPWR','SIGQUIT','SIGSEGV','SIGSTKFLT','SIGSTOP','SIGSYS','SIGTERM','SIGTRAP','SIGTSTP','SIGTTIN','SIGTTOU','SIGURG','SIGUSR1','SIGUSR2','SIGVTALRM','SIGWINCH','SIGXCPU','SIGXFSZ']);
function monotonicNs(value,label){assert(typeof value==='string'&&/^(?:0|[1-9][0-9]*)$/.test(value),`${label} canonical monotonic ns`);return BigInt(value)}
function normalExitCode(value,label){assert(value===null||(Number.isSafeInteger(value)&&value>=0&&value<=255),`${label} normal exit code`);return value}
/** Runtime companion to the shared JSON Schema normal-exit-code definition. */
export function validateNormalExitCode(value){return normalExitCode(value,'normal exit code')}
function exactKeys(value,keys,label){exact(Object.keys(value??{}).sort(),[...keys].sort(),label)}
function validateDispatchResult(result,label){
  exactKeys(result,['kind','value','error'],`${label} dispatch result keys`);
  if(result.kind==='returned'){assert(typeof result.value==='boolean'&&result.error===null,`${label} dispatch returned union`);return result}
  assert(result.kind==='threw'&&result.value===null,`${label} dispatch threw union`);exactKeys(result.error,['name','code','messageRawSha256'],`${label} dispatch error keys`);assert(typeof result.error.name==='string'&&result.error.name.length>0&&(result.error.code===null||(typeof result.error.code==='string'&&result.error.code.length>0))&&typeof result.error.messageRawSha256==='string'&&/^[0-9a-f]{64}$/.test(result.error.messageRawSha256),`${label} dispatch error`);return result;
}
function validateStructuredError(error,label){
  exactKeys(error,['name','code','messageRawSha256'],`${label} error keys`);
  assert(typeof error.name==='string'&&error.name.length>0&&(error.code===null||(typeof error.code==='string'&&error.code.length>0))&&typeof error.messageRawSha256==='string'&&/^[0-9a-f]{64}$/.test(error.messageRawSha256),`${label} error`);
  return error;
}
const sameBinding=(a,b,label)=>exact(a,b,label);
function safeAttemptRoot(attemptRoot){
  assert(typeof attemptRoot==='string'&&path.isAbsolute(attemptRoot),'absolute attempt root required');
  const root=path.resolve(attemptRoot);
  let cur=path.parse(root).root;for(const part of root.slice(cur.length).split('/').filter(Boolean)){cur=path.join(cur,part);const st=fs.lstatSync(cur);assert(!st.isSymbolicLink(),`attempt component symlink: ${part}`)}
  assert(fs.realpathSync(root)===root&&fs.statSync(root).isDirectory(),'attempt root directory');return root;
}
function validateAttemptParentNamespace(root){
  assert(path.basename(root)==='failure'&&['attempt-001','attempt-001.scratch'].includes(path.basename(path.dirname(root))),'attempt namespace basename');const parent=path.dirname(root),entries=fs.readdirSync(parent).sort(byteSort);
  for(const name of entries){const st=fs.lstatSync(path.join(parent,name));assert(!st.isSymbolicLink(),`attempt sibling symlink: ${name}`);assert(st.isDirectory()||st.isFile(),`attempt sibling non-regular: ${name}`)}
  exact(entries,['failure'],'attempt parent namespace');
}
function attemptFile(root,rel){safeRel(rel);let cur=root;for(const p of rel.split('/')){cur=path.join(cur,p);const st=fs.lstatSync(cur);assert(!st.isSymbolicLink(),`attempt symlink: ${rel}`)}const real=fs.realpathSync(cur);assert(real.startsWith(root+path.sep)&&fs.statSync(real).isFile(),`attempt file: ${rel}`);return real}
function attemptReadJson(root,rel,schema){const p=attemptFile(root,rel),b=fs.readFileSync(p),x=JSON.parse(b);schemaCheck(schema,x);return {path:rel,bytes:b,value:x}}
function attemptReadClaimCopy(root){
  const pathRel='execution-claim.json',p=attemptFile(root,pathRel),bytes=fs.readFileSync(p);let value;
  try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes))}catch{throw new Error('claim copy invalid canonical UTF-8 JSON')}
  assert(Buffer.from(`${JSON.stringify(canonicalize(value),null,2)}\n`,'utf8').equals(bytes),'claim copy noncanonical JSON');
  assert(value.schema==='shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3','claim copy schema');
  checkDigest(value.contentDigest,'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3/root',omitDigest(value));
  return {path:pathRel,bytes,value};
}
function genericDigestShape(d,label){assert(d&&typeof d==='object'&&Object.keys(d).sort().join(',')==='algorithm,canonicalization,domain,frame,value',`${label} digest shape`);assert(d.algorithm==='sha256'&&d.canonicalization===CANONICALIZATION&&d.frame===FRAME&&typeof d.domain==='string'&&d.domain.length>0&&typeof d.value==='string'&&/^[0-9a-f]{64}$/.test(d.value),`${label} digest metadata`)}
function projectionBinding(binding,label){assert(binding&&typeof binding==='object'&&Object.keys(binding).sort().join(',')==='contentDigest,path,rawSha256',`${label} binding shape`);safeRel(binding.path);assert(typeof binding.rawSha256==='string'&&/^[0-9a-f]{64}$/.test(binding.rawSha256),`${label} binding raw shape`);genericDigestShape(binding.contentDigest,`${label} binding`);return binding}
function projectionOpaqueBinding(binding,label){assert(binding&&typeof binding==='object'&&Object.keys(binding).sort().join(',')==='path,rawSha256',`${label} opaque binding shape`);assert(typeof binding.path==='string'&&binding.path.length>0&&!binding.path.includes('\0')&&typeof binding.rawSha256==='string'&&/^[0-9a-f]{64}$/.test(binding.rawSha256),`${label} opaque binding values`);return binding}
function validateInvocationDescriptor(x,label){
  exact(Object.keys(x??{}).sort(),['argv','cwd','engineBinding','entrypointBinding','environment','entrypointKind','runtime'].sort(),`${label} invocation keys`);
  assert(['module','external'].includes(x.entrypointKind)&&(x.argv===null||(Array.isArray(x.argv)&&x.argv.length>0&&x.argv.every(v=>typeof v==='string'))),`${label} argv`);
  assert(typeof x.cwd==='string'&&path.isAbsolute(x.cwd)&&x.environment&&typeof x.environment==='object'&&!Array.isArray(x.environment),`${label} invocation runtime`);
  exact(Object.keys(x.runtime??{}).sort(),['arch','executable','platform','version'],`${label} runtime keys`);for(const k of ['executable','version','platform','arch'])assert(typeof x.runtime[k]==='string'&&x.runtime[k].length>0,`${label} runtime ${k}`);
  projectionBinding(x.engineBinding,`${label} engine`);projectionOpaqueBinding(x.entrypointBinding,`${label} entrypoint`);assert((x.entrypointKind==='module')===(x.argv===null),`${label} module argv`);return x;
}
function validateAuthorityProjection(authority,root){
  exact(Object.keys(authority??{}).sort(),['attemptIndex','authorization','claim','contract','endpoints','epoch','limits','outputPaths','retry'],'non-authoritative projection shape');
  assert(authority.attemptIndex===1,'projection attempt index');
  for(const key of ['authorization','claim','contract','epoch','retry'])projectionBinding(authority[key],`projection ${key}`);
  const expectedPaths={failureRoot:root,successRoot:path.join(path.dirname(root),'success')};exact(authority.outputPaths,expectedPaths,'projection output paths');
  exact(authority.limits,{externalCombinedOutputBytes:EXTERNAL_OUTPUT_CAP,leanAggregateDeadlineMilliseconds:LEAN_AGGREGATE_DEADLINE_MS,terminationGraceMilliseconds:TERMINATION_GRACE_MS},'sealed resource limits');
  assert(Array.isArray(authority.endpoints)&&authority.endpoints.length===5,'sealed endpoint count');
  for(let i=0;i<5;i++){const e=authority.endpoints[i],[engineId,engineOrdinal,endpointRole,endpointKind]=endpointSpecs[i];exact(Object.keys(e??{}).sort(),['endpointKind','endpointRole','engineId','engineOrdinal','expectedRowCount','invocation'].sort(),`projection endpoint ${i} keys`);assert(e.engineId===engineId&&e.engineOrdinal===engineOrdinal&&e.endpointRole===endpointRole&&e.endpointKind===endpointKind&&e.expectedRowCount===4608,`projection endpoint ${i} identity`);validateInvocationDescriptor(e.invocation,`projection endpoint ${i}`)}
  return {authorization:authority.authorization,claim:authority.claim,contract:authority.contract,epoch:authority.epoch,retry:authority.retry,outputPaths:authority.outputPaths,limits:authority.limits,endpoints:authority.endpoints};
}
function strictUtf8NdjsonPrefix(bytes,label){
  let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes)}catch{throw new Error(`${label} invalid UTF-8`)}
  assert(!text.includes('\r')&&(!text.length||text.endsWith('\n')),`${label} LF`);const lines=text?text.slice(0,-1).split('\n'):[];for(const line of lines){assert(line.length>0,`${label} blank NDJSON line`);JSON.parse(line)}return lines.length;
}
function validateKillAttempts(attempts,outcome,label){
  assert(Array.isArray(attempts)&&attempts.length<=2,`${label} kill attempt count`);
  const controller=['timeout','capture-limit','executor-abort'].includes(outcome.terminalClosure);
  if(!controller){exact(attempts,[],`${label} no controller termination`);return}
  assert(attempts.length>=1,`${label} controller termination request`);
  const close=outcome.observedCloseAtMonotonicNanoseconds===null?null:monotonicNs(outcome.observedCloseAtMonotonicNanoseconds,`${label} observed close`);
  const term=attempts[0];
  exactKeys(term,['ordinal','reason','signal','graceMilliseconds','requestedAtMonotonicNanoseconds','closeObservedBeforeRequest','dispatchResult'],`${label} TERM shape`);
  /* Option B preserves the historical deadline/cap intent. If it cannot
   * produce an observed close after its bounded escalation, the terminal
   * closure becomes executor-abort without rewriting the earlier request. */
  const allowedTermReasons=outcome.terminalClosure==='executor-abort'?['timeout','capture-limit','executor-abort']:[outcome.terminalClosure];
  assert(term.ordinal===0&&allowedTermReasons.includes(term.reason)&&term.signal==='SIGTERM'&&term.graceMilliseconds===TERMINATION_GRACE_MS&&term.closeObservedBeforeRequest===false,`${label} TERM details`);
  const termAt=monotonicNs(term.requestedAtMonotonicNanoseconds,`${label} TERM request`),termDispatch=validateDispatchResult(term.dispatchResult,`${label} TERM`);
  if(close!==null)assert(close>=termAt,`${label} close before TERM request`);
  if(attempts.length===2){
    const kill=attempts[1];exactKeys(kill,['ordinal','reason','signal','graceMilliseconds','requestedAtMonotonicNanoseconds','closeObservedBeforeRequest','dispatchResult'],`${label} KILL shape`);
    assert(termDispatch.kind==='returned'&&termDispatch.value===true,`${label} KILL requires successful TERM`);
    assert(kill.ordinal===1&&kill.reason===term.reason&&kill.signal==='SIGKILL'&&kill.graceMilliseconds===0&&kill.closeObservedBeforeRequest===false,`${label} KILL details`);
    const killAt=monotonicNs(kill.requestedAtMonotonicNanoseconds,`${label} KILL request`);validateDispatchResult(kill.dispatchResult,`${label} KILL`);
    assert(killAt>=termAt+TERMINATION_GRACE_NS,`${label} KILL before TERM grace`);
    if(close!==null)assert(close>=killAt,`${label} close before KILL request`);
  }else if(close!==null&&termDispatch.kind==='returned'&&termDispatch.value===true)assert(close<=termAt+TERMINATION_GRACE_NS,`${label} TERM-only close after grace`);
  if(outcome.terminalClosure==='executor-abort'&&close===null){
    assert(['timeout','capture-limit','executor-abort'].includes(term.reason),`${label} executor-abort intent`);
    if(termDispatch.kind==='returned'&&termDispatch.value===true)assert(attempts.length===2,`${label} executor-abort must exhaust KILL after successful TERM`);
    else assert(attempts.length===1,`${label} executor-abort failed TERM has no KILL`);
  }
  if(outcome.terminalClosure==='executor-abort'&&['timeout','capture-limit'].includes(term.reason))assert(close===null,`${label} deadline/cap fallback cannot relabel an observed close`);
}
function validateLifecycle(lifecycle,outcome,kind,started,state,label){
  const keys=['capExceeded','captureClosed','closeEventObserved','controllerError','exitEventObserved','invocationStarted','killAttempts','kind','moduleErrorClass','moduleErrorMessageDigest','observedExitCode','observedSignal','returned','spawnAttempted','spawnError','stdinWriteError','spawnSucceeded','startObserved','stderrEndObserved','stdoutEndObserved','streamsFsynced','terminationKind','threw','transportError'].sort();
  exact(Object.keys(lifecycle??{}).sort(),keys,`${label} lifecycle keys`);assert(lifecycle.kind===kind,`${label} lifecycle kind`);
  normalExitCode(lifecycle.observedExitCode,`${label} lifecycle`);
  assert(lifecycle.observedExitCode===outcome.observedExitCode&&lifecycle.observedSignal===outcome.observedSignal&&lifecycle.terminationKind===outcome.terminalClosure,`${label} lifecycle outcome join`);
  if(!started){assert(lifecycle.kind===kind&&!lifecycle.spawnAttempted&&!lifecycle.spawnSucceeded&&!lifecycle.startObserved&&!lifecycle.exitEventObserved&&!lifecycle.closeEventObserved&&!lifecycle.stdoutEndObserved&&!lifecycle.stderrEndObserved&&lifecycle.observedExitCode===null&&lifecycle.observedSignal===null&&!lifecycle.capExceeded&&lifecycle.spawnError===null&&lifecycle.stdinWriteError===null&&lifecycle.transportError===null&&lifecycle.controllerError===null&&!lifecycle.streamsFsynced&&lifecycle.terminationKind==='not-started'&&!lifecycle.invocationStarted&&!lifecycle.returned&&!lifecycle.threw&&lifecycle.moduleErrorClass===null&&lifecycle.moduleErrorMessageDigest===null&&!lifecycle.captureClosed,`${label} unstarted lifecycle`);validateKillAttempts(lifecycle.killAttempts,outcome,label);return}
  if(kind==='module-ndjson'){
    assert(!lifecycle.spawnAttempted&&!lifecycle.spawnSucceeded&&!lifecycle.startObserved&&!lifecycle.exitEventObserved&&!lifecycle.closeEventObserved&&!lifecycle.stdoutEndObserved&&!lifecycle.stderrEndObserved&&lifecycle.observedExitCode===null&&lifecycle.observedSignal===null&&!lifecycle.capExceeded&&lifecycle.spawnError===null&&lifecycle.stdinWriteError===null&&lifecycle.transportError===null&&lifecycle.controllerError===null&&lifecycle.invocationStarted&&lifecycle.captureClosed&&lifecycle.streamsFsynced,`${label} module lifecycle`);validateKillAttempts(lifecycle.killAttempts,outcome,label);
    if(outcome.terminalClosure==='module-complete'||outcome.terminalClosure==='parser-after-complete')assert(lifecycle.returned&&!lifecycle.threw&&lifecycle.moduleErrorClass===null&&lifecycle.moduleErrorMessageDigest===null,`${label} module complete lifecycle`);else assert(outcome.terminalClosure==='module-error'&&lifecycle.threw&&!lifecycle.returned&&typeof lifecycle.moduleErrorClass==='string'&&typeof lifecycle.moduleErrorMessageDigest==='string',`${label} module error lifecycle`);
    return;
  }
  assert(lifecycle.spawnAttempted&&lifecycle.invocationStarted===(lifecycle.spawnSucceeded&&lifecycle.startObserved)&&!lifecycle.returned&&!lifecycle.threw&&lifecycle.moduleErrorClass===null&&lifecycle.moduleErrorMessageDigest===null,`${label} external lifecycle`);
  if(outcome.terminalClosure==='spawn-error'){assert(!lifecycle.spawnSucceeded&&!lifecycle.startObserved&&lifecycle.stdinWriteError===null&&lifecycle.transportError===null&&lifecycle.controllerError===null&&!lifecycle.exitEventObserved&&!lifecycle.closeEventObserved&&!lifecycle.streamsFsynced&&!lifecycle.captureClosed,`${label} spawn error lifecycle`);validateStructuredError(lifecycle.spawnError,`${label} spawn`) }
  else if(outcome.terminalClosure==='executor-abort'&&outcome.observedCloseAtMonotonicNanoseconds===null){assert(lifecycle.spawnSucceeded&&lifecycle.startObserved&&lifecycle.spawnError===null&&lifecycle.stdinWriteError===null&&!lifecycle.captureClosed&&!lifecycle.exitEventObserved&&!lifecycle.closeEventObserved,`${label} unresolved executor abort lifecycle`);if(lifecycle.transportError!==null)validateStructuredError(lifecycle.transportError,`${label} unresolved transport`);if(lifecycle.controllerError!==null)validateStructuredError(lifecycle.controllerError,`${label} unresolved controller`)}
  else if(outcome.terminalClosure==='abrupt-unobserved')assert(lifecycle.spawnSucceeded&&lifecycle.startObserved&&lifecycle.spawnError===null&&lifecycle.stdinWriteError===null&&lifecycle.transportError===null&&lifecycle.controllerError===null&&!lifecycle.captureClosed&&!lifecycle.streamsFsynced&&!lifecycle.exitEventObserved&&!lifecycle.closeEventObserved&&!lifecycle.stdoutEndObserved&&!lifecycle.stderrEndObserved,`${label} abrupt unobserved lifecycle`);
  else {assert(lifecycle.spawnSucceeded&&lifecycle.startObserved&&lifecycle.spawnError===null&&lifecycle.captureClosed,`${label} started external lifecycle`);assert(lifecycle.exitEventObserved&&lifecycle.closeEventObserved&&lifecycle.stdoutEndObserved&&lifecycle.stderrEndObserved&&lifecycle.streamsFsynced,`${label} closed external lifecycle`);if(state?.failureStage==='capture-write')validateStructuredError(lifecycle.stdinWriteError,`${label} capture-write`);else assert(lifecycle.stdinWriteError===null,`${label} unexpected stdin write error`);if(outcome.terminalClosure==='executor-abort'){assert(lifecycle.transportError!==null||lifecycle.controllerError!==null,`${label} executor abort cause`);if(lifecycle.transportError!==null)validateStructuredError(lifecycle.transportError,`${label} transport`);if(lifecycle.controllerError!==null)validateStructuredError(lifecycle.controllerError,`${label} controller`)}else assert(lifecycle.transportError===null&&lifecycle.controllerError===null,`${label} unexpected runner error`)}
  validateKillAttempts(lifecycle.killAttempts,outcome,label);
  assert(lifecycle.capExceeded===(outcome.terminalClosure==='capture-limit'),`${label} cap iff closure`);
}
function validateOutcome(x,lifecycle,kind,started,state,label){
  exactKeys(x,['observedExitCode','observedSignal','observedCloseAtMonotonicNanoseconds','observedOutcomeAttribution','terminalClosure'],`${label} outcome keys`);
  normalExitCode(x.observedExitCode,`${label} outcome`);
  if(!started){exact(x,{observedExitCode:null,observedSignal:null,observedCloseAtMonotonicNanoseconds:null,observedOutcomeAttribution:null,terminalClosure:'not-started'},`${label} unstarted outcome`);validateLifecycle(lifecycle,x,kind,false,state,label);return}
  assert((x.observedExitCode===null||Number.isInteger(x.observedExitCode))&&(x.observedSignal===null||OBSERVED_SIGNALS.has(x.observedSignal))&&!(x.observedExitCode!==null&&x.observedSignal!==null),`${label} observed outcome values`);
  const hasObserved=x.observedExitCode!==null||x.observedSignal!==null, close=x.observedCloseAtMonotonicNanoseconds;
  if(close!==null)monotonicNs(close,`${label} close`);
  if(kind==='module-ndjson')assert(x.observedExitCode===null&&x.observedSignal===null&&close===null&&x.observedOutcomeAttribution===null&&['module-complete','module-error','parser-after-complete'].includes(x.terminalClosure),`${label} module outcome`);
  else if(x.terminalClosure==='exit')assert(Number.isInteger(x.observedExitCode)&&x.observedSignal===null&&close!==null&&x.observedOutcomeAttribution===null,`${label} external exit outcome`);
  else if(x.terminalClosure==='parser-after-complete')assert(x.observedExitCode===0&&x.observedSignal===null&&close!==null&&x.observedOutcomeAttribution===null,`${label} clean parser outcome`);
  else if(x.terminalClosure==='signal')assert(x.observedExitCode===null&&x.observedSignal!==null&&close!==null&&x.observedOutcomeAttribution===null,`${label} signal outcome`);
  else if(['timeout','capture-limit'].includes(x.terminalClosure))assert(hasObserved&&close!==null&&x.observedOutcomeAttribution==='not-attributed-to-requested-signal',`${label} controller terminated outcome`);
  else if(x.terminalClosure==='executor-abort'){
    if(close===null)assert(!hasObserved&&x.observedOutcomeAttribution==='not-attributed-to-requested-signal'&&state?.state==='incomplete'&&state?.basis==='durable-controller-event',`${label} unclosed executor abort outcome`);
    else assert(hasObserved&&x.observedOutcomeAttribution==='not-attributed-to-requested-signal'&&state?.basis==='durable-endpoint-outcome',`${label} closed executor abort outcome`);
  }else if(x.terminalClosure==='spawn-error'||x.terminalClosure==='abrupt-unobserved')assert(!hasObserved&&close===null&&x.observedOutcomeAttribution===null,`${label} unavailable outcome`);
  else assert(false,`${label} external closure`);
  if(state?.state==='complete-captured-unpublished')assert((kind==='module-ndjson'&&x.terminalClosure==='module-complete')||(kind==='external-process'&&x.terminalClosure==='exit'),`${label} complete outcome`);
  if(state?.failureStage==='parser')assert(x.terminalClosure==='parser-after-complete',`${label} parser closure`);
  if(state?.failureStage==='capture-limit')assert(x.terminalClosure==='capture-limit',`${label} capture closure`);
  if(state?.failureStage==='capture-write')assert(kind==='external-process'&&x.terminalClosure==='exit'&&x.observedExitCode===0&&x.observedSignal===null,`${label} capture write closure`);
  if(state?.failureStage==='timeout')assert(x.terminalClosure==='timeout',`${label} timeout closure`);
  if(state?.failureStage==='process-exit')assert(kind==='external-process'&&x.terminalClosure==='exit'&&x.observedExitCode!==0,`${label} process exit closure`);
  if(state?.failureStage==='process-signal')assert(kind==='external-process'&&x.terminalClosure==='signal'&&x.observedSignal!==null,`${label} process signal closure`);
  if(state?.failureStage==='module-error')assert(kind==='module-ndjson'&&x.terminalClosure==='module-error',`${label} module error closure`);
  if(state?.failureStage==='spawn-error')assert(kind==='external-process'&&x.terminalClosure==='spawn-error',`${label} spawn closure`);
  if(state?.failureStage==='executor-abort')assert(x.terminalClosure==='executor-abort',`${label} executor abort closure`);
  if(state?.failureStage==='abrupt-unobserved')assert(x.terminalClosure==='abrupt-unobserved',`${label} abrupt closure`);
  validateLifecycle(lifecycle,x,kind,true,state,label);
}
function validateEndpointRecord(x,index,root,state,sealed){
  schemaCheck('endpoint-stream-binding.v1.schema.json',x);const [engineId,engineOrdinal,endpointRole,endpointKind]=endpointSpecs[index], expected=sealed.endpoints[index];
  assert(x.attemptIndex===1&&x.engineId===engineId&&x.engineOrdinal===engineOrdinal&&x.endpointRole===endpointRole&&x.endpointKind===endpointKind,`endpoint identity ${index}`);exact(x.invocation,expected.invocation,`endpoint invocation ${index}`);checkDigest(x.contentDigest,`shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/endpoint/${tag(1)}/${engineId}/${endpointRole}`,omitDigest(x));
  const started=x.status==='started';assert(started||x.status==='not-started',`endpoint status ${index}`);assert((state.state==='not-started')===!started,`endpoint state status ${index}`);validateOutcome(x.outcome,x.lifecycle,endpointKind,started,state,`endpoint ${index}`);
  if(!started){exact(x.streams,[],`unstarted streams ${index}`);assert(x.rowPrefixCardinality===0&&x.moduleNdjsonPrefix===null&&x.fsyncOnClose===false&&x.fsyncPerCompletedRow===false&&x.combinedOutputBytes===0,`unstarted durability ${index}`);return []}
  assert(x.streams.length===3,'started stream count');exact(x.streams.map(s=>s.streamRole),['stdin','stdout','stderr'],'stream order');assert(new Set(x.streams.filter(s=>s.path!==null).map(s=>s.path)).size===x.streams.filter(s=>s.path!==null).length,'stream path unique');
  if(endpointKind==='external-process')assert(x.moduleNdjsonPrefix===null&&x.rowPrefixCardinality===0&&x.fsyncPerCompletedRow===false,'external durability');else assert(x.moduleNdjsonPrefix&&typeof x.moduleNdjsonPrefix==='object'&&x.fsyncPerCompletedRow===true&&x.rowPrefixCardinality>=0,'module durability');
  const streams=x.streams.map(s=>{if(s.captureStatus==='unavailable'){assert(s.path===null&&s.byteLength===null&&s.rawSha256===null&&!s.fsynced&&!s.lineAligned,'unavailable stream union');return {...s,engineId,engineOrdinal,endpointRole,bytes:Buffer.alloc(0)}}assert(s.path===`streams/${String(index).padStart(2,'0')}-${engineId.slice(7)}-${endpointRole}.${s.streamRole}.bin`,'stream path');const b=fs.readFileSync(attemptFile(root,s.path));assert(b.length===s.byteLength&&sha(b)===s.rawSha256&&s.fsynced,'stream bytes/fsync');return {...s,engineId,engineOrdinal,endpointRole,bytes:b}});
  const slotsFsynced=x.streams.every(s=>s.fsynced),stdout=streams.find(s=>s.streamRole==='stdout').bytes,stderr=streams.find(s=>s.streamRole==='stderr').bytes;
  assert(x.lifecycle.streamsFsynced===slotsFsynced&&x.fsyncOnClose===slotsFsynced,`stream durability join ${index}`);
  if(state.failureStage==='abrupt-unobserved')assert(x.streams.every(s=>s.captureStatus==='unavailable')&&x.combinedOutputBytes===0&&!x.fsyncOnClose,`abrupt unavailable capture ${index}`);
  assert(x.combinedOutputBytes===stdout.length+stderr.length,`combined output bytes ${index}`);if(endpointKind==='external-process'){if(state.failureStage==='capture-limit')assert(x.combinedOutputBytes===sealed.limits.externalCombinedOutputBytes,`capture limit bytes ${index}`);else assert(x.combinedOutputBytes<=sealed.limits.externalCombinedOutputBytes,`external output cap ${index}`)}
  if(state.state==='complete-captured-unpublished')assert(x.streams.every(s=>s.captureStatus==='complete'),`complete capture status ${index}`);
  if(state.failureStage==='parser')assert(x.streams.every(s=>s.captureStatus==='complete'),`parser durable streams ${index}`);
  if(endpointKind==='module-ndjson'){const out=x.streams.find(s=>s.streamRole==='stdout');const last=stdout.lastIndexOf(0x0a), prefix=last<0?Buffer.alloc(0):stdout.subarray(0,last+1), trailing=last<0?stdout:stdout.subarray(last+1);const n=strictUtf8NdjsonPrefix(prefix,`module stdout ${index}`);assert(out.lineAligned===(trailing.length===0),`module stdout alignment ${index}`);if(out.captureStatus==='complete')assert(trailing.length===0,`complete module trailing`);if(out.captureStatus==='partial')assert(trailing.length>0,`partial module trailing`);exact(x.moduleNdjsonPrefix,{byteLength:prefix.length,rawSha256:sha(prefix),completedRowCount:n,trailingFragmentByteLength:trailing.length,trailingFragmentRawSha256:sha(trailing)},`module prefix ${index}`);assert(x.rowPrefixCardinality===n,`module row cardinality ${index}`);if(state.state==='complete-captured-unpublished'||(state.failureStage==='parser'&&x.outcome.terminalClosure==='parser-after-complete'))assert(n===expected.expectedRowCount,`module full transcript row count ${index}`);else assert(n<expected.expectedRowCount,`module incomplete row count ${index}`)}
  return streams.map(({bytes,...s})=>s);
}
function validateCausalFuture(c){
  schemaCheck('causal-batch-state.v1.schema.json',c);assert(c.attemptIndex===1,'causal attempt');exact(c.engineOrder,engines,'causal engine order');checkDigest(c.contentDigest,`shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/causal/${tag(1)}`,omitDigest(c));assert(c.states.length===5,'future causal count');
  let statePhase='complete',failed=0;
  for(let i=0;i<5;i++){
    const s=c.states[i],[engineId,engineOrdinal,endpointRole,endpointKind]=endpointSpecs[i];
    normalExitCode(s.endpointObservedExitCode,`causal endpoint ${i}`);
    assert(s.causalOrdinal===i&&s.engineId===engineId&&s.engineOrdinal===engineOrdinal&&s.endpointRole===endpointRole&&s.agreementEligible===false&&s.reusable===false&&s.streams===null&&s.observations===null&&s.verdicts===null&&s.metrics===null,`causal identity ${i}`);
    if(s.state==='complete-captured-unpublished'){
      assert(statePhase==='complete'&&s.basis==='durable-capture','causal complete basis');assert(s.failureStage===null&&s.endpointObservedExitCode===(endpointKind==='external-process'?0:null),'causal complete details');
    }else if(s.state==='failed'||s.state==='incomplete'){
      assert(statePhase==='complete'&&failed===0&&['parser','process-exit','process-signal','timeout','capture-limit','capture-write','spawn-error','executor-abort','abrupt-unobserved','module-error'].includes(s.failureStage),'causal failure count');
      if(s.failureStage==='parser')assert(s.basis==='durable-capture','parser terminal basis');
      else if(s.failureStage==='capture-write')assert(s.state==='incomplete'&&s.basis==='durable-endpoint-outcome'&&s.endpointObservedExitCode===0,'capture-write terminal basis');
      else if(s.failureStage==='executor-abort'){assert(['durable-controller-event','durable-endpoint-outcome'].includes(s.basis),'executor abort basis');if(s.basis==='durable-controller-event')assert(s.state==='incomplete','controller event is incomplete')}
      else assert(s.basis==='durable-endpoint-outcome','causal terminal basis');
      statePhase='failed';failed++;
    }else {assert(s.state==='not-started'&&failed===1&&s.basis==='control-flow-inference'&&s.failureStage===null&&s.endpointObservedExitCode===null,'causal not started');statePhase='not-started'}
  }
  assert(failed===1,'one terminal causal failure');return c.states;
}
function validateFailurePackageInternal(root,sealed){
  const rootFile=attemptReadJson(root,'failure-root.v1.json','failure-root.v1.schema.json'), receiptFile=attemptReadJson(root,'failure-receipt.v1.json','failure-receipt.v1.schema.json'), manifestFile=attemptReadJson(root,'failure-manifest.v1.json','failure-manifest.v1.schema.json'), causalFile=attemptReadJson(root,'causal-batch-state.v1.json','causal-batch-state.v1.schema.json'), claimFile=attemptReadClaimCopy(root);
  assert(rootFile.value.attemptIndex===1,'future attempt index');
  for(const [,file,domain] of [['root',rootFile,`shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-root/${tag(1)}`],['receipt',receiptFile,`shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-receipt/${tag(1)}`],['manifest',manifestFile,`shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-manifest/${tag(1)}`]])checkDigest(file.value.contentDigest,domain,omitDigest(file.value));
  assert(receiptFile.value.attemptIndex===1&&manifestFile.value.attemptIndex===1&&causalFile.value.attemptIndex===1,'attempt identity');assert(rootFile.value.failureId===`failure-root:execution-epoch-gate-b-v2:${tag(1)}:v1`&&receiptFile.value.receiptId===`failure-receipt:execution-epoch-gate-b-v2:${tag(1)}:v1`&&manifestFile.value.manifestId===`failure-manifest:execution-epoch-gate-b-v2:${tag(1)}:v1`,'artifact IDs');
  const states=validateCausalFuture(causalFile.value);assert(receiptFile.value.causalStates.length===5,'receipt causal count');for(let i=0;i<5;i++)exact(receiptFile.value.causalStates[i],states[i],`receipt causal ${i}`);
  exact(receiptFile.value.endpointOrder,endpointOrder,'receipt endpoint order');exact(manifestFile.value.endpointOrder,endpointOrder,'manifest endpoint order');assert(receiptFile.value.endpoints.length===5&&manifestFile.value.endpoints.length===5,'endpoint count');
  const endpointFiles=[];for(let i=0;i<5;i++){const [engineId,,role]=endpointSpecs[i], rel=`endpoints/${String(i).padStart(2,'0')}-${engineId.slice(7)}-${role}.endpoint.v1.json`, ef=attemptReadJson(root,rel,'endpoint-stream-binding.v1.schema.json');endpointFiles.push(ef);const streams=validateEndpointRecord(ef.value,i,root,states[i],sealed);assert(states[i].endpointObservedExitCode===ef.value.outcome.observedExitCode,`causal endpoint exit ${i}`);exact(receiptFile.value.endpoints[i],ef.value,`receipt endpoint ${i}`);exact(manifestFile.value.endpoints[i],ef.value,`manifest endpoint ${i}`);ef.streams=streams;}
  const streamInventory=endpointFiles.flatMap(x=>x.streams);exact(manifestFile.value.streamInventory,streamInventory,'stream inventory');
  const authorityBindings={authorization:sealed.authorization,contract:sealed.contract,epoch:sealed.epoch,retry:sealed.retry};for(const [k,b] of Object.entries(authorityBindings)){sameBinding(rootFile.value[`${k}Binding`],b,`root authority ${k}`);sameBinding(receiptFile.value[`${k}Binding`],b,`receipt authority ${k}`)}
  assert(sha(claimFile.bytes)===sealed.claim.rawSha256&&JSON.stringify(claimFile.value.contentDigest)===JSON.stringify(sealed.claim.contentDigest),'claim copy/source binding');
  const claimCopyBinding={path:'execution-claim.json',rawSha256:sha(claimFile.bytes),contentDigest:claimFile.value.contentDigest};sameBinding(rootFile.value.claimBinding,claimCopyBinding,'root claim copy');sameBinding(receiptFile.value.claimBinding,claimCopyBinding,'receipt claim copy');assert(manifestFile.value.claimPath==='execution-claim.json','manifest claim path');
  const rootBinding=x=>({path:x.path,rawSha256:sha(x.bytes),contentDigest:x.value.contentDigest});sameBinding(rootFile.value.failureReceiptBinding,rootBinding(receiptFile),'root receipt binding');sameBinding(rootFile.value.failureManifestBinding,rootBinding(manifestFile),'root manifest binding');
  const terminal=states.find(x=>x.state==='failed'||x.state==='incomplete'),terminalEndpoint=endpointFiles[terminal.causalOrdinal].value;normalExitCode(receiptFile.value.observedExitCode,'failure receipt');assert(rootFile.value.status===terminal.state&&receiptFile.value.status===rootFile.value.status&&manifestFile.value.status===rootFile.value.status,'failure status');exact({observedExitCode:receiptFile.value.observedExitCode,observedSignal:receiptFile.value.observedSignal,observedCloseAtMonotonicNanoseconds:receiptFile.value.observedCloseAtMonotonicNanoseconds,observedOutcomeAttribution:receiptFile.value.observedOutcomeAttribution,terminalClosure:receiptFile.value.terminalClosure},terminalEndpoint.outcome,'receipt endpoint outcome');if(terminal.failureStage==='parser')assert(receiptFile.value.parser.status==='failed'&&receiptFile.value.parser.stage==='parser'&&typeof receiptFile.value.parser.error==='string','parser receipt');else exact(receiptFile.value.parser,{status:'not-reached',stage:'none',error:null},'non-parser receipt');const externalObserved=[2,3,4].map(i=>({endpoint:endpointOrder[i],byteLength:endpointFiles[i].value.combinedOutputBytes}));exact(receiptFile.value.cap.externalEndpointObservedBytes,externalObserved,'receipt per-endpoint output');assert(receiptFile.value.cap.maxBytesPerExternalEndpoint===sealed.limits.externalCombinedOutputBytes&&receiptFile.value.cap.leanAggregateDeadlineMilliseconds===sealed.limits.leanAggregateDeadlineMilliseconds&&receiptFile.value.cap.terminationGraceMilliseconds===sealed.limits.terminationGraceMilliseconds,'receipt resource limits');const leanStarted=endpointFiles.slice(3).some(x=>x.value.status==='started'),leanTimedOut=terminal.engineId==='engine:leanbch'&&terminal.failureStage==='timeout',leanElapsed=receiptFile.value.cap.leanAggregateObservedMilliseconds;if(!leanStarted)assert(leanElapsed===0,'no Lean elapsed time');else if(leanTimedOut)assert(leanElapsed>=sealed.limits.leanAggregateDeadlineMilliseconds,'Lean timeout elapsed');else assert(leanElapsed<sealed.limits.leanAggregateDeadlineMilliseconds,'Lean non-timeout elapsed');for(const x of externalObserved)assert(x.byteLength<=receiptFile.value.cap.maxBytesPerExternalEndpoint,'receipt endpoint cap');for(const x of [rootFile.value,receiptFile.value,manifestFile.value,causalFile.value]){assert(x.normalized===null&&x.crossEngine===null&&x.ranking===null&&x.selection===null,'failure outputs')};assert(rootFile.value.metricsAllowed===false&&rootFile.value.executionAllowed===false&&receiptFile.value.agreementEligible===false&&receiptFile.value.reusableByLaterAttempt===false,'failure boundary');
  const expectedFiles=['causal-batch-state.v1.json','execution-claim.json','failure-manifest.v1.json','failure-receipt.v1.json','failure-root.v1.json',...endpointFiles.map(x=>x.path),...streamInventory.filter(x=>x.path!==null).map(x=>x.path)].sort(byteSort);const actual=walkFiles(root);exact(actual,expectedFiles,'failure package inventory');completeEntryClosure(root,expectedFiles,'failure package');const inventoryFiles=actual.filter(rel=>rel!=='failure-manifest.v1.json'&&rel!=='failure-root.v1.json');const files=inventoryFiles.map(rel=>{const b=fs.readFileSync(attemptFile(root,rel));return {path:rel,byteLength:b.length,rawSha256:sha(b)}});exact(manifestFile.value.files,files,'failure manifest files');const inventoryDigest=digestRecord(`shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/failure-inventory/${tag(1)}`,files);exact(rootFile.value.inventoryDigest,inventoryDigest,'root inventory digest');return true;
}
/** Pure structural core. A future v3 validator authenticates and derives projection. */
export function validateFailureStructureNonAuthoritative(failureRoot,expectedAuthorityProjection){const root=safeAttemptRoot(failureRoot);validateAttemptParentNamespace(root);const projection=validateAuthorityProjection(expectedAuthorityProjection,root);return validateFailurePackageInternal(root,projection)}
const main=process.argv[1]&&path.resolve(process.argv[1])===path.resolve(new URL(import.meta.url).pathname);
if(main&&process.argv.includes('--check')){validateAttemptAccounting();console.log('PASS attempt-accounting-v1')}
