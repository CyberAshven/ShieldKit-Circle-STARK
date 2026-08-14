/* Static-only PolicyAuthority P validator. It reads bytes and JSON; it never
 * imports a dependency module, endpoint, loader, binary, VM, or runtime. */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

export const PACKAGE_ROOT = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-policy-authority-v1';
export const DOMAIN_PREFIX = 'shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/';
export const FILE_DOMAIN = `${DOMAIN_PREFIX}file`;
export const SCHEMA_NAMES = Object.freeze(['root','dependency-binding','policy','causal-dag','q','a','live-f','manifest']);
export const OWN_FILES = Object.freeze([
  'COMMAND.txt','README.md','generate.mjs','validate.mjs',
  ...SCHEMA_NAMES.map(name => `schemas/${name}.v1.schema.json`),
  'tests/static-kat.test.mjs','tests/mutation.test.mjs'
]);
export const OWN_DIRECTORIES = Object.freeze(['.','schemas','tests']);
export const KAT_ROSTER = Object.freeze([
  'exact-dag','missing-edge','extra-edge','cycle','k-full-tuple','f-two-leaf-order','f-v3-rejection',
  'p-nonexecution','forbidden-instance-field','forbidden-predecessor-reference','initial-q','retry-q','abort-q',
  'variant-cross-substitution','a-no-consumption-state','c-only-consumer','live-f-stable-capture','live-f-race-rejection',
  'b-composite-binding','five-launch-rows','colon-alias-rejection','workload-as-k-rows-rejection','j-authority-free',
  'd-chain-binding','abort-no-activation','recovery-no-reactivation','filesystem-schema-check-mutants'
]);
export const EDGES = Object.freeze(['N→R','E→R','X→R','SOURCE→F','COHORT→F','R→P','K→P','F→P','Q→A','P→A','A→B','P→B','R→B','K→B','LIVE_F→B','B→C','B→J','C→J','B→D','C→D','J→D','WORKER_ROWS_ROOT→D','J→JOURNAL','D→JOURNAL','J→OBSERVATION','D→OBSERVATION','J→TERMINAL','D→TERMINAL']);
export const NODES = Object.freeze(['N','E','X','SOURCE','COHORT','R','K','F','P','Q','A','B','C','J','D','LIVE_F','WORKER_ROWS_ROOT','JOURNAL','OBSERVATION','TERMINAL']);
const here = path.dirname(fileURLToPath(import.meta.url));
const fail = message => { throw new Error(`FAIL-CLOSED: ${message}`); };
export const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
export const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value);
export const canonicalBytes = value => Buffer.from(`${canonical(value)}\n`, 'utf8');
export const domainDigest = (domain, value) => sha256(Buffer.concat([Buffer.from(domain, 'utf8'),Buffer.of(0),Buffer.isBuffer(value) ? value : canonicalBytes(value)]));
const wellFormedUnicodeScalars = value => {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
};
const canonicalLogicalPath = value => typeof value === 'string' && wellFormedUnicodeScalars(value) && value === value.normalize('NFC') && !/[\\\0]/.test(value) && safe(value);
export const assertLiveFRecordList = records => {
  if (!Array.isArray(records)) fail('live-F records array');
  let previous;
  for (const record of records) {
    exact(record,['logicalPath','dev','ino','mode','nlink','byteCount','rawSha256'],'live-F record');
    if (!canonicalLogicalPath(record.logicalPath) || !Number.isInteger(record.dev) || !Number.isInteger(record.ino) || !Number.isInteger(record.mode) || record.nlink !== 1 || !Number.isInteger(record.byteCount) || record.byteCount < 0 || !/^[0-9a-f]{64}$/.test(record.rawSha256)) fail('live-F record fields');
    const current = Buffer.from(record.logicalPath,'utf8');
    if (previous && Buffer.compare(previous,current) >= 0) fail('live-F logicalPath order/uniqueness');
    previous = current;
  }
  return true;
};
const digest = (suffix, value, field) => ({algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain:`${DOMAIN_PREFIX}${suffix}`,frame:`utf8(domain)||0x00||canonical-json-utf8-with-top-level-${field}-omitted`,value:domainDigest(`${DOMAIN_PREFIX}${suffix}`,value)});
const fileDigest = bytes => ({algorithm:'sha256',domain:FILE_DOMAIN,frame:'utf8(domain)||0x00||raw-file-bytes',value:domainDigest(FILE_DOMAIN,bytes)});
const exact = (value, keys, label) => { if (!value || typeof value !== 'object' || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) fail(`${label} exact keys`); };
const safe = value => typeof value === 'string' && value.length > 0 && !value.startsWith('/') && !value.includes('\\') && !value.includes('\0') && value.split('/').every(part => part && part !== '.' && part !== '..');
const rel = (base, file) => path.relative(base,file).split(path.sep).join('/');
export const findRepoRoot = (start = here) => { for (let current = path.resolve(start);;) { if (fs.existsSync(path.join(current,'research-lanes'))) return current; const next = path.dirname(current); if (next === current) fail('repository root missing'); current = next; } };
export const assertDirectoryChain = (base, relativePath, expectedRootMode, label) => {
  if (!path.isAbsolute(base) || (relativePath !== '.' && !safe(relativePath))) fail(`${label} path`);
  const basePath = path.resolve(base); const baseStat = fs.lstatSync(basePath);
  if (!baseStat.isDirectory() || baseStat.isSymbolicLink() || (baseStat.mode & 0o777) !== 0o755) fail(`${label} base root`);
  const realBase = fs.realpathSync(basePath); let current = basePath;
  for (const component of relativePath === '.' ? [] : relativePath.split('/')) {
    current = path.join(current,component); const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o755) fail(`${label} component ${component}`);
    const physical = path.relative(realBase,fs.realpathSync(current));
    if (physical === '..' || physical.startsWith(`..${path.sep}`) || path.isAbsolute(physical)) fail(`${label} containment`);
  }
  const rootStat = fs.lstatSync(current);
  if ((rootStat.mode & 0o777) !== expectedRootMode) fail(`${label} root mode`);
  return current;
};
const lstatFile = (file, mode, label) => { const stat = fs.lstatSync(file); if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== mode) fail(`${label} regular mode/link`); return stat; };
const readJson = (file, label, isCanonical = false) => { const bytes = fs.readFileSync(file); let value; try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(`${label} JSON`); } if (isCanonical && !bytes.equals(canonicalBytes(value))) fail(`${label} canonical JSON`); return value; };
const binding = (repoRoot, root, name) => { const bytes = fs.readFileSync(path.join(root,name)); return {path:path.posix.join(rel(repoRoot,root),name),bytes:bytes.length,rawSha256:sha256(bytes),fileContentDigest:fileDigest(bytes)}; };
const schemaBinding = (repoRoot, root, name) => ({...binding(repoRoot,root,name),schemaId:readJson(path.join(root,name),`schema ${name}`).$id});
const walk = (root, fileMode = 0o644, privateEnvelope = false) => {
  const files = []; const dirs = ['.'];
  const visit = current => { for (const entry of fs.readdirSync(current,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))) {
    const full = path.join(current,entry.name); const name = rel(root,full); const stat = fs.lstatSync(full);
    if (stat.isSymbolicLink()) fail(`symlink ${name}`);
    if (stat.isDirectory()) { if ((stat.mode & 0o777) !== 0o755) fail(`directory mode ${name}`); dirs.push(name); visit(full); }
    else if (stat.isFile()) { const expected = privateEnvelope && (name === 'MANIFEST.json' || name === 'SHA256SUMS') ? 0o600 : fileMode; if (stat.nlink !== 1 || (stat.mode & 0o777) !== expected) fail(`file mode/link ${name}`); files.push(name); }
    else fail(`special entry ${name}`);
  }};
  visit(root); return {files:files.sort(),dirs:dirs.sort()};
};
const parseSums = (file, label) => { const text = fs.readFileSync(file,'utf8'); if (!text.endsWith('\n') || text.includes('\r')) fail(`${label} newline`); const map = new Map(); for (const line of text.trimEnd().split('\n')) { const match = /^([0-9a-f]{64})  (.+)$/.exec(line); if (!match || map.has(match[2])) fail(`${label} row`); map.set(match[2],match[1]); } return map; };
const suffixName = (printed, expected) => printed === expected || printed.endsWith(`/${expected}`);
const DEPENDENCIES = Object.freeze({
  R:{root:'runtime-binding-root.v1.json',path:'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-runtime-binding-v1',raw:'b0ce9e0ec7b11770ed773b73a12ccb8a7d25a9ba3b4b38415dc1b90bf129d3dd',manifest:'2da4f55beba04efee8a019b1cac9493e7d6f099de91d36fe30d18e32cc5aa254',sums:'c25438471cfbd6949a886d723facb29ec5d0538be48dec7d28a87243065759ea',content:'8b73e8bbbfd97d8c451c5fd9466ff219ab36eeb65e3fb10c5f3629a89da36af1'},
  K:{root:'runtime-core.v1.json',path:'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-runner-core-v1',raw:'fc94be4544cf5e5e31c9f474a1ed3b95d47979fb23d46c55c9acffab9b690ea2',manifest:'913e5667c78de4f06a7ce34acfa13fb1393eeadbbf831641eab35ceddf3f01c4',sums:'27ffdc493af8e77ab89b22dde1b424f0d9733bf9491013943b8a63ccc87bb4db'},
  F:{root:'frozen-inputs-root.v1.json',path:'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-frozen-inputs-v1',raw:'19d90ed575404fa332f82d4cc28f1e1c4b71d99cff7f0d3a914664a0b72a2bd5',manifest:'f6b1dbf3f6757366c519e10f11e1fed80d071507445ad0085955aae164ad0867',sums:'4099e52c4acd2c2c34c49142bb28e6cb7ac31d048feb452e053038f3db578eff',content:'7f00510e5c4b8b4959b572c9c9ece8e97ca95174b5715c2ee0852ef79f28b08f'}
});
const dependency = (id, repoRoot) => {
  const spec = DEPENDENCIES[id]; const root = assertDirectoryChain(repoRoot,spec.path,0o755,`dependency ${id}`);
  const privateEnvelope = id === 'K'; const manifest = readJson(path.join(root,'MANIFEST.json'),`dependency ${id} manifest`);
  const records = Array.isArray(manifest.files) ? manifest.files.map(row => ({path:row.path,bytes:row.bytes,rawSha256:row.rawSha256})) : Array.isArray(manifest.entries) ? manifest.entries.map(row => ({path:row.locator,bytes:row.bytes,rawSha256:row.sha256})) : fail(`dependency ${id} manifest records`);
  const names = [];
  for (const row of records) { if (!safe(row.path) || !Number.isInteger(row.bytes) || !/^[0-9a-f]{64}$/.test(row.rawSha256)) fail(`dependency ${id} record shape`); const bytes = fs.readFileSync(path.join(root,row.path)); lstatFile(path.join(root,row.path),0o644,`dependency ${id} ${row.path}`); if (bytes.length !== row.bytes || sha256(bytes) !== row.rawSha256) fail(`dependency ${id} record ${row.path}`); names.push(row.path); }
  const closure = walk(root,0o644,privateEnvelope); const expectedFiles = [...names,'MANIFEST.json','SHA256SUMS'].sort(); const expectedDirs = new Set(['.']); for (const name of names) for (let parent = path.posix.dirname(name); parent !== '.'; parent = path.posix.dirname(parent)) expectedDirs.add(parent);
  if (canonical(closure.files) !== canonical(expectedFiles) || canonical(closure.dirs) !== canonical([...expectedDirs].sort())) fail(`dependency ${id} closure`);
  const sums = parseSums(path.join(root,'SHA256SUMS'),`dependency ${id} sums`); if (sums.size !== names.length + 1) fail(`dependency ${id} sums count`); for (const name of [...names,'MANIFEST.json']) { const row = [...sums].find(([printed]) => suffixName(printed,name)); if (!row || row[1] !== sha256(fs.readFileSync(path.join(root,name)))) fail(`dependency ${id} sums ${name}`); }
  for (const [name,hash] of [['MANIFEST.json',spec.manifest],['SHA256SUMS',spec.sums],[spec.root,spec.raw]]) if (sha256(fs.readFileSync(path.join(root,name))) !== hash) fail(`dependency ${id} pin ${name}`);
  const rootDoc = readJson(path.join(root,spec.root),`dependency ${id} root`);
  if (id === 'R' && (rootDoc.contentDigest?.value !== spec.content || rootDoc.runtimeAuthority?.digest !== 'fce66bed0f375e922e6b765a74f6b0dd81f784029df6079cee4668f89bb872d8')) fail('R semantic pin');
  if (id === 'F' && (rootDoc.contentDigest?.value !== spec.content || rootDoc.leafClosure?.leaves?.map(item=>item.id).join(',') !== 'source-set-v1,cohort-freeze-v2')) fail('F semantic pin');
  const value = {id,packageRoot:spec.path,root:binding(repoRoot,root,spec.root),manifest:binding(repoRoot,root,'MANIFEST.json'),sums:binding(repoRoot,root,'SHA256SUMS')};
  if (id === 'R') { value.nativeContentDigest = rootDoc.contentDigest.value; value.runtimeAuthorityDigest = rootDoc.runtimeAuthority.digest; }
  if (id === 'F') { value.nativeContentDigest = rootDoc.contentDigest.value; value.orderedLeafIds = rootDoc.leafClosure.leaves.map(item=>item.id); value.sourceNativeSemanticDigest = rootDoc.leafClosure.leaves[0].nativeSemanticDigest.value; value.freezeArtifactSemanticDigest = rootDoc.leafClosure.leaves[1].artifactSemanticDigest.value; }
  if (id === 'K') { if (manifest.entryCount !== 26 || manifest.entriesRoot !== '88ce4c1d2e91630344329f734fe65e23b6817c89400b431833f995e7a509033b' || manifest.packageRoot !== '10850743e64bf8f453b2a446019edb095861d9876a5e7785e946c4661d1ddac2' || manifest.manifestRoot !== '58928887efb9bffe5482eee0525854eaf08496e97ae890d7fb795c14995e98f1') fail('K complete entry authority'); value.manifestPackageRoot = manifest.packageRoot; value.manifestRoot = manifest.manifestRoot; value.entriesRoot = manifest.entriesRoot; value.runtimeEntrypoint = rootDoc.runtimeEntrypoint; value.runtimeModules = rootDoc.runtimeModules; value.runtimeExports = rootDoc.runtimeExports; value.typeModules = rootDoc.typeModules; value.buildTimeOnlyLocators = [...rootDoc.buildTimeOnlyLocators]; }
  value.bindingDigest = digest(`binding/${id.toLowerCase()}`,value,'bindingDigest'); return value;
};
const templateDigest = (suffix, value, field = 'contentDigest') => { const plain = {...value}; const result = {...value}; result[field] = digest(suffix,plain,field); return result; };
const policyTemplate = () => {
  const qVariants = {
    initial:templateDigest('q/initial',{variant:'initial',ordinal:0,predecessor:'none',target:null,fullCohort:true,reuse:false,request:'execute-once',activation:'template-only'}),
    retry:templateDigest('q/retry',{variant:'retry',ordinal:'predecessor-plus-one',predecessor:'terminal-or-abort',target:'full-cohort',fullCohort:true,reuse:false,newNonce:'template-only',newA:'template-only',newC:'template-only',restartEngineOrdinal:0,streamReuse:false,resultReuse:false,evidenceReuse:false,automatic:false}),
    abort:templateDigest('q/abort',{variant:'abort',ordinal:'exact-target',predecessor:'exact-target-chain',target:'exact-target',fullCohort:false,reuse:false,activation:'forbidden',recovery:'abort-recover-only',actions:['stop','reap','capture','fail','terminal']})
  };
  const aVariants = Object.fromEntries(['initial','retry','abort'].map(variant => [variant,templateDigest(`a/${variant}`,{variant,immutable:true,contentAddressed:true,activation:variant === 'abort' ? 'forbidden' : 'external-template-only'})]));
  const liveF = templateDigest('live-f',{template:'external-model-only',privateBinder:'WeakMap-keyed-by-K-B-handle',staticFRoot:'F.contentDigest-template-reference',logicalPathsOnly:true,kRetainsDescriptor:false,recordOrdering:{records:'external-ephemeral-only',sort:'strictly-increasing-utf8-bytewise-logicalPath',uniqueBy:'logicalPath',canonicalLogicalPath:'nfc-relative-no-dot-or-dotdot-no-backslash-no-nul'},recordShape:{orderedRecordKeys:['logicalPath','dev','ino','mode','nlink','byteCount','rawSha256'],nofollow:true,regular:true,singleLink:true,preStat:['dev','ino','mode','nlink','size','mtime','ctime'],postStat:['dev','ino','mode','nlink','size','mtime','ctime'],privateBytes:true,rawHash:true},workers:'private-captured-bytes-never-reopen'});
  const aliases = {native:'engine:native',libauth:'engine:libauth',bchn:'engine:bchn','leanbch-primary':'engine:leanbch:primary','leanbch-secondary':'engine:leanbch:secondary'};
  const launchRows = Object.entries(aliases).map(([alias,engineId]) => ({alias,engineId,capturedInput:{minimumBytes:1,complete:true,private:true},workloads:4608}));
  const b = {subject:templateDigest('b/subject',{preimageOrder:['aRoot','pRoot','rRoot','kPackageRoot'],canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',frame:'utf8(domain)||0x00||canonical-json-utf8-with-top-level-contentDigest-omitted'}),envelope:templateDigest('b/envelope',{preimageOrder:['subjectRoot','liveFRoot'],canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',frame:'utf8(domain)||0x00||canonical-json-utf8-with-top-level-contentDigest-omitted'})};
  return templateDigest('policy',{references:['q.v1.schema.json','a.v1.schema.json','live-f.v1.schema.json'],aliasMap:aliases,kLaunchAuthority:launchRows,q:{template:'generic-q-only',executionAllowed:false,variants:qVariants},a:{template:'model-only',immutable:true,contentAddressed:true,consumptionEvent:'external-C-only',forbiddenFields:['consumptionState'],variants:aVariants},liveF,b,c:{soleDurableConsumer:'external-C-only',creation:'openat-O_CREAT-O_EXCL-O_NOFOLLOW-O_CLOEXEC',mode:0o600,fsync:['file','parent'],crashOrphanConsumesA:true,pCreatesC:false},j:{journalKey:'template-journal-key-from-B-C',dispatchPlanRoot:'template-dispatch-plan-root',journalRoot:'template-journal-root',evidenceOnly:true,grantsAuthority:false},d:{chain:['B','C','J','plan'],plannedRows:{minimum:1,maximum:4096,uniqueBy:['workerId','endpointId'],kind:'template-only'},abortPrivate:true,abortExecutable:false,crossActivation:false,recoveryReactivation:false,rerun:'new-retry-Q-A'}});
};
export const makeRoot = (repoRoot, packageDir = here) => {
  const bindings = ['R','K','F'].map(id => dependency(id,repoRoot)); const causalDag = {nodes:[...NODES],edges:[...EDGES]};
  const value = {artifactId:'artifact:gate-b:cohort-policy-authority-v1',bindingRoot:digest('bindings',bindings,'bindingRoot'),causalDag,causalDagRoot:digest('causal-dag',causalDag,'causalDagRoot'),dependencyBindings:bindings,executionAllowed:false,katRoster:[...KAT_ROSTER],packageId:'cohort-policy-authority-v1',policy:policyTemplate(),runtimeBoundary:{activationCapability:null,buildTimeOnlyLocators:['generate.mjs','validate.mjs','tests/static-kat.test.mjs','tests/mutation.test.mjs'],runtimeEntrypoint:null,runtimeExports:[],runtimeModules:[]},schema:'shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/root',schemaBindings:SCHEMA_NAMES.map(name => schemaBinding(repoRoot,packageDir,`schemas/${name}.v1.schema.json`)),status:'static-policy-template-non-authorizing'};
  value.contentDigest = digest('root',value,'contentDigest'); return value;
};
export const makeManifest = (packageDir, rootBytes) => {
  const files = OWN_FILES.map(name => { const bytes = fs.readFileSync(path.join(packageDir,name)); return {path:name,bytes:bytes.length,mode:0o644,rawSha256:sha256(bytes),fileContentDigest:fileDigest(bytes)}; });
  if (!rootBytes) rootBytes = fs.readFileSync(path.join(packageDir,'policy-authority-root.v1.json'));
  files.push({path:'policy-authority-root.v1.json',bytes:rootBytes.length,mode:0o644,rawSha256:sha256(rootBytes),fileContentDigest:fileDigest(rootBytes)});
  return {directories:OWN_DIRECTORIES.map(path => ({path,mode:0o755})),directoryCount:OWN_DIRECTORIES.length,executionAllowed:false,fileCount:files.length,files,manifestRosterDigest:{algorithm:'sha256',canonicalization:'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',domain:`${DOMAIN_PREFIX}manifest-roster`,frame:'utf8(domain)||0x00||canonical-json-roster-v1',value:domainDigest(`${DOMAIN_PREFIX}manifest-roster`,files)},packageRoot:PACKAGE_ROOT,schema:'shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/manifest',status:'static-content-addressed'};
};
const ensureDomains = (value, includeManifestRoster = false) => { const domains = []; const visit = item => { if (Array.isArray(item)) item.forEach(visit); else if (item && typeof item === 'object') { if (typeof item.domain === 'string') domains.push(item.domain); Object.values(item).forEach(visit); } }; visit(value); if (domains.includes(`${DOMAIN_PREFIX}manifest`)) fail('forbidden manifest semantic domain'); const required = ['root','binding/r','binding/k','binding/f','bindings','policy','causal-dag','q/initial','q/retry','q/abort','a/initial','a/retry','a/abort','live-f','b/subject','b/envelope',...(includeManifestRoster ? ['manifest-roster'] : [])]; for (const suffix of required) if (!domains.includes(`${DOMAIN_PREFIX}${suffix}`)) fail(`missing digest domain ${suffix}`); };
const assertAcyclic = dag => { const todo = new Set(dag.nodes); const seen = new Set(); while (todo.size) { const ready = [...todo].filter(node => !dag.edges.some(edge => edge.endsWith(`→${node}`) && !seen.has(edge.split('→')[0]))); if (!ready.length) fail('causal DAG cycle'); for (const node of ready) { todo.delete(node); seen.add(node); } } };
export const validateRootObject = (root, repoRoot, packageDir = here) => {
  const expected = makeRoot(repoRoot,packageDir); if (canonical(root) !== canonical(expected)) fail('root exact static policy contract');
  exact(root,['artifactId','bindingRoot','causalDag','causalDagRoot','contentDigest','dependencyBindings','executionAllowed','katRoster','packageId','policy','runtimeBoundary','schema','schemaBindings','status'],'root');
  if (root.executionAllowed !== false || root.runtimeBoundary.activationCapability !== null || root.runtimeBoundary.runtimeEntrypoint !== null || root.runtimeBoundary.runtimeModules.length || root.runtimeBoundary.runtimeExports.length) fail('runtime boundary');
  if (root.dependencyBindings.map(item=>item.id).join('') !== 'RKF' || root.causalDag.edges.length !== 28 || canonical(root.causalDag.edges) !== canonical(EDGES) || canonical(root.causalDag.nodes) !== canonical(NODES)) fail('causal DAG exact');
  assertAcyclic(root.causalDag); ensureDomains(root); return true;
};
export const validateSchemas = (packageDir, root, manifest) => { const ajv = new Ajv2020({strict:true,allErrors:true,validateFormats:false}); for (const name of SCHEMA_NAMES) { const schema = readJson(path.join(packageDir,`schemas/${name}.v1.schema.json`),`schema ${name}`); ajv.addSchema(schema,schema.$id); } const validate = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/cohort-policy-authority/v1/root.v1.schema.json'); const validateManifest = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/cohort-policy-authority/v1/manifest.v1.schema.json'); if (!validate(root)) fail(`root schema ${ajv.errorsText(validate.errors)}`); if (!validateManifest(manifest)) fail(`manifest schema ${ajv.errorsText(validateManifest.errors)}`); };
export const assertOwnClosure = (packageDir, sealed = false) => { const closure = walk(packageDir); const expected = sealed ? [...OWN_FILES,'policy-authority-root.v1.json','MANIFEST.json','SHA256SUMS'].sort() : OWN_FILES.slice().sort(); if (canonical(closure.files) !== canonical(expected) || canonical(closure.dirs) !== canonical(OWN_DIRECTORIES)) fail(`${sealed ? 'sealed' : 'unsealed'} own closure`); return closure; };
export const validatePackage = (packageDir = here, repoRoot = findRepoRoot(packageDir), {allowUnsealed = false} = {}) => {
  if (path.resolve(packageDir) !== path.join(repoRoot,PACKAGE_ROOT)) fail('own package canonical path'); packageDir = assertDirectoryChain(repoRoot,PACKAGE_ROOT,0o755,'own package');
  const envelope = ['policy-authority-root.v1.json','MANIFEST.json','SHA256SUMS']; const present = envelope.filter(name => fs.existsSync(path.join(packageDir,name)));
  if (!present.length && allowUnsealed) { assertOwnClosure(packageDir); const candidateRoot = makeRoot(repoRoot,packageDir); const candidateManifest = makeManifest(packageDir,canonicalBytes(candidateRoot)); validateRootObject(candidateRoot,repoRoot,packageDir); ensureDomains({root:candidateRoot,manifest:candidateManifest},true); validateSchemas(packageDir,candidateRoot,candidateManifest); return {sealed:false,status:'unsealed-fail-closed',kats:KAT_ROSTER.length}; }
  if (present.length !== envelope.length) fail('partial sealed envelope');
  const closure = assertOwnClosure(packageDir,true);
  const root = readJson(path.join(packageDir,envelope[0]),'root',true); const manifest = readJson(path.join(packageDir,envelope[1]),'manifest',true); validateRootObject(root,repoRoot,packageDir); const expectedManifest = makeManifest(packageDir,fs.readFileSync(path.join(packageDir,envelope[0]))); if (canonical(manifest) !== canonical(expectedManifest)) fail('manifest exact roster envelope'); ensureDomains({root,manifest},true);
  const checksum = parseSums(path.join(packageDir,envelope[2]),'own sums'); const names = [...OWN_FILES,'policy-authority-root.v1.json','MANIFEST.json'].sort(); const qualified = names.map(name => `${PACKAGE_ROOT}/${name}`); if (checksum.size !== names.length || canonical([...checksum.keys()].sort()) !== canonical(qualified)) fail('own sums closure'); for (const name of names) { const found = checksum.get(`${PACKAGE_ROOT}/${name}`); if (!found || found !== sha256(fs.readFileSync(path.join(packageDir,name)))) fail(`own sums ${name}`); }
  validateSchemas(packageDir,root,manifest); return {sealed:true,root:sha256(fs.readFileSync(path.join(packageDir,envelope[0]))),manifest:sha256(fs.readFileSync(path.join(packageDir,envelope[1]))),sums:sha256(fs.readFileSync(path.join(packageDir,envelope[2]))),files:closure.files.length,directories:closure.dirs.length,kats:KAT_ROSTER.length};
};
export const seal = (packageDir = here, repoRoot = findRepoRoot(packageDir)) => {
  if (path.resolve(packageDir) !== path.join(repoRoot,PACKAGE_ROOT)) fail('seal package canonical path'); packageDir = assertDirectoryChain(repoRoot,PACKAGE_ROOT,0o755,'own package');
  for (const name of ['policy-authority-root.v1.json','MANIFEST.json','SHA256SUMS']) if (fs.existsSync(path.join(packageDir,name))) fail('seal requires unsealed envelope');
  const candidateRoot = makeRoot(repoRoot,packageDir); const rootBytes = canonicalBytes(candidateRoot); const candidateManifest = makeManifest(packageDir,rootBytes); validateSchemas(packageDir,candidateRoot,candidateManifest);
  const publish = (name,bytes) => { const fd = fs.openSync(path.join(packageDir,name),'wx',0o644); try { fs.writeFileSync(fd,bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); } };
  publish('policy-authority-root.v1.json',rootBytes); publish('MANIFEST.json',canonicalBytes(candidateManifest));
  const names = [...OWN_FILES,'policy-authority-root.v1.json','MANIFEST.json'].sort(); publish('SHA256SUMS',Buffer.from(`${names.map(name => `${sha256(fs.readFileSync(path.join(packageDir,name)))}  ${PACKAGE_ROOT}/${name}`).join('\n')}\n`,'utf8')); return validatePackage(packageDir,repoRoot);
};
if (process.argv[1] === fileURLToPath(import.meta.url)) { try { console.log(JSON.stringify(validatePackage())); } catch (error) { console.error(error.message); process.exitCode = 1; } }
