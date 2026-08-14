import assert from 'node:assert/strict';
import { chmodSync, cpSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { AUTHORED_FILES, assertP0FreezeManifest, canonicalJson, componentDigest, deriveSealEnvelope, parseValidationCliArgs, safeReadExternal, safeWalkReadExternal, sha256, validateStatic } from '../validate-static.mjs';

let negativeAssertions = 0;
let cliNegativeAssertions = 0;
let sealedPositiveAssertions = 0;
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repository = resolve(root, '../../../../..');
const options = parseValidationCliArgs(process.argv.slice(2));
const clone = () => { const dir = mkdtempSync(resolve(repository, '.gate-b0r-')); chmodSync(dir, 0o755); for (const locator of AUTHORED_FILES) { const destination = resolve(dir, locator); mkdirSync(dirname(destination), { recursive: true, mode: 0o755 }); cpSync(resolve(root, locator), destination, { dereference: false }); chmodSync(destination, 0o644); } for (const locator of ['schemas','test']) chmodSync(resolve(dir, locator), 0o755); return dir; };
const writeRoot = (dir, value, canonical = true) => writeFileSync(resolve(dir, 'evidence-plan-root.v1.json'), canonical ? `${canonicalJson(value)}\n` : JSON.stringify(value, null, 2));
const redigest = value => { for (const row of value.componentDigests) row.digest.value = componentDigest(row.digest.domain, value[row.component]); value.contentDigest.value = componentDigest(value.contentDigest.domain, Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'contentDigest'))); };
const expectNegative = (name, attempt, expected) => { assert.throws(attempt, typeof expected === 'function' ? expected : new RegExp(expected), name); negativeAssertions += 1; };
const expectCliNegative = (name, argv, code) => { assert.throws(() => parseValidationCliArgs(argv), new RegExp(code), name); cliNegativeAssertions += 1; };
const expectFail = (name, mutate, code) => { const dir = clone(); try { const value = JSON.parse(readFileSync(resolve(dir, 'evidence-plan-root.v1.json'))); mutate(value, dir); writeRoot(dir, value); expectNegative(name, () => validateStatic({ packageRoot: dir, repositoryRoot: repository, mode: 'unsealed' }), error => String(error.message).includes(code)); } finally { rmSync(dir, { recursive: true, force: true }); } };
validateStatic({ packageRoot: root, repositoryRoot: repository, mode: options.mode, reviewAnchorPin: options.reviewAnchorPin });
const sealedCliArgs = ['--mode','sealed','--anchor-root','/tmp/gate-b0r-review-anchor','--anchor-locator','review-anchor.v1.json','--anchor-bytes','17','--anchor-raw-sha256','a'.repeat(64)];
const withoutCliFlag = flag => { const index = sealedCliArgs.indexOf(flag); return [...sealedCliArgs.slice(0,index),...sealedCliArgs.slice(index+2)]; };
const withCliValue = (flag, value) => { const argv = [...sealedCliArgs]; argv[argv.indexOf(flag)+1] = value; return argv; };
expectCliNegative('cli missing mode', [], 'CLI_MODE_REQUIRED');
expectCliNegative('cli invalid mode', ['--mode','invalid'], 'CLI_MODE_VALUE');
for (const flag of ['--anchor-root','--anchor-locator','--anchor-bytes','--anchor-raw-sha256']) expectCliNegative(`cli missing ${flag}`, withoutCliFlag(flag), `CLI_SEALED_ANCHOR_REQUIRED:${flag}`);
expectCliNegative('cli duplicate flag', ['--mode','unsealed','--mode','unsealed'], 'CLI_DUPLICATE');
expectCliNegative('cli unknown flag', ['--mode','unsealed','--unknown','x'], 'CLI_UNKNOWN_OR_EXTRA');
expectCliNegative('cli extra positional', ['--mode','unsealed','extra'], 'CLI_UNKNOWN_OR_EXTRA');
expectCliNegative('cli noncanonical bytes', withCliValue('--anchor-bytes','01'), 'CLI_ANCHOR_BYTES');
expectCliNegative('cli zero bytes', withCliValue('--anchor-bytes','0'), 'CLI_ANCHOR_BYTES');
expectCliNegative('cli unsafe bytes', withCliValue('--anchor-bytes','9007199254740992'), 'CLI_ANCHOR_BYTES');
expectCliNegative('cli invalid hash', withCliValue('--anchor-raw-sha256','A'.repeat(64)), 'CLI_ANCHOR_RAW_SHA256');
expectCliNegative('cli relative root', withCliValue('--anchor-root','relative-anchor'), 'CLI_ANCHOR_ROOT_ABSOLUTE');
expectCliNegative('cli unsafe locator', withCliValue('--anchor-locator','../review-anchor'), 'CLI_ANCHOR_LOCATOR:SEGMENT');
expectCliNegative('cli unsealed anchor', ['--mode','unsealed','--anchor-root','/tmp/gate-b0r-review-anchor'], 'CLI_UNSEALED_ANCHOR_ARGUMENT');
expectFail('row remove', v => v.legacyReconciliation.rowBindings.pop(), 'ROOT_SCHEMA');
expectFail('row reorder', v => v.legacyReconciliation.rowBindings.reverse(), 'LEGACY_ROW_RECONCILIATION');
expectFail('row duplicate', v => v.legacyReconciliation.rowBindings[1] = structuredClone(v.legacyReconciliation.rowBindings[0]), 'LEGACY_ROW_RECONCILIATION');
expectFail('cross axis', v => v.legacyReconciliation.rowBindings[0].axis = 'fri', 'LEGACY_ROW_RECONCILIATION');
expectFail('tuple insertion', v => v.candidateTuples = [], 'ROOT_SCHEMA');
expectFail('role insertion', v => v.roleAssignments = [], 'ROOT_SCHEMA');
expectFail('parameter insertion', v => v.parameterAssignments = [], 'ROOT_SCHEMA');
expectFail('campaign drift', v => v.campaignTruth.counts.engines = 3, 'ROOT_SCHEMA');
expectFail('measurement lie', v => v.measurementAdmissionContract.measurementAdmissionAllowed = true, 'ROOT_SCHEMA');
expectFail('category corpus shrink', v => v.measurementAdmissionContract.plannedVectorObligations.pop(), 'ROOT_SCHEMA');
expectFail('phase missing', v => v.phaseDag.nodes.pop(), 'ROOT_SCHEMA');
expectFail('phase overlap', v => v.phaseDag.nodes[1].plannedOutputScope = v.phaseDag.nodes[0].plannedOutputScope, 'PHASE_NODES');
for (const key of ['executionAllowed','measurementAdmissionAllowed','qualificationAllowed','rankingAllowed','selectionAllowed','fallbackAuthorizationAllowed']) expectFail(`false gate ${key}`, v => v.nonAuthorityBoundary[key] = true, 'ROOT_SCHEMA');
expectFail('self pass', v => v.legacyReconciliation.typedKillGates[0].status = 'PASS', 'ROOT_SCHEMA');
expectFail('null placeholder', v => v.protocolAxisContract.componentFields[0].assignmentStates.air = null, 'ROOT_SCHEMA');
for (const key of ['metricRef','thresholdRef','comparison','quantifier','scope']) expectFail(`kill gate ${key}`, v => { v.legacyReconciliation.typedKillGates[0][key] = key === 'comparison' ? 'EQUALS' : key === 'quantifier' ? 'ANY_SCOPE_ITEM' : `${v.legacyReconciliation.typedKillGates[0][key]}:mutated`; redigest(v); }, 'KILL_GATE_BINDING');
expectFail('axis order', v => { v.protocolAxisContract.axes.reverse(); redigest(v); }, 'PROTOCOL_AXIS_ROSTER');
expectFail('engine order', v => { v.primitiveBenchmarkTemplate.engineApplicability.reverse(); redigest(v); }, 'PRIMITIVE_ENGINE_ROSTER');
expectFail('missing class order', v => { v.measurementAdmissionContract.missingAdditiveClasses.reverse(); redigest(v); }, 'MISSING_ADDITIVE_CLASS_ROSTER');
expectFail('campaign source order', v => { v.campaignTruth.sourceCatalogEntryIds.reverse(); redigest(v); }, 'CAMPAIGN_SOURCE_ROSTER');
expectFail('phase edge order', v => { v.phaseDag.edges.reverse(); redigest(v); }, 'PHASE_EDGES');
expectFail('vector obligation swap', v => { v.measurementAdmissionContract.plannedVectorObligations[0].currentObligation = 'P0_LIVENESS'; redigest(v); }, 'VECTOR_OBLIGATION');
{ const dir = clone(); try { const raw = resolve(dir, 'raw'); writeFileSync(raw, 'x'); const sym = resolve(dir, 'link'); symlinkSync(raw, sym); expectNegative('external symlink', () => safeReadExternal(dir, 'link', { bytes: 1, rawSha256: '2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881' }), 'LINK_OR_TYPE'); const hard = resolve(dir, 'hard'); linkSync(raw, hard); expectNegative('external hardlink', () => safeReadExternal(dir, 'hard', { bytes: 1, rawSha256: '2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881' }), 'LINK_OR_TYPE'); } finally { rmSync(dir, { recursive: true, force: true }); } }
{ const dir = clone(); const link = `${dir}-link`; try { symlinkSync(dir, link, 'dir'); expectNegative('package root symlink', () => validateStatic({ packageRoot: link, repositoryRoot: repository, mode: 'unsealed' }), 'PACKAGE_ROOT_METADATA'); } finally { rmSync(link, { force: true }); rmSync(dir, { recursive: true, force: true }); } }
{ const dir = clone(); try { const raw = readFileSync(resolve(dir, 'evidence-plan-root.v1.json'), 'utf8').trim(); writeFileSync(resolve(dir, 'evidence-plan-root.v1.json'), raw.slice(0, -1) + ',"apiVersion":"duplicate"}\n'); expectNegative('duplicate JSON key', () => validateStatic({ packageRoot: dir, repositoryRoot: repository, mode: 'unsealed' }), 'JSON_DUPLICATE'); } finally { rmSync(dir, { recursive: true, force: true }); } }
{ const dir = clone(); try { const value = JSON.parse(readFileSync(resolve(dir, 'evidence-plan-root.v1.json'))); writeRoot(dir, value, false); expectNegative('noncanonical JSON', () => validateStatic({ packageRoot: dir, repositoryRoot: repository, mode: 'unsealed' }), 'JSON_CANONICAL'); } finally { rmSync(dir, { recursive: true, force: true }); } }
{ const dir = clone(); try { writeFileSync(resolve(dir, 'MANIFEST.json'), '{}\n'); expectNegative('partial manifest envelope', () => validateStatic({ packageRoot: dir, repositoryRoot: repository, mode: 'unsealed' }), 'UNSEALED_ENVELOPE_ABSENT'); } finally { rmSync(dir, { recursive: true, force: true }); } }
{ const dir = clone(); try { writeFileSync(resolve(dir, 'SHA256SUMS'), '0'.repeat(64)+'  COMMAND.txt\n'); expectNegative('partial sums envelope', () => validateStatic({ packageRoot: dir, repositoryRoot: repository, mode: 'unsealed' }), 'UNSEALED_ENVELOPE_ABSENT'); } finally { rmSync(dir, { recursive: true, force: true }); } }
expectFail('external pin replacement', v => { v.sourceCatalog.entries[0].rawSha256 = '0'.repeat(64); v.componentDigests.find(x => x.component === 'sourceCatalog').digest.value = ''; v.contentDigest.value = ''; }, 'ROOT_SCHEMA');
expectFail('resigned source locator replacement', v => { v.sourceCatalog.entries[0].locator = 'atlas/profiles/desktop-prover-reference.json'; redigest(v); }, 'SOURCE_PIN_TABLE');
expectFail('resigned source byte replacement', v => { v.sourceCatalog.entries[0].bytes = 1; redigest(v); }, 'SOURCE_PIN_TABLE');
expectFail('resigned source class replacement', v => { v.sourceCatalog.entries[0].authorityClass = 'FROZEN_CAMPAIGN_INPUT'; redigest(v); }, 'SOURCE_PIN_TABLE');
expectFail('resigned source semantic replacement', v => { v.sourceCatalog.entries[18].semanticDigest = { extractionKind:'NONE',kind:'NOT_DECLARED' }; redigest(v); }, 'SOURCE_PIN_TABLE');
expectFail('component digest reorder', v => { v.componentDigests.reverse(); redigest(v); }, 'COMPONENT_DIGEST_ROSTER');
expectFail('component domain swap', v => { v.componentDigests[0].digest.domain = 'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/source-catalog'; redigest(v); }, 'COMPONENT_DIGEST_DOMAIN');
expectFail('lane domain swap', v => { v.authorityProjection.authorities[0].projection.contentDigest.domain = 'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/root'; redigest(v); }, 'LANE_PROJECTION_DOMAIN');
{ const dir = clone(); try { const raw = resolve(dir, 'raw'); writeFileSync(raw, 'x'); const expected={bytes:1,rawSha256:'2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881'}; assert.equal(safeReadExternal(dir, 'raw', expected).toString(), 'x'); writeFileSync(raw, 'y'); expectNegative('external raw drift', () => safeReadExternal(dir, 'raw', expected), 'RAW_OR_BYTES'); expectNegative('external locator traversal', () => safeWalkReadExternal(dir, '../raw'), 'SEGMENT'); } finally { rmSync(dir, { recursive: true, force: true }); } }
{ const dir = clone(); try { expectNegative('external pin table bypass', () => validateStatic({ packageRoot: dir, repositoryRoot: repository, mode: 'unsealed', externalPins: [] }), 'EXTERNAL_PIN_TABLE'); } finally { rmSync(dir, { recursive: true, force: true }); } }

const seal = dir => { const envelope=deriveSealEnvelope(dir); writeFileSync(resolve(dir,'MANIFEST.json'),envelope.manifestBytes); writeFileSync(resolve(dir,'SHA256SUMS'),envelope.sumsBytes); return envelope; };
const reviewAnchorPin = (dir, anchorRoot, envelope = deriveSealEnvelope(dir)) => { const model=JSON.parse(readFileSync(resolve(dir,'evidence-plan-root.v1.json'))); const p0=model.authorityProjection.authorities[2]; const anchor={entryCount:envelope.entries.length,laneProjectionDigest:model.authorityProjection.authorities[0].projection.contentDigest,manifestRawSha256:sha256(readFileSync(resolve(dir,'MANIFEST.json'))),nonAuthorityBoundary:model.nonAuthorityBoundary,orderedClosure:envelope.entries,p0Freeze:{aggregateSha256:p0.aggregateSha256,expectedLeafCount:p0.expectedLeafCount,manifestRawSha256:p0.rawSha256},package:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-evidence-plan-v1',rootContentDigest:model.contentDigest,rootRawSha256:sha256(readFileSync(resolve(dir,'evidence-plan-root.v1.json'))),rosterDigest:envelope.manifest.rosterDigest,schema:'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/external-review-anchor/v1',sha256SumsRawSha256:sha256(readFileSync(resolve(dir,'SHA256SUMS'))),validatorRawSha256:sha256(readFileSync(resolve(dir,'validate-static.mjs')))}; const locator='review-anchor.json'; const bytes=Buffer.from(`${canonicalJson(anchor)}\n`); writeFileSync(resolve(anchorRoot,locator),bytes); return {anchorRoot,bytes:bytes.length,locator,rawSha256:sha256(bytes)}; };
const sealedFixture = () => { const dir=clone(), anchorRoot=mkdtempSync(resolve(tmpdir(),'gate-b0r-anchor-')); try { const envelope=seal(dir); const pin=reviewAnchorPin(dir,anchorRoot,envelope); return {anchorRoot,dir,envelope,pin}; } catch(error) { rmSync(anchorRoot,{recursive:true,force:true});rmSync(dir,{recursive:true,force:true});throw error; } };
const cleanupSealed = fixture => { rmSync(fixture.anchorRoot,{recursive:true,force:true});rmSync(fixture.dir,{recursive:true,force:true}); };
{ const f=sealedFixture(); try { const result=validateStatic({packageRoot:f.dir,repositoryRoot:repository,mode:'sealed',reviewAnchorPin:f.pin}); assert.equal(result.files,17); sealedPositiveAssertions += 1; } finally { cleanupSealed(f); } }
{ const f=sealedFixture(); try { expectNegative('sealed anchor absent', () => validateStatic({packageRoot:f.dir,repositoryRoot:repository,mode:'sealed'}), 'SEALED_EXTERNAL_ANCHOR_REQUIRED'); } finally { cleanupSealed(f); } }
{ const f=sealedFixture(); try { expectNegative('sealed anchor raw mismatch', () => validateStatic({packageRoot:f.dir,repositoryRoot:repository,mode:'sealed',reviewAnchorPin:{...f.pin,rawSha256:'0'.repeat(64)}}), 'SEALED_EXTERNAL_ANCHOR:RAW_OR_BYTES'); } finally { cleanupSealed(f); } }
for (const [name, mutate, code] of [
  ['sealed-entry', (f)=>{ const x=JSON.parse(readFileSync(resolve(f.dir,'MANIFEST.json')));x.entries[0].sha256='0'.repeat(64);writeFileSync(resolve(f.dir,'MANIFEST.json'),`${canonicalJson(x)}\n`); },'SEALED_MANIFEST_RECOMPUTATION'],
  ['sealed-file-digest', (f)=>{ const x=JSON.parse(readFileSync(resolve(f.dir,'MANIFEST.json')));x.entries[0].fileDigest.value='0'.repeat(64);writeFileSync(resolve(f.dir,'MANIFEST.json'),`${canonicalJson(x)}\n`); },'SEALED_MANIFEST_RECOMPUTATION'],
  ['sealed-raw-frame', (f)=>{ const x=JSON.parse(readFileSync(resolve(f.dir,'MANIFEST.json')));x.entries[0].fileDigest.frame='utf8(domain)||raw-file-bytes';writeFileSync(resolve(f.dir,'MANIFEST.json'),`${canonicalJson(x)}\n`); },'MANIFEST_SCHEMA'],
  ['sealed-entry-order', (f)=>{ const x=JSON.parse(readFileSync(resolve(f.dir,'MANIFEST.json')));x.entries.reverse();writeFileSync(resolve(f.dir,'MANIFEST.json'),`${canonicalJson(x)}\n`); },'SEALED_MANIFEST:ORDER'],
  ['sealed-roster', (f)=>{ const x=JSON.parse(readFileSync(resolve(f.dir,'MANIFEST.json')));x.rosterDigest.value='0'.repeat(64);writeFileSync(resolve(f.dir,'MANIFEST.json'),`${canonicalJson(x)}\n`); },'SEALED_MANIFEST_RECOMPUTATION'],
  ['sealed-sums', (f)=>writeFileSync(resolve(f.dir,'SHA256SUMS'),'0'.repeat(64)+'  COMMAND.txt\n'),'SEALED_SUMS_RECOMPUTATION']
]) { const f=sealedFixture(); try { mutate(f); f.pin=reviewAnchorPin(f.dir,f.anchorRoot); expectNegative(name, () => validateStatic({packageRoot:f.dir,repositoryRoot:repository,mode:'sealed',reviewAnchorPin:f.pin}), code); } finally { cleanupSealed(f); } }
{ const f=sealedFixture(); try { rmSync(resolve(f.dir,'SHA256SUMS')); expectNegative('sealed partial envelope', () => validateStatic({packageRoot:f.dir,repositoryRoot:repository,mode:'sealed',reviewAnchorPin:f.pin}), 'SEALED_ENVELOPE_REQUIRED'); } finally { cleanupSealed(f); } }
{ const f=sealedFixture(); try { expectNegative('sealed bytes in unsealed mode', () => validateStatic({packageRoot:f.dir,repositoryRoot:repository,mode:'unsealed'}), 'UNSEALED_ENVELOPE_ABSENT'); } finally { cleanupSealed(f); } }
{ const f=sealedFixture(), linkRoot=mkdtempSync(resolve(repository,'.gate-b0r-link-')); try { const target=resolve(f.dir,'README.md'), outside=resolve(linkRoot,'readme-copy'); writeFileSync(outside,readFileSync(target)); rmSync(target); linkSync(outside,target); expectNegative('sealed package hardlink', () => validateStatic({packageRoot:f.dir,repositoryRoot:repository,mode:'sealed',reviewAnchorPin:f.pin}), 'PACKAGE_METADATA:README.md'); } finally { rmSync(linkRoot,{recursive:true,force:true}); cleanupSealed(f); } }
{ const f=sealedFixture(); try { const originalPin=structuredClone(f.pin); const replacementRoot=mkdtempSync(resolve(tmpdir(),'gate-b0r-replacement-anchor-')); try { const schemaPath=resolve(f.dir,'schemas/root.v1.schema.json'); const schema=JSON.parse(readFileSync(schemaPath)); schema.properties.replacementMarker={const:'replacement'}; schema.required.push('replacementMarker'); writeFileSync(schemaPath,`${canonicalJson(schema)}\n`); const model=JSON.parse(readFileSync(resolve(f.dir,'evidence-plan-root.v1.json'))); model.replacementMarker='replacement'; redigest(model); writeRoot(f.dir,model); writeFileSync(resolve(f.dir,'validate-static.mjs'),`${readFileSync(resolve(f.dir,'validate-static.mjs'),'utf8')}\n// replacement-local-validator\n`); const envelope=seal(f.dir); const replacementPin=reviewAnchorPin(f.dir,replacementRoot,envelope); const replacement=await import(`${pathToFileURL(resolve(f.dir,'validate-static.mjs')).href}?replacement=${Date.now()}`); replacement.validateStatic({packageRoot:f.dir,repositoryRoot:repository,mode:'sealed',reviewAnchorPin:replacementPin}); expectNegative('coordinated local replacement rejected by original anchor', () => validateStatic({packageRoot:f.dir,repositoryRoot:repository,mode:'sealed',reviewAnchorPin:originalPin}), 'SEALED_EXTERNAL_ANCHOR_ROOT_RAW'); } finally { rmSync(replacementRoot,{recursive:true,force:true}); } } finally { cleanupSealed(f); } }

const p0Source=resolve(repository,'research-lanes/bch-shielded-pool-design/spec/p0-freeze-manifest.json');
const p0Authority=()=>JSON.parse(readFileSync(resolve(root,'evidence-plan-root.v1.json'))).authorityProjection.authorities[2];
const p0Fixture=()=>{const dir=mkdtempSync(resolve(tmpdir(),'gate-b0r-p0-'));const manifest=JSON.parse(readFileSync(p0Source));const manifestPath=resolve(dir,'lane/spec/p0-freeze-manifest.json');mkdirSync(dirname(manifestPath),{recursive:true});for(const row of manifest.artifacts){const src=resolve(repository,'research-lanes/bch-shielded-pool-design',row.path),dst=resolve(dir,'lane',row.path);mkdirSync(dirname(dst),{recursive:true});cpSync(src,dst,{dereference:false});}writeFileSync(manifestPath,`${canonicalJson(manifest)}\n`);return {dir,manifestPath};};
const pinnedP0Authority=(fixture, update={})=>{const bytes=readFileSync(fixture.manifestPath);return {...p0Authority(),...update,bytes:bytes.length,rawSha256:sha256(bytes)};};
const expectP0Fail=(name, mutate, code)=>{const f=p0Fixture();try{const manifest=JSON.parse(readFileSync(f.manifestPath));const update=mutate(f,manifest)||{};if(update.write!==false)writeFileSync(f.manifestPath,`${canonicalJson(manifest)}\n`);expectNegative(name,()=>assertP0FreezeManifest(f.dir,pinnedP0Authority(f,update.authority||{}),{manifestLocator:'lane/spec/p0-freeze-manifest.json',lanePrefix:'lane/'}),code);}finally{rmSync(f.dir,{recursive:true,force:true});}};
expectP0Fail('p0 count',(_,m)=>{m.artifacts.pop();},'P0_MANIFEST_SHAPE');
expectP0Fail('p0 traversal',(_,m)=>{m.artifacts[0].path='../escape';m.artifacts.sort((a,b)=>a.path.localeCompare(b.path));},'P0_LEAF_RELATIVE:SEGMENT');
expectP0Fail('p0 prefix',(_,m)=>{m.artifacts[0].path='research-lanes/escape';m.artifacts.sort((a,b)=>a.path.localeCompare(b.path));},'P0_LEAF_PREFIX');
expectP0Fail('p0 order',(_,m)=>{[m.artifacts[0],m.artifacts[1]]=[m.artifacts[1],m.artifacts[0]];},'P0_LEAF_ORDER');
expectP0Fail('p0 duplicate',(_,m)=>{m.artifacts[1].path=m.artifacts[0].path;m.artifacts.sort((a,b)=>a.path.localeCompare(b.path));},'P0_LEAF_ORDER');
expectP0Fail('p0 leaf raw',(f,m)=>{writeFileSync(resolve(f.dir,'lane',m.artifacts[0].path),'tampered');return {write:false};},'P0_LEAF_RAW');
expectP0Fail('p0 leaf hardlink',(f,m)=>{const leaf=resolve(f.dir,'lane',m.artifacts[0].path),outside=resolve(f.dir,'p0-leaf-copy');writeFileSync(outside,readFileSync(leaf));rmSync(leaf);linkSync(outside,leaf);return {write:false};},'P0_LEAF:LINK_OR_TYPE');
expectP0Fail('p0 aggregate',(_,m)=>{m.aggregate.sha256='0'.repeat(64);return {authority:{aggregateSha256:'0'.repeat(64)}};},'P0_AGGREGATE');
console.log(`PASS causal mutations=${negativeAssertions} cli-negatives=${cliNegativeAssertions} sealed-positive=${sealedPositiveAssertions}`);
