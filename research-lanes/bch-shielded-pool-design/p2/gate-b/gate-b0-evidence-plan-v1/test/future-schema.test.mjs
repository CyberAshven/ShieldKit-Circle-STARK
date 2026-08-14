import assert from 'node:assert/strict';
import Ajv2020 from 'ajv/dist/2020.js';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertFutureAdversarialCase, assertFutureManifest, assertFutureMeasurementResult, canonicalDigestRecord, rawFileDigest } from '../validate-static.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const load = name => JSON.parse(readFileSync(resolve(root, 'schemas', name)));
const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: true });
let negativeKats = 0;
const expectKATFailure = (name, attempt, expected) => { assert.throws(attempt, new RegExp(expected), name); negativeKats += 1; };
const expectSchemaInvalid = (name, validator, value) => { assert.equal(validator(value), false, name); negativeKats += 1; };
for (const name of ['digest.v1.schema.json','kill-gate.v1.schema.json','manifest.v1.schema.json','measurement-result.v2.schema.json','adversarial-case.v2.schema.json']) ajv.addSchema(load(name));
const hex = 'a'.repeat(64);
const artifact = (artifactId, bytes, locator = `future/${artifactId.replace(':','-')}`) => ({ artifactId, bytes, locator, rawSha256: hex });
const input = x => ({ artifactId:x.artifactId, bytes:x.bytes, rawSha256:x.rawSha256 });
const measurementAuthority = Object.freeze([artifact('artifact:input',4),artifact('artifact:source',1)]);
const measurementInput = structuredClone(measurementAuthority[0]);
const full = { algorithmId:'FULL_BYTE_CONSUMPTION_ORDERED_SPANS_V1',domain:'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/measurement/full-consumption-derivation',inputArtifacts:[input(measurementInput)],segments:[{end:4,semanticRole:'PAYLOAD',start:0}] };
full.digest = canonicalDigestRecord(full.domain,{algorithmId:full.algorithmId,inputArtifacts:full.inputArtifacts,segments:full.segments});
const metricDerivation = { algorithmId:'METRIC_FORMULA_EVALUATION_V1',domain:'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/measurement/metric-derivation',formulaId:'RAW_ARTIFACT_BYTE_LENGTH_V1',inputArtifacts:[input(measurementInput)],metricRef:'metric:future:bytes',unit:'BYTES',value:{kind:'INTEGER',value:4} };
metricDerivation.digest = canonicalDigestRecord(metricDerivation.domain,{algorithmId:metricDerivation.algorithmId,formulaId:metricDerivation.formulaId,inputArtifacts:metricDerivation.inputArtifacts,metricRef:metricDerivation.metricRef,unit:metricDerivation.unit,value:metricDerivation.value});
const measurement = { argv:['future-runner'],byteFullConsumptionDerivation:full,engineApplicability:{commandContractDigest:hex,kind:'EXACT_MODEL_PIN',locator:'future/model',rawSha256:hex,symbol:'future_symbol'},engineIdentity:'engine:native',environment:{entries:[{key:'LANG',valueSha256:hex}]},exit:{logSha256:hex,outcome:{kind:'EXITED',value:0}},hostProfile:{id:'profile:future',rawSha256:hex},metricDerivations:[{derivation:metricDerivation,metricRef:'metric:future:bytes',sourceArtifactIds:['artifact:input'],unit:'BYTES',value:{kind:'INTEGER',value:4}}],planDigest:hex,rawArtifacts:[measurementInput],sourceClosure:[structuredClone(measurementAuthority[1])],workingDirectory:'future'};
// This map is an independently authored caller-side authority, never a map of
// the candidate record's own artifact objects.
const measurementPins = new Map(measurementAuthority.map(x=>[x.artifactId,x]));
const mv = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/gate-b0-evidence-plan/v1/measurement-result.v2.schema.json');
assert(mv(measurement), ajv.errorsText(mv.errors)); assertFutureMeasurementResult(measurement,{artifactPins:measurementPins});
for (const [name, mutate, code] of [
  ['duplicate-env', x => x.environment.entries.push({key:'LANG',valueSha256:hex}),'ENVIRONMENT_KEY_DUPLICATE'],
  ['overlap', x => x.byteFullConsumptionDerivation.segments=[{end:3,semanticRole:'A',start:0},{end:4,semanticRole:'B',start:2}],'SEGMENT_CONTIGUITY'],
  ['short-full-consumption', x => x.byteFullConsumptionDerivation.segments=[{end:3,semanticRole:'PAYLOAD',start:0}],'FULL_CONSUMPTION'],
  ['segment-gap', x => x.byteFullConsumptionDerivation.segments=[{end:2,semanticRole:'A',start:0},{end:4,semanticRole:'B',start:3}],'SEGMENT_CONTIGUITY'],
  ['wrong-domain', x => { x.byteFullConsumptionDerivation.domain='shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/measurement/other'; x.byteFullConsumptionDerivation.digest=canonicalDigestRecord(x.byteFullConsumptionDerivation.domain,{algorithmId:x.byteFullConsumptionDerivation.algorithmId,inputArtifacts:x.byteFullConsumptionDerivation.inputArtifacts,segments:x.byteFullConsumptionDerivation.segments}); },'FULL_DOMAIN'],
  ['wrong-full-digest', x => x.byteFullConsumptionDerivation.digest.value='0'.repeat(64),'FULL_DIGEST'],
  ['wrong-preimage', x => x.metricDerivations[0].derivation.inputArtifacts[0].rawSha256='b'.repeat(64),'METRIC_SOURCE_ARTIFACT'],
  ['wrong-value', x => { x.metricDerivations[0].value.value=5; x.metricDerivations[0].derivation.value.value=5; },'METRIC_FORMULA_VALUE'],
  ['wrong-digest', x => x.metricDerivations[0].derivation.digest.value='0'.repeat(64),'METRIC_DIGEST']
]) { const x=structuredClone(measurement); mutate(x); expectKATFailure(name,()=>assertFutureMeasurementResult(x,{artifactPins:measurementPins}),code); }
expectKATFailure('measurement pins required',()=>assertFutureMeasurementResult(measurement),'ARTIFACT_PINS_REQUIRED');

const adversarialAuthority = Object.freeze([artifact('artifact:base',8,'future/base.bin'),artifact('artifact:replacement',2,'future/replacement.bin'),artifact('artifact:insert',2,'future/insert.bin'),artifact('artifact:permutation',2,'future/permutation.bin')]);
const payload = structuredClone(adversarialAuthority[1]);
const adversarial={attemptAccounting:{firstAttempt:1,retryCount:0},baseArtifact:structuredClone(adversarialAuthority[0]),engineCoverage:['engine:native'],expectedEffect:{kind:'REJECT_ERROR_CODE',value:'PARSE_REJECT'},mutation:{operator:'REPLACE',replacementArtifactId:'artifact:replacement',targetPointer:'/field'},mutationArtifacts:[payload,structuredClone(adversarialAuthority[2]),structuredClone(adversarialAuthority[3])],responsibilityRefs:['responsibility:future'],threatRefs:['threat:future']};
const av = ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/gate-b0-evidence-plan/v1/adversarial-case.v2.schema.json');
assert(av(adversarial), ajv.errorsText(av.errors)); const pins=new Map(adversarialAuthority.map(x=>[x.artifactId,x])); assertFutureAdversarialCase(adversarial,{artifactPins:pins});
for (const [name, mutate, code] of [
  ['retry',x=>x.attemptAccounting.retryCount=1,'RETRY_POLICY'],
  ['missing-payload',x=>x.mutation.replacementArtifactId='artifact:missing','MUTATION_ARTIFACT'],
  ['wrong-hash',x=>x.mutationArtifacts[0].rawSha256='b'.repeat(64),'PINNED_ARTIFACT'],
  ['wrong-locator',x=>x.mutationArtifacts[0].locator='future/elsewhere.bin','PINNED_ARTIFACT']
]) { const x=structuredClone(adversarial);mutate(x);expectKATFailure(name,()=>assertFutureAdversarialCase(x,{artifactPins:pins}),code); }
for (const [name, operator, artifactKey] of [['insert','INSERT','payloadArtifactId'],['reorder','REORDER','permutationArtifactId']]) {
  const missing=structuredClone(adversarial);missing.mutation={operator,[artifactKey]:'artifact:missing',targetPointer:'/field'};expectKATFailure(`${name}-missing-artifact`,()=>assertFutureAdversarialCase(missing,{artifactPins:pins}),'MUTATION_ARTIFACT');
  const wrong=structuredClone(adversarial);wrong.mutation={operator,[artifactKey]:operator==='INSERT'?'artifact:insert':'artifact:permutation',targetPointer:'/field'};wrong.mutationArtifacts.find(x=>x.artifactId===wrong.mutation[artifactKey]).rawSha256='b'.repeat(64);expectKATFailure(`${name}-wrong-artifact`,()=>assertFutureAdversarialCase(wrong,{artifactPins:pins}),'PINNED_ARTIFACT');
}
expectKATFailure('adversarial pins required',()=>assertFutureAdversarialCase(adversarial),'ARTIFACT_PINS_REQUIRED');
const bit=structuredClone(adversarial);bit.mutation={bitMask:1,operator:'BIT_FLIP',targetRange:{end:Number.MAX_SAFE_INTEGER,start:0}};bit.mutationArtifacts=[];expectKATFailure('huge bit flip',()=>assertFutureAdversarialCase(bit,{artifactPins:new Map([[bit.baseArtifact.artifactId,adversarialAuthority[0]]])}),'BYTE_RANGE');

const digest = domain => canonicalDigestRecord(domain,{future:true});
const gate = {comparison:'LESS_THAN_OR_EQUAL',gateId:'kill-gate:future',metricRef:'metric:future',quantifier:'ALL_SCOPE_ITEMS',scope:'future',status:'PENDING',thresholdRef:'threshold:future'};
const gv=ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/gate-b0-evidence-plan/v1/kill-gate.v1.schema.json');assert(gv(gate),ajv.errorsText(gv.errors));const badGate={...gate,eliminationEvidence:{derivationDigest:digest('shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/future'),measurementResultRef:'measurement-result:future',planDigest:digest('shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/future-plan')}};expectSchemaInvalid('pending kill gate cannot self-certify elimination',gv,badGate);
const rawA=Buffer.from('a'),rawB=Buffer.from('bb');
const entries=[{bytes:1,fileDigest:rawFileDigest('a.json',rawA),locator:'a.json',sha256:'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'},{bytes:2,fileDigest:rawFileDigest('b.json',rawB),locator:'b.json',sha256:'3b64db95cb55c763391c707108489ae18b4112d783300de38a9d7a4b3420d5f0'}];
const manifest={entryCount:2,entries,format:'canonical-json-and-raw-file-sha256-lf-v1',package:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-evidence-plan-v1',rosterDigest:canonicalDigestRecord('shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/manifest-roster',entries),schema:'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/manifest/v1'};
const xv=ajv.getSchema('https://shieldkit-labs.local/p2/gate-b/gate-b0-evidence-plan/v1/manifest.v1.schema.json');assert(xv(manifest),ajv.errorsText(xv.errors));assertFutureManifest(manifest);const unordered=structuredClone(manifest);unordered.entries.reverse();expectKATFailure('manifest order',()=>assertFutureManifest(unordered),'ORDER');
const anchorEntries=Array.from({length:15},(_,i)=>{const locator=`f${String(i).padStart(2,'0')}.txt`,bytes=Buffer.from(String(i));return {bytes:bytes.length,fileDigest:rawFileDigest(locator,bytes),locator,sha256:hex};});
const falseBoundary={candidateCount:0,candidateTupleCount:0,executionAllowed:false,fallbackAuthorizationAllowed:false,measurementAdmissionAllowed:false,parameterAssignmentCount:0,providerInstanceCount:0,qualificationAllowed:false,rankingAllowed:false,roleAssignmentCount:0,selectionAllowed:false,status:'static-nonauthorizing-unqualified-plan-only-no-candidates-no-execution-no-selection',unavailableStatePolicy:'TAGGED_STATE_NEVER_NULL'};
const reviewAnchor={entryCount:15,laneProjectionDigest:digest('shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/lane-authority-projection'),manifestRawSha256:hex,nonAuthorityBoundary:falseBoundary,orderedClosure:anchorEntries,p0Freeze:{aggregateSha256:hex,expectedLeafCount:11,manifestRawSha256:hex},package:'research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-evidence-plan-v1',rootContentDigest:digest('shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/root'),rootRawSha256:hex,rosterDigest:canonicalDigestRecord('shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/manifest-roster',anchorEntries),schema:'shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/external-review-anchor/v1',sha256SumsRawSha256:hex,validatorRawSha256:hex};
const anchorValidator=ajv.compile({$ref:'https://shieldkit-labs.local/p2/gate-b/gate-b0-evidence-plan/v1/manifest.v1.schema.json#/$defs/externalReviewAnchor'});assert(anchorValidator(reviewAnchor),ajv.errorsText(anchorValidator.errors));const extraAnchor={...reviewAnchor,untrusted:true};expectSchemaInvalid('anchor closes extra fields',anchorValidator,extraAnchor);
console.log(`PASS future schema causal-negatives=${negativeKats}`);
