import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { AUTHORIZATION_DOMAIN, AUTHORIZATION_REL, CLAIM_REL, FAILURE_REL, OUTPUT_REL, SUCCESS_REL, buildAccountingProjection, buildAuthorizationTemplate, expectedEndpoints, staticSourceClosure, validateAuthorizationObject, validateSealedV3Authority, validateStaticExecutor } from './authority.mjs';
import { buildAtomicAttemptPlan } from './static-executor.mjs';
import { digestRecord, omit } from '../cohort-execution-v3/contract.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const workspace = path.resolve(here, '../../../../..');

test('static executor validates without authorization, output, child process, or engine work', () => {
  const checked = validateStaticExecutor(); assert.equal(checked.status, 'PASS');
  assert.equal(fs.existsSync(path.join(workspace, AUTHORIZATION_REL)), false); assert.equal(fs.existsSync(path.join(workspace, CLAIM_REL)), false); assert.equal(fs.existsSync(path.join(workspace, OUTPUT_REL)), false);
});
test('future authorization template has exact five frozen endpoint descriptors and current source/runtime closures', () => {
  const template = buildAuthorizationTemplate(); const checked = validateAuthorizationObject(template);
  assert.equal(checked.status, 'PASS'); assert.equal(template.endpoints.length, 5);
  assert.deepEqual(template.endpoints.map(x => `${x.engineId}/${x.endpointRole}/${x.endpointKind}`), ['engine:native/primary/module-ndjson', 'engine:libauth/primary/module-ndjson', 'engine:bchn/primary/external-process', 'engine:leanbch/primary/external-process', 'engine:leanbch/secondary/external-process']);
  assert.equal(template.runtimeDependencyTrees.length, 5); assert.ok(template.sourceBindings.length >= 5);
});
test('future authorization rejects endpoint, runtime, source, schedule, and digest substitutions', () => {
  for (const mutate of [
    value => { [value.endpoints[3], value.endpoints[4]] = [value.endpoints[4], value.endpoints[3]]; },
    value => { value.endpoints[0].invocation.runtime.version = 'forged'; },
    value => { value.sourceBindings[0].rawSha256 = '0'.repeat(64); },
    value => { value.schedule.maxConcurrency = 2; },
    value => { value.attempt.claimPath = value.attempt.authorizationPath; },
    value => { value.contentDigest.domain = 'forged-domain'; },
  ]) { const value = structuredClone(buildAuthorizationTemplate()); mutate(value); if (value.contentDigest.domain === AUTHORIZATION_DOMAIN) value.contentDigest = digestRecord(omit(value), AUTHORIZATION_DOMAIN); assert.throws(() => validateAuthorizationObject(value), /deterministic|schema|digest/); }
});
test('authorization schema is strict and static authority transport path is exact and absent', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(here, 'authorization.v3.schema.json'))); const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  const value = buildAuthorizationTemplate(); assert.equal(validate(value), true);
  const extra = structuredClone(value); extra.extra = null; assert.equal(validate(extra), false);
  assert.throws(() => validateSealedV3Authority(), /absent|ENOENT|no such/i);
  assert.notEqual(AUTHORIZATION_REL, CLAIM_REL); assert.equal(FAILURE_REL, `${OUTPUT_REL}/failure`); assert.equal(SUCCESS_REL, `${OUTPUT_REL}/success`);
});
test('static closure is process-free and accounting projection requires concrete authorization bytes', () => {
  const closure = staticSourceClosure(); assert.ok(closure.some(x => x.path.endsWith('/authority.mjs'))); assert.ok(closure.every(x => x.path.startsWith('research-lanes/')));
  const template = buildAuthorizationTemplate(); assert.throws(() => buildAccountingProjection(template, null, null), /byte binding/);
  const binding = { path: AUTHORIZATION_REL, rawSha256: 'a'.repeat(64), contentDigest: template.contentDigest };
  const claim = { path: CLAIM_REL, rawSha256: 'b'.repeat(64), contentDigest: { algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain: 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3/root', frame: 'utf8(domain)||0x00||canonical-json-utf8', value: 'c'.repeat(64) } };
  const projection = buildAccountingProjection(template, binding, claim); assert.equal(projection.attemptIndex, 1); assert.equal(projection.outputPaths.failureRoot, path.join(workspace, FAILURE_REL)); assert.deepEqual(Object.keys(projection).sort(), ['attemptIndex', 'authorization', 'claim', 'contract', 'endpoints', 'epoch', 'limits', 'outputPaths', 'retry']);
  assert.equal(projection.endpoints[0].invocation.runtime.executable, template.runtime.executable); assert.notEqual(projection.endpoints[0].invocation.runtime.executable, template.endpoints[0].invocation.entrypointBinding.realpath); assert.equal(projection.endpoints[2].invocation.runtime.executable, template.endpoints[2].invocation.entrypointBinding.realpath);
});
test('atomic whole-attempt plan fixes external claim, 26 payloads, and mutually exclusive terminals', () => {
  const plan = buildAtomicAttemptPlan({ attempt: { outputRoot: OUTPUT_REL, successRoot: SUCCESS_REL, failureRoot: FAILURE_REL, claimPath: CLAIM_REL } });
  assert.deepEqual(plan.terminalChildren, ['success', 'failure']); assert.equal(plan.successPayloadCount, 26); assert.equal(plan.successContainerFileCount, 28); assert.equal(plan.partialReuse, false); assert.match(plan.claim.creation, /exclusive-no-follow/);
});
