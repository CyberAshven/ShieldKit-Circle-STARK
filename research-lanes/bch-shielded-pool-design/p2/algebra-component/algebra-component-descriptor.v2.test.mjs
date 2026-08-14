import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import Ajv2020 from 'ajv/dist/2020.js';

import {
  EXPECTED_CONSTRUCTIONS,
  UPSTREAM,
  contentDigestFor,
  normalizedCertificateStatementDigest,
  validateFinalExternalReviewShape,
  validateDescriptorV2,
} from './algebra-component-descriptor-v2.mjs';

const schema = JSON.parse(readFileSync(new URL('./algebra-component-descriptor.v2.schema.json', import.meta.url), 'utf8'));
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const descriptors = EXPECTED_CONSTRUCTIONS.map((item) => JSON.parse(readFileSync(new URL('./descriptors/' + item.fileName, import.meta.url), 'utf8')));
const clone = (value) => structuredClone(value);
const refresh = (value) => { value.contentDigest.value = contentDigestFor(value); return value; };
const validSchema = (value) => validateSchema(value);
const semanticErrors = (value) => validateDescriptorV2(value);
const expectSemanticFailure = (value, needle) => {
  assert.equal(validSchema(value), true, JSON.stringify(validateSchema.errors));
  assert.ok(semanticErrors(value).some((item) => item.includes(needle)), semanticErrors(value).join('; '));
};
const externalReview = JSON.parse(readFileSync(new URL('../field-cert/external-direct-construction-cohort-v2/external-review.v2.json', import.meta.url), 'utf8'));
const externalReviewSchema = JSON.parse(readFileSync(new URL('../field-cert/external-direct-construction-cohort-v2/external-review.v2.schema.json', import.meta.url), 'utf8'));
const certificateSet = JSON.parse(readFileSync(new URL('../field-cert/direct-construction-cohort-v2/direct-construction-cohort-v2.v2.json', import.meta.url), 'utf8'));

test('all four v2 descriptors are strict, direct-only, complete, and nonexecutable', () => {
  assert.equal(descriptors.length, 4);
  assert.deepEqual(descriptors.map((item) => item.lineage.constructionId), EXPECTED_CONSTRUCTIONS.map((item) => item.constructionId));
  assert.deepEqual(descriptors.map((item) => item.scheduleArmBindings.length), [2, 3, 3, 6]);
  for (const descriptor of descriptors) {
    assert.equal(validSchema(descriptor), true, JSON.stringify(validateSchema.errors));
    assert.deepEqual(semanticErrors(descriptor), []);
    assert.equal(descriptor.status, 'frozen-cohort-formula-bound-nonexecutable');
    assert.equal(descriptor.qualification.selection, 'none');
    assert.equal(descriptor.qualification.tupleRef, null);
    assert.equal(descriptor.executionBoundary.executionAllowed, false);
    assert.equal(descriptor.scheduleFreezeBinding.resolvedPermutation, null);
    assert.equal(descriptor.executionBoundary.presentDownstreamBindings.length, 0);
  }
});

test('descriptor digest and unsafe numeric field values fail closed', () => {
  const stale = clone(descriptors[0]);
  stale.contentDigest.value = '0'.repeat(64);
  assert.ok(semanticErrors(stale).some((item) => item.includes('content digest')));

  const unsafeNumber = refresh(clone(descriptors[0]));
  unsafeNumber.directQuotient.p = Number(unsafeNumber.directQuotient.p);
  refresh(unsafeNumber);
  assert.equal(validSchema(unsafeNumber), false);
});

test('alternate/tower algebra and codec, including a late high-bit check, fail closed', () => {
  const towerCodec = refresh(clone(descriptors[3]));
  towerCodec.canonicalCodec.basis = 'tower-basis';
  refresh(towerCodec);
  assert.equal(validSchema(towerCodec), false);

  const towerAlgebra = refresh(clone(descriptors[3]));
  towerAlgebra.algebra = { kind: 'tower', codecId: 'codec:tower' };
  refresh(towerAlgebra);
  assert.equal(validSchema(towerAlgebra), false);

  const lateHighBit = refresh(clone(descriptors[0]));
  const steps = lateHighBit.canonicalCodec.parserSteps;
  [steps[2], steps[3]] = [steps[3], steps[2]];
  refresh(lateHighBit);
  assert.equal(validSchema(lateHighBit), false);
});

test('every frozen schedule arm is required and arm digests are exact', () => {
  const missing = refresh(clone(descriptors[3]));
  missing.scheduleArmBindings.pop();
  missing.symbolicBounds.perArmCounts.pop();
  refresh(missing);
  expectSemanticFailure(missing, 'schedule arm roster');

  const duplicate = refresh(clone(descriptors[1]));
  duplicate.scheduleArmBindings[2] = clone(duplicate.scheduleArmBindings[1]);
  duplicate.symbolicBounds.perArmCounts[2] = clone(duplicate.symbolicBounds.perArmCounts[1]);
  refresh(duplicate);
  expectSemanticFailure(duplicate, 'schedule arm roster');

  const changedDigest = refresh(clone(descriptors[2]));
  changedDigest.scheduleArmBindings[1].armDigest = '1'.repeat(64);
  refresh(changedDigest);
  expectSemanticFailure(changedDigest, 'schedule arm roster');

  const changedArm = refresh(clone(descriptors[0]));
  changedArm.scheduleArmBindings[1].algorithmId = 'algorithm:unfrozen-v2';
  refresh(changedArm);
  expectSemanticFailure(changedArm, 'schedule arm roster');

  const selected = refresh(clone(descriptors[0]));
  selected.selectedArmId = selected.scheduleArmBindings[0].armId;
  refresh(selected);
  assert.equal(validSchema(selected), false);
});

test('both checker families, certificate statement, certificate digest, and source pins are mandatory', () => {
  const missingExternal = refresh(clone(descriptors[0]));
  missingExternal.certificateBinding.checkerFamilies.pop();
  refresh(missingExternal);
  assert.equal(validSchema(missingExternal), false);

  const duplicateRepository = refresh(clone(descriptors[0]));
  duplicateRepository.certificateBinding.checkerFamilies[1].family = 'repository-rabin-replay';
  refresh(duplicateRepository);
  expectSemanticFailure(duplicateRepository, 'checker families');

  const statement = refresh(clone(descriptors[1]));
  statement.certificateBinding.normalizedStatementDigest = '2'.repeat(64);
  refresh(statement);
  expectSemanticFailure(statement, 'certificate statement/digest');

  const certificate = refresh(clone(descriptors[2]));
  certificate.certificateBinding.certificateDigest = '3'.repeat(64);
  refresh(certificate);
  expectSemanticFailure(certificate, 'certificate statement/digest');

  const source = refresh(clone(descriptors[3]));
  source.sourcePins.referenceDirectExtension.sha256 = '4'.repeat(64);
  refresh(source);
  expectSemanticFailure(source, 'direct extension source binding');

  assert.match(normalizedCertificateStatementDigest({
    certificateEntryId: descriptors[0].lineage.certificateEntryId,
    constructionId: descriptors[0].lineage.constructionId,
    fieldSpecRef: descriptors[0].lineage.fieldSpecRef,
    q: descriptors[0].directQuotient.q,
    p: descriptors[0].directQuotient.p,
    degree: descriptors[0].directQuotient.degree,
    polynomialCanonical: descriptors[0].directQuotient.definingPolynomialAscending,
  }), /^[0-9a-f]{64}$/u);
});

test('final external review is one dual-method external artifact and its exact final shape fails closed', () => {
  assert.deepEqual(validateFinalExternalReviewShape(externalReview, externalReviewSchema, certificateSet), []);

  const failedVerdict = clone(externalReview);
  failedVerdict.finalVerdict = 'FAIL';
  assert.ok(validateFinalExternalReviewShape(failedVerdict, externalReviewSchema, certificateSet).some((item) => item.includes('final PASS')));

  const wrongInput = clone(externalReview);
  wrongInput.inputBindings[0].contentDigest = '7'.repeat(64);
  wrongInput.contentDigest = contentDigestFor(wrongInput);
  assert.ok(validateFinalExternalReviewShape(wrongInput, externalReviewSchema, certificateSet).some((item) => item.includes('certificate-set')));

  const missingMethod = clone(externalReview);
  delete missingMethod.entries[0].checkerVerdicts['sympy-cas-irreducibility'];
  missingMethod.contentDigest = contentDigestFor(missingMethod);
  assert.ok(validateFinalExternalReviewShape(missingMethod, externalReviewSchema, certificateSet).some((item) => item.includes('dual-method')));

  const badStatement = clone(externalReview);
  badStatement.entries[0].statementDigest = '8'.repeat(64);
  badStatement.contentDigest = contentDigestFor(badStatement);
  assert.ok(validateFinalExternalReviewShape(badStatement, externalReviewSchema, certificateSet).some((item) => item.includes('dual-method')));
});

test('measurement, protocol, campaign, resolved-order, legacy-evidence, and stale-pin inflation fail closed', () => {
  const measured = refresh(clone(descriptors[0]));
  measured.symbolicBounds.vmMetrics = { opcodes: 1 };
  refresh(measured);
  assert.equal(validSchema(measured), false);

  const protocol = refresh(clone(descriptors[0]));
  protocol.protocolBoundary.circleDomain = 'circle:domain';
  refresh(protocol);
  assert.equal(validSchema(protocol), false);

  const campaign = refresh(clone(descriptors[0]));
  campaign.executionBoundary.campaignDigest = '5'.repeat(64);
  refresh(campaign);
  assert.equal(validSchema(campaign), false);

  const resolvedOrder = refresh(clone(descriptors[0]));
  resolvedOrder.scheduleFreezeBinding.resolvedPermutation = [resolvedOrder.scheduleArmBindings[0].armId];
  refresh(resolvedOrder);
  assert.equal(validSchema(resolvedOrder), false);

  const legacyEvidence = refresh(clone(descriptors[0]));
  legacyEvidence.legacyLineage.cohortEvidenceEligible = true;
  refresh(legacyEvidence);
  assert.equal(validSchema(legacyEvidence), false);

  const staleUpstream = refresh(clone(descriptors[3]));
  staleUpstream.scheduleFreezeBinding.artifact.fileSha256 = '6'.repeat(64);
  refresh(staleUpstream);
  expectSemanticFailure(staleUpstream, 'schedule freeze binding');
});

test('unknown fields are schema failures and legacy v1 remains byte-pinned shakedown-only', () => {
  const unknown = refresh(clone(descriptors[0]));
  unknown.unreviewedPromotion = 'forbidden';
  refresh(unknown);
  assert.equal(validSchema(unknown), false);

  assert.equal(descriptors[0].legacyLineage.descriptorFileSha256, UPSTREAM.legacyM89.fileSha256);
  assert.equal(descriptors[0].legacyLineage.descriptorContentDigest, UPSTREAM.legacyM89.contentDigest);
  assert.equal(descriptors[0].legacyLineage.cohortEvidenceEligible, false);
  for (const descriptor of descriptors.slice(1)) assert.equal(descriptor.legacyLineage, null);
});
