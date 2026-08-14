import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

import { contentDigestFor, validateDescriptor } from './algebra-component-validation.mjs';

const load = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const schema = load('./algebra-component-descriptor.v1.schema.json');
const descriptor = load('./descriptors/m89-d2-x2-plus-1.v1.json');
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const clone = () => structuredClone(descriptor);
const refresh = (value) => { value.contentDigest.value = contentDigestFor(value); return value; };

test('the exact M89 quadratic descriptor is pinned, algebra-only, and admitted only to Gate-B0', () => {
  assert.equal(validateSchema(descriptor), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(validateDescriptor(descriptor), []);
  assert.equal(descriptor.contentDigest.value, contentDigestFor(descriptor));
  assert.equal(descriptor.qualification.selection, 'none');
  assert.equal(descriptor.protocolBoundary.circleDomain, null);
  assert.equal(descriptor.registryBinding.matrixDigest, '203d2cabb6c12340ce117f1f07018a0c08072a6be87fd1eb0c76952faa9e3185');
  assert.equal(descriptor.intermediateBounds.maxArithmeticIntermediateBytes, 23);
});

test('semantic validation rejects matrix, polynomial, exact-relation, codec, and bound substitution', () => {
  const staleMatrix = refresh(clone());
  staleMatrix.registryBinding.matrixDigest = '4'.repeat(64);
  refresh(staleMatrix);
  assert.ok(validateDescriptor(staleMatrix).some((error) => error.includes('current frozen v2')));

  const polynomial = clone();
  polynomial.algebra.definingPolynomial[0] = '2';
  refresh(polynomial);
  assert.ok(validateDescriptor(polynomial).some((error) => error.includes('X^2+1') || error.includes('certificate polynomial')));

  const relation = clone();
  relation.relations.find((item) => item.operation === 'multiply').equations[0] = 'r0=modp(a0*b0+a1*b1)';
  refresh(relation);
  assert.ok(validateDescriptor(relation).some((error) => error.includes('exact relation formulas')));

  const codec = clone();
  codec.canonicalCodec.unusedHighBitMaskHex = '00';
  refresh(codec);
  assert.ok(validateDescriptor(codec).some((error) => error.includes('unused-high-bit')));

  const bound = clone();
  bound.intermediateBounds.operations.find((item) => item.operation === 'multiply').stages[0].maxSignedMagnitudeBytes = 22;
  refresh(bound);
  assert.ok(validateDescriptor(bound).some((error) => error.includes('signed-magnitude width')));
});

test('certificate replay files and both checker identities bind the same canonical fixture', () => {
  const canonicalDrift = clone();
  canonicalDrift.certificateBundle.extension.checkers[1].canonicalCertificateDigest = '9'.repeat(64);
  refresh(canonicalDrift);
  assert.ok(validateDescriptor(canonicalDrift).some((error) => error.includes('canonical certificate bytes')));

  const dependent = clone();
  dependent.certificateBundle.extension.checkers[1].sourceManifestDigest = dependent.certificateBundle.extension.checkers[0].sourceManifestDigest;
  refresh(dependent);
  assert.ok(validateDescriptor(dependent).some((error) => error.includes('source manifests are not distinct')));

  const missingOutput = clone();
  missingOutput.certificateBundle.extension.checkers[1].outputPath = 'p2/field-cert/external/missing.json';
  refresh(missingOutput);
  assert.ok(validateDescriptor(missingOutput).some((error) => error.includes('output file is missing')));
});

test('schema and semantics fail closed on protocol inflation and stale content', () => {
  for (const mutate of [
    (value) => { value.qualification.selection = 'selected'; },
    (value) => { value.protocolBoundary.protocolRoles.push('E'); },
    (value) => { value.protocolBoundary.circleDomain = 'circle:chosen'; },
    (value) => { value.protocolBoundary.deepStrategy = 'deep:chosen'; },
    (value) => { value.protocolBoundary.hashBindings.push('hash:chosen'); },
    (value) => { value.protocolBoundary.soundnessEventDag = 'soundness:chosen'; },
    (value) => { value.tuple = 'tuple:chosen'; }
  ]) {
    const candidate = clone();
    mutate(candidate);
    assert.equal(validateSchema(candidate), false);
  }

  const stale = clone();
  stale.contentDigest.value = '0'.repeat(64);
  assert.ok(validateDescriptor(stale).some((error) => error.includes('content digest')));

  const unsupportedProfile = clone();
  unsupportedProfile.algebra.semanticProfile = 'algebra-profile:unreviewed-v1';
  refresh(unsupportedProfile);
  assert.ok(validateDescriptor(unsupportedProfile).some((error) => error.includes('no reviewed construction-specific')));
});
