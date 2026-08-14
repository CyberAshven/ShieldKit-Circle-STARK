import Ajv2020 from 'ajv/dist/2020.js';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import {
  FIXED_STATEMENT_CODEC_BLOCKED_AUTHORITY,
  FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY,
  P0_REQUIRED_PROPERTY_NAMES,
  PENDING_SURFACE_KEYS,
  PENDING_SURFACE_MARKERS,
  SAFE_PROTOCOL_PROJECTION_DOMAIN,
  SAFE_PROJECTION_EXCLUSIONS,
  SAFE_PROJECTION_SECTIONS,
  TYPED_SCHEMA_URI,
  assertB0NonAdmittingObservations,
  assertFixedStatementCodecBlockedDependency,
  assertFixedStatementCodecSourceAuthority,
  assertFixedStatementInputValidation,
  assertNoDuplicateJsonKeys,
  assertNonAuthorizingProtocolProjectionDigest,
  assertPendingDescriptorBoundary,
  assertPendingSurfaceMarker,
  assertTypedSchemaRefReachability,
  digestRecord,
  safeProtocolProjectionPreimage
} from '../semantic-validator.mjs';

const schemas = readdirSync(new URL('../schemas/', import.meta.url)).map(name => JSON.parse(readFileSync(new URL(`../schemas/${name}`, import.meta.url))));
const typedSchema = schemas.find(schema => schema.$id === TYPED_SCHEMA_URI);
const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: true });
schemas.forEach(schema => ajv.addSchema(schema));
assert.ok(typedSchema);

const qualificationBoundary = {
  candidateInstantiationAllowed: false,
  executionAllowed: false,
  fallbackAuthorization: { kind: 'NONE' },
  fallbackAuthorized: false,
  providerResolutionAllowed: false,
  qualificationAllowed: false
};
const pendingSurfaces = structuredClone(PENDING_SURFACE_MARKERS);
const projectionDescriptor = Object.fromEntries(SAFE_PROJECTION_SECTIONS.map(section => [section, { section }]));
const projectionPreimage = safeProtocolProjectionPreimage(projectionDescriptor);
assert.deepEqual(Object.keys(projectionPreimage), SAFE_PROJECTION_SECTIONS, 'flat safe projection roster');
assert.equal(Object.hasOwn(projectionPreimage, 'pendingSurfaces'), false, 'no synthetic nested pending surface key');
const projection = {
  contentDigest: digestRecord(SAFE_PROTOCOL_PROJECTION_DOMAIN, projectionPreimage),
  excludedSections: SAFE_PROJECTION_EXCLUSIONS,
  includedSections: SAFE_PROJECTION_SECTIONS,
  kind: 'NONAUTHORIZING_SCHEMA_ARCHITECTURE_PROJECTION_DIGEST'
};
assert.doesNotThrow(() => assertPendingDescriptorBoundary({ pendingSurfaces, protocolProjectionDigest: projection, qualificationBoundary, code: 'PENDING_FRAGMENT' }));
assert.doesNotThrow(() => assertNonAuthorizingProtocolProjectionDigest(projection, 'PROJECTION_VALUE', projectionPreimage));
const staleProjectionValue = structuredClone(projection); staleProjectionValue.contentDigest.value = '00'.repeat(32);
assert.throws(() => assertNonAuthorizingProtocolProjectionDigest(staleProjectionValue, 'PROJECTION_VALUE_MUTANT', projectionPreimage), /PROJECTION_VALUE_MUTANT:DIGEST_VALUE/);
const wrongProjectionDomain = structuredClone(projection); wrongProjectionDomain.contentDigest.domain = 'shieldkit-labs/test/non-authorizing-projection';
assert.throws(() => assertNonAuthorizingProtocolProjectionDigest(wrongProjectionDomain, 'PROJECTION_DOMAIN_MUTANT', projectionPreimage), /PROJECTION_DOMAIN_MUTANT:DIGEST_SHAPE/);
for (const surface of PENDING_SURFACE_KEYS) {
  const validator = ajv.getSchema(`${TYPED_SCHEMA_URI}#/$defs/pendingMarker${surface[0].toUpperCase()}${surface.slice(1)}`);
  assert.ok(validator, surface);
  assert.equal(validator(PENDING_SURFACE_MARKERS[surface]), true, surface);
  const mutated = structuredClone(PENDING_SURFACE_MARKERS[surface]);
  mutated.qualificationEffect = 'QUALIFIES';
  assert.equal(validator(mutated), false, `${surface}:schema marker mutation`);
  assert.throws(() => assertPendingSurfaceMarker(surface, mutated, 'MARKER_MUTANT'), /MARKER_MUTANT/);
}
const extraMarker = structuredClone(PENDING_SURFACE_MARKERS.circle); extraMarker.selector = '/not-permitted';
assert.throws(() => assertPendingSurfaceMarker('circle', extraMarker, 'MARKER_EXTRA'), /MARKER_EXTRA:circle:KEYS/);
const pendingFallback = structuredClone(qualificationBoundary); pendingFallback.fallbackAuthorization = { kind: 'COMPLETE_DUAL_ACTION_OPTIMIZED_128_NONFIT' };
assert.throws(() => assertPendingDescriptorBoundary({ pendingSurfaces, qualificationBoundary: pendingFallback, code: 'FALLBACK_MUTANT' }), /FALLBACK_MUTANT:QUALIFICATION_SHAPE/);
const missingSurface = structuredClone(pendingSurfaces); delete missingSurface.deep;
assert.throws(() => assertPendingDescriptorBoundary({ pendingSurfaces: missingSurface, qualificationBoundary, code: 'MARKER_ROSTER_MUTANT' }), /MARKER_ROSTER_MUTANT:SURFACE_ROSTER/);
const badProjection = structuredClone(projection); badProjection.includedSections = badProjection.includedSections.slice(1);
assert.throws(() => assertNonAuthorizingProtocolProjectionDigest(badProjection, 'PROJECTION_MUTANT'), /PROJECTION_MUTANT:INCLUDED_SECTIONS/);

assert.doesNotThrow(() => assertB0NonAdmittingObservations({ candidateAdmissionAllowed: false, kind: 'B0_SOURCE_PINNED_NONADMITTING_OBSERVATIONS', observationDependencyIds: ['B0_M89_D2', 'B0_M61_D3', 'B0_M31_D5', 'B0_M31_D6'], qualificationEffect: 'NONE' }));
assert.throws(() => assertB0NonAdmittingObservations({ candidateAdmissionAllowed: true, kind: 'B0_SOURCE_PINNED_NONADMITTING_OBSERVATIONS', observationDependencyIds: ['B0_M89_D2', 'B0_M61_D3', 'B0_M31_D5', 'B0_M31_D6'], qualificationEffect: 'NONE' }, 'B0_MUTANT'), /B0_MUTANT:SHAPE/);

assert.doesNotThrow(() => assertFixedStatementCodecBlockedDependency(FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY, 'CODEC_EVIDENCE'));
for (const [name, mutate] of [
  ['LOCATOR', value => { value.componentEvidence[0].locator = 'research-lanes/bch-shielded-pool-design/p1/codec/other.mjs'; }],
  ['BYTES', value => { value.componentEvidence[1].bytes += 1; }],
  ['HASH', value => { value.componentEvidence[2].rawSha256 = '00'.repeat(32); }],
  ['EDGE', value => { value.importEdges[3].toRole = 'TOKEN_VALIDATION'; }],
  ['REMOVAL', value => { value.componentEvidence.pop(); }]
]) {
  const mutated = structuredClone(FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY); mutate(mutated);
  assert.throws(() => assertFixedStatementCodecBlockedDependency(mutated, `CODEC_${name}`), new RegExp(`CODEC_${name}`));
}
assert.doesNotThrow(() => assertFixedStatementCodecSourceAuthority({ authority: FIXED_STATEMENT_CODEC_BLOCKED_AUTHORITY, code: 'CODEC_AUTHORITY' }));
for (const [name, mutate] of [
  ['SELECTOR', value => { value.sourceCatalogEntryRef = 'source:selector-injection'; }],
  ['RESOLUTION', value => { value.digestAdapterAuthorities[0].algorithmRef = 'algorithm:resolved'; }],
  ['ADAPTER', value => { value.digestAdapterAuthorities[1].status = 'RESOLVED_LOCAL_BYTES'; }]
]) {
  const mutated = structuredClone(FIXED_STATEMENT_CODEC_BLOCKED_AUTHORITY); mutate(mutated);
  assert.throws(() => assertFixedStatementCodecSourceAuthority({ authority: mutated, code: `AUTHORITY_${name}` }), new RegExp(`AUTHORITY_${name}`));
}

const selector = path => ({ selector: path, selectorKind: 'JSON_POINTER', sourceRef: 'source:p0-relation-schema' });
const contract = action => ({ action, kind: 'P0_RELATION_SCHEMA_REQUIRED_PROPERTY_SELECTOR_COVERAGE', p0RelationSchemaSelector: selector(''), requiredPropertySelectors: P0_REQUIRED_PROPERTY_NAMES.map(name => selector(`/properties/${name}`)) });
const inputValidation = { actionContracts: [contract('DEPOSIT'), contract('WITHDRAWAL')], authorityRoleRef: 'fixedStatementCodecSourceAuthority', kind: 'P0_RELATION_SCHEMA_JSON_INPUT_VALIDATION', status: 'BLOCKED_EXTERNAL' };
assert.doesNotThrow(() => assertFixedStatementInputValidation(inputValidation, 'P0_INPUT'));
const reorderedActions = structuredClone(inputValidation); reorderedActions.actionContracts.reverse();
assert.throws(() => assertFixedStatementInputValidation(reorderedActions, 'P0_ACTION_ORDER'), /P0_ACTION_ORDER:ACTION_ORDER/);
const omittedProperty = structuredClone(inputValidation); omittedProperty.actionContracts[0].requiredPropertySelectors.pop();
assert.throws(() => assertFixedStatementInputValidation(omittedProperty, 'P0_SELECTOR_OMIT'), /P0_SELECTOR_OMIT:PROPERTY_COUNT/);
const swappedProperty = structuredClone(inputValidation); [swappedProperty.actionContracts[0].requiredPropertySelectors[0], swappedProperty.actionContracts[0].requiredPropertySelectors[1]] = [swappedProperty.actionContracts[0].requiredPropertySelectors[1], swappedProperty.actionContracts[0].requiredPropertySelectors[0]];
assert.throws(() => assertFixedStatementInputValidation(swappedProperty, 'P0_SELECTOR_SWAP'), /P0_SELECTOR_SWAP:PROPERTY_SELECTOR:0/);

assert.doesNotThrow(() => assertTypedSchemaRefReachability(typedSchema, 'REF_AUDIT'));
const oldDefinition = structuredClone(typedSchema); oldDefinition.$defs.circleFriFoldKernel = { type: 'object' };
assert.throws(() => assertTypedSchemaRefReachability(oldDefinition, 'REMOVED_DEFINITION'), /REMOVED_DEFINITION:DEFINITION_ALLOWLIST/);
const oldReference = structuredClone(typedSchema); oldReference.properties.circle.$ref = '#/$defs/circleFriFoldKernel';
assert.throws(() => assertTypedSchemaRefReachability(oldReference, 'REMOVED_REFERENCE'), /REMOVED_REFERENCE:SUBDEFINITION_REF:circleFriFoldKernel/);
const wrappedRootMarker = structuredClone(typedSchema); wrappedRootMarker.properties.circle = { anyOf: [{ $ref: '#/$defs/pendingMarkerCircle' }, { type: 'object' }] };
assert.throws(() => assertTypedSchemaRefReachability(wrappedRootMarker, 'ROOT_MARKER_WRAPPER'), /ROOT_MARKER_WRAPPER:ROOT_MARKER_REF:circle/);
const widenedQualification = structuredClone(typedSchema); widenedQualification.$defs.qualificationBoundary.properties.candidateInstantiationAllowed = { type: 'boolean' };
assert.throws(() => assertTypedSchemaRefReachability(widenedQualification, 'QUALIFICATION_WIDENING'), /QUALIFICATION_WIDENING:CANONICAL_DOCUMENT/);
const widenedEvidence = structuredClone(typedSchema); widenedEvidence.$defs.downstreamEvidenceSlots.properties.rawTransactions = {};
assert.throws(() => assertTypedSchemaRefReachability(widenedEvidence, 'EVIDENCE_WIDENING'), /EVIDENCE_WIDENING:CANONICAL_DOCUMENT/);
const widenedAuthority = structuredClone(typedSchema); widenedAuthority.$defs.authorityBindings.properties.circlePrimarySourceAuthority = { type: 'object' };
assert.throws(() => assertTypedSchemaRefReachability(widenedAuthority, 'AUTHORITY_WIDENING'), /AUTHORITY_WIDENING:CANONICAL_DOCUMENT/);
const unusedRootProperty = structuredClone(typedSchema); unusedRootProperty.properties.unusedActiveLanguage = { type: 'object' };
assert.throws(() => assertTypedSchemaRefReachability(unusedRootProperty, 'UNUSED_ROOT_PROPERTY'), /UNUSED_ROOT_PROPERTY:ROOT_PROPERTY_KEYS/);
const dynamicMarker = structuredClone(typedSchema); dynamicMarker.$defs.pendingMarkerCircle.$dynamicRef = '#/$defs/pendingMarkerCircle';
assert.throws(() => assertTypedSchemaRefReachability(dynamicMarker, 'DYNAMIC_MARKER'), /DYNAMIC_MARKER:DYNAMIC_OR_RECURSIVE_REFERENCE/);
const combinatorMarker = structuredClone(typedSchema); combinatorMarker.$defs.pendingMarkerCircle.oneOf = [{ type: 'object' }];
assert.throws(() => assertTypedSchemaRefReachability(combinatorMarker, 'COMBINATOR_MARKER'), /COMBINATOR_MARKER:MARKER_COMBINATOR/);
const nestedPatternMarker = structuredClone(typedSchema); nestedPatternMarker.$defs.pendingMarkerCircle.properties.kind.patternProperties = { '.*': {} };
assert.throws(() => assertTypedSchemaRefReachability(nestedPatternMarker, 'PATTERN_MARKER'), /PATTERN_MARKER:MARKER_COMBINATOR:patternProperties/);
const loosenedMarkerProperty = structuredClone(typedSchema); loosenedMarkerProperty.$defs.pendingMarkerCircle.properties.kind = { type: 'string' };
assert.throws(() => assertTypedSchemaRefReachability(loosenedMarkerProperty, 'LOOSENED_MARKER'), /LOOSENED_MARKER:MARKER_PROPERTY_DEFINITIONS:circle/);
const projectionValidator = ajv.getSchema(`${TYPED_SCHEMA_URI}#/$defs/protocolProjectionDigest`);
assert.equal(projectionValidator(projection), true, 'projection schema exact domain positive');
assert.equal(projectionValidator(wrongProjectionDomain), false, 'projection schema wrong domain rejection');
assert.throws(() => assertNoDuplicateJsonKeys('{"authority":1,"\\u0061uthority":2}', 'DUPLICATE_JSON_MUTANT'), /DUPLICATE_JSON_MUTANT:DUPLICATE_KEY/);
