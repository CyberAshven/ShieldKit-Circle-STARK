import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditSyntheticFutureGraph } from '../validate-static.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = join(here, '..', 'schemas');
const schemas = readdirSync(schemaDir).filter((name) => name.endsWith('.json')).sort()
  .map((name) => JSON.parse(readFileSync(join(schemaDir, name), 'utf8')));
const ajv = new Ajv2020({ strict: true, allErrors: true, validateFormats: false });
assert.equal(schemas.length, 18, 'exact strict schema population');
for (const schema of schemas) ajv.addSchema(schema);
for (const schema of schemas) assert.equal(typeof ajv.getSchema(schema.$id), 'function', `strict compiled ${schema.$id}`);

const PREFIX = 'shieldkit-labs/p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge/v1';
const BASE = 'https://shieldkit-labs.local/p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge/v1';
const S = (file, definition) => `${BASE}/${file}#/$defs/${definition}`;
const SLOT_IDS = Object.freeze([
  'RECOVERY_CHAIN_OWNER_PROVIDER', 'REQUEST_OWNER_PROVIDER', 'ACTIVATION_OWNER_PROVIDER',
  'PRIVATE_CAPTURE_OWNER_PROVIDER', 'PRIVATE_DESCRIPTOR_OWNER_PROVIDER', 'EXCLUSIVE_C_OWNER_PROVIDER',
  'PRIVATE_DISPATCH_OWNER_PROVIDER', 'WORKLOAD_ROOT_ORDER_PROVIDER', 'RAW_ARTIFACT_MAP_AUTHORITY',
  'INDEPENDENT_RESULT_VALIDATOR_AUTHORITY',
]);
const hash = '0'.repeat(64);
const copy = (value) => JSON.parse(JSON.stringify(value));
const rootDocument = JSON.parse(readFileSync(join(here, '..', 'external-authority-control-plane-schema-bridge-root.v1.json'), 'utf8'));
const rootValidator = ajv.getSchema(`${BASE}/root.v1.schema.json`);
assert.equal(typeof rootValidator, 'function', 'compiled exact root schema');
assert.equal(rootValidator(copy(rootDocument)), true, JSON.stringify(rootValidator.errors));
const assertRootBoundaryRejection = (mutate, expected) => {
  const value = copy(rootDocument);
  mutate(value);
  assert.equal(rootValidator(value), false, 'boundary mutation rejected');
  assert.deepEqual(rootValidator.errors?.map(({ instancePath, schemaPath, keyword, params }) => ({ instancePath, schemaPath, keyword, params })), [expected]);
};
assertRootBoundaryRejection((value) => { delete value.nonAuthorityBoundary.contentDigest; }, {
  instancePath: '/nonAuthorityBoundary', schemaPath: '#/required', keyword: 'required', params: { missingProperty: 'contentDigest' },
});
assertRootBoundaryRejection((value) => { delete value.runtimeBoundary.contentDigest; }, {
  instancePath: '/runtimeBoundary', schemaPath: '#/required', keyword: 'required', params: { missingProperty: 'contentDigest' },
});
assertRootBoundaryRejection((value) => { value.nonAuthorityBoundary.contentDigest.value = 'g'.repeat(64); }, {
  instancePath: '/nonAuthorityBoundary/contentDigest/value',
  schemaPath: `${BASE}/digest.v1.schema.json#/$defs/contentDigestRecord/properties/value/pattern`,
  keyword: 'pattern', params: { pattern: '^[0-9a-f]{64}$' },
});
assertRootBoundaryRejection((value) => { value.runtimeBoundary.unexpectedBoundaryProperty = true; }, {
  instancePath: '/runtimeBoundary', schemaPath: '#/additionalProperties', keyword: 'additionalProperties', params: { additionalProperty: 'unexpectedBoundaryProperty' },
});
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalJson = (value) => Array.isArray(value)
  ? `[${value.map(canonicalJson).join(',')}]`
  : value && typeof value === 'object'
  ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
  : JSON.stringify(value);
const digest = (domain, value) => ({
  algorithm: 'sha256',
  canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',
  domain,
  frame: 'utf8(domain)||0x00||canonical-json-utf8||0x0a',
  value: sha256(Buffer.concat([Buffer.from(domain), Buffer.from([0]), Buffer.from(`${canonicalJson(value)}\n`)])),
});
const nonceDigest = (authorizationId, inputHex) => sha256(Buffer.concat([
  Buffer.from(`${PREFIX}/future/b0-execution-authorization/nonce/${authorizationId}`),
  Buffer.from([0]), Buffer.from(inputHex, 'hex'),
]));

/* Ephemeral only: this creates a valid, acyclic in-memory future graph. */
const buildGraph = (options = {}) => {
  const from = '2030-01-02T03:04:00Z', issued = '2030-01-02T03:04:01Z',
    g0Issued = '2030-01-02T03:04:02Z', catalogIssued = '2030-01-02T03:04:03Z',
    g1Issued = options.b0ConsumesExpiredG1Fractional ? '2030-01-02T03:04:03.900Z' : options.b0ConsumesExpiredG1Submillisecond ? '2030-01-02T03:04:03.0000000000000000001Z' : '2030-01-02T03:04:04Z',
    b0Issued = options.b0ConsumesExpiredG1Fractional ? '2030-01-02T03:04:04.100Z' : options.b0ConsumesExpiredG1Submillisecond ? '2030-01-02T03:04:04.0000000000000000002Z' : '2030-01-02T03:04:05Z',
    g1Expires = options.b0ConsumesExpiredG1Fractional ? '2030-01-02T03:04:04Z' : options.b0ConsumesExpiredG1Submillisecond ? '2030-01-02T03:04:04.0000000000000000001Z' : '2030-01-02T03:04:30Z',
    instanceIssued = '2030-01-02T03:04:06Z', created = '2030-01-02T03:04:07Z',
    expires = '2030-01-02T03:04:30Z', nonceInputHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    schema = (file, definition) => S(file, definition),
    body = (value) => { const next = { ...value }; delete next.contentDigest; return next; },
    final = (kind, id, value) => ({
      ...value,
      contentDigest: digest(
        kind === 'principal-identity-ref' || kind === 'issuer-decision'
          ? `${PREFIX}/future/${kind}/${id}` : `${PREFIX}/future/${kind}/record/${id}`,
        value,
      ),
    }),
    core = (kind, id, value) => digest(`${PREFIX}/future/${kind}/core/${id}`, value),
    ref = (key, id, contentDigest) => ({ [key]: id, locator: `synthetic/${id}.json`, bytes: 1, rawSha256: hash, contentDigest }),
    source = (id) => ref('artifactId', id, digest(`${PREFIX}/future/source/${id}`, { id })),
    revoke = ref('policyId', 'policy:synthetic', digest(`${PREFIX}/future/revocation/policy:synthetic`, { id: 'policy:synthetic' })),
    alternateRevoke = ref('policyId', 'policy:alternate', digest(`${PREFIX}/future/revocation/policy:alternate`, { id: 'policy:alternate' })),
    revocationPolicyRef = (kind) => options.revocationFoundationMismatch === kind ? alternateRevoke : revoke,
    futureRef = (key, id, value) => ({
      [key]: id,
      locator: `synthetic/future-${id}.json`,
      bytes: Buffer.byteLength(`${canonicalJson(value)}\n`, 'utf8'),
      rawSha256: sha256(Buffer.from(`${canonicalJson(value)}\n`, 'utf8')),
      contentDigest: value.contentDigest,
    }),
    finalRef = (key, id, value) => futureRef(key, id, value),
    authoritySetId = 'artifact:authority-set', bindingSetId = 'artifact:binding-set',
    eacSource = source('artifact:eac'), b0rSource = source('artifact:b0r'), ssaSource = source('artifact:ssa'),
    eappSource = source('artifact:eapp'), bridgeSource = source('artifact:bridge'), policySource = source('artifact:policy'),
    expectedFoundationRefs = {
      authorityPolicyRef: policySource, controlPlaneBridgeRef: bridgeSource,
      uopcSourceRef: source('artifact:uopc'), eacSourceRef: eacSource,
      eacRef: eacSource, b0rRef: b0rSource, ssaRef: ssaSource, eappRef: eappSource,
      revocationPolicyRef: revoke,
    },
    collisionEacSource = options.collisionEacFoundationMismatch ? source('artifact:alternate-eac') : eacSource,
    authoritySource = options.authoritySourcePolicyFoundationMismatch ? source('artifact:alternate-policy') : policySource,
    g1AuthorityPolicyRef = options.g1AuthorityPolicyFoundationMismatch ? source('artifact:alternate-policy') : policySource,
    b0EacRef = options.b0EacFoundationMismatch ? source('artifact:alternate-eac') : eacSource,
    identity = (principalRefId, principalRole) => final('principal-identity-ref', principalRefId, {
      schema: schema('principal-identity-ref.v1.schema.json', 'principalIdentityRef'), artifactId: `artifact:${principalRefId}`,
      principalRefId, principalRole, identityArtifactLocator: `synthetic/${principalRefId}.identity`, identityArtifactBytes: 1,
      identityArtifactRawSha256: hash, identityArtifactSchemaId: 'synthetic-identity-schema', externalTrustRootId: 'trust:synthetic',
      validFrom: options.identityImpossibleCalendar && principalRefId === 'principal:root-governance' ? '2030-02-29T03:04:00Z' : options.identityNotYetValidFractional && principalRefId === 'principal:root-governance' ? '2030-01-02T03:04:01.900Z' : from,
      expiresAt: options.identityExpiryEquality && principalRefId === 'principal:root-governance' ? from : expires,
      revocationPolicyRef: revocationPolicyRef('identity'),
    });
  const identities = [
      identity('principal:root-governance', 'ROOT_SOL_GOVERNANCE_ISSUER'),
      identity('principal:authority-issuer', 'AUTHORITY_CONTRACT_ISSUER'),
      identity('principal:provider-issuer', 'PROVIDER_CONTRACT_ISSUER'),
      identity('principal:catalog-reviewer', 'PROVIDER_CATALOG_REVIEWER'),
      identity('principal:b0-issuer', 'B0_AUTHORIZATION_ISSUER'),
      identity('principal:instance-creator', 'INSTANCE_CREATOR'),
      ...SLOT_IDS.map((_, index) => identity(`principal:authority-${index}`, 'AUTHORITY_PRINCIPAL')),
      ...SLOT_IDS.map((_, index) => identity(`principal:provider-${index}`, 'PROVIDER_PRINCIPAL')),
    ],
    identityById = new Map(identities.map((value) => [value.principalRefId, value])),
    principalRef = (id) => finalRef('principalRefId', id, identityById.get(id)),
    authorityPrincipalIdForSlot = (index) => options.authorityPrincipalCrossSlot && index === 0
      ? 'principal:authority-1'
      : `principal:authority-${index}`,
    decision = (decisionId, decisionKind, issuerId, recordKind, recordId, coreDigest, decisionIssued = issued, decisionExpires = expires) => final('issuer-decision', decisionId, {
      schema: schema('issuer-decision.v1.schema.json', 'issuerDecision'), artifactId: `artifact:${decisionId}`, decisionId, decisionKind,
      issuerPrincipalRef: principalRef(issuerId), subjectCoreCommitments: [{ recordKind, recordId, coreDigest }],
      decisionScope: 'synthetic-scope', decisionStatus: 'ISSUED_EXTERNAL_DECISION', issuedAt: decisionIssued, expiresAt: decisionExpires,
      revocationPolicyRef: revocationPolicyRef('decision'),
    }),
    authorityCores = SLOT_IDS.map((policySlotId, index) => ({
      authorityContractId: `authority:${index}`, policySlotId, issuerPrincipalRef: principalRef('principal:authority-issuer'),
      authorityPrincipalRef: principalRef(authorityPrincipalIdForSlot(index)), authorityScope: 'synthetic-scope', sourceAuthorityRef: authoritySource,
      authorityPayload: index < 7
        ? { payloadType: 'OWNER_AUTHORITY_PAYLOAD', ownerScopeId: policySlotId, ownerContractSchemaId: 'synthetic-owner-schema', ownerBindingDomain: 'synthetic-owner-domain' }
        : index === 7
        ? { payloadType: 'WORKLOAD_MATERIAL_AUTHORITY_PAYLOAD', workloadRootOrderSchemaId: 'synthetic-workload-schema', projectionEncodingSchemaId: 'synthetic-projection-schema', workloadBindingDomain: 'synthetic-workload-domain' }
        : index === 8
        ? { payloadType: 'RAW_ARTIFACT_MAP_AUTHORITY_PAYLOAD', artifactMapSchemaId: 'synthetic-map-schema', exclusiveWriterPolicySchemaId: 'synthetic-writer-schema', artifactMapBindingDomain: 'synthetic-map-domain', artifactProducerSeparationRequired: true }
        : { payloadType: 'INDEPENDENT_RESULT_VALIDATOR_AUTHORITY_PAYLOAD', resultSchemaId: 'synthetic-result-schema', validatorInterfaceSchemaId: 'synthetic-validator-schema', independencePolicyId: 'synthetic-independence', resultProducerSeparationRequired: true, executionProducerSeparationRequired: true },
      providerBindingCreationCapability: 'REQUIRES_SEPARATE_G0_AUTHORIZATION', instanceCreationAllowed: false, executionAllowed: false,
      admissionAllowed: false, revocationPolicyRef: revocationPolicyRef('authority'), expiresAt: expires,
    })),
    authorityDigests = authorityCores.map((value) => core('external-authority-contract', value.authorityContractId, value)),
    authorityDecisions = authorityCores.map((value, index) => decision(`decision:authority-${index}`, 'EXTERNAL_AUTHORITY_CONTRACT_ISSUANCE', 'principal:authority-issuer', 'EXTERNAL_AUTHORITY_CONTRACT_V2', value.authorityContractId, options.decisionAlternateCoreDigest && index === 0 ? authorityDigests[1] : authorityDigests[index])),
    authorityContracts = authorityCores.map((value, index) => final('external-authority-contract', value.authorityContractId, {
      schema: schema('external-authority-contract.v2.schema.json', 'externalAuthorityContractV2'), artifactId: `artifact:authority-${index}`,
      contractCore: value, contractCoreDigest: authorityDigests[index], issuerDecisionRef: finalRef('decisionId', authorityDecisions[index].decisionId, authorityDecisions[index]),
    })),
    providerCores = SLOT_IDS.map((policySlotId, index) => ({
      providerContractId: `provider:${index}`, policySlotId, issuerPrincipalRef: principalRef('principal:provider-issuer'),
      providerPrincipalRef: principalRef(`principal:provider-${index}`), providerScope: 'synthetic-scope', providerInterfaceSchemaId: 'synthetic-provider-schema',
      providerMaterial: { materialClass: 'EXTERNAL_CONTENT_ADDRESSED_PROVIDER_CONTRACT_BYTES', contractArtifactLocator: 'synthetic/provider.bin', contractArtifactBytes: 1, contractArtifactRawSha256: hash, contractArtifactSchemaId: 'synthetic-material-schema', importEvaluationAllowed: false },
      instanceCreationAllowed: false, executionAllowed: false, admissionAllowed: false, revocationPolicyRef: revocationPolicyRef('provider'), expiresAt: expires,
    })),
    providerDigests = providerCores.map((value, index) => options.providerWrongDomainCoreDigest && index === 0
      ? digest(`${PREFIX}/future/provider-contract/wrong-domain/${value.providerContractId}`, value)
      : core('provider-contract', value.providerContractId, value)),
    providerDecisions = providerCores.map((value, index) => decision(`decision:provider-${index}`, 'PROVIDER_CONTRACT_ISSUANCE', 'principal:provider-issuer', 'PROVIDER_CONTRACT', value.providerContractId, providerDigests[index])),
    providerContracts = providerCores.map((value, index) => final('provider-contract', value.providerContractId, {
      schema: schema('provider-contract.v1.schema.json', 'providerContract'), artifactId: `artifact:provider-${index}`,
      contractCore: value, contractCoreDigest: providerDigests[index], issuerDecisionRef: finalRef('decisionId', providerDecisions[index].decisionId, providerDecisions[index]),
    })),
    collisionCores = ['UOPC', 'EAC'].map((selectedDag) => ({
      collisionDecisionId: `collision:${selectedDag.toLowerCase()}`, collisionId: 'UOPC_EAC_FUTURE_PROVIDER_DAG_DIVERGENCE', issuerPrincipalRef: principalRef('principal:root-governance'),
      uopcSourceRef: source('artifact:uopc'), eacSourceRef: options.collisionEacBranchMismatch && selectedDag === 'EAC' ? source('artifact:branch-eac') : collisionEacSource, eappCollisionComponentDigest: 'c69be9027fa2cfef09f82d706a099a756dc4a563d2febb2fc1eb1ab8eacaffc9', selectedDag,
      selectedDagComponentDigest: selectedDag === 'UOPC' ? '8c80d46922c05700f3d9bbd999e5a780201a09d42da1604dbc22f7a15bda585d' : '72edbc5ea6b08b018bed9a6794b518bab2fee5703e104fb36928f463dead4707',
      selectedDagEdgeCount: selectedDag === 'UOPC' ? 40 : 37,
      selectedAPath: selectedDag === 'UOPC' ? 'UOPC_INITIAL_RETRY_ABORT_WITH_A_INITIAL_TO_B_SUBJECT' : 'EAC_RETRY_TO_B_SUBJECT_WITH_INITIAL_ABORT_ACTIVATION_UNAVAILABLE',
      selectedRetryDisposition: selectedDag === 'UOPC' ? 'A_RETRY_DENY_PREREQUISITE_WHILE_Q_RETRY_BLOCKED_EXTERNAL' : 'A_RETRY_BLOCKED_EXTERNAL_REQUIRES_Q_RETRY_AND_ACTIVATION_OWNER',
      affectedRequirementIds: ['Q_INITIAL_PROVIDER', 'Q_RETRY_PROVIDER', 'Q_ABORT_PROVIDER', 'A_INITIAL_PROVIDER', 'A_RETRY_PROVIDER', 'A_ABORT_PROVIDER', 'B_SUBJECT_ROOT_TYPE', 'B_PROVIDER'],
      decisionScope: 'synthetic-scope', instanceCreationAllowed: false, executionAllowed: false, admissionAllowed: false, revocationPolicyRef: revocationPolicyRef('collision'), expiresAt: expires,
    })),
    collisionDigests = collisionCores.map((value) => core('source-collision-decision', value.collisionDecisionId, value)),
    collisionDecisions = collisionCores.map((value, index) => decision(`decision:collision-${index}`, 'SOURCE_COLLISION_SELECTION', 'principal:root-governance', 'SOURCE_COLLISION_DECISION_V2', value.collisionDecisionId, collisionDigests[index])),
    collisions = collisionCores.map((value, index) => final('source-collision-decision', value.collisionDecisionId, {
      schema: schema('source-collision-decision.v2.schema.json', 'sourceCollisionDecisionV2'), artifactId: `artifact:collision-${index}`,
      decisionCore: value, decisionCoreDigest: collisionDigests[index], issuerDecisionRef: finalRef('decisionId', collisionDecisions[index].decisionId, collisionDecisions[index]),
    })),
    authorityEntries = authorityContracts.map((value, index) => ({ authorityContractId: value.contractCore.authorityContractId, policySlotId: SLOT_IDS[index], ...finalRef('authorityContractId', value.contractCore.authorityContractId, value) })),
    authoritySet = final('external-authority-contract', authoritySetId, {
      schema: schema('external-authority-contract.v2.schema.json', 'externalAuthorityContractSet'), artifactId: authoritySetId,
      status: 'EXTERNALLY_ISSUED_AUTHORITY_CONTRACT_SET_NO_INSTANCES', entryCount: 10, entries: authorityEntries,
      rosterDigest: digest(`${PREFIX}/future/external-authority-contract/set-roster/${authoritySetId}`, authorityEntries),
    }),
    authoritySetRef = { schemaId: schema('external-authority-contract.v2.schema.json', 'externalAuthorityContractSet'), entryCount: 10, rosterDigest: authoritySet.rosterDigest, ...finalRef('artifactId', authoritySetId, authoritySet) },
    uopcCollision = collisions[0],
    g0Core = {
      authorizationId: 'authorization:g0', issuerPrincipalRef: principalRef('principal:root-governance'), authorityPolicyRef: policySource,
      controlPlaneBridgeRef: bridgeSource, externalAuthorityContractSetRef: authoritySetRef, sourceCollisionDecisionRef: finalRef('decisionId', uopcCollision.decisionCore.collisionDecisionId, uopcCollision),
      authorizedOperation: 'CREATE_AND_REVIEW_PROVIDER_BINDING_CATALOG_ONLY', authorizedPolicySlotIds: SLOT_IDS,
      principalCoincidencePolicy: { status: 'ALL_RELEVANT_PRINCIPALS_MUST_BE_DISTINCT', allowedPairs: [] }, issuedAt: g0Issued, expiresAt: expires,
      revocationPolicyRef: revocationPolicyRef('g0'), providerBindingCreationAllowed: true, instanceCreationAllowed: false, executionAllowed: false, admissionAllowed: false,
    },
    g0Digest = core('binding-creation-authorization-g0', g0Core.authorizationId, g0Core),
    g0Decision = decision('decision:g0', 'BINDING_CREATION_AUTHORIZATION_G0', 'principal:root-governance', 'BINDING_CREATION_AUTHORIZATION_G0', g0Core.authorizationId, g0Digest, g0Issued),
    g0 = final('binding-creation-authorization-g0', g0Core.authorizationId, {
      schema: schema('binding-creation-authorization-g0.v1.schema.json', 'bindingCreationAuthorizationG0'), artifactId: 'artifact:future-g0', authorizationCore: g0Core,
      authorizationCoreDigest: g0Digest, issuerDecisionRef: finalRef('decisionId', g0Decision.decisionId, g0Decision),
    }),
    proofs = SLOT_IDS.map((policySlotId, index) => {
      const alteredProvider = options.bindingProofAlternateProvider && index === 0;
      const projected = ['principal:root-governance', 'principal:authority-issuer', authorityPrincipalIdForSlot(index), 'principal:provider-issuer', alteredProvider ? 'principal:provider-1' : `principal:provider-${index}`, 'principal:catalog-reviewer'];
      const proof = {
        proofId: `proof:${index}`, proofType: 'SYNTHETIC_PRINCIPAL_INDEPENDENCE_PROJECTION_V1', bindingId: `binding:${index}`,
        policySlotId: options.bindingProofCrossSlot && index === 0 ? SLOT_IDS[1] : policySlotId,
        principalCoincidencePolicy: { status: 'ALL_RELEVANT_PRINCIPALS_MUST_BE_DISTINCT', allowedPairs: [] },
        principalProjection: projected.map((principalRefId, row) => ({
          relation: ['ROOT_GOVERNANCE', 'AUTHORITY_CONTRACT_ISSUER', 'AUTHORITY_PRINCIPAL', 'PROVIDER_CONTRACT_ISSUER', 'PROVIDER_PRINCIPAL', 'CATALOG_REVIEWER'][row],
          requiredPrincipalRole: ['ROOT_SOL_GOVERNANCE_ISSUER', 'AUTHORITY_CONTRACT_ISSUER', 'AUTHORITY_PRINCIPAL', 'PROVIDER_CONTRACT_ISSUER', 'PROVIDER_PRINCIPAL', 'PROVIDER_CATALOG_REVIEWER'][row],
          principalRefId,
          principalIdentityContentDigest: identityById.get(principalRefId).contentDigest,
        })),
        projectedPrincipalCount: 6, distinctPrincipalRefIdCount: 6, allProjectedPrincipalRefIdsDistinct: true,
      };
      return { ...proof, contentDigest: digest(`${PREFIX}/future/provider-binding/principal-independence-proof/${proof.proofId}`, proof) };
    }),
    bindings = SLOT_IDS.map((policySlotId, index) => {
      const bindingCollision = options.bindingCollisionAlternate && index === 0
        ? collisions[1]
        : uopcCollision;
      const bindingCore = {
        bindingId: `binding:${index}`, policySlotId, authorityContractRef: authorityEntries[index], authorityPrincipalRef: principalRef(authorityPrincipalIdForSlot(index)),
        providerContractRef: { providerContractId: providerContracts[index].contractCore.providerContractId, policySlotId, ...finalRef('providerContractId', providerContracts[index].contractCore.providerContractId, providerContracts[index]) },
        providerPrincipalRef: principalRef(`principal:provider-${index}`), catalogReviewerPrincipalRef: principalRef('principal:catalog-reviewer'),
        sourceCollisionDecisionRef: finalRef('decisionId', bindingCollision.decisionCore.collisionDecisionId, bindingCollision), principalIndependenceProofRef: finalRef('proofId', proofs[index].proofId, proofs[index]),
        instanceCreationAllowed: false, executionAllowed: false, admissionAllowed: false,
      };
      const bindingDigest = core('provider-binding', bindingCore.bindingId, bindingCore);
      return final('provider-binding', bindingCore.bindingId, {
        schema: schema('provider-binding.v2.schema.json', 'providerBindingV2'), artifactId: `artifact:binding-${index}`, bindingCore, bindingCoreDigest: bindingDigest,
        g0AuthorizationRef: finalRef('authorizationId', g0Core.authorizationId, g0),
      });
    }),
    bindingEntries = bindings.map((value, index) => ({ bindingId: value.bindingCore.bindingId, policySlotId: SLOT_IDS[index], ...finalRef('bindingId', value.bindingCore.bindingId, value) })),
    bindingSet = final('provider-binding', bindingSetId, {
      schema: schema('provider-binding.v2.schema.json', 'providerBindingSet'), artifactId: bindingSetId, status: 'G0_AUTHORIZED_PROVIDER_BINDING_SET_NO_INSTANCES', entryCount: 10,
      entries: bindingEntries, rosterDigest: digest(`${PREFIX}/future/provider-binding/set-roster/${bindingSetId}`, bindingEntries),
    }),
    bindingSetRef = { schemaId: schema('provider-binding.v2.schema.json', 'providerBindingSet'), entryCount: 10, rosterDigest: bindingSet.rosterDigest, ...finalRef('artifactId', bindingSetId, bindingSet) },
    catalogCore = {
      catalogId: 'catalog:synthetic', status: 'EXTERNALLY_REVIEWED_BINDINGS_NO_INSTANCES', authorityPolicyRef: policySource, controlPlaneBridgeRef: bridgeSource,
      externalAuthorityContractSetRef: authoritySetRef, g0AuthorizationRef: finalRef('authorizationId', g0Core.authorizationId, g0), sourceCollisionDecisionRef: finalRef('decisionId', uopcCollision.decisionCore.collisionDecisionId, uopcCollision),
      providerBindingSetRef: bindingSetRef, bindingCount: 10, bindingRefs: bindingEntries, reviewerPrincipalRef: principalRef('principal:catalog-reviewer'),
      allAuthorityRootsExternallyPinned: true, selfAttestationAllowed: false, principalCoincidenceAllowed: false, instanceCreationAllowed: false, executionAllowed: false, admissionAllowed: false,
    },
    catalogDigest = core('provider-binding-catalog', catalogCore.catalogId, catalogCore),
    catalogDecision = decision('decision:catalog', 'PROVIDER_BINDING_CATALOG_REVIEW', 'principal:catalog-reviewer', 'PROVIDER_BINDING_CATALOG', catalogCore.catalogId, catalogDigest, catalogIssued),
    catalog = final('provider-binding-catalog', catalogCore.catalogId, {
      schema: schema('provider-binding-catalog.v1.schema.json', 'providerBindingCatalog'), artifactId: 'artifact:future-catalog', catalogCore, catalogCoreDigest: catalogDigest,
      reviewDecisionRef: options.catalogReviewCollision ? finalRef('decisionId', uopcCollision.decisionCore.collisionDecisionId, uopcCollision) : finalRef('decisionId', catalogDecision.decisionId, catalogDecision),
    }),
    catalogRef = finalRef('artifactId', catalog.artifactId, catalog),
    g1Core = {
      authorizationId: 'authorization:g1', issuerPrincipalRef: principalRef('principal:root-governance'), authorityPolicyRef: g1AuthorityPolicyRef, controlPlaneBridgeRef: bridgeSource,
      externalAuthorityContractSetRef: authoritySetRef, providerBindingCatalogRef: options.g1CatalogAuthorityPolicySource ? policySource : catalogRef,
      sourceCollisionDecisionRef: finalRef('decisionId', uopcCollision.decisionCore.collisionDecisionId, uopcCollision), authorizedOperation: 'CREATE_B0_EXECUTION_AUTHORIZATION_RECORD_ONLY',
      authorizedTransition: { from: 'PROVIDER_BINDINGS_REVIEWED_NO_INSTANCES', to: 'B0_EXECUTION_AUTHORIZATION_CREATION_AUTHORIZED_NO_INSTANCES' }, authorizedPolicySlotIds: SLOT_IDS,
      issuedAt: g1Issued, expiresAt: g1Expires, revocationPolicyRef: revocationPolicyRef('g1'), b0ExecutionAuthorizationCreationAllowed: true, instanceCreationAllowed: false, executionAllowed: false, admissionAllowed: false,
    },
    g1Digest = core('governance-authorization-g1', g1Core.authorizationId, g1Core),
    g1Decision = decision('decision:g1', 'GOVERNANCE_AUTHORIZATION_G1', 'principal:root-governance', 'GOVERNANCE_AUTHORIZATION_G1', g1Core.authorizationId, g1Digest, g1Issued),
    g1 = final('governance-authorization-g1', g1Core.authorizationId, {
      schema: schema('governance-authorization-g1.v1.schema.json', 'governanceAuthorizationG1'), artifactId: 'artifact:future-g1', authorizationCore: g1Core,
      authorizationCoreDigest: g1Digest, issuerDecisionRef: finalRef('decisionId', g1Decision.decisionId, g1Decision),
    }),
    b0Nonce = options.nonceAlternate ? '1'.repeat(64) : nonceDigest('authorization:b0', nonceInputHex),
    b0Class = options.retryCausalMismatch ? 'Q_RETRY' : 'Q_INITIAL',
    retryPredecessorRef = b0Class === 'Q_RETRY' ? source('instance:predecessor') : null,
    b0Core = {
      authorizationId: 'authorization:b0', issuerPrincipalRef: principalRef('principal:b0-issuer'), eacRef: b0EacRef, b0rRef: b0rSource, ssaRef: ssaSource, eappRef: eappSource,
      controlPlaneBridgeRef: bridgeSource, externalAuthorityContractSetRef: authoritySetRef, providerBindingCatalogRef: catalogRef, sourceCollisionDecisionRef: finalRef('decisionId', uopcCollision.decisionCore.collisionDecisionId, uopcCollision),
      authorizedOperation: 'AUTHORIZE_ONE_FUTURE_B0_INSTANCE_CREATION_EVENT_ONLY', authorizationScope: { campaignClass: 'B0_EVIDENCE_CAMPAIGN', candidateSelectionAllowed: false, parameterAssignmentAllowed: false, providerSelectionAllowed: false },
      authorizationNonceDigest: b0Nonce, authorizedInstanceClass: b0Class, retryPredecessorRef, maxInstanceCreationEvents: 1, consumedInstanceCreationEventCount: 0,
      instanceCreationEventRequired: true, executionAuthorizationPresent: true, executionStartAllowed: false, admissionAllowed: false, evidenceAdmissionAllowed: false, qualificationAllowed: false,
      issuedAt: b0Issued, expiresAt: expires, revocationPolicyRef: revocationPolicyRef('b0'),
    },
    b0Digest = core('b0-execution-authorization', b0Core.authorizationId, b0Core),
    b0Decision = decision('decision:b0', 'B0_EXECUTION_AUTHORIZATION', 'principal:b0-issuer', 'B0_EXECUTION_AUTHORIZATION', b0Core.authorizationId, b0Digest, b0Issued),
    b0 = final('b0-execution-authorization', b0Core.authorizationId, {
      schema: schema('b0-execution-authorization.v1.schema.json', 'b0ExecutionAuthorization'), artifactId: 'artifact:future-b0', authorizationCore: b0Core,
      authorizationCoreDigest: b0Digest, issuerDecisionRef: finalRef('decisionId', b0Decision.decisionId, b0Decision), g1AuthorizationRef: finalRef('authorizationId', g1Core.authorizationId, g1),
    }),
    eventClass = options.eventAbort ? 'Q_ABORT' : b0Class,
    createdInstanceCore = { instanceClass: eventClass, instanceId: 'instance:synthetic' },
    eventCore = {
      eventId: 'event:synthetic', creatorPrincipalRef: principalRef('principal:instance-creator'),
      createdInstanceCoreCommitment: { instanceClass: eventClass, instanceId: createdInstanceCore.instanceId, coreDigest: digest(`${PREFIX}/future/instance-creation-event/instance-core/${createdInstanceCore.instanceId}`, createdInstanceCore) },
      authorizationNonceDigest: b0Nonce, predecessorInstanceRef: options.retryCausalMismatch ? source('instance:alternate-predecessor') : retryPredecessorRef, createdAt: created, executionStartAllowed: false, admissionAllowed: false, evidenceAdmissionAllowed: false,
    },
    eventDigest = core('instance-creation-event', eventCore.eventId, eventCore),
    eventDecision = decision('decision:event', 'INSTANCE_CREATION', 'principal:instance-creator', 'INSTANCE_CREATION_EVENT', eventCore.eventId, eventDigest, instanceIssued, options.eventDecisionExpiredBeforeCreation ? '2030-01-02T03:04:06.5Z' : expires),
    event = final('instance-creation-event', eventCore.eventId, {
      schema: schema('instance-creation-event.v1.schema.json', 'instanceCreationEvent'), artifactId: 'artifact:future-event', eventCore, eventCoreDigest: eventDigest,
      issuerDecisionRef: finalRef('decisionId', eventDecision.decisionId, eventDecision), b0ExecutionAuthorizationRef: finalRef('authorizationId', b0Core.authorizationId, b0),
    });
  return {
    identities, decisions: [...authorityDecisions, ...providerDecisions, ...collisionDecisions, g0Decision, catalogDecision, g1Decision, b0Decision, eventDecision],
    authorityContracts, providerContracts, collisions, authoritySet, proofs, bindings, bindingSet, g0, catalog, g1, b0, event, createdInstanceCores: [createdInstanceCore], expectedFoundationRefs, nonceInputHex,
  };
};

const recordSpecs = Object.freeze([
  ['principal-identity-ref.v1.schema.json', 'principalIdentityRef', (graph) => graph.identities[0]],
  ['issuer-decision.v1.schema.json', 'issuerDecision', (graph) => graph.decisions[0]],
  ['external-authority-contract.v2.schema.json', 'externalAuthorityContractV2', (graph) => graph.authorityContracts[0]],
  ['provider-contract.v1.schema.json', 'providerContract', (graph) => graph.providerContracts[0]],
  ['source-collision-decision.v2.schema.json', 'sourceCollisionDecisionV2', (graph) => graph.collisions[0]],
  ['binding-creation-authorization-g0.v1.schema.json', 'bindingCreationAuthorizationG0', (graph) => graph.g0],
  ['provider-binding.v2.schema.json', 'providerBindingV2', (graph) => graph.bindings[0]],
  ['provider-binding-catalog.v1.schema.json', 'providerBindingCatalog', (graph) => graph.catalog],
  ['governance-authorization-g1.v1.schema.json', 'governanceAuthorizationG1', (graph) => graph.g1],
  ['b0-execution-authorization.v1.schema.json', 'b0ExecutionAuthorization', (graph) => graph.b0],
  ['instance-creation-event.v1.schema.json', 'instanceCreationEvent', (graph) => graph.event],
]);
const validate = (file, definition) => {
  const compiled = ajv.getSchema(S(file, definition));
  assert.ok(compiled, `compiled ${definition}`);
  return compiled;
};

for (const spec of recordSpecs) {
  test(`${spec[1]} accepts one synthetic nonauthorizing future record`, () => {
    const compiled = validate(spec[0], spec[1]);
    assert.equal(compiled(copy(spec[2](buildGraph()))), true, JSON.stringify(compiled.errors));
  });
  test(`${spec[1]} rejects one missing top-level key`, () => {
    const compiled = validate(spec[0], spec[1]), value = copy(spec[2](buildGraph()));
    delete value[Object.keys(value)[0]];
    assert.equal(compiled(value), false);
  });
  test(`${spec[1]} rejects one unexpected top-level key`, () => {
    const compiled = validate(spec[0], spec[1]), value = copy(spec[2](buildGraph()));
    value.unexpectedTopLevelKey = true;
    assert.equal(compiled(value), false);
  });
}

test('EAC ownerScopeId different from its policy slot is an Ajv-invalid structural record', () => {
  const compiled = validate('external-authority-contract.v2.schema.json', 'externalAuthorityContractV2');
  const value = copy(buildGraph().authorityContracts[0]);
  value.contractCore.authorityPayload.ownerScopeId = SLOT_IDS[1];
  assert.equal(compiled(value), false);
});
test('collision selectedDag flip alone is an Ajv-invalid structural record', () => {
  const compiled = validate('source-collision-decision.v2.schema.json', 'sourceCollisionDecisionV2');
  const value = copy(buildGraph().collisions[0]);
  value.decisionCore.selectedDag = 'EAC';
  assert.equal(compiled(value), false);
});
test('G0 policy-slot removal and reorder are Ajv-invalid structural records', () => {
  const compiled = validate('binding-creation-authorization-g0.v1.schema.json', 'bindingCreationAuthorizationG0');
  const removed = copy(buildGraph().g0), reordered = copy(buildGraph().g0);
  removed.authorizationCore.authorizedPolicySlotIds.pop();
  [reordered.authorizationCore.authorizedPolicySlotIds[0], reordered.authorizationCore.authorizedPolicySlotIds[1]] = [reordered.authorizationCore.authorizedPolicySlotIds[1], reordered.authorizationCore.authorizedPolicySlotIds[0]];
  assert.equal(compiled(removed), false);
  assert.equal(compiled(reordered), false);
});

const expectAuditFailure = (graph, expected) => {
  const error = assert.throws(() => auditSyntheticFutureGraph(graph));
  assert.equal(error?.message, expected);
};
const auditCases = Object.freeze([
  ['fractional-second and sub-millisecond prerequisite-expiry inversions', {}, 'principal-identity-ref.v1.schema.json', 'principalIdentityRef', (graph) => graph.identities[0], [
    [{ identityNotYetValidFractional: true }, 'CPSB_ISSUER_DECISION_SCHEMA:identity:decision:collision-uopc:valid-from', [
      ['principal-identity-ref.v1.schema.json', 'principalIdentityRef', (graph) => graph.identities[0]],
    ]],
    [{ b0ConsumesExpiredG1Fractional: true }, 'CPSB_B0_AUTH_SCHEMA:time-edge:b0:g1', [
      ['governance-authorization-g1.v1.schema.json', 'governanceAuthorizationG1', (graph) => graph.g1],
      ['b0-execution-authorization.v1.schema.json', 'b0ExecutionAuthorization', (graph) => graph.b0],
    ]],
    [{ b0ConsumesExpiredG1Submillisecond: true }, 'CPSB_B0_AUTH_SCHEMA:time-edge:b0:g1', [
      ['governance-authorization-g1.v1.schema.json', 'governanceAuthorizationG1', (graph) => graph.g1],
      ['b0-execution-authorization.v1.schema.json', 'b0ExecutionAuthorization', (graph) => graph.b0],
    ]],
    [{ identityImpossibleCalendar: true }, 'CPSB_IDENTITY_SCHEMA:time:identity:principal:root-governance:left', [
      ['principal-identity-ref.v1.schema.json', 'principalIdentityRef', (graph) => graph.identities[0]],
    ]],
  ]],
  ['decision alternate valid coreDigest', {}, 'issuer-decision.v1.schema.json', 'issuerDecision', (graph) => graph.decisions[0], { decisionAlternateCoreDigest: true }, 'CPSB_ISSUER_DECISION_SCHEMA:commitment:authority:0'],
  ['provider wrong-domain core digest', {}, 'provider-contract.v1.schema.json', 'providerContract', (graph) => graph.providerContracts[0], { providerWrongDomainCoreDigest: true }, 'CPSB_PROVIDER_CONTRACT_SCHEMA:digest:provider:0'],
  ['binding proof/collision coherent alternate/cross-slot rows', {}, 'provider-binding.v2.schema.json', 'providerBindingV2', (graph) => graph.bindings[0], [
    [{ bindingProofAlternateProvider: true }, 'CPSB_PROVIDER_BINDING_SCHEMA:proof:proof:0'],
    [{ bindingProofCrossSlot: true }, 'CPSB_PROVIDER_BINDING_SCHEMA:proof:proof:0'],
    [{ bindingCollisionAlternate: true }, 'CPSB_PROVIDER_BINDING_SCHEMA:binding-collision:binding:0'],
    [{ authorityPrincipalCrossSlot: true }, 'CPSB_AUTHORITY_CONTRACT_SCHEMA:authority-principal-bijection'],
    [{ collisionEacBranchMismatch: true }, 'CPSB_COLLISION_DECISION_SCHEMA:foundation:collision:eac', [
      ['source-collision-decision.v2.schema.json', 'sourceCollisionDecisionV2', (graph) => graph.collisions[1]],
    ]],
  ], 'CPSB_PROVIDER_BINDING_SCHEMA:proof:proof:0'],
  ['catalog review reference collision decision', {}, 'provider-binding-catalog.v1.schema.json', 'providerBindingCatalog', (graph) => graph.catalog, { catalogReviewCollision: true }, 'CPSB_CATALOG_SCHEMA:issuer:catalog:synthetic'],
  ['coherent foundation reference substitutions', {}, 'governance-authorization-g1.v1.schema.json', 'governanceAuthorizationG1', (graph) => graph.g1, [
    [{ g1CatalogAuthorityPolicySource: true }, 'CPSB_G1_SCHEMA:g1-catalog'],
    [{ g1AuthorityPolicyFoundationMismatch: true }, 'CPSB_G1_SCHEMA:foundation:g1'],
    [{ authoritySourcePolicyFoundationMismatch: true }, 'CPSB_AUTHORITY_CONTRACT_SCHEMA:foundation:authority:0', [
      ['external-authority-contract.v2.schema.json', 'externalAuthorityContractV2', (graph) => graph.authorityContracts[0]],
    ]],
    [{ revocationFoundationMismatch: 'identity' }, 'CPSB_IDENTITY_SCHEMA:identity:principal:root-governance', [
      ['principal-identity-ref.v1.schema.json', 'principalIdentityRef', (graph) => graph.identities[0]],
    ]],
    [{ revocationFoundationMismatch: 'decision' }, 'CPSB_ISSUER_DECISION_SCHEMA:decision:decision:authority-0', [
      ['issuer-decision.v1.schema.json', 'issuerDecision', (graph) => graph.decisions[0]],
    ]],
    [{ revocationFoundationMismatch: 'authority' }, 'CPSB_AUTHORITY_CONTRACT_SCHEMA:foundation:authority:0', [
      ['external-authority-contract.v2.schema.json', 'externalAuthorityContractV2', (graph) => graph.authorityContracts[0]],
    ]],
    [{ revocationFoundationMismatch: 'provider' }, 'CPSB_PROVIDER_CONTRACT_SCHEMA:foundation:provider:0', [
      ['provider-contract.v1.schema.json', 'providerContract', (graph) => graph.providerContracts[0]],
    ]],
    [{ revocationFoundationMismatch: 'collision' }, 'CPSB_COLLISION_DECISION_SCHEMA:revocation:collision:uopc', [
      ['source-collision-decision.v2.schema.json', 'sourceCollisionDecisionV2', (graph) => graph.collisions[0]],
    ]],
    [{ revocationFoundationMismatch: 'g0' }, 'CPSB_G0_SCHEMA:foundation:g0', [
      ['binding-creation-authorization-g0.v1.schema.json', 'bindingCreationAuthorizationG0', (graph) => graph.g0],
    ]],
    [{ revocationFoundationMismatch: 'g1' }, 'CPSB_G1_SCHEMA:foundation:g1'],
    [{ revocationFoundationMismatch: 'b0' }, 'CPSB_B0_AUTH_SCHEMA:foundation:b0', [
      ['b0-execution-authorization.v1.schema.json', 'b0ExecutionAuthorization', (graph) => graph.b0],
    ]],
  ], 'CPSB_G1_SCHEMA:g1-catalog'],
  ['B0 alternate lowercase nonce propagates while private derivation fails', {}, 'b0-execution-authorization.v1.schema.json', 'b0ExecutionAuthorization', (graph) => graph.b0, [
    [{ nonceAlternate: true }, 'CPSB_B0_AUTH_SCHEMA:nonce-join'],
    [{ b0EacFoundationMismatch: true }, 'CPSB_B0_AUTH_SCHEMA:foundation:b0'],
  ], 'CPSB_B0_AUTH_SCHEMA:nonce-join'],
  ['event abort class with null predecessor leaves B0 initial', {}, 'instance-creation-event.v1.schema.json', 'instanceCreationEvent', (graph) => graph.event, [
    [{ eventAbort: true }, 'CPSB_B0_AUTH_SCHEMA:nonce-join'],
    [{ retryCausalMismatch: true }, 'CPSB_B0_AUTH_SCHEMA:retry-predecessor', [
      ['b0-execution-authorization.v1.schema.json', 'b0ExecutionAuthorization', (graph) => graph.b0],
      ['instance-creation-event.v1.schema.json', 'instanceCreationEvent', (graph) => graph.event],
    ]],
    [{ eventDecisionExpiredBeforeCreation: true }, 'CPSB_INSTANCE_EVENT_SCHEMA:time-stage:event', [
      ['issuer-decision.v1.schema.json', 'issuerDecision', (graph) => graph.decisions.at(-1)],
      ['instance-creation-event.v1.schema.json', 'instanceCreationEvent', (graph) => graph.event],
    ]],
  ], 'CPSB_B0_AUTH_SCHEMA:nonce-join'],
]);
for (const auditCase of auditCases) {
  test(`${auditCase[0]} is Ajv-valid but rejected by the synthetic graph oracle`, () => {
    const cases = Array.isArray(auditCase[5][0]) ? auditCase[5] : [[auditCase[5], auditCase[6]]];
    for (const causalCase of cases) {
      const graph = buildGraph(causalCase[0]);
      const caseRecords = causalCase[2] ?? [[auditCase[2], auditCase[3], auditCase[4]]];
      for (const caseRecord of caseRecords) {
        const compiled = validate(caseRecord[0], caseRecord[1]);
        assert.equal(compiled(copy(caseRecord[2](graph))), true, JSON.stringify(compiled.errors));
      }
      expectAuditFailure(graph, causalCase[1]);
    }
  });
}
