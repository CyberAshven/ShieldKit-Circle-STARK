import { createHash } from 'node:crypto';

export const PREFIX = 'shieldkit-labs/p2/gate-b/gate-b1-typed-protocol-descriptor/v1/';
export const TYPED_SCHEMA_URI = 'https://shieldkit-labs.local/p2/gate-b/gate-b1-typed-protocol-descriptor/v1/typed-protocol-descriptor/v1';
export const ARCHITECTURE_ROOT_DOMAIN = 'shieldkit-labs/p2/gate-b/gate-b1-typed-protocol-descriptor-schema/v1/schema-architecture-root';
export const LANE_PROJECTION_DOMAIN = 'shieldkit-labs/p2/gate-b/gate-b1-typed-protocol-descriptor-schema/v1/lane-authority-projection';
export const BLOCKED_V1_SCHEMA_ID = `${PREFIX}typed-protocol-descriptor/v1`;
export const ADDITIVE_V2_SCHEMA_ID = 'shieldkit-labs/p2/gate-b/gate-b1-typed-protocol-descriptor/v2/typed-protocol-descriptor/v2';
export const SAFE_PROTOCOL_PROJECTION_DOMAIN = `${PREFIX}non-authorizing-schema-architecture-projection`;
export const TYPED_SCHEMA_CANONICAL_SHA256 = 'd1f5777c40c8e2cccf58c888f692bb5e141864c6f7057939355c353879084664';
export const PENDING_LANGUAGE_STATUS = 'PENDING_ADDITIVE_SCHEMA_VERSION';
export const PENDING_MARKER_KEYS = Object.freeze(['candidateAdmissionAllowed', 'kind', 'languageStatus', 'qualificationEffect', 'reasonCode']);
export const PENDING_SURFACE_KEYS = Object.freeze([
  'protocolRoles', 'embeddingGraph', 'primitiveSuite', 'circle', 'air', 'masking', 'hashAndCommitment', 'transcript', 'samplers',
  'deep', 'fri', 'queries', 'proofEncoding', 'verifierTopology', 'transactionEnvelope', 'soundness', 'privacy', 'assumptionInventory'
]);
export const TOP_LEVEL_SECTIONS = Object.freeze([
  'schema', 'descriptorId', 'descriptorClass', 'contentDigest', 'qualificationBoundary', 'authorityBindings', 'sourceCatalog', 'scope',
  'algebraCatalog', 'fixedStatementInputValidation', ...PENDING_SURFACE_KEYS, 'protocolProjectionDigest', 'reviewPrerequisites', 'downstreamEvidenceSlots'
]);
export const SAFE_PROJECTION_SECTIONS = Object.freeze([
  'schema', 'descriptorId', 'descriptorClass', 'authorityBindings', 'sourceCatalog', 'scope', 'algebraCatalog', 'fixedStatementInputValidation', ...PENDING_SURFACE_KEYS
]);
export const SAFE_PROJECTION_EXCLUSIONS = Object.freeze([
  'contentDigest', 'qualificationBoundary', 'protocolProjectionDigest', 'reviewPrerequisites', 'downstreamEvidenceSlots', 'self'
]);

const pendingName = surface => surface.replace(/[A-Z]/gu, letter => `_${letter}`).toUpperCase();
export const PENDING_SURFACE_MARKERS = Object.freeze(Object.fromEntries(PENDING_SURFACE_KEYS.map(surface => [surface, Object.freeze({
  candidateAdmissionAllowed: false,
  kind: `${pendingName(surface)}_LANGUAGE_UNAVAILABLE`,
  languageStatus: PENDING_LANGUAGE_STATUS,
  qualificationEffect: 'NONE',
  reasonCode: `${pendingName(surface)}_PENDING_ADDITIVE_SCHEMA_VERSION`
})])));

export const FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY_ID = 'FIXED_STATEMENT_CODEC_SOURCE_AUTHORITY';
export const FIXED_STATEMENT_CODEC_EVIDENCE_ONLY_REASON = 'exact five codec source leaves are locally pinned as evidence-only; digest adapter authority and resolved v1 language remain unavailable';
export const FIXED_STATEMENT_CODEC_EVIDENCE_COMPONENTS = Object.freeze([
  Object.freeze({ bytes: 12903, componentRole: 'JSON_TO_FIXED_STATEMENT_PROJECTION', locator: 'research-lanes/bch-shielded-pool-design/p1/codec/statement-projection.mjs', rawSha256: '4d609aadd9f7a5c69d8518ecdc89d3e0f8d09b84306ca3f46dc6b61e3c39319d' }),
  Object.freeze({ bytes: 9938, componentRole: 'FIXED_STATEMENT_BINARY_CODEC', locator: 'research-lanes/bch-shielded-pool-design/p1/codec/pool-action-statement.mjs', rawSha256: '119c8742e2fcad89cff71c5a5ceaf3b2a15934e268cfcd1f41744073be379b3d' }),
  Object.freeze({ bytes: 9818, componentRole: 'CODEC_PRIMITIVES_WRITER_TAGS', locator: 'research-lanes/bch-shielded-pool-design/p1/codec/common.mjs', rawSha256: '756bf6817a3ef7479f0e1b088136982e6d63625f8143b3ba7f4464f71061c1c7' }),
  Object.freeze({ bytes: 3957, componentRole: 'TOKEN_VALIDATION', locator: 'research-lanes/bch-shielded-pool-design/p1/codec/token-record.mjs', rawSha256: '91ac90bdb4b65d7a518259cd41be69fce9afdf79a3af54e0983690042aefb130' }),
  Object.freeze({ bytes: 13065, componentRole: 'TX_CONTEXT_VALIDATION', locator: 'research-lanes/bch-shielded-pool-design/p1/codec/tx-context.mjs', rawSha256: 'd111ed7673f5fbff43f174607ae6de251884a7477d46d3e41b1e2715e5e03603' })
]);
export const FIXED_STATEMENT_CODEC_IMPORT_EDGE_RECORDS = Object.freeze([
  Object.freeze({ fromRole: 'JSON_TO_FIXED_STATEMENT_PROJECTION', toRole: 'CODEC_PRIMITIVES_WRITER_TAGS' }),
  Object.freeze({ fromRole: 'JSON_TO_FIXED_STATEMENT_PROJECTION', toRole: 'FIXED_STATEMENT_BINARY_CODEC' }),
  Object.freeze({ fromRole: 'JSON_TO_FIXED_STATEMENT_PROJECTION', toRole: 'TOKEN_VALIDATION' }),
  Object.freeze({ fromRole: 'JSON_TO_FIXED_STATEMENT_PROJECTION', toRole: 'TX_CONTEXT_VALIDATION' }),
  Object.freeze({ fromRole: 'FIXED_STATEMENT_BINARY_CODEC', toRole: 'CODEC_PRIMITIVES_WRITER_TAGS' }),
  Object.freeze({ fromRole: 'TOKEN_VALIDATION', toRole: 'CODEC_PRIMITIVES_WRITER_TAGS' }),
  Object.freeze({ fromRole: 'TX_CONTEXT_VALIDATION', toRole: 'CODEC_PRIMITIVES_WRITER_TAGS' }),
  Object.freeze({ fromRole: 'TX_CONTEXT_VALIDATION', toRole: 'TOKEN_VALIDATION' })
]);
export const FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY = Object.freeze({
  admissionAllowed: false,
  componentEvidence: FIXED_STATEMENT_CODEC_EVIDENCE_COMPONENTS,
  dependencyId: FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY_ID,
  digestAdapterAuthority: null,
  importEdges: FIXED_STATEMENT_CODEC_IMPORT_EDGE_RECORDS,
  kind: 'BLOCKED_EXTERNAL_REQUIREMENT',
  reason: FIXED_STATEMENT_CODEC_EVIDENCE_ONLY_REASON,
  requirementKind: 'FIXED_STATEMENT_CODEC_SOURCE_AUTHORITY',
  resolvedLanguageStatus: PENDING_LANGUAGE_STATUS,
  role: 'fixed-statement-codec-source-authority',
  validationMode: 'component-walk-read-regular-file-bytes-raw-sha256-only-no-import-no-evaluation-evidence-only-non-selectable'
});
const FIXED_STATEMENT_DIGEST_ADAPTER_AUTHORITIES = Object.freeze([
  Object.freeze({ adapterRawSha256: null, adapterSourceRef: null, admissionAllowed: false, algorithmRef: null, claimedDigestJsonSelector: null, digestRole: 'PAYOUT_LOCK', domainFraming: "UTF8('PoolActionFv1/PayoutLock') || u16le(length) || lockingBytecode", fixedStatementBinaryFieldRef: null, hashSubroleRef: null, outputByteWidth: 32, outputCodecRef: null, preimageConstructorComponentRole: 'FIXED_STATEMENT_BINARY_CODEC', preimageConstructorExport: null, preimageJsonSelector: null, status: 'BLOCKED_EXTERNAL', verificationMode: 'UNAVAILABLE_PENDING_SOURCE_AUTHORITY' }),
  Object.freeze({ adapterRawSha256: null, adapterSourceRef: null, admissionAllowed: false, algorithmRef: null, claimedDigestJsonSelector: null, digestRole: 'TRANSACTION_CONTEXT', domainFraming: "UTF8('PoolActionFv1/TxContext') || encodeTxContext(context)", fixedStatementBinaryFieldRef: null, hashSubroleRef: null, outputByteWidth: 32, outputCodecRef: null, preimageConstructorComponentRole: 'TX_CONTEXT_VALIDATION', preimageConstructorExport: null, preimageJsonSelector: null, status: 'BLOCKED_EXTERNAL', verificationMode: 'UNAVAILABLE_PENDING_SOURCE_AUTHORITY' })
]);
export const FIXED_STATEMENT_CODEC_BLOCKED_AUTHORITY = Object.freeze({
  admissionAllowed: false,
  artifact: 'pinned evidence-only fixed-statement projection and binary codec source closure',
  componentBindings: FIXED_STATEMENT_CODEC_EVIDENCE_COMPONENTS,
  digestAdapterAuthorities: FIXED_STATEMENT_DIGEST_ADAPTER_AUTHORITIES,
  digestAdapterAuthorityStatus: 'BLOCKED_EXTERNAL',
  importEdges: FIXED_STATEMENT_CODEC_IMPORT_EDGE_RECORDS,
  kind: 'PINNED_FIXED_STATEMENT_CODEC_SOURCE_CLOSURE_EVIDENCE_ONLY',
  reason: FIXED_STATEMENT_CODEC_EVIDENCE_ONLY_REASON,
  resolvedLanguageStatus: PENDING_LANGUAGE_STATUS,
  sourceCatalogEntryRef: 'source:fixed-statement-codec-authority',
  sourceClosureStatus: 'PINNED_EVIDENCE_ONLY',
  status: 'BLOCKED_EXTERNAL'
});
export const B0_OBSERVATION_DEPENDENCY_IDS = Object.freeze(['B0_M89_D2', 'B0_M61_D3', 'B0_M31_D5', 'B0_M31_D6']);
export const P0_REQUIRED_PROPERTY_NAMES = Object.freeze([
  'schema', 'relationVersion', 'profileId', 'networkId', 'poolInstanceIdHex', 'proofSecurityProfileDigestHex', 'actionKind', 'stateInput', 'stateOutput',
  'ticketSats', 'reserveDeltaSats', 'noteCommitmentHex', 'nullifierHex', 'payout', 'fee', 'carrierManifestDigestHex', 'transactionContextDigestHex', 'transactionContext'
]);
export const EXPECTED_DEPENDENCY_IDS = Object.freeze([
  'FIELD_FRONTIER', 'P0_FREEZE_MANIFEST', 'P0_THREAT', 'P0_THREAT_SCHEMA', 'P0_RELATION', 'P0_RELATION_SCHEMA', 'P0_CONFIG', 'P0_STATE', 'P0_STATE_SCHEMA',
  'P0_RESPONSIBILITY', 'P0_TX_BINDING', 'P0_VECTOR_INDEX', 'P0_VECTOR_SCHEMA', 'BCH_PROFILE', 'DESKTOP_PROFILE', 'SOUNDNESS_V2_SCHEMA', 'SOUNDNESS_CHECKER',
  'ZK_LEAKAGE_SCHEMA', 'B0_DESCRIPTOR_SCHEMA', ...B0_OBSERVATION_DEPENDENCY_IDS, 'SOURCE_MAP_ROOT', 'SOURCE_MAP_MANIFEST', 'SOURCE_MAP_SUMS',
  'SOURCE_MAP_VALIDATOR', 'LANE_AUTHORITY_PROJECTION', FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY_ID
]);
export const SOURCE_MAP_PINS = Object.freeze({
  b1ReentryBoundaryDigest: 'a0619058be75e650f155814b55be7af94069fba7fcdc48d743814c91cc127f29',
  checksums: Object.freeze({ path: 'p2/gate-b/cohort-upstream-provider-source-map-v1/SHA256SUMS', rawSha256: 'd89e2e670847abb483f83fdcc85c335fecf3d38b1239adb4a03e8ebb50a9ec51' }),
  manifest: Object.freeze({ path: 'p2/gate-b/cohort-upstream-provider-source-map-v1/MANIFEST.json', rawSha256: 'bc214e4ba6d6e2501b5a6f33a61947d9dce007ef8a1ca4c520d365285ac9ed76' }),
  nonAuthorityBoundaryDigest: 'b5c60933657ad66d992d5c703c0e4ae497b887fc53d01adbd5980c3923b3eb95',
  root: Object.freeze({ contentDigest: 'afddc9f5c7ff6a8f3950a50892e1ff281ab9f64e65f9f85df913e6e865cbf75b', path: 'p2/gate-b/cohort-upstream-provider-source-map-v1/upstream-provider-source-map-root.v1.json', rawSha256: '19268c8cfca0fc12038a6b89a23ccf7719a8d0f1337bd16bc10ab81647b0179a' }),
  validator: Object.freeze({ path: 'p2/gate-b/cohort-upstream-provider-source-map-v1/validate-static.mjs', rawSha256: '5c10f189bb33b1d334ab00e0cc5f92cf198289692ab6bf99718f3c3e2abb397d' })
});

const fail = code => { throw new Error(code); };
const assert = (condition, code) => { if (!condition) fail(code); };
export const canonicalJson = value => Array.isArray(value)
  ? `[${value.map(canonicalJson).join(',')}]`
  : value && typeof value === 'object'
    ? `{${Object.keys(value).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right))).map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const exactKeys = (value, keys, code) => assert(value && typeof value === 'object' && !Array.isArray(value) && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort()), code);
const equal = (actual, expected, code) => assert(canonicalJson(actual) === canonicalJson(expected), code);
const indexBy = (items, key, code) => {
  const index = new Map();
  for (const item of items) { const value = item?.[key]; assert(!index.has(value), code); index.set(value, item); }
  return index;
};

// JSON.parse silently overwrites duplicate members. Scan raw authority bytes
// before parsing so schemas and root pins cannot normalize an ambiguity away.
export const assertNoDuplicateJsonKeys = (raw, code = 'JSON') => {
  const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw); let offset = 0;
  const whitespace = () => { while (/[\u0009\u000a\u000d\u0020]/u.test(text[offset] ?? '')) offset += 1; };
  const string = () => { assert(text[offset] === '"', `${code}:STRING_OPEN`); const start = offset; offset += 1; while (offset < text.length) { const character = text[offset]; if (character === '"') { offset += 1; try { return JSON.parse(text.slice(start, offset)); } catch { fail(`${code}:STRING_ESCAPE`); } } if (character === '\\') { offset += 2; continue; } assert(character.charCodeAt(0) >= 0x20, `${code}:STRING_CONTROL`); offset += 1; } fail(`${code}:STRING_UNTERMINATED`); };
  const literal = value => { assert(text.startsWith(value, offset), `${code}:LITERAL`); offset += value.length; };
  const number = () => { const match = text.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u); assert(match, `${code}:NUMBER`); offset += match[0].length; };
  const value = () => { whitespace(); const character = text[offset]; if (character === '{') { offset += 1; whitespace(); const keys = new Set(); if (text[offset] === '}') { offset += 1; return; } while (true) { whitespace(); const key = string(); assert(!keys.has(key), `${code}:DUPLICATE_KEY`); keys.add(key); whitespace(); assert(text[offset] === ':', `${code}:OBJECT_COLON`); offset += 1; value(); whitespace(); if (text[offset] === '}') { offset += 1; return; } assert(text[offset] === ',', `${code}:OBJECT_COMMA`); offset += 1; } } if (character === '[') { offset += 1; whitespace(); if (text[offset] === ']') { offset += 1; return; } while (true) { value(); whitespace(); if (text[offset] === ']') { offset += 1; return; } assert(text[offset] === ',', `${code}:ARRAY_COMMA`); offset += 1; } } if (character === '"') { string(); return; } if (character === 't') { literal('true'); return; } if (character === 'f') { literal('false'); return; } if (character === 'n') { literal('null'); return; } number(); };
  value(); whitespace(); assert(offset === text.length, `${code}:TRAILING_BYTES`); return true;
};
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const fileDigest = (domain, bytes) => sha256(Buffer.concat([Buffer.from(domain), Buffer.from([0]), Buffer.from(bytes)]));
export const digestPreimage = (domain, preimage) => sha256(Buffer.concat([Buffer.from(domain), Buffer.from([0]), Buffer.from(`${canonicalJson(preimage)}\n`)]));
export const digestRecord = (domain, preimage) => ({ algorithm: 'sha256', canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1', domain, frame: 'utf8(domain)||0x00||canonical-json-utf8-lf-v1', value: digestPreimage(domain, preimage) });
const omitOwnContentDigest = value => { assert(value && typeof value === 'object' && !Array.isArray(value), 'DIGEST_PREIMAGE_OBJECT'); const { contentDigest, ...preimage } = value; return preimage; };
export const semanticDigest = (domain, value) => digestPreimage(domain, omitOwnContentDigest(value));

export const assertFixedStatementCodecBlockedDependency = (entry, code = 'FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY') => {
  exactKeys(entry, ['admissionAllowed', 'componentEvidence', 'dependencyId', 'digestAdapterAuthority', 'importEdges', 'kind', 'reason', 'requirementKind', 'resolvedLanguageStatus', 'role', 'validationMode'], `${code}:KEYS`);
  equal(entry, FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY, `${code}:SHAPE`);
  return entry.componentEvidence;
};
export const assertFixedStatementCodecSourceAuthority = ({ authority, sourceEntry = undefined, code = 'FIXED_STATEMENT_CODEC_AUTHORITY' }) => {
  exactKeys(authority, ['admissionAllowed', 'artifact', 'componentBindings', 'digestAdapterAuthorities', 'digestAdapterAuthorityStatus', 'importEdges', 'kind', 'reason', 'resolvedLanguageStatus', 'sourceCatalogEntryRef', 'sourceClosureStatus', 'status'], `${code}:KEYS`);
  equal(authority, FIXED_STATEMENT_CODEC_BLOCKED_AUTHORITY, `${code}:BLOCKED_SHAPE`);
  if (sourceEntry !== undefined) equal(sourceEntry, { dependencyKind: 'FIXED_STATEMENT_CODEC_SOURCE_AUTHORITY', source: { availability: 'BLOCKED_EXTERNAL', reason: FIXED_STATEMENT_CODEC_EVIDENCE_ONLY_REASON, requirementKind: 'FIXED_STATEMENT_CODEC_SOURCE_AUTHORITY' }, sourceId: 'source:fixed-statement-codec-authority' }, `${code}:SOURCE_ENTRY`);
  return false;
};
export const assertB0NonAdmittingObservations = (catalog, code = 'B0_NONADMITTING_OBSERVATIONS') => {
  exactKeys(catalog, ['candidateAdmissionAllowed', 'kind', 'observationDependencyIds', 'qualificationEffect'], `${code}:KEYS`);
  equal(catalog, { candidateAdmissionAllowed: false, kind: 'B0_SOURCE_PINNED_NONADMITTING_OBSERVATIONS', observationDependencyIds: B0_OBSERVATION_DEPENDENCY_IDS, qualificationEffect: 'NONE' }, `${code}:SHAPE`);
  return false;
};
export const assertFixedStatementInputValidation = (validation, code = 'FIXED_STATEMENT_INPUT_VALIDATION') => {
  exactKeys(validation, ['actionContracts', 'authorityRoleRef', 'kind', 'status'], `${code}:KEYS`);
  assert(validation.authorityRoleRef === 'fixedStatementCodecSourceAuthority' && validation.kind === 'P0_RELATION_SCHEMA_JSON_INPUT_VALIDATION' && validation.status === 'BLOCKED_EXTERNAL', `${code}:IDENTITY`);
  assert(Array.isArray(validation.actionContracts) && validation.actionContracts.length === 2, `${code}:ACTION_ROSTER`);
  const actions = validation.actionContracts.map(item => item?.action); equal(actions, ['DEPOSIT', 'WITHDRAWAL'], `${code}:ACTION_ORDER`);
  validation.actionContracts.forEach(contract => {
    exactKeys(contract, ['action', 'kind', 'p0RelationSchemaSelector', 'requiredPropertySelectors'], `${code}:CONTRACT_KEYS`);
    assert(contract.kind === 'P0_RELATION_SCHEMA_REQUIRED_PROPERTY_SELECTOR_COVERAGE', `${code}:CONTRACT_KIND`);
    exactKeys(contract.p0RelationSchemaSelector, ['selector', 'selectorKind', 'sourceRef'], `${code}:SCHEMA_SELECTOR_KEYS`);
    assert(contract.p0RelationSchemaSelector.selector === '' && contract.p0RelationSchemaSelector.selectorKind === 'JSON_POINTER', `${code}:SCHEMA_SELECTOR`);
    assert(Array.isArray(contract.requiredPropertySelectors) && contract.requiredPropertySelectors.length === P0_REQUIRED_PROPERTY_NAMES.length, `${code}:PROPERTY_COUNT`);
    contract.requiredPropertySelectors.forEach((selector, ordinal) => {
      exactKeys(selector, ['selector', 'selectorKind', 'sourceRef'], `${code}:PROPERTY_SELECTOR_KEYS`);
      assert(selector.selector === `/properties/${P0_REQUIRED_PROPERTY_NAMES[ordinal]}` && selector.selectorKind === 'JSON_POINTER' && selector.sourceRef === contract.p0RelationSchemaSelector.sourceRef, `${code}:PROPERTY_SELECTOR:${ordinal}`);
    });
  });
  return validation;
};

export const assertPendingSurfaceMarker = (surface, marker, code = 'PENDING_SURFACE_MARKER') => {
  assert(PENDING_SURFACE_KEYS.includes(surface), `${code}:SURFACE`);
  exactKeys(marker, PENDING_MARKER_KEYS, `${code}:${surface}:KEYS`);
  equal(marker, PENDING_SURFACE_MARKERS[surface], `${code}:${surface}:SHAPE`);
  return marker;
};
export const assertPendingDescriptorBoundary = ({ qualificationBoundary, pendingSurfaces, protocolProjectionDigest = undefined, protocolProjectionPreimage = undefined, code = 'PENDING_DESCRIPTOR_BOUNDARY' }) => {
  exactKeys(qualificationBoundary, ['candidateInstantiationAllowed', 'executionAllowed', 'fallbackAuthorization', 'fallbackAuthorized', 'providerResolutionAllowed', 'qualificationAllowed'], `${code}:QUALIFICATION_KEYS`);
  equal(qualificationBoundary, { candidateInstantiationAllowed: false, executionAllowed: false, fallbackAuthorization: { kind: 'NONE' }, fallbackAuthorized: false, providerResolutionAllowed: false, qualificationAllowed: false }, `${code}:QUALIFICATION_SHAPE`);
  exactKeys(pendingSurfaces, PENDING_SURFACE_KEYS, `${code}:SURFACE_ROSTER`);
  PENDING_SURFACE_KEYS.forEach(surface => assertPendingSurfaceMarker(surface, pendingSurfaces[surface], code));
  if (protocolProjectionDigest !== undefined) assertNonAuthorizingProtocolProjectionDigest(protocolProjectionDigest, `${code}:PROJECTION`, protocolProjectionPreimage);
  return false;
};
export const safeProtocolProjectionPreimage = descriptor => {
  return Object.fromEntries(SAFE_PROJECTION_SECTIONS.map(section => [section, descriptor[section]]));
};
export const assertNonAuthorizingProtocolProjectionDigest = (projection, code = 'NONAUTHORIZING_PROTOCOL_PROJECTION', expectedPreimage = undefined) => {
  exactKeys(projection, ['contentDigest', 'excludedSections', 'includedSections', 'kind'], `${code}:KEYS`);
  assert(projection.kind === 'NONAUTHORIZING_SCHEMA_ARCHITECTURE_PROJECTION_DIGEST', `${code}:KIND`);
  equal(projection.includedSections, SAFE_PROJECTION_SECTIONS, `${code}:INCLUDED_SECTIONS`);
  equal(projection.excludedSections, SAFE_PROJECTION_EXCLUSIONS, `${code}:EXCLUDED_SECTIONS`);
  const partition = [...projection.includedSections, ...projection.excludedSections.filter(section => section !== 'self')];
  assert(new Set(partition).size === TOP_LEVEL_SECTIONS.length, `${code}:SECTION_PARTITION_DUPLICATE`);
  equal([...partition].sort(), [...TOP_LEVEL_SECTIONS].sort(), `${code}:SECTION_PARTITION`);
  exactKeys(projection.contentDigest, ['algorithm', 'canonicalization', 'domain', 'frame', 'value'], `${code}:DIGEST_KEYS`);
  assert(projection.contentDigest.algorithm === 'sha256' && projection.contentDigest.canonicalization === 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1' && projection.contentDigest.frame === 'utf8(domain)||0x00||canonical-json-utf8-lf-v1' && projection.contentDigest.domain === SAFE_PROTOCOL_PROJECTION_DOMAIN && /^[0-9a-f]{64}$/u.test(projection.contentDigest.value), `${code}:DIGEST_SHAPE`);
  if (expectedPreimage !== undefined) {
    exactKeys(expectedPreimage, SAFE_PROJECTION_SECTIONS, `${code}:PREIMAGE_SECTIONS`);
    equal(projection.contentDigest, digestRecord(SAFE_PROTOCOL_PROJECTION_DOMAIN, expectedPreimage), `${code}:DIGEST_VALUE`);
  }
  return projection;
};

const allowedExternalRefs = new Set([
  'https://shieldkit-labs.local/p2/gate-b/gate-b1-typed-protocol-descriptor/v1/common.v1.schema.json#/$defs/nullEvidenceSlot',
  'https://shieldkit-labs.local/p2/gate-b/gate-b1-typed-protocol-descriptor/v1/digest.v1.schema.json',
  'https://shieldkit-labs.local/p2/gate-b/gate-b1-typed-protocol-descriptor/v1/source-reference.v1.schema.json'
]);
export const SAFE_TYPED_SCHEMA_DEFINITIONS = Object.freeze([
  'algebraCatalog', 'authorityBindings', 'b0NonAdmittingObservations', 'descriptorId', 'downstreamEvidenceSlots',
  'fallbackAuthorization', 'fixedStatementActionInputContract', 'fixedStatementCodecSourceAuthority', 'fixedStatementInputValidation', 'pendingMarkerAssumptionInventory',
  'pendingMarkerAir', 'pendingMarkerCircle', 'pendingMarkerDeep', 'pendingMarkerEmbeddingGraph', 'pendingMarkerFri', 'pendingMarkerHashAndCommitment',
  'pendingMarkerMasking', 'pendingMarkerPrimitiveSuite', 'pendingMarkerPrivacy', 'pendingMarkerProofEncoding', 'pendingMarkerProtocolRoles', 'pendingMarkerQueries',
  'pendingMarkerSamplers', 'pendingMarkerSoundness', 'pendingMarkerTranscript', 'pendingMarkerTransactionEnvelope', 'pendingMarkerVerifierTopology',
  'protocolProjectionDigest', 'qualificationBoundary', 'reviewPrerequisites', 'scope', 'sourceCatalog', 'sourceCatalogEntry', 'sourceId'
]);
const markerDefinitionForSurface = surface => `pendingMarker${surface[0].toUpperCase()}${surface.slice(1)}`;
const forbiddenSchemaKeywords = new Set(['$anchor', '$dynamicAnchor', '$dynamicRef', '$recursiveAnchor', '$recursiveRef']);
const markerCombinators = new Set(['allOf', 'anyOf', 'contains', 'dependentRequired', 'dependentSchemas', 'else', 'if', 'not', 'oneOf', 'patternProperties', 'propertyNames', 'then', 'unevaluatedProperties']);
export const assertTypedSchemaRefReachability = (schema, code = 'TYPED_SCHEMA_REACHABILITY') => {
  assert(schema && typeof schema === 'object' && !Array.isArray(schema), `${code}:DOCUMENT`);
  exactKeys(schema, ['$defs', '$id', '$schema', 'additionalProperties', 'properties', 'required', 'title', 'type'], `${code}:ROOT_KEYS`);
  assert(schema.$id === TYPED_SCHEMA_URI, `${code}:ID`);
  assert(schema.$schema === 'https://json-schema.org/draft/2020-12/schema' && schema.additionalProperties === false && schema.title === 'Gate B1 blocked v1 descriptor schema architecture' && schema.type === 'object', `${code}:ROOT_SHAPE`);
  exactKeys(schema.properties, TOP_LEVEL_SECTIONS, `${code}:ROOT_PROPERTY_KEYS`);
  equal(schema.required, TOP_LEVEL_SECTIONS, `${code}:ROOT_REQUIRED_KEYS`);
  const definitions = schema.$defs; exactKeys(definitions, SAFE_TYPED_SCHEMA_DEFINITIONS, `${code}:DEFINITION_ALLOWLIST`);
  const reachable = new Set();
  const visit = (value, marker = false) => {
    if (Array.isArray(value)) return value.forEach(item => visit(item, marker));
    if (!value || typeof value !== 'object') return;
    Object.keys(value).forEach(key => {
      assert(!forbiddenSchemaKeywords.has(key), `${code}:DYNAMIC_OR_RECURSIVE_REFERENCE:${key}`);
      if (marker) assert(!markerCombinators.has(key), `${code}:MARKER_COMBINATOR:${key}`);
    });
    if (Object.hasOwn(value, '$ref')) {
      const ref = value.$ref; assert(typeof ref === 'string', `${code}:REF_TYPE`);
      if (ref.startsWith('#/$defs/')) {
        const name = ref.slice('#/$defs/'.length); assert(SAFE_TYPED_SCHEMA_DEFINITIONS.includes(name) && Object.hasOwn(definitions, name), `${code}:SUBDEFINITION_REF:${name}`);
        if (!reachable.has(name)) { reachable.add(name); visit(definitions[name], name.startsWith('pendingMarker')); }
      } else assert(allowedExternalRefs.has(ref), `${code}:EXTERNAL_REF:${ref}`);
    }
    Object.entries(value).forEach(([key, item]) => { if (key !== '$defs' && key !== '$ref') visit(item, marker); });
  };
  visit(Object.fromEntries(Object.entries(schema).filter(([key]) => key !== '$defs')));
  equal([...reachable].sort(), [...SAFE_TYPED_SCHEMA_DEFINITIONS].sort(), `${code}:UNREACHABLE_OR_HIDDEN_DEFINITION`);
  PENDING_SURFACE_KEYS.forEach(surface => {
    const name = markerDefinitionForSurface(surface); const definition = definitions[name];
    equal(schema.properties[surface], { $ref: `#/$defs/${name}` }, `${code}:ROOT_MARKER_REF:${surface}`);
    exactKeys(definition, ['additionalProperties', 'properties', 'required', 'type'], `${code}:MARKER_DEF_KEYS:${surface}`);
    assert(definition.additionalProperties === false && definition.type === 'object', `${code}:MARKER_DEF_SHAPE:${surface}`);
    exactKeys(definition.properties, PENDING_MARKER_KEYS, `${code}:MARKER_PROPERTY_KEYS:${surface}`);
    equal(definition.properties, Object.fromEntries(PENDING_MARKER_KEYS.map(key => [key, { const: PENDING_SURFACE_MARKERS[surface][key] }])), `${code}:MARKER_PROPERTY_DEFINITIONS:${surface}`);
    equal(definition.required, PENDING_MARKER_KEYS, `${code}:MARKER_REQUIRED_KEYS:${surface}`);
  });
  assert(sha256(Buffer.from(`${canonicalJson(schema)}\n`)) === TYPED_SCHEMA_CANONICAL_SHA256, `${code}:CANONICAL_DOCUMENT`);
  return [...reachable].sort();
};

export const extractLaneAuthorityProjection = lane => {
  assert(lane && typeof lane === 'object' && !Array.isArray(lane), 'LANE_AUTHORITY_DOCUMENT');
  for (const key of ['apiVersion', 'kind', 'id', 'objective', 'scopeDecision', 'proofBackendDecision', 'productDecisions', 'promotionGate', 'p2FieldCheckpoint']) assert(Object.hasOwn(lane, key), `LANE_AUTHORITY_MISSING:${key}`);
  const binding = lane.p2FieldCheckpoint?.cohortUpstreamProviderSourceMapV1Binding;
  assert(binding && typeof binding === 'object', 'LANE_AUTHORITY_SOURCE_MAP_BINDING');
  const projection = {
    schema: 'shieldkit-labs/p2/gate-b/gate-b1-typed-protocol-descriptor-schema/v1/lane-authority-projection/v0',
    laneIdentity: { apiVersion: lane.apiVersion, kind: lane.kind, id: lane.id }, objective: lane.objective,
    scopeDecision: lane.scopeDecision, proofBackendDecision: lane.proofBackendDecision,
    productDecisions: lane.productDecisions, promotionGate: lane.promotionGate,
    sourceMapIntegration: { path: binding.path, root: binding.root, nonAuthorityBoundaryDigest: binding.nonAuthorityBoundaryDigest, b1ReentryBoundaryDigest: binding.b1ReentryBoundaryDigest, status: binding.status }
  };
  projection.contentDigest = digestRecord(LANE_PROJECTION_DOMAIN, projection);
  return projection;
};
export const assertNoInstanceBoundary = root => {
  assert(Array.isArray(root.candidateDescriptors) && root.candidateDescriptors.length === 0, 'NO_INSTANCE_CANDIDATE_DESCRIPTORS');
  assert(Array.isArray(root.evidence) && root.evidence.length === 0, 'NO_INSTANCE_EVIDENCE');
  equal(root.noInstanceBoundary, { candidateDescriptors: false, deploymentData: false, evidence: false, parameterAssignments: false, providerInstances: false, roleAssignments: false }, 'NO_INSTANCE_BOUNDARY');
  equal(root.b1ReentryBoundary, { candidateDescriptorsBlocked: true, executionAllowed: false, gateB0ReviewRequired: true, packageOpensCandidateGate: false, schemaArchitectureOnly: true }, 'B1_REENTRY_BOUNDARY');
};
export const assertArchitectureRoot = ({ root, lane, typedSchemaRawSha256 }) => {
  exactKeys(root, ['architectureIdentity', 'b1ReentryBoundary', 'candidateDescriptors', 'contentDigest', 'dependencyCatalog', 'descriptorContract', 'evidence', 'laneAuthorityProjection', 'noInstanceBoundary', 'schema', 'sourceMapBoundary', 'status'], 'ROOT_KEYS');
  assert(root.schema === 'shieldkit-labs/p2/gate-b/gate-b1-typed-protocol-descriptor-schema/v1/architecture-root/v1', 'ROOT_SCHEMA');
  assert(root.status === 'static-blocked-v1-schema-architecture-unsealed-no-descriptor-no-instance-non-authorizing-unqualified', 'ROOT_STATUS');
  equal(root.architectureIdentity, { descriptorIdentity: 'gate-b1-protocol-descriptor', deploymentIdentity: 'pool-deployment-instance', schemaIdentity: 'gate-b1-schema-architecture' }, 'IDENTITY_SEPARATION');
  assertNoInstanceBoundary(root);
  exactKeys(root.descriptorContract, ['blockedV1', 'resolvedTarget'], 'DESCRIPTOR_CONTRACT_KEYS');
  equal(root.descriptorContract.blockedV1, {
    pendingSurfaceKeys: PENDING_SURFACE_KEYS,
    rawSha256: typedSchemaRawSha256,
    safeProjectionDigestPolicy: 'acyclic-safe-observations-and-pending-markers-excludes-qualification-evidence-and-self',
    schemaId: BLOCKED_V1_SCHEMA_ID,
    schemaPath: 'schemas/typed-protocol-descriptor.v1.schema.json',
    status: 'BLOCKED_NON_AUTHORIZING_SCHEMA_ARCHITECTURE',
    topLevelSections: TOP_LEVEL_SECTIONS
  }, 'BLOCKED_V1_CONTRACT');
  equal(root.descriptorContract.resolvedTarget, { rawSha256: null, schemaId: ADDITIVE_V2_SCHEMA_ID, schemaPath: null, status: PENDING_LANGUAGE_STATUS }, 'ADDITIVE_V2_TARGET');
  const projection = extractLaneAuthorityProjection(lane); equal(root.laneAuthorityProjection, projection, 'LANE_AUTHORITY_PROJECTION_DRIFT');
  const entries = root.dependencyCatalog.entries; const byId = indexBy(entries, 'dependencyId', 'DEPENDENCY_ID_DUPLICATE');
  equal(entries.map(entry => entry.dependencyId), EXPECTED_DEPENDENCY_IDS, 'DEPENDENCY_ID_ORDER');
  assertFixedStatementCodecBlockedDependency(byId.get(FIXED_STATEMENT_CODEC_BLOCKED_DEPENDENCY_ID));
  const laneEntry = byId.get('LANE_AUTHORITY_PROJECTION');
  equal(laneEntry, { dependencyId: 'LANE_AUTHORITY_PROJECTION', kind: 'JSON_TYPED_PROJECTION', locator: 'research-lanes/bch-shielded-pool-design/lane.json', projectionDigest: projection.contentDigest.value, projectionId: 'lane-authority:bch-shielded-pool-design-gate-b1-v1', projectionSchemaId: projection.schema, role: 'lane-authority-projection', validationMode: 'read-current-regular-json-bytes-extract-exact-projection' }, 'LANE_AUTHORITY_DEPENDENCY_DRIFT');
  assert(root.dependencyCatalog.contentDigest?.value === semanticDigest(`${PREFIX}dependency-catalog`, root.dependencyCatalog), 'DEPENDENCY_CATALOG_DIGEST');
  equal(root.sourceMapBoundary.root, SOURCE_MAP_PINS.root, 'SOURCE_MAP_ROOT_PIN');
  equal(root.sourceMapBoundary.manifest, SOURCE_MAP_PINS.manifest, 'SOURCE_MAP_MANIFEST_PIN');
  equal(root.sourceMapBoundary.checksums, SOURCE_MAP_PINS.checksums, 'SOURCE_MAP_SUMS_PIN');
  equal(root.sourceMapBoundary.validator, SOURCE_MAP_PINS.validator, 'SOURCE_MAP_VALIDATOR_PIN');
  assert(root.sourceMapBoundary.nonAuthorityBoundaryDigest === SOURCE_MAP_PINS.nonAuthorityBoundaryDigest && root.sourceMapBoundary.b1ReentryBoundaryDigest === SOURCE_MAP_PINS.b1ReentryBoundaryDigest && root.sourceMapBoundary.providerResolutionAllowed === false, 'SOURCE_MAP_NONAUTHORITY_BOUNDARY');
  assert(root.contentDigest?.value === semanticDigest(ARCHITECTURE_ROOT_DOMAIN, root), 'ROOT_CONTENT_DIGEST');
  return { dependencyDigest: root.dependencyCatalog.contentDigest.value, projectionDigest: projection.contentDigest.value, rootDigest: root.contentDigest.value };
};

export const validateTypedDescriptorSemantics = descriptor => {
  exactKeys(descriptor, TOP_LEVEL_SECTIONS, 'DESCRIPTOR_TOP_LEVEL_KEYS');
  assert(descriptor.schema === BLOCKED_V1_SCHEMA_ID && descriptor.descriptorClass === 'gate-b1-protocol-descriptor', 'DESCRIPTOR_IDENTITY');
  const pendingSurfaces = Object.fromEntries(PENDING_SURFACE_KEYS.map(surface => [surface, descriptor[surface]]));
  assertPendingDescriptorBoundary({ qualificationBoundary: descriptor.qualificationBoundary, pendingSurfaces, protocolProjectionDigest: descriptor.protocolProjectionDigest, protocolProjectionPreimage: safeProtocolProjectionPreimage(descriptor), code: 'DESCRIPTOR_PENDING_BOUNDARY' });
  fail('DESCRIPTOR_LANGUAGE_PENDING_ADDITIVE_SCHEMA_VERSION');
};
