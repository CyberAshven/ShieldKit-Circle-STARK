/**
 * Deterministic, non-executing transport for a source-set plan.
 *
 * This module only serializes an exact one-input fixture. It never evaluates a
 * BCH VM and deliberately retains the caller's raw operand bytes unchanged.
 */

import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const REPOSITORY_ROOT = resolve(here, '../../../../..');
export const SOURCE_SET_DIRECTORY = resolve(REPOSITORY_ROOT, 'research-lanes/bch-shielded-pool-design/p2/source-set-v1');
export const SOURCE_SET_ROOT_PATH = resolve(SOURCE_SET_DIRECTORY, 'source-set.v1.json');

export const SOURCE_VALUE_SATOSHIS = 1000n;
export const OUTPUT_VALUE_SATOSHIS = 1000n;
export const MAX_DATA_PUSH_BYTES = 0xffff;
export const VERIFIED_EXECUTION_CEILING_BYTES = 10000;
export const FIXTURE_ARTIFACT_ID = 'artifact:gate-b:cohort-freeze-v2:execution-fixture';
export const DUMMY_OUTPOINT_HASH = Uint8Array.from({ length: 32 }, () => 0x11);
export const OUTPUT_LOCKING_BYTECODE = Uint8Array.of(0x51);

const sha256Bytes = (value) => createHash('sha256').update(value).digest();
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
export const hash256 = (value) => sha256Bytes(sha256Bytes(value));
export const hex = (value) => Buffer.from(value).toString('hex');

const require = (condition, message) => {
  if (!condition) throw new TypeError(message);
};

const bytesEqual = (left, right) => Buffer.from(left).equals(Buffer.from(right));
const byteLength = (value) => Buffer.byteLength(value);

export const byteBinding = (value) => Object.freeze({
  byteLength: value.length,
  sha256: sha256(value),
});

const assertNoSymlinkComponents = (root, target) => {
  const rootReal = realpathSync(root);
  const candidate = resolve(rootReal, target);
  const rel = relative(rootReal, candidate);
  require(rel !== '' && !rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel), `path escapes root: ${target}`);
  let cursor = rootReal;
  for (const component of rel.split(sep)) {
    require(component !== '' && component !== '.' && component !== '..', `invalid path component: ${target}`);
    cursor = resolve(cursor, component);
    require(!lstatSync(cursor).isSymbolicLink(), `symlink component forbidden: ${target}`);
  }
  const targetReal = realpathSync(candidate);
  const targetRel = relative(rootReal, targetReal);
  require(!targetRel.startsWith(`..${sep}`) && targetRel !== '..' && !isAbsolute(targetRel), `realpath escapes root: ${target}`);
  return targetReal;
};

export const assertContainedRegularFile = (root, relativePath) => {
  require(typeof relativePath === 'string' && relativePath.length > 0 && !isAbsolute(relativePath), 'relative file path required');
  const path = assertNoSymlinkComponents(root, relativePath);
  require(lstatSync(path).isFile(), `regular file required: ${relativePath}`);
  return path;
};

export const parseLowercaseEvenHex = (value, label = 'hex') => {
  require(typeof value === 'string' && /^[0-9a-f]*$/u.test(value) && value.length % 2 === 0, `${label} must be lowercase even hexadecimal`);
  return Uint8Array.from(Buffer.from(value, 'hex'));
};

const readHexArtifact = (root, relativePath, expectedBinding) => {
  const path = assertContainedRegularFile(root, relativePath);
  const text = readFileSync(path, 'utf8');
  require(/^[0-9a-f]+\n$/u.test(text), `${relativePath} must be lowercase hex followed by one LF`);
  const value = parseLowercaseEvenHex(text.slice(0, -1), relativePath);
  require(value.length === expectedBinding.byteLength, `${relativePath} byte length drift`);
  require(sha256(value) === expectedBinding.sha256, `${relativePath} raw SHA-256 drift`);
  return value;
};

/** Bitcoin CompactSize without accepting a nonminimal representation. */
export const encodeCompactSize = (value) => {
  require(Number.isSafeInteger(value) && value >= 0, 'CompactSize value must be a nonnegative safe integer');
  if (value < 0xfd) return Uint8Array.of(value);
  if (value <= 0xffff) return Uint8Array.of(0xfd, value & 0xff, value >>> 8);
  if (value <= 0xffffffff) return Uint8Array.of(0xfe, value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
  const wide = BigInt(value);
  return Uint8Array.from([0xff, ...Array.from({ length: 8 }, (_, index) => Number((wide >> BigInt(index * 8)) & 0xffn))]);
};

const u32le = (value) => {
  require(Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff, 'u32 out of range');
  return Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
};

const u64le = (value) => {
  require(typeof value === 'bigint' && value >= 0n && value <= 0xffffffffffffffffn, 'u64 out of range');
  return Uint8Array.from(Array.from({ length: 8 }, (_, index) => Number((value >> BigInt(index * 8)) & 0xffn)));
};

const join = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));

/**
 * Minimal-data serializer. The special one-byte Script number opcodes are
 * required by BCH minimal-push rules but still push the exact same raw bytes.
 */
export const encodeMinimalDataPush = (value) => {
  require(value instanceof Uint8Array, 'push payload must be Uint8Array');
  require(value.length <= MAX_DATA_PUSH_BYTES, `push payload exceeds ${MAX_DATA_PUSH_BYTES} byte encoding maximum`);
  if (value.length === 0) return Uint8Array.of(0x00);
  // BCHN CheckMinimalPush accepts direct one-byte raw 00/80 pushes. They are
  // intentionally distinct from OP_0 (empty) and preserve the corpus bytes.
  if (value.length === 1 && value[0] >= 1 && value[0] <= 16) return Uint8Array.of(0x50 + value[0]);
  if (value.length === 1 && value[0] === 0x81) return Uint8Array.of(0x4f);
  if (value.length <= 75) return join(Uint8Array.of(value.length), value);
  if (value.length <= 0xff) return join(Uint8Array.of(0x4c, value.length), value);
  return join(Uint8Array.of(0x4d, value.length & 0xff, value.length >>> 8), value);
};

/** Parse and reject nonminimal, truncated, non-push, and oversized encodings. */
export const decodeMinimalDataPushes = (encoded) => {
  require(encoded instanceof Uint8Array, 'encoded pushes must be Uint8Array');
  const pushes = [];
  for (let offset = 0; offset < encoded.length;) {
    const opcode = encoded[offset++];
    let length;
    if (opcode === 0x00) length = 0;
    else if (opcode === 0x4f) {
      pushes.push(Uint8Array.of(0x81));
      continue;
    } else if (opcode >= 0x51 && opcode <= 0x60) {
      pushes.push(Uint8Array.of(opcode - 0x50));
      continue;
    } else if (opcode >= 1 && opcode <= 75) length = opcode;
    else if (opcode === 0x4c) {
      require(offset < encoded.length, 'truncated OP_PUSHDATA1 length');
      length = encoded[offset++];
      require(length > 75, 'nonminimal OP_PUSHDATA1');
    } else if (opcode === 0x4d) {
      require(offset + 1 < encoded.length, 'truncated OP_PUSHDATA2 length');
      length = encoded[offset] | (encoded[offset + 1] << 8);
      offset += 2;
      require(length > 0xff, 'nonminimal OP_PUSHDATA2');
    } else {
      throw new TypeError(`non-push or unsupported push opcode 0x${opcode.toString(16).padStart(2, '0')}`);
    }
    require(length <= MAX_DATA_PUSH_BYTES, `push payload exceeds ${MAX_DATA_PUSH_BYTES} byte encoding maximum`);
    require(offset + length <= encoded.length, 'truncated push payload');
    const payload = encoded.slice(offset, offset + length);
    offset += length;
    require(bytesEqual(encodeMinimalDataPush(payload), encoded.slice(offset - length - (opcode === 0x4c ? 2 : opcode === 0x4d ? 3 : 1), offset)), 'nonminimal data push');
    pushes.push(payload);
  }
  return Object.freeze(pushes);
};

const encodeOutput = ({ valueSatoshis, lockingBytecode }) => join(
  u64le(valueSatoshis), encodeCompactSize(lockingBytecode.length), lockingBytecode,
);

const encodeTransaction = ({ unlockingBytecode, outputLockingBytecode }) => join(
  u32le(2),
  Uint8Array.of(1),
  DUMMY_OUTPOINT_HASH,
  u32le(0),
  encodeCompactSize(unlockingBytecode.length),
  unlockingBytecode,
  u32le(0xffffffff),
  Uint8Array.of(1),
  encodeOutput({ valueSatoshis: OUTPUT_VALUE_SATOSHIS, lockingBytecode: outputLockingBytecode }),
  u32le(0),
);

const encodeSourceOutputs = ({ sourceLockingBytecode }) => join(
  Uint8Array.of(1),
  encodeOutput({ valueSatoshis: SOURCE_VALUE_SATOSHIS, lockingBytecode: sourceLockingBytecode }),
);

export const p2sh32LockingBytecode = (redeemBytecode) => {
  require(redeemBytecode instanceof Uint8Array, 'redeem bytecode must be Uint8Array');
  return join(Uint8Array.of(0xaa, 0x20), hash256(redeemBytecode), Uint8Array.of(0x87));
};

const assertExactPushSequence = (encoded, expected, label) => {
  const decoded = decodeMinimalDataPushes(encoded);
  require(decoded.length === expected.length, `${label} push count drift`);
  decoded.forEach((item, index) => require(bytesEqual(item, expected[index]), `${label} push ${index} byte drift`));
};

/** Read a complete source-set plan without accepting path escape or byte drift. */
export const loadSourceSetPlan = (planId, { sourceSetDirectory = SOURCE_SET_DIRECTORY } = {}) => {
  require(typeof planId === 'string' && planId.length > 0, 'planId required');
  const rootPath = assertContainedRegularFile(sourceSetDirectory, 'source-set.v1.json');
  const sourceSetBytes = readFileSync(rootPath);
  const sourceSet = JSON.parse(sourceSetBytes.toString('utf8'));
  const plan = sourceSet.planIndex?.find((entry) => entry.planId === planId);
  require(plan !== undefined, `unknown source-set plan: ${planId}`);
  require(Number.isInteger(plan.orderIndex) && plan.orderIndex >= 0, 'invalid plan order');
  const redeemBytecode = readHexArtifact(sourceSetDirectory, plan.hexPath, {
    byteLength: plan.bytecodeBytes,
    sha256: plan.bytecodeSha256,
  });
  const mapPath = assertContainedRegularFile(sourceSetDirectory, plan.mapPath);
  const map = JSON.parse(readFileSync(mapPath, 'utf8'));
  require(map.planId === planId && map.planOrder === plan.orderIndex, 'source-set map identity drift');
  const expectedOperandCount = Number(map.instructions?.[0]?.irTypedContract?.transientStackContract?.typedTransientItems?.[1]?.value);
  require(Number.isInteger(expectedOperandCount) && expectedOperandCount >= 0, 'source-set entry ABI missing');
  return Object.freeze({
    artifactId: FIXTURE_ARTIFACT_ID,
    planId,
    planOrder: plan.orderIndex,
    expectedOperandCount,
    redeemBytecode,
    redeemBinding: byteBinding(redeemBytecode),
    sourceSetBinding: Object.freeze({
      rootPath: 'source-set.v1.json',
      rootRawSha256: sha256(sourceSetBytes),
      contentDigest: sourceSet.contentDigest?.value ?? null,
      planIndexEntrySha256: sha256(Buffer.from(JSON.stringify(plan))),
    }),
  });
};

export const deriveExecutionFixture = ({ sourcePlan, operandsBottomToTop }) => {
  require(sourcePlan !== null && typeof sourcePlan === 'object', 'sourcePlan required');
  require(sourcePlan.redeemBytecode instanceof Uint8Array && sourcePlan.redeemBinding?.sha256 === sha256(sourcePlan.redeemBytecode), 'source-plan redeem binding drift');
  require(Array.isArray(operandsBottomToTop), 'operandsBottomToTop must be an array');
  require(operandsBottomToTop.length === sourcePlan.expectedOperandCount, `operand count ${operandsBottomToTop.length} does not match plan ABI ${sourcePlan.expectedOperandCount}`);
  const operands = operandsBottomToTop.map((operand, index) => {
    require(operand instanceof Uint8Array, `operand ${index} must be Uint8Array`);
    require(operand.length <= MAX_DATA_PUSH_BYTES, `operand ${index} is oversized`);
    return operand.slice();
  });
  const operandUnlockingBytecode = join(...operands.map(encodeMinimalDataPush));
  const redeemPush = encodeMinimalDataPush(sourcePlan.redeemBytecode);
  const unlockingBytecode = join(operandUnlockingBytecode, redeemPush);
  assertExactPushSequence(unlockingBytecode, [...operands, sourcePlan.redeemBytecode], 'unlocking bytecode');
  const sourceLockingBytecode = p2sh32LockingBytecode(sourcePlan.redeemBytecode);
  const transaction = encodeTransaction({ unlockingBytecode, outputLockingBytecode: OUTPUT_LOCKING_BYTECODE });
  const sourceOutputs = encodeSourceOutputs({ sourceLockingBytecode });
  return Object.freeze({
    artifactId: FIXTURE_ARTIFACT_ID,
    kind: 'synthetic-one-input-one-output-p2sh32-component-fixture-v2',
    planId: sourcePlan.planId,
    planOrder: sourcePlan.planOrder,
    operandOrder: 'bottom-to-top-exact-raw-bytes-no-normalization',
    sourceSetBinding: sourcePlan.sourceSetBinding,
    sourceBinding: Object.freeze({
      sourceSet: sourcePlan.sourceSetBinding,
      executionCeiling: Object.freeze({
        bytes: VERIFIED_EXECUTION_CEILING_BYTES,
        sourcePath: 'src/script/vm_limits.h',
        sourceSymbol: 'MAX_SCRIPT_SIZE',
      }),
    }),
    bytes: Object.freeze({
      operandsBottomToTop: Object.freeze(operands),
      redeemBytecode: sourcePlan.redeemBytecode.slice(),
      operandUnlockingBytecode,
      redeemPush,
      unlockingBytecode,
      sourceLockingBytecode,
      transaction,
      sourceOutputs,
      outputLockingBytecode: OUTPUT_LOCKING_BYTECODE.slice(),
    }),
    bindings: Object.freeze({
      operandsBottomToTop: Object.freeze(operands.map(byteBinding)),
      redeemBytecode: byteBinding(sourcePlan.redeemBytecode),
      operandUnlockingBytecode: byteBinding(operandUnlockingBytecode),
      redeemPush: byteBinding(redeemPush),
      unlockingBytecode: byteBinding(unlockingBytecode),
      sourceLockingBytecode: byteBinding(sourceLockingBytecode),
      transaction: byteBinding(transaction),
      sourceOutputs: byteBinding(sourceOutputs),
      outputLockingBytecode: byteBinding(OUTPUT_LOCKING_BYTECODE),
    }),
  });
};

const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  return value;
};
export const DOMAIN_DIGEST_CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
export const DOMAIN_DIGEST_FRAME = 'utf8(domain)||0x00||canonical-json-utf8';
export const canonicalJsonUtf8 = (value) => Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8');
export const domainSeparatedSha256 = (domain, value) => {
  require(typeof domain === 'string' && domain.length > 0, 'domain must be nonempty UTF-8 text');
  return sha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.of(0), canonicalJsonUtf8(value)]));
};

const canonicalFixtureIdentityKeys = Object.freeze(['caseDigest', 'caseKey', 'constructionId', 'constructionIndex', 'planId', 'vectorAttempt']);
const canonicalCorpusConstructions = Object.freeze([
  'algebra-component:m89-d2-x2-plus-1-v2',
  'algebra-component:m61-d3-x3-minus-5-v2',
  'algebra-component:m31-d5-x5-plus-2x-minus-1-v2',
  'algebra-component:m31-d6-x6-minus-5-v2',
]);
const canonicalCorpusRelations = new Set(['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check']);
const canonicalCorpusCategories = new Set(['category:valid', 'category:boundary', 'category:random', 'category:metamorphic', 'category:malformed']);
const canonicalUnsigned = /^(?:0|[1-9][0-9]*)$/u;
const parseCanonicalCorpusCaseKey = (caseKey) => {
  require(typeof caseKey === 'string', 'caseKey must be a string');
  const fields = caseKey.split('|');
  require(fields.length === 5, 'caseKey must have exactly five pipe-delimited fields');
  const [constructionId, relationId, categoryId, caseIndex, vectorAttempt] = fields;
  require(canonicalCorpusConstructions.includes(constructionId), 'caseKey constructionId is not frozen');
  require(canonicalCorpusRelations.has(relationId), 'caseKey relationId is not frozen');
  require(canonicalCorpusCategories.has(categoryId), 'caseKey categoryId is not frozen');
  require(canonicalUnsigned.test(caseIndex) && canonicalUnsigned.test(vectorAttempt), 'caseKey numeric fields must be canonical nonnegative integers');
  return Object.freeze({ constructionId, relationId, categoryId, caseIndex: Number(caseIndex), vectorAttempt: Number(vectorAttempt) });
};
const assertEpochFixtureIdentity = (identity, fixture) => {
  require(identity !== null && typeof identity === 'object' && !Array.isArray(identity), 'epoch fixture identity required');
  require(JSON.stringify(Object.keys(identity).sort()) === JSON.stringify(canonicalFixtureIdentityKeys), 'epoch fixture identity keys drift');
  require(Number.isInteger(identity.constructionIndex) && identity.constructionIndex >= 0, 'constructionIndex must be a nonnegative integer');
  require(typeof identity.constructionId === 'string' && identity.constructionId.length > 0, 'constructionId required');
  require(identity.planId === fixture.planId, 'epoch fixture identity planId drift');
  const caseKey = parseCanonicalCorpusCaseKey(identity.caseKey);
  require(identity.constructionId === caseKey.constructionId && identity.constructionIndex === canonicalCorpusConstructions.indexOf(caseKey.constructionId), 'caseKey construction binding drift');
  require(identity.vectorAttempt === caseKey.vectorAttempt, 'caseKey vectorAttempt binding drift');
  require(identity.planId.includes(`:relation:${caseKey.relationId.slice('relation:'.length)}:v1`), 'caseKey relation binding drift');
  require(typeof identity.caseDigest === 'string' && /^[0-9a-f]{64}$/u.test(identity.caseDigest), 'caseDigest must be a lowercase SHA-256');
  require(Number.isInteger(identity.vectorAttempt) && identity.vectorAttempt >= 0, 'vectorAttempt must be a nonnegative integer');
  return Object.freeze({
    constructionIndex: identity.constructionIndex,
    constructionId: identity.constructionId,
    planId: identity.planId,
    caseKey: identity.caseKey,
    caseDigest: identity.caseDigest,
    vectorAttempt: identity.vectorAttempt,
  });
};

/** A path-safe epoch key derived only from the approved epoch identity. */
export const deriveEpochFixtureKey = (input) => {
  require(input !== null && typeof input === 'object' && JSON.stringify(Object.keys(input).sort()) === JSON.stringify(['epochIdentity', 'fixture']), 'fixture key input shape drift');
  const { epochIdentity, fixture } = input;
  require(fixture?.artifactId === FIXTURE_ARTIFACT_ID && fixture.bindings !== undefined, 'execution fixture required');
  return `fixture:${domainSeparatedSha256('shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture-key', assertEpochFixtureIdentity(epochIdentity, fixture))}`;
};

/** Compact non-secret roster entry: identity and byte bindings only, never raw fixture hex. */
export const buildFixtureRosterRecord = (input) => {
  require(input !== null && typeof input === 'object' && JSON.stringify(Object.keys(input).sort()) === JSON.stringify(['epochIdentity', 'fixture']), 'fixture roster input shape drift');
  const { epochIdentity, fixture } = input;
  require(fixture?.artifactId === FIXTURE_ARTIFACT_ID && fixture.bindings !== undefined, 'execution fixture required');
  const identity = assertEpochFixtureIdentity(epochIdentity, fixture);
  const derivedFixtureKey = deriveEpochFixtureKey({ epochIdentity: identity, fixture });
  const preflightLimitViolation = Object.freeze({
    verifiedExecutionCeilingBytes: VERIFIED_EXECUTION_CEILING_BYTES,
    scriptSig: fixture.bindings.unlockingBytecode.byteLength > VERIFIED_EXECUTION_CEILING_BYTES,
    redeem: fixture.bindings.redeemBytecode.byteLength > VERIFIED_EXECUTION_CEILING_BYTES,
  });
  const record = {
    schema: 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/fixture-roster-record/v2',
    artifactId: FIXTURE_ARTIFACT_ID,
    fixtureKey: derivedFixtureKey,
    epochIdentity: identity,
    planId: fixture.planId,
    planOrder: fixture.planOrder,
    status: preflightLimitViolation.scriptSig || preflightLimitViolation.redeem ? 'preflight-limit-violation' : 'preflight-ready-no-vm-execution',
    executionAllowed: false,
    sourceBinding: fixture.sourceBinding,
    byteBindings: fixture.bindings,
    preflightLimitViolation,
    contentDigest: null,
  };
  record.contentDigest = Object.freeze({
    algorithm: 'sha256',
    domain: `shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture/${derivedFixtureKey}`,
    canonicalization: DOMAIN_DIGEST_CANONICALIZATION,
    frame: DOMAIN_DIGEST_FRAME,
    value: domainSeparatedSha256(`shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture/${derivedFixtureKey}`, record),
  });
  return Object.freeze(canonicalize(record));
};

export const deriveExecutionFixtureFromRawHex = ({ planId, operandsBottomToTop, options } = {}) => {
  require(Array.isArray(operandsBottomToTop), 'operandsBottomToTop raw hexadecimal array required');
  return deriveExecutionFixture({
    sourcePlan: loadSourceSetPlan(planId, options),
    operandsBottomToTop: operandsBottomToTop.map((item, index) => parseLowercaseEvenHex(item, `operand ${index}`)),
  });
};
