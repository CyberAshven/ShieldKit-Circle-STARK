import {
  ACTION_TAGS,
  Reader,
  Writer,
  actionKindForTag,
  actionTagFor,
  assertExactKeys,
  assertBytecodeHex,
  assertHex,
  assertI64,
  assertInteger,
  assertU16,
  assertU64,
  bytesToHex,
  fail,
  hexToBytes,
  isZeroHex,
  networkIdForTag,
  networkTagFor,
} from "./common.mjs";

const STATEMENT_KEYS = [
  "relationVersion",
  "profileTag",
  "networkId",
  "actionKind",
  "poolInstanceIdHex",
  "proofSecurityProfileDigestHex",
  "carrierManifestDigestHex",
  "oldStateOutpointTxidWireHex",
  "oldStateOutpointIndex",
  "oldStateValueSats",
  "oldStateBytesHex",
  "newStateOutputIndex",
  "newStateValueSats",
  "newStateBytesHex",
  "ticketSats",
  "reserveDeltaSats",
  "noteCommitmentOrZeroHex",
  "nullifierOrZeroHex",
  "payoutOutputIndexOrffff",
  "payoutSatsOrZero",
  "payoutLockingBytecodeDigestOrZeroHex",
  "feeInputIndex",
  "transparentChangeOutputIndexOrffff",
  "feeSats",
  "maxFeeSats",
  "transactionContextDigestHex",
];

const ZERO32 = "00".repeat(32);
const TICKET = "10000000";

function validateStatement(statement, name = "statement") {
  assertExactKeys(statement, STATEMENT_KEYS, [], name);
  if (statement.relationVersion !== 1) fail(`${name}.relationVersion must be 1`);
  if (statement.profileTag !== 1) fail(`${name}.profileTag must be 1`);
  networkTagFor(statement.networkId);
  const actionTag = actionTagFor(statement.actionKind);
  assertHex(statement.poolInstanceIdHex, `${name}.poolInstanceIdHex`, 32);
  assertHex(statement.proofSecurityProfileDigestHex, `${name}.proofSecurityProfileDigestHex`, 32);
  assertHex(statement.carrierManifestDigestHex, `${name}.carrierManifestDigestHex`, 32);
  assertHex(statement.oldStateOutpointTxidWireHex, `${name}.oldStateOutpointTxidWireHex`, 32);
  if (statement.oldStateOutpointIndex !== 0) fail(`${name}.oldStateOutpointIndex must be 0`);
  assertU64(statement.oldStateValueSats, `${name}.oldStateValueSats`);
  assertHex(statement.oldStateBytesHex, `${name}.oldStateBytesHex`, 128);
  if (statement.newStateOutputIndex !== 0) fail(`${name}.newStateOutputIndex must be 0`);
  assertU64(statement.newStateValueSats, `${name}.newStateValueSats`);
  assertHex(statement.newStateBytesHex, `${name}.newStateBytesHex`, 128);
  if (statement.ticketSats !== TICKET) fail(`${name}.ticketSats must be 10000000`);
  assertI64(statement.reserveDeltaSats, `${name}.reserveDeltaSats`);
  assertHex(statement.noteCommitmentOrZeroHex, `${name}.noteCommitmentOrZeroHex`, 32);
  assertHex(statement.nullifierOrZeroHex, `${name}.nullifierOrZeroHex`, 32);
  assertU16(statement.payoutOutputIndexOrffff, `${name}.payoutOutputIndexOrffff`);
  assertU64(statement.payoutSatsOrZero, `${name}.payoutSatsOrZero`);
  assertHex(statement.payoutLockingBytecodeDigestOrZeroHex, `${name}.payoutLockingBytecodeDigestOrZeroHex`, 32);
  assertU16(statement.feeInputIndex, `${name}.feeInputIndex`);
  if (statement.feeInputIndex === 0) fail(`${name}.feeInputIndex must identify the external input`);
  assertU16(statement.transparentChangeOutputIndexOrffff, `${name}.transparentChangeOutputIndexOrffff`);
  assertU64(statement.feeSats, `${name}.feeSats`);
  assertU64(statement.maxFeeSats, `${name}.maxFeeSats`);
  if (BigInt(statement.feeSats) > BigInt(statement.maxFeeSats)) fail(`${name}.feeSats exceeds maxFeeSats`);
  assertHex(statement.transactionContextDigestHex, `${name}.transactionContextDigestHex`, 32);

  if (actionTag === ACTION_TAGS.DEPOSIT) {
    if (statement.reserveDeltaSats !== TICKET) fail("deposit reserveDeltaSats must be +10000000");
    if (isZeroHex(statement.noteCommitmentOrZeroHex)) fail("deposit note commitment must be nonzero");
    if (!isZeroHex(statement.nullifierOrZeroHex)) fail("deposit nullifier must be zero");
    if (statement.payoutOutputIndexOrffff !== 0xffff || statement.payoutSatsOrZero !== "0" || !isZeroHex(statement.payoutLockingBytecodeDigestOrZeroHex)) {
      fail("deposit payout fields must be the canonical absent form");
    }
  } else {
    if (statement.reserveDeltaSats !== "-10000000") fail("withdrawal reserveDeltaSats must be -10000000");
    if (!isZeroHex(statement.noteCommitmentOrZeroHex)) fail("withdrawal note commitment must be zero");
    if (isZeroHex(statement.nullifierOrZeroHex)) fail("withdrawal nullifier must be nonzero");
    if (statement.payoutOutputIndexOrffff === 0xffff || statement.payoutSatsOrZero !== TICKET) {
      fail("withdrawal payout fields must identify the fixed ticket payout");
    }
  }
  return statement;
}

export function validatePoolActionStatement(statement, name = "statement") {
  return validateStatement(statement, name);
}

export function encodePoolActionStatement(statement) {
  validateStatement(statement);
  const writer = new Writer();
  writer.bytes(new TextEncoder().encode("PAST"), "magic", 4);
  writer.u16(statement.relationVersion);
  writer.u8(statement.profileTag);
  writer.u8(networkTagFor(statement.networkId));
  writer.u8(actionTagFor(statement.actionKind));
  writer.bytes(hexToBytes(statement.poolInstanceIdHex, "poolInstanceIdHex"), "poolInstanceIdHex", 32);
  writer.bytes(hexToBytes(statement.proofSecurityProfileDigestHex, "proofSecurityProfileDigestHex"), "proofSecurityProfileDigestHex", 32);
  writer.bytes(hexToBytes(statement.carrierManifestDigestHex, "carrierManifestDigestHex"), "carrierManifestDigestHex", 32);
  writer.bytes(hexToBytes(statement.oldStateOutpointTxidWireHex, "oldStateOutpointTxidWireHex"), "oldStateOutpointTxidWireHex", 32);
  writer.u32(statement.oldStateOutpointIndex);
  writer.u64(statement.oldStateValueSats, "oldStateValueSats");
  writer.bytes(hexToBytes(statement.oldStateBytesHex, "oldStateBytesHex"), "oldStateBytesHex", 128);
  writer.u16(statement.newStateOutputIndex);
  writer.u64(statement.newStateValueSats, "newStateValueSats");
  writer.bytes(hexToBytes(statement.newStateBytesHex, "newStateBytesHex"), "newStateBytesHex", 128);
  writer.u64(statement.ticketSats, "ticketSats");
  writer.i64(statement.reserveDeltaSats, "reserveDeltaSats");
  writer.bytes(hexToBytes(statement.noteCommitmentOrZeroHex, "noteCommitmentOrZeroHex"), "noteCommitmentOrZeroHex", 32);
  writer.bytes(hexToBytes(statement.nullifierOrZeroHex, "nullifierOrZeroHex"), "nullifierOrZeroHex", 32);
  writer.u16(statement.payoutOutputIndexOrffff);
  writer.u64(statement.payoutSatsOrZero, "payoutSatsOrZero");
  writer.bytes(hexToBytes(statement.payoutLockingBytecodeDigestOrZeroHex, "payoutLockingBytecodeDigestOrZeroHex"), "payoutLockingBytecodeDigestOrZeroHex", 32);
  writer.u16(statement.feeInputIndex);
  writer.u16(statement.transparentChangeOutputIndexOrffff);
  writer.u64(statement.feeSats, "feeSats");
  writer.u64(statement.maxFeeSats, "maxFeeSats");
  writer.bytes(hexToBytes(statement.transactionContextDigestHex, "transactionContextDigestHex"), "transactionContextDigestHex", 32);
  return writer.finish();
}

export function decodePoolActionStatement(input) {
  const bytes = input instanceof Uint8Array ? input : hexToBytes(input, "PoolActionFv1Statement");
  const reader = new Reader(bytes, "PoolActionFv1Statement");
  const magic = new TextDecoder().decode(reader.bytes(4, "magic"));
  if (magic !== "PAST") fail("PoolActionFv1Statement magic must be PAST");
  const statement = {
    relationVersion: reader.u16("relationVersion"),
    profileTag: reader.u8("profileTag"),
    networkId: networkIdForTag(reader.u8("networkTag")),
    actionKind: actionKindForTag(reader.u8("actionTag")),
    poolInstanceIdHex: bytesToHex(reader.bytes(32, "poolInstanceId")),
    proofSecurityProfileDigestHex: bytesToHex(reader.bytes(32, "proofSecurityProfileDigest")),
    carrierManifestDigestHex: bytesToHex(reader.bytes(32, "carrierManifestDigest")),
    oldStateOutpointTxidWireHex: bytesToHex(reader.bytes(32, "oldStateOutpointTxidWire")),
    oldStateOutpointIndex: reader.u32("oldStateOutpointIndex"),
    oldStateValueSats: reader.u64("oldStateValueSats"),
    oldStateBytesHex: bytesToHex(reader.bytes(128, "oldStateBytes")),
    newStateOutputIndex: reader.u16("newStateOutputIndex"),
    newStateValueSats: reader.u64("newStateValueSats"),
    newStateBytesHex: bytesToHex(reader.bytes(128, "newStateBytes")),
    ticketSats: reader.u64("ticketSats"),
    reserveDeltaSats: reader.i64("reserveDeltaSats"),
    noteCommitmentOrZeroHex: bytesToHex(reader.bytes(32, "noteCommitmentOrZero")),
    nullifierOrZeroHex: bytesToHex(reader.bytes(32, "nullifierOrZero")),
    payoutOutputIndexOrffff: reader.u16("payoutOutputIndexOrffff"),
    payoutSatsOrZero: reader.u64("payoutSatsOrZero"),
    payoutLockingBytecodeDigestOrZeroHex: bytesToHex(reader.bytes(32, "payoutLockingBytecodeDigestOrZero")),
    feeInputIndex: reader.u16("feeInputIndex"),
    transparentChangeOutputIndexOrffff: reader.u16("transparentChangeOutputIndexOrffff"),
    feeSats: reader.u64("feeSats"),
    maxFeeSats: reader.u64("maxFeeSats"),
    transactionContextDigestHex: bytesToHex(reader.bytes(32, "transactionContextDigest")),
  };
  reader.done("PoolActionFv1Statement");
  validateStatement(statement, "decoded statement");
  return statement;
}

export function poolActionStatementHex(statement) {
  return bytesToHex(encodePoolActionStatement(statement));
}

/**
 * Construct the frozen payout-lock digest domain preimage only. The selected
 * context-digest algorithm is intentionally not implemented here.
 */
export function payoutLockDomainPreimage(lockingBytecodeHex) {
  assertBytecodeHex(lockingBytecodeHex, "payoutLockingBytecodeHex");
  const domain = new TextEncoder().encode("PoolActionFv1/PayoutLock");
  const lock = hexToBytes(lockingBytecodeHex, "payoutLockingBytecodeHex");
  const writer = new Writer();
  writer.bytes(domain, "domain", domain.length);
  writer.u16(lock.length);
  writer.bytes(lock, "payoutLockingBytecode", lock.length);
  return writer.finish();
}

export const encodePoolActionFv1Statement = encodePoolActionStatement;
export const decodePoolActionFv1Statement = decodePoolActionStatement;
