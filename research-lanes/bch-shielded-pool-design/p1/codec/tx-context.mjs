import {
  ACTION_NAMES,
  ACTION_TAGS,
  INPUT_ROLE_NAMES,
  INPUT_ROLE_TAGS,
  OUTPUT_ROLE_NAMES,
  OUTPUT_ROLE_TAGS,
  Reader,
  Writer,
  assertBytecodeHex,
  assertExactKeys,
  assertHex,
  assertU16,
  assertU32,
  assertU64,
  actionKindForTag,
  actionTagFor,
  bytesToHex,
  fail,
  hexToBytes,
  networkIdForTag,
  networkTagFor,
  roleNameFor,
  roleTagFor,
} from "./common.mjs";
import { readTokenRecord, tokenRecordsEqual, validateTokenRecord, writeTokenRecord } from "./token-record.mjs";

const CONTEXT_KEYS = [
  "codecVersion",
  "networkId",
  "poolInstanceIdHex",
  "actionKind",
  "transactionVersion",
  "locktime",
  "carrierManifestDigestHex",
  "proofSecurityProfileDigestHex",
  "inputs",
  "outputs",
];
const INPUT_KEYS = [
  "index",
  "role",
  "roleOrdinal",
  "outpointTxidWireHex",
  "outpointIndex",
  "sequence",
  "sourceValueSats",
  "sourceLockingBytecodeHex",
  "sourceToken",
];
const OUTPUT_KEYS = [
  "index",
  "role",
  "roleOrdinal",
  "valueSats",
  "lockingBytecodeHex",
  "token",
];

function validateInput(input, name) {
  assertExactKeys(input, INPUT_KEYS, [], name);
  assertU16(input.index, `${name}.index`);
  roleTagFor(input.role, INPUT_ROLE_TAGS, "input role");
  assertU16(input.roleOrdinal, `${name}.roleOrdinal`);
  assertHex(input.outpointTxidWireHex, `${name}.outpointTxidWireHex`, 32);
  assertU32(input.outpointIndex, `${name}.outpointIndex`);
  if (input.sequence !== 0xffffffff) fail(`${name}.sequence must be 0xffffffff`);
  assertU32(input.sequence, `${name}.sequence`);
  assertU64(input.sourceValueSats, `${name}.sourceValueSats`);
  assertBytecodeHex(input.sourceLockingBytecodeHex, `${name}.sourceLockingBytecodeHex`);
  validateTokenRecord(input.sourceToken, `${name}.sourceToken`);
}

function validateOutput(output, name) {
  assertExactKeys(output, OUTPUT_KEYS, [], name);
  assertU16(output.index, `${name}.index`);
  roleTagFor(output.role, OUTPUT_ROLE_TAGS, "output role");
  assertU16(output.roleOrdinal, `${name}.roleOrdinal`);
  assertU64(output.valueSats, `${name}.valueSats`);
  assertBytecodeHex(output.lockingBytecodeHex, `${name}.lockingBytecodeHex`);
  validateTokenRecord(output.token, `${name}.token`);
}

function validateStateToken(token, name) {
  if (token.capability !== "mutable" || token.amount !== "0" || token.categoryHex === "" || token.commitmentHex.length !== 256) {
    fail(`${name} must be a mutable zero-amount 128-byte state token`);
  }
}

function validateStructuralRoles(context) {
  const { actionKind, inputs, outputs } = context;
  const carrierCount = inputs.length - 2;
  if (carrierCount < 1) fail("inputs must contain at least one verifier carrier");
  if (inputs.length !== carrierCount + 2) fail("input count is inconsistent");
  if (outputs.length < carrierCount + 1) fail("outputs omit the state/carrier successor bundle");

  for (let i = 0; i < inputs.length; i += 1) {
    validateInput(inputs[i], `inputs[${i}]`);
    if (inputs[i].index !== i) fail(`inputs[${i}].index must equal wire position`);
  }
  for (let i = 0; i < outputs.length; i += 1) {
    validateOutput(outputs[i], `outputs[${i}]`);
    if (outputs[i].index !== i) fail(`outputs[${i}].index must equal wire position`);
  }

  const stateInput = inputs[0];
  if (stateInput.role !== "STATE" || stateInput.roleOrdinal !== 0 || stateInput.outpointIndex !== 0) {
    fail("input 0 must be STATE ordinal 0 with outpoint index 0");
  }
  validateStateToken(stateInput.sourceToken, "inputs[0].sourceToken");
  for (let i = 0; i < carrierCount; i += 1) {
    const input = inputs[i + 1];
    if (input.role !== "VERIFIER_CARRIER" || input.roleOrdinal !== i) {
      fail(`inputs[${i + 1}] must be carrier ordinal ${i}`);
    }
    if (input.outpointIndex !== i + 1 || input.outpointTxidWireHex !== stateInput.outpointTxidWireHex) {
      fail(`inputs[${i + 1}] must be the state predecessor carrier outpoint ${i + 1}`);
    }
  }
  const external = inputs[carrierCount + 1];
  const expectedExternalRole = actionKind === "DEPOSIT" ? "DEPOSIT_FUNDING" : "FEE_FUNDING";
  if (external.role !== expectedExternalRole || external.roleOrdinal !== 0 || !tokenRecordsEqual(external.sourceToken, noneToken())) {
    fail("final input must be the token-free action funding role");
  }

  const stateOutput = outputs[0];
  if (stateOutput.role !== "STATE_SUCCESSOR" || stateOutput.roleOrdinal !== 0) {
    fail("output 0 must be STATE_SUCCESSOR ordinal 0");
  }
  validateStateToken(stateOutput.token, "outputs[0].token");
  if (stateOutput.token.categoryHex !== stateInput.sourceToken.categoryHex) {
    fail("state successor token category differs from state source");
  }
  for (let i = 0; i < carrierCount; i += 1) {
    const source = inputs[i + 1];
    const successor = outputs[i + 1];
    if (successor.role !== "VERIFIER_CARRIER_SUCCESSOR" || successor.roleOrdinal !== i) {
      fail(`outputs[${i + 1}] must be carrier successor ordinal ${i}`);
    }
    if (
      source.sourceValueSats !== successor.valueSats
      || source.sourceLockingBytecodeHex !== successor.lockingBytecodeHex
      || !tokenRecordsEqual(source.sourceToken, successor.token)
    ) {
      fail(`carrier ${i} lock/value/token is not preserved`);
    }
  }

  const bundleEnd = carrierCount + 1;
  if (actionKind === "DEPOSIT") {
    if (outputs.length > bundleEnd + 1) fail("deposit has more than one optional final change output");
    if (outputs.length === bundleEnd + 1) validateChange(outputs[bundleEnd], bundleEnd);
  } else {
    if (outputs.length < bundleEnd + 1 || outputs.length > bundleEnd + 2) fail("withdrawal output count is not canonical");
    const payout = outputs[bundleEnd];
    if (payout.role !== "PAYOUT" || payout.roleOrdinal !== 0 || payout.valueSats !== "10000000" || !tokenRecordsEqual(payout.token, noneToken())) {
      fail("withdrawal payout is not the fixed token-free ticket output");
    }
    if (outputs.length === bundleEnd + 2) validateChange(outputs[bundleEnd + 1], bundleEnd + 1);
  }
}

function validateChange(output, index) {
  if (output.role !== "TRANSPARENT_CHANGE" || output.roleOrdinal !== 0 || !tokenRecordsEqual(output.token, noneToken())) {
    fail(`outputs[${index}] must be the final token-free transparent change`);
  }
}

function noneToken() {
  return { categoryHex: "", capability: "none", commitmentHex: "", amount: "0" };
}

export function validateTxContext(context, name = "transactionContext") {
  assertExactKeys(context, CONTEXT_KEYS, [], name);
  if (context.codecVersion !== 1) fail(`${name}.codecVersion must be 1`);
  networkTagFor(context.networkId);
  assertHex(context.poolInstanceIdHex, `${name}.poolInstanceIdHex`, 32);
  actionTagFor(context.actionKind);
  if (context.transactionVersion !== 2) fail(`${name}.transactionVersion must be 2`);
  if (context.locktime !== 0) fail(`${name}.locktime must be 0`);
  assertHex(context.carrierManifestDigestHex, `${name}.carrierManifestDigestHex`, 32);
  assertHex(context.proofSecurityProfileDigestHex, `${name}.proofSecurityProfileDigestHex`, 32);
  if (!Array.isArray(context.inputs) || !Array.isArray(context.outputs)) fail(`${name}.inputs/outputs must be arrays`);
  if (context.inputs.length < 3 || context.inputs.length > 65535) fail(`${name}.inputs count is out of bounds`);
  if (context.outputs.length < 2 || context.outputs.length > 65535) fail(`${name}.outputs count is out of bounds`);
  validateStructuralRoles(context);
  return context;
}

function writeContextInput(writer, input, index) {
  writer.u16(index);
  writer.u8(roleTagFor(input.role, INPUT_ROLE_TAGS, "input role"));
  writer.u16(input.roleOrdinal);
  writer.bytes(hexToBytes(input.outpointTxidWireHex, `inputs[${index}].outpointTxidWireHex`), "outpointTxidWireHex", 32);
  writer.u32(input.outpointIndex);
  writer.u32(input.sequence);
  writer.u64(input.sourceValueSats, `inputs[${index}].sourceValueSats`);
  writer.varbytes(hexToBytes(input.sourceLockingBytecodeHex, `inputs[${index}].sourceLockingBytecodeHex`), "sourceLockingBytecode");
  writeTokenRecord(writer, input.sourceToken, `inputs[${index}].sourceToken`);
}

function writeContextOutput(writer, output, index) {
  writer.u16(index);
  writer.u8(roleTagFor(output.role, OUTPUT_ROLE_TAGS, "output role"));
  writer.u16(output.roleOrdinal);
  writer.u64(output.valueSats, `outputs[${index}].valueSats`);
  writer.varbytes(hexToBytes(output.lockingBytecodeHex, `outputs[${index}].lockingBytecodeHex`), "lockingBytecode");
  writeTokenRecord(writer, output.token, `outputs[${index}].token`);
}

export function encodeTxContext(context) {
  validateTxContext(context);
  const writer = new Writer();
  writer.bytes(new TextEncoder().encode("PCTX"), "magic", 4);
  writer.u16(context.codecVersion);
  writer.u8(networkTagFor(context.networkId));
  writer.u8(actionTagFor(context.actionKind));
  writer.bytes(hexToBytes(context.poolInstanceIdHex, "poolInstanceIdHex"), "poolInstanceIdHex", 32);
  writer.bytes(hexToBytes(context.carrierManifestDigestHex, "carrierManifestDigestHex"), "carrierManifestDigestHex", 32);
  writer.bytes(hexToBytes(context.proofSecurityProfileDigestHex, "proofSecurityProfileDigestHex"), "proofSecurityProfileDigestHex", 32);
  writer.u32(context.transactionVersion);
  writer.u32(context.locktime);
  writer.u16(context.inputs.length);
  context.inputs.forEach((input, index) => writeContextInput(writer, input, index));
  writer.u16(context.outputs.length);
  context.outputs.forEach((output, index) => writeContextOutput(writer, output, index));
  return writer.finish();
}

export function txContextDomainPreimage(context) {
  const contextBytes = encodeTxContext(context);
  const domain = new TextEncoder().encode("PoolActionFv1/TxContext");
  const writer = new Writer();
  writer.bytes(domain, "domain", domain.length);
  writer.bytes(contextBytes, "TxContextFv1Preimage", contextBytes.length);
  return writer.finish();
}

function readContextInput(reader, index) {
  const wireIndex = reader.u16(`inputs[${index}].index`);
  const roleTag = reader.u8(`inputs[${index}].roleTag`);
  const roleOrdinal = reader.u16(`inputs[${index}].roleOrdinal`);
  const input = {
    index: wireIndex,
    role: roleNameFor(roleTag, INPUT_ROLE_NAMES, "input role"),
    roleOrdinal,
    outpointTxidWireHex: bytesToHex(reader.bytes(32, `inputs[${index}].outpointTxidWire`)),
    outpointIndex: reader.u32(`inputs[${index}].outpointIndex`),
    sequence: reader.u32(`inputs[${index}].sequence`),
    sourceValueSats: reader.u64(`inputs[${index}].sourceValueSats`),
    sourceLockingBytecodeHex: bytesToHex(reader.varbytes(`inputs[${index}].sourceLockingBytecode`)),
    sourceToken: readTokenRecord(reader, `inputs[${index}].sourceToken`),
  };
  return input;
}

function readContextOutput(reader, index) {
  const wireIndex = reader.u16(`outputs[${index}].index`);
  const roleTag = reader.u8(`outputs[${index}].roleTag`);
  const roleOrdinal = reader.u16(`outputs[${index}].roleOrdinal`);
  return {
    index: wireIndex,
    role: roleNameFor(roleTag, OUTPUT_ROLE_NAMES, "output role"),
    roleOrdinal,
    valueSats: reader.u64(`outputs[${index}].valueSats`),
    lockingBytecodeHex: bytesToHex(reader.varbytes(`outputs[${index}].lockingBytecode`)),
    token: readTokenRecord(reader, `outputs[${index}].token`),
  };
}

export function decodeTxContext(input) {
  const bytes = input instanceof Uint8Array ? input : hexToBytes(input, "TxContextFv1");
  const reader = new Reader(bytes, "TxContextFv1");
  const magic = new TextDecoder().decode(reader.bytes(4, "magic"));
  if (magic !== "PCTX") fail("TxContextFv1 magic must be PCTX");
  const codecVersion = reader.u16("codecVersion");
  const networkId = networkIdForTag(reader.u8("networkTag"));
  const actionKind = actionKindForTag(reader.u8("actionTag"));
  const context = {
    codecVersion,
    networkId,
    poolInstanceIdHex: bytesToHex(reader.bytes(32, "poolInstanceId")),
    actionKind,
    carrierManifestDigestHex: bytesToHex(reader.bytes(32, "carrierManifestDigest")),
    proofSecurityProfileDigestHex: bytesToHex(reader.bytes(32, "proofSecurityProfileDigest")),
    transactionVersion: reader.u32("transactionVersion"),
    locktime: reader.u32("locktime"),
    inputs: [],
    outputs: [],
  };
  const inputCount = reader.u16("inputCount");
  if (inputCount < 3) fail("inputCount must include state, carrier, and funding input");
  for (let i = 0; i < inputCount; i += 1) context.inputs.push(readContextInput(reader, i));
  const outputCount = reader.u16("outputCount");
  if (outputCount < 2) fail("outputCount must include state and carrier successor");
  for (let i = 0; i < outputCount; i += 1) context.outputs.push(readContextOutput(reader, i));
  reader.done("TxContextFv1");
  validateTxContext(context, "decoded transactionContext");
  return context;
}

export function txContextHex(context) {
  return bytesToHex(encodeTxContext(context));
}

export const CONTEXT_ACTION_TAGS = ACTION_TAGS;
export const CONTEXT_ACTION_NAMES = ACTION_NAMES;
export const encodeTxContextFv1 = encodeTxContext;
export const decodeTxContextFv1 = decodeTxContext;
