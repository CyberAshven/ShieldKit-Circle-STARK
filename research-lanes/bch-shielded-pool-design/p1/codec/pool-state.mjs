import {
  Reader,
  Writer,
  assertExactKeys,
  assertHex,
  assertU64,
  bytesToHex,
  fail,
  hexToBytes,
} from "./common.mjs";

const STATE_SCHEMA = "shieldkit-labs/pool-state-fv1/v1";
const STATE_KEYS = [
  "schema",
  "magic",
  "stateCodecVersion",
  "reservedHex",
  "sequence",
  "depositCount",
  "withdrawalCount",
  "poolInstanceIdHex",
  "noteRootHex",
  "nullifierRootHex",
];
const STATE_OPTIONAL_KEYS = ["serializedHex"];

function validateState(state, name = "state") {
  assertExactKeys(state, STATE_KEYS, STATE_OPTIONAL_KEYS, name);
  if (state.schema !== STATE_SCHEMA) fail(`${name}.schema is not PoolStateFv1`);
  if (state.magic !== "PAF1") fail(`${name}.magic must be PAF1`);
  if (state.stateCodecVersion !== 1) fail(`${name}.stateCodecVersion must be 1`);
  if (state.reservedHex !== "0000") fail(`${name}.reservedHex must be 0000`);
  assertU64(state.sequence, `${name}.sequence`);
  assertU64(state.depositCount, `${name}.depositCount`);
  assertU64(state.withdrawalCount, `${name}.withdrawalCount`);
  assertHex(state.poolInstanceIdHex, `${name}.poolInstanceIdHex`, 32);
  assertHex(state.noteRootHex, `${name}.noteRootHex`, 32);
  assertHex(state.nullifierRootHex, `${name}.nullifierRootHex`, 32);
  if (state.serializedHex !== undefined) assertHex(state.serializedHex, `${name}.serializedHex`, 128);
  return state;
}

export function validatePoolState(state, name = "state") {
  return validateState(state, name);
}

export function encodePoolState(state) {
  validateState(state);
  const writer = new Writer();
  writer.bytes(new TextEncoder().encode("PAF1"), "magic", 4);
  writer.u16(1);
  writer.u16(0);
  writer.u64(state.sequence, "sequence");
  writer.u64(state.depositCount, "depositCount");
  writer.u64(state.withdrawalCount, "withdrawalCount");
  writer.bytes(hexToBytes(state.poolInstanceIdHex, "poolInstanceIdHex"), "poolInstanceIdHex", 32);
  writer.bytes(hexToBytes(state.noteRootHex, "noteRootHex"), "noteRootHex", 32);
  writer.bytes(hexToBytes(state.nullifierRootHex, "nullifierRootHex"), "nullifierRootHex", 32);
  const result = writer.finish();
  if (result.length !== 128) fail(`PoolStateFv1 encoding length is ${result.length}, expected 128`);
  const encodedHex = bytesToHex(result);
  if (state.serializedHex !== undefined && state.serializedHex !== encodedHex) {
    fail("state.serializedHex does not equal canonical field serialization");
  }
  return result;
}

export function decodePoolState(input) {
  const bytes = input instanceof Uint8Array ? input : hexToBytes(input, "PoolStateFv1");
  if (bytes.length !== 128) fail(`PoolStateFv1 must be exactly 128 bytes, got ${bytes.length}`);
  const reader = new Reader(bytes, "PoolStateFv1");
  const magic = new TextDecoder().decode(reader.bytes(4, "magic"));
  const state = {
    schema: STATE_SCHEMA,
    magic,
    stateCodecVersion: reader.u16("stateCodecVersion"),
    reservedHex: bytesToHex(reader.bytes(2, "reserved")),
    sequence: reader.u64("sequence"),
    depositCount: reader.u64("depositCount"),
    withdrawalCount: reader.u64("withdrawalCount"),
    poolInstanceIdHex: bytesToHex(reader.bytes(32, "poolInstanceId")),
    noteRootHex: bytesToHex(reader.bytes(32, "noteRoot")),
    nullifierRootHex: bytesToHex(reader.bytes(32, "nullifierRoot")),
  };
  reader.done("PoolStateFv1");
  validateState(state, "decoded state");
  state.serializedHex = bytesToHex(bytes);
  return state;
}

export function poolStateHex(state) {
  return bytesToHex(encodePoolState(state));
}

export const encodePoolStateFv1 = encodePoolState;
export const decodePoolStateFv1 = decodePoolState;
