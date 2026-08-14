import {
  CodecError,
  Reader,
  Writer,
  TOKEN_KIND_NAMES,
  TOKEN_KIND_TAGS,
  assertExactKeys,
  assertHex,
  assertU8,
  assertU64,
  bytesToHex,
  fail,
  hexToBytes,
} from "./common.mjs";

const TOKEN_KEYS = ["categoryHex", "capability", "commitmentHex", "amount"];

function validateToken(token, name = "token") {
  assertExactKeys(token, TOKEN_KEYS, [], name);
  if (!Object.prototype.hasOwnProperty.call(TOKEN_KIND_TAGS, token.capability)) {
    fail(`${name}.capability is not canonical`);
  }
  assertU64(token.amount, `${name}.amount`);
  if (token.capability === "none") {
    if (token.categoryHex !== "" || token.commitmentHex !== "" || token.amount !== "0") {
      fail(`${name} none token must have empty category/commitment and zero amount`);
    }
    return;
  }

  assertHex(token.categoryHex, `${name}.categoryHex`, 32);
  if (token.capability === "fungible-only" && token.commitmentHex !== "") {
    fail(`${name} fungible-only token must have empty commitment`);
  }
  if (token.capability === "fungible-only" && token.amount === "0") {
    fail(`${name} fungible-only token amount must be nonzero; zero is the none-token alias`);
  }
  if (token.commitmentHex !== "") {
    if (token.commitmentHex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(token.commitmentHex)) {
      fail(`${name}.commitmentHex must be lowercase even-length hex`);
    }
    const length = token.commitmentHex.length / 2;
    if (length < 1 || length > 128) fail(`${name}.commitmentHex must be 1..128 bytes`);
  }
}

export function validateTokenRecord(token, name = "token") {
  validateToken(token, name);
  return token;
}

export function writeTokenRecord(writer, token, name = "token") {
  validateToken(token, name);
  const kind = TOKEN_KIND_TAGS[token.capability];
  writer.u8(kind);
  if (kind === 0) return;
  writer.bytes(hexToBytes(token.categoryHex, `${name}.categoryHex`), `${name}.categoryHex`, 32);
  writer.u64(token.amount, `${name}.amount`);
  const commitment = hexToBytes(token.commitmentHex, `${name}.commitmentHex`);
  assertU8(commitment.length, `${name}.commitmentLength`);
  writer.u8(commitment.length);
  if (commitment.length > 0) writer.bytes(commitment, `${name}.commitmentHex`, commitment.length);
}

export function readTokenRecord(reader, name = "token") {
  const kind = reader.u8(`${name}.tokenKind`);
  if (kind >= TOKEN_KIND_NAMES.length) fail(`${name}.tokenKind ${kind} is reserved`);
  if (kind === 0) {
    return { categoryHex: "", capability: "none", commitmentHex: "", amount: "0" };
  }
  const categoryHex = bytesToHex(reader.bytes(32, `${name}.categoryWire32`));
  const amount = reader.u64(`${name}.fungibleAmount`);
  const commitmentLength = reader.u8(`${name}.commitmentLength`);
  if (kind === 1 && commitmentLength !== 0) fail(`${name} fungible-only commitment must be empty`);
  if (commitmentLength > 128) fail(`${name}.commitmentLength exceeds 128`);
  const commitmentHex = bytesToHex(reader.bytes(commitmentLength, `${name}.commitment`));
  return { categoryHex, capability: TOKEN_KIND_NAMES[kind], commitmentHex, amount };
}

export function encodeTokenRecord(token) {
  const writer = new Writer();
  writeTokenRecord(writer, token);
  return writer.finish();
}

export function decodeTokenRecord(input) {
  const bytes = input instanceof Uint8Array ? input : hexToBytes(input, "tokenRecord");
  const reader = new Reader(bytes, "tokenRecord");
  const token = readTokenRecord(reader);
  reader.done("tokenRecord");
  validateToken(token, "decoded token");
  return token;
}

export function tokenRecordHex(token) {
  return bytesToHex(encodeTokenRecord(token));
}

export function tokenRecordsEqual(left, right) {
  try {
    return tokenRecordHex(left) === tokenRecordHex(right);
  } catch (error) {
    if (error instanceof CodecError) return false;
    throw error;
  }
}

export const encodeCanonicalTokenRecord = encodeTokenRecord;
export const decodeCanonicalTokenRecord = decodeTokenRecord;
