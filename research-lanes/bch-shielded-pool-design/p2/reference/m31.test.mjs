import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  M31_MODULUS,
  M31Error,
  add,
  assertFullConsumption,
  bytesToHex,
  decodeM31,
  decodeM31Hex,
  decodeM31Sequence,
  encodeM31,
  encodeM31Hex,
  hexToBytesStrict,
  inverse,
  inverseWithHint,
  mul,
  neg,
  readM31,
  square,
  sub,
  verifyInverseHint,
} from "./m31.mjs";

const kat = JSON.parse(readFileSync(new URL("./m31-kat.json", import.meta.url), "utf8"));
const KAT_SHA256 = "603fd7283038b1e61d2fb92c82192a46d548b314dd9a0078540f2d2add11427f";
const value = (decimal) => BigInt(decimal);
const expectThrow = (fn, pattern, message) => assert.throws(
  fn,
  (error) => error instanceof M31Error && pattern.test(error.message),
  message,
);

test("KAT artifact is internally canonical and independently recorded", () => {
  assert.equal(kat.modulus, M31_MODULUS.toString());
  assert.equal(kat.wireBytes, 4);
  for (const item of kat.elements) {
    assert.equal(encodeM31Hex(value(item.value)), item.wireHex);
    assert.equal(decodeM31Hex(item.wireHex), value(item.value));
  }
  const canonicalDigest = createHash("sha256")
    .update(readFileSync(new URL("./m31-kat.json", import.meta.url)))
    .digest("hex");
  assert.equal(canonicalDigest, KAT_SHA256);
  for (const item of kat.rejections) {
    expectThrow(() => decodeM31Hex(item.wireHex), />= p/, item.id);
  }
});

test("canonical wire boundary vectors", () => {
  assert.equal(bytesToHex(encodeM31(0n)), "00000000");
  assert.equal(bytesToHex(encodeM31(1n)), "01000000");
  assert.equal(bytesToHex(encodeM31(M31_MODULUS - 1n)), "feffff7f");
  assert.equal(decodeM31(new Uint8Array([0, 0, 0, 0])), 0n);
  assert.equal(decodeM31(new Uint8Array([0xfe, 0xff, 0xff, 0x7f])), M31_MODULUS - 1n);
  expectThrow(() => decodeM31Hex("ffffff7f"), />= p/);
  expectThrow(() => decodeM31Hex("ffffffff"), />= p/);
  expectThrow(() => decodeM31(new Uint8Array(0)), /exactly 4/);
  expectThrow(() => decodeM31(new Uint8Array(3)), /exactly 4/);
  expectThrow(() => decodeM31(new Uint8Array(5)), /exactly 4/);
  expectThrow(() => encodeM31(1), /BigInt/);
  expectThrow(() => decodeM31Hex("0100000F"), /lowercase/);
  expectThrow(() => decodeM31Hex("010000"), /exactly 8/);
});

test("strict sequence reading and full-consumption helpers", () => {
  const bytes = hexToBytesStrict("0100000078563412");
  assert.deepEqual(decodeM31Sequence(bytes), [1n, 305419896n]);
  assert.deepEqual(readM31(bytes, 4), { value: 305419896n, nextOffset: 8 });
  assertFullConsumption(8, 8, "fixture");
  expectThrow(() => readM31(bytes, 5), /ends before/);
  expectThrow(() => decodeM31Sequence(hexToBytesStrict("01000000ff")), /ends before/);
  expectThrow(() => hexToBytesStrict("01 0"), /lowercase even-length/);
  expectThrow(() => assertFullConsumption(4, 5, "fixture"), /trailing/);
});

test("independently derived arithmetic KATs", () => {
  for (const item of kat.operations) {
    const left = value(item.left);
    const expected = value(item.expected);
    let actual;
    if (item.op === "add") actual = add(left, value(item.right));
    else if (item.op === "sub") actual = sub(left, value(item.right));
    else if (item.op === "neg") actual = neg(left);
    else if (item.op === "mul") actual = mul(left, value(item.right));
    else if (item.op === "square") actual = square(left);
    else if (item.op === "inverse") actual = inverse(left);
    else assert.fail(`unknown KAT operation ${item.op}`);
    assert.equal(actual, expected, item.op);
    assert.equal(encodeM31Hex(actual), item.expectedWireHex, item.op);
  }
  assert.equal(mul(M31_MODULUS - 1n, M31_MODULUS - 1n), 1n);
  assert.equal(sub(0n, M31_MODULUS - 1n), 1n);
  assert.equal(neg(0n), 0n);
});

test("inverse hints verify, reject mismatches, and reject zero", () => {
  assert.equal(verifyInverseHint(305419896n, 1135688465n), true);
  assert.equal(verifyInverseHint(305419896n, 1135688466n), false);
  assert.equal(inverseWithHint(305419896n, 1135688465n), 1135688465n);
  expectThrow(() => inverseWithHint(305419896n, 1135688466n), /does not verify/);
  expectThrow(() => inverse(0n), /zero/);
  expectThrow(() => verifyInverseHint(0n, 1n), /zero/);
  expectThrow(() => inverseWithHint(1n, M31_MODULUS), /must be in/);
});

test("all arithmetic APIs reject noncanonical values and Number truncation", () => {
  for (const operation of [add, sub, mul]) {
    expectThrow(() => operation(M31_MODULUS, 1n), /must be in/);
    expectThrow(() => operation(1n, -1n), /\[0,/);
    expectThrow(() => operation(1, 1n), /BigInt/);
  }
  expectThrow(() => square(M31_MODULUS), /must be in/);
  expectThrow(() => neg(-1n), /\[0,/);
  expectThrow(() => inverse(1), /BigInt/);
});
