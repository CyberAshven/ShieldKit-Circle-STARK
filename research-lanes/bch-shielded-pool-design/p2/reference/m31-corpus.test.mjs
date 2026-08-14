import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  M31_MODULUS,
  add,
  decodeM31,
  encodeM31,
  inverse,
  inverseWithHint,
  mul,
  neg,
  square,
  sub,
  verifyInverseHint,
} from "./m31.mjs";

const corpusPath = new URL("./m31-corpus.json", import.meta.url);
const corpus = JSON.parse(readFileSync(corpusPath, "utf8"));
const P = M31_MODULUS;
const n = (value) => BigInt(value);
const expectedDigest = "fa76c62cfd3fb2ea4898b0b42fda5f21edcd41cb023c84925237eb903fe0dcd9";

function splitMix64Next(state) {
  const mask = (1n << 64n) - 1n;
  let z = (state + 0x9e3779b97f4a7c15n) & mask;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & mask;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & mask;
  z ^= z >> 31n;
  return { state: (state + 0x9e3779b97f4a7c15n) & mask, output: z & mask };
}

function expectedOperation(op, a, b) {
  if (op === "add") return (a + b) % P;
  if (op === "sub") return (a - b + P) % P;
  if (op === "neg") return a === 0n ? 0n : P - a;
  if (op === "mul") return (a * b) % P;
  if (op === "square") return (a * a) % P;
  throw new Error(`unknown operation ${op}`);
}

test("corpus metadata and content pin", () => {
  assert.equal(corpus.schema, "shieldkit-labs/m31-reference-corpus/v1");
  assert.equal(corpus.modulus, P.toString());
  assert.equal(corpus.wireBytes, 4);
  assert.equal(corpus.randomGenerator.name, "SplitMix64");
  assert.equal(corpus.randomGenerator.seedHex, "0123456789abcdef");
  assert.equal(corpus.randomGenerator.count, corpus.randomVectors.length);
  const digest = createHash("sha256").update(readFileSync(corpusPath)).digest("hex");
  assert.equal(digest, expectedDigest);
});

test("required SOL KATs cover every base operation", () => {
  const required = new Set(["add", "sub", "neg", "mul", "square", "inverse", "inverse-hint"]);
  assert.deepEqual(new Set(corpus.requiredKats.map((kat) => kat.op)), required);
  for (const kat of corpus.requiredKats) {
    const a = n(kat.a);
    if (kat.op === "inverse") assert.equal(inverse(a), n(kat.expected), kat.id);
    else if (kat.op === "inverse-hint") {
      assert.equal(verifyInverseHint(a, n(kat.hint)), kat.valid, kat.id);
      if (kat.valid) assert.equal(inverseWithHint(a, n(kat.hint)), n(kat.hint), kat.id);
    } else {
      const actual = expectedOperation(kat.op, a, kat.b === undefined ? undefined : n(kat.b));
      const implemented = kat.op === "add" ? add(a, n(kat.b))
        : kat.op === "sub" ? sub(a, n(kat.b))
          : kat.op === "neg" ? neg(a)
            : kat.op === "mul" ? mul(a, n(kat.b))
              : square(a);
      assert.equal(actual, n(kat.expected), `${kat.id} independent oracle`);
      assert.equal(implemented, n(kat.expected), kat.id);
    }
  }
});

test("SplitMix64 random vectors reproduce the pinned corpus and KAT outputs", () => {
  let state = n(`0x${corpus.randomGenerator.seedHex}`);
  for (let i = 0; i < corpus.randomVectors.length; i += 1) {
    const left = splitMix64Next(state);
    state = left.state;
    const right = splitMix64Next(state);
    state = right.state;
    const a = left.output % (P - 1n) + 1n;
    const b = right.output % (P - 1n) + 1n;
    const row = corpus.randomVectors[i];
    assert.equal(row.id, `random-${String(i).padStart(3, "0")}`);
    assert.equal(n(row.a), a);
    assert.equal(n(row.b), b);
    assert.equal(add(a, b), n(row.add));
    assert.equal(sub(a, b), n(row.sub));
    assert.equal(neg(a), n(row.negA));
    assert.equal(mul(a, b), n(row.mul));
    assert.equal(square(a), n(row.squareA));
    assert.equal(inverse(a), n(row.inverseA));
    assert.equal(verifyInverseHint(a, n(row.inverseHintA)), true);
    assert.equal(verifyInverseHint(a, n(row.wrongInverseHintA)), false);
  }
  assert.equal(state.toString(16).padStart(16, "0"), corpus.randomGenerator.finalStateHex);
});

test("exhaustive low-range arithmetic and boundary subset", () => {
  const lowStart = n(corpus.exhaustiveLowRange.start);
  const lowEnd = n(corpus.exhaustiveLowRange.endExclusive);
  for (let a = lowStart; a < lowEnd; a += 1n) {
    assert.equal(neg(a), (P - a) % P);
    assert.equal(square(a), mul(a, a));
    for (let b = lowStart; b < lowEnd; b += 1n) {
      assert.equal(add(a, b), (a + b) % P);
      assert.equal(sub(a, b), (a - b + P) % P);
      assert.equal(mul(a, b), (a * b) % P);
    }
  }

  const boundary = corpus.boundaryValues.map(n);
  for (const a of boundary) {
    assert.equal(decodeM31(encodeM31(a)), a);
    assert.equal(neg(neg(a)), a);
    if (a !== 0n) assert.equal(mul(a, inverse(a)), 1n);
    for (const b of boundary) {
      assert.equal(add(a, b), (a + b) % P);
      assert.equal(sub(a, b), (a - b + P) % P);
      assert.equal(mul(a, b), (a * b) % P);
    }
  }
});

test("metamorphic field identities over pinned random and boundary values", () => {
  const values = [
    ...corpus.randomVectors.flatMap((row) => [n(row.a), n(row.b)]),
    ...corpus.boundaryValues.map(n),
  ];
  for (let i = 0; i < values.length; i += 1) {
    const a = values[i];
    const b = values[(i + 1) % values.length];
    const c = values[(i + 2) % values.length];
    assert.equal(add(a, b), add(b, a), "add commutativity");
    assert.equal(mul(a, b), mul(b, a), "mul commutativity");
    assert.equal(add(add(a, b), c), add(a, add(b, c)), "add associativity");
    assert.equal(mul(mul(a, b), c), mul(a, mul(b, c)), "mul associativity");
    assert.equal(mul(a, add(b, c)), add(mul(a, b), mul(a, c)), "distributivity");
    assert.equal(square(a), mul(a, a), "square=mul");
    assert.equal(add(sub(a, b), b), a, "sub/add inverse");
    assert.equal(sub(add(a, b), b), a, "add/sub inverse");
    assert.equal(decodeM31(encodeM31(a)), a, "codec roundtrip");
  }
});
