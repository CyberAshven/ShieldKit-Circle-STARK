import assert from 'node:assert/strict';
import test from 'node:test';

import {
  M89_CORPUS,
  M89_RELATION_OPERANDS,
  buildM89ShakedownFixture,
  evaluateM89ShakedownCase,
  evaluateM89ShakedownCorpus,
} from './m89-shakedown-fixture.mjs';

const readPushes = (bytes) => {
  const pushes = [];
  for (let offset = 0; offset < bytes.length;) {
    const opcode = bytes[offset++];
    let length;
    if (opcode <= 75) length = opcode;
    else if (opcode === 0x4c) {
      assert.ok(offset < bytes.length, 'truncated OP_PUSHDATA1');
      length = bytes[offset++];
    } else if (opcode === 0x4d) {
      assert.ok(offset + 1 < bytes.length, 'truncated OP_PUSHDATA2');
      length = bytes[offset] | (bytes[offset + 1] << 8);
      offset += 2;
    } else {
      assert.fail(`non-push opcode 0x${opcode.toString(16)}`);
    }
    assert.ok(offset + length <= bytes.length, 'truncated push payload');
    pushes.push({ opcode, payload: bytes.slice(offset, offset + length) });
    offset += length;
  }
  return pushes;
};

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const equalBytes = (left, right) => assert.equal(hex(left), hex(right));

test('all 266 frozen corpus cases replay under Libauth standard VM rules with P2SH32', () => {
  const results = evaluateM89ShakedownCorpus();
  assert.equal(results.length, 266);
  assert.deepEqual(
    Object.fromEntries(Object.keys(M89_RELATION_OPERANDS).map((relation) => [
      relation, results.filter((result) => result.relationId === relation).length,
    ])),
    {
      'relation:e-mac': 88,
      'relation:e-square-mac': 88,
      'relation:e-inverse-check': 90,
    },
  );
  assert.equal(results.filter((result) => result.accepted).length, 206);
  assert.equal(results.filter((result) => !result.accepted).length, 60);

  for (const result of results) {
    assert.equal(result.standardVmRules, true, result.fixtureId);
    assert.equal(result.accepted, result.expected.verdict === 'accept', result.fixtureId);
    assert.equal(result.sourceLockingBytes, 35, result.fixtureId);
    assert.equal(result.sourceLockingHex.slice(0, 4), 'aa20', result.fixtureId);
    assert.equal(result.sourceLockingHex.slice(-2), '87', result.fixtureId);
    assert.equal(result.sourceLockingHex.slice(4, -2), result.redeemHash256Hex);
    assert.notEqual(result.redeemDigestSha256, result.redeemHash256Hex);
    assert.equal(result.dustSafe, true, result.fixtureId);
    assert.equal(result.outputLockingHex, '51');

    const operandPushes = readPushes(result.operandUnlockingBytecode);
    assert.equal(operandPushes.length, M89_RELATION_OPERANDS[result.relationId].length, result.fixtureId);
    assert.equal(result.operandUnlockingBytes, result.operandUnlockingBytecode.length, result.fixtureId);
    const wrapperPushes = readPushes(result.unlockingBytecode);
    assert.equal(wrapperPushes.length, operandPushes.length + 1, result.fixtureId);
    equalBytes(wrapperPushes.at(-1).payload, result.redeemBytecode);
    equalBytes(result.unlockingBytecode.slice(0, result.operandUnlockingBytes), result.operandUnlockingBytecode);
    assert.equal(result.redeemPushBytes, result.redeemPush.length, result.fixtureId);
    assert.equal(result.unlockingBytes, result.operandUnlockingBytes + result.redeemPushBytes, result.fixtureId);
  }
});

test('malformed raw operands remain byte-identical and are rejected at the declared relation stage', () => {
  const malformed = M89_CORPUS.cases.filter(({ categoryId }) => categoryId === 'category:malformed');
  assert.equal(malformed.length, 44);
  for (const entry of malformed) {
    const fixture = buildM89ShakedownFixture(entry);
    for (const name of M89_RELATION_OPERANDS[entry.relationId]) {
      equalBytes(fixture.raw[name], Uint8Array.from(Buffer.from(entry.raw[name], 'hex')));
    }
    const result = evaluateM89ShakedownCase(entry);
    assert.equal(result.accepted, false, fixture.fixtureId);
    assert.equal(result.expected.stage, entry.expected.stage, fixture.fixtureId);
  }
  const emptyOperand = malformed.find(({ raw }) => Object.values(raw).some((value) => value.length === 0));
  assert.ok(emptyOperand);
  const emptyFixture = buildM89ShakedownFixture(emptyOperand);
  assert.ok(Object.values(emptyFixture.raw).some((value) => value.length === 0));
  assert.ok(readPushes(emptyFixture.operandUnlockingBytecode).some(({ payload }) => payload.length === 0), 'empty raw operand must use OP_0');
});

test('trace metric extraction KAT is stable for the first canonical E-MAC case', () => {
  const result = evaluateM89ShakedownCase(M89_CORPUS.cases[0]);
  assert.equal(result.fixtureId, 'm89-gate-b0:mac:valid:0:v0');
  assert.equal(result.accepted, true);
  assert.equal(result.traceLength, 364);
  assert.deepEqual(result.rawMetrics, {
    arithmeticCost: 187,
    definedFunctions: 0,
    densityControlLength: 712,
    evaluatedInstructionCount: 360,
    hashDigestIterations: 11,
    maximumHashDigestIterations: 356,
    maximumOperationCost: 569600,
    maximumSignatureCheckCount: 17,
    operationCost: 39998,
    signatureCheckCount: 0,
    stackPushedBytes: 1699,
  });
  assert.deepEqual(result.arithmeticCounts, { mul: 4, div: 0, mod: 8 });
  assert.equal(result.mulByteProduct, 1);
  assert.equal(result.divByteProduct, 0);
  assert.equal(result.modByteProduct, 168);
  assert.equal(result.resultPushBytes, 4);
  assert.deepEqual(result.stackMaximums, {
    primaryItems: 11,
    alternateItems: 6,
    definedFunctions: 0,
    controlDepth: 0,
    functionCallDepth: 0,
    cumulativeMemoryItems: 13,
    elementBytes: 568,
  });
  assert.deepEqual(result.standardnessByteSizes, {
    sourceLockingBytes: 35,
    unlockingBytes: 671,
    sourceOutputsBytes: 45,
    redeemBytes: 568,
    redeemPushBytes: 571,
    outputLockingBytes: 1,
  });
  assert.equal(result.redeemHash256Hex, 'f2022ce5d353d1dac649cf6bd1b6cd36b2309eba3e61b0cdcdd53c379847256c');
  assert.equal(result.redeemDigestSha256, '93be03468372ca3d75d1bc929944d2990f85ab07867b7d88d785f381f9a10dc9');
  assert.equal(result.wrapperDigestSha256, '0ea3c25b188c00f31e09d5c538c249f0e85a6192ac75a8bfb3551b334607ae8a');
  assert.equal(result.transactionDigestSha256, '0ae8bd5d9eb8d27da23047185e7eee862d8199e872b2fa9897687655d642cda8');
  assert.equal(result.sourceOutputsDigestSha256, '2139ef93aaa3d1ae8f1985eb64da36040ab860030cc462f40502fdc352bb3c33');
  assert.equal(result.opcodeHistogram['0xaa'], 1);
  assert.equal(result.opcodeHistogram['0x95'], 4);
  assert.equal(result.opcodeHistogram['0x97'], 8);
  assert.equal(result.opcodeHistogram['0x4d'], 1);
});
