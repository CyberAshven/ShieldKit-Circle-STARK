import { createHash } from 'node:crypto';

import {
  binToHex,
  decodeTransactionBch,
  decodeTransactionOutputs,
  encodeLockingBytecodeP2pkh,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  encodeTransactionOutputs,
  hash256,
  verifyTransactionTokens,
} from '@bitauth/libauth';

export const TICKET_SATS = 10_000_000n;
export const MAX_STANDARD_TRANSACTION_BYTES = 100_000;
export const MAX_UNLOCKING_BYTECODE_BYTES = 10_000;
export const DEFAULT_STATE_BASE_SATS = 1_000n;
export const DEFAULT_CARRIER_VALUE_SATS = 1_000n;
export const DEFAULT_FEE_SATS = 1_000n;
export const DEFAULT_CHANGE_SATS = 2_000n;
export const DEFAULT_EXTERNAL_UNLOCKING_BYTES = 107;
export const MAX_MONEY_SATS = 2_100_000_000_000_000n;

const textEncoder = new TextEncoder();
const ACTIONS = new Set(['DEPOSIT', 'WITHDRAWAL']);

const fail = (message) => {
  throw new Error(message);
};

const assertInteger = (value, label, minimum, maximum) => {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be a safe integer in [${minimum}, ${maximum}]`);
  }
};

const assertSats = (value, label) => {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_MONEY_SATS) {
    fail(`${label} must be a nonnegative BCH monetary bigint`);
  }
};

const assertBytes = (value, length, label) => {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must be exactly ${length} bytes`);
  }
};

const assertPoolStateBytes = (value, label) => {
  assertBytes(value, 128, label);
  if (binToHex(value.subarray(0, 4)) !== '50414631') fail(`${label} has invalid PAF1 magic`);
  if (value[4] !== 1 || value[5] !== 0) fail(`${label} has invalid codec version`);
  if (value[6] !== 0 || value[7] !== 0) fail(`${label} has nonzero reserved bytes`);
};

const cloneBytes = (value) => Uint8Array.from(value);

const cloneToken = (token) => token === undefined
  ? undefined
  : {
      amount: token.amount,
      category: cloneBytes(token.category),
      ...(token.nft === undefined
        ? {}
        : {
            nft: {
              capability: token.nft.capability,
              commitment: cloneBytes(token.nft.commitment),
            },
          }),
    };

const cloneOutput = (output) => ({
  lockingBytecode: cloneBytes(output.lockingBytecode),
  valueSatoshis: output.valueSatoshis,
  ...(output.token === undefined ? {} : { token: cloneToken(output.token) }),
});

const sumValues = (outputs) => outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n);

const deterministicBytes = (length, domain) => {
  assertInteger(length, 'placeholder length', 0, MAX_UNLOCKING_BYTECODE_BYTES);
  const seed = createHash('sha256').update(domain).digest();
  return Uint8Array.from({ length }, (_, index) => seed[index % seed.length] ^ (index & 0xff));
};

const fixtureP2sh32 = (domain) => encodeLockingBytecodeP2sh32(
  hash256(textEncoder.encode(`PoolActionFv1/P1Shell/${domain}`)),
);

const fixtureP2pkh = (octet) => encodeLockingBytecodeP2pkh(new Uint8Array(20).fill(octet));

const stateToken = (category, commitment) => ({
  amount: 0n,
  category: cloneBytes(category),
  nft: {
    capability: 'mutable',
    commitment: cloneBytes(commitment),
  },
});

const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

const validateDecoded = (decoded, label) => {
  if (typeof decoded === 'string') fail(`${label} failed to decode: ${decoded}`);
  return decoded;
};

export const buildDeterministicProofFreeShell = ({
  action,
  carrierCount,
  oldStateCommitment,
  newStateCommitment,
  includeChange = false,
  proofUnlockingLengths,
  externalUnlockingLength = DEFAULT_EXTERNAL_UNLOCKING_BYTES,
  stateBaseSats = DEFAULT_STATE_BASE_SATS,
  carrierValueSats = DEFAULT_CARRIER_VALUE_SATS,
  feeSats = DEFAULT_FEE_SATS,
  changeSats = DEFAULT_CHANGE_SATS,
} = {}) => {
  if (!ACTIONS.has(action)) fail('action must be DEPOSIT or WITHDRAWAL');
  assertInteger(carrierCount, 'carrierCount', 1, 65_532);
  if (typeof includeChange !== 'boolean') fail('includeChange must be boolean');
  assertPoolStateBytes(oldStateCommitment, 'oldStateCommitment');
  assertPoolStateBytes(newStateCommitment, 'newStateCommitment');
  assertInteger(externalUnlockingLength, 'externalUnlockingLength', 0, MAX_UNLOCKING_BYTECODE_BYTES);
  assertSats(stateBaseSats, 'stateBaseSats');
  assertSats(carrierValueSats, 'carrierValueSats');
  assertSats(feeSats, 'feeSats');
  assertSats(changeSats, 'changeSats');

  const proofInputCount = carrierCount + 1;
  const resolvedProofLengths = proofUnlockingLengths ?? new Array(proofInputCount).fill(0);
  if (!Array.isArray(resolvedProofLengths) || resolvedProofLengths.length !== proofInputCount) {
    fail(`proofUnlockingLengths must contain exactly ${proofInputCount} lengths`);
  }
  resolvedProofLengths.forEach((length, index) => {
    assertInteger(length, `proofUnlockingLengths[${index}]`, 0, MAX_UNLOCKING_BYTECODE_BYTES);
  });

  const stateCategory = new Uint8Array(32).fill(0x11);
  const stateLock = fixtureP2sh32('state');
  const carrierLocks = Array.from(
    { length: carrierCount },
    (_, ordinal) => fixtureP2sh32(`carrier/${ordinal}`),
  );
  const fundingLock = fixtureP2pkh(0x22);
  const payoutLock = fixtureP2pkh(0x33);
  const changeLock = fixtureP2pkh(0x44);

  const oldStateValueSats = action === 'DEPOSIT'
    ? stateBaseSats
    : stateBaseSats + TICKET_SATS;
  const newStateValueSats = action === 'DEPOSIT'
    ? stateBaseSats + TICKET_SATS
    : stateBaseSats;
  const transparentChangeSats = includeChange ? changeSats : 0n;
  const externalValueSats = action === 'DEPOSIT'
    ? TICKET_SATS + transparentChangeSats + feeSats
    : transparentChangeSats + feeSats;
  assertSats(oldStateValueSats, 'oldStateValueSats');
  assertSats(newStateValueSats, 'newStateValueSats');
  assertSats(externalValueSats, 'externalValueSats');

  const stateSource = {
    lockingBytecode: stateLock,
    valueSatoshis: oldStateValueSats,
    token: stateToken(stateCategory, oldStateCommitment),
  };
  const carrierSources = carrierLocks.map((lockingBytecode) => ({
    lockingBytecode,
    valueSatoshis: carrierValueSats,
  }));
  const externalSource = {
    lockingBytecode: fundingLock,
    valueSatoshis: externalValueSats,
  };
  const sourceOutputs = [stateSource, ...carrierSources, externalSource].map(cloneOutput);

  const predecessorTransaction = {
    version: 2,
    inputs: [{
      outpointTransactionHash: hash256(textEncoder.encode('PoolActionFv1/P1Shell/predecessor-parent')),
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array([0x51]),
    }],
    outputs: [stateSource, ...carrierSources].map(cloneOutput),
    locktime: 0,
  };
  const predecessorWire = encodeTransaction(predecessorTransaction);
  const predecessorTransactionHashWire = hash256(predecessorWire);

  const proofUnlockingBytecodes = resolvedProofLengths.map((length, index) => (
    deterministicBytes(length, `PoolActionFv1/P1Shell/proof-bearing/${action}/${carrierCount}/${index}`)
  ));
  const externalUnlockingBytecode = deterministicBytes(
    externalUnlockingLength,
    `PoolActionFv1/P1Shell/external-signature-placeholder/${externalUnlockingLength}`,
  );

  const inputs = [
    {
      outpointTransactionHash: predecessorTransactionHashWire,
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: proofUnlockingBytecodes[0],
    },
    ...carrierLocks.map((_, ordinal) => ({
      outpointTransactionHash: predecessorTransactionHashWire,
      outpointIndex: ordinal + 1,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: proofUnlockingBytecodes[ordinal + 1],
    })),
    {
      outpointTransactionHash: hash256(textEncoder.encode('PoolActionFv1/P1Shell/external-source')),
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: externalUnlockingBytecode,
    },
  ];

  const outputs = [
    {
      lockingBytecode: stateLock,
      valueSatoshis: newStateValueSats,
      token: stateToken(stateCategory, newStateCommitment),
    },
    ...carrierSources.map(cloneOutput),
    ...(action === 'WITHDRAWAL'
      ? [{ lockingBytecode: payoutLock, valueSatoshis: TICKET_SATS }]
      : []),
    ...(includeChange
      ? [{ lockingBytecode: changeLock, valueSatoshis: transparentChangeSats }]
      : []),
  ];

  const transaction = { version: 2, inputs, outputs, locktime: 0 };
  const transactionWire = encodeTransaction(transaction);
  const sourceOutputsWire = encodeTransactionOutputs(sourceOutputs);
  const predecessorBundleOutputsWire = encodeTransactionOutputs(predecessorTransaction.outputs);
  const sourceBundleWire = encodeTransactionOutputs(sourceOutputs.slice(0, carrierCount + 1));
  const decodedTransaction = validateDecoded(decodeTransactionBch(transactionWire), 'transaction');
  const decodedSourceOutputs = validateDecoded(decodeTransactionOutputs(sourceOutputsWire), 'source outputs');

  if (binToHex(encodeTransaction(decodedTransaction)) !== binToHex(transactionWire)) {
    fail('transaction did not round-trip byte-for-byte');
  }
  if (binToHex(encodeTransactionOutputs(decodedSourceOutputs)) !== binToHex(sourceOutputsWire)) {
    fail('source outputs did not round-trip byte-for-byte');
  }
  if (binToHex(predecessorBundleOutputsWire) !== binToHex(sourceBundleWire)) {
    fail('predecessor outputs do not exactly reproduce the state/carrier source bundle');
  }

  const inputValueSats = sumValues(sourceOutputs);
  const outputValueSats = sumValues(outputs);
  assertSats(inputValueSats, 'inputValueSats');
  assertSats(outputValueSats, 'outputValueSats');
  if (inputValueSats - outputValueSats !== feeSats) {
    fail('fixture monetary conservation does not equal feeSats');
  }
  const tokenValidity = verifyTransactionTokens(
    transaction,
    sourceOutputs,
    { maximumTokenCommitmentLength: 128 },
  );
  if (tokenValidity !== true) fail(`CashToken conservation failed: ${tokenValidity}`);

  return {
    status: 'proof-free-size-fixture-not-a-valid-spend',
    action,
    carrierCount,
    includeChange,
    assumptions: {
      stateAndCarrierLockType: 'deterministic 35-byte P2SH32 fixtures; deployment locks unselected',
      externalSourceLockType: 'deterministic 25-byte P2PKH fixture',
      externalUnlockingBytecode: 'length-exact invalid-signature placeholder',
      proofBearingUnlockingBytecodes: 'length-exact opaque placeholders; includes all future wrappers and proof sections',
      stateBaseSats: stateBaseSats.toString(),
      carrierValueSats: carrierValueSats.toString(),
      feeSats: feeSats.toString(),
      changeSats: transparentChangeSats.toString(),
    },
    roleMap: {
      inputs: [
        { index: 0, role: 'STATE', ordinal: 0 },
        ...carrierLocks.map((_, ordinal) => ({ index: ordinal + 1, role: 'VERIFIER_CARRIER', ordinal })),
        { index: carrierCount + 1, role: action === 'DEPOSIT' ? 'DEPOSIT_FUNDING' : 'FEE_FUNDING', ordinal: 0 },
      ],
      outputs: [
        { index: 0, role: 'STATE_SUCCESSOR', ordinal: 0 },
        ...carrierLocks.map((_, ordinal) => ({ index: ordinal + 1, role: 'VERIFIER_CARRIER_SUCCESSOR', ordinal })),
        ...(action === 'WITHDRAWAL'
          ? [{ index: carrierCount + 1, role: 'PAYOUT', ordinal: 0 }]
          : []),
        ...(includeChange
          ? [{ index: outputs.length - 1, role: 'TRANSPARENT_CHANGE', ordinal: 0 }]
          : []),
      ],
    },
    accounting: {
      transactionBytes: transactionWire.length,
      sourceOutputsBytes: sourceOutputsWire.length,
      predecessorTransactionBytes: predecessorWire.length,
      proofBearingInputCount: proofInputCount,
      proofBearingUnlockingBytes: resolvedProofLengths.reduce((sum, length) => sum + length, 0),
      proofBearingUnlockingLengths: [...resolvedProofLengths],
      externalUnlockingBytes: externalUnlockingLength,
      inputValueSats: inputValueSats.toString(),
      outputValueSats: outputValueSats.toString(),
      feeSats: feeSats.toString(),
      transactionHeadroomBytes: MAX_STANDARD_TRANSACTION_BYTES - transactionWire.length,
    },
    checks: {
      canonicalTransactionRoundTrip: true,
      canonicalSourceOutputsRoundTrip: true,
      predecessorBundleByteEquality: true,
      monetaryConservation: true,
      cashTokenConservation: true,
      standardTransactionSizeOnly: transactionWire.length <= MAX_STANDARD_TRANSACTION_BYTES,
      scriptExecution: 'not-run-proof-and-signature-placeholders',
      nodePolicy: 'not-run',
    },
    digests: {
      algorithm: 'sha256-artifact-identity-only-not-a-protocol-selection',
      transactionSha256: sha256Hex(transactionWire),
      sourceOutputsSha256: sha256Hex(sourceOutputsWire),
      predecessorTransactionSha256: sha256Hex(predecessorWire),
    },
    bytes: {
      transaction: transactionWire,
      sourceOutputs: sourceOutputsWire,
      predecessorTransaction: predecessorWire,
    },
    structures: {
      transaction,
      sourceOutputs,
      predecessorTransaction,
    },
  };
};

const compactSizePrefixBytesForUnlock = (length) => length <= 252 ? 1 : 3;

const allocateForLargeCount = (total, inputCount, largeCount, minimum) => {
  const lengths = new Array(inputCount).fill(minimum);
  for (let index = 0; index < largeCount; index += 1) lengths[index] = 253;
  let remaining = total - largeCount * 253 - (inputCount - largeCount) * minimum;
  for (let index = 0; index < largeCount && remaining > 0; index += 1) {
    const delta = Math.min(10_000 - 253, remaining);
    lengths[index] += delta;
    remaining -= delta;
  }
  for (let index = largeCount; index < inputCount && remaining > 0; index += 1) {
    const delta = Math.min(252, remaining);
    lengths[index] += delta;
    remaining -= delta;
  }
  if (remaining !== 0) fail('internal proof-bearing allocation failure');
  return lengths;
};

export const maximumProofBearingUnlockEnvelope = (options) => {
  const minimum = options?.minimumProofBearingUnlockingBytes ?? 1;
  assertInteger(minimum, 'minimumProofBearingUnlockingBytes', 0, 252);
  const shellOptions = { ...options };
  delete shellOptions.minimumProofBearingUnlockingBytes;
  const empty = buildDeterministicProofFreeShell({ ...shellOptions, proofUnlockingLengths: undefined });
  const inputCount = empty.accounting.proofBearingInputCount;
  const fixedWithoutProofPrefixes = empty.accounting.transactionBytes - inputCount;
  let best;

  for (let largeCount = 0; largeCount <= inputCount; largeCount += 1) {
    const prefixBytes = inputCount + 2 * largeCount;
    const capacity = largeCount * 10_000 + (inputCount - largeCount) * 252;
    const budget = MAX_STANDARD_TRANSACTION_BYTES - fixedWithoutProofPrefixes - prefixBytes;
    const aggregate = Math.min(capacity, budget);
    const minimumForClass = largeCount * 253 + (inputCount - largeCount) * minimum;
    if (aggregate < minimumForClass || aggregate < 0) continue;
    const lengths = allocateForLargeCount(aggregate, inputCount, largeCount, minimum);
    const shell = buildDeterministicProofFreeShell({ ...shellOptions, proofUnlockingLengths: lengths });
    if (shell.accounting.transactionBytes > MAX_STANDARD_TRANSACTION_BYTES) {
      fail('internal envelope computation exceeded standard transaction size');
    }
    if (best === undefined || aggregate > best.aggregateUnlockingBytes) {
      best = {
        status: 'exact-unlocking-envelope-for-stated-fixture-assumptions',
        action: shell.action,
        carrierCount: shell.carrierCount,
        includeChange: shell.includeChange,
        aggregateUnlockingBytes: aggregate,
        allocation: lengths,
        minimumPerProofBearingInputBytes: minimum,
        compactSizePrefixBytes: lengths.reduce(
          (sum, length) => sum + compactSizePrefixBytesForUnlock(length),
          0,
        ),
        transactionBytes: shell.accounting.transactionBytes,
        transactionHeadroomBytes: shell.accounting.transactionHeadroomBytes,
        fixedZeroProofTransactionBytes: empty.accounting.transactionBytes,
        limitingRule: aggregate === inputCount * MAX_UNLOCKING_BYTECODE_BYTES
          ? 'per-input-10000-byte-limit'
          : '100000-byte-standard-transaction-limit',
        caveat: 'This is an envelope for complete proof-bearing unlocking bytecodes, including wrappers and statements; it is not a Circle-FRI proof-byte estimate.',
        shell,
      };
    }
  }

  if (best === undefined) fail('no standard-size shell allocation exists');
  return best;
};
