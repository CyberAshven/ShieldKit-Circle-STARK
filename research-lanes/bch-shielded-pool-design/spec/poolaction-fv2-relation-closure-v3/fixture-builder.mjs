// SPDX-License-Identifier: CC0-1.0
// Deterministic structural-only fixture builder. It does not serialize a complete BCH transaction.

import {
  TICKET_SATS,
  bytesToHex,
  deriveRelationV3,
  deriveStructuralProvenanceV3,
  encodeMinimalPush,
  encodeSegmentFrameV3,
  runtimeU64LeHex,
  sha256,
  u64le,
} from "./validate.mjs";

const ZERO_RUNTIME = runtimeU64LeHex(0n);
const NONE = () => ({ categoryWireHex: "", commitmentHex: "", amountLeHex: ZERO_RUNTIME });
const hex = (bytes) => bytesToHex(bytes);
const seed = (text) => sha256(Buffer.from(`PoolActionFv2 fixture/v3/${text}`, "ascii"));

function stateCommitment({ sequence, deposits, withdrawals, poolInstanceId, noteRoot, nullifierRoot }) {
  return Buffer.concat([
    Buffer.from("PAF1"), Buffer.from([1, 0, 0, 0]), u64le(sequence), u64le(deposits), u64le(withdrawals),
    poolInstanceId, noteRoot, nullifierRoot,
  ]);
}

function p2pkh(seedText) {
  return Buffer.concat([Buffer.from("76a914", "hex"), seed(seedText).subarray(0, 20), Buffer.from("88ac", "hex")]);
}

function runtime(value) {
  return runtimeU64LeHex(value);
}

function rawInput({ hash, index, value, lock, token }) {
  return {
    outpointTxHashOpcodeOrderHex: hex(hash),
    outpointIndexLeHex: runtime(index),
    sequenceLeHex: runtime(0xffffffffn),
    sourceValueSatsLeHex: runtime(value),
    sourceLockingBytecodeHex: hex(lock),
    tokenProjection: token,
  };
}

function rawOutput({ value, lock, token }) {
  return { valueSatsLeHex: runtime(value), lockingBytecodeHex: hex(lock), tokenProjection: token };
}

function serializeProvenance(value) {
  return {
    templateSetHex: hex(value.templateSet),
    protocolTemplateDigestHex: hex(value.protocolTemplateDigest),
    anchorTxHashOpcodeOrderHex: hex(value.anchorTxHashOpcodeOrder),
    anchorOutputIndexLeHex: runtime(BigInt(value.anchorOutputIndex)),
    preExistingAnchorDigestHex: hex(value.preExistingAnchorDigest),
    poolIdentityConfigHex: hex(value.poolIdentityConfig),
    poolInstanceIdHex: hex(value.poolInstanceId),
    stateCategoryWireHex: hex(value.stateCategoryWire),
    genesisAncestryDigestHex: hex(value.genesisAncestryDigest),
    deploymentManifestCoreHex: hex(value.manifestCore),
    deploymentCommitmentHex: hex(value.deploymentCommitment),
    genesisInitialStateValueSatsLeHex: runtime(value.genesisInitialStateValueSats),
    roles: value.roles.map((role) => ({
      roleClass: role.roleClass,
      ordinalLeHex: runtime(BigInt(role.ordinal)),
      roleInstanceHex: hex(role.roleInstance),
      redeemHex: hex(role.redeem),
      lockHex: hex(role.lock),
      redeemIntervals: role.redeemIntervals,
      lockIntervals: role.lockIntervals,
    })),
    structuralOnly: true,
    nonDeployable: true,
    proofSuite: "UNSELECTED",
  };
}

export function buildFixtureV3(action, carrierCount) {
  if (!Number.isInteger(carrierCount) || ![1, 3].includes(carrierCount)) throw new Error("fixtures are materialized only for N=1 and N=3");
  if (!["DEPOSIT", "WITHDRAWAL"].includes(action)) throw new Error("action must be DEPOSIT or WITHDRAWAL");
  const fixtureId = `${action.toLowerCase()}-n${carrierCount}`;
  const base = 100000000n;
  const capacity = 10n;
  const fee = 1000n;
  const change = 2000n;
  const anchorHash = seed(`${fixtureId}/anchor`);
  const carrierValues = Array.from({ length: carrierCount }, (_, index) => 1000n + BigInt(index));
  const provenance = deriveStructuralProvenanceV3({
    anchorTxHashOpcodeOrderHex: hex(anchorHash),
    anchorOutputIndexLeHex: runtime(0n),
    networkId: "regtest",
    stateCarrierBaseSatsLeHex: runtime(base),
    maxLifetimeDepositsLeHex: runtime(capacity),
    feePolicyMaxSatsLeHex: runtime(10000n),
    carrierExpectedValuesSatsLeHex: carrierValues.map((value) => runtime(value)),
    genesisInitialStateValueSatsLeHex: runtime(base),
  });
  const oldDeposits = action === "DEPOSIT" ? 2n : 3n;
  const oldWithdrawals = 1n;
  const newDeposits = action === "DEPOSIT" ? oldDeposits + 1n : oldDeposits;
  const newWithdrawals = action === "DEPOSIT" ? oldWithdrawals : oldWithdrawals + 1n;
  const oldStateValue = base + ((oldDeposits - oldWithdrawals) * TICKET_SATS);
  const newStateValue = base + ((newDeposits - newWithdrawals) * TICKET_SATS);
  const noteRoot = seed(`${fixtureId}/note-root`);
  const nullifierRoot = seed(`${fixtureId}/nullifier-root`);
  const oldCommitment = stateCommitment({
    sequence: 7n, deposits: oldDeposits, withdrawals: oldWithdrawals, poolInstanceId: provenance.poolInstanceId,
    noteRoot, nullifierRoot,
  });
  const newCommitment = stateCommitment({
    sequence: 8n, deposits: newDeposits, withdrawals: newWithdrawals, poolInstanceId: provenance.poolInstanceId,
    noteRoot: action === "DEPOSIT" ? seed(`${fixtureId}/note-root-next`) : noteRoot,
    nullifierRoot: action === "WITHDRAWAL" ? seed(`${fixtureId}/nullifier-root-next`) : nullifierRoot,
  });
  const stateRole = provenance.roles[0];
  const carriers = provenance.roles.slice(1);
  // Current token introspection returns the observable extended category.
  // The lock-selected P3DM base category is 32 bytes; state evidence must
  // carry its required mutable capability suffix rather than synthesizing it.
  const stateExtendedCategoryWireHex = `${hex(provenance.stateCategoryWire)}01`;
  const predecessorHash = seed(`${fixtureId}/predecessor`);
  const inputs = [rawInput({
    hash: predecessorHash, index: 0n, value: oldStateValue, lock: stateRole.lock,
    token: { categoryWireHex: stateExtendedCategoryWireHex, commitmentHex: hex(oldCommitment), amountLeHex: ZERO_RUNTIME },
  })];
  for (let i = 0; i < carrierCount; i += 1) {
    inputs.push(rawInput({ hash: predecessorHash, index: BigInt(i + 1), value: carrierValues[i], lock: carriers[i].lock, token: NONE() }));
  }
  const externalValue = action === "DEPOSIT" ? TICKET_SATS + change + fee : change + fee;
  inputs.push(rawInput({ hash: seed(`${fixtureId}/external`), index: 9n, value: externalValue, lock: p2pkh(`${fixtureId}/external`), token: NONE() }));
  const outputs = [rawOutput({
    value: newStateValue, lock: stateRole.lock,
    token: { categoryWireHex: stateExtendedCategoryWireHex, commitmentHex: hex(newCommitment), amountLeHex: ZERO_RUNTIME },
  })];
  for (let i = 0; i < carrierCount; i += 1) outputs.push(rawOutput({ value: carrierValues[i], lock: carriers[i].lock, token: NONE() }));
  if (action === "WITHDRAWAL") outputs.push(rawOutput({ value: TICKET_SATS, lock: p2pkh(`${fixtureId}/payout`), token: NONE() }));
  outputs.push(rawOutput({ value: change, lock: p2pkh(`${fixtureId}/change`), token: NONE() }));
  const carrierUnlockingBytecodesHex = carriers.map((carrier, ordinal) => {
    const payload = Buffer.concat([Buffer.from("opaque-unverified/v3/", "ascii"), Buffer.from([ordinal]), seed(`${fixtureId}/payload/${ordinal}`).subarray(0, 7)]);
    const frame = encodeSegmentFrameV3({ ordinal, inputIndex: ordinal + 1, payload });
    return hex(Buffer.concat([encodeMinimalPush(frame), encodeMinimalPush(carrier.redeem)]));
  });
  const relationInput = {
    schema: "shieldkit-labs/poolaction-fv2/relation-input/v3",
    relationId: "PoolActionFv2",
    relationVersion: 2,
    abiVersion: 3,
    transaction: { versionLeHex: runtime(2n), locktimeLeHex: ZERO_RUNTIME, inputs, outputs },
    stateActiveRedeemHex: hex(stateRole.redeem),
    carrierUnlockingBytecodesHex,
    verifierRoleConsumptions: [
      { roleTagHex: "00", ordinalLeHex: ZERO_RUNTIME, observedInputIndexLeHex: ZERO_RUNTIME },
      ...carriers.map((_, ordinal) => ({ roleTagHex: "01", ordinalLeHex: runtime(BigInt(ordinal)), observedInputIndexLeHex: runtime(BigInt(ordinal + 1)) })),
    ],
  };
  const expected = deriveRelationV3(relationInput);
  return {
    raw: {
      schema: "shieldkit-labs/poolaction-fv2/structural-fixture-raw/v3",
      fixtureId,
      classification: "STRUCTURAL_PROOF_REJECTED_NONDEPLOYABLE",
      relationInput,
      structuralProvenance: serializeProvenance(provenance),
      nonClaims: ["proof acceptance", "BCH VM execution", "complete transaction", "standardness", "deployment", "activation"],
    },
    expected,
  };
}
