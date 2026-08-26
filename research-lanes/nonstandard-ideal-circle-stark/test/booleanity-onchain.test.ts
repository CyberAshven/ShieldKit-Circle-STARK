import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cashAssemblyToBin, createVirtualMachineBch2026 } from "@bitauth/libauth";
import { encodeFriProof, proveFri, proveFromTLde, wDeposit } from "../src/backends/circle/fri.ts";
import { algebraicCQuotientLde } from "../src/backends/circle/air.ts";
import { circleDomain } from "../src/backends/circle/fri.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { FRI_N, TRACE_LEN } from "../src/backends/circle/params.ts";
import { encodeAirPacked, AIR_OFF_HASHBIT, AIR_OFF_NTABLE, SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import {
  BOOL_CHECK_INPUT,
  compileBooleanityDataKernel,
  compileBooleanityKernel,
  compileBooleanityLocks,
  occupancyBoolShardsFromNote,
  occupancyBoolUnlockings,
} from "../src/chain/booleanity-kernel.ts";
import { BOOL_KERNEL_COUNT } from "../src/chain/sha-bit-air.ts";
import { booleanityAlpha, parseFeltBytes, SHA_BIT_GROUP_COLS } from "../src/chain/sha-bit-air.ts";
import { UNLOCKING_MAX_BYTES } from "../src/chain/envelope.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import { evaluateBch2026, evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));

function mix() {
  const note: Note = { amountSats: 8_000n, rho: rnd32(), ownerSecret: rnd32() };
  const d = applyDeposit(
    { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
  const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
  return { note, d, proof, packed };
}

function evalBool(note: Note, statement: Parameters<typeof occupancyBoolUnlockings>[0]["statement"], packed: Uint8Array) {
  const carrier = Uint8Array.of(0x75, 0x51);
  const dummy = Uint8Array.of(0x51);
  const boolLocks = compileBooleanityLocks();
  const boolUnlocks = occupancyBoolUnlockings({ note, statement, packed });
  const n = BOOL_CHECK_INPUT + BOOL_KERNEL_COUNT;
  const sourceOutputs = Array.from({ length: n }, (_, i) => ({
    lockingBytecode:
      i === 0
        ? carrier
        : i >= BOOL_CHECK_INPUT
          ? boolLocks[i - BOOL_CHECK_INPUT]!
          : dummy,
    valueSatoshis: 1000n,
  }));
  const unlockFor = (i: number): Uint8Array => {
    if (i === 0) return pushData(packed);
    if (i >= BOOL_CHECK_INPUT) return boolUnlocks[i - BOOL_CHECK_INPUT]!;
    return new Uint8Array();
  };
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: Array.from({ length: n }, (_, i) => ({
      outpointTransactionHash: new Uint8Array(32).fill(i + 1),
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: unlockFor(i),
    })),
    outputs: [{ lockingBytecode: carrier, valueSatoshis: 1000n }],
  };
  const vm = createVirtualMachineBch2026(true);
  const full = vm.verify({ sourceOutputs, transaction } as never);
  const state = vm.evaluate({
    inputIndex: BOOL_CHECK_INPUT,
    sourceOutputs,
    transaction,
  } as never);
  const ok = vm.stateSuccess(state);
  const m = (state as { metrics?: Record<string, number | bigint> }).metrics ?? {};
  const num = (x: number | bigint | undefined) => (x === undefined ? 0 : typeof x === "bigint" ? Number(x) : x);
  return {
    accepted: ok === true,
    error: ok === true ? null : String(ok).slice(0, 240),
    txAccepted: full === true,
    unlocking: transaction.inputs[BOOL_CHECK_INPUT]!.unlockingBytecode.length,
    operationCost: num(m.operationCost),
    maximumOperationCost: num(m.maximumOperationCost),
  };
}

describe("on-chain occupancy booleanity kernel", () => {
  it("one-column boolCol matches JS", () => {
    const { note, d, packed } = mix();
    const hash = defaultInternalHash();
    const bitRoot = packed.subarray(AIR_OFF_HASHBIT, AIR_OFF_HASHBIT + 32);
    const alpha = booleanityAlpha(hash, bitRoot);
    const shards = occupancyBoolShardsFromNote({ note, statement: d.statement, packed });
    const felts = parseFeltBytes(shards[0]!.subarray(0, SHA_BIT_GROUP_COLS * 4));
    const bit = felts[0]!;
    const c = (bit * ((bit + 2147483647n - 1n) % 2147483647n)) % 2147483647n;
    const hexPush = (data: Uint8Array) => `<0x${Buffer.from(data).toString("hex")}>`;
    const felt4 = shards[0]!.subarray(0, 4);
    const defineBody = cashAssemblyToBin(`
<4> OP_SPLIT
OP_SWAP
<0x00> OP_CAT OP_BIN2NUM
OP_DUP
<1>
OP_SUB <2147483647> OP_ADD <2147483647> OP_MOD
OP_MUL <2147483647> OP_MOD
OP_3 OP_PICK
OP_MUL <2147483647> OP_MOD
OP_4 OP_PICK
OP_ADD <2147483647> OP_MOD
OP_3 OP_PICK
OP_3 OP_PICK
OP_MUL <2147483647> OP_MOD
OP_5 OP_ROLL
OP_DROP
OP_4 OP_ROLL
OP_DROP
OP_2SWAP
`);
    if (typeof defineBody === "string") throw new Error(defineBody);
    const lock = cashAssemblyToBin(`
${hexPush(defineBody)}
<1>
OP_DEFINE
<0>
<1>
<${alpha.toString()}>
${hexPush(felt4)}
<1> OP_INVOKE
OP_DROP
OP_DROP
OP_DROP
<${c.toString()}>
OP_NUMEQUAL
`);
    if (typeof lock === "string") throw new Error(lock);
    const ev = evaluateBch2026(lock, new Uint8Array());
    assert.equal(ev.accepted, true, ev.error ?? `boolCol acc=${c} bit=${bit} alpha=${alpha}`);
  });

  it("redeem and unlocking stay under 10 KB", () => {
    const redeem = compileBooleanityKernel();
    const data = compileBooleanityDataKernel();
    assert.ok(redeem.length <= UNLOCKING_MAX_BYTES, `booleanity redeem ${redeem.length}`);
    assert.ok(data.length <= UNLOCKING_MAX_BYTES, `booleanity data redeem ${data.length}`);
    console.log(`booleanity redeem ${redeem.length} data ${data.length}`);
  });

  it("honest T vs packed booleanity C accepts under density", { timeout: 60_000 }, () => {
    const { note, d, packed } = mix();
    const ev = evalBool(note, d.statement, packed);
    assert.equal(ev.accepted, true, ev.error ?? "honest booleanity");
    assert.equal(ev.txAccepted, true, "both booleanity inputs must accept");
    assert.ok(ev.unlocking <= UNLOCKING_MAX_BYTES, String(ev.unlocking));
    assert.ok(ev.operationCost <= ev.maximumOperationCost, `${ev.operationCost}/${ev.maximumOperationCost}`);
    console.log(`booleanity cost ${ev.operationCost}/${ev.maximumOperationCost} unlock ${ev.unlocking}`);
  });

  it("honest T vs zero nTable rejects", { timeout: 60_000 }, () => {
    const { note, d, packed } = mix();
    const zeroed = new Uint8Array(packed);
    zeroed.fill(0, AIR_OFF_NTABLE, AIR_OFF_NTABLE + 36 * 4);
    const ev = evalBool(note, d.statement, zeroed);
    assert.equal(ev.accepted, false, "nTable=0 must fail booleanity of honest T");
  });

  it("occupancy-only leftover + honest T is consensus VM-reject", { timeout: 180_000 }, () => {
    const note: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const wit = wDeposit(note, d.index, d.path);
    const honest = proveFri(d.statement, wit);
    const { qLde } = algebraicCQuotientLde(
      d.statement,
      circleDomain(TRACE_LEN),
      circleDomain(FRI_N),
      defaultInternalHash(),
    );
    const occ = proveFromTLde(d.statement, qLde, honest.auth, {
      hashRoot: honest.hashRoot,
      hashLeaves: honest.hashLeaves,
      hashBitRoot: honest.hashBitRoot,
    });
    const vm = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: encodeFriProof(occ),
      statement: d.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note,
    });
    assert.equal(vm.accepted, false, "occupancy-only must VM-reject");
  });
});
