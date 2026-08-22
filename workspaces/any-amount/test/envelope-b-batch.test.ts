/**
 * Envelope B batching: N notes walked on chain in ONE consensus transaction.
 *
 * Until now B could walk exactly one note, because the audited kernel reads both
 * nullifier roots at absolute index 0 and a transaction has one such pair. The
 * step kernel bakes the roots in instead, so N of them coexist — and the covenant
 * pins each one by index, which is what stops a prover from simply omitting them.
 * That pinning is the difference between "the kernels can be there" and "the
 * kernels must be there"; plain option A taught that lesson the hard way.
 *
 * These run the real 2026 VM over a whole transaction built by
 * `compileCovenantSuccessor`, not a hand-assembled one.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createVirtualMachineBch2026, decodeTransaction } from "@bitauth/libauth";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { poolLockP2sh32 } from "../src/chain/covenant-p2s.ts";
import { runBatchSuccessor } from "../src/pool/mix-successor.ts";
import { stepRoots, compileNoteAuthStepLockP2sh32 } from "../src/chain/note-auth-step-kernel.ts";
import { compileNoteAuthLockP2sh32 } from "../src/chain/note-auth-kernel.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { compileFriQueryLockP2sh32 } from "../src/chain/fri-kernel.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  SLOT_KERNEL_COUNT_CONSENSUS,
} from "../src/chain/air-cqz.ts";
import { compileFoldLockP2sh32, foldKernelCount } from "../src/chain/fold-kernel.ts";
import { compileGrindLockP2sh32 } from "../src/chain/grind-kernel.ts";
import { compileAlgebraicCLockP2sh32 } from "../src/chain/algebraic-c-kernel.ts";
import { nullifierOf } from "../src/pool/notes.ts";
import { createLabWallet, p2pkhLockingOf } from "../src/chain/wallet.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";

/**
 * Envelope B is consensus-valid and NON-standard by design (~500 KB), so it must
 * be verified with standard=false. Verifying it in standard mode would reject it
 * on size alone - which would also make every negative test below pass for the
 * wrong reason. vm-verifier.ts:257 uses the same rule: standard iff slots <= 4.
 */
const consensusVm = () => createVirtualMachineBch2026(false);

/** true only when the VM accepted; otherwise the reason, for asserting on it. */
function verdict(transaction: unknown, sourceOutputs: unknown): true | string {
  const r = consensusVm().verify({ transaction, sourceOutputs } as never);
  if (r === true) return true;
  const msg = String(r);
  if (/maximum standard byte length/.test(msg)) {
    throw new Error(`verified in the wrong mode - B is non-standard: ${msg}`);
  }
  return msg;
}

const CAT = new Uint8Array(32).fill(0x33);
const POOL = "33".repeat(32);
const KERNEL = "cc".repeat(32);
const FEE = "ee".repeat(32);
// createLabWallet() makes a RANDOM key per call, so the funder input must be
// signed by and paid back to the SAME wallet object, or the P2PKH check fails.
const WALLET = createLabWallet();
const KERNEL_SATS = 1000n;
const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;
const FOLDS = foldKernelCount(SLOTS);

function buildB(noteCount: number) {
  const b = runBatchSuccessor({ depositCount: Math.max(6, noteCount), noteCount });
  const hash = defaultInternalHash();
  const nfs = b.spends.map((s) => nullifierOf(s.note, b.oldState.poolInstanceId, hash));
  const roots = stepRoots(b.oldState.nullifierRoot, nfs);
  const stepSpends = b.spends.map((s, i) => ({
    note: s.note,
    index: s.index,
    path: s.path,
    rIn: roots[i]!,
    rOut: roots[i + 1]!,
  }));
  const stepLocks = stepSpends.map((s) => compileNoteAuthStepLockP2sh32(s.rIn, s.rOut));
  const finalNfRoot = roots[noteCount]!;
  const nExtras = 3 + FOLDS + SLOTS + noteCount;
  const tx = compileCovenantSuccessor({
    pool: {
      tx_hash: POOL,
      tx_pos: 0,
      value: utxoValueFor(b.oldState),
      category: CAT,
      commitment: encodePublicPaa1(b.oldState),
    },
    newState: b.newState,
    statement: b.statement,
    proof: b.proof,
    lockKind: "p2sh32",
    envelope: "consensus",
    slotKernels: SLOTS,
    stepSpends,
    finalNfRoot,
    // BIND_PAA1 checks withdrawalCount delta == outputCount - 2, so a batch of N
    // needs N payout outputs plus a change output - hence the fee utxo.
    extraPayouts: b.payouts.map((p) => ({ lockingBytecode: p.lockingBytecode, sats: p.sats })),
    wallet: WALLET,
    feeUtxo: { tx_hash: FEE, tx_pos: 0, value: 1_000_000 },
    kernelUtxos: Array.from({ length: 10 }, (_, i) => ({ tx_hash: KERNEL, tx_pos: i, value: 1000 })),
    extraKernels: Array.from({ length: nExtras }, (_, i) => ({
      tx_hash: KERNEL,
      tx_pos: 10 + i,
      value: 1000,
    })),
  });
  return { b, roots, stepSpends, stepLocks, finalNfRoot, tx, noteCount };
}

function sourceOutputsFor(built: ReturnType<typeof buildB>, stepLocks: Uint8Array[]) {
  return [
    {
      lockingBytecode: poolLockP2sh32({
        slotKernels: SLOTS,
        finalNfRoot: built.finalNfRoot,
        stepLocks,
      }),
      valueSatoshis: BigInt(utxoValueFor(built.b.oldState)),
      token: {
        amount: 0n,
        category: CAT,
        nft: {
          capability: "mutable" as const,
          commitment: encodePublicPaa1(built.b.oldState),
        },
      },
    },
    ...Array.from({ length: 10 }, () => ({
      lockingBytecode: compileFriQueryLockP2sh32(),
      valueSatoshis: KERNEL_SATS,
    })),
    { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileGrindLockP2sh32(), valueSatoshis: KERNEL_SATS },
    { lockingBytecode: compileAlgebraicCLockP2sh32(), valueSatoshis: KERNEL_SATS },
    ...Array.from({ length: FOLDS }, (_, f) => ({
      lockingBytecode: compileFoldLockP2sh32(1, f),
      valueSatoshis: KERNEL_SATS,
    })),
    ...Array.from({ length: SLOTS }, (_, i) => ({
      lockingBytecode: compileSlotsLockP2sh32(i),
      valueSatoshis: KERNEL_SATS,
    })),
    ...stepLocks.map((l) => ({ lockingBytecode: l, valueSatoshis: KERNEL_SATS })),
    // the funder input that pays the fee and receives the change output
    {
      lockingBytecode: p2pkhLockingOf(WALLET),
      valueSatoshis: 1_000_000n,
    },
  ];
}

describe("envelope B: N notes walked on chain in one consensus transaction", () => {
  it("the step roots close on the batch's new nullifier root", () => {
    const built = buildB(3);
    assert.deepEqual(
      built.roots[3],
      built.b.newState.nullifierRoot,
      "R_3 must be the state's new root",
    );
  });

  it("a 3-note batch verifies on the 2026 VM", () => {
    const built = buildB(3);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    const sourceOutputs = sourceOutputsFor(built, built.stepLocks);
    assert.equal(tx.inputs.length, sourceOutputs.length, "input count must line up");
    assert.equal(verdict(tx, sourceOutputs), true, "the batched consensus transaction must verify");
  });

  it("the covenant REQUIRES the step kernels — dropping one is rejected", () => {
    const built = buildB(3);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    // Same transaction, but the pool is locked to a covenant that pins only two
    // steps. The input count check and the per-index pins must both object.
    const short = sourceOutputsFor(built, built.stepLocks.slice(0, 2));
    assert.notEqual(
      verdict(tx, short),
      true,
      "a covenant pinning fewer steps must not accept this transaction",
    );
  });

  it("swapping two step locks is rejected — order is pinned by index", () => {
    const built = buildB(3);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    const swapped = [built.stepLocks[1]!, built.stepLocks[0]!, built.stepLocks[2]!];
    assert.notEqual(
      verdict(tx, sourceOutputsFor(built, swapped)),
      true,
      "the covenant pins each step at its own index",
    );
  });

  it("a batched B drops the audited single-note kernel", () => {
    const built = buildB(3);
    const withSteps = poolLockP2sh32({
      slotKernels: SLOTS,
      finalNfRoot: built.finalNfRoot,
      stepLocks: built.stepLocks,
    });
    const plain = poolLockP2sh32({ slotKernels: SLOTS });
    assert.notDeepEqual(withSteps, plain, "a batched covenant must differ from FRI9's");
    // and the transaction must not be carrying the audited lock anywhere
    const noteLock = Buffer.from(compileNoteAuthLockP2sh32()).toString("hex");
    const outs = sourceOutputsFor(built, built.stepLocks);
    assert.equal(
      outs.some((o) => Buffer.from(o.lockingBytecode).toString("hex") === noteLock),
      false,
      "the audited kernel must be absent from a batched B",
    );
  });

  it("eight notes also fit and verify, well inside the 1 MB envelope", () => {
    const built = buildB(8);
    const tx = decodeTransaction(built.tx.raw);
    if (typeof tx === "string") throw new Error(tx);
    assert.equal(
      verdict(tx, sourceOutputsFor(built, built.stepLocks)),
      true,
      "8 notes in one consensus transaction must verify",
    );
    // Non-standard on purpose: over 100 KB, under the 1 MB consensus ceiling.
    assert.ok(built.tx.txBytes > 100_000, `B is non-standard by design (${built.tx.txBytes})`);
    assert.ok(built.tx.txBytes < 1_000_000, `B stays under 1 MB (${built.tx.txBytes})`);
  });

  it("FRI9's unbatched covenant is untouched", () => {
    // No stepLocks, no finalNfRoot: must be exactly the lock that is landed today.
    assert.deepEqual(
      poolLockP2sh32({ slotKernels: SLOTS }),
      poolLockP2sh32({ slotKernels: SLOTS, stepLocks: [] }),
      "an empty step list must change nothing",
    );
  });
});
