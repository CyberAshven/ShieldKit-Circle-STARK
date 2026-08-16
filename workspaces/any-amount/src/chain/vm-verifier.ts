/**
 * BCH 2026 VM verifier for Circle FRI paired Merkle openings.
 * Standard P2S lock is 201 bytes — this kernel is a P2SH32 redeem
 * (OP_SHA256 + OP_BEGIN/OP_UNTIL). A digest / OP_RETURN is not Verify.
 */
import { createTestAuthenticationProgramBch, createVirtualMachineBch2026 } from "@bitauth/libauth";
import { add, encodeLe, mul } from "../backends/circle/m31.ts";
import { decodeFriProof, verifyFri, type FriProof } from "../backends/circle/fri.ts";
import { FRI_N, FRI_QUERIES } from "../backends/circle/params.ts";
import {
  compileFriQueryKernel,
  compileFriQueryLockP2sh32,
  FRI_KERNEL_INPUTS,
  FRI_QUERY_KERNEL,
} from "./fri-kernel.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  cqzKernelUnlocking,
  SLOT_KERNEL_COUNT,
  SLOTS_PER_KERNEL,
  slotsKernelUnlocking,
} from "./air-cqz.ts";
import { encodeSteps, parentIndexOf } from "./vm-steps.ts";
import {
  collectFriOpenings,
  dummyFriOpenings,
  dummyFriOpeningsWide,
  dummyFriShardUnlockings,
  dummyFriShardUnlockingsNoL0,
  dummyFriShardUnlockingsUnbound,
  encodeLayerRootsPrefix,
  friShardUnlockings,
  proofShardReport,
} from "./fri-openings.ts";
import {
  AIR_OFF_EVEN,
  AIR_OFF_IDX,
  AIR_OFF_NTABLE,
  AIR_OFF_QTABLE,
  AIR_PACKED_SIZE,
  encodeAirPacked,
  fiatShamirQueryIndices,
  nqzAt,
} from "./air-cqz.ts";
import { sha256 } from "../pool/bytes.ts";
import { encodeStatement } from "../pool/statement.ts";
import { COMMITTED_LAYERS } from "../backends/circle/params.ts";
import {
  compilePoolCovenant,
  FIVE_POINT_PAA1,
  p2sh32Unlocking,
  poolLockP2sh32,
  pushData,
  walkWitnessFromAuth,
} from "./covenant-p2s.ts";
import { encodePublicPaa1, STATE_BASE_SATS, type AnyAmountState } from "../pool/state.ts";
import type { PoolStatement } from "../pool/statement.ts";

export { compileFriQueryKernel, compileFriQueryLockP2sh32, FRI_QUERY_KERNEL };

export function poolLockRedeem(): Uint8Array {
  return compilePoolCovenant();
}



function concat(parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function push(data: Uint8Array): Uint8Array {
  return pushData(data);
}

export { encodeSteps, parentIndexOf };

export function encodeFriQueryUnlocking(args: {
  left: Uint8Array;
  right: Uint8Array;
  root: Uint8Array;
  parentPath: Uint8Array[];
  parentIndex: number;
  layerIndex?: number;
}): Uint8Array {
  const steps = encodeSteps(args.parentIndex, args.parentPath);
  const layer = args.layerIndex ?? 0;
  const layerPush = layer === 0 ? Uint8Array.of(0x00) : Uint8Array.of(0x50 + layer);
  return concat([
    push(args.left),
    push(args.right),
    push(steps),
    layerPush,
    Uint8Array.of(0x51),
    push(compileFriQueryKernel()),
  ]);
}

export type VmEval = {
  accepted: boolean;
  error: string | null;
  unlockingBytes: number;
  lockingBytes: number;
};

export function evaluateBch2026(locking: Uint8Array, unlocking: Uint8Array): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const program = createTestAuthenticationProgramBch({
    lockingBytecode: locking,
    unlockingBytecode: unlocking,
    valueSatoshis: 1000n,
  });
  const state = vm.evaluate(program);
  const ok = vm.stateSuccess(state);
  return {
    accepted: ok === true,
    error: ok === true ? null : String(ok),
    unlockingBytes: unlocking.length,
    lockingBytes: locking.length,
  };
}

/** Roots + qTable so an isolated kernel can membership-check layer-0 leaves. */
function packedForOpening(p: FriProof, layerRoots?: Uint8Array[]): Uint8Array {
  const packed = new Uint8Array(AIR_PACKED_SIZE);
  const roots = layerRoots ?? p.layerRoots;
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) {
    packed.set(roots[r] ?? new Uint8Array(32), r * 32);
  }
  for (let s = 0; s < p.queries.length && s < FRI_QUERIES; s += 1) {
    packed.set(encodeLe(p.queries[s]!.layers[0]!.value), AIR_OFF_QTABLE + s * 4);
  }
  return packed;
}

export function evaluateFriQueryOpening(args: {
  left: Uint8Array;
  right: Uint8Array;
  root: Uint8Array;
  parentPath: Uint8Array[];
  parentIndex: number;
  layerIndex?: number;
  packed?: Uint8Array;
}): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const layer = args.layerIndex ?? 0;
  const roots = Array.from({ length: 7 }, (_, i) => (i === layer ? args.root : new Uint8Array(32)));
  const carrierUnlock = args.packed ? pushData(args.packed) : encodeLayerRootsPrefix(roots);
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const sourceOutputs = [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
    { lockingBytecode: compileFriQueryLockP2sh32(), valueSatoshis: 1000n },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x22),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: carrierUnlock,
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x44),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: encodeFriQueryUnlocking(args),
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: encodeFriQueryUnlocking(args).length,
    lockingBytes: compileFriQueryLockP2sh32().length,
  };
}

export function evaluateDigestOnly(): VmEval {
  const digest = new Uint8Array(40);
  digest.set(new TextEncoder().encode("PAA1PROF"));
  const unlocking = concat([push(digest), push(compileFriQueryKernel())]);
  return evaluateBch2026(compileFriQueryLockP2sh32(), unlocking);
}

export function evaluateMissingProof(): VmEval {
  return evaluateBch2026(compileFriQueryLockP2sh32(), push(compileFriQueryKernel()));
}

export function firstFriQueryUnlocking(proof: Uint8Array | FriProof): Uint8Array {
  return friShardUnlockings(proof)[0]!;
}

/** Full pool successor: five-point + FRI-kernel input, no OP_RETURN digest. */
export function evaluatePoolSuccessorVm(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  category?: Uint8Array;
  kernelUnlockings?: Uint8Array[];
  statement?: PoolStatement;
  airPacked?: Uint8Array;
  outputValueSats?: bigint;
}): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const poolLock = poolLockP2sh32();
  const friLock = compileFriQueryLockP2sh32();
  const category = args.category ?? new Uint8Array(32).fill(0x11);
  const poolValue = STATE_BASE_SATS;
  const newValue = args.outputValueSats ?? STATE_BASE_SATS;
  const shards = args.kernelUnlockings ?? friShardUnlockings(args.proof);
  const cqzLock = compileCqzLockP2sh32();
  const cqzUnlock = cqzKernelUnlocking();
  const slotsLock = compileSlotsLockP2sh32();
  const slotUnlocks = Array.from({ length: SLOT_KERNEL_COUNT }, (_, i) =>
    slotsKernelUnlocking(i * SLOTS_PER_KERNEL),
  );
  const sourceOutputs = [
    {
      lockingBytecode: poolLock,
      valueSatoshis: poolValue,
      token: {
        amount: 0n,
        category,
        nft: { capability: "mutable" as const, commitment: encodePublicPaa1(args.oldState) },
      },
    },
    ...shards.map(() => ({ lockingBytecode: friLock, valueSatoshis: 1000n })),
    { lockingBytecode: cqzLock, valueSatoshis: 1000n },
    ...slotUnlocks.map(() => ({ lockingBytecode: slotsLock, valueSatoshis: 1000n })),
  ];
  const decoded = decodeFriProof(args.proof);
  const prefix = args.airPacked
    ?? (args.statement ? encodeAirPacked(args.statement, decoded) : decoded.layerRoots);
  const poolUnlock = p2sh32Unlocking(
    walkWitnessFromAuth(decoded.auth, args.oldState.noteRoot, args.newState.noteRoot),
    prefix,
  );
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x11),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: poolUnlock,
      },
      ...shards.map((unlocking, i) => ({
        outpointTransactionHash: new Uint8Array(32).fill(0x44 + i),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      })),
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x88),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: cqzUnlock,
      },
      ...slotUnlocks.map((unlocking, i) => ({
        outpointTransactionHash: new Uint8Array(32).fill(0x89 + i),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      })),
    ],
    outputs: [
      {
        lockingBytecode: poolLock,
        valueSatoshis: newValue,
        token: {
          amount: 0n,
          category,
          nft: { capability: "mutable" as const, commitment: encodePublicPaa1(args.newState) },
        },
      },
    ],
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: transaction.inputs[0]!.unlockingBytecode.length,
    lockingBytes: poolLock.length,
  };
}

export function evaluateDigestOnlyPool(oldState: AnyAmountState): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const poolLock = poolLockP2sh32();
  const digest = new Uint8Array(40);
  digest.set(new TextEncoder().encode("PAA1PROF"));
  const sourceOutputs = [
    {
      lockingBytecode: poolLock,
      valueSatoshis: STATE_BASE_SATS,
      token: {
        amount: 0n,
        category: new Uint8Array(32).fill(0x11),
        nft: { capability: "mutable" as const, commitment: encodePublicPaa1(oldState) },
      },
    },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x11),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: concat([push(digest), p2sh32Unlocking()]),
      },
    ],
    outputs: [
      {
        lockingBytecode: poolLock,
        valueSatoshis: STATE_BASE_SATS,
        token: {
          amount: 0n,
          category: new Uint8Array(32).fill(0x11),
          nft: { capability: "mutable" as const, commitment: encodePublicPaa1(oldState) },
        },
      },
    ],
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: transaction.inputs[0]!.unlockingBytecode.length,
    lockingBytes: poolLock.length,
  };
}

export function evaluateMissingProofPool(oldState: AnyAmountState): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const poolLock = poolLockP2sh32();
  const sourceOutputs = [
    {
      lockingBytecode: poolLock,
      valueSatoshis: STATE_BASE_SATS,
      token: {
        amount: 0n,
        category: new Uint8Array(32).fill(0x11),
        nft: { capability: "mutable" as const, commitment: encodePublicPaa1(oldState) },
      },
    },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x11),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: p2sh32Unlocking(),
      },
    ],
    outputs: sourceOutputs,
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: p2sh32Unlocking().length,
    lockingBytes: poolLock.length,
  };
}

/** Executed 2026 lock only. JS verifyFri is logged separately, not AND-ed. */
export function evaluateOnChainVerify(
  statement: PoolStatement,
  proof: Uint8Array,
): { accepted: boolean; pool: VmEval; stark: ReturnType<typeof verifyFri> } {
  const pool = evaluatePoolSuccessorVm({
    oldState: statement.oldState,
    newState: statement.newState,
    proof,
    statement,
  });
  const stark = verifyFri(statement, decodeFriProof(proof));
  return { accepted: pool.accepted, pool, stark };
}

export function evaluateProofOnVm(proof: FriProof | Uint8Array): {
  accepted: boolean;
  failed: string | null;
  queryEvals: number;
  unlockingMax: number;
} {
  const p = proof instanceof Uint8Array ? decodeFriProof(proof) : proof;
  const packed = packedForOpening(p);
  const shards = friShardUnlockings(p);
  let unlockingMax = 0;
  for (let s = 0; s < shards.length; s += 1) {
    const ev = evaluateFriShard(packed, shards[s]!);
    unlockingMax = Math.max(unlockingMax, ev.unlockingBytes);
    if (!ev.accepted) {
      return {
        accepted: false,
        failed: ev.error ?? `shard ${s}`,
        queryEvals: collectFriOpenings(p).length,
        unlockingMax,
      };
    }
  }
  return { accepted: true, failed: null, queryEvals: collectFriOpenings(p).length, unlockingMax };
}

function evaluateFriShard(packed: Uint8Array, unlocking: Uint8Array): VmEval {
  const vm = createVirtualMachineBch2026(true);
  const carrierUnlock = pushData(packed);
  const carrierLock = Uint8Array.of(0x75, 0x51);
  const sourceOutputs = [
    { lockingBytecode: carrierLock, valueSatoshis: 1000n },
    { lockingBytecode: compileFriQueryLockP2sh32(), valueSatoshis: 1000n },
  ];
  const transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x22),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: carrierUnlock,
      },
      {
        outpointTransactionHash: new Uint8Array(32).fill(0x44),
        outpointIndex: 0,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      },
    ],
    outputs: [{ lockingBytecode: carrierLock, valueSatoshis: 1000n }],
  };
  const result = vm.verify({ sourceOutputs, transaction });
  return {
    accepted: result === true,
    error: result === true ? null : String(result),
    unlockingBytes: unlocking.length,
    lockingBytes: compileFriQueryLockP2sh32().length,
  };
}

export function evaluateFalseRoot(proof: FriProof | Uint8Array): VmEval {
  const p = proof instanceof Uint8Array ? decodeFriProof(proof) : proof;
  const q = p.queries[0]!;
  const layer = q.layers[0]!;
  const n = FRI_N;
  const i = q.index % n;
  const lo = i < n / 2;
  const bad = new Uint8Array(p.layerRoots[0]!);
  bad[0] ^= 1;
  const packed = packedForOpening(p);
  packed.set(bad, 0);
  return evaluateFriQueryOpening({
    left: encodeLe(lo ? layer.value : layer.partner),
    right: encodeLe(lo ? layer.partner : layer.value),
    root: bad,
    parentPath: layer.path,
    parentIndex: parentIndexOf(i, n),
    layerIndex: 0,
    packed,
  });
}

/** Honest PAA1 walk + dummy 8-leaf kernel openings against this statement's roots. */
export function evaluateDummyKernels(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement?: PoolStatement;
}): VmEval {
  return evaluatePoolSuccessorVm({
    ...args,
    kernelUnlockings: dummyFriShardUnlockings(),
  });
}

/** Honest Merkle kernels; qTable[0] and nTable[0] cooked so q'·Z = n' (old C=QZ would pass). */
export function evaluateCookedNTable(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const cooked = new Uint8Array(honest);
  const i = (cooked[AIR_OFF_IDX]! << 8) | cooked[AIR_OFF_IDX + 1]!;
  const { z, q } = nqzAt(args.statement, i);
  const q2 = add(q, 1n);
  cooked.set(encodeLe(q2), AIR_OFF_QTABLE);
  cooked.set(encodeLe(mul(q2, z)), AIR_OFF_NTABLE);
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: cooked,
    statement: args.statement,
  });
}

/** Honest kernels; Newton even[0] flipped so T is not the public interpolant. */
export function evaluateCookedT(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const cooked = new Uint8Array(honest);
  cooked[AIR_OFF_EVEN] ^= 1;
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: cooked,
    statement: args.statement,
  });
}

/** Honest slot 0; a later off-trace slot has q'·Z cooked into nTable. */
export function evaluateCookedLaterSlot(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const cooked = new Uint8Array(encodeAirPacked(args.statement, args.proof));
  for (let s = 1; s < FRI_QUERIES; s += 1) {
    const i = (cooked[AIR_OFF_IDX + s * 2]! << 8) | cooked[AIR_OFF_IDX + s * 2 + 1]!;
    const { z, q } = nqzAt(args.statement, i);
    if (z === 0n) continue;
    const q2 = add(q, 1n);
    cooked.set(encodeLe(q2), AIR_OFF_QTABLE + s * 4);
    cooked.set(encodeLe(mul(q2, z)), AIR_OFF_NTABLE + s * 4);
    break;
  }
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: cooked,
    statement: args.statement,
  });
}

/**
 * 8-leaf dummy openings (short Merkle path) with qTable planted so membership
 * would pass. Must fail the FRI_N path-depth gate (issue #2: synthetic tree).
 */
export function evaluateDummyShortPath(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const dummy = dummyFriOpenings(8);
  const packed = new Uint8Array(honest);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) packed.set(dummy[0]!.root, r * 32);
  for (let s = 0; s < FRI_QUERIES; s += 1) {
    packed.set(dummy[s % dummy.length]!.left, AIR_OFF_QTABLE + s * 4);
  }
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: packed,
    kernelUnlockings: dummyFriShardUnlockings(),
  });
}

/**
 * Honest openings of proof A against packed AIR of a different statement.
 * Independent fixtures must not assemble into one accept (issue #2).
 */
export function evaluateCrossPacked(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
  otherPacked: Uint8Array;
}): VmEval {
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: args.otherPacked,
  });
}

/**
 * Dummy 8-leaf openings with only layerIndex 17–22 (no actual layer 0),
 * dummy roots, honest T, qTable[0]=nTable[0]=N/Z at FS(dummy roots).
 */
export function evaluateDummyNoL0(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const dummy = dummyFriOpenings(8);
  const packed = new Uint8Array(honest);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) packed.set(dummy[0]!.root, r * 32);
  const decoded = decodeFriProof(args.proof);
  const dummyRoots = Array.from({ length: COMMITTED_LAYERS }, () => dummy[0]!.root);
  const i0 = fiatShamirQueryIndices(sha256(encodeStatement(args.statement)), {
    ...decoded,
    layerRoots: dummyRoots,
  })[0]!;
  const slot = nqzAt(args.statement, i0);
  packed.set(encodeLe(slot.q), AIR_OFF_QTABLE);
  packed.set(encodeLe(slot.n), AIR_OFF_NTABLE);
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: packed,
    kernelUnlockings: dummyFriShardUnlockingsNoL0(),
  });
}

/**
 * Dummy 8-leaf openings with layerIndex 16+k, dummy roots, honest T,
 * qTable[0]=nTable[0]=N/Z at FS(dummy roots). A kernel that skips the Q bind
 * on 16+ would accept this.
 */
export function evaluateDummyUnbound(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const dummy = dummyFriOpenings(8);
  const packed = new Uint8Array(honest);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) packed.set(dummy[0]!.root, r * 32);
  const decoded = decodeFriProof(args.proof);
  const dummyRoots = Array.from({ length: COMMITTED_LAYERS }, () => dummy[0]!.root);
  const i0 = fiatShamirQueryIndices(sha256(encodeStatement(args.statement)), {
    ...decoded,
    layerRoots: dummyRoots,
  })[0]!;
  const slot = nqzAt(args.statement, i0);
  packed.set(encodeLe(slot.q), AIR_OFF_QTABLE);
  packed.set(encodeLe(slot.n), AIR_OFF_NTABLE);
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: packed,
    kernelUnlockings: dummyFriShardUnlockingsUnbound(),
  });
}

/**
 * Dummy 8-leaf openings + dummy layerRoots, honest T / qTable = N/Z.
 * Skeptic dummy-consistent spend: Merkle walks the dummy tree; C=QZ sees honest Q.
 */
export function evaluateDummyConsistent(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const honest = encodeAirPacked(args.statement, args.proof);
  const dummy = dummyFriOpenings(8);
  const packed = new Uint8Array(honest);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) packed.set(dummy[0]!.root, r * 32);
  return evaluatePoolSuccessorVm({
    ...args,
    airPacked: packed,
    kernelUnlockings: dummyFriShardUnlockings(),
  });
}

/** Dummy 8-leaf kernels AND dummy layerRoots/qTable in the pool unlocking. */
export function evaluateSwappedDummyKernels(args: {
  oldState: AnyAmountState;
  newState: AnyAmountState;
  proof: Uint8Array;
  statement: PoolStatement;
}): VmEval {
  const dummy = dummyFriOpenings(8);
  const honest = encodeAirPacked(args.statement, args.proof);
  const swapped = new Uint8Array(honest);
  for (let r = 0; r < 7; r += 1) swapped.set(dummy[0]!.root, r * 32);
  for (let s = 0; s < FRI_QUERIES && AIR_OFF_QTABLE + (s + 1) * 4 <= swapped.length; s += 1) {
    swapped.set(dummy[s % dummy.length]!.left, AIR_OFF_QTABLE + s * 4);
  }
  swapped.set(encodeLe(1n), AIR_OFF_NTABLE);
  return evaluatePoolSuccessorVm({
    ...args,
    kernelUnlockings: dummyFriShardUnlockings(),
    airPacked: swapped,
    statement: args.statement,
  });
}

export function proofFitsEnvelope(proof: Uint8Array): {
  proofBytes: number;
  shards: number;
  unlockingLimit: number;
  txLimit: number;
  shardsFit10k: boolean;
  txFit100k: boolean;
  unlockingMax: number;
  openings: number;
} {
  const report = proofShardReport(proof);
  return {
    proofBytes: proof.length,
    shards: report.shards,
    unlockingLimit: 10_000,
    txLimit: 100_000,
    shardsFit10k: report.shardsFit10k,
    txFit100k: report.txFit100k,
    unlockingMax: report.unlockingMax,
    openings: report.openings,
  };
}

export { FIVE_POINT_PAA1, FRI_QUERIES };
