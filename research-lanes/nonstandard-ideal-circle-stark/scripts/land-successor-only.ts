import { writeFileSync } from "node:fs";
import {
  binToHex,
  createVirtualMachineBch2026,
  decodeTransaction,
  hexToBin,
} from "@bitauth/libauth";
import { encodeFriProof, proveFri, verifyFri } from "../src/backends/circle/fri.ts";
import { wDeposit } from "../src/backends/circle/air.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { loadLabWallet, p2pkhLockingOf } from "../src/chain/wallet.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  SLOTS_PER_KERNEL,
} from "../src/chain/air-cqz.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import {
  compileFoldLockP2sh32,
  foldKernelCount,
  foldQueriesPerKernel,
  slotInputsCount,
} from "../src/chain/fold-kernel.ts";
import { compileNoteAuthLockP2sh32, prefixExtraKernelCount } from "../src/chain/note-auth-kernel.ts";
import { compileGrindLockP2sh32 } from "../src/chain/grind-kernel.ts";
import { compileAlgebraicCLockP2sh32 } from "../src/chain/algebraic-c-kernel.ts";
import { poolLockP2sh32 } from "../src/chain/covenant-p2s.ts";

const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;
const GENESIS = process.argv[2]!;
const INSTANCE = process.argv[3]!;
const CATEGORY = process.argv[4]!;
const KERNELS = process.argv[5]!;
const FEE_TX = process.argv[6]!;
const FEE_POS = Number(process.argv[7]);
const FEE_VAL = Number(process.argv[8]);
const OUT = process.argv[9] ?? "/tmp/grok-goal-d2ca769fa6a6/implementer/land-successor.hex";

if (!GENESIS || !INSTANCE || !CATEGORY || !KERNELS || !FEE_TX || !Number.isInteger(FEE_POS) || !FEE_VAL) {
  throw new Error("usage: land-successor-only <genesis> <instance> <category> <kernels> <feeTx> <feePos> <feeValue> [out]");
}

const extraCount = prefixExtraKernelCount(SLOTS) + foldKernelCount(SLOTS) + slotInputsCount(SLOTS);
const fri = [
  { tx_hash: KERNELS, tx_pos: 0, value: 121546 },
  ...Array.from({ length: FRI_KERNEL_INPUTS - 1 }, (_, i) => ({
    tx_hash: KERNELS,
    tx_pos: i + 1,
    value: 1000,
  })),
];
const extra = Array.from({ length: extraCount }, (_, i) => ({
  tx_hash: KERNELS,
  tx_pos: FRI_KERNEL_INPUTS + i,
  value: 1000,
}));

const wallet = await loadLabWallet();
const genesisState = emptyState(hexToBin(INSTANCE));
const note: Note = {
  amountSats: 10_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: genesisState, notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const proved = proveFri(d.statement, wDeposit(note, d.index, d.path));
const proof = encodeFriProof(proved);
const friOk = verifyFri(d.statement, proved, wDeposit(note, d.index, d.path));
if (!friOk.ok) throw new Error("verifyFri");
const vm = evaluatePoolSuccessorVm({
  oldState: genesisState,
  newState: d.machine.state,
  proof,
  statement: d.statement,
  slotKernels: SLOTS,
  standard: false,
  note,
});
if (!vm.accepted) throw new Error(`vm ${vm.error}`);
const depositTx = compileCovenantSuccessor({
  wallet,
  feeUtxo: { tx_hash: FEE_TX, tx_pos: FEE_POS, value: FEE_VAL },
  pool: {
    tx_hash: GENESIS,
    tx_pos: 0,
    value: utxoValueFor(genesisState),
    category: hexToBin(CATEGORY),
    commitment: encodePublicPaa1(genesisState),
  },
  newState: d.machine.state,
  proof,
  statement: d.statement,
  lockKind: "p2sh32",
  envelope: "consensus",
  slotKernels: SLOTS,
  kernelUtxos: fri,
  extraKernels: extra,
  note,
});

const decoded = decodeTransaction(depositTx.raw);
if (typeof decoded === "string") throw new Error(decoded);
const foldN = foldKernelCount(SLOTS);
const foldQ = foldQueriesPerKernel(SLOTS);
const slotN = slotInputsCount(SLOTS);
const kernelLocks = [
  ...Array.from({ length: FRI_KERNEL_INPUTS }, (_, i) => compileFriQueryLockP2sh32(i)),
  compileCqzLockP2sh32(),
  compileGrindLockP2sh32(),
  compileAlgebraicCLockP2sh32(),
  compileNoteAuthLockP2sh32(),
  ...Array.from({ length: foldN }, (_, f) => compileFoldLockP2sh32(foldQ, f * foldQ)),
  ...Array.from({ length: slotN }, (_, i) =>
    compileSlotsLockP2sh32(
      i * (SLOTS > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1),
      SLOTS > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1,
    ),
  ),
];
const poolLock = poolLockP2sh32({ slotKernels: SLOTS });
const sourceOutputs = [
  {
    lockingBytecode: poolLock,
    valueSatoshis: utxoValueFor(genesisState),
    token: {
      amount: 0n,
      category: hexToBin(CATEGORY),
      nft: { capability: "mutable" as const, commitment: encodePublicPaa1(genesisState) },
    },
  },
  ...kernelLocks.map((lockingBytecode, i) => ({
    lockingBytecode,
    valueSatoshis: BigInt(i === 0 ? 121546 : 1000),
  })),
  {
    lockingBytecode: p2pkhLockingOf(wallet),
    valueSatoshis: BigInt(FEE_VAL),
  },
];
if (decoded.inputs.length !== sourceOutputs.length) {
  throw new Error(`input/source mismatch ${decoded.inputs.length} vs ${sourceOutputs.length}`);
}
const realVm = createVirtualMachineBch2026(false);
const real = realVm.verify({ sourceOutputs, transaction: decoded } as never);
if (real !== true) throw new Error(`real-prevout vm ${String(real)}`);

writeFileSync(OUT, binToHex(depositTx.raw));
console.log(
  JSON.stringify({
    txid: depositTx.txid,
    bytes: depositTx.txBytes,
    dummyVm: vm.accepted,
    realPrevoutVm: true,
    changePos: -1,
    fee: { tx: FEE_TX, pos: FEE_POS, value: FEE_VAL },
    nIn: decoded.inputs.length,
  }),
);
