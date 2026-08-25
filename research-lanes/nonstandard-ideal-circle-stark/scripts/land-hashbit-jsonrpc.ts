/**
 * Genesis + kernels + silent SHA-LDE note-auth successor. JSON-RPC land path.
 * Fee coin is a hot-wallet UTXO, not kernel treasury change.
 */
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
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
  compileSelfSendVout0,
} from "../src/chain/covenant-spend.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { successorFeeCoinSats } from "../src/chain/envelope.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  SLOT_KERNEL_COUNT,
  SLOTS_PER_KERNEL,
} from "../src/chain/air-cqz.ts";
import {
  compileFoldLockP2sh32,
  foldKernelCount,
  foldQueriesPerKernel,
  slotInputsCount,
} from "../src/chain/fold-kernel.ts";
import { compileNoteAuthLockP2sh32 } from "../src/chain/note-auth-kernel.ts";
import { compileGrindLockP2sh32 } from "../src/chain/grind-kernel.ts";
import { compileAlgebraicCLockP2sh32 } from "../src/chain/algebraic-c-kernel.ts";
import { poolLockP2sh32 } from "../src/chain/covenant-p2s.ts";

const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;
const FUND_TX = process.argv[2]!;
const FUND_POS = Number(process.argv[3]);
const FUND_VAL = Number(process.argv[4]);
const FEE_TX = process.argv[5]!;
const FEE_POS = Number(process.argv[6]);
const FEE_VAL = Number(process.argv[7]);
const OUT = process.argv[8] ?? "/tmp/grok-goal-d2ca769fa6a6/implementer";

if (!FUND_TX || !FEE_TX || !Number.isInteger(FUND_POS) || !Number.isInteger(FEE_POS)) {
  throw new Error("usage: land-hashbit-jsonrpc <fundTx> <pos> <value> <feeTx> <feePos> <feeValue> [outDir]");
}

const wallet = await loadLabWallet();
const prep = compileSelfSendVout0(wallet, { tx_hash: FUND_TX, tx_pos: FUND_POS, value: FUND_VAL });
writeFileSync(`${OUT}/land-prep.hex`, binToHex(prep.raw));

const instance = crypto.getRandomValues(new Uint8Array(32));
const genesisState = emptyState(instance);
const genesis = compileCovenantSpend({
  wallet,
  utxo: { tx_hash: prep.txid, tx_pos: 0, value: prep.value },
  state: genesisState,
  proof: new Uint8Array(32),
  lockKind: "p2sh32",
  envelope: "consensus",
  slotKernels: SLOTS,
});
writeFileSync(`${OUT}/land-genesis.hex`, binToHex(genesis.raw));
if (genesis.changeValue === undefined) throw new Error("no genesis change");

const funded = compileFundVerifierKernels(
  wallet,
  { tx_hash: genesis.txid, tx_pos: 1, value: genesis.changeValue },
  1_000,
  SLOTS,
  successorFeeCoinSats("consensus"),
);
writeFileSync(`${OUT}/land-kernels.hex`, binToHex(funded.raw));

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
const dummyVm = evaluatePoolSuccessorVm({
  oldState: genesisState,
  newState: d.machine.state,
  proof,
  statement: d.statement,
  slotKernels: SLOTS,
  standard: false,
  note,
});
if (!dummyVm.accepted) throw new Error(`dummy vm ${dummyVm.error}`);

const category = hexToBin(prep.txid);
const depositTx = compileCovenantSuccessor({
  wallet,
  feeUtxo: { tx_hash: FEE_TX, tx_pos: FEE_POS, value: FEE_VAL },
  pool: {
    tx_hash: genesis.txid,
    tx_pos: 0,
    value: utxoValueFor(genesisState),
    category,
    commitment: encodePublicPaa1(genesisState),
  },
  newState: d.machine.state,
  proof,
  statement: d.statement,
  lockKind: "p2sh32",
  envelope: "consensus",
  slotKernels: SLOTS,
  kernelUtxos: funded.fri,
  extraKernels: funded.extra,
  note,
});
writeFileSync(`${OUT}/land-successor.hex`, binToHex(depositTx.raw));

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
const sourceOutputs = [
  {
    lockingBytecode: poolLockP2sh32({ slotKernels: SLOTS }),
    valueSatoshis: utxoValueFor(genesisState),
    token: {
      amount: 0n,
      category,
      nft: { capability: "mutable" as const, commitment: encodePublicPaa1(genesisState) },
    },
  },
  ...kernelLocks.map((lockingBytecode, i) => ({
    lockingBytecode,
    valueSatoshis: BigInt(i === 0 ? funded.fri[0]!.value : 1000),
  })),
  { lockingBytecode: p2pkhLockingOf(wallet), valueSatoshis: BigInt(FEE_VAL) },
];
if (decoded.inputs.length !== sourceOutputs.length) {
  throw new Error(`input/source mismatch ${decoded.inputs.length} vs ${sourceOutputs.length}`);
}
const real = createVirtualMachineBch2026(false).verify({ sourceOutputs, transaction: decoded } as never);
if (real !== true) throw new Error(`real-prevout vm ${String(real)}`);

const report = {
  prep: prep.txid,
  instance: Buffer.from(instance).toString("hex"),
  genesis: genesis.txid,
  genesisChange: genesis.changeValue,
  kernels: funded.txid,
  successor: depositTx.txid,
  successorBytes: depositTx.txBytes,
  dummyVm: dummyVm.accepted,
  realPrevoutVm: true,
  nIn: decoded.inputs.length,
  category: prep.txid,
};
writeFileSync(`${OUT}/land-plan.json`, JSON.stringify(report, null, 2));
console.log(JSON.stringify(report));
