/** Measure occupancy A (standard 36q fused), B (consensus + booleanity), C (chained). */
import { writeFileSync } from "node:fs";
import { decodeTransaction } from "@bitauth/libauth";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import {
  FRI_QUERIES,
  FRI_VERSION,
  GRIND_BITS,
  TRACE_LEN,
} from "../src/backends/circle/params.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { compileChainedWithdraw } from "../src/chain/chained.ts";
import { booleanityKernelCount } from "../src/chain/booleanity-kernel.ts";
import { SLOT_KERNEL_COUNT, SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { foldKernelCount, foldQueriesPerKernel, slotInputsCount } from "../src/chain/fold-kernel.ts";
import { includeNoteAuth, prefixExtraKernelCount } from "../src/chain/note-auth-kernel.ts";
import {
  CONSENSUS_TX_BYTES,
  KERNEL_UNLOCK_PAD_HIGH,
  RELAY_STANDARD_TX_BYTES,
  UNLOCKING_MAX_BYTES,
} from "../src/chain/envelope.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { encodePublicPaa1, emptyState, utxoValueFor } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";

const outPath = process.argv[2];
if (!outPath) throw new Error("usage: measure-goal-envelopes <out.txt>");

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
const d = applyDeposit(
  { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
const wallet = createLabWallet();
const pool = {
  tx_hash: "11".repeat(32),
  tx_pos: 0,
  value: utxoValueFor(w.statement.oldState),
  category: new Uint8Array(32).fill(0x11),
  commitment: encodePublicPaa1(w.statement.oldState),
};
const newState = w.statement.newState;
const statement = w.statement;
const change = w.created?.note;

function hexLeak(raw: Uint8Array): boolean {
  const h = Buffer.from(raw).toString("hex");
  return h.includes(Buffer.from(note.rho).toString("hex")) || h.includes(Buffer.from(note.ownerSecret).toString("hex"));
}

function maxUnlock(raw: Uint8Array): { n: number; padded: number } {
  const tx = decodeTransaction(raw);
  if (typeof tx === "string") throw new Error(tx);
  const lens = tx.inputs.map((i) => i.unlockingBytecode.length);
  return {
    n: Math.max(...lens),
    padded: lens.filter((n) => n === KERNEL_UNLOCK_PAD_HIGH).length,
  };
}

function kernels(slotKernels: number, envelope: "standard" | "consensus") {
  return {
    slotKernels,
    folds: foldKernelCount(slotKernels),
    foldQueries: foldQueriesPerKernel(slotKernels),
    slotInputs: slotInputsCount(slotKernels),
    noteAuth: includeNoteAuth(slotKernels),
    prefixExtra: prefixExtraKernelCount(slotKernels),
    booleanity: booleanityKernelCount(slotKernels, envelope !== "standard"),
  };
}

const a4 = compileCovenantSuccessor({
  wallet,
  feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 2_000_000 },
  pool,
  newState,
  proof,
  statement,
  lockKind: "p2sh32",
  envelope: "standard",
  slotKernels: SLOT_KERNEL_COUNT,
  note,
  change,
});
const aOcc = compileCovenantSuccessor({
  wallet,
  feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 2_000_000 },
  pool,
  newState,
  proof,
  statement,
  lockKind: "p2sh32",
  envelope: "standard",
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  note,
  change,
});
const b = compileCovenantSuccessor({
  wallet,
  feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 2_000_000 },
  pool,
  newState,
  proof,
  statement,
  lockKind: "p2sh32",
  envelope: "consensus",
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  note,
  change,
});
const c = compileChainedWithdraw({
  wallet,
  tapeUtxo: { tx_hash: "aa".repeat(32), tx_pos: 0, value: 400_000 },
  digest: proof.slice(0, 32),
  proof,
  pool,
  newState,
  statement,
  note,
  change,
});

const ua4 = maxUnlock(a4.raw);
const uaOcc = maxUnlock(aOcc.raw);
const ub = maxUnlock(b.raw);
const lines = [
  `FRI_VERSION=${FRI_VERSION} q=${FRI_QUERIES} grind=${GRIND_BITS} TRACE=${TRACE_LEN}`,
  `SLOT_KERNEL_COUNT=${SLOT_KERNEL_COUNT} CONSENSUS=${SLOT_KERNEL_COUNT_CONSENSUS}`,
  `A4kernels ${JSON.stringify(kernels(SLOT_KERNEL_COUNT, "standard"))}`,
  `A4 txBytes=${a4.txBytes} maxUnlock=${ua4.n} pad6000=${ua4.padded} leak=${hexLeak(a4.raw)} fit100k=${a4.txBytes <= RELAY_STANDARD_TX_BYTES} unlockOk=${ua4.n <= UNLOCKING_MAX_BYTES}`,
  `AoccKernels ${JSON.stringify(kernels(SLOT_KERNEL_COUNT_CONSENSUS, "standard"))}`,
  `Aocc txBytes=${aOcc.txBytes} maxUnlock=${uaOcc.n} pad6000=${uaOcc.padded} leak=${hexLeak(aOcc.raw)} fit100k=${aOcc.txBytes <= RELAY_STANDARD_TX_BYTES} unlockOk=${uaOcc.n <= UNLOCKING_MAX_BYTES}`,
  `Bkernels ${JSON.stringify(kernels(SLOT_KERNEL_COUNT_CONSENSUS, "consensus"))}`,
  `B txBytes=${b.txBytes} maxUnlock=${ub.n} pad6000=${ub.padded} leak=${hexLeak(b.raw)} fit1mb=${b.txBytes <= CONSENSUS_TX_BYTES} unlockOk=${ub.n <= UNLOCKING_MAX_BYTES}`,
  `C hops=${c.hops.length} total=${c.totalBytes} payIndex=${c.payIndex}`,
  ...c.hops.map((h, i) => {
    const u = maxUnlock(h.raw);
    return `C hop${i} role=${h.role} txBytes=${h.txBytes} maxUnlock=${u.n} pad6000=${u.padded} leak=${hexLeak(h.raw)} fit100k=${h.txBytes <= RELAY_STANDARD_TX_BYTES} gt20k=${h.txBytes > 20_000}`;
  }),
];
writeFileSync(outPath, `${lines.join("\n")}\n`);
console.log(lines.join("\n"));
