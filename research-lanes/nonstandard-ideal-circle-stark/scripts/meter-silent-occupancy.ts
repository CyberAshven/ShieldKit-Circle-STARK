import { writeFileSync } from "node:fs";
import { decodeTransaction } from "@bitauth/libauth";
import { encodeFriProof, proveFri, verifyFri, wDeposit } from "../src/backends/circle/fri.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { encodePublicPaa1, emptyState, utxoValueFor } from "../src/pool/state.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { FRI_LEFTOVER_BYTES } from "../src/chain/fri-kernel.ts";
import { KERNEL_UNLOCK_PAD_HIGH } from "../src/chain/envelope.ts";
import { soundnessWorksheet } from "../src/backends/circle/soundness.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const note: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
const d = applyDeposit(
  { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const proved = proveFri(d.statement, wDeposit(note, d.index, d.path));
const fri = verifyFri(d.statement, proved, wDeposit(note, d.index, d.path));
if (!fri.ok) throw new Error(fri.ok ? "ok" : fri.reason);
const raw = encodeFriProof(proved);
const measured = compileCovenantSuccessor({
  wallet: createLabWallet(),
  feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 2_000_000 },
  pool: {
    tx_hash: "11".repeat(32),
    tx_pos: 0,
    value: utxoValueFor(d.statement.oldState),
    category: new Uint8Array(32).fill(0x11),
    commitment: encodePublicPaa1(d.statement.oldState),
  },
  newState: d.statement.newState,
  proof: raw,
  statement: d.statement,
  lockKind: "p2sh32",
  envelope: "consensus",
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  note,
});
const tx = decodeTransaction(measured.raw);
if (typeof tx === "string") throw new Error(tx);
const unlocks = tx.inputs.map((i) => i.unlockingBytecode.length);
const meters = {
  txBytes: measured.txBytes,
  nIn: tx.inputs.length,
  unlocks,
  maxUnlock: Math.max(...unlocks),
  leftoverPairBind: FRI_LEFTOVER_BYTES,
  kernelUnlockPadHigh: KERNEL_UNLOCK_PAD_HIGH,
  padded6000: unlocks.filter((n) => n === KERNEL_UNLOCK_PAD_HIGH).length,
  shaLdeInLeftover: false,
  extraHashAirInputs: 0,
  worksheet: soundnessWorksheet(),
};
console.log(JSON.stringify(meters, null, 2));
const out = process.argv[2];
if (out) writeFileSync(out, JSON.stringify(meters, null, 2));
