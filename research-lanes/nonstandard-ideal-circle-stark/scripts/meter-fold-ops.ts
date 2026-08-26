import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { evaluateSuccessorInputMeters } from "../src/chain/vm-verifier.ts";
import { FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";

const note: Note = {
  amountSats: 10_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const raw = encodeFriProof(proveFri(d.statement, wDeposit(note, d.index, d.path)));
const meters = evaluateSuccessorInputMeters({
  oldState: d.statement.oldState,
  newState: d.statement.newState,
  proof: raw,
  statement: d.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: false,
  note,
});
const noteIdx = 1 + FRI_KERNEL_INPUTS + 3;
console.log(JSON.stringify({
  n: meters.inputs.length,
  noteAuth: meters.inputs[noteIdx],
  folds: meters.inputs.slice(noteIdx + 1, noteIdx + 7),
  grind: meters.inputs[noteIdx - 2],
  alg: meters.inputs[noteIdx - 1],
}, null, 2));
