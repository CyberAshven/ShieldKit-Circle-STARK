import { encodeFriProof, proveFri, decodeFriProof, wDeposit } from "../src/backends/circle/fri.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { evaluatePoolSuccessorVm, evaluateSuccessorInputMeters } from "../src/chain/vm-verifier.ts";
import { encodeShaLdeBlob } from "../src/chain/sha-lde.ts";
import { AIR_OFF_HASHBIT, encodeAirPacked } from "../src/chain/air-cqz.ts";

const note: Note = {
  amountSats: 10_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const proved = proveFri(d.statement, wDeposit(note, d.index, d.path));
const raw = encodeFriProof(proved);
const decoded = decodeFriProof(raw);
const packed = encodeAirPacked(d.statement, decoded);
const hb = packed.subarray(AIR_OFF_HASHBIT, AIR_OFF_HASHBIT + 32);
console.log(JSON.stringify({
  hashBitLde: Boolean(decoded.hashBitLde),
  blob: decoded.hashBitLde ? encodeShaLdeBlob(decoded.hashBitLde).length : 0,
  packedHashBit: Buffer.from(hb).toString("hex"),
  packedNonzero: hb.some((b) => b !== 0),
  proofHashBit: decoded.hashBitRoot ? Buffer.from(decoded.hashBitRoot).toString("hex") : null,
}));
const meters = evaluateSuccessorInputMeters({
  oldState: d.statement.oldState,
  newState: d.statement.newState,
  proof: raw,
  statement: d.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: false,
  note,
});
const i11 = meters.inputs[11];
console.log(JSON.stringify({ i11, n: meters.inputs.length, maxUnlock: Math.max(...meters.inputs.map((x) => x.unlocking)) }, null, 2));
const vm = evaluatePoolSuccessorVm({
  oldState: d.statement.oldState,
  newState: d.statement.newState,
  proof: raw,
  statement: d.statement,
  slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  standard: false,
  note,
});
console.log("vm", vm.accepted, vm.error);
