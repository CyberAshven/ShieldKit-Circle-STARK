import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { evaluateFoldKernelOnly } from "../src/chain/vm-verifier.ts";
import { foldKernelUnlocking, compileFoldKernel } from "../src/chain/fold-kernel.ts";
import { encodeAirPacked } from "../src/chain/air-cqz.ts";

const note: Note = {
  amountSats: 10_000n,
  rho: crypto.getRandomValues(new Uint8Array(32)),
  ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
};
const d = applyDeposit(
  { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
  note,
);
const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
const packed = encodeAirPacked(w.statement, proof);
for (const n of [4, 5, 6]) {
  const ev = evaluateFoldKernelOnly({ statement: w.statement, proof, nFold: n, queryIndex: 0 });
  console.log(JSON.stringify({
    n,
    accepted: ev.accepted,
    unlocking: ev.unlockingBytes,
    redeem: compileFoldKernel(n, 0).length,
    packedUnlock: foldKernelUnlocking(n, 0, packed).length,
    error: ev.error?.slice(0, 280) ?? null,
  }));
}
