/**
 * Meter SHA-LDE cargo + compact walks inside the note-auth unlocking
 * (leftover stays pair-bind; not 36 extra AIR inputs).
 */
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeShaLdeBlob } from "../src/chain/sha-lde.ts";
import { decodeFriProof } from "../src/backends/circle/fri.ts";

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
if (!decoded.hashBitLde) throw new Error("no hashBitLde");
const blob = encodeShaLdeBlob(decoded.hashBitLde);
console.log(JSON.stringify({
  blob: blob.length,
  table: decoded.hashBitLde.table.length,
  openings: decoded.hashBitLde.openings.length,
  hashBitRoot: decoded.hashBitRoot ? Buffer.from(decoded.hashBitRoot).toString("hex").slice(0, 16) : null,
  noteAuthNow: 1671,
  withBlob: 1671 + 1 + blob.length,
  under10k: 1671 + 1 + blob.length <= 10000,
}));
