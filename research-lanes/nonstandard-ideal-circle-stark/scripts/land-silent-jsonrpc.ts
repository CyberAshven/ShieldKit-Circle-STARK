import { writeFileSync } from "node:fs";
import { binToHex, hexToBin } from "@bitauth/libauth";
import { encodeFriProof, proveFri, verifyFri } from "../src/backends/circle/fri.ts";
import { wDeposit } from "../src/backends/circle/air.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { loadLabWallet } from "../src/chain/wallet.ts";
import { compileCovenantSuccessor, compileFundVerifierKernels } from "../src/chain/covenant-spend.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { successorFeeCoinSats } from "../src/chain/envelope.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";

const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;
const GENESIS = process.argv[2];
const INSTANCE_HEX = process.argv[3];
const CHANGE_VAL = Number(process.argv[4] ?? "396800");
const OUT = process.argv[5] ?? "/tmp/grok-goal-d2ca769fa6a6/implementer/land-hex";

if (!GENESIS || !INSTANCE_HEX) throw new Error("usage: land-silent-jsonrpc <genesisTxid> <instanceHex> [changeValue] [outPrefix]");

const wallet = await loadLabWallet();
const instance = hexToBin(INSTANCE_HEX);
const genesisState = emptyState(instance);
const funded = compileFundVerifierKernels(
  wallet,
  { tx_hash: GENESIS, tx_pos: 1, value: CHANGE_VAL },
  1_000,
  SLOTS,
  successorFeeCoinSats("consensus"),
);
writeFileSync(`${OUT}-kernels.hex`, binToHex(funded.raw));
console.log("kernels", funded.txid, "bytes", funded.raw.length);

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
const fri = verifyFri(d.statement, proved, wDeposit(note, d.index, d.path));
if (!fri.ok) throw new Error("verifyFri");
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
  feeUtxo: funded.changePos >= 0
    ? { tx_hash: funded.txid, tx_pos: funded.changePos, value: funded.changeValue }
    : { tx_hash: GENESIS, tx_pos: 1, value: CHANGE_VAL },
  pool: {
    tx_hash: GENESIS,
    tx_pos: 0,
    value: utxoValueFor(genesisState),
    category: hexToBin(process.env.POOL_CATEGORY ?? GENESIS),
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
writeFileSync(`${OUT}-successor.hex`, binToHex(depositTx.raw));
console.log(JSON.stringify({
  kernelsTxid: funded.txid,
  successorTxid: depositTx.txid,
  successorBytes: depositTx.txBytes,
  vmAccepted: vm.accepted,
}));
