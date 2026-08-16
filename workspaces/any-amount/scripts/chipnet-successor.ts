import { decodeTransaction, hexToBin } from "@bitauth/libauth";
import { connectChipnet, getTx, listUnspent, broadcast } from "../src/chain/electrum.ts";
import { binToHex } from "@bitauth/libauth";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { decodeState, encodeState, emptyState, STATE_BASE_SATS } from "../src/pool/state.ts";
import { loadLabWallet } from "../src/chain/wallet.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { encodeFriProof, proveFri } from "../src/backends/circle/fri.ts";

const genesisTxid = process.argv[2];
if (!genesisTxid) {
  console.error("usage: tsx scripts/chipnet-successor.ts <genesis-txid>");
  process.exit(1);
}

const wallet = await loadLabWallet();
const client = await connectChipnet();
try {
  const rawHex = await getTx(client, genesisTxid);
  const tx = decodeTransaction(hexToBin(rawHex));
  if (typeof tx === "string") throw new Error(tx);
  const poolOut = tx.outputs[0]!;
  const token = poolOut.token;
  if (!token?.nft) throw new Error("genesis output 0 has no NFT");
  const oldState = decodeState(token.nft.commitment);
  const note: Note = {
    amountSats: oldState.reserveSats > 0n ? oldState.reserveSats : 10_000n,
    rho: crypto.getRandomValues(new Uint8Array(32)),
    ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
  };
  // Local machine is not the on-chain tree; bump sequence only so five-point still holds.
  const next = {
    ...oldState,
    sequence: oldState.sequence + 1n,
  };
  const proof = encodeFriProof(
    proveFri(
      applyDeposit(
        { state: emptyState(oldState.poolInstanceId), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
        note,
      ).statement,
    ),
  );
  const v = circleFriPlugin.verify(
    applyDeposit(
      { state: emptyState(oldState.poolInstanceId), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    ).statement,
    proof,
  );
  if (!v.ok) throw new Error(v.reason);
  const utxos = await listUnspent(client, wallet.address);
  const feeUtxo = utxos.find((u) => u.value >= 10_000);
  if (!feeUtxo) throw new Error("no fee utxo on lab p2pkh");
  const measured = compileCovenantSuccessor({
    wallet,
    feeUtxo,
    pool: {
      tx_hash: genesisTxid,
      tx_pos: 0,
      value: Number(poolOut.valueSatoshis),
      category: token.category,
      commitment: token.nft.commitment,
    },
    newState: next,
    proof,
    lockKind: "p2sh32",
  });
  const txid = await broadcast(client, binToHex(measured.raw));
  console.log(
    JSON.stringify(
      {
        txid,
        explorer: `https://chipnet.imaginary.cash/tx/${txid}`,
        unlockingBytes: measured.unlockingBytes,
        txBytes: measured.txBytes,
        nextSequence: next.sequence.toString(),
        reserveSats: next.reserveSats.toString(),
      },
      null,
      2,
    ),
  );
} finally {
  client.close();
}
