/** Compile a consensus successor and write raw hex. No keys printed. */
import { writeFileSync } from "node:fs";
import { binToHex, hexToBin } from "@bitauth/libauth";
import { loadLabWallet } from "../src/chain/wallet.ts";
import { connectChipnet, listUnspent } from "../src/chain/electrum.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
  compileSelfSendVout0,
} from "../src/chain/covenant-spend.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "../src/pool/mix-successor.ts";
import { encodePublicPaa1, STATE_BASE_SATS } from "../src/pool/state.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";

const out = process.argv[2];
if (!out) throw new Error("usage: dump-consensus-raw <out.hex>");

const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 500n });
if (!mixChangedRootsAndReserve(mix)) throw new Error("mix did not update roots");
const v = circleFriPlugin.verify(mix.statement, mix.proof);
if (!v.ok) throw new Error(`verify: ${v.reason}`);
const wallet = await loadLabWallet();
const client = await connectChipnet();
try {
  const utxos = await listUnspent(client, wallet.address);
  let picked =
    utxos.find((u) => u.tx_pos === 0 && u.value > 200_000) ??
    utxos.find((u) => u.value > 200_000);
  if (!picked) throw new Error("no funded utxo");
  if (picked.tx_pos !== 0) {
    const prep = compileSelfSendVout0(wallet, picked);
    const { broadcast } = await import("../src/chain/electrum.ts");
    await broadcast(client, binToHex(prep.raw));
    picked = { tx_hash: prep.txid, tx_pos: 0, value: prep.value, height: 0 };
  }
  const genesis = compileCovenantSpend({
    wallet,
    utxo: picked,
    state: mix.oldState,
    proof: mix.proof,
    lockKind: "p2sh32",
    envelope: "consensus",
    slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
  });
  const { broadcast } = await import("../src/chain/electrum.ts");
  const genesisTxid = await broadcast(client, binToHex(genesis.raw));
  const funded = compileFundVerifierKernels(
    wallet,
    { tx_hash: genesisTxid, tx_pos: 1, value: genesis.changeValue ?? 0 },
    1_000,
    SLOT_KERNEL_COUNT_CONSENSUS,
  );
  const kernelTxid = await broadcast(client, binToHex(funded.raw));
  const successor = compileCovenantSuccessor({
    wallet,
    feeUtxo: { tx_hash: funded.txid, tx_pos: funded.changePos, value: funded.changeValue },
    pool: {
      tx_hash: genesisTxid,
      tx_pos: 0,
      value: Number(STATE_BASE_SATS),
      category: hexToBin(picked.tx_hash),
      commitment: encodePublicPaa1(mix.oldState),
    },
    newState: mix.newState,
    proof: mix.proof,
    statement: mix.statement,
    lockKind: "p2sh32",
    envelope: "consensus",
    slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
    kernelUtxos: funded.fri,
    extraKernels: funded.extra,
  });
  writeFileSync(out, binToHex(successor.raw));
  process.stdout.write(
    JSON.stringify(
      {
        genesis: genesisTxid,
        kernels: kernelTxid,
        successor: successor.txid,
        txBytes: successor.txBytes,
        hexPath: out,
      },
      null,
      2,
    ) + "\n",
  );
} finally {
  client.close();
}
