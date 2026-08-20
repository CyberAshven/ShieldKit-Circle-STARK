#!/usr/bin/env node
import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { circleFriPlugin } from "./backends/circle/plugin.ts";
import { hashLabPlugin } from "./backends/hash-lab.ts";
import { requestFaucet, walletBalance } from "./chain/chipnet.ts";
import { createLabWallet, loadLabWallet, saveLabWallet, type LabWallet } from "./chain/wallet.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "./pool/notes.ts";
import {
  DEFAULT_INTERNAL_HASH_ID,
  INTERNAL_HASH_IDS,
  isInternalHashId,
  internalHash,
  type InternalHashId,
} from "./backends/circle/internal-hash.ts";
import {
  BATCH_EXIT_WINDOW_SECONDS_DEFAULT,
  decodeRound,
  encodeRound,
  parseBatchWindowSeconds,
  planBatchExit,
  remainingSeconds,
  runBatchExitCountdown,
  shapeFusionOutputs,
  fusionBatchSketch,
  type BatchRound,
} from "./pool/batch-exit.ts";
import { LAB_PAYOUT_LOCKING } from "./chain/payout.ts";
import { emptyState, encodeState, STATE_BASE_SATS, utxoValueFor } from "./pool/state.ts";
import { applyDeposit, applyWithdraw, type PoolMachine } from "./pool/transition.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "./pool/mix-successor.ts";
import { announceEvent, newRoundKey } from "./nostr/bus.ts";
import { torStatus } from "./nostr/tor.ts";
import { DEFAULT_ZKP_FAMILY, describePlugins, zkpPluginByFamily } from "./plugins/registry.ts";
import { sendMany } from "./chain/send.ts";

import {
  broadcastCovenantGenesis,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
  measureGenesisAndSuccessor,
} from "./chain/covenant-spend.ts";
import { encodePublicPaa1 } from "./pool/state.ts";
import { FRI_KERNEL_INPUTS } from "./chain/fri-kernel.ts";
import { foldKernelCount } from "./chain/fold-kernel.ts";
import { proofShardReport } from "./chain/fri-openings.ts";
import { broadcast, connectChipnet, listUnspent } from "./chain/electrum.ts";
import { binToHex, hexToBin } from "@bitauth/libauth";
import {
  decodeFriProof,
  encodeFriProof,
  proveFri,
  proofByteLength,
  verifyFri,
  wDeposit,
  wWithdraw,
} from "./backends/circle/fri.ts";

const help = `any-amount — Chipnet lab (ZKP-agnostic)

  wallet new              create a Chipnet lab key in .local/ (gitignored)
  wallet show             print address
  faucet                  try public Chipnet faucets
  balance                 electrum listunspent
  pool create             local genesis state (PAA1)
  pool deposit --sats N [--hash sha256|blake2s|poseidon2-m31] [--plugin circle-fri-m31|hash-lab-v0]
  pool withdraw --sats N [--batch-exit] [--batch-window 180]
                          partial withdraw (same hash/plugin as the machine)
                          --batch-exit is opt-in: join a shared round. First
                          waiter opens a 180s window (override with --batch-window).
                          At close, flush whoever already opted in as N P2PKH
                          payouts (each lock+value bound). Not FUSE.

  pool chipnet-covenant   compile+sign+broadcast P2SH32 five-point genesis
  pool chipnet-mix        mix successor (deposit→withdraw) on Chipnet if funded
  pool measure-tx         compile genesis+successor, print byte counts
  serve                   localhost:17432 for the OPTN addon
  lab demo --wallets K    sequential rehearsal + Circle FRI prove/verify
  lab e2e                 deposit-aggregate-withdraw twice (anon set growth)
  bench                   time prove/verify/VM, print proof bytes + worksheet
  fund-wallets --count N  Chipnet fan-out from the funded lab UTXO
  status                  honest capability dump

Seeds: never pass a mnemonic here. Import stays a future hidden prompt.
`;

function arg(name: string, fallback?: string): string {
  const i = process.argv.indexOf(name);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1]!;
  if (fallback !== undefined) return fallback;
  throw new Error(`missing ${name}`);
}

function hashIdArg(fallback: InternalHashId = DEFAULT_INTERNAL_HASH_ID): InternalHashId {
  const v = arg("--hash", fallback);
  if (!isInternalHashId(v)) throw new Error(`internal hash must be ${INTERNAL_HASH_IDS.join("|")}, got ${v}`);
  return v;
}

function flag(name: string): boolean {
  return process.argv.includes(name);
}

function batchWindowArg(): number {
  if (flag("--batch-min")) {
    throw new Error(
      "batch-exit is one shared round, not a per-user min/max wait. Use --batch-window seconds (default 180).",
    );
  }
  const raw = flag("--batch-window")
    ? arg("--batch-window")
    : flag("--batch-max")
      ? arg("--batch-max")
      : String(BATCH_EXIT_WINDOW_SECONDS_DEFAULT);
  if (flag("--batch-max") && !flag("--batch-window")) {
    console.error("note: --batch-max is an alias for --batch-window (shared round close, not a personal max)");
  }
  return parseBatchWindowSeconds(Number(raw));
}

function batchRoundPath(): string {
  return join(process.cwd(), ".local", "batch-exit", "round.json");
}

async function loadBatchRound(): Promise<BatchRound | null> {
  try {
    const raw = JSON.parse(await readFile(batchRoundPath(), "utf8")) as Parameters<typeof decodeRound>[0];
    return decodeRound(raw);
  } catch {
    return null;
  }
}

async function saveBatchRound(round: BatchRound): Promise<void> {
  await mkdir(join(process.cwd(), ".local", "batch-exit"), { recursive: true });
  await writeFile(batchRoundPath(), JSON.stringify(encodeRound(round), null, 2));
}

function pluginFamilyArg(fallback: string = DEFAULT_ZKP_FAMILY): string {
  const v = arg("--plugin", fallback);
  return zkpPluginByFamily(v).family;
}

async function wallet(): Promise<LabWallet> {
  try {
    return await loadLabWallet();
  } catch {
    throw new Error("no lab wallet — run: npx tsx src/cli.ts wallet new");
  }
}

function machinePath(): string {
  return join(process.cwd(), ".local", "machine.json");
}

type HeldNote = { note: Note; index: number };

async function loadMachine(): Promise<{ machine: PoolMachine; notes: HeldNote[]; pluginFamily: string }> {
  const { readFile } = await import("node:fs/promises");
  const raw = JSON.parse(await readFile(machinePath(), "utf8")) as {
    state: ReturnType<typeof emptyState>;
    leaves: string[];
    notebook: Array<{ amountSats: string; rho: string; ownerSecret: string; index?: number }>;
    nullifiers: string[];
    instance: string;
    hash?: string;
    plugin?: string;
  };
  const hash = internalHash(raw.hash && isInternalHashId(raw.hash) ? raw.hash : DEFAULT_INTERNAL_HASH_ID);
  const notes = new IncrementalMerkle(undefined, hash);
  for (const leaf of raw.leaves) notes.leaves.push(Buffer.from(leaf, "hex"));
  const nullifiers = new NullifierSet(hash);
  for (const n of raw.nullifiers) nullifiers.items.push(Buffer.from(n, "hex"));
  const notebook: HeldNote[] = raw.notebook.map((n, i) => ({
    note: {
      amountSats: BigInt(n.amountSats),
      rho: Buffer.from(n.rho, "hex"),
      ownerSecret: Buffer.from(n.ownerSecret, "hex"),
    },
    index: n.index ?? i,
  }));
  return {
    machine: {
      state: {
        ...raw.state,
        sequence: BigInt(raw.state.sequence),
        reserveSats: BigInt(raw.state.reserveSats),
        depositCount: BigInt(raw.state.depositCount),
        withdrawalCount: BigInt(raw.state.withdrawalCount),
        poolInstanceId: Buffer.from(raw.instance, "hex"),
        noteRoot: Buffer.from(raw.state.noteRoot as unknown as string, "hex"),
        nullifierRoot: Buffer.from(raw.state.nullifierRoot as unknown as string, "hex"),
      },
      notes,
      nullifiers,
    },
    notes: notebook,
    pluginFamily: raw.plugin ? zkpPluginByFamily(raw.plugin).family : DEFAULT_ZKP_FAMILY,
  };
}

async function saveMachine(machine: PoolMachine, notebook: HeldNote[], pluginFamily = DEFAULT_ZKP_FAMILY): Promise<void> {
  await mkdir(join(process.cwd(), ".local"), { recursive: true });
  const body = {
    plugin: pluginFamily,
    hash: machine.notes.hash.id,
    instance: Buffer.from(machine.state.poolInstanceId).toString("hex"),
    state: {
      magic: machine.state.magic,
      version: machine.state.version,
      sequence: machine.state.sequence.toString(),
      reserveSats: machine.state.reserveSats.toString(),
      depositCount: machine.state.depositCount.toString(),
      withdrawalCount: machine.state.withdrawalCount.toString(),
      noteRoot: Buffer.from(machine.state.noteRoot).toString("hex"),
      nullifierRoot: Buffer.from(machine.state.nullifierRoot).toString("hex"),
    },
    leaves: machine.notes.leaves.map((l) => Buffer.from(l).toString("hex")),
    nullifiers: machine.nullifiers.items.map((n) => Buffer.from(n).toString("hex")),
    notebook: notebook.map((h) => ({
      amountSats: h.note.amountSats.toString(),
      rho: Buffer.from(h.note.rho).toString("hex"),
      ownerSecret: Buffer.from(h.note.ownerSecret).toString("hex"),
      index: h.index,
    })),
  };
  await writeFile(machinePath(), JSON.stringify(body, null, 2));
}

async function main(): Promise<void> {
  const cmd = process.argv[2] ?? "help";
  if (cmd === "help" || cmd === "-h" || cmd === "--help") {
    console.log(help);
    return;
  }
  if (cmd === "status") {
    console.log(
      JSON.stringify(
        {
          profile: "any-amount-v0",
          pluginFamily: circleFriPlugin.family,
          defaultZkp: DEFAULT_ZKP_FAMILY,
          zkpFamilies: ["circle-fri-m31", "hash-lab-v0"],
          internalHash: DEFAULT_INTERNAL_HASH_ID,
          internalHashIds: INTERNAL_HASH_IDS,
          batchExit: {
            optIn: true,
            windowSeconds: BATCH_EXIT_WINDOW_SECONDS_DEFAULT,
            shape: "cashfusion-like-multi-p2pkh",
            model: "shared-round",
          },
          vkId: circleFriPlugin.vkId,
          sound: circleFriPlugin.sound,
          proveVerify: "circle-fri-m31 AIR+FRI + 2026 VM kernel",
          worksheet: (await import("./backends/circle/soundness.ts")).soundnessWorksheet(),
          covenant: "P2S/P2SH32 five-point + PAA1 bind + FRI-kernel inputs (not OP_RETURN)",
          design: describePlugins(),
          tor: torStatus("optional"),
          chipnet: "wss://chipnet.imaginary.cash:50004",
        },
        null,
        2,
      ),
    );
    return;
  }
  if (cmd === "wallet" && process.argv[3] === "new") {
    const w = createLabWallet();
    await saveLabWallet(w);
    console.log(w.address);
    console.log("saved .local/lab-wallet.json (gitignored)");
    return;
  }
  if (cmd === "wallet" && process.argv[3] === "show") {
    const w = await wallet();
    console.log(w.address);
    return;
  }
  if (cmd === "faucet") {
    const w = await wallet();
    console.log(await requestFaucet(w.address));
    return;
  }
  if (cmd === "balance") {
    const w = await wallet();
    const b = await walletBalance(w.address);
    console.log(`${b.sats} sats  utxos=${b.utxos.length}`);
    return;
  }
  if (cmd === "pool" && process.argv[3] === "create") {
    const instance = crypto.getRandomValues(new Uint8Array(32));
    const hash = internalHash(hashIdArg());
    const machine: PoolMachine = {
      state: emptyState(instance, hash),
      notes: new IncrementalMerkle(undefined, hash),
      nullifiers: new NullifierSet(hash),
    };
    await saveMachine(machine, []);
    const ev = announceEvent(newRoundKey().secret, {
      network: "chipnet",
      profile: "any-amount-v0",
      pluginFamily: hashLabPlugin.family,
      instanceHint: Buffer.from(instance).toString("hex").slice(0, 16),
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    });
    console.log(`created PAA1 instance ${Buffer.from(instance).toString("hex")}`);
    console.log(`nostr announce kind ${ev.kind} id ${ev.id} (not published)`);
    return;
  }
  if (cmd === "pool" && process.argv[3] === "deposit") {
    const sats = BigInt(arg("--sats"));
    let loaded: { machine: PoolMachine; notes: HeldNote[]; pluginFamily: string };
    try {
      loaded = await loadMachine();
    } catch {
      const hash = internalHash(hashIdArg());
      const instance = crypto.getRandomValues(new Uint8Array(32));
      loaded = {
        machine: {
          state: emptyState(instance, hash),
          notes: new IncrementalMerkle(undefined, hash),
          nullifiers: new NullifierSet(hash),
        },
        notes: [],
        pluginFamily: DEFAULT_ZKP_FAMILY,
      };
    }
    const hash = loaded.machine.notes.hash;
    const plugin = zkpPluginByFamily(pluginFamilyArg(loaded.pluginFamily));
    const note: Note = {
      amountSats: sats,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(loaded.machine, note);
    const witness = { ...wDeposit(note, d.index, d.path), hash: hash.id };
    const proof = await plugin.prove(d.statement, witness);
    const v = plugin.verify(d.statement, proof, { hash: hash.id });
    if (!v.ok) throw new Error(v.reason);
    loaded.notes.push({ note, index: d.index });
    await saveMachine(d.machine, loaded.notes, plugin.family);
    console.log(`deposit ${sats} reserve=${d.machine.state.reserveSats} plugin=${plugin.family} hash=${hash.id} proofBytes=${proof.length} verify=ok`);
    return;
  }
  if (cmd === "pool" && process.argv[3] === "withdraw") {
    const sats = BigInt(arg("--sats"));
    const loaded = await loadMachine();
    const hash = loaded.machine.notes.hash;
    const plugin = zkpPluginByFamily(pluginFamilyArg(loaded.pluginFamily));
    const held = loaded.notes.find((n) => n.note.amountSats >= sats);
    if (!held) throw new Error("no note covers that amount");
    let batchNote: string | undefined;
    if (flag("--batch-exit")) {
      const windowSeconds = batchWindowArg();
      const plan = planBatchExit({
        sats,
        lockingBytecode: LAB_PAYOUT_LOCKING,
        round: await loadBatchRound(),
        windowSeconds,
      });
      await saveBatchRound(plan.round);
      const who = plan.openedNew ? "opened a new round" : "joined the open round";
      console.error(
        `batch-exit opt-in: ${who}; ${plan.round.claims.length} waiter(s); closes in ${plan.remainingSeconds}s (window ${plan.windowSeconds}s)`,
      );
      await runBatchExitCountdown(plan.remainingSeconds);
      const latest = (await loadBatchRound()) ?? plan.round;
      const left = remainingSeconds(latest, Date.now());
      if (left === 0) {
        const sketch = fusionBatchSketch(shapeFusionOutputs(latest.claims));
        batchNote = `batch-exit waiters=${latest.claims.length} window=${latest.windowSeconds}s shape=${sketch.shape}`;
        console.log(JSON.stringify(sketch));
      } else {
        batchNote = `batch-exit still-open remaining=${left}s waiters=${latest.claims.length}`;
        console.log(JSON.stringify({ remainingSeconds: left, waiters: latest.claims.length }));
      }
    }
    const w = applyWithdraw(loaded.machine, held.note, held.index, new Uint8Array(32), sats);
    const witness = { ...wWithdraw(held.note, held.index, w.path, w.created), hash: hash.id };
    const proof = await plugin.prove(w.statement, witness);
    const v = plugin.verify(w.statement, proof, { hash: hash.id });
    if (!v.ok) throw new Error(v.reason);
    const next = loaded.notes.filter((n) => n.index !== held.index);
    if (w.change && w.changeIndex !== undefined) next.push({ note: w.change, index: w.changeIndex });
    await saveMachine(w.machine, next, plugin.family);
    const extra = batchNote ? ` ${batchNote}` : "";
    console.log(`withdraw ${sats} reserve=${w.machine.state.reserveSats} plugin=${plugin.family} hash=${hash.id} verify=ok${extra}`);
    return;
  }
  if (cmd === "lab" && process.argv[3] === "demo") {
    const k = Number(arg("--wallets", "3"));
    const instance = crypto.getRandomValues(new Uint8Array(32));
    let machine: PoolMachine = {
      state: emptyState(instance),
      notes: new IncrementalMerkle(),
      nullifiers: new NullifierSet(),
    };
    const held: Array<{ note: Note; index: number }> = [];
    for (let i = 0; i < k; i += 1) {
      const note: Note = {
        amountSats: 1000n * BigInt(i + 1),
        rho: crypto.getRandomValues(new Uint8Array(32)),
        ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
      };
      const d = applyDeposit(machine, note);
      const proof = await circleFriPlugin.prove(d.statement, wDeposit(note, d.index, d.path));
      const v = circleFriPlugin.verify(d.statement, proof);
      if (!v.ok) throw new Error(`deposit proof: ${v.reason}`);
      machine = d.machine;
      held.push({ note, index: d.index });
    }
    const afterPartial: Array<{ note: Note; index: number }> = [];
    for (const h of held) {
      const half = h.note.amountSats / 2n;
      if (half > 0n && h.note.amountSats - half > 0n) {
        const w = applyWithdraw(machine, h.note, h.index, new Uint8Array(32), half);
        const proof = await circleFriPlugin.prove(w.statement, wWithdraw(h.note, h.index, w.path, w.created));
        const v = circleFriPlugin.verify(w.statement, proof);
        if (!v.ok) throw new Error(`partial proof: ${v.reason}`);
        if (!w.change || w.changeIndex === undefined) throw new Error("partial withdraw produced no change");
        machine = w.machine;
        afterPartial.push({ note: w.change, index: w.changeIndex });
      } else {
        afterPartial.push(h);
      }
    }
    for (const h of afterPartial.reverse()) {
      const w = applyWithdraw(machine, h.note, h.index, new Uint8Array(32), h.note.amountSats);
      const proof = await circleFriPlugin.prove(w.statement, wWithdraw(h.note, h.index, w.path));
      const v = circleFriPlugin.verify(w.statement, proof);
      if (!v.ok) throw new Error(`withdraw proof: ${v.reason}`);
      machine = w.machine;
    }
    console.log(
      `lab demo wallets=${k} finalReserve=${machine.state.reserveSats} seq=${machine.state.sequence} plugin=${circleFriPlugin.family} sound=${circleFriPlugin.sound} prove=ok verify=ok`,
    );
    return;
  }
  if (cmd === "lab" && process.argv[3] === "e2e") {
    const run = (tag: string) => {
      const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
      const v = circleFriPlugin.verify(mix.statement, mix.proof);
      if (!v.ok) throw new Error(`${tag} mix proof: ${v.reason}`);
      if (!mixChangedRootsAndReserve(mix)) throw new Error(`${tag} mix did not update roots/reserve`);
      return {
        tag,
        publicBefore: mix.publicBefore,
        publicAfter: mix.publicAfter,
        sound: circleFriPlugin.sound,
        changed: {
          noteRoot: mix.publicBefore.noteRoot !== mix.publicAfter.noteRoot,
          nullifierRoot: mix.publicBefore.nullifierRoot !== mix.publicAfter.nullifierRoot,
          reserve: mix.publicBefore.reserveSats !== mix.publicAfter.reserveSats,
        },
      };
    };
    const a = run("e2e-1");
    const b = run("e2e-2");
    console.log(JSON.stringify({ a, b, grew: a.publicAfter.anonSet >= 6 && b.publicAfter.anonSet >= 6 }, null, 2));
    return;
  }
  if (cmd === "bench") {
    const instance = crypto.getRandomValues(new Uint8Array(32));
    const benchNote = { amountSats: 50_000n, rho: crypto.getRandomValues(new Uint8Array(32)), ownerSecret: crypto.getRandomValues(new Uint8Array(32)) };
    const d = applyDeposit(
      { state: emptyState(instance), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      benchNote,
    );
    const t0 = performance.now();
    const proof = await circleFriPlugin.prove(d.statement, wDeposit(benchNote, d.index, d.path));
    const t1 = performance.now();
    const v = circleFriPlugin.verify(d.statement, proof);
    const t2 = performance.now();
    const { evaluateProofOnVm, proofFitsEnvelope } = await import("./chain/vm-verifier.ts");
    const { soundnessWorksheet } = await import("./backends/circle/soundness.ts");
    const tVm0 = performance.now();
    const vm = evaluateProofOnVm(proof);
    const tVm1 = performance.now();
    console.log(JSON.stringify({
      family: circleFriPlugin.family,
      sound: circleFriPlugin.sound,
      ok: v.ok,
      vmAccepted: vm.accepted,
      vmQueries: vm.queryEvals,
      proofBytes: proof.length,
      proveMs: +(t1 - t0).toFixed(2),
      verifyMs: +(t2 - t1).toFixed(2),
      vmMs: +(tVm1 - tVm0).toFixed(2),
      envelope: proofFitsEnvelope(proof),
      worksheet: soundnessWorksheet(),
    }));
    return;
  }
  if (cmd === "fund-wallets") {
    const n = Number(arg("--count", "15"));
    const funder = await wallet();
    const dir = join(process.cwd(), ".local", "wallets");
    await mkdir(dir, { recursive: true });
    const pays: Array<{ address: string; sats: bigint }> = [];
    for (let i = 1; i <= n; i += 1) {
      const w = createLabWallet();
      await saveLabWallet(w, join(dir, `w${i}.json`));
      pays.push({ address: w.address, sats: 2_000_000n });
    }
    const txid = await sendMany(funder, pays);
    console.log(`funded ${n} wallets 2e6 sats each tx=${txid}`);
    console.log("https://chipnet.imaginary.cash/tx/" + txid);
    return;
  }
  if (cmd === "pool" && process.argv[3] === "measure-tx") {
    const instance = crypto.getRandomValues(new Uint8Array(32));
    let machine: PoolMachine = {
      state: emptyState(instance),
      notes: new IncrementalMerkle(),
      nullifiers: new NullifierSet(),
    };
    const note: Note = {
      amountSats: 10_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(machine, note);
    const depW = wDeposit(note, d.index, d.path);
    const proof = encodeFriProof(proveFri(d.statement, depW));
    const { LAB_PAYOUT_DIGEST } = await import("./chain/payout.ts");
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 3_000n);
    const sizes = measureGenesisAndSuccessor(d.machine.state, w.machine.state, proof);
    const { compileCovenantSuccessor } = await import("./chain/covenant-spend.ts");
    const { createLabWallet } = await import("./chain/wallet.ts");
    const { encodePublicPaa1, utxoValueFor } = await import("./pool/state.ts");
    const { SLOT_KERNEL_COUNT, SLOT_KERNEL_COUNT_CONSENSUS } = await import("./chain/air-cqz.ts");
    const cons = compileCovenantSuccessor({
      wallet: createLabWallet(),
      feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 1_000_000 },
      pool: {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: utxoValueFor(d.machine.state),
        category: new Uint8Array(32).fill(0x11),
        commitment: encodePublicPaa1(d.machine.state),
      },
      newState: w.machine.state,
      proof,
      statement: w.statement,
      lockKind: "p2sh32",
      envelope: "consensus",
    });
    const report = {
      plugin: circleFriPlugin.family,
      sound: circleFriPlugin.sound,
      proofBytes: proofByteLength(proveFri(d.statement, depW)),
      unlockingLimit: 10_000,
      txLimit: 100_000,
      consensusTxLimit: 1_000_000,
      slotKernelsStandard: SLOT_KERNEL_COUNT,
      slotKernelsConsensus: SLOT_KERNEL_COUNT_CONSENSUS,
      foldKernelsStandard: foldKernelCount(SLOT_KERNEL_COUNT),
      foldKernelsConsensus: foldKernelCount(SLOT_KERNEL_COUNT_CONSENSUS),
      consensusSuccessor: { txBytes: cons.txBytes, unlockingBytes: cons.unlockingBytes },
      genesisP2sh32: {
        txBytes: sizes.genesisP2sh32.txBytes,
        unlockingBytes: sizes.genesisP2sh32.unlockingBytes,
        lockP2sBytes: sizes.genesisP2sh32.lockP2sBytes,
        lockP2sh32Bytes: sizes.genesisP2sh32.lockP2sh32Bytes,
      },
      genesisP2s: {
        txBytes: sizes.genesisP2s.txBytes,
        unlockingBytes: sizes.genesisP2s.unlockingBytes,
      },
      successorP2sh32: {
        txBytes: sizes.successorP2sh32.txBytes,
        unlockingBytes: sizes.successorP2sh32.unlockingBytes,
      },
    };
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  if (cmd === "pool" && process.argv[3] === "chipnet-covenant") {
    const w = await wallet();
    const instance = crypto.getRandomValues(new Uint8Array(32));
    const note: Note = {
      amountSats: 10_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(instance), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = await circleFriPlugin.prove(d.statement, wDeposit(note, d.index, d.path));
    const v = circleFriPlugin.verify(d.statement, proof);
    if (!v.ok) throw new Error(`covenant prove: ${v.reason}`);
    const sent = await broadcastCovenantGenesis(w, d.machine.state, proof, "p2sh32");
    console.log(
      JSON.stringify(
        {
          txid: sent.broadcast,
          prepTxid: sent.prepTxid ?? null,
          explorer: `https://chipnet.imaginary.cash/tx/${sent.broadcast}`,
          plugin: circleFriPlugin.family,
          sound: circleFriPlugin.sound,
          lockKind: sent.lockKind,
          txBytes: sent.txBytes,
          unlockingBytes: sent.unlockingBytes,
          proofBytes: sent.proofBytes,
          proofSlotBytes: sent.proofSlotBytes,
          lockP2sBytes: sent.lockP2sBytes,
          lockP2sh32Bytes: sent.lockP2sh32Bytes,
        },
        null,
        2,
      ),
    );
    return;
  }
  if (cmd === "pool" && process.argv[3] === "chipnet-mix") {
    const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
    if (!mixChangedRootsAndReserve(mix)) throw new Error("mix did not update roots/reserve");
    const v = circleFriPlugin.verify(mix.statement, mix.proof);
    if (!v.ok) throw new Error(v.reason);
    const w = await wallet();
    const genesis = await broadcastCovenantGenesis(w, mix.oldState, mix.proof, "p2sh32");
    if (genesis.changeValue === undefined || genesis.changeValue < 150_000) {
      throw new Error("genesis left no usable change for FRI kernels + successor fee");
    }
    const client = await connectChipnet();
    try {
      const funder = { tx_hash: genesis.broadcast, tx_pos: 1, value: genesis.changeValue };
      const funded = compileFundVerifierKernels(w, funder);
      const kernelTxid = await broadcast(client, binToHex(funded.raw));
      const feeUtxo = { tx_hash: funded.txid, tx_pos: funded.changePos, value: funded.changeValue };
      const successor = compileCovenantSuccessor({
        wallet: w,
        feeUtxo,
        pool: {
          tx_hash: genesis.broadcast,
          tx_pos: 0,
          value: utxoValueFor(mix.oldState),
          category: hexToBin(genesis.categoryHex),
          commitment: encodePublicPaa1(mix.oldState),
        },
        newState: mix.newState,
        proof: mix.proof,
        statement: mix.statement,
        lockKind: "p2sh32",
        kernelUtxos: funded.fri,
        extraKernels: funded.extra,
      });
      const succTxid = await broadcast(client, binToHex(successor.raw));
      const shards = proofShardReport(mix.proof);
      console.log(
        JSON.stringify(
          {
            genesis: genesis.broadcast,
            kernelTxid,
            successor: succTxid,
            explorer: `https://chipnet.imaginary.cash/tx/${succTxid}`,
            publicBefore: mix.publicBefore,
            publicAfter: mix.publicAfter,
            txBytes: successor.txBytes,
            unlockingBytes: successor.unlockingBytes,
            kernelInputs: FRI_KERNEL_INPUTS,
            openings: shards.openings,
            unlockingMax: shards.unlockingMax,
          },
          null,
          2,
        ),
      );
    } finally {
      client.close();
    }
    return;
  }

  if (cmd === "serve") {
    const port = Number(process.env.POOL_PORT ?? 17432);
    const server = createServer(async (req, res) => {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Headers", "content-type");
      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }
      if (req.url === "/status") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            profile: "any-amount-v0",
            plugins: [hashLabPlugin.family, circleFriPlugin.family],
            circleSound: circleFriPlugin.sound,
            chipnetOnly: true,
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end("not found");
    });
    server.listen(port, "127.0.0.1", () => {
      console.log(`pool sidecar http://127.0.0.1:${port}/status`);
    });
    return;
  }
  console.log(help);
  process.exitCode = 1;
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
