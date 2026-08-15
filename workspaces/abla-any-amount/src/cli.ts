#!/usr/bin/env node
import { createServer } from "node:http";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { circleFriPlugin } from "./backends/circle/plugin.ts";
import { hashLabPlugin } from "./backends/hash-lab.ts";
import { broadcastMarkerTx, genesisStateFor, requestFaucet, walletBalance } from "./chain/chipnet.ts";
import { createLabWallet, loadLabWallet, saveLabWallet, type LabWallet } from "./chain/wallet.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "./pool/notes.ts";
import { emptyState } from "./pool/state.ts";
import { applyDeposit, applyWithdraw, type PoolMachine } from "./pool/transition.ts";
import { announceEvent, newRoundKey } from "./nostr/bus.ts";
import { torStatus } from "./nostr/tor.ts";

const help = `abla-pool — Chipnet any-amount lab (ZKP-agnostic)

  wallet new              create a Chipnet lab key in .local/ (gitignored)
  wallet show             print address
  faucet                  try public Chipnet faucets
  balance                 electrum listunspent
  pool create             local genesis state (PAA1)
  pool deposit --sats N   any-amount deposit (off-chain machine + plugin)
  pool withdraw --sats N  partial withdraw
  pool chipnet-marker     broadcast PAA1 OP_RETURN (needs faucet coins)
  serve                   localhost:17432 for the OPTN addon
  lab demo --wallets K    sequential rehearsal (no seeds on argv)
  status                  honest capability dump

Seeds: never pass a mnemonic here. Import stays a future hidden prompt.
`;

function arg(name: string, fallback?: string): string {
  const i = process.argv.indexOf(name);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1]!;
  if (fallback !== undefined) return fallback;
  throw new Error(`missing ${name}`);
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

async function loadMachine(): Promise<{ machine: PoolMachine; notes: Note[] }> {
  const { readFile } = await import("node:fs/promises");
  const raw = JSON.parse(await readFile(machinePath(), "utf8")) as {
    state: ReturnType<typeof emptyState>;
    leaves: string[];
    notebook: Array<{ amountSats: string; rho: string; ownerSecret: string }>;
    nullifiers: string[];
    instance: string;
  };
  const notes = new IncrementalMerkle();
  for (const leaf of raw.leaves) notes.leaves.push(Buffer.from(leaf, "hex"));
  const nullifiers = new NullifierSet();
  for (const n of raw.nullifiers) nullifiers.items.push(Buffer.from(n, "hex"));
  const notebook: Note[] = raw.notebook.map((n) => ({
    amountSats: BigInt(n.amountSats),
    rho: Buffer.from(n.rho, "hex"),
    ownerSecret: Buffer.from(n.ownerSecret, "hex"),
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
  };
}

async function saveMachine(machine: PoolMachine, notebook: Note[]): Promise<void> {
  const body = {
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
    notebook: notebook.map((n) => ({
      amountSats: n.amountSats.toString(),
      rho: Buffer.from(n.rho).toString("hex"),
      ownerSecret: Buffer.from(n.ownerSecret).toString("hex"),
    })),
  };
  await writeFile(machinePath(), JSON.stringify(body, null, 2));
}

async function main(): Promise<void> {
  const cmd = process.argv[2] ?? "help";
  if (cmd === "help" || cmd === "-h") {
    console.log(help);
    return;
  }
  if (cmd === "status") {
    console.log(
      JSON.stringify(
        {
          profile: "any-amount-v0",
          plugins: [
            { family: hashLabPlugin.family, sound: hashLabPlugin.sound },
            { family: circleFriPlugin.family, sound: circleFriPlugin.sound },
          ],
          tor: torStatus("optional"),
          chipnet: "wss://chipnet.imaginary.cash:50004",
          honest:
            "Circle FRI verify refuses. On-chain spend is a lab conservation cell, not a sound shielded withdraw.",
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
    const machine: PoolMachine = {
      state: emptyState(instance),
      notes: new IncrementalMerkle(),
      nullifiers: new NullifierSet(),
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
    const loaded = await loadMachine();
    const note: Note = {
      amountSats: sats,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(loaded.machine, note);
    const proof = await hashLabPlugin.prove(d.statement, {});
    const v = hashLabPlugin.verify(d.statement, proof);
    if (!v.ok) throw new Error(v.reason);
    loaded.notes.push(note);
    await saveMachine(d.machine, loaded.notes);
    console.log(`deposit ${sats} reserve=${d.machine.state.reserveSats} plugin=${hashLabPlugin.family}`);
    return;
  }
  if (cmd === "pool" && process.argv[3] === "withdraw") {
    const sats = BigInt(arg("--sats"));
    const loaded = await loadMachine();
    const note = loaded.notes.find((n) => n.amountSats >= sats);
    if (!note) throw new Error("no note covers that amount");
    const index = loaded.notes.indexOf(note);
    const w = applyWithdraw(loaded.machine, note, index, new Uint8Array(32), sats);
    const proof = await hashLabPlugin.prove(w.statement, {
      index,
      leaf: (await import("./pool/notes.ts")).commitNote(note),
      path: loaded.machine.notes.authPath(index),
    });
    const v = hashLabPlugin.verify(w.statement, proof);
    if (!v.ok) throw new Error(v.reason);
    loaded.notes[index] = w.change ?? { ...note, amountSats: 0n };
    await saveMachine(w.machine, loaded.notes.filter((n) => n.amountSats > 0n));
    console.log(`withdraw ${sats} reserve=${w.machine.state.reserveSats}`);
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
      machine = d.machine;
      held.push({ note, index: d.index });
    }
    for (const h of held.reverse()) {
      const w = applyWithdraw(machine, h.note, h.index, new Uint8Array(32), h.note.amountSats);
      machine = w.machine;
    }
    console.log(`lab demo wallets=${k} finalReserve=${machine.state.reserveSats} seq=${machine.state.sequence}`);
    return;
  }
  if (cmd === "pool" && process.argv[3] === "chipnet-marker") {
    const w = await wallet();
    const txid = await broadcastMarkerTx(w, genesisStateFor(w));
    console.log(`chipnet marker ${txid}`);
    console.log("https://chipnet.imaginary.cash/tx/" + txid);
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
            circleSound: false,
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
