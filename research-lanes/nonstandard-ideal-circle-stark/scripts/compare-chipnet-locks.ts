/**
 * Compare live kernel/pool P2SH32 hashes to Chipnet genesis + kernel UTXOs.
 * Does not print keys.
 */
import { binToHex, hash256, hexToBin } from "@bitauth/libauth";
import { compilePoolCovenant, poolLockP2sh32 } from "../src/chain/covenant-p2s.ts";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "../src/chain/fri-kernel.ts";
import { compileCqzLockP2sh32, compileSlotsLockP2sh32, SLOT_KERNEL_COUNT, SLOT_KERNEL_COUNT_CONSENSUS, SLOTS_PER_KERNEL } from "../src/chain/air-cqz.ts";
import { compileGrindLockP2sh32 } from "../src/chain/grind-kernel.ts";
import { compileAlgebraicCLockP2sh32 } from "../src/chain/algebraic-c-kernel.ts";
import { compileNoteAuthLockP2sh32 } from "../src/chain/note-auth-kernel.ts";
import { compileFoldLockP2sh32, foldKernelCount, foldQueriesPerKernel, slotInputsCount } from "../src/chain/fold-kernel.ts";
import { emptyState, encodePublicPaa1 } from "../src/pool/state.ts";

function p2sh32hash(lock: Uint8Array): string {
  return binToHex(lock.subarray(2, 34));
}

const SLOTS = SLOT_KERNEL_COUNT_CONSENSUS;
const GENESIS_LOCK = "e44c046a55dec2dc4f10307a1b64fd8a894f05458b38cc97d2e25455f788695a";
const INSTANCE = "8bb049bcc5055ffa6da60823ec4b6db02463b0c79d4aab98d73ba436660d086f";
const GENESIS_COMMIT =
  "50414131010000000000000000000000000000000000000000000000000000008bb049bcc5055ffa6da60823ec4b6db02463b0c79d4aab98d73ba436660d086f8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb0000000000000000000000000000000000000000000000000000000000000000";
const KERNEL_LOCKS = [
  "19921d3c4998fbb27a9490017b649355469a3e60fe7d42c8e58d086403caf823",
  "7b1c910714bfb408889fdeb6832ebf5be544d854405f4cc603801c138ca82a17",
  "e6b824b18b005df20036de2be87dbc62cc9006bd7d3ece42d262db1b3170baf6",
  "109ec9da494ecf5d86eed87ba7051358fb4c735a046f1d9599f8c000359896f9",
  "73b59c52a5de429c87404a1bdc3be646955e71585296256b51eb5cf54a303892",
  "2021fad936dbfda5b4762ed289cddc0448d53968c4c78659147bc14e9cf1bec1",
  "20f278c83937923a04b0735bfcc73e223e4c9e5afae855594b04f32b1dd6baba",
  "e8d7ee3d208c453c24bfeb041adeb0e9bf31820bf92e9a1e6282daa2680070c2",
  "a9ce4f42d12890f1e7bdaadfb347cbf9afd631789ede28f12fa99bd3db6fbb0e",
  "a40642b1929b8b468068b6bdd79c0b026a09f86be912c1ec32d10b29556386f9",
  "33b8da1d581fd10fddf83df7f116849f62dd21ae5ef408e8cdaee6da47d7d910",
  "69a235f0a24708006e7d12311cd500d7ec88785078e135097d9bd5a66d2f46fc",
  "fca74941ec6ad1383678b00f293c61923ece87f66357c9dec1415e92822e5f20",
  "e50a5a61ded81719fdbdeb69bc27251727338f92edacadce0bc06ba5264905b5",
  "56d95559737a08ae51270ea0567702e01a5c0e04245f7c510d09fa33e0856d72",
  "ec01a3a4be79b1e55e73d310fd9f8f018ad50cbc7c1c96fbd68f6733cd460a44",
  "465b81dbd74d8c624670bba670f315edb57d48ad2073ec542b1f6d95eb507d6f",
];

const expected = [
  ...Array.from({ length: FRI_KERNEL_INPUTS }, (_, i) => ["fri" + i, compileFriQueryLockP2sh32(i)] as const),
  ["cqz", compileCqzLockP2sh32()] as const,
  ["grind", compileGrindLockP2sh32()] as const,
  ["alg", compileAlgebraicCLockP2sh32()] as const,
  ["note", compileNoteAuthLockP2sh32()] as const,
  ...Array.from({ length: foldKernelCount(SLOTS) }, (_, f) =>
    [
      "fold" + f,
      compileFoldLockP2sh32(foldQueriesPerKernel(SLOTS), f * foldQueriesPerKernel(SLOTS)),
    ] as const,
  ),
  ...Array.from({ length: slotInputsCount(SLOTS) }, (_, i) =>
    [
      "slot" + i,
      compileSlotsLockP2sh32(
        i * (SLOTS > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1),
        SLOTS > SLOT_KERNEL_COUNT ? SLOTS_PER_KERNEL : 1,
      ),
    ] as const,
  ),
];

const pool = poolLockP2sh32({ slotKernels: SLOTS });
const state = emptyState(hexToBin(INSTANCE));
const commit = Buffer.from(encodePublicPaa1(state)).toString("hex");
const mismatches: string[] = [];
if (p2sh32hash(pool) !== GENESIS_LOCK) mismatches.push("pool");
if (commit !== GENESIS_COMMIT) mismatches.push("paa1");
const hashes = expected.map(([n, l]) => {
  const h = p2sh32hash(l);
  return { n, h, ok: KERNEL_LOCKS[expected.findIndex((e) => e[0] === n)] === h };
});
for (let i = 0; i < expected.length; i += 1) {
  if (p2sh32hash(expected[i]![1]) !== KERNEL_LOCKS[i]) mismatches.push(expected[i]![0]);
}

console.log(
  JSON.stringify(
    {
      poolLock: p2sh32hash(pool),
      poolRedeem: binToHex(hash256(compilePoolCovenant({ slotKernels: SLOTS }))),
      matchGenesisPool: p2sh32hash(pool) === GENESIS_LOCK,
      matchPaa1: commit === GENESIS_COMMIT,
      nExpected: expected.length,
      nKernelUtxos: KERNEL_LOCKS.length,
      mismatches,
      hashes,
    },
    null,
    2,
  ),
);
if (mismatches.length > 0) process.exit(1);
