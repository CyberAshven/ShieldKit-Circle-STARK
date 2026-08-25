import { cashAssemblyToBin, createVirtualMachineBch2026, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { encodeFriProof, proveFri, decodeFriProof, wDeposit } from "../src/backends/circle/fri.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { walkShaOpening, SHA_LDE_PATH_DEPTH } from "../src/chain/sha-lde.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { COMPACT_PATH_STRIDE } from "../src/chain/fri-kernel.ts";


function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}
function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

const step = `
<${COMPACT_PATH_STRIDE}> OP_SPLIT
OP_TOALTSTACK
<1> OP_SPLIT
OP_SWAP
<0x00> OP_CAT OP_BIN2NUM
OP_TOALTSTACK
<0x00> OP_CAT OP_BIN2NUM
OP_2 OP_PICK
OP_SWAP
<32> OP_MUL
OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_SWAP
OP_FROMALTSTACK
OP_NOTIF
  OP_SWAP
OP_ENDIF
OP_CAT
OP_SHA256
OP_FROMALTSTACK
`;
const body = cashAssemblyToBin(`
OP_TOALTSTACK
OP_SHA256
OP_SWAP
${Array.from({ length: SHA_LDE_PATH_DEPTH }, () => step).join("\n")}
OP_SIZE
OP_0NOTEQUAL
OP_IF
  OP_DROP
OP_ENDIF
OP_SWAP
OP_DROP
OP_FROMALTSTACK
OP_EQUALVERIFY
`);
if (typeof body === "string") throw new Error(body);

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
const decoded = decodeFriProof(encodeFriProof(proved));
const lde = decoded.hashBitLde!;
const value = lde.openings[0]!.value;
const compact = lde.openings[0]!.compact;
const table = lde.table;
const root = decoded.hashBitRoot!;
console.log("js walk", walkShaOpening(value, compact, table, root, defaultInternalHash()));

const redeem = cashAssemblyToBin(`
${hexPush(body)}
<1>
OP_DEFINE
<1>
OP_INVOKE
OP_1
`);
if (typeof redeem === "string") throw new Error(redeem);
const lock = encodeLockingBytecodeP2sh32(hash256(redeem));
const unlocking = (() => {
  const p = (d: Uint8Array) => pushData(d);
  return Buffer.concat([p(table), p(compact), p(value), p(root), p(redeem)]);
})();
const vm = createVirtualMachineBch2026(false);
const sourceOutputs = [{ lockingBytecode: lock, valueSatoshis: 1000n }];
const transaction = {
  version: 2,
  locktime: 0,
  inputs: [{ outpointTransactionHash: new Uint8Array(32).fill(1), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: unlocking }],
  outputs: [{ lockingBytecode: lock, valueSatoshis: 1000n }],
};
const r = vm.verify({ sourceOutputs, transaction } as never);
console.log("iso walk", r === true ? true : String(r));
