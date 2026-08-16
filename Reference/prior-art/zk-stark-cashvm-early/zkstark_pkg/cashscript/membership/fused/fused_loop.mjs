import { readFileSync } from 'fs';
import { createVirtualMachineBch2026, cashAssemblyToBin } from '@bitauth/libauth';
const d = JSON.parse(readFileSync('/tmp/loop.json'));
const omega = d.omegaN, offset = d.offset;
const MOD = `<0x01000000ffffffff00> OP_MOD`;
const body = `
  <${omega}> OP_SWAP
  OP_TOALTSTACK OP_TOALTSTACK OP_1 OP_FROMALTSTACK OP_FROMALTSTACK
  OP_BEGIN OP_DUP OP_2 OP_DIV OP_TOALTSTACK OP_2 OP_MOD
    OP_IF OP_DUP OP_ROT OP_MUL ${MOD} OP_SWAP OP_ENDIF
    OP_DUP OP_MUL ${MOD} OP_FROMALTSTACK OP_DUP OP_0 OP_NUMEQUAL OP_UNTIL
  OP_2DROP <${offset}> OP_MUL ${MOD} OP_NUMEQUALVERIFY
`.replace(/\s+/g,' ').trim();
const bodyBin = cashAssemblyToBin(body);
const bodyHex = Buffer.from(bodyBin).toString('hex');

// REDEEM (program only, constant size): define subroutine + loop-invoke over queries.
// First it DROPs the large opening-data blob that real proofs carry in the witness.
const redeemAsm = `
  OP_DROP
  <0x${bodyHex}> <0x00> OP_DEFINE
  <${d.pairs.length}> OP_TOALTSTACK
  OP_BEGIN
    <0x00> OP_INVOKE
    OP_FROMALTSTACK OP_1SUB OP_DUP OP_TOALTSTACK OP_0 OP_NUMEQUAL
  OP_UNTIL
  OP_FROMALTSTACK OP_DROP OP_1
`.replace(/\s+/g,' ').trim();
const redeem = cashAssemblyToBin(redeemAsm);

// UNLOCKING (witness): the per-query (x,k) data + a realistic-size opening blob.
// Real membership proof openings ~= 64KB; that witness size sets the op-cost budget.
function buildUnlock(pairs, padBytes) {
  let a = '';
  for (let i = pairs.length-1; i >= 0; i--) a += ` <${pairs[i][1]}> <${pairs[i][0]}>`;
  a += ` <0x${'00'.repeat(padBytes)}>`;   // opening-data stand-in, pushed LAST (on top) -> OP_DROP removes it
  return cashAssemblyToBin(a.replace(/\s+/g,' ').trim());
}
const vm = createVirtualMachineBch2026();
function run(pairs, padBytes) {
  const unlock = buildUnlock(pairs, padBytes);
  const tx = { version:2, inputs:[{ outpointIndex:0, outpointTransactionHash:new Uint8Array(32),
    sequenceNumber:0, unlockingBytecode: unlock }],
    outputs:[{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis:0n }], locktime:0 };
  const tr = vm.debug({ inputIndex:0, sourceOutputs:[{ lockingBytecode:redeem, valueSatoshis:1000n }], transaction:tx });
  const s = tr[tr.length-1];
  const top = s.stack && s.stack.length ? s.stack[s.stack.length-1] : undefined;
  return { ok: !s.error && top && top.length>0, err: s.err||s.error, witness: unlock.length };
}
console.log('redeem bytes (program, constant in #queries):', redeem.length, '<=10000:', redeem.length<=10000);
for (const pad of [200, 4000, 9000]) {
  const r = run(d.pairs, pad);
  console.log(`witness ~${(r.witness/1000).toFixed(1)}KB : ${r.ok ? 'ACCEPTED' : 'REJECTED '+(r.err||'')}`);
}
// tamper: corrupt one query's expected x -> must reject
const bad = d.pairs.map(p=>p.slice()); bad[5][1] = (BigInt(bad[5][1])+1n).toString();
const rb = run(bad, 9000);
console.log('tampered query x (witness ~9KB):', rb.ok ? 'ACCEPTED (BAD)' : 'REJECTED (correct)');
