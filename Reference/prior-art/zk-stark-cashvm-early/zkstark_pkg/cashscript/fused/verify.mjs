import { readFileSync } from 'fs';
import { createVirtualMachineBch2026, cashAssemblyToBin } from '@bitauth/libauth';
const vm = createVirtualMachineBch2026();
const asm = readFileSync(new URL('./verifier.asm', import.meta.url),'utf8').replace(/\n/g,' ');
const redeem = cashAssemblyToBin(asm);
if (typeof redeem === 'string') { console.log('asm error:', redeem); process.exit(1); }
const tx = { version:2, inputs:[{ outpointIndex:0, outpointTransactionHash:new Uint8Array(32),
  sequenceNumber:0, unlockingBytecode: cashAssemblyToBin('<0x'+'00'.repeat(1100)+'>') }],
  outputs:[{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis:0n }], locktime:0 };
const trace = vm.debug({ inputIndex:0, sourceOutputs:[{ lockingBytecode:redeem, valueSatoshis:1000n }], transaction:tx });
const last = trace[trace.length-1];
const top = last.stack && last.stack.length ? last.stack[last.stack.length-1] : undefined;
const ok = !last.error && top && top.length>0 && !(top.length===1 && top[0]===0);
console.log('redeem bytes:', redeem.length);
console.log(ok ? 'ACCEPTED' : 'REJECTED' + (last.error ? ' ('+last.error+')' : ''));
