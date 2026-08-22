import { readFileSync } from 'fs';
import { createVirtualMachineBch2026, cashAssemblyToBin, binToHex } from '@bitauth/libauth';
const vm=createVirtualMachineBch2026();
const asm=readFileSync(new URL('./fold.asm', import.meta.url),'utf8').replace(/\n/g,' ');
const l=cashAssemblyToBin(asm); if(typeof l==='string'){console.log('ASM ERROR:',l);process.exit(1);}
const tx={version:2,inputs:[{outpointIndex:0,outpointTransactionHash:new Uint8Array(32),sequenceNumber:0,unlockingBytecode:cashAssemblyToBin('<0x'+'00'.repeat(480)+'>')}],
  outputs:[{lockingBytecode:Uint8Array.of(0x6a),valueSatoshis:0n}],locktime:0};
const prog={inputIndex:0,sourceOutputs:[{lockingBytecode:l,valueSatoshis:1000n}],transaction:tx};
const trace=vm.debug(prog);
const last=trace[trace.length-1];
const top=last.stack&&last.stack.length?last.stack[last.stack.length-1]:undefined;
const ok=!last.error && top && top.length>0 && !(top.length===1&&top[0]===0);
console.log('lock bytesize:',l.length);
console.log('FRI fold (unrolled, hand asm) vs real q0:', ok?'ACCEPTED':'REJECTED');
if(!ok){
  console.log('error:', last.error);
  // dump last few states
  for(const s of trace.slice(-6)){
    console.log('  ip='+s.ip, 'err='+(s.error||'-'), 'stack=['+(s.stack||[]).map(x=>binToHex(x).slice(0,12)).join(',')+']');
  }
}
