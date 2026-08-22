import { createVirtualMachineBch2026, cashAssemblyToBin } from '@bitauth/libauth';
const vm = createVirtualMachineBch2026();
export function evalScript(unlock, lock){
  const u=unlock?cashAssemblyToBin(unlock):new Uint8Array(); if(typeof u==='string') throw new Error('unlock asm: '+u);
  const l=cashAssemblyToBin(lock);   if(typeof l==='string') throw new Error('lock asm: '+l);
  const tx={version:2,inputs:[{outpointIndex:0,outpointTransactionHash:new Uint8Array(32),sequenceNumber:0,unlockingBytecode:u}],
    outputs:[{lockingBytecode:Uint8Array.of(0x6a),valueSatoshis:0n}],locktime:0};
  const trace=vm.debug({inputIndex:0,sourceOutputs:[{lockingBytecode:l,valueSatoshis:1000n}],transaction:tx});
  const last=trace[trace.length-1];
  const top=last.stack&&last.stack.length?last.stack[last.stack.length-1]:undefined;
  const truthy = top!==undefined && top.length>0 && !(top.length===1&&top[0]===0);
  return { ok: !last.error && truthy, error:last.error, stackLen:last.stack?last.stack.length:0 };
}
