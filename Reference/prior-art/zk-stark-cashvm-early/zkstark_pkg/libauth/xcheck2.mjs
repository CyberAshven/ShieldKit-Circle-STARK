import { createVirtualMachineBch2026, cashAssemblyToBin } from '@bitauth/libauth';
const vm = createVirtualMachineBch2026();
function makeProgram(unlockingAsm, lockingAsm) {
  const u = cashAssemblyToBin(unlockingAsm); if (typeof u === 'string') throw new Error('unlock: '+u);
  const l = cashAssemblyToBin(lockingAsm);   if (typeof l === 'string') throw new Error('lock: '+l);
  return { inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: l, valueSatoshis: 1000n }],
    transaction: { version: 2,
      inputs: [{ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: u }],
      // pad output to push tx >= 65 bytes
      outputs: [{ lockingBytecode: Uint8Array.of(0x6a, 0x20, ...new Uint8Array(32)), valueSatoshis: 0n }],
      locktime: 0 } };
}
const show = (name, asm, unlock='') => {
  const r = vm.verify(makeProgram(unlock || 'OP_1', asm));
  const t = vm.debug(makeProgram(unlock || 'OP_1', asm));
  const mx = t[t.length-1].metrics || {};
  console.log(`${name}: ${r===true?'ACCEPTED':'REJECTED: '+r}  | opCost=${mx.operationCost} hashIters=${mx.hashDigestIterations}`);
};

// loop: sum 1..5 == 15 (unlock OP_1 is consumed by an initial OP_DROP)
show('loop sum1..5==15',
  `OP_DROP OP_0 OP_TOALTSTACK OP_5
   OP_BEGIN OP_DUP OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_1SUB OP_DUP OP_0 OP_NUMEQUAL OP_UNTIL
   OP_DROP OP_FROMALTSTACK <15> OP_NUMEQUAL`);

// function: define id=0 as (DUP MUL), invoke on 9 -> 81
show('function square(9)==81',
  `OP_DROP <OP_DUP OP_MUL> <0> OP_DEFINE  <9> <0> OP_INVOKE <81> OP_NUMEQUAL`);

// recursive function via INVOKE: factorial(5)==120  (id 1)
show('recursive factorial(5)==120',
  `OP_DROP
   <OP_DUP <1> OP_GREATERTHAN OP_IF OP_DUP <1> OP_SUB <1> OP_INVOKE OP_MUL OP_ELSE OP_DROP <1> OP_ENDIF> <1> OP_DEFINE
   <5> <1> OP_INVOKE <120> OP_NUMEQUAL`);
