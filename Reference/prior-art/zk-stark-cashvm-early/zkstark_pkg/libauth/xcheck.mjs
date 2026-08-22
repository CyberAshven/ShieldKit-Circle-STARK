import { createVirtualMachineBch2026, cashAssemblyToBin, hexToBin, binToHex, sha256, utf8ToBin } from '@bitauth/libauth';

const vm = createVirtualMachineBch2026();

// helper: build a minimal spending context to evaluate locking/unlocking bytecode
function makeProgram(unlockingAsm, lockingAsm) {
  const u = cashAssemblyToBin(unlockingAsm); if (typeof u === 'string') throw new Error('unlock asm: '+u);
  const l = cashAssemblyToBin(lockingAsm);   if (typeof l === 'string') throw new Error('lock asm: '+l);
  const sourceOutputs = [{ lockingBytecode: l, valueSatoshis: 1000n }];
  const transaction = {
    version: 2,
    inputs: [{ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32),
               sequenceNumber: 0, unlockingBytecode: u }],
    outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n }],
    locktime: 0,
  };
  return { inputIndex: 0, sourceOutputs, transaction };
}

// ---- TEST 1: Merkle inner step  H(left||right) == expected ----
const left  = new Uint8Array(32).fill(0xaa);
const right = new Uint8Array(32).fill(0xbb);
const cat = new Uint8Array([...left, ...right]);
const expected = sha256.hash(cat);                       // reference
const unlock = `<0x${binToHex(left)}> <0x${binToHex(right)}>`;
const lock   = `OP_CAT OP_SHA256 <0x${binToHex(expected)}> OP_EQUAL`;
const prog = makeProgram(unlock, lock);

const result = vm.verify(prog);   // true if script verifies, else error string
console.log('TEST1 merkle-step verify:', result === true ? 'ACCEPTED (matches my model)' : 'REJECTED: '+result);

// read cost metrics from the final debug state
const trace = vm.debug(prog);
const last = trace[trace.length - 1];
const metricKeys = last && last.metrics ? Object.keys(last.metrics) : [];
console.log('  libauth final-state metric keys:', metricKeys.join(', '));
if (last && last.metrics) {
  console.log('  libauth hashDigestIterations =', last.metrics.hashDigestIterations);
  console.log('  libauth operationCost        =', last.metrics.operationCost);
}

// ---- TEST 2: do the 2026 opcodes (loops/functions) assemble & run? ----
// sum 1..5 with a bounded loop: acc on alt, i on main
const loopAsm = `
OP_0 OP_TOALTSTACK
OP_5
OP_BEGIN
  OP_DUP OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
  OP_1SUB
  OP_DUP OP_0 OP_NUMEQUAL
OP_UNTIL
OP_DROP OP_FROMALTSTACK
<15> OP_EQUAL`;
try {
  const r2 = vm.verify(makeProgram('OP_1', loopAsm)); // unlock pushes a dummy then drop? need clean
  console.log('TEST2 loop (sum1..5==15):', r2 === true ? 'ACCEPTED' : ('REJECTED: '+r2));
} catch(e){ console.log('TEST2 loop assemble/run error:', e.message); }
