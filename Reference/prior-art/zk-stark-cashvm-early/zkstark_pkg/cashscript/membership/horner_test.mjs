import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, TransactionBuilder } from 'cashscript';
import { compileFile } from 'cashc';
import { hexToBin } from '@bitauth/libauth';
import { URL } from 'url';

const d = JSON.parse(readFileSync('/tmp/horner.json'));
const P = BigInt(d.P), T = BigInt(d.T), x = BigInt(d.x);
const blob = hexToBin(d.blob);
const artifact = compileFile(new URL('./selector_horner.cash', import.meta.url));
const provider = new MockNetworkProvider();
const pinBin = hexToBin(d.pin);
const c = new Contract(artifact, [P, pinBin], { provider });
provider.addUtxo(c.address, { satoshis: 100000n, txid: '00'.repeat(32), vout: 0 });

async function run(coeffs, idx, claimed) {
  try {
    const u = (await c.getUtxos())[0];
    await new TransactionBuilder({ provider })
      .addInput(u, c.unlock.eval(coeffs, BigInt(idx), T, x, BigInt(claimed)))
      .addOutput({ to: c.address, amount: 99000n }).debug();
    return 'ACCEPTED';
  } catch (e) { return 'REJECTED (' + String(e.message).split('\n')[0].slice(0,50) + ')'; }
}
console.log('selector Horner on-chain (D=4, hash-pinned coeffs):');
for (let i = 0; i < d.names.length; i++) {
  const r = await run(blob, i, d.truevals[d.names[i]]);
  console.log(`  ${d.names[i].padEnd(4)}(x) verifier-computed == claimed :`, r);
}
// tamper: claim a wrong selector value -> Horner recomputes true value, mismatch -> reject
console.log('  isr with WRONG claimed value              :', await run(blob, 0, (BigInt(d.truevals.isr)+1n).toString()));
// tamper: forge a coefficient -> hash pin fails
const bad = blob.slice(); bad[0] ^= 1;
console.log('  forged coefficient (breaks hash pin)      :', await run(bad, 0, d.truevals.isr));
