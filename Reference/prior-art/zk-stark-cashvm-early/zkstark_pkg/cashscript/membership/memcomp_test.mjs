import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, TransactionBuilder } from 'cashscript';
import { compileFile } from 'cashc';
import { URL } from 'url';
const d = JSON.parse(readFileSync('/tmp/memq.json'));
const P = BigInt(d.P);
const mod = a => ((a % P) + P) % P;
const mpow = (b,e) => { b=mod(b); let r=1n; while(e>0n){ if(e&1n) r=mod(r*b); b=mod(b*b); e>>=1n;} return r; };
const inv = a => mpow(a, P-2n);
const k = BigInt(d.k);
const x = mod(BigInt(d.offsetD) * mpow(BigInt(d.omegaN), k));
const invZH = inv(mod(mpow(x,64n)-1n));
const invX0 = inv(mod(x-1n));
const invXroot = inv(mod(x-BigInt(d.hd_root)));
const invXnull = inv(mod(x-BigInt(d.hd_null)));
const B = v => BigInt(v);
const args = [ k,
  B(d.isr_x),B(d.sl_x),B(d.slv_x),B(d.sn_x),B(d.sp_x),B(d.rc_x),
  B(d.st),B(d.u2),B(d.u4),B(d.u6),B(d.nu),B(d.inj),
  B(d.stn),B(d.nun),
  ...d.alphas.map(B),
  B(d.root),B(d.nh),B(d.hd_root),B(d.hd_null),
  invZH,invX0,invXroot,invXnull,
  B(d.target) ];
const art = compileFile(new URL('./membership_comp.cash', import.meta.url));
const provider = new MockNetworkProvider();
const c = new Contract(art, [P,B(d.omegaN),B(d.offsetD),B(d.last),B(d.DOM)], { provider });
provider.addUtxo(c.address, { satoshis:100000n, txid:'00'.repeat(32), vout:0 });
async function run(a){ try{ const u=(await c.getUtxos())[0];
  await new TransactionBuilder({provider}).addInput(u,c.unlock.check(...a)).addOutput({to:c.address,amount:99000n}).debug();
  return 'ACCEPTED'; } catch(e){ return 'REJECTED ('+String(e.message).split('\n')[0].slice(0,48)+')'; } }
console.log('membership composition (6-col) on real VM:  args', args.length);
console.log('  valid query                 :', await run(args));
const t1=args.slice(); t1[7]=mod(t1[7]+1n);  console.log('  tampered column (st)        :', await run(t1));
const t2=args.slice(); t2[t2.length-1]=mod(t2[t2.length-1]+1n); console.log('  tampered FRI target         :', await run(t2));
const t3=args.slice(); t3[12]=mod(t3[12]+1n); console.log('  tampered inj (secret)       :', await run(t3));
