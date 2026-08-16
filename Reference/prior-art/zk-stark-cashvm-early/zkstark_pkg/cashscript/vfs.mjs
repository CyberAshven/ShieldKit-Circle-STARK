import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, randomUtxo, TransactionBuilder } from 'cashscript';
import { hexToBin } from '@bitauth/libauth';
const art=JSON.parse(readFileSync('./fiatshamir.json','utf8'));
const f=JSON.parse(readFileSync('./fs_inputs.json','utf8'));
const provider=new MockNetworkProvider();
const c=new Contract(art,[],{provider,addressType:'p2sh32'});
provider.addUtxo(c.address,{...randomUtxo(),satoshis:1000000n});
const args=(o)=>[hexToBin(o.tp_root),hexToBin(o.out_le),hexToBin(o.fri_roots),BigInt(o.n_layers),
  hexToBin(o.nonce),BigInt(o.grind_target),hexToBin(o.a1raw),hexToBin(o.a2raw),
  hexToBin(o.betas_raw),hexToBin(o.idxs_raw),BigInt(o.n_queries)];
async function run(tag,o){const u=await provider.getUtxos(c.address);
 try{await new TransactionBuilder({provider}).addInput(u[0],c.unlock.check(...args(o))).addOutput({to:c.address,amount:900000n}).debug();
 console.log(tag+': ACCEPTED');}catch(e){console.log(tag+': REJECTED ('+(e.message||'').split('\n')[0].slice(0,55)+')');}}
console.log('layers=',f.n_layers,'queries=',f.n_queries,'redeem bytesize=',c.bytesize,'opcount=',c.opcount);
await run('real stark.py transcript',f);
// negative: forge a challenge (flip a byte of a1raw) -> must reject
const bad1={...f,a1raw: f.a1raw.slice(0,2)+(f.a1raw[2]==='0'?'1':'0')+f.a1raw.slice(3)};
await run('forged a1 challenge',bad1);
// negative: weaken grinding target so the nonce no longer satisfies PoW
const badG={...f,grind_target:'1'};
await run('insufficient grinding',badG);
// negative: tamper a fri root (changes transcript) 
const badR={...f,fri_roots:(f.fri_roots[0]==='0'?'1':'0')+f.fri_roots.slice(1)};
await run('tampered fri root',badR);
