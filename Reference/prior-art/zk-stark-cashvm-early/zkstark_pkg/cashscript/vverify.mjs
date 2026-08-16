import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, randomUtxo, TransactionBuilder } from 'cashscript';
import { hexToBin } from '@bitauth/libauth';
const art=JSON.parse(readFileSync('./starkverifier.json','utf8'));
const d=JSON.parse(readFileSync('./sv_inputs.json','utf8'));
const provider=new MockNetworkProvider();
const c=new Contract(art,[BigInt(d.P), hexToBin(d.tp_root)],{provider,addressType:'p2sh32'});
provider.addUtxo(c.address,{...randomUtxo(),satoshis:2000000n});
const A=(o)=>[hexToBin(o.out_le),hexToBin(o.fri_roots),BigInt(o.n_layers),hexToBin(o.nonce),
 BigInt(o.grind_target),hexToBin(o.challRaw),hexToBin(o.idxsRaw),BigInt(o.n_queries),
 hexToBin(o.leaves),hexToBin(o.paths),BigInt(o.depth),BigInt(o.leafLen),hexToBin(o.compHints)];
async function run(tag,o){const u=await provider.getUtxos(c.address);
 try{await new TransactionBuilder({provider}).addInput(u[0],c.unlock.verify(...A(o))).addOutput({to:c.address,amount:1800000n}).debug();
 console.log(tag+': ACCEPTED');}catch(e){console.log(tag+': REJECTED ('+(e.message||'').split('\n')[0].slice(0,60)+')');}}
console.log('full verifier: redeem bytesize=',c.bytesize,'opcount=',c.opcount,'queries=',d.n_queries,'depth=',d.depth);
await run('real full stark.py proof',d);
// negatives
await run('forged challenge', {...d, challRaw:(d.challRaw[0]==='0'?'1':'0')+d.challRaw.slice(1)});
await run('tampered trace leaf', {...d, leaves:(d.leaves[0]==='0'?'1':'0')+d.leaves.slice(1)});
await run('bad composition inverse hint', {...d, compHints:(d.compHints[0]==='0'?'1':'0')+d.compHints.slice(1)});
