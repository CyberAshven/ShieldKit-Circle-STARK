import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, randomUtxo, TransactionBuilder } from 'cashscript';
const art=JSON.parse(readFileSync('./composition.json','utf8'));
const d=JSON.parse(readFileSync('./comp_inputs.json','utf8'));
const B=(s)=>BigInt(s);
const provider=new MockNetworkProvider();
const c=new Contract(art,[B(d.P),B(d.omegaN),B(d.offset),B(d.last),B(d.C),B(d.out)],{provider,addressType:'p2sh32'});
provider.addUtxo(c.address,{...randomUtxo(),satoshis:1000000n});
const A=(o)=>[B(o.k0),B(o.half0),B(o.tp),B(o.tpn),B(o.a1),B(o.a2),B(o.invXn1),B(o.invXlast),B(o.v0),B(o.w0)];
async function run(tag,o){const u=await provider.getUtxos(c.address);
 try{await new TransactionBuilder({provider}).addInput(u[0],c.unlock.check(...A(o))).addOutput({to:c.address,amount:900000n}).debug();
 console.log(tag+': ACCEPTED');}catch(e){console.log(tag+': REJECTED');}}
console.log('composition: bytesize=',c.bytesize,'opcount=',c.opcount);
await run('valid',d);
await run('tampered tp',{...d,tp:String(B(d.tp)+1n)});
await run('tampered a1',{...d,a1:String(B(d.a1)+1n)});
await run('bad invXn1 hint',{...d,invXn1:String(B(d.invXn1)+1n)});
await run('tampered layer0 w0',{...d,w0:String(B(d.w0)+1n)});
