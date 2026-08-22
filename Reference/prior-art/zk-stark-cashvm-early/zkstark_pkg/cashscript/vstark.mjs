import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, randomUtxo, TransactionBuilder } from 'cashscript';
import { hexToBin } from '@bitauth/libauth';
const art=JSON.parse(readFileSync('./starkmerkle.json','utf8'));
const proof=JSON.parse(readFileSync('./stark_proof.json','utf8'));
const root=hexToBin(proof['tp_root']);
const enc8=(v)=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,BigInt(v)&((1n<<64n)-1n),true);return b;};
const Q=proof.queries.slice(0,6);
const depth=Q[0].tp_path.length;
let leaves=new Uint8Array(),paths=new Uint8Array();
for(const q of Q){
  const salt=hexToBin(q.tp_salt), val=hexToBin(q.tp_hex);
  leaves=new Uint8Array([...leaves,...salt,...val]);
  for(const [shex,bit] of q.tp_path){ paths=new Uint8Array([...paths,bit,...hexToBin(shex)]); }
}
const provider=new MockNetworkProvider();
const c=new Contract(art,[root],{provider,addressType:'p2sh32'});
provider.addUtxo(c.address,{...randomUtxo(),satoshis:1000000n});
const u=await provider.getUtxos(c.address);
try{
  await new TransactionBuilder({provider})
    .addInput(u[0], c.unlock.proveAll(leaves,paths,BigInt(Q.length),BigInt(depth),24n))
    .addOutput({to:c.address,amount:900000n}).debug();
  console.log('REAL stark.py trace openings ('+Q.length+' queries, depth '+depth+'): ACCEPTED by CashScript verifier');
}catch(e){console.log('REJECTED:',(e.message||'').split('\n')[0]);}
// negative: corrupt one opened value
try{
  const bad=new Uint8Array(leaves); bad[0]^=1;
  await new TransactionBuilder({provider})
    .addInput((await provider.getUtxos(c.address))[0], c.unlock.proveAll(bad,paths,BigInt(Q.length),BigInt(depth),24n))
    .addOutput({to:c.address,amount:900000n}).debug();
  console.log('corrupted opening: ACCEPTED (BUG)');
}catch(e){console.log('corrupted opening: REJECTED (correct)');}
console.log('redeem bytesize=',c.bytesize,'opcount=',c.opcount);
