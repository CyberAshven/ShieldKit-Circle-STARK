import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, randomUtxo, TransactionBuilder } from 'cashscript';
import { sha256 } from '@bitauth/libauth';
const art=JSON.parse(readFileSync('./grind.json','utf8'));
const transcript=new Uint8Array(32).fill(7);
function findNonce(){let i=0;for(;;){const n=new Uint8Array(8);new DataView(n.buffer).setBigUint64(0,BigInt(i),true);
  const h=sha256.hash(new Uint8Array([...transcript,...n]));if(h[0]===0&&h[1]===0)return n;i++;}}
const nonce=findNonce();
const provider=new MockNetworkProvider();
const c=new Contract(art,[transcript],{provider,addressType:'p2sh32'});
provider.addUtxo(c.address,{...randomUtxo(),satoshis:100000n});
async function run(tag,nn){const u=await provider.getUtxos(c.address);
 try{await new TransactionBuilder({provider}).addInput(u[0],c.unlock.check(nn)).addOutput({to:c.address,amount:90000n}).debug();
 console.log(tag+': ACCEPTED');}catch(e){console.log(tag+': REJECTED');}}
console.log('redeem bytesize=',c.bytesize,'opcount=',c.opcount);
await run('valid 16-bit PoW nonce',nonce);
await run('bad nonce',new Uint8Array(8));
