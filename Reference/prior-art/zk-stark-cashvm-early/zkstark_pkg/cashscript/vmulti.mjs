import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, randomUtxo, TransactionBuilder } from 'cashscript';
import { sha256, binToHex } from '@bitauth/libauth';
const art=JSON.parse(readFileSync('./multimerkle.json','utf8'));
const H=(b)=>sha256.hash(b);
function tree(values){let lvl=values.map(v=>H(v));const L=[lvl];while(lvl.length>1){const nx=[];for(let i=0;i<lvl.length;i+=2){const l=lvl[i],r=(i+1<lvl.length)?lvl[i+1]:lvl[i];nx.push(H(new Uint8Array([...l,...r])));}lvl=nx;L.push(lvl);}return L;}
function proofOf(L,index){let idx=index;const parts=[];for(let d=0;d<L.length-1;d++){const lv=L[d];if(idx%2===0){const s=(idx+1<lv.length)?lv[idx+1]:lv[idx];parts.push(new Uint8Array([0,...s]));}else parts.push(new Uint8Array([1,...lv[idx-1]]));idx=Math.floor(idx/2);}return parts.reduce((a,b)=>new Uint8Array([...a,...b]),new Uint8Array());}
const N=256;const values=Array.from({length:N},()=>crypto.getRandomValues(new Uint8Array(40)));
const L=tree(values);const root=L[L.length-1][0];const depth=L.length-1;
const idxs=[3,17,42,88,129,200,255,7];
let leaves=new Uint8Array(),paths=new Uint8Array();
for(const k of idxs){leaves=new Uint8Array([...leaves,...values[k]]);paths=new Uint8Array([...paths,...proofOf(L,k)]);}
const provider=new MockNetworkProvider();
const c=new Contract(art,[root],{provider,addressType:'p2sh32'});
provider.addUtxo(c.address,{...randomUtxo(),satoshis:1000000n});
async function run(tag,lv,pt){const u=await provider.getUtxos(c.address);
 try{await new TransactionBuilder({provider}).addInput(u[0],c.unlock.proveAll(lv,pt,BigInt(idxs.length),BigInt(depth))).addOutput({to:c.address,amount:900000n}).debug();
 console.log(tag+': ACCEPTED');}catch(e){console.log(tag+': REJECTED ('+(e.message||'').split('\n')[0].slice(0,55)+')');}}
console.log('queries=',idxs.length,'depth=',depth,'redeem bytesize=',c.bytesize,'opcount=',c.opcount);
await run('all '+idxs.length+' queries valid',leaves,paths);
const bad=new Uint8Array(leaves); bad[40*3]^=1; // corrupt 4th query's leaf
await run('one query corrupted',bad,paths);
