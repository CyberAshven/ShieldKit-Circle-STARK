import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, randomUtxo, TransactionBuilder } from 'cashscript';
import { sha256, binToHex } from '@bitauth/libauth';
const artifact = JSON.parse(readFileSync('./merkle.json','utf8'));
const H = (b)=>sha256.hash(b);
function buildProof(values, index){
  let level=values.map(v=>H(v)); const layers=[level];
  while(level.length>1){const nxt=[];for(let i=0;i<level.length;i+=2){const l=level[i],r=(i+1<level.length)?level[i+1]:level[i];nxt.push(H(new Uint8Array([...l,...r])));}level=nxt;layers.push(level);}
  const root=layers[layers.length-1][0]; let idx=index; const parts=[];
  for(let d=0;d<layers.length-1;d++){const lvl=layers[d];
    if(idx%2===0){const sib=(idx+1<lvl.length)?lvl[idx+1]:lvl[idx];parts.push(new Uint8Array([0,...sib]));}
    else parts.push(new Uint8Array([1,...lvl[idx-1]])); idx=Math.floor(idx/2);}
  const path=parts.reduce((a,b)=>new Uint8Array([...a,...b]),new Uint8Array());
  return {root,path,depth:layers.length-1};
}
const N=256,index=137;
const values=Array.from({length:N},(_,i)=>new Uint8Array([i&255,(i>>8)&255,...new Uint8Array(6)]));
const {root,path,depth}=buildProof(values,index); const leaf=values[index];
const provider=new MockNetworkProvider();
const contract=new Contract(artifact,[root],{provider,addressType:'p2sh32'});
provider.addUtxo(contract.address,{...randomUtxo(),satoshis:100000n});

async function run(tag,leafArg,pathArg,depthArg){
  const utxos=await provider.getUtxos(contract.address);
  try{
    const txb=new TransactionBuilder({provider})
      .addInput(utxos[0], contract.unlock.prove(leafArg,pathArg,BigInt(depthArg)))
      .addOutput({to:contract.address,amount:90000n});
    await txb.debug();
    console.log(`${tag}: ACCEPTED`);
  }catch(e){console.log(`${tag}: REJECTED (${(e.message||'').split('\n')[0].slice(0,60)})`);}
}
console.log('depth =',depth,' contract redeem bytesize =',contract.bytesize,' opcount =',contract.opcount);
await run('valid proof',leaf,path,depth);
const bad=new Uint8Array(path); bad[40]^=1; await run('tampered path',leaf,bad,depth);
await run('wrong leaf',values[100],path,depth);
