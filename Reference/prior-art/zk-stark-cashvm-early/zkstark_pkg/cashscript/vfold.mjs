import { readFileSync } from 'fs';
import { Contract, MockNetworkProvider, randomUtxo, TransactionBuilder } from 'cashscript';
const art=JSON.parse(readFileSync('./frifold.json','utf8'));
const P=18446744069414584321n;
const mod=(a)=>((a%P)+P)%P;
const inv=(a)=>{let[r0,r1]=[mod(a),P],[s0,s1]=[1n,0n];while(r1){const q=r0/r1;[r0,r1]=[r1,r0-q*r1];[s0,s1]=[s1,s0-q*s1];}return mod(s0);};
const fpos=mod(123456789n),fneg=mod(987654321n),beta=mod(555n),x=mod(7n);
const inv2=inv(2n),inv2x=inv(mod(2n*x));
const expected=mod(mod((fpos+fneg)*inv2)+mod(mod(mod((fpos-fneg+P))*inv2x)*beta));
const provider=new MockNetworkProvider();
const c=new Contract(art,[P],{provider,addressType:'p2sh32'});
provider.addUtxo(c.address,{...randomUtxo(),satoshis:100000n});
async function run(tag,args){const u=await provider.getUtxos(c.address);
 try{await new TransactionBuilder({provider}).addInput(u[0],c.unlock.fold(...args)).addOutput({to:c.address,amount:90000n}).debug();
 console.log(tag+': ACCEPTED');}catch(e){console.log(tag+': REJECTED ('+(e.message||'').split('\n')[0].slice(0,50)+')');}}
console.log('redeem bytesize=',c.bytesize,'opcount=',c.opcount);
await run('correct fold+hints',[fpos,fneg,beta,x,inv2,inv2x,expected]);
await run('bad inverse hint',[fpos,fneg,beta,x,inv2,mod(inv2x+1n),expected]);
await run('wrong expected',[fpos,fneg,beta,x,inv2,inv2x,mod(expected+1n)]);
