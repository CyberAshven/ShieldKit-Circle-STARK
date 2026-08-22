import { evalScript } from './run.mjs';
const P=18446744069414584321n, omegaN=1803076106186727246n;
const mp=(b,e,m)=>{let r=1n;b%=m;while(e>0n){if(e&1n)r=r*b%m;b=b*b%m;e>>=1n;}return r;};
const Ph='<0x01000000ffffffff00>';
const MODEXP = `
OP_TOALTSTACK OP_TOALTSTACK OP_1 OP_FROMALTSTACK OP_FROMALTSTACK
OP_BEGIN
  OP_DUP OP_2 OP_DIV OP_TOALTSTACK
  OP_2 OP_MOD
  OP_IF
    OP_DUP OP_ROT OP_MUL ${Ph} OP_MOD OP_SWAP
  OP_ENDIF
  OP_DUP OP_MUL ${Ph} OP_MOD
  OP_FROMALTSTACK
  OP_DUP OP_0 OP_NUMEQUAL
OP_UNTIL
OP_2DROP`;
for(const e of [0n,1n,2n,3n,98n,354n,511n]){
  const exp=mp(omegaN,e,P);
  try{ const r=evalScript('', `<${omegaN}> <${e}> ${MODEXP} <${exp}> OP_EQUAL`);
    console.log('omegaN^'+e+' :', r.ok?'ACCEPTED':('REJECTED '+(r.error||'').slice(0,50))); }
  catch(err){ console.log('omegaN^'+e+' ERR', err.message.slice(0,60)); }
}
