import { Contract, MockNetworkProvider, SignatureTemplate, TransactionBuilder } from 'cashscript';
import { compileFile } from 'cashc';
import { secp256k1, sha256, ripemd160 } from '@bitauth/libauth';
const hash160 = (x) => ripemd160.hash(sha256.hash(x));
import { randomBytes as nodeRand } from 'crypto';
const randomBytes = (n) => new Uint8Array(nodeRand(n));
import { URL } from 'url';

const artifact = compileFile(new URL('./htlc.cash', import.meta.url));
const provider = new MockNetworkProvider();

function key() {
  let priv; do { priv = randomBytes(32); } while (secp256k1.validatePrivateKey(priv) !== true);
  const pub = secp256k1.derivePublicKeyCompressed(priv);
  return { priv, pub, pkh: hash160(pub) };
}
const recipient = key(), sender = key();
const secret = randomBytes(32);
const hashlock = sha256.hash(secret);
const timeout = 1000000n;

const htlc = new Contract(artifact, [recipient.pkh, sender.pkh, hashlock, timeout], { provider });
provider.addUtxo(htlc.address, { satoshis: 100000n, txid: '00'.repeat(32), vout: 0 });

async function tryClaim(sec, signer) {
  try {
    const utxo = (await htlc.getUtxos())[0];
    const tx = await new TransactionBuilder({ provider })
      .addInput(utxo, htlc.unlock.claim(signer.pub, new SignatureTemplate(signer.priv), sec))
      .addOutput({ to: htlc.address, amount: 99000n })
      .debug();
    return 'ACCEPTED';
  } catch (e) { return 'REJECTED (' + String(e.message).split('\n')[0].slice(0,60) + ')'; }
}
async function tryRefund(locktime) {
  try {
    const utxo = (await htlc.getUtxos())[0];
    const b = new TransactionBuilder({ provider })
      .addInput(utxo, htlc.unlock.refund(sender.pub, new SignatureTemplate(sender.priv)))
      .addOutput({ to: htlc.address, amount: 99000n });
    b.setLocktime(locktime);
    await b.debug();
    return 'ACCEPTED';
  } catch (e) { return 'REJECTED (' + String(e.message).split('\n')[0].slice(0,60) + ')'; }
}

console.log('HTLC address:', htlc.address.slice(0,24)+'...');
console.log('claim, correct secret + recipient sig :', await tryClaim(secret, recipient));
console.log('claim, wrong secret                   :', await tryClaim(randomBytes(32), recipient));
console.log('claim, correct secret + wrong signer  :', await tryClaim(secret, sender));
console.log('refund before timeout (locktime 500k) :', await tryRefund(500000));
console.log('refund after timeout  (locktime 1.0M) :', await tryRefund(1000000));
