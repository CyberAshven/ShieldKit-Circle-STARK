import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { minimalPush, primitives, roleInstance, structuralRedeem, structuralLock, RecomputeError } from '../recompute.mjs';

const H = (x) => createHash('sha256').update(x).digest();
const A = (x) => Buffer.from(x, 'ascii');
const U32 = (x) => { const b=Buffer.alloc(4); b.writeUInt32BE(x); return b; };
const U64 = (x) => { const b=Buffer.alloc(8); b.writeBigUInt64LE(BigInt(x)); return b; };
const LP = (x) => Buffer.concat([U32(x.length),x]);
const DH = (domain,...parts) => H(Buffer.concat([A(domain),Buffer.from([0]),...parts]));
const hx = (b) => b.toString('hex');
const Z32 = Buffer.alloc(32), Z8 = Buffer.alloc(8);
function roleMap(n, withdrawal) { return Buffer.concat([U32(0),U32(n+1),U32(0),Buffer.from([withdrawal?1:0]),U32(withdrawal?n+1:0),Buffer.from([1]),U32(withdrawal?n+2:n+1)]); }
function selfConstructedAction(action='DEPOSIT', withChange=false) {
  const n=1, anchor=Buffer.alloc(32,0x42), anchorIndex=9, p=primitives();
  const anchorDigest=DH('PoolActionFv2/pre-existing-anchor/v3',LP(anchor),LP(U32(anchorIndex)));
  const layout=Buffer.concat([U32(0),U32(1),U32(1),U64(500)]), depositMap=roleMap(n,false), withdrawalMap=roleMap(n,true);
  const identity=Buffer.concat([A('P3PI'),Buffer.from([0,3,0,0]),p.protocolTemplateDigest,anchorDigest,anchor,U64(10_000_000),U64(1_000_000),U64(10),U64(10_000),Buffer.from([0]),Z32,Buffer.from([1]),U32(n),layout,depositMap,withdrawalMap]);
  const pool=DH('PoolActionFv2/pool-instance/v3',LP(identity)); const ancestry=DH('PoolActionFv2/genesis-ancestry/v3',LP(anchorDigest),LP(pool),LP(anchor));
  const manifest=Buffer.concat([A('P3DM'),Buffer.from([0,3,0,0]),p.protocolTemplateDigest,pool,anchorDigest,ancestry,anchor,U64(10_000_000),U64(1_000_000),U64(10),U64(10_000),Buffer.from([0]),Z32,Buffer.from([1]),U32(n),layout,depositMap,withdrawalMap]);
  const state = (sequence,deposits,withdrawals,note,nullifier) => Buffer.concat([A('PAF1'),Buffer.from([1,0,0,0]),U64(sequence),U64(deposits),U64(withdrawals),pool,note,nullifier]);
  const isWithdrawal = action === 'WITHDRAWAL';
  const old=isWithdrawal?state(0,1,0,Buffer.alloc(32,0x23),Z32):state(0,0,0,Z32,Z32);
  const next=isWithdrawal?state(1,1,1,Buffer.alloc(32,0x23),Buffer.alloc(32,0x24)):state(1,1,0,Buffer.alloc(32,0x23),Z32);
  const stateRedeem=structuralRedeem(manifest,roleInstance(0,0,0,0)); const carrierRedeem=structuralRedeem(manifest,roleInstance(1,0,1,1));
  const stateLock=structuralLock(stateRedeem), carrierLock=structuralLock(carrierRedeem);
  const stateToken=(s)=>({categoryHex:hx(Buffer.concat([anchor,Buffer.from([0x01])])),commitmentHex:hx(s),amountHex:hx(Z8)});
  const none={categoryHex:'',commitmentHex:'',amountHex:hx(Z8)};
  const frame=Buffer.concat([A('P3SG'),Buffer.from([0,3]),U32(0),U32(1),U32(1),Buffer.from([0xaa])]); const carrierUnlock=Buffer.concat([minimalPush(frame),minimalPush(carrierRedeem)]);
  const predecessor=Buffer.alloc(32,0x91);
  const inRow=(outpoint, value, lock, token, unlock='', outpointHash=predecessor)=>({outpointIndexHex:hx(U64(outpoint)),outpointTxHashOpcodeOrderHex:hx(outpointHash),sequenceHex:'ffffffff00000000',sourceValueSatsHex:hx(U64(value)),sourceLockingBytecodeHex:hx(lock),token,unlockingBytecodeHex:unlock});
  const outRow=(value,lock,token)=>({valueSatsHex:hx(U64(value)),lockingBytecodeHex:hx(lock),token});
  const fee=1000, change=withChange?1000:0, oldValue=isWithdrawal?11_000_000:1_000_000, nextValue=isWithdrawal?1_000_000:11_000_000;
  const externalValue=isWithdrawal?change+fee:10_000_000+change+fee;
  const outputs=[outRow(nextValue,stateLock,stateToken(next)),outRow(500,carrierLock,none)];
  if(isWithdrawal) outputs.push(outRow(10_000_000,Buffer.from([0x51]),none));
  if(withChange) outputs.push(outRow(change,Buffer.from([0x51]),none));
  return {schema:'poolaction-fv2-recomputer-v3/raw-evidence-v1',manifestCoreHex:hx(manifest),anchor:{txHashOpcodeOrderHex:hx(anchor),outputIndexHex:hx(U32(anchorIndex))},interfaces:{sourceTableStatus:'NOT_SUPPLIED',provenanceStatus:'NOT_SUPPLIED'},transaction:{versionHex:'0200000000000000',locktimeHex:hx(Z8),stateActiveRedeemHex:hx(stateRedeem),inputs:[inRow(0,oldValue,stateLock,stateToken(old)),inRow(1,500,carrierLock,none,hx(carrierUnlock)),inRow(2,externalValue,Buffer.from([0x51]),none,'',Buffer.alloc(32,0x37))],outputs}};
}

test('self-constructed P3 templates are deterministic and ABI-v3 tagged', () => {
  const a = primitives(), b = primitives();
  assert.equal(a.structuralProgram.toString('hex'), '00000175020001750100');
  assert.deepEqual(a.templateSet, b.templateSet);
  assert.equal(a.protocolTemplateDigest.length, 32);
  assert.equal(a.templateSet.subarray(0, 6).toString('hex'), '503354530003');
});
test('minimal push boundaries are canonical', () => {
  assert.equal(minimalPush(Buffer.alloc(0)).toString('hex'), '00');
  assert.equal(minimalPush(Buffer.from([0x12])).toString('hex'), '0112');
  assert.equal(minimalPush(Buffer.alloc(76, 0x22)).subarray(0,2).toString('hex'), '4c4c');
});
test('role instances produce distinct P2SH20 locks', () => {
  const manifest = Buffer.from('5033444d0003', 'hex');
  const state = structuralRedeem(manifest, roleInstance(0,0,0,0));
  const carrier = structuralRedeem(manifest, roleInstance(1,0,1,1));
  const lock = structuralLock(state);
  assert.equal(lock.length, 23); assert.equal(lock[0], 0xa9); assert.equal(lock[1], 0x14); assert.equal(lock[22], 0x87);
  assert.notDeepEqual(structuralLock(state), structuralLock(carrier));
});
test('strict parser rejects unknown raw-evidence fields', async () => {
  const { recompute } = await import('../recompute.mjs');
  assert.throws(() => recompute({}), (e) => e instanceof RecomputeError && e.code === 'E_SCHEMA_TOP');
});
test('self-constructed N=1 deposit derives all structural roots but remains proof-rejected', async () => {
  const { recompute } = await import('../recompute.mjs');
  const result = recompute(selfConstructedAction());
  assert.equal(result.verdict, 'REJECT_UNSELECTED_PROOF_SUITE');
  assert.equal(result.derived.action, 'DEPOSIT');
  assert.equal(result.bytes.txViewHex.slice(0, 12), '503354560003');
  assert.equal(result.bytes.carrierRoleInstancesHex.length, 1);
  assert.equal(result.digests.sessionDigestHex.length, 64);
});
test('nativePrefixHex is unknown and cannot become token authority', async () => {
  const { recompute } = await import('../recompute.mjs');
  const evidence = selfConstructedAction();
  evidence.transaction.inputs[0].token.nativePrefixHex = '';
  assert.throws(() => recompute(evidence), (e) => e instanceof RecomputeError && e.code === 'E_TOKEN_SCHEMA');
});
test('all exact no-change and final-change topologies are structural-only', async () => {
  const { recompute } = await import('../recompute.mjs');
  for (const [action, withChange] of [['DEPOSIT',false],['DEPOSIT',true],['WITHDRAWAL',false],['WITHDRAWAL',true]]) {
    const result = recompute(selfConstructedAction(action,withChange));
    assert.equal(result.verdict, 'REJECT_UNSELECTED_PROOF_SUITE');
    assert.equal(result.derived.action, action);
  }
});
test('carrier source must share the state predecessor and state category excludes native prefix', async () => {
  const { recompute } = await import('../recompute.mjs');
  const wrongPredecessor = selfConstructedAction();
  wrongPredecessor.transaction.inputs[1].outpointTxHashOpcodeOrderHex = '77'.repeat(32);
  assert.throws(() => recompute(wrongPredecessor), (e) => e instanceof RecomputeError && e.code === 'E_CARRIER_PREDECESSOR');
  const nativePrefixedCategory = selfConstructedAction();
  nativePrefixedCategory.transaction.inputs[0].token.categoryHex = `ef${nativePrefixedCategory.anchor.txHashOpcodeOrderHex}`;
  assert.throws(() => recompute(nativePrefixedCategory), (e) => e instanceof RecomputeError && e.code === 'E_STATE_TOKEN');
});
test('state active redeem is exact comparison-only execution evidence', async () => {
  const { recompute } = await import('../recompute.mjs');
  const evidence = selfConstructedAction();
  evidence.transaction.stateActiveRedeemHex = `00${evidence.transaction.stateActiveRedeemHex.slice(2)}`;
  assert.throws(() => recompute(evidence), (e) => e instanceof RecomputeError && e.code === 'E_STATE_ACTIVE_REDEEM');
});
