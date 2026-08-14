/*
 * Standalone structural recomputer derived from the ABI-v3 charter only.
 * It is intentionally dependency-free and deliberately proof/VM blind.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const MAX = 2_100_000_000_000_000n;
const RUNTIME_MAX = 0x7fff_ffff_ffff_ffffn;
const TICKET = 10_000_000n;
const ZERO32 = Buffer.alloc(32);
const ZERO8 = Buffer.alloc(8);
export class RecomputeError extends Error { constructor(code, detail = '') { super(`${code}${detail ? `: ${detail}` : ''}`); this.code = code; } }
const fail = (code, detail) => { throw new RecomputeError(code, detail); };
const ascii = (s) => Buffer.from(s, 'ascii');
const eq = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
const hex = (b) => Buffer.from(b).toString('hex');
const sha256 = (b) => createHash('sha256').update(b).digest();
const hash160 = (b) => createHash('ripemd160').update(sha256(b)).digest();
const domHash = (domain, ...parts) => sha256(Buffer.concat([ascii(domain), Buffer.from([0]), ...parts]));
const lp = (b) => Buffer.concat([u32be(b.length), b]);
const u16be = (n) => { if (!Number.isInteger(n) || n < 0 || n > 0xffff) fail('E_U16_RANGE'); const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32be = (n) => { if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) fail('E_U32_RANGE'); const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64le = (n) => { if (typeof n !== 'bigint' || n < 0n || n > 0xffff_ffff_ffff_ffffn) fail('E_U64_RANGE'); const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
function rawHex(v, bytes, code = 'E_HEX') { if (typeof v !== 'string' || !/^[0-9a-f]*$/.test(v) || v.length !== bytes * 2) fail(code); return Buffer.from(v, 'hex'); }
function rawVarHex(v, code = 'E_HEX') { if (typeof v !== 'string' || !/^[0-9a-f]*$/.test(v) || v.length % 2) fail(code); return Buffer.from(v, 'hex'); }
function le8Hex(v, code = 'E_U64_HEX') { const b = rawHex(v, 8, code); return b.readBigUInt64LE(); }
function runtimeLe8(v, code = 'E_RUNTIME_RANGE') { const n = le8Hex(v, code); if (n > RUNTIME_MAX) fail(code); return n; }
function moneyLe8(v, code = 'E_MONEY_RANGE') { const n = le8Hex(v, code); if (n > MAX) fail(code); return n; }
function nonzero32(b, code) { if (eq(b, ZERO32)) fail(code); }
function object(x, keys, code = 'E_SCHEMA_OBJECT') { if (!x || Array.isArray(x) || typeof x !== 'object') fail(code); const actual = Object.keys(x).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((k, i) => k !== expected[i])) fail(code, `keys=${actual.join(',')}`); return x; }
function arr(x, code = 'E_SCHEMA_ARRAY') { if (!Array.isArray(x)) fail(code); return x; }
function readU16(b, p) { if (p + 2 > b.length) fail('E_PARSE_TRUNCATED'); return b.readUInt16BE(p); }
function readU32(b, p) { if (p + 4 > b.length) fail('E_PARSE_TRUNCATED'); return b.readUInt32BE(p); }
function readU64(b, p) { if (p + 8 > b.length) fail('E_PARSE_TRUNCATED'); return b.readBigUInt64LE(p); }
function take(b, p, n) { if (p + n > b.length) fail('E_PARSE_TRUNCATED'); return b.subarray(p, p + n); }
function requireEq(a, b, code) { if (typeof a === 'bigint' || typeof b === 'bigint') { if (a !== b) fail(code); } else if (Buffer.isBuffer(a)) { if (!eq(a, b)) fail(code); } else if (a !== b) fail(code); }

export function minimalPush(data) {
  if (!Buffer.isBuffer(data)) fail('E_PUSH_DATA');
  const n = data.length;
  if (n === 0) return Buffer.from([0]);
  if (n === 1 && data[0] >= 1 && data[0] <= 16) return Buffer.from([0x50 + data[0]]);
  if (n === 1 && data[0] === 0x81) return Buffer.from([0x4f]);
  if (n <= 75) return Buffer.concat([Buffer.from([n]), data]);
  if (n <= 255) return Buffer.concat([Buffer.from([0x4c, n]), data]);
  if (n <= 65535) { const h = Buffer.alloc(3); h[0] = 0x4d; h.writeUInt16LE(n, 1); return Buffer.concat([h, data]); }
  fail('E_PUSH_OVERSIZE');
}
function parsePush(b, p) {
  if (p >= b.length) fail('E_PUSH_TRUNCATED');
  const op = b[p]; let n; let head;
  if (op === 0) return { data: Buffer.alloc(0), end: p + 1 };
  if (op >= 1 && op <= 75) { n = op; head = 1; }
  else if (op === 0x4c) { if (p + 2 > b.length) fail('E_PUSH_TRUNCATED'); n = b[p + 1]; head = 2; if (n < 76) fail('E_NONMINIMAL_PUSH'); }
  else if (op === 0x4d) { if (p + 3 > b.length) fail('E_PUSH_TRUNCATED'); n = b.readUInt16LE(p + 1); head = 3; if (n <= 255) fail('E_NONMINIMAL_PUSH'); }
  else fail('E_PUSH_OPCODE');
  const data = take(b, p + head, n); if (n === 1 && (data[0] >= 1 && data[0] <= 16 || data[0] === 0x81)) fail('E_NONMINIMAL_PUSH');
  return { data, end: p + head + n };
}

export function primitives() {
  const program = Buffer.from('00000175020001750100', 'hex');
  const roleTemplate = (roleClass) => Buffer.concat([ascii('P3RT'), u16be(3), Buffer.from([roleClass, 5]), program]);
  const state = roleTemplate(0), carrier = roleTemplate(1);
  const set = Buffer.concat([ascii('P3TS'), u16be(3), lp(ascii('poolaction-fv2-structural-compiler-v3')), lp(state), lp(carrier)]);
  return { structuralProgram: program, stateTemplate: state, carrierTemplate: carrier, templateSet: set, protocolTemplateDigest: domHash('PoolActionFv2/protocol-template/v3', lp(set)) };
}
export function roleInstance(roleTag, ordinal, inputIndex, outputIndex) { return Buffer.concat([ascii('P3RI'), u16be(3), Buffer.from([roleTag]), u32be(ordinal), u32be(inputIndex), u32be(outputIndex)]); }
export function structuralRedeem(manifest, instance) { return Buffer.concat([minimalPush(manifest), Buffer.from([0x75]), minimalPush(instance), Buffer.from([0x75, 0x00])]); }
export function structuralLock(redeem) { return Buffer.concat([Buffer.from([0xa9, 0x14]), hash160(redeem), Buffer.from([0x87])]); }

function parseManifest(bytes) {
  let p = 0; const magic = take(bytes, p, 4); p += 4; if (!eq(magic, ascii('P3DM')) || readU16(bytes, p) !== 3) fail('E_MANIFEST_HEADER'); p += 2;
  const networkTag = take(bytes, p++, 1)[0]; if (networkTag > 2 || bytes[p++] !== 0) fail('E_MANIFEST_NETWORK');
  const protocolTemplateDigest = take(bytes, p, 32); p += 32; const poolInstanceId = take(bytes, p, 32); p += 32;
  const preExistingAnchorDigest = take(bytes, p, 32); p += 32; const genesisAncestryDigest = take(bytes, p, 32); p += 32; const stateCategoryWire = take(bytes, p, 32); p += 32;
  const ticketSats = readU64(bytes, p); p += 8; const stateCarrierBaseSats = readU64(bytes, p); p += 8; const maxLifetimeDeposits = readU64(bytes, p); p += 8; const feePolicyMaxSats = readU64(bytes, p); p += 8;
  const proofSuiteStatus = bytes[p++]; const proofSuiteManifestDigest = take(bytes, p, 32); p += 32; const noUpgrade = bytes[p++]; const n = readU32(bytes, p); p += 4;
  if (n < 1 || n > 483) fail('E_MANIFEST_CARRIER_COUNT'); if (ticketSats !== TICKET || noUpgrade !== 1) fail('E_MANIFEST_FIXED');
  if (stateCarrierBaseSats > MAX || feePolicyMaxSats > MAX || maxLifetimeDeposits < 1n || maxLifetimeDeposits > RUNTIME_MAX) fail('E_MANIFEST_RANGE');
  if (stateCarrierBaseSats + maxLifetimeDeposits * TICKET > MAX) fail('E_MANIFEST_CAPACITY');
  if (!((proofSuiteStatus === 0 && eq(proofSuiteManifestDigest, ZERO32)) || (proofSuiteStatus === 1 && !eq(proofSuiteManifestDigest, ZERO32)))) fail('E_SUITE_STATUS_DIGEST');
  const carriers = []; for (let i = 0; i < n; i++) { const ordinal = readU32(bytes,p); p+=4; const inputIndex=readU32(bytes,p);p+=4; const outputIndex=readU32(bytes,p);p+=4; const expectedValueSats=readU64(bytes,p);p+=8; if (ordinal!==i||inputIndex!==i+1||outputIndex!==i+1||expectedValueSats>MAX) fail('E_CARRIER_LAYOUT'); carriers.push({ordinal,inputIndex,outputIndex,expectedValueSats}); }
  const maps = []; for (let m = 0; m < 2; m++) { const stateInputIndex=readU32(bytes,p);p+=4; const externalInputIndex=readU32(bytes,p);p+=4; const stateOutputIndex=readU32(bytes,p);p+=4; const payoutPresent=bytes[p++]; const payoutOutputIndex=readU32(bytes,p);p+=4; const changeOptional=bytes[p++]; const changeOutputIndex=readU32(bytes,p);p+=4; maps.push({stateInputIndex,externalInputIndex,stateOutputIndex,payoutPresent,payoutOutputIndex,changeOptional,changeOutputIndex}); }
  if (p !== bytes.length) fail('E_MANIFEST_TRAILING');
  const [depositMap, withdrawalMap] = maps; const expectedDeposit={stateInputIndex:0,externalInputIndex:n+1,stateOutputIndex:0,payoutPresent:0,payoutOutputIndex:0,changeOptional:1,changeOutputIndex:n+1}; const expectedWithdrawal={stateInputIndex:0,externalInputIndex:n+1,stateOutputIndex:0,payoutPresent:1,payoutOutputIndex:n+1,changeOptional:1,changeOutputIndex:n+2};
  for (const [actual, expected] of [[depositMap,expectedDeposit],[withdrawalMap,expectedWithdrawal]]) for (const k of Object.keys(expected)) if (actual[k] !== expected[k]) fail('E_ROLE_MAP');
  const m = {bytes,networkTag,protocolTemplateDigest,poolInstanceId,preExistingAnchorDigest,genesisAncestryDigest,stateCategoryWire,ticketSats,stateCarrierBaseSats,maxLifetimeDeposits,feePolicyMaxSats,proofSuiteStatus,proofSuiteManifestDigest,noUpgrade,n,carriers,depositMap,withdrawalMap};
  const idBytes = Buffer.concat([ascii('P3PI'),u16be(3),Buffer.from([networkTag,0]),protocolTemplateDigest,preExistingAnchorDigest,stateCategoryWire,u64le(ticketSats),u64le(stateCarrierBaseSats),u64le(maxLifetimeDeposits),u64le(feePolicyMaxSats),Buffer.from([proofSuiteStatus]),proofSuiteManifestDigest,Buffer.from([noUpgrade]),u32be(n),...carriers.map(c=>Buffer.concat([u32be(c.ordinal),u32be(c.inputIndex),u32be(c.outputIndex),u64le(c.expectedValueSats)])),encodeRoleMap(depositMap),encodeRoleMap(withdrawalMap)]);
  m.poolIdentityConfigBytes=idBytes; m.recomputedPoolInstanceId=domHash('PoolActionFv2/pool-instance/v3',lp(idBytes));
  requireEq(m.poolInstanceId,m.recomputedPoolInstanceId,'E_POOL_ID'); return m;
}
function encodeRoleMap(x) { return Buffer.concat([u32be(x.stateInputIndex),u32be(x.externalInputIndex),u32be(x.stateOutputIndex),Buffer.from([x.payoutPresent]),u32be(x.payoutOutputIndex),Buffer.from([x.changeOptional]),u32be(x.changeOutputIndex)]); }
function parseState(b, manifest) {
  if (b.length!==128 || !eq(b.subarray(0,4),ascii('PAF1')) || b.readUInt16LE(4)!==1 || b[6]!==0 || b[7]!==0) fail('E_STATE_CODEC');
  const sequence=b.readBigUInt64LE(8), depositCount=b.readBigUInt64LE(16), withdrawalCount=b.readBigUInt64LE(24); if ([sequence,depositCount,withdrawalCount].some(x=>x>RUNTIME_MAX)) fail('E_STATE_RUNTIME_RANGE');
  const poolInstanceId=b.subarray(32,64), noteRoot=b.subarray(64,96), nullifierRoot=b.subarray(96,128); requireEq(poolInstanceId,manifest.poolInstanceId,'E_STATE_POOL_ID');
  if (withdrawalCount>depositCount||depositCount>manifest.maxLifetimeDeposits) fail('E_STATE_COUNT_ORDER'); const outstanding=depositCount-withdrawalCount; const reserve=outstanding*TICKET; const value=manifest.stateCarrierBaseSats+reserve; if(value>MAX) fail('E_STATE_VALUE');
  return {bytes:b,sequence,depositCount,withdrawalCount,poolInstanceId,noteRoot,nullifierRoot,value};
}
function parseToken(x) { object(x,['amountHex','categoryHex','commitmentHex'],'E_TOKEN_SCHEMA'); return {category:rawVarHex(x.categoryHex,'E_TOKEN_CATEGORY'),commitment:rawVarHex(x.commitmentHex,'E_TOKEN_COMMITMENT'),amount:le8Hex(x.amountHex,'E_TOKEN_AMOUNT')}; }
function tokenObservation(t) { if(t.category.length>0xffff||t.commitment.length>0xffff) fail('E_TOKEN_LENGTH'); return Buffer.concat([Buffer.from([0]),u16be(t.category.length),t.category,u16be(t.commitment.length),t.commitment,u64le(t.amount)]); }
function stateObservation(t) { if(t.category.length>0xffff||t.commitment.length>0xffff) fail('E_TOKEN_LENGTH'); return Buffer.concat([Buffer.from([1]),u16be(t.category.length),t.category,u16be(t.commitment.length),t.commitment,u64le(t.amount)]); }
function requireNone(t) { if (t.category.length||t.commitment.length||t.amount!==0n) fail('E_TOKEN_NOT_NONE'); }
function requireStateToken(t, manifest, stateBytes) { const expectedCategory=Buffer.concat([manifest.stateCategoryWire,Buffer.from([0x01])]); if(!eq(t.category,expectedCategory)||t.commitment.length!==128||!eq(t.commitment,stateBytes)||t.amount!==0n) fail('E_STATE_TOKEN'); return Buffer.concat([Buffer.from([1]),u16be(t.category.length),t.category,u16be(t.commitment.length),t.commitment,u64le(t.amount)]); }
function validateRaw(e) {
  object(e,['anchor','interfaces','manifestCoreHex','schema','transaction'],'E_SCHEMA_TOP'); if(e.schema!=='poolaction-fv2-recomputer-v3/raw-evidence-v1') fail('E_SCHEMA_VERSION');
  object(e.anchor,['outputIndexHex','txHashOpcodeOrderHex']); const anchor={outputIndex:readU32(rawHex(e.anchor.outputIndexHex,4,'E_ANCHOR_INDEX'),0),txHash:rawHex(e.anchor.txHashOpcodeOrderHex,32,'E_ANCHOR_HASH')};
  object(e.interfaces,['provenanceStatus','sourceTableStatus']); for(const k of ['provenanceStatus','sourceTableStatus']) if(!['NOT_SUPPLIED','SUPPLIED_UNVERIFIED'].includes(e.interfaces[k])) fail('E_INTERFACE_STATUS');
  object(e.transaction,['inputs','locktimeHex','outputs','stateActiveRedeemHex','versionHex']); const tx={version:le8Hex(e.transaction.versionHex,'E_TX_VERSION'),locktime:le8Hex(e.transaction.locktimeHex,'E_TX_LOCKTIME'),stateActiveRedeem:rawVarHex(e.transaction.stateActiveRedeemHex,'E_STATE_ACTIVE_REDEEM'),inputs:arr(e.transaction.inputs),outputs:arr(e.transaction.outputs)};
  if(tx.stateActiveRedeem.length>10000) fail('E_SCRIPT_LIMIT');
  if(tx.version!==2n||tx.locktime!==0n) fail('E_TX_CONSTANT');
  const inKeys=['outpointIndexHex','outpointTxHashOpcodeOrderHex','sequenceHex','sourceLockingBytecodeHex','sourceValueSatsHex','token','unlockingBytecodeHex'];
  tx.inputs=tx.inputs.map((x,i)=>{object(x,inKeys); const outpointIndex=le8Hex(x.outpointIndexHex,'E_INPUT_OUTPOINT'); const sequence=le8Hex(x.sequenceHex,'E_INPUT_SEQUENCE'); const sourceValue=moneyLe8(x.sourceValueSatsHex,'E_INPUT_VALUE'); const sourceLock=rawVarHex(x.sourceLockingBytecodeHex,'E_INPUT_LOCK'), unlock=rawVarHex(x.unlockingBytecodeHex,'E_INPUT_UNLOCK'); if(sequence!==4294967295n) fail('E_TX_SEQUENCE'); if(sourceLock.length>10000||unlock.length>10000) fail('E_SCRIPT_LIMIT'); return {outpointIndex,outpointHash:rawHex(x.outpointTxHashOpcodeOrderHex,32,'E_INPUT_HASH'),sequence,sourceValue,sourceLock,token:parseToken(x.token),unlock,wireIndex:i};});
  const outKeys=['lockingBytecodeHex','token','valueSatsHex']; tx.outputs=tx.outputs.map((x,i)=>{object(x,outKeys); const lock=rawVarHex(x.lockingBytecodeHex,'E_OUTPUT_LOCK'); if(lock.length>10000) fail('E_SCRIPT_LIMIT'); return {value:moneyLe8(x.valueSatsHex,'E_OUTPUT_VALUE'),lock,token:parseToken(x.token),wireIndex:i};});
  return {manifestBytes:rawVarHex(e.manifestCoreHex,'E_MANIFEST_HEX'),anchor,interfaces:e.interfaces,tx};
}
function parseRedeem(redeem, manifest, instance) { let p=0; const a=parsePush(redeem,p);p=a.end; requireEq(a.data,manifest.bytes,'E_REDEEM_MANIFEST'); if(redeem[p++]!==0x75) fail('E_REDEEM_DROP'); const b=parsePush(redeem,p);p=b.end; requireEq(b.data,instance,'E_REDEEM_ROLE'); if(redeem[p++]!==0x75||redeem[p++]!==0||p!==redeem.length) fail('E_REDEEM_SUFFIX'); }
function inspectCarrierUnlock(unlock, manifest, instance, ordinal, inputIndex) { if(unlock.length>10000) fail('E_SCRIPT_LIMIT'); let p=0; const framePush=parsePush(unlock,p);p=framePush.end; const redeemPush=parsePush(unlock,p);p=redeemPush.end; if(p!==unlock.length) fail('E_CARRIER_UNLOCK_SUFFIX'); parseRedeem(redeemPush.data,manifest,instance); const f=framePush.data; if(f.length<18||!eq(f.subarray(0,4),ascii('P3SG'))||f.readUInt16BE(4)!==3||f.readUInt32BE(6)!==ordinal||f.readUInt32BE(10)!==inputIndex) fail('E_FRAME_HEADER'); const n=f.readUInt32BE(14); if(n===0||18+n!==f.length) fail('E_FRAME_LENGTH'); return {payload:f.subarray(18),frame:f,redeem:redeemPush.data}; }
function roleLockCheck(actual, redeem) { if(actual.length>10000||redeem.length>10000) fail('E_SCRIPT_LIMIT'); requireEq(actual,structuralLock(redeem),'E_LOCK_MISMATCH'); }
function derive(manifest, raw) {
  const {tx,anchor}=raw; const n=manifest.n; if(tx.inputs.length!==n+2) fail('E_INPUT_COUNT'); if(tx.inputs[0].outpointIndex!==0n) fail('E_STATE_OUTPOINT');
  const p=primitives(); requireEq(manifest.protocolTemplateDigest,p.protocolTemplateDigest,'E_TEMPLATE_DIGEST'); const anchorDigest=domHash('PoolActionFv2/pre-existing-anchor/v3',lp(anchor.txHash),lp(u32be(anchor.outputIndex))); requireEq(manifest.preExistingAnchorDigest,anchorDigest,'E_ANCHOR_DIGEST'); requireEq(manifest.stateCategoryWire,anchor.txHash,'E_STATE_CATEGORY'); const ancestry=domHash('PoolActionFv2/genesis-ancestry/v3',lp(anchorDigest),lp(manifest.poolInstanceId),lp(manifest.stateCategoryWire)); requireEq(manifest.genesisAncestryDigest,ancestry,'E_ANCESTRY_DIGEST');
  if(manifest.bytes.length>10000) fail('E_SCRIPT_LIMIT'); const stateInstance=roleInstance(0,0,0,0), stateRedeem=structuralRedeem(manifest.bytes,stateInstance), stateLock=structuralLock(stateRedeem); requireEq(tx.stateActiveRedeem,stateRedeem,'E_STATE_ACTIVE_REDEEM'); roleLockCheck(tx.inputs[0].sourceLock,stateRedeem); const oldState=parseState(tx.inputs[0].token.commitment,manifest); requireStateToken(tx.inputs[0].token,manifest,oldState.bytes); if(tx.inputs[0].sourceValue!==oldState.value) fail('E_STATE_SOURCE_VALUE');
  const carrier=[]; for(let i=0;i<n;i++){const input=tx.inputs[i+1], c=manifest.carriers[i], instance=roleInstance(1,i,i+1,i+1), redeem=structuralRedeem(manifest.bytes,instance); if(input.outpointIndex!==BigInt(i+1)) fail('E_CARRIER_OUTPOINT'); requireEq(input.outpointHash,tx.inputs[0].outpointHash,'E_CARRIER_PREDECESSOR'); roleLockCheck(input.sourceLock,redeem); if(input.sourceValue!==c.expectedValueSats) fail('E_CARRIER_VALUE'); requireNone(input.token); carrier.push({input,instance,redeem,lock:structuralLock(redeem),...inspectCarrierUnlock(input.unlock,manifest,instance,i,i+1)}); }
  const successor=tx.outputs[0]; roleLockCheck(successor.lock,stateRedeem); const newState=parseState(successor.token.commitment,manifest); requireStateToken(successor.token,manifest,newState.bytes); if(successor.value!==newState.value) fail('E_STATE_SUCCESSOR_VALUE'); for(let i=0;i<n;i++){const output=tx.outputs[i+1], c=carrier[i]; requireEq(output.lock,c.lock,'E_CARRIER_SUCCESSOR_LOCK'); if(output.value!==manifest.carriers[i].expectedValueSats) fail('E_CARRIER_SUCCESSOR_VALUE'); requireNone(output.token); }
  const delta=newState.value-oldState.value; const action=delta===TICKET?'DEPOSIT':delta===-TICKET?'WITHDRAWAL':null; if(!action) fail('E_ACTION_DELTA'); const baseOutputCount=n+(action==='DEPOSIT'?1:2); if(tx.outputs.length!==baseOutputCount&&tx.outputs.length!==baseOutputCount+1) fail('E_OUTPUT_COUNT'); if(oldState.sequence>=RUNTIME_MAX||newState.sequence!==oldState.sequence+1n) fail('E_STATE_SEQUENCE');
  if(action==='DEPOSIT'){if(oldState.depositCount>=manifest.maxLifetimeDeposits||newState.depositCount!==oldState.depositCount+1n||newState.withdrawalCount!==oldState.withdrawalCount||eq(newState.noteRoot,oldState.noteRoot)||eq(newState.noteRoot,ZERO32)||!eq(newState.nullifierRoot,oldState.nullifierRoot)) fail('E_DEPOSIT_TRANSITION');} else {if(newState.depositCount!==oldState.depositCount||newState.withdrawalCount!==oldState.withdrawalCount+1n||!eq(newState.noteRoot,oldState.noteRoot)||eq(newState.nullifierRoot,oldState.nullifierRoot)||eq(newState.nullifierRoot,ZERO32)) fail('E_WITHDRAWAL_TRANSITION'); const payout=tx.outputs[n+1]; if(payout.value!==TICKET) fail('E_PAYOUT_VALUE'); requireNone(payout.token);}
  const external=tx.inputs[n+1]; requireNone(external.token); const changeIndex=action==='DEPOSIT'?n+1:n+2; const change=tx.outputs.length===changeIndex+1?tx.outputs[changeIndex]:null; if(change) requireNone(change.token); const inSum=tx.inputs.reduce((s,x)=>s+x.sourceValue,0n), outSum=tx.outputs.reduce((s,x)=>s+x.value,0n); if(inSum>MAX||outSum>MAX||inSum<outSum) fail('E_CONSERVATION'); const fee=inSum-outSum; if(fee>manifest.feePolicyMaxSats) fail('E_FEE'); if(action==='DEPOSIT'&&external.sourceValue!==TICKET+(change?change.value:0n)+fee) fail('E_DEPOSIT_FUNDING'); if(action==='WITHDRAWAL'&&external.sourceValue!==(change?change.value:0n)+fee) fail('E_WITHDRAWAL_FUNDING');
  const txView=buildTxView(manifest,tx,action,fee,change); const frames=carrier.map(c=>c.frame), payloads=carrier.map(c=>c.payload); const sessionBytes=Buffer.concat([u32be(n),...carrier.map((c,i)=>Buffer.concat([u32be(i),u32be(i+1),lp(c.input.unlock)]))]); const offsets=[];let o=0;for(const x of payloads){offsets.push(o);o+=x.length;} const schedule=Buffer.concat([u32be(n),...payloads.map((x,i)=>Buffer.concat([u32be(i),u32be(i+1),u32be(offsets[i]),u32be(x.length)]))]); const envelope=Buffer.concat(payloads); const deployment=domHash('PoolActionFv2/deployment/v3',lp(manifest.bytes)); const context=domHash('PoolActionFv2/context/v3',lp(deployment),lp(txView)); const carrierRoot=domHash('PoolActionFv2/carrier-session/v3',lp(sessionBytes)); const envelopeRoot=domHash('PoolActionFv2/envelope/v3',lp(envelope)); const session=domHash('PoolActionFv2/session/v3',lp(context),lp(carrierRoot),lp(envelopeRoot),lp(schedule),lp(manifest.proofSuiteManifestDigest));
  return {p,anchorDigest,ancestry,stateRedeem,stateLock,carrier,oldState,newState,action,fee,change,txView,frames,sessionBytes,envelope,schedule,deployment,context,carrierRoot,envelopeRoot,session};
}
function buildTxView(m,tx,action,fee,change){ const inRecords=tx.inputs.map((x,i)=>{const tag=i===0?0:i<=m.n?1:action==='DEPOSIT'?2:3;const ord=i>=1&&i<=m.n?i-1:0;const disposition=i===0?0:i<=m.n?1:2;const observation=i===0?stateObservation(x.token):tokenObservation(x.token);return Buffer.concat([u32be(i),Buffer.from([tag]),u32be(ord),x.outpointHash,u64le(x.outpointIndex),u64le(x.sequence),u64le(x.sourceValue),lp(x.sourceLock),observation,Buffer.from([disposition])]);}); const outRecords=tx.outputs.map((x,i)=>{const tag=i===0?0x10:i<=m.n?0x11:action==='WITHDRAWAL'&&i===m.n+1?0x12:0x13;const ord=i>=1&&i<=m.n?i-1:0;const observation=i===0?stateObservation(x.token):tokenObservation(x.token);return Buffer.concat([u32be(i),Buffer.from([tag]),u32be(ord),u64le(x.value),lp(x.lock),observation]);}); const payoutPresent=action==='WITHDRAWAL'?1:0;const payoutIndex=payoutPresent?m.n+1:0;const changePresent=change?1:0;const changeIndex=change?action==='DEPOSIT'?m.n+1:m.n+2:0;return Buffer.concat([ascii('P3TV'),u16be(3),Buffer.from([action==='DEPOSIT'?0:1,0]),u64le(tx.version),u64le(tx.locktime),u32be(m.n),u32be(tx.inputs.length),...inRecords,u32be(tx.outputs.length),...outRecords,u64le(TICKET),Buffer.from([action==='DEPOSIT'?0:1]),u64le(fee),u64le(m.feePolicyMaxSats),Buffer.from([payoutPresent]),u32be(payoutIndex),Buffer.from([changePresent]),u32be(changeIndex)]); }
function canonical(x){if(Buffer.isBuffer(x))return hex(x);if(typeof x==='bigint')return x.toString();if(Array.isArray(x))return x.map(canonical);if(x&&typeof x==='object')return Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])]));return x;}
export function recompute(evidence){ const raw=validateRaw(evidence), manifest=parseManifest(raw.manifestBytes); if(manifest.proofSuiteStatus!==0) fail('E_SUITE_NOT_UNSELECTED'); const d=derive(manifest,raw); const result={schema:'poolaction-fv2-recomputer-v3/result-v1',relationId:'PoolActionFv2',relationVersion:2,abiVersion:3,verdict:'REJECT_UNSELECTED_PROOF_SUITE',verdictCode:'REJECT_UNSELECTED_PROOF_SUITE',interfaces:{sourceTable:raw.interfaces.sourceTableStatus==='SUPPLIED_UNVERIFIED'?'UNVERIFIED_NO_CHARTER_ROSTER':'REQUIRES_PACKAGE_SOURCE_TABLE',provenance:raw.interfaces.provenanceStatus==='SUPPLIED_UNVERIFIED'?'UNVERIFIED_NO_PACKAGE_SCHEMA':'REQUIRES_PACKAGE_PROVENANCE_SCHEMA'},bytes:{structuralProgramHex:hex(d.p.structuralProgram),stateTemplateHex:hex(d.p.stateTemplate),carrierTemplateHex:hex(d.p.carrierTemplate),templateSetHex:hex(d.p.templateSet),poolIdentityConfigHex:hex(manifest.poolIdentityConfigBytes),manifestCoreHex:hex(manifest.bytes),stateRoleInstanceHex:hex(roleInstance(0,0,0,0)),stateRedeemHex:hex(d.stateRedeem),stateLockHex:hex(d.stateLock),carrierRoleInstancesHex:d.carrier.map(c=>hex(c.instance)),carrierRedeemsHex:d.carrier.map(c=>hex(c.redeem)),carrierLocksHex:d.carrier.map(c=>hex(c.lock)),carrierFramesHex:d.frames.map(hex),txViewHex:hex(d.txView),carrierSessionHex:hex(d.sessionBytes),envelopeHex:hex(d.envelope),scheduleHex:hex(d.schedule)},digests:{protocolTemplateDigestHex:hex(d.p.protocolTemplateDigest),anchorDigestHex:hex(d.anchorDigest),poolInstanceIdHex:hex(manifest.poolInstanceId),genesisAncestryDigestHex:hex(d.ancestry),deploymentCommitmentHex:hex(d.deployment),contextDigestHex:hex(d.context),carrierSessionRootHex:hex(d.carrierRoot),envelopeRootHex:hex(d.envelopeRoot),sessionDigestHex:hex(d.session)},derived:{action:d.action,feeSats:d.fee.toString(),carrierCount:manifest.n,oldState:{sequence:d.oldState.sequence.toString(),depositCount:d.oldState.depositCount.toString(),withdrawalCount:d.oldState.withdrawalCount.toString()},newState:{sequence:d.newState.sequence.toString(),depositCount:d.newState.depositCount.toString(),withdrawalCount:d.newState.withdrawalCount.toString()}}}; return canonical(result); }
if (import.meta.url === `file://${process.argv[1]}`) { try { if(process.argv.length!==3) fail('E_USAGE','node recompute.mjs raw-evidence.json'); const input=JSON.parse(readFileSync(process.argv[2],'utf8')); process.stdout.write(`${JSON.stringify(recompute(input))}\n`); } catch(e) { const out={schema:'poolaction-fv2-recomputer-v3/error-v1',verdict:'REJECT',code:e instanceof RecomputeError?e.code:'E_INTERNAL'}; process.stderr.write(`${JSON.stringify(out)}\n`); process.exitCode=1; } }
