#!/usr/bin/env node
/*
 * PoolActionFv2 structural recomputer A.  This is deliberately self-contained:
 * it parses BCH-style transaction/source-output bytes and does not import any
 * Fv1 digest oracle or a caller supplied derived value.
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const H = (x) => createHash("sha256").update(x).digest();
const A = (s) => Buffer.from(s, "ascii");
const lp = (x) => Buffer.concat([be32(x.length), x]);
const domain = (s, ...xs) => H(Buffer.concat([A(s), Buffer.of(0), ...xs.map(lp)]));
const be32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const le32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const le64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const hex = (x, name) => {
  if (typeof x !== "string" || !/^[0-9a-f]*$/.test(x) || x.length % 2) throw new TypeError(`${name} must be lowercase even hex`);
  return Buffer.from(x, "hex");
};
const u64 = (x, name) => {
  if (typeof x !== "string" || !/^(0|[1-9][0-9]*)$/.test(x)) throw new TypeError(`${name} must be canonical decimal`);
  const n = BigInt(x); if (n > 0xffffffffffffffffn) throw new TypeError(`${name} exceeds uint64`); return n;
};
const same = (a, b, name) => { if (!a.equals(b)) throw new TypeError(`${name} differs`); };

class R {
  constructor(b, n) { this.b = b; this.n = n; this.o = 0; }
  take(n, f) { if (!Number.isSafeInteger(n) || n < 0 || this.o + n > this.b.length) throw new TypeError(`${this.n}.${f} truncated`); const x = this.b.subarray(this.o, this.o + n); this.o += n; return x; }
  u8(f) { return this.take(1, f)[0]; }
  u32(f) { return this.take(4, f).readUInt32LE(); }
  u64(f) { return this.take(8, f).readBigUInt64LE(); }
  compact(f) { const x = this.u8(f); if (x < 253) return x; if (x === 253) { const n = this.take(2, f).readUInt16LE(); if (n < 253) throw new TypeError(`${this.n}.${f} noncanonical compact`); return n; } if (x === 254) { const n = this.u32(f); if (n <= 0xffff) throw new TypeError(`${this.n}.${f} noncanonical compact`); return n; } const n = this.u64(f); if (n <= 0xffffffffn || n > BigInt(Number.MAX_SAFE_INTEGER)) throw new TypeError(`${this.n}.${f} compact out of range`); return Number(n); }
  done() { if (this.o !== this.b.length) throw new TypeError(`${this.n} trailing bytes`); }
}
function compact(n) { if (n < 253) return Buffer.of(n); if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 253; b.writeUInt16LE(n, 1); return b; } throw new TypeError("fixture compact length too large"); }
function output(r, label) {
  let token = { kind: "none", category: Buffer.alloc(0), commitment: Buffer.alloc(0), amount: 0n };
  if (r.b[r.o] === 0xef) {
    r.u8(`${label}.prefix`); const category = r.take(32, `${label}.category`); const bitfield = r.u8(`${label}.bitfield`);
    if (bitfield !== 0x61) throw new TypeError(`${label} only permits mutable-NFT zero-amount token bitfield 0x61`);
    const cLen = r.compact(`${label}.commitmentLength`); if (cLen !== 128) throw new TypeError(`${label} mutable state commitment must be 128 bytes`);
    token = { kind: "mutable", category, commitment: r.take(cLen, `${label}.commitment`), amount: 0n };
  }
  const value = r.u64(`${label}.value`); const sl = r.compact(`${label}.scriptLength`); const lock = r.take(sl, `${label}.lockingBytecode`);
  return { token, value, lock };
}
function rawOutput(b, label) { const r = new R(b, label); const x = output(r, label); r.done(); return x; }
function transaction(b) {
  const r = new R(b, "transaction"); const version = r.u32("version"); const count = r.compact("inputCount"); if (count !== 3) throw new TypeError("transaction must have exactly 3 inputs"); const inputs = [];
  for (let i = 0; i < count; i++) { const txid = r.take(32, `inputs[${i}].txidWire`); const index = r.u32(`inputs[${i}].index`); const n = r.compact(`inputs[${i}].scriptLength`); inputs.push({ txid, index, script: r.take(n, `inputs[${i}].unlockingBytecode`), sequence: r.u32(`inputs[${i}].sequence`) }); }
  const nout = r.compact("outputCount"); if (nout < 2 || nout > 4) throw new TypeError("transaction output count out of closure bounds"); const outputs = []; for (let i = 0; i < nout; i++) outputs.push(output(r, `outputs[${i}]`)); const locktime = r.u32("locktime"); r.done(); if (version !== 2 || locktime !== 0) throw new TypeError("transaction version/locktime not canonical"); return { version, inputs, outputs, locktime };
}
function encToken(t) { if (t.kind === "none") return Buffer.of(0); return Buffer.concat([Buffer.of(3), t.category, le64(t.amount), Buffer.of(t.commitment.length), t.commitment]); }
function encOutput(x) { if (x.lock.length > 0xffff) throw new TypeError("lock too large"); const l = Buffer.alloc(2); l.writeUInt16LE(x.lock.length); return Buffer.concat([encToken(x.token), le64(x.value), l, x.lock]); }
function pushEnvelope(script) { if (script.length < 3 || script[0] !== 0x4c || script[1] !== script.length - 2) throw new TypeError("envelope input must be exact OP_PUSHDATA1 envelope"); return script.subarray(2); }
function envelope(b) {
  const r = new R(b, "envelope"); same(r.take(4, "magic"), A("F2EV"), "envelope magic"); if (r.u8("version") !== 1 || r.u8("count") !== 2) throw new TypeError("envelope version/count noncanonical"); const schedule = r.take(20, "directory"); const d = new R(schedule, "sectionSchedule"); const want = [[1, 0], [2, 0]]; let expected = 0; const sections = [];
  for (const [type, ordinal] of want) { if (d.u8("type") !== type || d.u8("ordinal") !== ordinal) throw new TypeError("section directory order/type noncanonical"); const offset = d.u32("offset"), length = d.u32("length"); if (!length || offset !== expected) throw new TypeError("section directory gap/empty section"); expected += length; sections.push({ type, ordinal, offset, length }); }
  d.done(); const payload = r.take(expected, "payload"); r.done(); for (const s of sections) if (!payload.subarray(s.offset, s.offset + s.length).length) throw new TypeError("empty opaque proof payload"); return { schedule, sections };
}
function validateFixture(f) {
  const keys = ["fixtureVersion", "networkId", "actionKind", "transactionHex", "sourceOutputs", "proofSuiteManifestDigestHex", "feePolicyMaxSats", "provenance"];
  if (!f || typeof f !== "object" || Array.isArray(f) || Object.keys(f).length !== keys.length || keys.some((k) => !(k in f))) throw new TypeError("fixture keys are not canonical");
  if (f.fixtureVersion !== 1 || !["mainnet", "chipnet", "regtest"].includes(f.networkId) || !["DEPOSIT", "WITHDRAWAL"].includes(f.actionKind)) throw new TypeError("fixture identity invalid");
  if (!Array.isArray(f.sourceOutputs) || f.sourceOutputs.length !== 3) throw new TypeError("exactly three raw source outputs required");
  if (!f.provenance || Object.keys(f.provenance).sort().join(",") !== "carrierTemplateHex,stateTemplateHex,toolchainId" || f.provenance.toolchainId !== "PoolActionFv2/closure-template-compiler/v1") throw new TypeError("provenance input invalid");
  if (f.provenance.stateTemplateHex !== "6af0" || f.provenance.carrierTemplateHex !== "6af1") throw new TypeError("only frozen closure templates accepted");
  hex(f.proofSuiteManifestDigestHex, "proofSuiteManifestDigestHex"); if (hex(f.proofSuiteManifestDigestHex, "proofSuiteManifestDigestHex").length !== 32) throw new TypeError("proof suite digest must be bytes32"); u64(f.feePolicyMaxSats, "feePolicyMaxSats");
}
function provenance(f) {
  const p = f.provenance, suite = hex(f.proofSuiteManifestDigestHex, "proofSuiteManifestDigestHex"), templateNode = domain("PoolActionFv2/provenance/template/v1", A(p.toolchainId), hex(p.stateTemplateHex, "stateTemplateHex"), hex(p.carrierTemplateHex, "carrierTemplateHex"));
  const poolInstanceId = domain("PoolActionFv2/provenance/instance/v1", templateNode, A(f.networkId), suite); const category = domain("PoolActionFv2/provenance/category/v1", poolInstanceId); const stateLock = Buffer.concat([Buffer.from([0x6a, 0x20]), domain("PoolActionFv2/provenance/state-lock/v1", poolInstanceId)]); const carrierLock = Buffer.concat([Buffer.from([0x6a, 0x20]), domain("PoolActionFv2/provenance/carrier-lock/v1", poolInstanceId)]);
  const instanceNode = domain("PoolActionFv2/provenance/instance-node/v1", templateNode, poolInstanceId); const lockNode = domain("PoolActionFv2/provenance/lock-node/v1", instanceNode, stateLock, carrierLock); const genesisRecipeDigest = domain("PoolActionFv2/provenance/genesis-recipe/v1", lockNode, category, be64(10_000_000)); const provenanceRoot = domain("PoolActionFv2/provenance/root/v1", templateNode, instanceNode, lockNode, genesisRecipeDigest);
  return { templateNode, poolInstanceId, category, stateLock, carrierLock, instanceNode, lockNode, genesisRecipeDigest, provenanceRoot };
}
function txView(f, tx, sources, p) {
  const suite = hex(f.proofSuiteManifestDigestHex, "proofSuiteManifestDigestHex");
  for (let i = 0; i < 3; i++) { const s = f.sourceOutputs[i]; if (!s || Object.keys(s).sort().join(",") !== "outpointIndex,outpointTxidWireHex,serializedOutputHex") throw new TypeError(`sourceOutputs[${i}] keys invalid`); same(hex(s.outpointTxidWireHex, "source txid"), tx.inputs[i].txid, `source ${i} txid`); if (s.outpointIndex !== tx.inputs[i].index) throw new TypeError(`source ${i} index differs`); }
  const state = sources[0], carrier = sources[1]; if (state.token.kind !== "mutable" || !state.token.category.equals(p.category) || !state.lock.equals(p.stateLock)) throw new TypeError("state source is not derived mutable state NFT"); if (carrier.token.kind !== "none" || !carrier.lock.equals(p.carrierLock)) throw new TypeError("carrier token/lock invalid"); if (sources[2].token.kind !== "none") throw new TypeError("funding token must be NONE");
  const isDeposit = f.actionKind === "DEPOSIT", roles = isDeposit ? [2, 0x10] : [3, 0x11]; const expectedOutputs = isDeposit ? 2 : 4; if (tx.outputs.length !== expectedOutputs) throw new TypeError("action output count noncanonical"); const stateOut = tx.outputs[0], carrierOut = tx.outputs[1]; if (stateOut.token.kind !== "mutable" || !stateOut.token.category.equals(state.token.category) || !stateOut.token.commitment.equals(state.token.commitment) || !stateOut.lock.equals(p.stateLock)) throw new TypeError("state successor invalid"); if (carrierOut.token.kind !== "none" || carrierOut.value !== carrier.value || !carrierOut.lock.equals(p.carrierLock)) throw new TypeError("carrier successor invalid");
  const delta = isDeposit ? 10_000_000n : -10_000_000n; if (stateOut.value - state.value !== delta) throw new TypeError("ticket reserve delta invalid"); if (!isDeposit && (tx.outputs[2].value !== 10_000_000n || tx.outputs[2].token.kind !== "none")) throw new TypeError("withdrawal payout invalid"); if (!isDeposit && tx.outputs[3].token.kind !== "none") throw new TypeError("transparent change token invalid");
  const env = pushEnvelope(tx.inputs[1].script); const e = envelope(env); const inputSum = sources.reduce((a, x) => a + x.value, 0n), outputSum = tx.outputs.reduce((a, x) => a + x.value, 0n); if (inputSum < outputSum) throw new TypeError("negative fee"); const fee = inputSum - outputSum; if (fee > u64(f.feePolicyMaxSats, "feePolicyMaxSats")) throw new TypeError("fee exceeds policy");
  const chunks = [A("F2TV"), Buffer.from([0, 2, ["mainnet", "chipnet", "regtest"].indexOf(f.networkId), isDeposit ? 0 : 1]), le32(tx.version), le32(tx.locktime), Buffer.from([0, 0, 1, 0, 3, 0])];
  for (let i = 0; i < 3; i++) { const input = tx.inputs[i]; chunks.push(Buffer.from([i, 0, i === 0 ? 0 : i === 1 ? 1 : roles[0]]), input.txid, le32(input.index), le32(input.sequence), encOutput(sources[i])); if (i === 1) chunks.push(Buffer.of(1)); else { if (input.script.length > 0xffff) throw new TypeError("script too long"); const n = Buffer.alloc(2); n.writeUInt16LE(input.script.length); chunks.push(Buffer.of(0), n, input.script); } }
  chunks.push(Buffer.from([tx.outputs.length, 0])); for (const o of tx.outputs) chunks.push(encOutput(o)); const economics = Buffer.alloc(8 + 8 + 8 + 8 + 2); economics.writeBigUInt64LE(10_000_000n, 0); economics.writeBigInt64LE(delta, 8); economics.writeBigUInt64LE(fee, 16); economics.writeBigUInt64LE(u64(f.feePolicyMaxSats, "feePolicyMaxSats"), 24); economics.writeUInt16LE(isDeposit ? 0xffff : 2, 32); chunks.push(economics);
  return { bytes: Buffer.concat(chunks), envelope: env, schedule: e.schedule, fee };
}
export function recompute(fixture) { validateFixture(fixture); const tx = transaction(hex(fixture.transactionHex, "transactionHex")); const sources = fixture.sourceOutputs.map((x, i) => rawOutput(hex(x.serializedOutputHex, `sourceOutputs[${i}]`), `sourceOutputs[${i}]`)); const p = provenance(fixture); const v = txView(fixture, tx, sources, p); const contextDigest = domain("PoolActionFv2/context/v1", A(fixture.networkId), v.bytes, p.provenanceRoot); const envelopeRoot = domain("PoolActionFv2/envelope/v1", v.envelope); const sessionDigest = domain("PoolActionFv2/session/v1", contextDigest, envelopeRoot, v.schedule, hex(fixture.proofSuiteManifestDigestHex, "proofSuiteManifestDigestHex"));
  return { transactionViewHex: v.bytes.toString("hex"), sectionScheduleHex: v.schedule.toString("hex"), envelopeRootHex: envelopeRoot.toString("hex"), provenanceRootHex: p.provenanceRoot.toString("hex"), contextDigestHex: contextDigest.toString("hex"), sessionDigestHex: sessionDigest.toString("hex"), stateLockingBytecodeHex: p.stateLock.toString("hex"), carrierLockingBytecodeHex: p.carrierLock.toString("hex"), genesisRecipeDigestHex: p.genesisRecipeDigest.toString("hex"), poolInstanceIdHex: p.poolInstanceId.toString("hex"), stateTokenCategoryHex: p.category.toString("hex"), transactionByteCount: hex(fixture.transactionHex, "transactionHex").length, envelopeByteCount: v.envelope.length, sectionScheduleByteCount: v.schedule.length, proofAcceptance: false, proofAcceptanceReason: "PROOF_SUITE_UNSELECTED" };
}
async function main() { const path = process.argv[2]; if (!path) throw new TypeError("usage: recompute.mjs fixture.raw.json"); console.log(JSON.stringify(recompute(JSON.parse(await readFile(path, "utf8"))), null, 2)); }
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch((e) => { console.error(`REJECT: ${e.message}`); process.exitCode = 1; });
