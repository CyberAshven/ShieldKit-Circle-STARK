import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { assembleBytecodeBCH, disassembleBytecodeBCH } from '@bitauth/libauth';
import {
  assertKnownPassingPackageDigest,
  canonicalJson as irCanonicalJson,
  generatePackage
} from '../lowering-arm-ir-freeze/generate.mjs';
import { generatePhysicalPlans } from '../lowering-arm-ir-freeze/physical-plan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(here, '../../../..');
const DIRECTORY = here;
const IR_DIRECTORY = resolve(here, '../lowering-arm-ir-freeze');
const BCHN_ROOT = '/home/toorik/Projects/BCH/bchn-src';
const IR_PATH = 'research-lanes/bch-shielded-pool-design/p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.json';
const IR_SCHEMA_PATH = 'research-lanes/bch-shielded-pool-design/p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.schema.json';
const EXPECTED_IR_RAW_SHA256 = '95cb8b14117de17bd7d6064cc15b778ad44b0b076b009d81c9515d2748054aeb';
const EXPECTED_IR_CONTENT_DIGEST = '49a1d851812881b3cd58cc64871f5628dd8ab7b76cb11ed2495fe4fc0549db64';
const EXPECTED_IR_SCHEMA_SHA256 = 'e358b8a7c28fdcb2201d5fe5ae38c495769f85894d122e7cec1b1b7b300c87f2';
const BCHN_COMMIT = '864c53ee34924cca6c6b6d96607ff2cedcdccf02';
const ROOT_DOMAIN = 'shieldkit-labs/p2/source-set/v1/root';
const MAP_DOMAIN = 'shieldkit-labs/p2/source-set/v1/plan-map';
const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
const DOMAIN_FRAME = 'utf8(domain)||0x00||canonical-json-utf8';
const RECIPE_VERSION = 'bch-asm-physical-plan-recipe-v1';
const STATIC_FILES = Object.freeze([
  'README.md', 'COMMAND.txt', 'generate.mjs', 'validate.mjs', 'source-set.test.mjs',
  'source-set.v1.schema.json', 'plan-source-map.v1.schema.json'
]);
const PACKAGE_REPO_PREFIX = 'research-lanes/bch-shielded-pool-design/p2/source-set-v1';
const ROOT_SCHEMA_PATH = `${PACKAGE_REPO_PREFIX}/source-set.v1.schema.json`;
const MAP_SCHEMA_PATH = `${PACKAGE_REPO_PREFIX}/plan-source-map.v1.schema.json`;
const GENERATOR_PATH = `${PACKAGE_REPO_PREFIX}/generate.mjs`;
const VALIDATOR_PATH = `${PACKAGE_REPO_PREFIX}/validate.mjs`;
const TEST_PATH = `${PACKAGE_REPO_PREFIX}/source-set.test.mjs`;

const fail = (message) => { throw new Error(`source-set-v1: ${message}`); };
const clone = (value) => structuredClone(value);
const canonicalValue = (value) => Array.isArray(value)
  ? value.map(canonicalValue)
  : value !== null && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]))
    : value;
export const canonicalJson = (value) => `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const rawDigest = (bytes) => ({ algorithm: 'sha256', preimage: 'exact-file-bytes', value: sha256(bytes) });
const domainDigest = (domain, value, omittedKey = 'contentDigest') => {
  const copy = clone(value);
  delete copy[omittedKey];
  return {
    algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: DOMAIN_FRAME,
    value: sha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), Buffer.from(canonicalJson(copy), 'utf8')]))
  };
};
const contentDigestFor = (value) => domainDigest(ROOT_DOMAIN, value);
const mapDigestFor = (value, planId) => domainDigest(`${MAP_DOMAIN}/${planId}`, value);
export const mapContentDigestFor = (map) => mapDigestFor(map, map.planId);
const bytes = (value) => Buffer.from(value, 'utf8');
const asHex = (value) => Buffer.from(value).toString('hex');
const normalizeTokens = (value) => value.trim() === '' ? [] : value.trim().split(/\s+/u);

const assertContained = (root, path) => {
  if (typeof path !== 'string' || path.length === 0 || isAbsolute(path)) fail(`unsafe absolute/empty path ${path}`);
  const rootReal = realpathSync(root);
  const candidate = resolve(rootReal, path);
  if (candidate !== rootReal && !candidate.startsWith(`${rootReal}${sep}`)) fail(`path escapes root: ${path}`);
  let cursor = rootReal;
  for (const part of relative(rootReal, candidate).split(sep).filter(Boolean)) {
    cursor = resolve(cursor, part);
    const stat = lstatSync(cursor);
    if (stat.isSymbolicLink()) fail(`symlink component rejected: ${path}`);
  }
  const candidateReal = realpathSync(candidate);
  if (candidateReal !== rootReal && !candidateReal.startsWith(`${rootReal}${sep}`)) fail(`realpath escapes root: ${path}`);
  return candidateReal;
};
const repoFile = (path) => assertContained(REPO, path);
const sourceFile = (path) => assertContained(DIRECTORY, path);
const sourceOutput = (path) => {
  if (typeof path !== 'string' || path.length === 0 || isAbsolute(path)) fail(`unsafe output path ${path}`);
  const rootReal = realpathSync(DIRECTORY);
  const candidate = resolve(rootReal, path);
  if (candidate !== rootReal && !candidate.startsWith(`${rootReal}${sep}`)) fail(`output path escapes root: ${path}`);
  const parent = dirname(candidate);
  if (!existsSync(parent)) fail(`output parent is absent: ${path}`);
  const parentReal = realpathSync(parent);
  if (parentReal !== rootReal && !parentReal.startsWith(`${rootReal}${sep}`)) fail(`output parent escapes root: ${path}`);
  let cursor = rootReal;
  for (const part of relative(rootReal, parentReal).split(sep).filter(Boolean)) {
    cursor = resolve(cursor, part);
    if (lstatSync(cursor).isSymbolicLink()) fail(`output symlink component rejected: ${path}`);
  }
  return candidate;
};
const bchnFile = (path) => assertContained(BCHN_ROOT, path);
const filePin = (root, path) => {
  const absolute = assertContained(root, path);
  const value = readFileSync(absolute);
  return { path, byteCount: value.length, rawSha256: sha256(value) };
};
const repoPin = (path) => filePin(REPO, path);
const schemaPin = (id, path) => ({ id, ...repoPin(path) });

const encodeMinimalScriptNum = (input) => {
  let value = BigInt(input);
  if (value === 0n) return '';
  const negative = value < 0n;
  if (negative) value = -value;
  const out = [];
  while (value > 0n) { out.push(Number(value & 0xffn)); value >>= 8n; }
  if ((out.at(-1) & 0x80) !== 0) out.push(negative ? 0x80 : 0x00);
  else if (negative) out[out.length - 1] |= 0x80;
  return Buffer.from(out).toString('hex');
};
const pushOpcode = (length) => {
  if (!Number.isInteger(length) || length < 1 || length > 75) fail(`unsupported explicit push width ${length}`);
  return `OP_PUSHBYTES_${length}`;
};
const scriptNumTokens = (value, semanticId) => {
  const canonical = String(BigInt(value));
  const encoded = encodeMinimalScriptNum(canonical);
  if (canonical === '0') return {
    tokens: ['OP_0'],
    literal: { semanticId, kind: 'minimal-scriptnum', canonical, scriptNumHex: encoded, encoding: 'opcode-OP_0', tokenCount: 1 }
  };
  if (canonical === '-1') return {
    tokens: ['OP_1NEGATE'],
    literal: { semanticId, kind: 'minimal-scriptnum', canonical, scriptNumHex: encoded, encoding: 'opcode-OP_1NEGATE', tokenCount: 1 }
  };
  if (BigInt(canonical) >= 1n && BigInt(canonical) <= 16n) return {
    tokens: [`OP_${canonical}`],
    literal: { semanticId, kind: 'minimal-scriptnum', canonical, scriptNumHex: encoded, encoding: `opcode-OP_${canonical}`, tokenCount: 1 }
  };
  const width = encoded.length / 2;
  return {
    tokens: [pushOpcode(width), `0x${encoded}`],
    literal: { semanticId, kind: 'minimal-scriptnum', canonical, scriptNumHex: encoded, encoding: 'explicit-push', pushOpcode: pushOpcode(width), tokenCount: 2 }
  };
};
const rawBytesTokens = (hex, semanticId) => {
  if (typeof hex !== 'string' || !/^(?:[0-9a-f]{2})+$/u.test(hex)) fail(`raw literal ${semanticId} is not nonempty lowercase even hex`);
  const width = hex.length / 2;
  return {
    tokens: [pushOpcode(width), `0x${hex}`],
    literal: { semanticId, kind: 'raw-bytes', hex, encoding: 'explicit-push', pushOpcode: pushOpcode(width), tokenCount: 2 }
  };
};

const parserMaskIndex = (entry) => {
  const match = entry.id.match(/:mask:c(\d+)$/u);
  if (!match) fail(`${entry.id}: mask instruction lacks coefficient index`);
  const coefficientIndex = Number(match[1]);
  const limbBytes = Number(entry.effects.sourceCandidateMacroTrace?.tokens?.[1]?.match(/^<(\d+)>$/u)?.[1]);
  if (!Number.isInteger(limbBytes)) fail(`${entry.id}: frozen source-candidate mask index is absent`);
  return limbBytes;
};

const PRIMITIVE_RECIPE_AUTHORITY = Object.freeze({
  'stack.assert_depth_exact': { kind: 'fixed-token-recipe', tokens: 'OP_DEPTH <expected-primary-depth> OP_NUMEQUALVERIFY' },
  'bytes.assert_length_exact': { kind: 'fixed-token-recipe', tokens: 'OP_SIZE <exact-element-byte-length> OP_NUMEQUALVERIFY' },
  'bytes.split_at_exact': { kind: 'fixed-token-recipe', tokens: '<exact-split-left-bytes> OP_SPLIT' },
  'bytes.assert_mask_zero': { kind: 'fixed-token-recipe', tokens: 'OP_DUP <mask-split-index> OP_SPLIT OP_PUSHBYTES_1 0xNN OP_AND OP_PUSHBYTES_1 0x00 OP_EQUALVERIFY OP_DROP' },
  'bytes.cat_zero_sign_byte': { kind: 'fixed-token-recipe', tokens: 'OP_1 OP_1 OP_XOR OP_CAT' },
  'scriptnum.bin2num': { kind: 'fixed-token-recipe', tokens: 'OP_BIN2NUM' },
  'integer.assert_nonnegative': { kind: 'fixed-token-recipe', tokens: 'OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY' },
  'integer.assert_lt_const': { kind: 'fixed-token-recipe', tokens: 'OP_DUP <field-modulus-range-bound> OP_LESSTHAN OP_VERIFY' },
  'bytes.assert_empty': { kind: 'fixed-token-recipe', tokens: 'OP_SIZE OP_0 OP_NUMEQUALVERIFY OP_DROP' },
  'stack.pick': { kind: 'fixed-token-recipe', tokens: '<exact-pick-depth> OP_PICK' },
  'stack.dup': { kind: 'fixed-token-recipe', tokens: 'OP_DUP' },
  'stack.drop': { kind: 'fixed-token-recipe', tokens: 'OP_DROP' },
  'stack.toalt': { kind: 'fixed-token-recipe', tokens: 'OP_TOALTSTACK' },
  'stack.fromalt': { kind: 'fixed-token-recipe', tokens: 'OP_FROMALTSTACK' },
  'field.arithmetic': {
    kind: 'operator-dispatch',
    operators: {
      add: 'OP_ADD', sub: 'OP_SUB', mul: 'OP_MUL',
      square: 'OP_MUL (RHS is materialized by frozen stack.dup)',
      scale: '<canonical-scale-scalar> OP_MUL'
    }
  },
  'field.canonicalize_identity': { kind: 'fixed-token-recipe', tokens: '<p> OP_MOD <p> OP_ADD <p> OP_MOD' },
  'boolean.equal': { kind: 'fixed-token-recipe', tokens: 'OP_NUMEQUAL' },
  'boolean.and': { kind: 'fixed-token-recipe', tokens: 'OP_BOOLAND' },
  'boolean.or': { kind: 'fixed-token-recipe', tokens: 'OP_BOOLOR' },
  'integer.is_nonzero': { kind: 'fixed-token-recipe', tokens: 'OP_0NOTEQUAL' },
  'integer.equals_const': { kind: 'fixed-token-recipe', tokens: '<equals-constant> OP_NUMEQUAL' }
});
const FIELD_ARITHMETIC_OPCODES = Object.freeze({ add: 'OP_ADD', sub: 'OP_SUB', mul: 'OP_MUL', square: 'OP_MUL', scale: 'OP_MUL' });
export const assertPrimitiveRecipeAuthority = (candidate) => {
  if (canonicalJson(candidate) !== canonicalJson(PRIMITIVE_RECIPE_AUTHORITY)) fail('primitive recipe authority is not the exact closed frozen roster');
};

const finalizedRecipeFor = (entry) => {
  if (!Object.hasOwn(PRIMITIVE_RECIPE_AUTHORITY, entry.primitive)) fail(`${entry.id}: primitive is outside the closed recipe authority`);
  {
    const tokens = []; const literals = []; const substeps = [];
    const op = (text, primaryDelta = 0, altDelta = 0, transient = false) => {
      const index = tokens.length; tokens.push({ text, kind: 'opcode' }); substeps.push({ label: text, tokenIndices: [index], primaryDelta, altDelta, transient });
    };
    const literal = (kind, value, semanticId, primaryDelta, transient = true) => {
      const spec = kind === 'raw' ? rawBytesTokens(value, semanticId) : scriptNumTokens(value, semanticId);
      const start = tokens.length;
      spec.tokens.forEach((text, offset) => tokens.push({ text, kind: offset === 0 && spec.tokens.length === 2 ? 'push-opcode' : 'literal', literalSemanticId: semanticId }));
      literals.push(spec.literal);
      substeps.push({ label: `push:${semanticId}`, tokenIndices: Array.from({ length: spec.tokens.length }, (_, index) => start + index), primaryDelta, altDelta: 0, transient });
    };
    const e = entry.effects;
    switch (entry.primitive) {
      case 'stack.assert_depth_exact': op('OP_DEPTH', 1, 0, true); literal('scriptnum', e.expectedPrimaryDepth, 'expected-primary-depth', 1); op('OP_NUMEQUALVERIFY', -2); break;
      case 'bytes.assert_length_exact': op('OP_SIZE', 1, 0, true); literal('scriptnum', e.exactBytes, 'exact-element-byte-length', 1); op('OP_NUMEQUALVERIFY', -2); break;
      case 'bytes.split_at_exact': literal('scriptnum', e.leftBytes, 'exact-split-left-bytes', 1); op('OP_SPLIT'); break;
      case 'bytes.assert_mask_zero':
        op('OP_DUP', 1, 0, true); literal('scriptnum', parserMaskIndex(entry), 'mask-split-index', 1); op('OP_SPLIT');
        literal('raw', e.maskHex, 'unused-high-bit-mask', 1); op('OP_AND', -1);
        literal('raw', '00', 'raw-one-byte-zero-comparator', 1); op('OP_EQUALVERIFY', -2); op('OP_DROP', -1); break;
      case 'bytes.cat_zero_sign_byte': op('OP_1', 1, 0, true); op('OP_1', 1, 0, true); op('OP_XOR', -1); op('OP_CAT', -1); break;
      case 'scriptnum.bin2num': op('OP_BIN2NUM'); break;
      case 'integer.assert_nonnegative': op('OP_DUP', 1, 0, true); op('OP_0', 1, 0, true); op('OP_GREATERTHANOREQUAL', -1); op('OP_VERIFY', -1); break;
      case 'integer.assert_lt_const': op('OP_DUP', 1, 0, true); literal('scriptnum', e.constant, 'field-modulus-range-bound', 1); op('OP_LESSTHAN', -1); op('OP_VERIFY', -1); break;
      case 'bytes.assert_empty': op('OP_SIZE', 1, 0, true); op('OP_0', 1, 0, true); op('OP_NUMEQUALVERIFY', -2); op('OP_DROP', -1); break;
      case 'stack.pick': literal('scriptnum', e.depth, 'exact-pick-depth', 1); op('OP_PICK'); break;
      case 'stack.dup': op('OP_DUP', 1); break;
      case 'stack.drop': op('OP_DROP', -1); break;
      case 'stack.toalt': op('OP_TOALTSTACK', -1, 1); break;
      case 'stack.fromalt': op('OP_FROMALTSTACK', 1, -1); break;
      case 'field.arithmetic':
        if (!Object.hasOwn(FIELD_ARITHMETIC_OPCODES, e.operator)) fail(`${entry.id}: unsupported field.arithmetic operator ${e.operator}`);
        if (e.operator === 'scale') { literal('scriptnum', e.scalarCanonical, 'canonical-scale-scalar', 1); op(FIELD_ARITHMETIC_OPCODES.scale, -1); }
        else op(FIELD_ARITHMETIC_OPCODES[e.operator], 1 - e.inputValueIds.length);
        break;
      case 'field.canonicalize_identity':
        literal('scriptnum', e.modulus, 'canonicalize-modulus:first', 1); op('OP_MOD', -1);
        literal('scriptnum', e.modulus, 'canonicalize-modulus:add', 1); op('OP_ADD', -1);
        literal('scriptnum', e.modulus, 'canonicalize-modulus:second', 1); op('OP_MOD', -1); break;
      case 'boolean.equal': op('OP_NUMEQUAL', -1); break;
      case 'boolean.and': op('OP_BOOLAND', -1); break;
      case 'boolean.or': op('OP_BOOLOR', -1); break;
      case 'integer.is_nonzero': op('OP_0NOTEQUAL'); break;
      case 'integer.equals_const': literal('scriptnum', e.constantCanonical, 'equals-constant', 1); op('OP_NUMEQUAL', -1); break;
      default: fail(`${entry.id}: unsupported primitive ${entry.primitive}`);
    }
    return { tokens, literals, substeps };
  }
  fail(`${entry.id}: unreachable recipe branch`);
};

const parserIdentity = (plan, entry) => {
  const invocation = plan.parserInvocations.find((candidate) => entry.id.startsWith(`${candidate.invocationId}:`));
  return invocation ? { planId: plan.planId, invocationId: invocation.invocationId } : null;
};
const assertPartition = (spans, length, label) => {
  let cursor = 0;
  for (const span of spans) {
    if (!Number.isInteger(span.start) || !Number.isInteger(span.end) || span.start !== cursor || span.end <= span.start) fail(`${label} has a gap/overlap at ${cursor}`);
    cursor = span.end;
  }
  if (cursor !== length) fail(`${label} does not cover exact length`);
};
const assertSubPartition = (spans, start, end, label) => {
  let cursor = start;
  for (const span of spans) {
    if (span.start !== cursor || span.end <= span.start || span.end > end) fail(`${label} does not exactly match its instruction span`);
    cursor = span.end;
  }
  if (cursor !== end) fail(`${label} does not exactly cover its instruction span`);
};
const instructionFragments = (sourceBytes, bytecode, instruction) => {
  const sourceFragmentBytes = sourceBytes.subarray(instruction.source.span.start, instruction.source.span.end);
  const bytecodeBytes = bytecode.subarray(instruction.bytecodeSpan.start, instruction.bytecodeSpan.end);
  return {
    source: { encoding: 'utf8-lf-including-final-line-feed', byteLength: sourceFragmentBytes.length, sha256: sha256(sourceFragmentBytes) },
    bytecode: { encoding: 'raw-bytecode-fragment', byteLength: bytecodeBytes.length, sha256: sha256(bytecodeBytes) }
  };
};

export const assertExactRoster = (expectedNames, actualEntries, label) => {
  const expected = new Set(expectedNames);
  const actual = Array.from(actualEntries);
  if (actual.length !== expected.size) fail(`${label} roster cardinality mismatch`);
  for (const name of actual) if (!expected.has(name)) fail(`${label} has unexpected or stale entry: ${name}`);
  for (const name of expected) if (!actual.includes(name)) fail(`${label} misses required entry: ${name}`);
};

export const validatePlanEmission = ({ asm, bytecode, map, plan }) => {
  if (typeof asm !== 'string' || !asm.endsWith('\n') || /\r|\n\n|[ \t]+\n/u.test(asm)) fail(`${map.planId}: source formatting drift`);
  if (!Buffer.isBuffer(bytecode)) fail(`${map.planId}: bytecode is not Buffer`);
  if (map.schemaBinding?.rawSha256 !== sha256(readFileSync(repoFile(MAP_SCHEMA_PATH)))) fail(`${map.planId}: map schema binding drift`);
  if (map.source.byteLength !== Buffer.byteLength(asm, 'utf8') || map.source.sha256 !== sha256(bytes(asm))) fail(`${map.planId}: source metadata drift`);
  if (map.bytecode.byteLength !== bytecode.length || map.bytecode.sha256 !== sha256(bytecode) || map.bytecode.hex !== asHex(bytecode)) fail(`${map.planId}: bytecode metadata drift`);
  assertPartition(map.sourceCoverage, Buffer.byteLength(asm, 'utf8'), `${map.planId} source coverage`);
  assertPartition(map.bytecodeCoverage, bytecode.length, `${map.planId} bytecode coverage`);
  const coverageByInstruction = (coverage) => coverage.reduce((grouped, span) => {
    const spans = grouped.get(span.instructionOrder) ?? [];
    spans.push(span); grouped.set(span.instructionOrder, spans);
    return grouped;
  }, new Map());
  const sourceCoverageByInstruction = coverageByInstruction(map.sourceCoverage);
  const bytecodeCoverageByInstruction = coverageByInstruction(map.bytecodeCoverage);
  const sourceBytes = bytes(asm);
  for (const instruction of map.instructions) {
    const sourceCoverage = sourceCoverageByInstruction.get(instruction.instructionOrder) ?? [];
    const bytecodeCoverage = bytecodeCoverageByInstruction.get(instruction.instructionOrder) ?? [];
    assertSubPartition(sourceCoverage, instruction.source.span.start, instruction.source.span.end, `${map.planId}/${instruction.instructionId} source coverage`);
    assertSubPartition(bytecodeCoverage, instruction.bytecodeSpan.start, instruction.bytecodeSpan.end, `${map.planId}/${instruction.instructionId} bytecode coverage`);
    const fragments = instructionFragments(sourceBytes, bytecode, instruction);
    if (canonicalJson(instruction.sourceFragment) !== canonicalJson(fragments.source)) fail(`${map.planId}/${instruction.instructionId}: LF-inclusive source fragment digest/span drift`);
    if (canonicalJson(instruction.bytecodeFragment) !== canonicalJson(fragments.bytecode)) fail(`${map.planId}/${instruction.instructionId}: raw bytecode fragment digest/span drift`);
  }
  const assembled = assembleBytecodeBCH(asm);
  if (!assembled.success || !Buffer.from(assembled.bytecode).equals(bytecode)) fail(`${map.planId}: source reassembly mismatch`);
  if (JSON.stringify(normalizeTokens(disassembleBytecodeBCH(bytecode))) !== JSON.stringify(normalizeTokens(asm))) fail(`${map.planId}: disassembly mismatch`);
  if (map.contentDigest?.value !== mapDigestFor(map, map.planId).value) fail(`${map.planId}: map content digest drift`);
  if (plan) {
    if (map.planId !== plan.planId || map.instructions.length !== plan.instructions.length) fail(`${map.planId}: map/plan identity cardinality drift`);
    for (const [index, instruction] of map.instructions.entries()) {
      const authoritative = plan.instructions[index];
      if (instruction.instructionId !== authoritative.id || instruction.primitive !== authoritative.primitive || canonicalJson(instruction.irTypedContract) !== canonicalJson({ consumes: authoritative.effects.consumes, produces: authoritative.effects.produces, transientStackContract: authoritative.effects.transientStackContract })) fail(`${map.planId}/${instruction.instructionId}: typed IR contract drift`);
    }
    if (map.stackLedger.sourceMaxPrimary !== plan.simulation.maxPrimaryDepth || map.stackLedger.sourceMaxAlt !== plan.simulation.maxAltDepth || map.stackLedger.sourceMaxCombined !== plan.maximumStack || canonicalJson(map.stackLedger.terminalTypedBoundary) !== canonicalJson(plan.simulation.terminal)) fail(`${map.planId}: stack ledger drift`);
  }
  return true;
};

const buildPlanArtifacts = (plan, planOrder) => {
  const sourceCoverage = [];
  const bytecodeCoverage = [];
  const instructions = [];
  const asmLines = [];
  const bytecodeChunks = [];
  let sourceOffset = 0;
  let bytecodeOffset = 0;
  let sourceMaxPrimary = plan.initialStack.primary.length;
  let sourceMaxAlt = plan.initialStack.alt.length;
  let sourceMaxCombined = sourceMaxPrimary + sourceMaxAlt;
  for (const [instructionOrder, entry] of plan.instructions.entries()) {
    const before = plan.simulation.trace[instructionOrder];
    const recipe = finalizedRecipeFor(entry);
    const line = recipe.tokens.map((token) => token.text).join(' ');
    if (line.length === 0 || /\r|\n|\s{2}|\s$/u.test(line)) fail(`${plan.planId}/${entry.id}: noncanonical source line`);
    const assembled = assembleBytecodeBCH(line);
    if (!assembled.success) fail(`${plan.planId}/${entry.id}: assembler failure ${assembled.errors?.map((error) => error.error).join('; ')}`);
    const fragment = Buffer.from(assembled.bytecode);
    const lineStart = sourceOffset;
    let tokenCursor = lineStart;
    const tokenSpans = recipe.tokens.map((token, tokenIndex) => {
      const start = tokenCursor; const end = start + Buffer.byteLength(token.text, 'utf8');
      const span = { tokenIndex, text: token.text, kind: token.kind, start, end, ...(token.literalSemanticId ? { literalSemanticId: token.literalSemanticId } : {}) };
      sourceCoverage.push({ start, end, kind: 'token', instructionOrder, tokenIndex });
      tokenCursor = end;
      if (tokenIndex + 1 < recipe.tokens.length) { sourceCoverage.push({ start: tokenCursor, end: tokenCursor + 1, kind: 'separator', instructionOrder }); tokenCursor += 1; }
      return span;
    });
    sourceCoverage.push({ start: tokenCursor, end: tokenCursor + 1, kind: 'line-ending', instructionOrder });
    sourceOffset = tokenCursor + 1;
    const bytecodeSpan = { start: bytecodeOffset, end: bytecodeOffset + fragment.length };
    bytecodeCoverage.push({ ...bytecodeSpan, instructionOrder });
    bytecodeOffset += fragment.length;
    let primary = before.primaryDepthBefore;
    let alt = before.altDepthBefore;
    let observedTransientAdditionalPeak = 0;
    const stackSteps = recipe.substeps.map((step) => {
      primary += step.primaryDelta; alt += step.altDelta;
      if (step.transient) observedTransientAdditionalPeak = Math.max(observedTransientAdditionalPeak, primary - before.primaryDepthBefore);
      sourceMaxPrimary = Math.max(sourceMaxPrimary, primary); sourceMaxAlt = Math.max(sourceMaxAlt, alt); sourceMaxCombined = Math.max(sourceMaxCombined, primary + alt);
      return { ...step, primaryDepth: primary, altDepth: alt };
    });
    if (primary !== before.primaryDepthAfter || alt !== before.altDepthAfter) fail(`${plan.planId}/${entry.id}: source microtrace terminal depth mismatch`);
    const declared = entry.effects.transientStackContract.primaryAdditionalPeak;
    if (observedTransientAdditionalPeak !== declared) fail(`${plan.planId}/${entry.id}: source microtrace peak ${observedTransientAdditionalPeak} != refreshed IR ${declared}`);
    const sourceSpan = { start: lineStart, end: sourceOffset };
    instructions.push({
      instructionOrder, instructionId: entry.id, primitive: entry.primitive, planId: plan.planId, planOrder,
      parserInvocation: parserIdentity(plan, entry), macroVersion: RECIPE_VERSION,
      irTypedContract: { consumes: clone(entry.effects.consumes), produces: clone(entry.effects.produces), transientStackContract: clone(entry.effects.transientStackContract) },
      source: { line: instructionOrder + 1, span: sourceSpan, tokenSpans },
      sourceFragment: { encoding: 'utf8-lf-including-final-line-feed', byteLength: Buffer.byteLength(`${line}\n`, 'utf8'), sha256: sha256(bytes(`${line}\n`)) },
      bytecodeSpan, bytecodeFragment: { encoding: 'raw-bytecode-fragment', byteLength: fragment.length, sha256: sha256(fragment) }, literalSemantics: recipe.literals, substeps: stackSteps,
      stackMicrotrace: {
        entryPrimaryDepth: before.primaryDepthBefore, entryAltDepth: before.altDepthBefore,
        exitPrimaryDepth: before.primaryDepthAfter, exitAltDepth: before.altDepthAfter,
        observedTransientAdditionalPeak, declaredTransientAdditionalPeak: declared,
        sourceOnly: true
      }
    });
    asmLines.push(line); bytecodeChunks.push(fragment);
  }
  const asm = `${asmLines.join('\n')}\n`;
  const bytecode = Buffer.concat(bytecodeChunks);
  assertPartition(sourceCoverage, Buffer.byteLength(asm, 'utf8'), `${plan.planId} source coverage`);
  assertPartition(bytecodeCoverage, bytecode.length, `${plan.planId} bytecode coverage`);
  const whole = assembleBytecodeBCH(asm);
  if (!whole.success || !Buffer.from(whole.bytecode).equals(bytecode)) fail(`${plan.planId}: full-source reassembly differs from line chunks`);
  const expectedTokens = normalizeTokens(asm);
  const disassembledTokens = normalizeTokens(disassembleBytecodeBCH(bytecode));
  if (JSON.stringify(disassembledTokens) !== JSON.stringify(expectedTokens)) fail(`${plan.planId}: canonical disassembly token sequence differs`);
  const map = {
    schema: 'shieldkit-labs/p2/source-set/plan-source-map/v1',
    schemaBinding: schemaPin('shieldkit-labs/p2/source-set/plan-source-map/v1', MAP_SCHEMA_PATH),
    planId: plan.planId, planOrder,
    source: { encoding: 'utf8-lf-one-physical-instruction-per-line', byteLength: Buffer.byteLength(asm, 'utf8'), sha256: sha256(bytes(asm)) },
    bytecode: { encoding: 'raw-script-bytes-and-lowercase-hex', byteLength: bytecode.length, sha256: sha256(bytecode), hex: asHex(bytecode) },
    instructions, sourceCoverage, bytecodeCoverage,
    stackLedger: {
      kind: 'symbolic-source-macro-only-not-bch-vm-execution',
      sourceMaxPrimary, sourceMaxAlt, sourceMaxCombined,
      refreshedIrSymbolicMax: plan.maximumStack,
      terminalTypedBoundary: clone(plan.simulation.terminal),
      equalToRefreshedIrSymbolicMax: sourceMaxCombined === plan.maximumStack
    },
    nonClaims: ['not BCH-VM execution', 'not a BCH VM-limit or standardness proof', 'not campaign, metric, ranking, selection, or qualification evidence'],
    contentDigest: null
  };
  if (sourceMaxPrimary !== plan.simulation.maxPrimaryDepth || sourceMaxAlt !== plan.simulation.maxAltDepth || sourceMaxCombined !== plan.maximumStack) {
    fail(`${plan.planId}: source-level macro maxima diverge from corrected refreshed IR maxima`);
  }
  map.contentDigest = mapDigestFor(map, plan.planId);
  validatePlanEmission({ asm, bytecode, map, plan });
  return { asm, bytecode, hex: `${asHex(bytecode)}\n`, map, mapBytes: bytes(canonicalJson(map)) };
};

const slug = (value) => value.replace(/[^a-zA-Z0-9]+/gu, '-').replace(/^-|-$/gu, '').toLowerCase();
const planPaths = (plan, orderIndex) => {
  const stem = `${String(orderIndex).padStart(2, '0')}-${slug(plan.planId)}`;
  return { asmPath: `plans/${stem}.asm`, hexPath: `plans/${stem}.hex`, mapPath: `plans/${stem}.map.json` };
};

const toolchainBinding = () => {
  const lock = JSON.parse(readFileSync(repoFile('package-lock.json'), 'utf8'));
  const libauth = lock.packages?.['node_modules/@bitauth/libauth'];
  if (!libauth || libauth.version !== '3.1.0-next.8' || typeof libauth.integrity !== 'string') fail('Libauth lock binding drift');
  const installed = JSON.parse(readFileSync(repoFile('node_modules/@bitauth/libauth/package.json'), 'utf8'));
  if (installed.version !== '3.1.0-next.8') fail('installed Libauth version drift');
  if (process.version !== 'v22.23.1' || process.platform !== 'linux' || process.arch !== 'x64') fail(`Node runtime/platform/arch drift: ${process.version}/${process.platform}/${process.arch}`);
  return {
    nodeRuntime: { runtime: 'node', version: process.version, platform: process.platform, arch: process.arch },
    rootPackageLock: repoPin('package-lock.json'),
    libauth: {
      package: repoPin('node_modules/@bitauth/libauth/package.json'),
      buildIndex: repoPin('node_modules/@bitauth/libauth/build/index.js'),
      compilerUtils: repoPin('node_modules/@bitauth/libauth/build/lib/compiler/compiler-utils.js'),
      version: installed.version, npmIntegrity: libauth.integrity, assemblerExport: 'assembleBytecodeBCH'
    }
  };
};
const bchnBinding = () => ({
  repository: 'Bitcoin-Cash-Node', commit: BCHN_COMMIT,
  files: ['src/script/script.h', 'src/script/script.cpp', 'src/script/interpreter.cpp', 'src/policy/policy.h'].map((path) => filePin(BCHN_ROOT, path))
});
const upstreamBinding = () => {
  const artifactBytes = readFileSync(repoFile(IR_PATH));
  const artifact = JSON.parse(artifactBytes);
  if (sha256(artifactBytes) !== EXPECTED_IR_RAW_SHA256 || artifact.contentDigest?.value !== EXPECTED_IR_CONTENT_DIGEST || sha256(readFileSync(repoFile(IR_SCHEMA_PATH))) !== EXPECTED_IR_SCHEMA_SHA256) fail('approved IR raw/content/schema pin mismatch');
  assertKnownPassingPackageDigest(artifact, EXPECTED_IR_CONTENT_DIGEST);
  const regenerated = generatePackage();
  if (irCanonicalJson(artifact) !== irCanonicalJson(regenerated)) fail('approved IR does not exactly regenerate');
  return {
    path: IR_PATH, rawSha256: EXPECTED_IR_RAW_SHA256, contentDigest: EXPECTED_IR_CONTENT_DIGEST, schemaSha256: EXPECTED_IR_SCHEMA_SHA256,
    authorityModulePins: [
      repoPin('research-lanes/bch-shielded-pool-design/p2/lowering-arm-ir-freeze/generate.mjs'),
      repoPin('research-lanes/bch-shielded-pool-design/p2/lowering-arm-ir-freeze/physical-plan.mjs'),
      repoPin('research-lanes/bch-shielded-pool-design/p2/lowering-arm-ir-freeze/arm-ssa.mjs')
    ]
  };
};
const opcodeTableFor = (built) => {
  const names = new Set();
  for (const { plan } of built) for (const instruction of plan.instructions) {
    for (const token of finalizedRecipeFor(instruction).tokens) if (token.text.startsWith('OP_')) names.add(token.text);
  }
  const scriptH = readFileSync(bchnFile('src/script/script.h'), 'utf8');
  const requireEnumByte = (name) => {
    const match = scriptH.match(new RegExp(`^\\s*${name}\\s*=\\s*0x([0-9a-fA-F]{1,2})\\b`, 'mu'));
    if (!match) fail(`pinned BCHN script.h lacks direct enum byte for ${name}`);
    return Number.parseInt(match[1], 16);
  };
  const pushRangeWitness = [requireEnumByte('OP_0'), requireEnumByte('OP_PUSHDATA1')];
  if (pushRangeWitness[0] !== 0x00 || pushRangeWitness[1] !== 0x4c) fail('pinned BCHN direct-push byte range witness drift');
  return [...names].sort().map((name) => {
    const push = name.match(/^OP_PUSHBYTES_([1-9]|[1-6][0-9]|7[0-5])$/u);
    const expectedByte = push ? Number(push[1]) : requireEnumByte(name);
    const assembled = assembleBytecodeBCH(name);
    if (!assembled.success || assembled.bytecode.length !== 1 || assembled.bytecode[0] !== expectedByte) fail(`assembler/BCHN opcode disagreement for ${name}`);
    return { name, byte: `0x${expectedByte.toString(16).padStart(2, '0')}`, scriptHBinding: push ? 'direct-push-byte-range' : 'direct-enum' };
  });
};
const recipeBinding = (opcodeTable) => ({
  version: RECIPE_VERSION,
  assembler: 'assembleBytecodeBCH',
  sourceFormat: 'one-exact-physical-plan-instruction-per-LF-terminated-line; no-comments-no-blank-lines-no-trailing-whitespace',
  literalFormat: 'minimal-scriptnum-or-explicit-raw-bytes; explicit-push-opcode-plus-lowercase-0x-hex-for-non-small-pushes',
  rawByteRule: 'raw masks and zero comparator are OP_PUSHBYTES_1 0xNN; OP_0 is forbidden for raw 00',
  primitiveRecipes: clone(PRIMITIVE_RECIPE_AUTHORITY),
  opcodeTable
});

export const generateSourceSet = () => {
  const upstream = upstreamBinding();
  const physical = generatePhysicalPlans();
  if (physical.plans.length !== 42 || physical.plans.reduce((sum, plan) => sum + plan.instructions.length, 0) !== 25098) fail('regenerated physical authority cardinality drift');
  const built = physical.plans.map((plan, orderIndex) => ({ plan, orderIndex, paths: planPaths(plan, orderIndex), ...buildPlanArtifacts(plan, orderIndex) }));
  if (built.some((entry, index) => entry.plan.planId !== physical.plans[index].planId)) fail('plan order drift');
  const planIndex = built.map(({ plan, orderIndex, paths, asm, bytecode, map, mapBytes, hex }) => ({
    orderIndex, planId: plan.planId, ...paths,
    sourceSha256: sha256(bytes(asm)), bytecodeSha256: sha256(bytecode), mapSha256: sha256(mapBytes),
    sourceBytes: Buffer.byteLength(asm, 'utf8'), bytecodeBytes: bytecode.length, mapBytes: mapBytes.length, hexFileBytes: Buffer.byteLength(hex, 'utf8'),
    sourceMapDigest: map.contentDigest
  }));
  const opcodeTable = opcodeTableFor(built);
  assertPrimitiveRecipeAuthority(PRIMITIVE_RECIPE_AUTHORITY);
  const root = {
    schema: 'shieldkit-labs/p2/source-set/v1', artifactId: 'source-set:mechanical-bch-script-v1', status: 'mechanical-source-bytecode-only-no-vm-execution',
    schemaBinding: {
      rootSchema: schemaPin('shieldkit-labs/p2/source-set/v1', ROOT_SCHEMA_PATH),
      planSourceMapSchema: schemaPin('shieldkit-labs/p2/source-set/plan-source-map/v1', MAP_SCHEMA_PATH)
    },
    implementationBinding: { files: [repoPin(GENERATOR_PATH), repoPin(VALIDATOR_PATH), repoPin(TEST_PATH)] },
    boundary: { sourceAndBytecodeArtifactOnly: true, vmExecutionAllowed: false, campaignAllowed: false, metricsAllowed: false, selectionAllowed: false },
    upstreamBinding: upstream, toolchainBinding: toolchainBinding(), bchnBinding: bchnBinding(), recipe: recipeBinding(opcodeTable), planIndex,
    cardinalities: {
      plans: built.length, instructions: built.reduce((sum, entry) => sum + entry.plan.instructions.length, 0), parserInvocations: physical.counts.parserInvocations,
      sourceBytes: planIndex.reduce((sum, row) => sum + row.sourceBytes, 0), bytecodeBytes: planIndex.reduce((sum, row) => sum + row.bytecodeBytes, 0), mapBytes: planIndex.reduce((sum, row) => sum + row.mapBytes, 0),
      minPlanSourceBytes: Math.min(...planIndex.map((row) => row.sourceBytes)), maxPlanSourceBytes: Math.max(...planIndex.map((row) => row.sourceBytes)),
      minPlanBytecodeBytes: Math.min(...planIndex.map((row) => row.bytecodeBytes)), maxPlanBytecodeBytes: Math.max(...planIndex.map((row) => row.bytecodeBytes)),
      minPlanMapBytes: Math.min(...planIndex.map((row) => row.mapBytes)), maxPlanMapBytes: Math.max(...planIndex.map((row) => row.mapBytes))
    },
    nonClaims: ['not BCH-VM execution', 'not campaign/corpus/metric evidence', 'not a standardness, limit, ranking, selection, protocol, soundness, or qualification claim'],
    contentDigest: null
  };
  root.contentDigest = contentDigestFor(root);
  return { root, built };
};

const outputEntries = (generated) => [
  ...STATIC_FILES,
  'source-set.v1.json',
  ...generated.built.flatMap((entry) => [entry.paths.asmPath, entry.paths.hexPath, entry.paths.mapPath])
];
export const manifestFor = (generated) => ({
  schema: 'shieldkit-labs/p2/source-set/raw-manifest/v1',
  files: outputEntries(generated).map((path, orderIndex) => {
    const absolute = sourceFile(path);
    const value = readFileSync(absolute);
    if (value.includes(0x0d)) fail(`CR byte in package output ${path}`);
    return { orderIndex, path, byteCount: value.length, fileDigest: rawDigest(value) };
  })
});
export const sha256SumsFor = (generated, manifestBytes) => `${[
  ...outputEntries(generated).map((path) => `${sha256(readFileSync(sourceFile(path)))}  ${path}`),
  `${sha256(manifestBytes)}  MANIFEST.json`
].join('\n')}\n`;

export const writeSourceSet = () => {
  const generated = generateSourceSet();
  mkdirSync(resolve(DIRECTORY, 'plans'), { recursive: true });
  for (const entry of generated.built) {
    writeFileSync(sourceOutput(entry.paths.asmPath), entry.asm, 'utf8');
    writeFileSync(sourceOutput(entry.paths.hexPath), entry.hex, 'utf8');
    writeFileSync(sourceOutput(entry.paths.mapPath), entry.mapBytes);
  }
  writeFileSync(sourceOutput('source-set.v1.json'), canonicalJson(generated.root), 'utf8');
  const manifest = manifestFor(generated);
  const manifestBytes = bytes(canonicalJson(manifest));
  writeFileSync(sourceOutput('MANIFEST.json'), manifestBytes);
  writeFileSync(sourceOutput('SHA256SUMS'), sha256SumsFor(generated, manifestBytes), 'utf8');
  return generated;
};

export const checkSourceSet = () => {
  const generated = generateSourceSet();
  const expectedPlanFiles = new Set(generated.built.flatMap((entry) => [entry.paths.asmPath.slice('plans/'.length), entry.paths.hexPath.slice('plans/'.length), entry.paths.mapPath.slice('plans/'.length)]));
  const actualPlanEntries = readdirSync(sourceFile('plans'), { withFileTypes: true });
  if (actualPlanEntries.some((entry) => !entry.isFile())) fail('plans roster contains a non-file entry');
  assertExactRoster(expectedPlanFiles, actualPlanEntries.map((entry) => entry.name), 'plans');
  const expectedTopLevel = new Set([...STATIC_FILES, 'plans', 'source-set.v1.json', 'MANIFEST.json', 'SHA256SUMS']);
  assertExactRoster(expectedTopLevel, readdirSync(DIRECTORY, { withFileTypes: true }).map((entry) => entry.name), 'package');
  const expected = new Map([
    ['source-set.v1.json', bytes(canonicalJson(generated.root))],
    ...generated.built.flatMap((entry) => [[entry.paths.asmPath, bytes(entry.asm)], [entry.paths.hexPath, bytes(entry.hex)], [entry.paths.mapPath, entry.mapBytes]])
  ]);
  for (const [path, expectedBytes] of expected) {
    const actual = readFileSync(sourceFile(path));
    if (!actual.equals(expectedBytes)) fail(`deterministic regeneration mismatch: ${path}`);
  }
  for (const entry of generated.built) validatePlanEmission(entry);
  const manifest = manifestFor(generated);
  const manifestBytes = bytes(canonicalJson(manifest));
  if (!readFileSync(sourceFile('MANIFEST.json')).equals(manifestBytes)) fail('MANIFEST.json mismatch');
  if (readFileSync(sourceFile('SHA256SUMS'), 'utf8') !== sha256SumsFor(generated, manifestBytes)) fail('SHA256SUMS mismatch');
  return generated;
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes('--write')) writeSourceSet();
  else if (process.argv.includes('--check')) checkSourceSet();
  else fail('usage: node generate.mjs --write|--check');
}
