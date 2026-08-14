import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  canonicalJson,
  evaluateArmSsa,
  generateArmSsa,
  sha256,
  validateArmSsaProgram
} from './arm-ssa.mjs';

/*
 * This is a symbolic, executable stack plan. It is deliberately not BCH
 * source or bytecode: each instruction names its exact typed stack effect so
 * that a future source lowerer has one unambiguous object to implement.
 */
const here = dirname(fileURLToPath(import.meta.url));
const schedule = JSON.parse(readFileSync(resolve(here, '../schedule-freeze/schedule-freeze.v1.json'), 'utf8'));
const lowering = JSON.parse(readFileSync(resolve(here, '../lowering-freeze/lowering-freeze.v1.json'), 'utf8'));

const fail = (message) => { throw new TypeError(`physical-plan: ${message}`); };
const clone = (value) => structuredClone(value);
const mod = (value, modulus) => ((value % modulus) + modulus) % modulus;
const textBool = (value) => value ? 'true' : 'false';
const asBool = (value) => {
  if (value === 'true') return true;
  if (value === 'false') return false;
  fail(`invalid boolean item value ${value}`);
};
const asBigInt = (value, label = 'integer') => {
  try { return BigInt(value); } catch { fail(`${label} is not an integer`); }
};
const digestWithout = (value, key = 'contentDigest') => {
  const copy = clone(value);
  delete copy[key];
  return sha256(canonicalJson(copy));
};
const canonicalObjectEqual = (left, right) => canonicalJson(left) === canonicalJson(right);

export const PRIMITIVE_VOCABULARY = Object.freeze([
  'bytes.assert_length_exact',
  'bytes.split_at_exact',
  'bytes.assert_mask_zero',
  'bytes.cat_zero_sign_byte',
  'scriptnum.bin2num',
  'integer.assert_nonnegative',
  'integer.assert_lt_const',
  'bytes.assert_empty',
  'stack.assert_depth_exact',
  'stack.pick',
  'stack.dup',
  'stack.drop',
  'stack.toalt',
  'stack.fromalt',
  'field.arithmetic',
  'field.canonicalize_identity',
  'boolean.equal',
  'boolean.and',
  'boolean.or',
  'integer.is_nonzero',
  'integer.equals_const'
]);
const primitiveSet = new Set(PRIMITIVE_VOCABULARY);

const RELATIONS = Object.freeze({
  'relation:e-mac': Object.freeze({
    relationTargetId: 'relation:e-mac',
    rawBottomToTop: ['D', 'C', 'B', 'A'],
    parseTopFirst: ['A', 'B', 'C', 'D'],
    parserInvocationCount: 4,
    armProgramKind: 'multiply',
    parsedPrefixByRawRole: { A: 'a', B: 'b', C: 'C', D: 'D' },
    relationOperation: 'arm(A,B)+C=D'
  }),
  'relation:e-square-mac': Object.freeze({
    relationTargetId: 'relation:e-square-mac',
    rawBottomToTop: ['D', 'C', 'A'],
    parseTopFirst: ['A', 'C', 'D'],
    parserInvocationCount: 3,
    armProgramKind: 'square',
    parsedPrefixByRawRole: { A: 'a', C: 'C', D: 'D' },
    relationOperation: 'square(A)+C=D'
  }),
  'relation:e-inverse-check': Object.freeze({
    relationTargetId: 'relation:e-inverse-check',
    rawBottomToTop: ['H', 'A'],
    parseTopFirst: ['A', 'H'],
    parserInvocationCount: 2,
    armProgramKind: 'multiply',
    // H is the second multiply formal. This is a binding to the parsed H
    // bytes, not a renamed/created coefficient: parser invocation parse:H
    // produces the actual b.c* formals consumed by the arm program.
    parsedPrefixByRawRole: { A: 'a', H: 'b' },
    relationOperation: 'A!=0 and arm(A,H)=[1,0,...]'
  })
});
export const relationWrappers = RELATIONS;
export const CANONICAL_RELATION_IDS = Object.freeze(Object.keys(RELATIONS));

const relationFor = (relationTargetId) => {
  if (typeof relationTargetId !== 'string' || !Object.hasOwn(RELATIONS, relationTargetId)) {
    fail('relationTargetId must be one of the canonical relation IDs');
  }
  return RELATIONS[relationTargetId];
};

const codecRows = schedule.fieldConstructions.map((construction) => Object.freeze({
  constructionId: construction.constructionId,
  fieldSpecRef: construction.fieldSpecRef,
  codecId: construction.codec.codecId,
  degree: construction.degree,
  modulus: construction.p,
  limbBytes: construction.codec.baseLimbBytes,
  elementBytes: construction.codec.elementBytes,
  modulusBitLength: construction.codec.modulusBitLength,
  unusedHighBits: construction.codec.unusedHighBits,
  unusedHighBitMaskHex: construction.codec.unusedHighBitMaskHex,
  coefficientOrder: construction.codec.coefficientOrder,
  codec: clone(construction.codec)
}));
export const codecs = Object.freeze(codecRows);
const codecByConstruction = new Map(codecRows.map((codec) => [codec.constructionId, codec]));
const constructionById = new Map(schedule.fieldConstructions.map((construction) => [construction.constructionId, construction]));

const codecFor = (constructionOrCodec) => {
  const constructionId = constructionOrCodec?.constructionId;
  const codecId = constructionOrCodec?.codecId;
  const found = constructionId ? codecByConstruction.get(constructionId) : codecRows.find((codec) => codec.codecId === codecId);
  if (!found) fail('unknown frozen construction/codec binding');
  return found;
};

const transientStackContract = (primaryAdditionalPeak = 0, typedTransientItems = [], description = 'no additional item crosses this primitive boundary') => ({
  exactAtPrimitiveBoundary: true,
  primaryAdditionalPeak,
  altAdditionalPeak: 0,
  typedTransientItems,
  description
});
const contract = (consumes, produces, detail = {}) => ({
  consumes,
  produces,
  transientStackContract: transientStackContract(),
  ...detail
});
const instruction = (id, primitive, effects, detail = {}) => {
  if (!primitiveSet.has(primitive)) fail(`primitive ${primitive} is outside the closed vocabulary`);
  if (!effects?.transientStackContract) fail(`${id}: primitive lacks an exact transient stack contract`);
  return { id, primitive, effects, ...detail };
};

const deepSubstitute = (value, substitutions) => {
  if (typeof value === 'string') return value.replace(/\{\{([A-Za-z][A-Za-z0-9_]*)\}\}/gu, (_, key) => {
    if (!Object.hasOwn(substitutions, key)) fail(`parser template lacks substitution ${key}`);
    return substitutions[key];
  });
  if (Array.isArray(value)) return value.map((entry) => deepSubstitute(entry, substitutions));
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, deepSubstitute(entry, substitutions)]));
  return value;
};

const parserTemplatesFor = (codec) => {
  const output = [];
  const elementExact = '{{invocationId}}:element:exact';
  output.push(instruction('{{invocationId}}:length', 'bytes.assert_length_exact', contract(['RawElementBytes'], ['ExactElementBytes'], {
    inputValueId: '{{rawValueId}}', outputValueId: elementExact, exactBytes: codec.elementBytes,
    transientStackContract: transientStackContract(2, [
      { type: 'ScriptNum', value: String(codec.elementBytes), provenance: 'exact-OP_SIZE-result' },
      { type: 'ScriptNumConstant', value: String(codec.elementBytes), provenance: 'exact-byte-length-constant' }
    ], 'phase-accurate OP_SIZE result and exact-length constant comparison envelope')
  })));
  let remainder = elementExact;
  for (let coefficientIndex = codec.degree - 1; coefficientIndex >= 0; coefficientIndex -= 1) {
    const prefix = `{{invocationId}}:remainder:c${coefficientIndex}`;
    const limb = `{{invocationId}}:limb:c${coefficientIndex}`;
    const masked = `{{invocationId}}:masked:c${coefficientIndex}`;
    const signed = `{{invocationId}}:signed:c${coefficientIndex}`;
    const decoded = `{{invocationId}}:decoded:c${coefficientIndex}`;
    const nonnegative = `{{invocationId}}:nonnegative:c${coefficientIndex}`;
    const outputValueId = `{{outputPrefix}}.c${coefficientIndex}`;
    output.push(instruction(`{{invocationId}}:split:c${coefficientIndex}`, 'bytes.split_at_exact', contract(['ExactElementBytes|RawRemainderBytes'], ['RawRemainderBytes', 'FixedLimbBytes'], {
      inputValueId: remainder,
      leftValueId: prefix,
      rightValueId: limb,
      leftBytes: coefficientIndex * codec.limbBytes,
      rightBytes: codec.limbBytes,
      exactSplit: true,
      transientStackContract: transientStackContract(1, [{ type: 'ScriptNumConstant', value: String(coefficientIndex * codec.limbBytes), provenance: 'exact-split-index-constant' }], 'exact split-index constant')
    })));
    output.push(instruction(`{{invocationId}}:mask:c${coefficientIndex}`, 'bytes.assert_mask_zero', contract(['FixedLimbBytes'], ['MaskedLimbBytes'], {
      inputValueId: limb,
      outputValueId: masked,
      maskHex: codec.unusedHighBitMaskHex,
      checkedByte: 'most-significant-limb-byte',
      policy: 'reject-before-numeric-decode',
      transientStackContract: transientStackContract(3, [
        { type: 'RawRemainderBytes', value: 'OP_SPLIT-prefix', provenance: 'source-candidate-first-peak-prefix' },
        { type: 'Byte', value: 'OP_SPLIT-one-byte-suffix', provenance: 'source-candidate-first-peak-most-significant-byte' },
        { type: 'ByteMaskConstant', value: codec.unusedHighBitMaskHex, provenance: 'source-candidate-first-peak-raw-mask-byte' }
      ], 'phase-accurate symbolic source-candidate high-bit mask envelope; no source, bytecode, or VM execution claim'),
      sourceCandidateMacroTrace: {
        status: 'symbolic-unexecuted-source-candidate-only',
        typedBoundary: { input: 'L:FixedLimbBytes', output: 'L:MaskedLimbBytes', transition: 'L->L' },
        tokens: ['OP_DUP', `<${codec.limbBytes - 1}>`, 'OP_SPLIT', `<0x${codec.unusedHighBitMaskHex}>`, 'OP_AND', '<0x00>', 'OP_EQUALVERIFY', 'OP_DROP'],
        phases: [
          {
            phase: 'first-peak-after-raw-mask-push',
            primaryAdditionalPeak: 3,
            typedTransientItems: [
              { type: 'RawRemainderBytes', value: 'OP_SPLIT-prefix', provenance: 'source-candidate-first-peak-prefix' },
              { type: 'Byte', value: 'OP_SPLIT-one-byte-suffix', provenance: 'source-candidate-first-peak-most-significant-byte' },
              { type: 'ByteMaskConstant', value: codec.unusedHighBitMaskHex, provenance: 'source-candidate-first-peak-raw-mask-byte' }
            ]
          },
          {
            phase: 'later-peak-after-raw-zero-comparator-push',
            primaryAdditionalPeak: 3,
            typedTransientItems: [
              { type: 'RawRemainderBytes', value: 'OP_SPLIT-prefix', provenance: 'source-candidate-later-peak-prefix' },
              { type: 'Byte', value: 'OP_AND-result', provenance: 'source-candidate-later-peak-masked-high-byte' },
              { type: 'ByteConstant', value: '00', provenance: 'source-candidate-later-peak-raw-one-byte-zero-comparator-not-OP_0' }
            ]
          }
        ]
      }
    })));
    output.push(instruction(`{{invocationId}}:zero-sign:c${coefficientIndex}`, 'bytes.cat_zero_sign_byte', contract(['MaskedLimbBytes'], ['ZeroSignScriptBytes'], {
      inputValueId: masked,
      outputValueId: signed,
      appendedByteHex: '00',
      zeroSignByteProvenance: {
        opcodeSequence: ['OP_1', 'OP_1', 'OP_XOR'],
        exactResultByteHex: '00',
        purpose: 'force-nonnegative-scriptnum-sign-byte'
      },
      transientStackContract: transientStackContract(2, [
        { type: 'ScriptNumConstant', value: '1', provenance: 'OP_1:first' },
        { type: 'ScriptNumConstant', value: '1', provenance: 'OP_1:second' }
      ], 'OP_1 OP_1 OP_XOR creates the exact zero-sign byte before concatenation')
    })));
    output.push(instruction(`{{invocationId}}:bin2num:c${coefficientIndex}`, 'scriptnum.bin2num', contract(['ZeroSignScriptBytes'], ['ScriptNum'], {
      inputValueId: signed, outputValueId: decoded
    })));
    output.push(instruction(`{{invocationId}}:nonnegative:c${coefficientIndex}`, 'integer.assert_nonnegative', contract(['ScriptNum'], ['NonnegativeScriptNum'], {
      inputValueId: decoded, outputValueId: nonnegative,
      transientStackContract: transientStackContract(2, [
        { type: 'ScriptNum', value: 'duplicate-of-input', provenance: 'symbolic preservation duplicate' },
        { type: 'ScriptNumConstant', value: '0', provenance: 'nonnegative-lower-bound' }
      ], 'conservative symbolic nonnegative comparison envelope')
    })));
    output.push(instruction(`{{invocationId}}:lt-p:c${coefficientIndex}`, 'integer.assert_lt_const', contract(['NonnegativeScriptNum'], ['FpCanonical'], {
      inputValueId: nonnegative, outputValueId, constant: codec.modulus, comparison: 'n<p',
      transientStackContract: transientStackContract(2, [
        { type: 'NonnegativeScriptNum', value: 'duplicate-of-input', provenance: 'symbolic preservation duplicate' },
        { type: 'ScriptNumConstant', value: codec.modulus, provenance: 'frozen-field-modulus' }
      ], 'conservative symbolic n<p comparison envelope')
    })));
    output.push(instruction(`{{invocationId}}:toalt:c${coefficientIndex}`, 'stack.toalt', contract(['FpCanonical'], ['FpCanonical'], {
      expectedValueId: outputValueId, transfer: 'primary-to-alt'
    })));
    remainder = prefix;
  }
  output.push(instruction('{{invocationId}}:leftover-empty', 'bytes.assert_empty', contract(['RawRemainderBytes'], [], {
    inputValueId: remainder, exactLeftoverBytes: 0,
    transientStackContract: transientStackContract(2, [
      { type: 'ScriptNum', value: '0', provenance: 'exact-OP_SIZE-result' },
      { type: 'ScriptNumConstant', value: '0', provenance: 'exact-leftover-length' }
    ], 'phase-accurate OP_SIZE result and zero-length constant comparison envelope')
  })));
  for (let coefficientIndex = 0; coefficientIndex < codec.degree; coefficientIndex += 1) {
    output.push(instruction(`{{invocationId}}:fromalt:c${coefficientIndex}`, 'stack.fromalt', contract(['FpCanonical'], ['FpCanonical'], {
      expectedValueId: `{{outputPrefix}}.c${coefficientIndex}`, transfer: 'alt-to-primary'
    })));
  }
  return output;
};

export function parserTemplate(constructionOrCodec, relationTargetId) {
  if (relationTargetId !== undefined) fail('parser modules are relation-neutral and do not accept a relation target');
  const codec = codecFor(constructionOrCodec);
  const module = {
    moduleId: `parser:${codec.codecId}:direct-wire-v1`,
    moduleKind: 'direct-codec-parser',
    constructionId: codec.constructionId,
    codecId: codec.codecId,
    degree: codec.degree,
    codecBinding: {
      limbBytes: codec.limbBytes,
      elementBytes: codec.elementBytes,
      unusedHighBitMaskHex: codec.unusedHighBitMaskHex,
      modulus: codec.modulus,
      coefficientOrder: codec.coefficientOrder
    },
    parameters: ['invocationId', 'rawValueId', 'outputPrefix'],
    primaryEntry: ['RawElementBytes at primary top'],
    primaryExit: Array.from({ length: codec.degree }, (_, index) => `{{outputPrefix}}.c${index}:FpCanonical`),
    altEffect: 'preserves pre-existing alt items and restores this invocation items only',
    instructionTemplates: parserTemplatesFor(codec)
  };
  module.contentDigest = digestWithout(module);
  return module;
}
export const buildParserTemplate = parserTemplate;

export function instantiateParserModule(module, { invocationId, rawValueId, outputPrefix } = {}) {
  if (!module || module.moduleKind !== 'direct-codec-parser') fail('invalid parser module');
  for (const [name, value] of Object.entries({ invocationId, rawValueId, outputPrefix })) if (typeof value !== 'string' || value.length === 0) fail(`parser invocation ${name} is required`);
  return deepSubstitute(module.instructionTemplates, { invocationId, rawValueId, outputPrefix });
}

const wrapperTemplate = (relationTargetId) => {
  const relation = relationFor(relationTargetId);
  const template = {
    moduleId: `wrapper-template:${relation.relationTargetId}:v1`,
    moduleKind: 'relation-wrapper-template',
    relationTargetId: relation.relationTargetId,
    degreeBinding: 'required-at-instantiation',
    parserInvocationCount: relation.parserInvocationCount,
    rawBottomToTop: relation.rawBottomToTop,
    parseTopFirst: relation.parseTopFirst,
    armProgramKind: relation.armProgramKind,
    relationOperation: relation.relationOperation,
    templateInstructionFamilies: relation.relationTargetId === 'relation:e-inverse-check'
      ? ['coefficientwise-nonzero-or', 'arm-output-fetch', 'equals-constant-vector', 'boolean-and', 'explicit-drop-cleanup']
      : ['arm-output-fetch', 'add-actual-C', 'equals-actual-D', 'boolean-and', 'explicit-drop-cleanup']
  };
  template.contentDigest = digestWithout(template);
  return template;
};

export function buildRelationWrapper({ construction, relationTargetId, relationTarget } = {}) {
  const relation = relationFor(relationTargetId ?? relationTarget);
  const codec = codecFor(construction);
  const template = wrapperTemplate(relation.relationTargetId);
  const instance = {
    moduleId: `wrapper-instance:${relation.relationTargetId}:${codec.codecId}:d${codec.degree}:v1`,
    moduleKind: 'relation-wrapper-instance',
    relationTargetId: relation.relationTargetId,
    templateModuleId: template.moduleId,
    templateDigest: template.contentDigest,
    constructionId: codec.constructionId,
    codecId: codec.codecId,
    degree: codec.degree,
    parserModuleId: parserTemplate(codec).moduleId,
    parserInvocationCount: relation.parserInvocationCount,
    rawBottomToTop: relation.rawBottomToTop,
    parseTopFirst: relation.parseTopFirst,
    armProgramKind: relation.armProgramKind
  };
  instance.contentDigest = digestWithout(instance);
  return instance;
}

const encodeMinimalScriptNum = (input) => {
  let value = asBigInt(input, 'script number');
  if (value === 0n) return '';
  const negative = value < 0n;
  if (negative) value = -value;
  const bytes = [];
  while (value > 0n) {
    bytes.push(Number(value & 0xffn));
    value >>= 8n;
  }
  if ((bytes.at(-1) & 0x80) !== 0) bytes.push(negative ? 0x80 : 0x00);
  else if (negative) bytes[bytes.length - 1] |= 0x80;
  return Buffer.from(bytes).toString('hex');
};

const decodeScriptNum = (hex) => {
  if (typeof hex !== 'string' || !/^(?:[0-9a-f]{2})*$/u.test(hex)) fail('scriptnum bytes are not lowercase hexadecimal');
  if (hex.length === 0) return 0n;
  const bytes = Buffer.from(hex, 'hex');
  const negative = (bytes.at(-1) & 0x80) !== 0;
  const copy = Buffer.from(bytes);
  copy[copy.length - 1] &= 0x7f;
  let result = 0n;
  for (let index = copy.length - 1; index >= 0; index -= 1) result = (result << 8n) + BigInt(copy[index]);
  return negative ? -result : result;
};

const assertPinnedMinimalScriptNum = (canonical, encoded) => {
  if (encodeMinimalScriptNum(canonical) !== encoded) fail('scale/constant is not encoded by the pinned minimal ScriptNum rule');
  if (decodeScriptNum(encoded) !== asBigInt(canonical)) fail('scale/constant ScriptNum decode mismatch');
};

const fixedLimbHex = (value, bytes) => {
  let number = asBigInt(value, 'coefficient');
  if (number < 0n) fail('cannot encode a negative field coefficient');
  const result = Buffer.alloc(bytes);
  for (let index = 0; index < bytes; index += 1) {
    result[index] = Number(number & 0xffn);
    number >>= 8n;
  }
  if (number !== 0n) fail('coefficient does not fit the frozen limb width');
  return result.toString('hex');
};
const elementHex = (coefficients, codec) => {
  if (!Array.isArray(coefficients) || coefficients.length !== codec.degree) fail('direct element degree mismatch');
  const p = asBigInt(codec.modulus);
  const hex = coefficients.map((coefficient) => {
    const value = asBigInt(coefficient, 'coefficient');
    if (value < 0n || value >= p) fail('cannot serialize non-canonical coefficient');
    return fixedLimbHex(value, codec.limbBytes);
  }).join('');
  if (hex.length !== codec.elementBytes * 2) fail('direct element byte-length mismatch');
  return hex;
};

const deterministicVector = (modulus, degree, seed) => Array.from({ length: degree }, (_, index) => {
  const i = BigInt(index + 1);
  return mod((BigInt(seed + 17) * i * i * i) + (BigInt(seed * 41 + 13) * i) + BigInt(index + 3), modulus);
});
const addVectors = (left, right, modulus) => left.map((value, index) => mod(value + right[index], modulus));
const oneVector = (degree) => [1n, ...Array(degree - 1).fill(0n)];

const relationFixture = (arm, relation, codec) => {
  const program = arm.programs[relation.armProgramKind];
  const p = asBigInt(codec.modulus);
  let coefficientVectors;
  if (relation.relationTargetId === 'relation:e-mac') {
    const A = deterministicVector(p, codec.degree, arm.orderIndex + 7);
    const B = deterministicVector(p, codec.degree, arm.orderIndex + 31);
    const C = deterministicVector(p, codec.degree, arm.orderIndex + 59);
    const product = evaluateArmSsa(program, Object.fromEntries([
      ...A.map((value, index) => [`a.c${index}`, value]),
      ...B.map((value, index) => [`b.c${index}`, value])
    ]));
    coefficientVectors = { A, B, C, D: addVectors(product, C, p) };
  } else if (relation.relationTargetId === 'relation:e-square-mac') {
    const A = deterministicVector(p, codec.degree, arm.orderIndex + 11);
    const C = deterministicVector(p, codec.degree, arm.orderIndex + 47);
    const square = evaluateArmSsa(program, Object.fromEntries(A.map((value, index) => [`a.c${index}`, value])));
    coefficientVectors = { A, C, D: addVectors(square, C, p) };
  } else {
    const A = oneVector(codec.degree);
    const H = oneVector(codec.degree);
    coefficientVectors = { A, H };
  }
  return Object.fromEntries(Object.entries(coefficientVectors).map(([role, values]) => [role, {
    coefficients: values.map(String),
    elementHex: elementHex(values, codec)
  }]));
};

const initialItem = (role, fixture, codec) => ({
  slotId: `input:raw:${role}`,
  valueId: `raw:${role}`,
  type: 'RawElementBytes',
  value: fixture.elementHex,
  provenance: {
    kind: 'relation-raw-input',
    role,
    codecId: codec.codecId,
    directCoefficientOrder: codec.coefficientOrder,
    decodedCoefficients: fixture.coefficients
  }
});

const outputItem = (instructionId, outputIndex, valueId, type, value, provenance) => ({
  slotId: `${instructionId}:out${outputIndex}`,
  valueId,
  type,
  value,
  provenance
});
const outputLike = (instructionId, outputIndex, valueId, type, source, extra = {}) => outputItem(instructionId, outputIndex, valueId, type, source.value, {
  derivedBy: instructionId,
  primitive: extra.primitive,
  inputSlotId: source.slotId,
  inputValueId: source.valueId,
  ...extra
});

const expectTop = (primary, valueId, type, instructionId) => {
  const item = primary.at(-1);
  if (!item) fail(`${instructionId}: primary stack underflow`);
  if (valueId !== undefined && item.valueId !== valueId) fail(`${instructionId}: expected top ${valueId}, got ${item.valueId}`);
  if (type !== undefined && item.type !== type) fail(`${instructionId}: expected ${type}, got ${item.type}`);
  return item;
};
const expectAltTop = (alt, valueId, type, instructionId) => {
  const item = alt.at(-1);
  if (!item) fail(`${instructionId}: alt stack underflow`);
  if (valueId !== undefined && item.valueId !== valueId) fail(`${instructionId}: expected alt top ${valueId}, got ${item.valueId}`);
  if (type !== undefined && item.type !== type) fail(`${instructionId}: expected alt ${type}, got ${item.type}`);
  return item;
};
const popPrimary = (primary, valueId, type, instructionId) => {
  expectTop(primary, valueId, type, instructionId);
  return primary.pop();
};
const popMany = (primary, ids, type, instructionId) => ids.map((id) => popPrimary(primary, undefined, type, instructionId)).reverse().map((item, index) => {
  if (item.valueId !== ids[index]) fail(`${instructionId}: operand ${index} expected ${ids[index]}, got ${item.valueId}`);
  return item;
});
const stateView = (primary, alt) => ({ primary: clone(primary), alt: clone(alt) });
const stateDigest = (primary, alt) => sha256(canonicalJson({ primary, alt }));
const readTransientStackContract = (entry) => {
  const declared = entry.effects?.transientStackContract;
  if (!declared || declared.exactAtPrimitiveBoundary !== true || !Number.isInteger(declared.primaryAdditionalPeak) || !Number.isInteger(declared.altAdditionalPeak)
    || declared.primaryAdditionalPeak < 0 || declared.altAdditionalPeak < 0 || !Array.isArray(declared.typedTransientItems)) {
    fail(`${entry.id}: invalid exact transient stack contract`);
  }
  if (declared.typedTransientItems.length < declared.primaryAdditionalPeak) fail(`${entry.id}: transient peak lacks typed item provenance`);
  return declared;
};

const executeInstruction = (entry, primary, alt) => {
  if (!entry || typeof entry !== 'object' || !primitiveSet.has(entry.primitive)) fail(`unknown or opaque primitive ${entry?.primitive}`);
  const effects = entry.effects;
  if (!effects || typeof effects !== 'object') fail(`${entry.id}: missing typed effect contract`);
  const exactHex = (value, label) => {
    if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})*$/u.test(value)) fail(`${entry.id}: ${label} is not lowercase hexadecimal bytes`);
    return value;
  };
  switch (entry.primitive) {
    case 'bytes.assert_length_exact': {
      const source = popPrimary(primary, effects.inputValueId, 'RawElementBytes', entry.id);
      const value = exactHex(source.value, 'raw element');
      if (value.length / 2 !== effects.exactBytes) fail(`${entry.id}: raw element length is not exact`);
      primary.push(outputLike(entry.id, 0, effects.outputValueId, 'ExactElementBytes', source, { primitive: entry.primitive, exactBytes: effects.exactBytes }));
      return;
    }
    case 'bytes.split_at_exact': {
      const source = popPrimary(primary, effects.inputValueId, undefined, entry.id);
      if (!['ExactElementBytes', 'RawRemainderBytes'].includes(source.type)) fail(`${entry.id}: split input is not exact bytes/remainder`);
      const value = exactHex(source.value, 'split input');
      const leftLength = effects.leftBytes * 2;
      const rightLength = effects.rightBytes * 2;
      if (!Number.isInteger(effects.leftBytes) || !Number.isInteger(effects.rightBytes) || value.length !== leftLength + rightLength) fail(`${entry.id}: split boundary is not exact`);
      primary.push(outputItem(entry.id, 0, effects.leftValueId, 'RawRemainderBytes', value.slice(0, leftLength), {
        derivedBy: entry.id, primitive: entry.primitive, inputSlotId: source.slotId, split: 'left', bytes: effects.leftBytes
      }));
      primary.push(outputItem(entry.id, 1, effects.rightValueId, 'FixedLimbBytes', value.slice(leftLength), {
        derivedBy: entry.id, primitive: entry.primitive, inputSlotId: source.slotId, split: 'right', bytes: effects.rightBytes
      }));
      return;
    }
    case 'bytes.assert_mask_zero': {
      const source = popPrimary(primary, effects.inputValueId, 'FixedLimbBytes', entry.id);
      const value = exactHex(source.value, 'limb');
      const mask = Number.parseInt(effects.maskHex, 16);
      if (!Number.isInteger(mask) || mask < 0 || mask > 255 || value.length < 2) fail(`${entry.id}: invalid high-bit mask contract`);
      if ((Number.parseInt(value.slice(-2), 16) & mask) !== 0) fail(`${entry.id}: unused high bits are nonzero`);
      primary.push(outputLike(entry.id, 0, effects.outputValueId, 'MaskedLimbBytes', source, { primitive: entry.primitive, maskHex: effects.maskHex }));
      return;
    }
    case 'bytes.cat_zero_sign_byte': {
      const source = popPrimary(primary, effects.inputValueId, 'MaskedLimbBytes', entry.id);
      const provenance = effects.zeroSignByteProvenance;
      if (!provenance || !canonicalObjectEqual(provenance.opcodeSequence, ['OP_1', 'OP_1', 'OP_XOR']) || provenance.exactResultByteHex !== '00' || effects.appendedByteHex !== '00') {
        fail(`${entry.id}: zero-sign byte lacks exact OP_1 OP_1 OP_XOR provenance`);
      }
      primary.push(outputItem(entry.id, 0, effects.outputValueId, 'ZeroSignScriptBytes', `${source.value}00`, {
        derivedBy: entry.id,
        primitive: entry.primitive,
        inputSlotId: source.slotId,
        zeroSignByteProvenance: clone(provenance)
      }));
      return;
    }
    case 'scriptnum.bin2num': {
      const source = popPrimary(primary, effects.inputValueId, 'ZeroSignScriptBytes', entry.id);
      const decoded = decodeScriptNum(source.value);
      primary.push(outputItem(entry.id, 0, effects.outputValueId, 'ScriptNum', String(decoded), {
        derivedBy: entry.id, primitive: entry.primitive, inputSlotId: source.slotId, inputHex: source.value
      }));
      return;
    }
    case 'integer.assert_nonnegative': {
      const source = popPrimary(primary, effects.inputValueId, 'ScriptNum', entry.id);
      if (asBigInt(source.value) < 0n) fail(`${entry.id}: ScriptNum is negative`);
      primary.push(outputLike(entry.id, 0, effects.outputValueId, 'NonnegativeScriptNum', source, { primitive: entry.primitive }));
      return;
    }
    case 'integer.assert_lt_const': {
      const source = popPrimary(primary, effects.inputValueId, 'NonnegativeScriptNum', entry.id);
      const constant = asBigInt(effects.constant, 'range constant');
      if (asBigInt(source.value) >= constant) fail(`${entry.id}: coefficient is not below p`);
      primary.push(outputLike(entry.id, 0, effects.outputValueId, 'FpCanonical', source, {
        primitive: entry.primitive, comparison: effects.comparison, constant: String(constant)
      }));
      return;
    }
    case 'bytes.assert_empty': {
      const source = popPrimary(primary, effects.inputValueId, 'RawRemainderBytes', entry.id);
      if (source.value !== '' || effects.exactLeftoverBytes !== 0) fail(`${entry.id}: parser left bytes unconsumed`);
      return;
    }
    case 'stack.assert_depth_exact': {
      if (primary.length !== effects.expectedPrimaryDepth || alt.length !== effects.expectedAltDepth) {
        fail(`${entry.id}: OP_DEPTH ABI mismatch primary=${primary.length} alt=${alt.length}`);
      }
      if (!canonicalObjectEqual(primary.map((item) => item.valueId), effects.expectedPrimaryValueIdsBottomToTop)
        || !canonicalObjectEqual(primary.map((item) => item.type), effects.expectedPrimaryTypesBottomToTop)) {
        fail(`${entry.id}: initial typed primary stack ABI mismatch`);
      }
      return;
    }
    case 'stack.pick': {
      const index = primary.findLastIndex((item) => item.valueId === effects.sourceValueId);
      if (index < 0) fail(`${entry.id}: OP_PICK source ${effects.sourceValueId} is absent`);
      const depth = primary.length - 1 - index;
      if (effects.depth !== depth) fail(`${entry.id}: OP_PICK depth ${effects.depth} is not top-most exact ${depth}`);
      const source = primary[index];
      if (effects.expectedType && source.type !== effects.expectedType) fail(`${entry.id}: OP_PICK source type mismatch`);
      primary.push(outputItem(entry.id, 0, effects.copyValueId ?? source.valueId, source.type, source.value, {
        derivedBy: entry.id, primitive: entry.primitive, sourceSlotId: source.slotId, sourceValueId: source.valueId, depth
      }));
      return;
    }
    case 'stack.dup': {
      const source = expectTop(primary, effects.sourceValueId, effects.expectedType, entry.id);
      primary.push(outputItem(entry.id, 0, effects.copyValueId ?? source.valueId, source.type, source.value, {
        derivedBy: entry.id, primitive: entry.primitive, sourceSlotId: source.slotId
      }));
      return;
    }
    case 'stack.toalt': {
      const source = popPrimary(primary, effects.expectedValueId, undefined, entry.id);
      alt.push(source);
      return;
    }
    case 'stack.fromalt': {
      const source = expectAltTop(alt, effects.expectedValueId, undefined, entry.id);
      alt.pop();
      primary.push(source);
      return;
    }
    case 'stack.drop': {
      popPrimary(primary, effects.expectedValueId, effects.expectedType, entry.id);
      return;
    }
    case 'field.arithmetic': {
      const operands = popMany(primary, effects.inputValueIds, 'FpCanonical', entry.id);
      const numbers = operands.map((item) => asBigInt(item.value, `${entry.id} operand`));
      let result;
      if (effects.operator === 'add') result = numbers[0] + numbers[1];
      else if (effects.operator === 'sub') result = numbers[0] - numbers[1];
      else if (effects.operator === 'mul') result = numbers[0] * numbers[1];
      else if (effects.operator === 'square') result = numbers[0] * numbers[1];
      else if (effects.operator === 'scale') {
        assertPinnedMinimalScriptNum(effects.scalarCanonical, effects.scalarScriptNumHex);
        result = numbers[0] * asBigInt(effects.scalarCanonical);
      } else fail(`${entry.id}: unsupported field arithmetic operation ${effects.operator}`);
      primary.push(outputItem(entry.id, 0, effects.outputValueId, 'FpInteger', String(result), {
        derivedBy: entry.id,
        primitive: entry.primitive,
        operator: effects.operator,
        operandSlots: operands.map((item) => item.slotId),
        operandValueIds: operands.map((item) => item.valueId),
        ...(effects.operator === 'scale' ? {
          scalarCanonical: effects.scalarCanonical,
          scalarScriptNumHex: effects.scalarScriptNumHex,
          scalarEncoding: 'bch-minimal-scriptnum-v1'
        } : {})
      }));
      return;
    }
    case 'field.canonicalize_identity': {
      const source = popPrimary(primary, effects.inputValueId, 'FpInteger', entry.id);
      const p = asBigInt(effects.modulus, 'field modulus');
      primary.push(outputItem(entry.id, 0, effects.outputValueId, 'FpCanonical', String(mod(asBigInt(source.value), p)), {
        derivedBy: entry.id,
        primitive: entry.primitive,
        inputSlotId: source.slotId,
        modulus: String(p),
        semantics: '((x mod p)+p) mod p'
      }));
      return;
    }
    case 'boolean.equal': {
      const [left, right] = popMany(primary, effects.inputValueIds, 'FpCanonical', entry.id);
      primary.push(outputItem(entry.id, 0, effects.outputValueId, 'Bool', textBool(asBigInt(left.value) === asBigInt(right.value)), {
        derivedBy: entry.id, primitive: entry.primitive, leftSlotId: left.slotId, rightSlotId: right.slotId,
        operandValueIds: [left.valueId, right.valueId]
      }));
      return;
    }
    case 'integer.equals_const': {
      const source = popPrimary(primary, effects.inputValueId, 'FpCanonical', entry.id);
      assertPinnedMinimalScriptNum(effects.constantCanonical, effects.constantScriptNumHex);
      primary.push(outputItem(entry.id, 0, effects.outputValueId, 'Bool', textBool(asBigInt(source.value) === asBigInt(effects.constantCanonical)), {
        derivedBy: entry.id, primitive: entry.primitive, inputSlotId: source.slotId,
        constantCanonical: effects.constantCanonical, constantScriptNumHex: effects.constantScriptNumHex
      }));
      return;
    }
    case 'integer.is_nonzero': {
      const source = popPrimary(primary, effects.inputValueId, 'FpCanonical', entry.id);
      primary.push(outputItem(entry.id, 0, effects.outputValueId, 'Bool', textBool(asBigInt(source.value) !== 0n), {
        derivedBy: entry.id, primitive: entry.primitive, inputSlotId: source.slotId
      }));
      return;
    }
    case 'boolean.and':
    case 'boolean.or': {
      const [left, right] = popMany(primary, effects.inputValueIds, 'Bool', entry.id);
      const value = entry.primitive === 'boolean.and' ? asBool(left.value) && asBool(right.value) : asBool(left.value) || asBool(right.value);
      primary.push(outputItem(entry.id, 0, effects.outputValueId, 'Bool', textBool(value), {
        derivedBy: entry.id, primitive: entry.primitive, leftSlotId: left.slotId, rightSlotId: right.slotId,
        operandValueIds: [left.valueId, right.valueId]
      }));
      return;
    }
    default:
      fail(`${entry.id}: unimplemented primitive ${entry.primitive}`);
  }
};

export function replayPhysicalPlan(plan, initialStack = plan?.initialStack, { includeFullTrace = false } = {}) {
  if (!plan || !Array.isArray(plan.instructions)) fail('plan has no instruction sequence');
  if (!initialStack || !Array.isArray(initialStack.primary) || !Array.isArray(initialStack.alt)) fail('plan has no typed initial stack');
  const primary = clone(initialStack.primary);
  const alt = clone(initialStack.alt);
  const trace = [];
  const fullTrace = includeFullTrace ? [] : undefined;
  let maxPrimaryDepth = primary.length;
  let maxAltDepth = alt.length;
  let maxCombinedDepth = primary.length + alt.length;
  for (const entry of plan.instructions) {
    const before = stateView(primary, alt);
    const beforeDigest = stateDigest(primary, alt);
    const transient = readTransientStackContract(entry);
    maxPrimaryDepth = Math.max(maxPrimaryDepth, primary.length + transient.primaryAdditionalPeak);
    maxAltDepth = Math.max(maxAltDepth, alt.length + transient.altAdditionalPeak);
    maxCombinedDepth = Math.max(maxCombinedDepth, primary.length + alt.length + transient.primaryAdditionalPeak + transient.altAdditionalPeak);
    executeInstruction(entry, primary, alt);
    const after = stateView(primary, alt);
    const afterDigest = stateDigest(primary, alt);
    maxPrimaryDepth = Math.max(maxPrimaryDepth, primary.length);
    maxAltDepth = Math.max(maxAltDepth, alt.length);
    maxCombinedDepth = Math.max(maxCombinedDepth, primary.length + alt.length);
    const row = {
      instructionId: entry.id,
      primitive: entry.primitive,
      stateDigestBefore: beforeDigest,
      stateDigestAfter: afterDigest,
      primaryDepthBefore: before.primary.length,
      primaryDepthAfter: after.primary.length,
      altDepthBefore: before.alt.length,
      altDepthAfter: after.alt.length,
      combinedDepthBefore: before.primary.length + before.alt.length,
      combinedDepthAfter: after.primary.length + after.alt.length,
      transientPrimaryAdditionalPeak: transient.primaryAdditionalPeak,
      transientAltAdditionalPeak: transient.altAdditionalPeak,
      transientTypedItems: clone(transient.typedTransientItems)
    };
    trace.push(row);
    if (includeFullTrace) fullTrace.push({ ...row, before, after });
  }
  return {
    trace,
    ...(includeFullTrace ? { fullTrace } : {}),
    terminal: stateView(primary, alt),
    maxPrimaryDepth,
    maxAltDepth,
    maxCombinedDepth
  };
}
export const simulatePhysicalPlan = replayPhysicalPlan;

class StackPlanBuilder {
  constructor(initialPrimary) {
    this.primary = initialPrimary.map((item) => ({ valueId: item.valueId, type: item.type }));
    this.alt = [];
    this.instructions = [];
  }

  top(expectedId, expectedType, instructionId) {
    const item = this.primary.at(-1);
    if (!item) fail(`${instructionId}: planning primary stack underflow`);
    if (expectedId !== undefined && item.valueId !== expectedId) fail(`${instructionId}: planning expected ${expectedId}, got ${item.valueId}`);
    if (expectedType !== undefined && item.type !== expectedType) fail(`${instructionId}: planning expected ${expectedType}, got ${item.type}`);
    return item;
  }
  altTop(expectedId, expectedType, instructionId) {
    const item = this.alt.at(-1);
    if (!item) fail(`${instructionId}: planning alt stack underflow`);
    if (expectedId !== undefined && item.valueId !== expectedId) fail(`${instructionId}: planning expected alt ${expectedId}, got ${item.valueId}`);
    if (expectedType !== undefined && item.type !== expectedType) fail(`${instructionId}: planning expected alt ${expectedType}, got ${item.type}`);
    return item;
  }
  pop(expectedId, expectedType, instructionId) {
    this.top(expectedId, expectedType, instructionId);
    return this.primary.pop();
  }
  emit(entry) {
    const item = clone(entry);
    const effects = item.effects;
    switch (item.primitive) {
      case 'bytes.assert_length_exact': {
        this.pop(effects.inputValueId, 'RawElementBytes', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'ExactElementBytes' });
        break;
      }
      case 'bytes.split_at_exact': {
        const source = this.pop(effects.inputValueId, undefined, item.id);
        if (!['ExactElementBytes', 'RawRemainderBytes'].includes(source.type)) fail(`${item.id}: planning split input type`);
        this.primary.push({ valueId: effects.leftValueId, type: 'RawRemainderBytes' });
        this.primary.push({ valueId: effects.rightValueId, type: 'FixedLimbBytes' });
        break;
      }
      case 'bytes.assert_mask_zero':
        this.pop(effects.inputValueId, 'FixedLimbBytes', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'MaskedLimbBytes' });
        break;
      case 'bytes.cat_zero_sign_byte':
        this.pop(effects.inputValueId, 'MaskedLimbBytes', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'ZeroSignScriptBytes' });
        break;
      case 'scriptnum.bin2num':
        this.pop(effects.inputValueId, 'ZeroSignScriptBytes', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'ScriptNum' });
        break;
      case 'integer.assert_nonnegative':
        this.pop(effects.inputValueId, 'ScriptNum', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'NonnegativeScriptNum' });
        break;
      case 'integer.assert_lt_const':
        this.pop(effects.inputValueId, 'NonnegativeScriptNum', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'FpCanonical' });
        break;
      case 'bytes.assert_empty':
        this.pop(effects.inputValueId, 'RawRemainderBytes', item.id);
        break;
      case 'stack.assert_depth_exact':
        if (this.primary.length !== effects.expectedPrimaryDepth || this.alt.length !== effects.expectedAltDepth) fail(`${item.id}: planning initial depth mismatch`);
        if (!canonicalObjectEqual(this.primary.map((stackItem) => stackItem.valueId), effects.expectedPrimaryValueIdsBottomToTop)
          || !canonicalObjectEqual(this.primary.map((stackItem) => stackItem.type), effects.expectedPrimaryTypesBottomToTop)) fail(`${item.id}: planning initial typed ABI mismatch`);
        break;
      case 'stack.pick': {
        const index = this.primary.findLastIndex((stackItem) => stackItem.valueId === effects.sourceValueId);
        if (index < 0) fail(`${item.id}: planning OP_PICK source absent`);
        const source = this.primary[index];
        if (effects.expectedType && source.type !== effects.expectedType) fail(`${item.id}: planning OP_PICK type mismatch`);
        const depth = this.primary.length - 1 - index;
        const scriptNumHex = encodeMinimalScriptNum(depth);
        assertPinnedMinimalScriptNum(depth, scriptNumHex);
        effects.depth = depth;
        effects.transientStackContract = transientStackContract(1, [{
          type: 'ScriptNumConstant',
          value: String(depth),
          scriptNumHex,
          provenance: 'exact-pick-depth'
        }], 'exact OP_PICK depth ScriptNum is transiently pushed then consumed');
        this.primary.push({ valueId: effects.copyValueId ?? source.valueId, type: source.type });
        break;
      }
      case 'stack.dup': {
        const source = this.top(effects.sourceValueId, effects.expectedType, item.id);
        this.primary.push({ valueId: effects.copyValueId ?? source.valueId, type: source.type });
        break;
      }
      case 'stack.toalt': {
        const source = this.pop(effects.expectedValueId, undefined, item.id);
        this.alt.push(source);
        break;
      }
      case 'stack.fromalt': {
        const source = this.altTop(effects.expectedValueId, undefined, item.id);
        this.alt.pop();
        this.primary.push(source);
        break;
      }
      case 'stack.drop':
        this.pop(effects.expectedValueId, effects.expectedType, item.id);
        break;
      case 'field.arithmetic':
        for (let index = effects.inputValueIds.length - 1; index >= 0; index -= 1) this.pop(effects.inputValueIds[index], 'FpCanonical', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'FpInteger' });
        break;
      case 'field.canonicalize_identity':
        this.pop(effects.inputValueId, 'FpInteger', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'FpCanonical' });
        break;
      case 'boolean.equal':
        for (let index = effects.inputValueIds.length - 1; index >= 0; index -= 1) this.pop(effects.inputValueIds[index], 'FpCanonical', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'Bool' });
        break;
      case 'integer.equals_const':
      case 'integer.is_nonzero':
        this.pop(effects.inputValueId, 'FpCanonical', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'Bool' });
        break;
      case 'boolean.and':
      case 'boolean.or':
        for (let index = effects.inputValueIds.length - 1; index >= 0; index -= 1) this.pop(effects.inputValueIds[index], 'Bool', item.id);
        this.primary.push({ valueId: effects.outputValueId, type: 'Bool' });
        break;
      default:
        fail(`${item.id}: planning unknown primitive ${item.primitive}`);
    }
    this.instructions.push(item);
    return item;
  }
}

const emitPick = (builder, id, sourceValueId, purpose, expectedType = 'FpCanonical') => builder.emit(instruction(id, 'stack.pick', contract(['typed stack occurrence'], ['same typed logical value'], {
  sourceValueId,
  expectedType,
  depth: null,
  purpose
})));
const emitArithmetic = (builder, id, rawNode, reduction, modulus) => {
  const physicalInputValueIds = rawNode.op === 'square' ? [rawNode.args[0], rawNode.args[0]] : [...rawNode.args];
  const effects = {
    operator: rawNode.op,
    inputValueIds: physicalInputValueIds,
    outputValueId: rawNode.id,
    sourceNodeId: rawNode.id,
    scalarCanonical: rawNode.op === 'scale' ? rawNode.scalarCanonical : undefined,
    scalarScriptNumHex: rawNode.op === 'scale' ? encodeMinimalScriptNum(rawNode.scalarCanonical) : undefined,
    transientStackContract: rawNode.op === 'scale'
      ? transientStackContract(1, [{
        type: 'ScriptNumConstant',
        value: rawNode.scalarCanonical,
        scriptNumHex: encodeMinimalScriptNum(rawNode.scalarCanonical),
        provenance: 'pinned-minimal-scriptnum-scale-constant'
      }], 'minimal ScriptNum scale constant is transiently pushed then consumed')
      : transientStackContract()
  };
  if (rawNode.op === 'scale') {
    assertPinnedMinimalScriptNum(effects.scalarCanonical, effects.scalarScriptNumHex);
    if (rawNode.scalar !== rawNode.scalarCanonical || rawNode.scalarProvenance !== 'signed-source-canonicalized-mod-p') fail(`SSA scale ${rawNode.id} lost pinned canonical provenance`);
  }
  builder.emit(instruction(id, 'field.arithmetic', contract(Array(physicalInputValueIds.length).fill('FpCanonical'), ['FpInteger'], effects)));
  builder.emit(instruction(`${id}:reduce`, 'field.canonicalize_identity', contract(['FpInteger'], ['FpCanonical'], {
    inputValueId: rawNode.id,
    outputValueId: reduction.id,
    sourceReduceNodeId: reduction.id,
    modulus: String(modulus),
    immediateAfterNodeId: rawNode.id,
    transientStackContract: transientStackContract(1, [{
      type: 'ScriptNumConstant',
      value: String(modulus),
      provenance: 'canonicalize-identity-modulus'
    }], 'conservative symbolic ((x mod p)+p) mod p modulus-constant envelope')
  })));
};

const assertProgramForRelation = (program, relation) => {
  const errors = validateArmSsaProgram(program);
  if (errors.length > 0) fail(`malformed SSA program: ${errors.join('; ')}`);
  if (program.kind !== relation.armProgramKind) fail(`relation ${relation.relationTargetId} requires ${relation.armProgramKind} SSA program`);
  const expectedInputs = relation.armProgramKind === 'multiply'
    ? [
      ...Array.from({ length: program.degree }, (_, index) => `a.c${index}`),
      ...Array.from({ length: program.degree }, (_, index) => `b.c${index}`)
    ]
    : Array.from({ length: program.degree }, (_, index) => `a.c${index}`);
  if (!canonicalObjectEqual(program.inputs.map((entry) => entry.id), expectedInputs)) fail('SSA formals do not exactly match the parsed relation formals');
  if (program.nodes.length % 2 !== 0) fail('SSA nodes are not raw/reduce pairs');
  for (let index = 0; index < program.nodes.length; index += 2) {
    const raw = program.nodes[index];
    const reduction = program.nodes[index + 1];
    if (raw.op === 'reduce' || reduction.op !== 'reduce' || reduction.args[0] !== raw.id) fail(`SSA ${raw.id} has no immediate reduction`);
  }
  const outputRefs = new Set(program.outputs.map((output) => output.ref));
  if (outputRefs.size !== program.degree || program.outputs.some((output, index) => output.coefficientIndex !== index)) fail('SSA output vector is malformed');
};

const emitParserAndExposeAll = (builder, relation, parserModule, codec) => {
  const invocations = [];
  for (const [parseIndex, rawRole] of relation.parseTopFirst.entries()) {
    const outputPrefix = relation.parsedPrefixByRawRole[rawRole];
    const invocationId = `parse:${rawRole}`;
    const expanded = instantiateParserModule(parserModule, { invocationId, rawValueId: `raw:${rawRole}`, outputPrefix });
    for (const entry of expanded) builder.emit(entry);
    invocations.push({
      invocationId,
      parserModuleId: parserModule.moduleId,
      parserModuleDigest: parserModule.contentDigest,
      rawRole,
      rawValueId: `raw:${rawRole}`,
      outputPrefix,
      parseIndex,
      rawPositionFromTopAtEntry: 0,
      initialRawPositionFromTop: parseIndex
    });
    if (parseIndex !== relation.parseTopFirst.length - 1) {
      for (let coefficientIndex = codec.degree - 1; coefficientIndex >= 0; coefficientIndex -= 1) {
        const valueId = `${outputPrefix}.c${coefficientIndex}`;
        builder.emit(instruction(`${invocationId}:stage:c${coefficientIndex}`, 'stack.toalt', contract(['FpCanonical'], ['FpCanonical'], {
          expectedValueId: valueId,
          transfer: 'primary-to-alt',
          purpose: 'reveal-next-top-first-raw-element'
        })));
      }
    }
  }
  for (const rawRole of relation.parseTopFirst.slice(0, -1).reverse()) {
    const outputPrefix = relation.parsedPrefixByRawRole[rawRole];
    for (let coefficientIndex = 0; coefficientIndex < codec.degree; coefficientIndex += 1) {
      const valueId = `${outputPrefix}.c${coefficientIndex}`;
      builder.emit(instruction(`parse:restore:${rawRole}:c${coefficientIndex}`, 'stack.fromalt', contract(['FpCanonical'], ['FpCanonical'], {
        expectedValueId: valueId,
        transfer: 'alt-to-primary',
        purpose: 'restore-direct-wire-order-after-top-first-parsing'
      })));
    }
  }
  if (builder.alt.length !== 0) fail('parser staging did not empty the alt stack');
  return invocations;
};

const emitSsa = (builder, program, modulus) => {
  for (let index = 0; index < program.nodes.length; index += 2) {
    const raw = program.nodes[index];
    const reduction = program.nodes[index + 1];
    if (raw.op === 'square') {
      emitPick(builder, `ssa:${raw.id}:pick:${raw.args[0]}:0`, raw.args[0], 'ssa-square-operand-fetch-once');
      builder.emit(instruction(`ssa:${raw.id}:dup`, 'stack.dup', contract(['FpCanonical'], ['FpCanonical'], {
        sourceValueId: raw.args[0], expectedType: 'FpCanonical', copyValueId: raw.args[0], purpose: 'ssa-square-second-operand'
      })));
    } else {
      for (const [operandIndex, ref] of raw.args.entries()) emitPick(builder, `ssa:${raw.id}:pick:${ref}:${operandIndex}`, ref, 'ssa-operand-fetch');
    }
    emitArithmetic(builder, `ssa:${raw.id}:arith`, raw, reduction, modulus);
  }
};

const emitBooleanFold = (builder, primitive, accumulatorId, nextId, outputId, id) => builder.emit(instruction(id, primitive, contract(['Bool', 'Bool'], ['Bool'], {
  inputValueIds: [accumulatorId, nextId], outputValueId: outputId
})));

const emitWrapper = (builder, relation, program, codec) => {
  let nonzeroId = null;
  if (relation.relationTargetId === 'relation:e-inverse-check') {
    for (let index = 0; index < codec.degree; index += 1) {
      const source = `a.c${index}`;
      const current = `wrapper:a-nonzero:c${index}`;
      emitPick(builder, `wrapper:nonzero:pick:a.c${index}`, source, 'inverse-nonzero-source-fetch');
      builder.emit(instruction(`wrapper:nonzero:c${index}`, 'integer.is_nonzero', contract(['FpCanonical'], ['Bool'], {
        inputValueId: source, outputValueId: current, coefficientIndex: index
      })));
      if (nonzeroId === null) nonzeroId = current;
      else {
        const folded = `wrapper:a-nonzero:through-c${index}`;
        emitBooleanFold(builder, 'boolean.or', nonzeroId, current, folded, `wrapper:nonzero:or:c${index}`);
        nonzeroId = folded;
      }
    }
  }
  let equalityId = null;
  for (const output of program.outputs) {
    const index = output.coefficientIndex;
    const outputRef = output.ref;
    emitPick(builder, `wrapper:output:pick:c${index}`, outputRef, 'wrapper-actual-ssa-output-fetch');
    const current = `wrapper:equality:c${index}`;
    if (relation.relationTargetId === 'relation:e-inverse-check') {
      const constantCanonical = String(index === 0 ? 1 : 0);
      builder.emit(instruction(`wrapper:compare-one:c${index}`, 'integer.equals_const', contract(['FpCanonical'], ['Bool'], {
        inputValueId: outputRef,
        outputValueId: current,
        constantCanonical,
        constantScriptNumHex: encodeMinimalScriptNum(constantCanonical),
        targetVectorPosition: index,
        transientStackContract: transientStackContract(1, [{
          type: 'ScriptNumConstant',
          value: constantCanonical,
          scriptNumHex: encodeMinimalScriptNum(constantCanonical),
          provenance: 'inverse-target-vector-constant'
        }], 'minimal ScriptNum inverse target constant is transiently pushed then consumed')
      })));
    } else {
      const cRef = `C.c${index}`;
      const dRef = `D.c${index}`;
      emitPick(builder, `wrapper:C:pick:c${index}`, cRef, 'wrapper-actual-C-fetch');
      const rawSum = `wrapper:sum:c${index}:raw`;
      const canonicalSum = `wrapper:sum:c${index}`;
      builder.emit(instruction(`wrapper:add-C:c${index}`, 'field.arithmetic', contract(['FpCanonical', 'FpCanonical'], ['FpInteger'], {
        operator: 'add', inputValueIds: [outputRef, cRef], outputValueId: rawSum, purpose: 'add-actual-C'
      })));
      builder.emit(instruction(`wrapper:add-C:reduce:c${index}`, 'field.canonicalize_identity', contract(['FpInteger'], ['FpCanonical'], {
        inputValueId: rawSum,
        outputValueId: canonicalSum,
        modulus: codec.modulus,
        immediateAfterNodeId: rawSum,
        transientStackContract: transientStackContract(1, [{
          type: 'ScriptNumConstant',
          value: codec.modulus,
          provenance: 'canonicalize-identity-modulus'
        }], 'conservative symbolic ((x mod p)+p) mod p modulus-constant envelope')
      })));
      emitPick(builder, `wrapper:D:pick:c${index}`, dRef, 'wrapper-actual-D-fetch');
      builder.emit(instruction(`wrapper:compare-D:c${index}`, 'boolean.equal', contract(['FpCanonical', 'FpCanonical'], ['Bool'], {
        inputValueIds: [canonicalSum, dRef], outputValueId: current, purpose: 'compare-actual-D'
      })));
    }
    if (equalityId === null) equalityId = current;
    else {
      const folded = `wrapper:equality:through-c${index}`;
      emitBooleanFold(builder, 'boolean.and', equalityId, current, folded, `wrapper:equality:and:c${index}`);
      equalityId = folded;
    }
  }
  if (relation.relationTargetId === 'relation:e-inverse-check') {
    const combined = 'wrapper:inverse-final';
    emitPick(builder, 'wrapper:nonzero:pick-final', nonzeroId, 'inverse-final-nonzero-fetch', 'Bool');
    emitBooleanFold(builder, 'boolean.and', equalityId, nonzeroId, combined, 'wrapper:inverse:and-nonzero');
    equalityId = combined;
  }
  builder.emit(instruction('terminal:preserve-derived-result', 'stack.toalt', contract(['Bool'], ['Bool'], {
    expectedValueId: equalityId, transfer: 'primary-to-alt', purpose: 'explicit-cleanup-preserve-derived-boolean'
  })));
  let cleanupIndex = 0;
  while (builder.primary.length > 0) {
    const source = builder.primary.at(-1);
    builder.emit(instruction(`terminal:drop:${String(cleanupIndex).padStart(4, '0')}`, 'stack.drop', contract([source.type], [], {
      expectedValueId: source.valueId, expectedType: source.type, purpose: 'one-by-one-explicit-terminal-cleanup'
    })));
    cleanupIndex += 1;
  }
  builder.emit(instruction('terminal:restore-derived-result', 'stack.fromalt', contract(['Bool'], ['Bool'], {
    expectedValueId: equalityId, transfer: 'alt-to-primary', purpose: 'terminal-derived-boolean'
  })));
  if (builder.primary.length !== 1 || builder.primary[0].valueId !== equalityId || builder.primary[0].type !== 'Bool' || builder.alt.length !== 0) fail('wrapper did not plan the exact terminal stack');
  return equalityId;
};

let authorityArmCache;
const authorityArmById = () => {
  if (!authorityArmCache) authorityArmCache = new Map(generateArmSsa().map((arm) => [arm.armId, arm]));
  return authorityArmCache;
};
const expectedAuthorityBinding = (arm) => {
  const frozen = lowering.arms.find((entry) => entry.armId === arm.armId);
  if (!frozen || frozen.armDigest !== arm.armDigest || frozen.formulaDigest !== arm.formulaDigest) fail(`upstream lowering binding mismatch for ${arm.armId}`);
  return frozen;
};

const materializePlan = (arm, relationTargetId, suppliedProgram) => {
  const relation = relationFor(relationTargetId);
  const codec = codecFor({ constructionId: arm.constructionId });
  const construction = constructionById.get(arm.constructionId);
  if (!construction) fail(`missing frozen construction for ${arm.armId}`);
  const program = suppliedProgram ?? arm.programs[relation.armProgramKind];
  assertProgramForRelation(program, relation);
  if (program.programDigest !== arm.programs[relation.armProgramKind].programDigest) fail('program digest does not bind the authoritative arm program');
  const frozenBinding = expectedAuthorityBinding(arm);
  const parserModule = parserTemplate(codec);
  const wrapperInstance = buildRelationWrapper({ construction: codec, relationTargetId });
  const fixture = relationFixture(arm, relation, codec);
  const initialStack = {
    primary: relation.rawBottomToTop.map((role) => initialItem(role, fixture[role], codec)),
    alt: []
  };
  const builder = new StackPlanBuilder(initialStack.primary);
  builder.emit(instruction('entry:assert-depth-exact', 'stack.assert_depth_exact', contract([], [], {
    expectedPrimaryDepth: relation.rawBottomToTop.length,
    expectedAltDepth: 0,
    expectedPrimaryValueIdsBottomToTop: relation.rawBottomToTop.map((role) => `raw:${role}`),
    expectedPrimaryTypesBottomToTop: relation.rawBottomToTop.map(() => 'RawElementBytes'),
    transientStackContract: transientStackContract(2, [
      { type: 'ScriptNum', value: String(relation.rawBottomToTop.length), provenance: 'OP_DEPTH-result' },
      { type: 'ScriptNumConstant', value: String(relation.rawBottomToTop.length), provenance: 'expected-primary-depth' }
    ], 'OP_DEPTH expected-depth NUMEQUALVERIFY plan-entry ABI assertion')
  })));
  const parserInvocations = emitParserAndExposeAll(builder, relation, parserModule, codec);
  emitSsa(builder, program, codec.modulus);
  const terminalValueId = emitWrapper(builder, relation, program, codec);
  const skeleton = {
    schema: 'shieldkit-labs/p2/physical-symbolic-bch-stack-plan/v1',
    status: 'symbolic-typed-stack-lowering-no-source-or-bytecode',
    stackQualification: {
      boundary: 'closed typed primitive semantics with explicit transient-stack envelopes',
      maximumMeaning: 'conservative symbolic primary-plus-alt peak derived from all declared primitive transitions and transient envelopes',
      bchVmExact: false,
      blockedVmExactGate: 'frozen opcode/source lowering for bytes assertions and canonicalization is absent; this artifact must not be presented as a VM-exact stack proof',
      sourceOrBytecodeSerialization: 'out-of-scope'
    },
    planId: `physical-plan:${arm.armId}:${relation.relationTargetId}:v1`,
    relationTargetId: relation.relationTargetId,
    constructionId: codec.constructionId,
    codecBinding: {
      codecId: codec.codecId,
      degree: codec.degree,
      limbBytes: codec.limbBytes,
      elementBytes: codec.elementBytes,
      unusedHighBitMaskHex: codec.unusedHighBitMaskHex,
      modulus: codec.modulus,
      coefficientOrder: codec.coefficientOrder
    },
    upstreamBinding: {
      armId: arm.armId,
      armDigest: frozenBinding.armDigest,
      formulaId: arm.formulaId,
      formulaDigest: frozenBinding.formulaDigest,
      programId: program.programId,
      programDigest: program.programDigest,
      programKind: program.kind
    },
    relationAbi: {
      rawBottomToTop: relation.rawBottomToTop,
      parseTopFirst: relation.parseTopFirst,
      parserInvocationCount: relation.parserInvocationCount,
      parsedPrefixByRawRole: relation.parsedPrefixByRawRole
    },
    parserInvocations,
    parserModuleId: parserModule.moduleId,
    parserModuleDigest: parserModule.contentDigest,
    wrapperBinding: {
      wrapperTemplateModuleId: wrapperInstance.templateModuleId,
      wrapperInstanceModuleId: wrapperInstance.moduleId,
      wrapperInstanceDigest: wrapperInstance.contentDigest,
      degree: codec.degree,
      codecId: codec.codecId
    },
    ssaProgram: clone(program),
    initialStack,
    instructions: builder.instructions
  };
  const replay = replayPhysicalPlan(skeleton);
  const terminal = replay.terminal;
  if (terminal.primary.length !== 1 || terminal.primary[0].type !== 'Bool' || terminal.primary[0].value !== 'true' || terminal.primary[0].valueId !== terminalValueId || terminal.alt.length !== 0) {
    fail(`relation fixture did not produce the required derived true terminal for ${arm.armId} ${relation.relationTargetId}`);
  }
  const plan = {
    ...skeleton,
    simulation: {
      trace: replay.trace,
      terminal,
      maxPrimaryDepth: replay.maxPrimaryDepth,
      maxAltDepth: replay.maxAltDepth,
      maxCombinedDepth: replay.maxCombinedDepth
    },
    maximumStack: replay.maxCombinedDepth,
    terminal: {
      primary: [{ valueId: terminalValueId, type: 'Bool', value: 'true', provenance: 'derived-relation-boolean' }],
      alt: []
    }
  };
  plan.contentDigest = digestWithout(plan);
  return plan;
};

export function buildPhysicalPlan({ arm, construction, relationTargetId, relationTarget, program } = {}) {
  const id = relationTargetId ?? relationTarget;
  const relation = relationFor(id);
  if (!arm || typeof arm !== 'object') fail('an authoritative arm is required for a physical plan');
  if (construction && construction.constructionId !== arm.constructionId) fail('construction does not match arm construction');
  const expected = arm.programs?.[relation.armProgramKind];
  if (!expected) fail('arm lacks the relation program kind');
  if (program !== undefined) {
    const errors = validateArmSsaProgram(program);
    if (errors.length > 0) fail(`malformed SSA program: ${errors.join('; ')}`);
    if (program.programDigest !== expected.programDigest) fail('supplied SSA program is not the exact authoritative program');
  }
  return materializePlan(arm, relation.relationTargetId, program ?? expected);
}

export const contentDigestForPhysicalPlan = (plan) => digestWithout(plan);

export function generatePhysicalPlans() {
  const arms = generateArmSsa();
  const parserModules = codecRows.map((codec) => parserTemplate(codec));
  const wrapperTemplates = CANONICAL_RELATION_IDS.map((id) => wrapperTemplate(id));
  const wrapperInstances = codecRows.flatMap((codec) => CANONICAL_RELATION_IDS.map((relationTargetId) => buildRelationWrapper({ construction: codec, relationTargetId })));
  const plans = arms.flatMap((arm) => CANONICAL_RELATION_IDS.map((relationTargetId) => materializePlan(arm, relationTargetId)));
  const parserInvocations = plans.reduce((total, plan) => total + plan.parserInvocations.length, 0);
  const moduleIndex = Object.fromEntries([
    ...parserModules,
    ...wrapperTemplates,
    ...wrapperInstances
  ].map((module) => [module.moduleId, module.contentDigest]));
  const artifact = {
    artifactId: 'physical-symbolic-bch-stack-lowering-v1',
    scope: 'symbolic-typed-stack-plan-only-no-source-bytecode-or-vm-metrics',
    nonClaims: [
      'not a BCH-VM-exact stack proof',
      'not source or bytecode serialization',
      'not VM execution, byte scoring, or release qualification'
    ],
    exactStackGate: {
      state: 'blocked-until-source-bytecode-lowering-is-frozen',
      requiredEvidence: ['exact source/bytecode binding', 'VM stack-transition replay', 'BCH limit check on that replay'],
      currentMaximum: 'conservative symbolic screen only'
    },
    parserModules,
    wrapperTemplates,
    wrapperInstances,
    // Kept as an explicit alias for consumers which call the three canonical
    // relation templates "wrapper modules". Instances are listed separately.
    wrapperModules: wrapperTemplates,
    moduleIndex,
    plans,
    counts: {
      parserModules: parserModules.length,
      wrapperTemplates: wrapperTemplates.length,
      wrapperInstances: wrapperInstances.length,
      plans: plans.length,
      parserInvocations
    }
  };
  artifact.contentDigest = digestWithout(artifact);
  return artifact;
}

export function validatePhysicalPlan(plan, { strictAuthority = false } = {}) {
  const errors = [];
  const report = (message) => errors.push(message);
  if (!plan || typeof plan !== 'object') return ['plan must be an object'];
  if (plan.schema !== 'shieldkit-labs/p2/physical-symbolic-bch-stack-plan/v1') report('plan schema mismatch');
  if (plan.contentDigest !== contentDigestForPhysicalPlan(plan)) report('stale plan content digest');
  let relation;
  try { relation = relationFor(plan.relationTargetId); } catch (error) { report(error.message); return errors; }
  const codec = codecByConstruction.get(plan.constructionId);
  if (!codec) report('unknown construction binding');
  if (codec && !canonicalObjectEqual(plan.codecBinding, {
    codecId: codec.codecId,
    degree: codec.degree,
    limbBytes: codec.limbBytes,
    elementBytes: codec.elementBytes,
    unusedHighBitMaskHex: codec.unusedHighBitMaskHex,
    modulus: codec.modulus,
    coefficientOrder: codec.coefficientOrder
  })) report('codec binding mismatch');
  const ssaErrors = validateArmSsaProgram(plan.ssaProgram);
  for (const error of ssaErrors) report(`malformed SSA: ${error}`);
  if (plan.ssaProgram?.kind !== relation.armProgramKind) report('SSA kind does not match canonical relation');
  if (plan.ssaProgram?.programDigest !== plan.upstreamBinding?.programDigest) report('SSA program digest binding mismatch');
  if (!Array.isArray(plan.instructions) || plan.instructions.some((entry) => !primitiveSet.has(entry?.primitive))) report('instruction uses an opaque or forbidden primitive');
  if (plan.instructions?.some((entry) => ['assert', 'append', 'cleanup', 'parse'].includes(entry.primitive))) report('forbidden opaque/cleanup primitive');
  if (!canonicalObjectEqual(plan.relationAbi?.rawBottomToTop, relation.rawBottomToTop) || !canonicalObjectEqual(plan.relationAbi?.parseTopFirst, relation.parseTopFirst)) report('canonical relation parser ABI mismatch');
  const entry = plan.instructions?.[0];
  if (entry?.id !== 'entry:assert-depth-exact' || entry?.primitive !== 'stack.assert_depth_exact') report('missing exact initial OP_DEPTH assertion');
  else if (entry.effects?.expectedPrimaryDepth !== relation.rawBottomToTop.length || entry.effects?.expectedAltDepth !== 0
    || !canonicalObjectEqual(entry.effects?.expectedPrimaryValueIdsBottomToTop, relation.rawBottomToTop.map((role) => `raw:${role}`))
    || !canonicalObjectEqual(entry.effects?.expectedPrimaryTypesBottomToTop, relation.rawBottomToTop.map(() => 'RawElementBytes'))) report('initial OP_DEPTH assertion does not bind canonical relation ABI');
  if (plan.parserInvocations?.length !== relation.parserInvocationCount) report('parser invocation count mismatch');
  if (!canonicalObjectEqual(plan.parserInvocations?.map((entry) => entry.rawRole), relation.parseTopFirst)) report('parser top-first order mismatch');
  if (codec) {
    const parser = parserTemplate(codec);
    if (plan.parserModuleId !== parser.moduleId || plan.parserModuleDigest !== parser.contentDigest) report('parser module binding mismatch');
    const wrapper = buildRelationWrapper({ construction: codec, relationTargetId: relation.relationTargetId });
    if (!canonicalObjectEqual(plan.wrapperBinding, {
      wrapperTemplateModuleId: wrapper.templateModuleId,
      wrapperInstanceModuleId: wrapper.moduleId,
      wrapperInstanceDigest: wrapper.contentDigest,
      degree: codec.degree,
      codecId: codec.codecId
    })) report('degree/codec-specific wrapper binding mismatch');
    for (const invocation of plan.parserInvocations ?? []) {
      if (invocation.parserModuleId !== parser.moduleId || invocation.parserModuleDigest !== parser.contentDigest) report(`parser invocation ${invocation.invocationId} has an unknown module binding`);
    }
  }
  let replay;
  try {
    replay = replayPhysicalPlan(plan);
    if (!canonicalObjectEqual(replay.trace, plan.simulation?.trace)) report('stored instruction trace differs from independently replayed semantics');
    if (!canonicalObjectEqual(replay.terminal, plan.simulation?.terminal)) report('stored terminal differs from independently replayed semantics');
    if (replay.maxPrimaryDepth !== plan.simulation?.maxPrimaryDepth || replay.maxAltDepth !== plan.simulation?.maxAltDepth || replay.maxCombinedDepth !== plan.simulation?.maxCombinedDepth) report('stored stack maximum differs from independently replayed transitions');
    if (plan.maximumStack !== replay.maxCombinedDepth) report('maximumStack is not the derived conservative symbolic maximum');
    if (replay.maxCombinedDepth > 1000) report(`conservative symbolic stack screen exceeds 1000: ${replay.maxCombinedDepth}`);
    if (replay.terminal.primary.length !== 1 || replay.terminal.primary[0].type !== 'Bool' || replay.terminal.primary[0].value !== 'true' || replay.terminal.alt.length !== 0) report('terminal is not exactly [derived true], alt empty');
  } catch (error) {
    report(`semantic replay failed: ${error.message}`);
  }
  try {
    const authority = authorityArmById().get(plan.upstreamBinding?.armId);
    if (!authority) report('unknown upstream arm binding');
    else {
      const expectedProgram = authority.programs[relation.armProgramKind];
      if (!canonicalObjectEqual(plan.upstreamBinding, {
        armId: authority.armId,
        armDigest: authority.armDigest,
        formulaId: authority.formulaId,
        formulaDigest: authority.formulaDigest,
        programId: expectedProgram.programId,
        programDigest: expectedProgram.programDigest,
        programKind: expectedProgram.kind
      })) report('upstream arm/program digest binding mismatch');
      if (strictAuthority) {
      const expected = materializePlan(authority, relation.relationTargetId);
      if (!canonicalObjectEqual(plan, expected)) report('plan diverges from the exact frozen SSA/codec/relation lowering');
      }
    }
  } catch (error) {
    report(`authoritative reconstruction failed: ${error.message}`);
  }
  return errors;
}

export default {
  CANONICAL_RELATION_IDS,
  PRIMITIVE_VOCABULARY,
  codecs,
  relationWrappers,
  parserTemplate,
  buildParserTemplate,
  instantiateParserModule,
  buildRelationWrapper,
  buildPhysicalPlan,
  replayPhysicalPlan,
  simulatePhysicalPlan,
  contentDigestForPhysicalPlan,
  generatePhysicalPlans,
  validatePhysicalPlan
};
