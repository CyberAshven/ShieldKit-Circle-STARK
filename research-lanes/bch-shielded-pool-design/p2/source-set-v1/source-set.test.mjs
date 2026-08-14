import assert from 'node:assert/strict';
import test from 'node:test';

import { assertExactRoster, assertPrimitiveRecipeAuthority, mapContentDigestFor, validatePlanEmission } from './generate.mjs';
import { assertExactGeneratedMap, assertExactGeneratedRoot, assertMapSchema, assertRootSchema, validateSourceSet } from './validate.mjs';

const clone = (value) => structuredClone(value);
const primitiveFamilies = [
  'stack.assert_depth_exact', 'bytes.assert_length_exact', 'bytes.split_at_exact', 'bytes.assert_mask_zero', 'bytes.cat_zero_sign_byte', 'scriptnum.bin2num',
  'integer.assert_nonnegative', 'integer.assert_lt_const', 'bytes.assert_empty', 'stack.pick', 'stack.dup', 'stack.drop', 'stack.toalt', 'stack.fromalt',
  'field.arithmetic', 'field.canonicalize_identity', 'boolean.equal', 'boolean.and', 'boolean.or', 'integer.is_nonzero', 'integer.equals_const'
];
let generated;
const sourceSet = () => {
  generated ??= validateSourceSet();
  return generated;
};

test('deterministic source-set dimensions and strict semantic validation', () => {
  const generated = sourceSet();
  assert.equal(generated.root.cardinalities.plans, 42);
  assert.equal(generated.root.cardinalities.instructions, 25098);
  assert.equal(generated.root.cardinalities.sourceBytes, 788958);
  assert.equal(generated.root.cardinalities.bytecodeBytes, 123079);
  assert.equal(generated.root.cardinalities.minPlanSourceBytes, 3006);
  assert.equal(generated.root.cardinalities.maxPlanSourceBytes, 64628);
  assert.equal(generated.root.cardinalities.minPlanBytecodeBytes, 552);
  assert.equal(generated.root.cardinalities.maxPlanBytecodeBytes, 10374);
});

test('all frozen primitive recipes are represented and source mutation is rejected', () => {
  const generated = sourceSet();
  for (const primitive of primitiveFamilies) {
    const entry = generated.built.find((candidate) => candidate.map.instructions.some((instruction) => instruction.primitive === primitive));
    assert.ok(entry, `missing ${primitive}`);
    const instruction = entry.map.instructions.find((candidate) => candidate.primitive === primitive);
    const mutatedAsm = `${entry.asm.slice(0, instruction.source.span.start)}OP_NOP${entry.asm.slice(instruction.source.span.start + 2)}`;
    assert.throws(() => validatePlanEmission({ asm: mutatedAsm, bytecode: entry.bytecode, map: entry.map, plan: entry.plan }), /source metadata drift|source reassembly mismatch|disassembly mismatch/);
  }
});

test('primitive recipe authority is exact, exhaustive, and mutation-resistant', () => {
  const generated = sourceSet();
  const recipes = generated.root.recipe.primitiveRecipes;
  assert.deepEqual(Object.keys(recipes).sort(), [...primitiveFamilies].sort());
  assert.doesNotThrow(() => assertPrimitiveRecipeAuthority(recipes));
  for (const primitive of primitiveFamilies) {
    const mutated = clone(generated.root);
    if (primitive === 'field.arithmetic') mutated.recipe.primitiveRecipes[primitive].operators.add = 'OP_SUB';
    else mutated.recipe.primitiveRecipes[primitive].tokens = 'OP_NOP';
    assert.throws(() => assertExactGeneratedRoot(mutated, generated.root), /semantic equality/);
  }
  const extra = clone(generated.root); extra.recipe.primitiveRecipes['forged.primitive'] = { kind: 'fixed-token-recipe', tokens: 'OP_NOP' };
  assert.throws(() => assertRootSchema(extra), /schema rejection/);
});

test('raw mask zero is an explicit raw push distinct from OP_0', () => {
  const generated = sourceSet();
  const mask = generated.built.flatMap((entry) => entry.map.instructions).find((instruction) => instruction.primitive === 'bytes.assert_mask_zero');
  assert.ok(mask);
  const line = generated.built[mask.planOrder].asm.slice(mask.source.span.start, mask.source.span.end);
  assert.match(line, /OP_PUSHBYTES_1 0x00 OP_EQUALVERIFY OP_DROP\n$/u);
  assert.doesNotMatch(line, /OP_AND OP_0 OP_EQUALVERIFY/u);
});

test('IR typed contract, map coverage, schema, and exact source map mutations are rejected', () => {
  const generated = sourceSet();
  const entry = generated.built[0];
  const typed = clone(entry.map); typed.instructions[0].irTypedContract.consumes = ['forged'];
  assert.throws(() => validatePlanEmission({ asm: entry.asm, bytecode: entry.bytecode, map: typed, plan: entry.plan }), /content digest drift|typed IR contract drift/);
  const covered = clone(entry.map); covered.sourceCoverage[0].end += 1;
  assert.throws(() => validatePlanEmission({ asm: entry.asm, bytecode: entry.bytecode, map: covered, plan: entry.plan }), /gap\/overlap|content digest drift/);
  const schemaSubstitution = clone(entry.map); schemaSubstitution.schemaBinding.rawSha256 = '0'.repeat(64);
  assert.throws(() => validatePlanEmission({ asm: entry.asm, bytecode: entry.bytecode, map: schemaSubstitution, plan: entry.plan }), /schema binding drift/);
  const malformedRaw = clone(entry.map); const raw = malformedRaw.instructions.find((instruction) => instruction.literalSemantics.some((literal) => literal.kind === 'raw-bytes')); raw.literalSemantics.find((literal) => literal.kind === 'raw-bytes').canonical = 'forbidden';
  assert.throws(() => assertMapSchema(malformedRaw), /schema rejection/);
  assert.throws(() => assertExactGeneratedMap(typed, entry.map), /semantic equality/);
});

test('LF-inclusive and raw fragment digests reject span swaps and independently re-digested false fragments', () => {
  const generated = sourceSet();
  const entry = generated.built[0];
  const spanSwap = clone(entry.map);
  [spanSwap.instructions[0].source.span, spanSwap.instructions[1].source.span] = [spanSwap.instructions[1].source.span, spanSwap.instructions[0].source.span];
  spanSwap.contentDigest = mapContentDigestFor(spanSwap);
  assert.throws(() => validatePlanEmission({ asm: entry.asm, bytecode: entry.bytecode, map: spanSwap, plan: entry.plan }), /source coverage.*instruction span/);
  const falseSource = clone(entry.map); falseSource.instructions[0].sourceFragment.sha256 = '0'.repeat(64); falseSource.contentDigest = mapContentDigestFor(falseSource);
  assert.throws(() => validatePlanEmission({ asm: entry.asm, bytecode: entry.bytecode, map: falseSource, plan: entry.plan }), /source fragment digest\/span drift/);
  const falseBytecode = clone(entry.map); falseBytecode.instructions[0].bytecodeFragment.sha256 = '0'.repeat(64); falseBytecode.contentDigest = mapContentDigestFor(falseBytecode);
  assert.throws(() => validatePlanEmission({ asm: entry.asm, bytecode: entry.bytecode, map: falseBytecode, plan: entry.plan }), /bytecode fragment digest\/span drift/);
});

test('root bindings, complete opcode table, and stale roster mutations are rejected', () => {
  const generated = sourceSet();
  const schemaDrift = clone(generated.root); schemaDrift.schemaBinding.rootSchema.rawSha256 = '0'.repeat(64);
  assert.throws(() => assertExactGeneratedRoot(schemaDrift, generated.root), /semantic equality/);
  const implementationDrift = clone(generated.root); implementationDrift.implementationBinding.files[0].rawSha256 = '0'.repeat(64);
  assert.throws(() => assertExactGeneratedRoot(implementationDrift, generated.root), /semantic equality/);
  const missingOpcode = clone(generated.root); missingOpcode.recipe.opcodeTable.pop();
  assert.throws(() => assertExactGeneratedRoot(missingOpcode, generated.root), /semantic equality/);
  const wrongOpcode = clone(generated.root); wrongOpcode.recipe.opcodeTable[0].byte = '0xff';
  assert.throws(() => assertExactGeneratedRoot(wrongOpcode, generated.root), /semantic equality/);
  assert.throws(() => assertExactRoster(['a.asm'], ['a.asm', 'stale.asm'], 'plans'), /roster/);
  assert.throws(() => assertExactRoster(['a.asm'], [], 'plans'), /roster/);
  assertRootSchema(generated.root);
});
