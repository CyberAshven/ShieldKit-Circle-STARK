import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import {
  CANONICAL_RELATION_IDS,
  PRIMITIVE_VOCABULARY,
  buildPhysicalPlan,
  codecs,
  contentDigestForPhysicalPlan,
  generatePhysicalPlans,
  parserTemplate,
  replayPhysicalPlan,
  validatePhysicalPlan
} from './physical-plan.mjs';
import { generateArmSsa } from './arm-ssa.mjs';

const generated = generatePhysicalPlans();
const AUDITED_TRANSIENT_PRIMITIVES = Object.freeze([
  'bytes.assert_length_exact',
  'bytes.assert_mask_zero',
  'bytes.assert_empty',
  'stack.pick'
]);
const auditedTransientPrimitiveSet = new Set(AUDITED_TRANSIENT_PRIMITIVES);
const unmodifiedTransientContractDigest = (plans) => {
  const rows = plans.flatMap((plan) => plan.instructions
    .filter((entry) => !auditedTransientPrimitiveSet.has(entry.primitive))
    .map(({ id, primitive, effects }) => ({ id, primitive, effects })));
  return createHash('sha256').update(JSON.stringify(rows)).digest('hex');
};
const expectedNonAuditedContractDigest = 'fce9818015387bb4fdaaf9ddb2fb41fac7b2eed8f59191526ca05428a7a0b24b';
const minimalScriptNumHex = (input) => {
  let value = BigInt(input);
  if (value === 0n) return '';
  const bytes = [];
  while (value > 0n) {
    bytes.push(Number(value & 0xffn));
    value >>= 8n;
  }
  if ((bytes.at(-1) & 0x80) !== 0) bytes.push(0);
  return Buffer.from(bytes).toString('hex');
};
const cloned = (value) => structuredClone(value);
const redigest = (plan) => {
  plan.contentDigest = contentDigestForPhysicalPlan(plan);
  return plan;
};
const invalid = (plan, label) => assert.ok(validatePhysicalPlan(plan).length > 0, label);
const invalidRelationFixture = (plan, rawRole) => {
  const initial = cloned(plan.initialStack);
  const raw = initial.primary.find((item) => item.valueId === `raw:${rawRole}`);
  assert.ok(raw, `fixture has ${rawRole}`);
  const lowByte = Number.parseInt(raw.value.slice(0, 2), 16);
  raw.value = `${(lowByte === 1 ? 2 : 1).toString(16).padStart(2, '0')}${raw.value.slice(2)}`;
  return replayPhysicalPlan(plan, initial);
};

test('the frozen population has four relation-neutral parsers, three templates, twelve exact bindings, forty-two plans, and 126 invocations', () => {
  assert.equal(generateArmSsa().length, 14);
  assert.deepEqual(CANONICAL_RELATION_IDS, ['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check']);
  assert.equal(generated.parserModules.length, 4);
  assert.equal(generated.wrapperTemplates.length, 3);
  assert.equal(generated.wrapperInstances.length, 12);
  assert.equal(generated.plans.length, 42);
  assert.deepEqual(generated.counts, { parserModules: 4, wrapperTemplates: 3, wrapperInstances: 12, plans: 42, parserInvocations: 126 });
  assert.equal(generated.plans.reduce((sum, plan) => sum + plan.parserInvocations.length, 0), 126);
  assert.ok(generated.parserModules.every((module) => module.moduleKind === 'direct-codec-parser' && !('relationTargetId' in module)));
  assert.ok(generated.plans.every((plan) => generated.moduleIndex[plan.parserModuleId] === plan.parserModuleDigest));
  assert.ok(generated.plans.every((plan) => generated.moduleIndex[plan.wrapperBinding.wrapperInstanceModuleId] === plan.wrapperBinding.wrapperInstanceDigest));
  assert.equal(new Set(generated.parserModules.map((module) => module.contentDigest)).size, 4);
  assert.equal(new Set(generated.wrapperTemplates.map((module) => module.contentDigest)).size, 3);
});

test('each direct parser consumes a raw element, splits every limb, checks high bits and n<p before decode output, and binds OP_1 OP_1 OP_XOR', () => {
  for (const codec of codecs) {
    const parser = parserTemplate(codec);
    assert.throws(() => parserTemplate(codec, 'relation:e-mac'), /relation-neutral/u);
    const templates = parser.instructionTemplates;
    assert.equal(templates.filter((entry) => entry.primitive === 'bytes.split_at_exact').length, codec.degree);
    assert.equal(templates.filter((entry) => entry.primitive === 'bytes.assert_mask_zero').length, codec.degree);
    assert.equal(templates.filter((entry) => entry.primitive === 'integer.assert_lt_const').length, codec.degree);
    assert.equal(templates.filter((entry) => entry.primitive === 'bytes.cat_zero_sign_byte').length, codec.degree);
    assert.equal(templates.filter((entry) => entry.primitive === 'bytes.assert_empty').length, 1);
    for (const entry of templates.filter((candidate) => candidate.primitive === 'bytes.cat_zero_sign_byte')) {
      assert.deepEqual(entry.effects.zeroSignByteProvenance.opcodeSequence, ['OP_1', 'OP_1', 'OP_XOR']);
      assert.equal(entry.effects.zeroSignByteProvenance.exactResultByteHex, '00');
    }
  }
  assert.ok(PRIMITIVE_VOCABULARY.every((primitive) => !['assert', 'append', 'cleanup', 'parse'].includes(primitive)));
});

test('the four SOL-audited transient contracts are phase-accurate and all other seventeen primitive contracts are unchanged', () => {
  assert.equal(PRIMITIVE_VOCABULARY.length, 21);
  assert.deepEqual(PRIMITIVE_VOCABULARY.filter((primitive) => !auditedTransientPrimitiveSet.has(primitive)), [
    'bytes.split_at_exact', 'bytes.cat_zero_sign_byte', 'scriptnum.bin2num', 'integer.assert_nonnegative', 'integer.assert_lt_const',
    'stack.assert_depth_exact', 'stack.dup', 'stack.drop', 'stack.toalt', 'stack.fromalt', 'field.arithmetic',
    'field.canonicalize_identity', 'boolean.equal', 'boolean.and', 'boolean.or', 'integer.is_nonzero', 'integer.equals_const'
  ]);
  assert.equal(unmodifiedTransientContractDigest(generated.plans), expectedNonAuditedContractDigest, 'the seventeen unaudited primitive contracts drifted');

  for (const codec of codecs) {
    const templates = parserTemplate(codec).instructionTemplates;
    const length = templates.find((entry) => entry.primitive === 'bytes.assert_length_exact');
    assert.deepEqual(length.effects.transientStackContract, {
      exactAtPrimitiveBoundary: true,
      primaryAdditionalPeak: 2,
      altAdditionalPeak: 0,
      typedTransientItems: [
        { type: 'ScriptNum', value: String(codec.elementBytes), provenance: 'exact-OP_SIZE-result' },
        { type: 'ScriptNumConstant', value: String(codec.elementBytes), provenance: 'exact-byte-length-constant' }
      ],
      description: 'phase-accurate OP_SIZE result and exact-length constant comparison envelope'
    });

    const mask = templates.find((entry) => entry.primitive === 'bytes.assert_mask_zero');
    const candidate = mask.effects.sourceCandidateMacroTrace;
    assert.equal(mask.effects.transientStackContract.primaryAdditionalPeak, 3);
    assert.deepEqual(mask.effects.consumes, ['FixedLimbBytes']);
    assert.deepEqual(mask.effects.produces, ['MaskedLimbBytes']);
    assert.deepEqual(candidate.typedBoundary, { input: 'L:FixedLimbBytes', output: 'L:MaskedLimbBytes', transition: 'L->L' });
    assert.deepEqual(candidate.tokens, ['OP_DUP', `<${codec.limbBytes - 1}>`, 'OP_SPLIT', `<0x${codec.unusedHighBitMaskHex}>`, 'OP_AND', '<0x00>', 'OP_EQUALVERIFY', 'OP_DROP']);
    assert.equal(candidate.status, 'symbolic-unexecuted-source-candidate-only');
    assert.deepEqual(candidate.phases.map((phase) => phase.primaryAdditionalPeak), [3, 3]);
    assert.deepEqual(candidate.phases[0].typedTransientItems, mask.effects.transientStackContract.typedTransientItems);
    assert.deepEqual(candidate.phases[1].typedTransientItems, [
      { type: 'RawRemainderBytes', value: 'OP_SPLIT-prefix', provenance: 'source-candidate-later-peak-prefix' },
      { type: 'Byte', value: 'OP_AND-result', provenance: 'source-candidate-later-peak-masked-high-byte' },
      { type: 'ByteConstant', value: '00', provenance: 'source-candidate-later-peak-raw-one-byte-zero-comparator-not-OP_0' }
    ]);

    const empty = templates.find((entry) => entry.primitive === 'bytes.assert_empty');
    assert.deepEqual(empty.effects.transientStackContract, {
      exactAtPrimitiveBoundary: true,
      primaryAdditionalPeak: 2,
      altAdditionalPeak: 0,
      typedTransientItems: [
        { type: 'ScriptNum', value: '0', provenance: 'exact-OP_SIZE-result' },
        { type: 'ScriptNumConstant', value: '0', provenance: 'exact-leftover-length' }
      ],
      description: 'phase-accurate OP_SIZE result and zero-length constant comparison envelope'
    });
  }

  const picks = generated.plans.flatMap((plan) => plan.instructions.filter((entry) => entry.primitive === 'stack.pick'));
  assert.ok(picks.length > 0);
  for (const pick of picks) {
    assert.deepEqual(pick.effects.transientStackContract, {
      exactAtPrimitiveBoundary: true,
      primaryAdditionalPeak: 1,
      altAdditionalPeak: 0,
      typedTransientItems: [{
        type: 'ScriptNumConstant',
        value: String(pick.effects.depth),
        scriptNumHex: minimalScriptNumHex(pick.effects.depth),
        provenance: 'exact-pick-depth'
      }],
      description: 'exact OP_PICK depth ScriptNum is transiently pushed then consumed'
    });
  }
});

test('mutations to each of the four audited transient contracts fail exact authority reconstruction', () => {
  const mac = generated.plans.find((plan) => plan.relationTargetId === 'relation:e-mac');
  const mutations = [
    ['length OP_SIZE provenance', (entry) => { entry.effects.transientStackContract.typedTransientItems[0].provenance = 'fake-duplicate'; }, 'bytes.assert_length_exact'],
    ['mask later raw zero comparator', (entry) => { entry.effects.sourceCandidateMacroTrace.phases[1].typedTransientItems[2].value = ''; }, 'bytes.assert_mask_zero'],
    ['empty OP_SIZE provenance', (entry) => { entry.effects.transientStackContract.typedTransientItems[0].type = 'RawRemainderBytes'; }, 'bytes.assert_empty'],
    ['pick exact depth literal', (entry) => { entry.effects.transientStackContract.typedTransientItems[0].scriptNumHex = '00'; }, 'stack.pick']
  ];
  for (const [label, mutate, primitive] of mutations) {
    const plan = cloned(mac);
    const entry = plan.instructions.find((candidate) => candidate.primitive === primitive);
    assert.ok(entry, label);
    mutate(entry);
    redigest(plan);
    assert.ok(validatePhysicalPlan(plan, { strictAuthority: true }).length > 0, label);
  }
});

test('all forty-two plans independently replay every typed transition and use the actual SSA operands and outputs', () => {
  for (const plan of generated.plans) {
    const replay = replayPhysicalPlan(plan);
    assert.deepEqual(replay.trace, plan.simulation.trace, `${plan.planId} trace`);
    assert.deepEqual(replay.terminal, plan.simulation.terminal, `${plan.planId} terminal`);
    assert.equal(replay.maxCombinedDepth, plan.maximumStack, `${plan.planId} max stack`);
    assert.ok(replay.maxCombinedDepth <= 1000, `${plan.planId} conservative symbolic screen`);
    assert.deepEqual(replay.terminal.alt, []);
    assert.equal(replay.terminal.primary.length, 1);
    assert.deepEqual(replay.terminal.primary[0].type, 'Bool');
    assert.deepEqual(replay.terminal.primary[0].value, 'true');
    assert.equal(plan.instructions[0].id, 'entry:assert-depth-exact');
    assert.equal(plan.instructions[0].primitive, 'stack.assert_depth_exact');
    assert.equal(plan.instructions[0].effects.expectedPrimaryDepth, plan.relationAbi.rawBottomToTop.length);
    assert.equal(plan.instructions[0].effects.expectedAltDepth, 0);
    for (const step of replay.trace) {
      assert.match(step.stateDigestBefore, /^[0-9a-f]{64}$/u);
      assert.match(step.stateDigestAfter, /^[0-9a-f]{64}$/u);
    }
    const expectedInputs = plan.ssaProgram.inputs.map((entry) => entry.id);
    const parserOutputs = plan.parserInvocations.flatMap((invocation) => Array.from({ length: plan.codecBinding.degree }, (_, index) => `${invocation.outputPrefix}.c${index}`));
    assert.ok(expectedInputs.every((id) => parserOutputs.includes(id)), `${plan.planId} parsed formals are actual SSA inputs`);
    const nodeFetches = plan.instructions.filter((entry) => entry.effects?.purpose === 'ssa-operand-fetch' || entry.effects?.purpose === 'ssa-square-operand-fetch-once');
    assert.ok(nodeFetches.every((entry) => plan.ssaProgram.nodes.some((node) => node.args.includes(entry.effects.sourceValueId))));
    const outputFetches = plan.instructions.filter((entry) => entry.effects?.purpose === 'wrapper-actual-ssa-output-fetch');
    assert.deepEqual(outputFetches.map((entry) => entry.effects.sourceValueId), plan.ssaProgram.outputs.map((entry) => entry.ref));
    const squares = plan.ssaProgram.nodes.filter((node) => node.op === 'square');
    for (const square of squares) {
      assert.equal(plan.instructions.filter((entry) => entry.id === `ssa:${square.id}:pick:${square.args[0]}:0`).length, 1);
      assert.equal(plan.instructions.filter((entry) => entry.id === `ssa:${square.id}:dup`).length, 1);
    }
  }
});

test('opt-in representative replay retains full typed primary and alt-stack records for every codec and relation', () => {
  for (const codec of codecs) for (const relationTargetId of CANONICAL_RELATION_IDS) {
    const plan = generated.plans.find((candidate) => candidate.constructionId === codec.constructionId && candidate.relationTargetId === relationTargetId);
    const replay = replayPhysicalPlan(plan, plan.initialStack, { includeFullTrace: true });
    if (codec === codecs[0]) assert.deepEqual(validatePhysicalPlan(plan, { strictAuthority: true }), [], `${plan.planId} strict authority reconstruction`);
    assert.equal(replay.fullTrace.length, plan.instructions.length);
    for (const step of replay.fullTrace) {
      assert.equal(step.primaryDepthBefore, step.before.primary.length);
      assert.equal(step.primaryDepthAfter, step.after.primary.length);
      assert.equal(step.altDepthBefore, step.before.alt.length);
      assert.equal(step.altDepthAfter, step.after.alt.length);
      assert.equal(step.combinedDepthAfter, step.after.primary.length + step.after.alt.length);
      assert.ok(step.before.primary.every((item) => item.valueId && item.type && typeof item.value === 'string' && item.provenance));
      assert.ok(step.after.alt.every((item) => item.valueId && item.type && typeof item.value === 'string' && item.provenance));
    }
  }
});

test('digest stability and exact relation parser invocation multiplicities survive independent authoritative rematerialization', () => {
  const arm = generateArmSsa()[0];
  for (const relationTargetId of CANONICAL_RELATION_IDS) {
    const rematerialized = buildPhysicalPlan({ arm, construction: codecs[0], relationTargetId });
    const original = generated.plans.find((plan) => plan.planId === rematerialized.planId);
    assert.deepEqual(rematerialized, original);
  }
  for (const plan of generated.plans) {
    assert.equal(plan.contentDigest, contentDigestForPhysicalPlan(plan));
    assert.equal(plan.parserInvocations.length, plan.relationTargetId === 'relation:e-mac' ? 4 : plan.relationTargetId === 'relation:e-square-mac' ? 3 : 2);
    assert.deepEqual(plan.parserInvocations.map((entry) => entry.rawRole), plan.relationAbi.parseTopFirst);
  }
});

test('actual invalid C, D, and H bytes are parsed and make their respective relations false without fabricated cleanup truth', () => {
  const mac = generated.plans.find((plan) => plan.relationTargetId === 'relation:e-mac');
  const inverse = generated.plans.find((plan) => plan.relationTargetId === 'relation:e-inverse-check');
  for (const role of ['C', 'D']) {
    const replay = invalidRelationFixture(mac, role);
    assert.equal(replay.terminal.primary.length, 1, role);
    assert.equal(replay.terminal.primary[0].value, 'false', role);
    assert.deepEqual(replay.terminal.alt, [], role);
  }
  const inverseReplay = invalidRelationFixture(inverse, 'H');
  assert.equal(inverseReplay.terminal.primary.length, 1);
  assert.equal(inverseReplay.terminal.primary[0].value, 'false');
  assert.deepEqual(inverseReplay.terminal.alt, []);
});

test('mutations fail closed: fake cleanup, invented coefficients, missing parser guards, parse order, source substitution, pick depth, stale digest, malformed SSA, and max stack', () => {
  const mac = generated.plans.find((plan) => plan.relationTargetId === 'relation:e-mac');
  const inverse = generated.plans.find((plan) => plan.relationTargetId === 'relation:e-inverse-check');

  const fakeCleanup = redigest(cloned(mac));
  fakeCleanup.instructions.find((entry) => entry.primitive === 'stack.drop').primitive = 'cleanup';
  redigest(fakeCleanup);
  invalid(fakeCleanup, 'fake cleanup');

  const missingDepthAssertion = redigest(cloned(mac));
  missingDepthAssertion.instructions.shift();
  redigest(missingDepthAssertion);
  invalid(missingDepthAssertion, 'missing initial OP_DEPTH assertion');

  for (const [relationTargetId, wrongDepth] of [
    ['relation:e-mac', 3],
    ['relation:e-square-mac', 4],
    ['relation:e-inverse-check', 3]
  ]) {
    const wrongDepthPlan = redigest(cloned(generated.plans.find((plan) => plan.relationTargetId === relationTargetId)));
    wrongDepthPlan.instructions[0].effects.expectedPrimaryDepth = wrongDepth;
    redigest(wrongDepthPlan);
    invalid(wrongDepthPlan, `wrong initial depth for ${relationTargetId}`);
  }

  const inventedCoefficient = redigest(cloned(mac));
  inventedCoefficient.instructions.find((entry) => entry.primitive === 'integer.assert_lt_const').effects.outputValueId = 'invented.c0';
  redigest(inventedCoefficient);
  invalid(inventedCoefficient, 'invented coefficient');

  for (const primitive of ['bytes.split_at_exact', 'bytes.assert_mask_zero', 'integer.assert_lt_const', 'bytes.cat_zero_sign_byte']) {
    const missing = redigest(cloned(mac));
    const index = missing.instructions.findIndex((entry) => entry.primitive === primitive);
    missing.instructions.splice(index, 1);
    redigest(missing);
    invalid(missing, `missing ${primitive}`);
  }

  const wrongOrder = redigest(cloned(mac));
  [wrongOrder.parserInvocations[0], wrongOrder.parserInvocations[1]] = [wrongOrder.parserInvocations[1], wrongOrder.parserInvocations[0]];
  redigest(wrongOrder);
  invalid(wrongOrder, 'wrong top-first parse order');

  const outputSubstitution = redigest(cloned(mac));
  const outputPick = outputSubstitution.instructions.find((entry) => entry.effects?.purpose === 'wrapper-actual-ssa-output-fetch');
  outputPick.effects.sourceValueId = mac.ssaProgram.outputs.at(-1).ref;
  redigest(outputSubstitution);
  invalid(outputSubstitution, 'output substitution');

  const wrongC = redigest(cloned(mac));
  wrongC.instructions.find((entry) => entry.effects?.purpose === 'wrapper-actual-C-fetch').effects.sourceValueId = 'D.c0';
  redigest(wrongC);
  invalid(wrongC, 'wrong C source');

  const wrongD = redigest(cloned(mac));
  wrongD.instructions.find((entry) => entry.effects?.purpose === 'wrapper-actual-D-fetch').effects.sourceValueId = 'C.c0';
  redigest(wrongD);
  invalid(wrongD, 'wrong D source');

  const wrongH = redigest(cloned(inverse));
  wrongH.instructions.find((entry) => entry.effects?.purpose === 'ssa-operand-fetch' && entry.effects.sourceValueId.startsWith('b.c')).effects.sourceValueId = 'a.c0';
  redigest(wrongH);
  invalid(wrongH, 'wrong H/output source');

  const wrongPickDepth = redigest(cloned(mac));
  wrongPickDepth.instructions.find((entry) => entry.primitive === 'stack.pick').effects.depth += 1;
  redigest(wrongPickDepth);
  invalid(wrongPickDepth, 'wrong OP_PICK depth');

  const stale = cloned(mac);
  stale.maximumStack += 1;
  invalid(stale, 'stale digest');

  const maxStack = redigest(cloned(mac));
  maxStack.maximumStack = 1001;
  redigest(maxStack);
  invalid(maxStack, 'fabricated maximum stack');

  const arm = generateArmSsa()[0];
  const malformed = cloned(arm.programs.multiply);
  malformed.nodes[0].args[0] = 'unknown-ref';
  assert.throws(() => buildPhysicalPlan({ arm, construction: codecs[0], relationTargetId: 'relation:e-mac', program: malformed }), /malformed SSA|authoritative/u);
});
