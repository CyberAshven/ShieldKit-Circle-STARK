# Lowering arm IR decision — 2026-08-09

## Outcome

Raw BCH source and bytecode emission is blocked until a logically separate,
content-addressed `lowering-arm-ir-freeze.v1` is generated, reviewed, and
validated. The existing schedule is an algebraic equivalence oracle; its
`dagSteps` and tower maps are prose and therefore cannot uniquely determine an
ordered typed graph, normalization schedule, parser expansion, or physical BCH
stack allocation.

This is an additive gate. It does not modify the schedule, descriptors, or
`lowering-freeze.v1`, and it does not open execution, metrics, ranking, field
roles, or protocol selection.

## Required frozen population

- four construction-specific direct-codec parser modules;
- three relation-wrapper modules;
- fourteen ordered arm records, each with separate multiply and square SSA
  graphs;
- forty-two ordered arm-by-relation plans;
- one uniform physical allocation policy and complete symbolic stack plans.

The logical arm totals are 192 variable-base multiply occurrences and 146
variable-base square occurrences. Instantiating multiply for both E-MAC and
E-INVERSE-CHECK gives 530 physical variable-base operation occurrences across
the forty-two plans. The relation plans invoke parsers 126 times in total.

## Realization rules

1. Direct `c0..c(d-1)` coordinates are the only wire representation. Tower
   coordinates are typed, internal views with explicit ordered map/unmap
   dispositions.
2. Every arithmetic occurrence has a unique ordered SSA node. Inputs precede
   uses; all nodes reach an output or terminal control assertion; no implicit
   coercion, CSE, dead, optional, or data-dependent node is allowed.
3. Every scalar arithmetic operation is followed by an explicit canonical
   reduction with semantics `((x mod p) + p) mod p`.
4. Enumeration is deterministic: upstream construction/arm/relation order,
   numeric index and matrix row/column order, and strict left folds. Matrix zero
   cells are recorded `omit-zero`, one cells `alias-unit`, and all other cells
   own a unique scale node.
5. The exact Toom-3 evaluation template is frozen as
   `E0=a0`, `E1=((a0+a1)+a2)`, `Em=((a0-a1)+a2)`,
   `E2=((a0+2a1)+4a2)`, and `Einf=a2`, with an explicit reduction after each
   scalar operation. Scalar juxtaposition is `scale(k, value)`.
6. Pairwise square instantiates its `b=a` graph without a special-square or CSE
   substitution. Direct Toom square uses explicit square nodes at product
   positions. M89 and the tower-2×3 arms use only their expressly frozen square
   formulas. Tower-3×2 square uses exactly two general inner Fp3-Toom-3
   multiplications and no Fp3-square substitution.
7. M89 optimized and tower results that are already reduced and unmapped are
   not passed through the generic direct-product reduction a second time.
8. Every node has a mechanically recomputed inclusive integer range row. Fixed
   scalar work is distinct from variable-base multiply/square occurrence
   counts.
9. Each concrete relation plan starts with the exact relation-specific depth
   assertion. Its relation-neutral parser invocation then consumes one
   contiguous raw element, rejects unused high bits before numeric decoding,
   constructs the CAT sign byte using exactly `OP_1 OP_1 OP_XOR`, enforces
   `0 <= coefficient < p`, and proves full consumption.
10. The uniform physical policy is append-only SSA storage: deterministic
    `OP_PICK` operand depths, `DUP` only for explicit square nodes, no arm
    arithmetic altstack use, and exact terminal cleanup leaving one true primary
    value and an empty altstack. Parser and terminal-cleanup altstack use must be
    explicit and balanced.

## Validation boundary

The IR freeze may perform deterministic host-only algebra replay against the
direct-extension reference and static stack-transition/range checks. It must not
run Libauth, BCHN, LeanBCH, a campaign, or a benchmark. It is implementation
machinery, not execution evidence.

Only a later mechanical emitter may consume the frozen IR digest to produce the
fourteen arm source modules and forty-two complete relation source/bytecode
artifacts. Campaign-v2, corpus-v2, and execution-epoch-v2 remain separate later
gates.
