# Design options: frozen Circle-FRI fixed-ticket lane

## Decision now in force

The active product relation is `profile:fixed-ticket-serial-pool`:

- one transparent fixed-ticket deposit transaction;
- one later unilateral withdrawal transaction;
- one user action and one proof per transaction;
- no private transfers, variable amounts, change notes, or user batching;
- full on-chain proof verification and conservation enforcement; and
- public reconstruction with no required coordinator, private database, or
  privileged spending path.

The pool family and proof family are both frozen. The selected backend family
is **Circle-domain FRI**. The base field, extension tower, circle domain,
commitment scheme, transcript, and folding/query schedule remain research
variables to optimize for BCH. Groth16, conventional Goldilocks FRI, and WHIR
remain historical comparators only; they are not active implementation branches.

No external prover stack is selected. Stwo is prior art, not a base or protocol
authority. A qualifying design must include witness masking/zero knowledge from
the outset, derive explicit soundness parameters, and embody the verifier in
one complete current-BCH transaction.

## Active architecture family: serial public state

```text
wallet reconstructs latest public state
        |
        v
builds exactly one deposit or withdrawal action
        |
        v
generates one action proof
        |
        v
broadcasts one complete standard BCH transaction
        |
        v
transaction consumes current state and creates its sole successor
```

The baseline has no builder or sequencer role. A relayer may broadcast already
constructed transaction bytes, but it cannot be a proving, recovery, or
withdrawal dependency. Two valid transactions may race for the same state
outpoint; one wins under ordinary UTXO ordering and the losing wallet must
reconstruct, re-prove if required, and retry.

Verifier execution may span several BCH inputs or carriers. That is one proof
for one user action in one transaction, not user batching. PairFold is one such
verifier-partition topology; it is not a proof system and must not be treated as
a synonym for Groth16.

## Action graph

```text
DEPOSIT
  user funding + current pool state
    -> exact ticket-value and transaction-binding checks
    -> insert one hidden note commitment
    -> increase publicly accountable reserve by one ticket
    -> successor pool state

WITHDRAWAL
  current pool state + private note witness
    -> prove note membership and spend authority
    -> derive and register exactly one unused nullifier
    -> decrease reserve by one ticket
    -> bind ordinary-BCH payout, fee, and successor state
    -> successor pool state + user payout
```

The P0 relation freeze uses one continuation UTXO that co-locates the native
state commitment and BCH reserve. Every verifier role is a persistent carrier
UTXO consumed and recreated by the same action transaction. The concrete
carrier count, locks, values, and proof-section schedule remain measurement
variables; state/reserve sidecars are no longer an active Fv1 branch because
they would reopen the frozen conservation and recovery relation.

## Responsibility allocation

| Responsibility | Frozen Fv1 allocation | Cryptographic/deployment work still open |
| --- | --- | --- |
| Custody | reserve and complete 128-byte state share one authoritative mutable-NFT UTXO | genesis outpoint, token issuance audit, base sats, capacity, and exact covenant |
| State | sequence, deposit/withdrawal counts, pool ID, note root, and nullifier root use the frozen 128-byte codec | selected root algorithms and empty-root constants |
| Ordering | one genesis-derived state lineage; stale proofs are discarded and re-proved after races/reorgs | measured retry/mempool behavior and wallet FSM implementation |
| Deposit | one Circle-FRI action proof inserts one note and adds exactly one ticket | note accumulator primitive, AIR layout, and concrete proof profile |
| Withdrawal | one proof establishes note membership, secret authority, nullifier absence/insertion, fixed payout, and state transition | authorization/nullifier primitives and concrete proof profile |
| Conservation | state value is base plus outstanding tickets; one transparent external input funds fees | token-aware base value, immutable maximum fee, dust and signature template |
| Uniqueness | authenticated nullifier nonmembership plus deterministic insertion | sparse versus indexed set representation and capacity |
| Recovery | public state replay plus wallet-owned note backup; no private operator database | checkpoint/index format and measured bounded replay cost |
| Submission | wallet proves and signs locally; relayer is optional and non-authoritative | concrete CLI and transparent-input signing integration |
| Upgradeability | no runtime selector, admin path, migration, or privileged spend | any future migration requires a different explicitly reviewed profile |

## Non-negotiable relation contract

The frozen backend-neutral `PoolActionFv1` statement binds:

```text
pool/domain/version
action kind: deposit or withdrawal
old state commitment and consumed state outpoint
new state commitment and exact successor output
fixed ticket denomination and reserve delta
inserted note commitment or revealed nullifier
membership, ownership/spend authorization, and uniqueness
ordinary-BCH payout locking bytecode and amount
public fee policy
all transaction inputs/outputs whose substitution could change validity
```

Fixed denomination removes a general variable-amount range-proof requirement;
it does not remove conservation, input/output substitution resistance, or the
need to reject out-of-domain field encodings.

## Selected proof-family boundary

```text
selected family:       Circle-domain FRI
selected relation:     direct custom PoolActionFv1 AIR
field/domain:           open; derive from BCH verifier and prover costs
implementation base:   none selected; first-principles BCH co-design
prior art:             Circle STARK papers, Stwo, and other implementations
not selected:          generic Cairo proving stack
hard requirement:      witness masking / zero knowledge by construction
settlement target:     one current-standard BCH transaction per action
```

The formal S-two AIR paper remains useful methodology, but its Cairo theorem
does not prove `PoolActionFv1`, the Circle-FRI cryptographic implementation, or
the BCH verifier. Published Cairo proof sizes do not determine the size of a
direct minimal AIR.

Archived comparators may be consulted for engineering ideas and regression
metrics, but a smaller Groth16, Goldilocks, or WHIR result no longer changes the
selected backend scope.

## Circle-FRI qualification program

The implementation must use one valid/invalid action corpus and report:

1. exact source, toolchain, parameter, setup/key, AIR/circuit, and artifact
   digests;
2. a concrete Circle-FRI soundness derivation, witness-masking/ZK construction,
   transcript and Merkle binding, and canonical field-decoding rules;
3. proof bytes, verifier/carrier bytes, unlocking bytes, locking bytes, and the
   complete serialized deposit and withdrawal transaction bytes;
4. unmodified current BCHN and Libauth acceptance for one standard transaction
   per action, plus VM/op/hash/stack budgets;
5. cold and warm proving median/p95, peak RSS, core count, and preparation/key
   material on the pinned ordinary desktop;
6. rejection of mutations to proof, old/new state, nullifier, note,
   denomination, reserve delta, payout, fee, input order, output order, and
   carrier bindings; and
7. LeanBCH agreement wherever the required VM model exists.

The active profile's withdrawal gate is under 60 seconds on the pinned desktop.
Mobile proving is a desirable later product dimension, not a current kill gate.
No isolated “proof size” or “verifier size” is a pass: the current standard BCH
transaction limit is the complete-transaction envelope. Failure to achieve
zero knowledge eliminates the implementation even if all byte and speed gates
pass.

## Preserved but inactive source concepts

| Source concept | Disposition under the active profile | Reason |
| --- | --- | --- |
| Transferable private notes | retired out of scope | changes the relation to mint/transfer/change/exit |
| Multi-user recursion or aggregation | retired out of scope | violates one-user/no-batching constraint |
| K lanes plus epoch/master proof | retired out of scope | exists to scale batching/concurrency and leaves cross-lane privacy/atomicity open |
| UTXO-sealed JoinSplit | separate-profile only | exposes a different public graph and relies on multi-party mixing semantics |
| Client-side or spot-check conservation | eliminated | active profile requires full consensus enforcement |
| CashFusion anonymity formation | inactive | not part of fixed-ticket shielded-set formation |
| Pedersen/range-proof backend family | deprioritized | variable amounts are a non-goal; fixed equality and conservation are required instead |

The Telegram diagram remains useful as an observed state-carrier and encrypted
delivery prototype. Its 12 packet outputs, CEv1 labels, and suggested roots are
not automatically part of the qualifying fixed-ticket transaction.

## Frozen product decisions

These choices are fixed by product intent rather than benchmark results:

1. **Ticket and fee rule.** Each ticket is exactly 0.1 BCH (10,000,000
   satoshis). Withdrawal pays exactly 0.1 BCH and reduces the pool reserve by
   exactly 0.1 BCH. An explicit transparent non-pool input funds the transaction
   fee. Fee privacy, fee-input unlinkability, and hidden fee sponsorship are out
   of scope.
2. **Security target.** Design for 128-bit soundness. The current standard BCH
   transaction-policy envelope is exactly 100,000 bytes. If a concretely
   derived 128-bit configuration cannot fit as one complete transaction after
   measured protocol, verifier, and encoding optimization, select the strongest
   fitting parameter set at or above 100 bits. Security parameters are discrete
   constructions, not a cosmetic bit slider; every selected value requires a
   full derivation and may never be lowered silently.
3. **Client envelope.** The first client is a local desktop CLI. A complete
   unilateral withdrawal proof must take less than 60 seconds on the pinned
   ordinary desktop. Mobile, browser, GUI, and required remote proving are out
   of scope for this phase.
4. **PQ scope.** Orient the proof and private spend path toward defensible
   post-quantum assumptions, including commitments, nullifiers, note
   authorization, and wallet recovery. Maintain a component-by-component
   assumption inventory. Do not sacrifice classical security, transaction
   binding, privacy, availability, BCH standardness, or implementation assurance
   merely to replace a classical primitive. Current BCH settlement or fee-input
   authorization dependencies must be disclosed; the complete system is not
   labeled post-quantum until every relevant dependency qualifies.

## Questions the research must answer

These are experiment tracks, not user preference polls:

1. Which base field, extension tower, and circle subgroup minimize total BCH
   verifier bytes/op-cost without making the prover impractical?
2. Which trace/commitment masking construction provides defensible zero
   knowledge with the smallest proof and prover overhead?
3. Which Merkle commitment and Fiat-Shamir channel is optimal under BCH-native
   hash operations, proof bytes, and prover performance?
4. Which AIR layout jointly minimizes trace width/length, openings, and
   transaction-binding work for deposit and withdrawal?
5. Which blowup, query, folding, grinding, and final-polynomial schedule reaches
   128-bit soundness at the best byte/VM/prover Pareto point, and—only if the
   complete transaction cannot fit—which strongest configuration at or above
   100 bits clears the standard-policy envelope?
6. Which verifier partition across BCH inputs/carriers is smallest while still
   binding one complete action transaction and rejecting substitution attacks?
7. What exact persistent-carrier count and proof-section schedule minimizes the
   complete transaction while preserving role authentication and successor
   continuity?
8. What are the measured reconstruction, stale-proof discard, re-proving,
   mempool-eviction, and reorg costs of the frozen wallet lifecycle?
9. Which components of the proof, private spend path, CLI wallet, explicit fee
   input, and BCH settlement boundary remain classically dependent, and which
   PQ-oriented substitutions improve the assumption profile without weakening
   the system elsewhere?

P0 relation, transaction binding, responsibility, and threat semantics are now
frozen, and P1 codecs, semantic oracles, and exact empty shells are complete.
P2 has one measured neutral M31 base control and one measured, explicitly
non-ranking M89-d2 canonical-schoolbook component shakedown. All 266 frozen M89
cases agree across the native model, standard Libauth, real BCHN Script, and
LeanBCH; this establishes only parser/arithmetic/VM compatibility for those
isolated relations. It does not rank M89 or measure a Circle-FRI proof.

The four construction descriptors, 14-arm lowering policy, 28 typed SSA
programs, 42 symbolic stack plans, and the mechanically emitted source-set-v1
package are now frozen and content-addressed. The additive cohort-freeze-v2
package is also frozen. It binds campaign-v2, the canonical four-construction corpus-v2, and one shared execution-epoch-v2 contract alongside its fixture
and work-item artifacts. Together they bind 4,732 fixtures, 18,928 deduplicated
engine work items, 4,608
preflight-ready records, and 124 exact preflight-limit violations, all at the
M31-d6 direct-Toom6 E-MAC plan/relation slice. Manifest, raw-file, schema,
content-digest, and four-engine pins are recorded in the package and lane
metadata. These are contract and preflight artifacts, not VM evidence,
selection, or ranking.

The sealed cohort-upstream-origin-provider-contract-v1 package is a static, non-authorizing, unqualified provider-requirements catalog only. It authenticates only pinned static bytes and type/catalog relationships; no instances are represented, and every provider, owner, ownerBindingRoot, origin, fact, root, order, projection, and private byte remains unavailable. J remains ownerless and non-authorizing; retry and D remain BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture. sealed cohort-upstream-provider-source-map-v1 is a static non-authorizing unqualified source-coverage catalog that classifies all sixteen UOPC interfaces against sixteen pinned source references as exact authoritative type fragments, shape-only references, requirement-only references, or explicitly missing upstream sources; it resolves or instantiates no provider, owner, ownerBindingRoot, origin, fact, root value, order, projection, private byte, authority, admission, guard, runtime, or execution surface.

The sealed gate-b0-evidence-plan-v1 package is a static, non-authorizing, unqualified evidence-obligation plan bound by an outside-package review anchor; it authenticates only the reviewed 15-file authored closure, its two mechanical envelope files, 35 source pins, and false/zero admission boundary, and it creates no candidate, tuple, role assignment, parameter assignment, provider instance, measurement, execution, qualification, ranking, selection, or fallback authority.

The sealed gate-b0-execution-admission-contract-v1 package is a static, non-authorizing, non-admitting, unqualified pre-execution prerequisite catalog bound by an outside-package review anchor; it authenticates only the reviewed 18-file authored closure, its two mechanical envelope files, 64 raw-pinned source leaves with native semantic joins, 30 zero-instance external-requirement rows, 37 retry-prerequisite edges, 7 artifact/result edges, and the exact false/zero boundary, and it creates no candidate, tuple, role assignment, parameter assignment, provider, owner, fact, nonce, private byte, workload root, artifact map, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, or execution authority.

The sealed gate-b0-execution-admission-contract-v1 integration closes only the static pre-execution prerequisite-catalog stage. The next B0-R phase-DAG node is B0_EXECUTION_AUTHORIZATION, but it remains closed. It may open only under separate root/SOL authorization after independently pinned external authorities satisfy every provider, owner, fact, order, projection, private-byte, retry-predecessor, LIVE_F, B/C/J/D, raw-artifact-map, and independent-result-validation prerequisite represented by the closed 30-row catalog and exact 37+7 causal edges. This integration creates or authorizes no Q, A, LIVE_F, B, C, J, D, nonce, attempt, candidate, tuple, role, parameter, provider, owner, fact, private byte, workload root, artifact map, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, or execution; Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.

The sealed gate-b0-static-source-authority-v1 package is a static, non-authorizing, non-admitting, unqualified source-contract-language authority bound by an outside-package review anchor; it authenticates only the reviewed 24-file authored closure, its two mechanical envelope files, 64 raw-pinned transitive source leaves with native semantic joins, 17 closed source-contract records, 2 supplemental source contracts, 30 false/zero requirement-resolution rows, 15 raw-pinned schemas, and the exact false/zero non-authority boundary, and it creates no provider, owner, fact, root value, order material, projection material, private byte, raw artifact map authority or instance, independent result-validator implementation or evaluation, Q/A/LIVE_F/B/C/J/D instance, candidate, tuple, role assignment, parameter assignment, nonce, attempt, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution authority.

The sealed gate-b0-static-source-authority-v1 integration closes only the static source-contract-language prerequisite stage beneath the sealed gate-b0-execution-admission-contract-v1. It authenticates 17 source-kind contracts and 2 supplemental contracts, but all 30 EAC provider requirements remain false/zero, unavailable, and uninstantiated. The next B0-R phase-DAG node is B0_EXECUTION_AUTHORIZATION, but it remains closed. It may open only under separate root/SOL authorization after independently pinned external authority contracts govern and bind the future authorized creation or satisfaction of every provider, owner, fact, order, projection, private-byte, retry-predecessor, LIVE_F, B/C/J/D, raw-artifact-map, and independent-result-validator prerequisite under the closed EAC grammar; no provider, owner, state, artifact, or runtime instance may be created before that authorization, and static source-contract resolution alone is insufficient. This integration creates or authorizes no Q, A, LIVE_F, B, C, J, D, nonce, attempt, candidate, tuple, role, parameter, provider, owner, fact, private byte, workload root, artifact map, result-validator implementation or evaluation, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution; Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.

The sealed gate-b0-external-authority-prerequisite-policy-v1 package is a static, non-authorizing, non-admitting, unqualified prerequisite-policy language bound by an outside-package review anchor; it authenticates only the reviewed 21-file authored closure, its two mechanical envelope files, 12 raw-pinned schemas, 15 component digests, 10 policy groups, 2 supplemental policies, 30 false/zero requirement-authority rows, one unresolved UOPC/EAC source collision with selectedDag null, 31 prerequisite-DAG edges, a 6-state/5-edge transition policy with zero authorized transitions, and the exact false/zero non-authority boundary, and it creates no governance authorization, external authority contract, provider binding, principal, owner, fact, root value, order material, projection material, private byte, raw artifact map authority or instance, independent result-validator implementation or evaluation, Q/A/LIVE_F/B/C/J/D instance, candidate, tuple, role assignment, parameter assignment, nonce, attempt, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution authority.

The sealed gate-b0-external-authority-prerequisite-policy-v1 integration closes only the static external-authority prerequisite-policy-language stage beneath B0_EXECUTION_AUTHORIZATION. The package's current state is AUTHORITY_POLICY_FROZEN_NO_AUTHORITY: its represented SOURCE_LANGUAGE_RESOLVED→AUTHORITY_POLICY_FROZEN_NO_AUTHORITY transition is static policy representation only, all four later transitions are BLOCKED_EXTERNAL, authorizedTransitions is empty, and selectedDag is null. The next B0-R phase-DAG node remains B0_EXECUTION_AUTHORIZATION, but it remains closed. Before it may open, separately authorized external principals must provide independently pinned external authority contracts; an independently reviewed provider-binding catalog; an explicit root/SOL governance authorization that resolves the UOPC/EAC precedence collision; and satisfaction of every closed EAC prerequisite, including the raw-artifact-map and independent-result-validator requirements. This package and this lane integration may not infer, issue, bind, instantiate, or satisfy any of those prerequisites. Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, Gate B1, admission, execution, evidence, qualification, ranking, and selection remain closed.

The CPSB exact29 authenticated sealed static validation authenticates only future control-plane grammar and content-hash ordering for the pinned 27-entry source closure, 29-file sealed package, 18 schema bindings, and 11 future-record schemas, all with zero records. The retained 8,147-byte receipt is `AUTHENTICATED_SEALED_STATIC_VALIDATION_ONLY` with authorization `NONE`; it is unsigned and replayable, depends on the external caller and host TCB, is not independent attestation or runtime-readiness evidence, and creates no principal, decision, contract, binding, authorization, instance, admission, attempt, execution, evidence admission, measurement, qualification, ranking, selection, candidate tuple, parameter, field/domain, AIR/FRI/proof/prover progress, or PoolActionFv1 amendment. B0_EXECUTION_AUTHORIZATION, Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.

The retained PoolActionFv1 contradiction capsule records four open qualification blockers with authority `none` and status `observed-open-blockers-not-a-relation-amendment`: network schema/codec drift, injected context-digest facts, carrier-lock anchor erasure, and proof-session context erasure. They keep Hard Gates 1 and 5 blocked under `cannot-qualify-select-or-begin-full-prover`; the capsule executes nothing and is not a relation amendment or complete transaction witness.

The quiescent `poolaction-relation-disposition-refreeze-v2`, `measurement-admission-v2`, inert v1 synthetic subset, and v2 falsifier source-contract/16-file review anchor form one `BLOCKED_VERSION_PIVOT_NO_REFREEZE` transition only: v2 preserves source-contract integrity while the supervisory-matrix raw file remains absent; it grants no authority, admission, execution, measurement, qualification, ranking, selection, candidate, tuple, role, parameter, or refreeze credit. Hard Gates 1 and 5 and `B0_EXECUTION_AUTHORIZATION` remain closed.
