# Proof-backend evidence triage — 2026-08-08

## Scope decision and evidence verdict

On 2026-08-08, the Circle-domain FRI family was selected for this lane. The
field and protocol instantiation remain open for first-principles BCH
co-design. No external prover stack, including Stwo, is selected as a
dependency. Groth16, conventional Goldilocks FRI, and WHIR are inactive
comparators rather than competing implementation branches.

This is a product/research-scope decision, not an evidence claim that Circle
FRI has already won a benchmark. The primary-source review below still finds
no direct equal-relation Circle-FRI-versus-WHIR comparison.

- The decision does not reopen batching, transferable notes, lanes/epochs, or
  client-side conservation under the frozen fixed-ticket profile.
- Stock S-two is not currently a shielded-pool backend: its official
  documentation says witness commitments are not masked and the system does
  not provide zero knowledge.
- The target is a direct custom `PoolActionFv1` AIR, not generic Cairo.
- The decisive metrics remain complete fixed-ticket deposit and unilateral
  withdrawal transactions under one frozen security target.

The product envelope is also frozen: one ticket is 0.1 BCH (10,000,000
satoshis); withdrawal pays the full ticket and a separate transparent input
funds fees; the first client is a local desktop CLI with a less-than-60-second
withdrawal target; and the proof/private-spend path is PQ-oriented without
trading away classical security or overstating the current BCH settlement
boundary. The soundness target is 128 bits. Only if a complete derived 128-bit
transaction cannot fit the 100,000-byte standard-policy envelope after measured
optimization may the research select the strongest configuration at or above
the 100-bit floor.

The scoped chat excerpt is treated as source-attributed raw claims. This file
stores technical paraphrases rather than the full chat transcript.

## Evidence classes

| Class | Meaning in this note |
| --- | --- |
| Raw chat claim | faithfully attributed lead; not independently true |
| Primary-source statement | supported by a paper or project controlled by its authors/maintainers |
| Local observation | read from a pinned local artifact; not rerun unless stated |
| Chain observation | decoded from independent public Starknet RPC responses |
| Inference | conclusion drawn here; must not be restated as a source claim |

## Aug-7 claims captured as leads

| Speaker label in supplied excerpt | Raw proposition | Required resolution |
| --- | --- | --- |
| `toorik` | FRI-STARK is just under 100 KB | identify exact artifact, relation, security parameters, and whether this is proof, verifier, score, or complete transaction |
| `toorik` | smallest Groth candidate is 54 KB | pin artifact/setup/relation and whole-transaction byte convention |
| `toorik` | Groth preparation is about 10 seconds | define phase boundary, hardware, cold/warm state, repetitions, and peak RSS |
| `CrazyDever` | an improved-security FRI verifier was about 38% larger | obtain both exact artifacts and parameter/soundness diff; do not apply 38% to an unrelated 100-KB value |
| `CrazyDever` | standard-FRI proving was not mobile-ready | product limitation only; current profile requires an ordinary desktop, not a phone |
| `CrazyDever` | one prover improved from 96 s/24 GB to 39 s/1.3 GB on an i9-13900K/64-GB host | pin repository, before/after commits, workload, parameters, commands, thread count, and memory metric |
| `Adaptive Blocksize Limit` | Circle FRI is faster than conventional FRI and competitive with WHIR | run equal-relation, equal-security, equal-hardware measurements |
| `Adaptive Blocksize Limit` | hash-based proof methods are post-quantum and other approaches are vulnerable | replace with a component-by-component assumption inventory; the blanket claim is not technically valid |
| unattributed hardware estimate | 8 cores and 8–16 GB should suffice | measure the exact fixed-ticket prover; a resource estimate is not a requirement or result |

The reported optimization arithmetic is internally consistent as a claim:
`96 s -> 39 s` is about 2.46x faster, and `24 GB -> 1.3 GB` is about 18.5x
smaller. It remains non-comparable to this lane until the workload is the frozen
pool relation.

## Primary-source review

### Formal verification of the S-two AIR

Source: [arXiv:2606.04311v1](https://arxiv.org/abs/2606.04311v1), submitted
2026-06-03. PDF SHA-256:
`03685d53d6e5c652a90888f13de9c35d21e462000254893e13c50be36ba025e8`.

The Lean development establishes an AIR-level implication: satisfying the
modeled S-two Cairo AIR entails a Cairo execution trace under the theorem's
hypotheses. This is valuable evidence that AIR correctness is being treated
seriously. It does **not**:

- benchmark Circle FRI against WHIR or conventional FRI;
- verify ShieldKit's fixed-ticket AIR;
- prove the complete cryptographic protocol, Fiat-Shamir transform, or
  implementation end to end;
- measure proof bytes, BCH VM cost, prover time, memory, or mobile readiness;
  or
- remove stated infrastructure assumptions. The paper explicitly does not
  model global code that collects and arranges component lookups.

Design consequence: formalize or independently cross-check `PoolActionFv1`;
do not inherit Cairo-AIR assurance by choosing Stwo.

### Circle STARKs

Source: [IACR ePrint 2024/278](https://eprint.iacr.org/2024/278), revision
2025-02-20. PDF SHA-256:
`0d577a9c8a0a138d5e217f5e0945daf77752c532c3243331a59fb2b7faebb560`.

The construction enables efficient STARKs over M31 using the circle group. Its
abstract reports a preliminary 1.4x prover speed-up over a traditional
BabyBear-field STARK. This is a useful direction, not evidence that a BCH
verifier, proof size, or fixed-ticket prover beats the current Goldilocks lane.
It provides no Circle-versus-WHIR production comparison.

### WHIR

Source: [IACR ePrint 2024/1586](https://eprint.iacr.org/2024/1586), revision
2024-11-21. PDF SHA-256:
`8c5c0d22a224d6bbace19d43c9f6d6ede1a44e82505a1da74cc6fba45c95ba0d`.

WHIR is an IOP of proximity for constrained Reed-Solomon codes and can replace
FRI-like proximity machinery in suitable compositions. The paper gives a
100-bit polynomial-commitment example with 63 KiB communication and roughly
360 microsecond opening verification. That is not a complete shielded-pool
SNARG, not a BCH transaction, and not commensurate with the chat's FRI/Groth
figures.

Design consequence: WHIR remains interesting only after a concrete
`PoolActionFv1` composition, Fiat-Shamir transcript, proof encoding, and BCH
verifier exist.

The paper authors' [reference implementation](https://github.com/WizardOfMenlo/whir)
labels itself an academic prototype that has not received careful code review
and is not production-ready. [World Foundation ProveKit](https://github.com/worldfnd/ProveKit)
is an actively developed client-side ZK stack combining WHIR with a
Spartan-based protocol, so there is real implementation activity. This review
found no primary-source corroboration for the stronger chat claim that the
Ethereum Foundation is actively integrating WHIR into Ethereum itself. Keep
that attribution raw until an exact repository, proposal, or research post is
provided.

### Stwo prior art and published benchmarks

Source: [starkware-libs/stwo](https://github.com/starkware-libs/stwo), observed
dev commit `88e95ba9c37aa81975575a52ccdadd1b93c08f24` and main commit
`5879ead36241ee1593af64d42fd7ef038391e9f6` on 2026-08-08.

The repository provides a maintained Rust Circle-STARK prover and a `no_std`
verifier over M31/CM31/QM31 with several hash-channel choices. Its own security
section says soundness is conjectured under hash collision resistance in the
random-oracle model and the small-distance decoding hardness implicit in FRI;
security depends on consumer-selected blowup, query, and grinding parameters,
and test defaults are not production parameters. “It uses hashes” is therefore
not a complete soundness or PQ argument.

More importantly for this project, the official
[Why S-two?](https://docs.starknet.io/learn/S-two-book/why-stwo) page states
that S-two does not currently provide zero knowledge: witness commitments are
not hidden with randomness and can leak witness information. That is a hard
failure for a shielded withdrawal, independent of prover speed. Circle FRI
remains a candidate only with a concrete masking/ZK construction, leakage
analysis, and measured proof-size/prover overhead; the stock Stwo path is not
admissible.

The [official S-two benchmark report](https://docs.starknet.io/learn/S-two-book/benchmarks)
is a 2025-07-03 snapshot at commit
`f27856ec17fbd9e85ec31cba9c2cb9e96d8dd08f`. It benchmarks a 96-bit Cairo-VM
stack on a 48-vCPU AMD EPYC host with 184.25 GB RAM. Reported Stwo Fibonacci
proofs are about 783–808 KB across the displayed range; other workloads are
also hundreds of KB to roughly 1 MB. These figures do not fit a 100,000-byte
BCH standard transaction, but they are generic Cairo proofs, not a direct
minimal fixed-ticket AIR. The proper conclusion is “direct AIR must be
measured,” not “Circle FRI cannot fit.”

The linked [S-two launch article](https://www.starknet.io/blog/s-two-is-live-on-starknet-mainnet-the-fastest-prover-for-a-more-private-future/)
is useful project context, but its broad speed/mobile statements are not a
profile-qualified fixed-ticket benchmark.

### Related 77-KB recursive proof lead

A separate [Starknet January 2026 recap](https://www.starknet.io/blog/starknet-january-recap-2026-strk-layerzero-ecosystem/)
reports that StarkWare and Weikend reduced a 1.3-MB S-two Cairo proof to 77 KB.
The related `recursive-stwo` repository at commit
`13bd86f677f272364dd88f5294549b31461b4558` contains a 77,304-byte serialized
artifact, `level14-1.bin` (SHA-256
`4e0900aa67775b4edc9dbf889b7c6241e82225232158215da9781807f271b185`).
That is proof-file size, not a complete BCH withdrawal transaction or verifier
size. The companion `recursive-stwo-bitcoin` demo at commit
`083df955a7588ae1bb5e4e251dbf7df6733a08bc` broadcasts 175 numbered signet
verification transactions after funding. Its topology is therefore
incompatible with this lane's one-standard-withdrawal-transaction gate. The
artifact is a promising compression lead, not a BCH feasibility result.

## Starknet transaction check

Supplied transaction:
[Voyager](https://voyager.online/tx/0x67a776ccbaa049d9f80c879b1d62cd8e94ac090be95257357282a0e10283885).

Two public RPC providers returned the transaction and receipt. The exact
transaction is an `INVOKE v3`, succeeded, and is `ACCEPTED_ON_L1` in Starknet
block `10592114` with block hash
`0x50f7ce46c01122d9a083392c168c2a4edf2cd25db78e392549b83b0ab7d3e3e`.

The account calls contract
`0x40337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a`,
class hash
`0x30b8c540cf04d8ef0f4db2a9098d9cc0e35e83af1cb3325f5a4f40144b4b30b`,
at selector
`0x246333a752c1ac637ff1591c5c885e27d56060d241a29aad8475072da0777db`.
The contract ABI resolves that selector to `apply_actions` in a `privacy`
framework.

The ten-action payload decodes as two write-once markers, two `NoteUsed`
nullifiers, and three paired `TransferTo`/`Withdrawal` actions. The three STRK
amounts are `0.577215664`, `0.69314718`, and `0.729637156`, totaling exactly
`2 STRK`. This is concrete evidence that a deployed privacy-framework action
executed and that the wallet interacted with it. It does not establish:

- authorship or reverse engineering;
- use of Stwo, Circle FRI, WHIR, or any particular proof backend;
- the 96-to-39-second optimization claim; or
- compatibility with the fixed-ticket BCH profile.

The ABI also exposes auditor-key, fee, pause, role, and upgrade controls. That
contract is therefore a useful implementation reference, not a template for a
profile that forbids admin keys, privileged paths, upgradeability, and private
withdrawal dependencies.

## BCH envelope correction

The active standard transaction limit is **100,000 bytes**; the consensus
transaction-size limit is **1,000,000 bytes**. The current
[TXv5 proposal](https://github.com/bitjson/bch-txv5) was observed at commit
`f8e45acfb7e38e27d6f922e8f688364b92326c0a`. It is a draft proposed for May
2027. It proposes raising individual bytecode and stack-element limits to
100,000 bytes, explicitly equal to the maximum standard transaction size; it
does not raise standard transactions to 1 MB.

Therefore “FRI is just under 100 KB” is not yet a fit result. A proof or
verifier near 100 KB leaves no room for transaction structure, state, payout,
fees, and binding data. Only a complete serialized standard transaction can
pass the active profile.

## Local comparison lead

The sibling verifier.cash lane currently records a secure Goldilocks
DEEP-ALI/FRI result at:

```text
/home/toorik/Projects/ZK-Proofs/verifier.cash/lanes/goldilocks-98k/
```

Its recorded profile is `nq=7`, `B=2048`, grinding `30`, depth `4`, and a
declared 100-bit estimate. The stored benchmark reports score `98,776`,
measured verifier bytes `98,025`, and estimated transaction bytes `98,181`.
This was inspected, not rerun here. It is a hash-chain verifier specimen, not
the fixed-ticket pool relation, so it is a feasibility control and cannot be
promoted as the pool backend.

## Selected Circle-FRI program

1. Freeze `PoolActionFv1` and its mutation corpus before porting the prover.
2. Design and test a concrete witness-masking/ZK construction as part of the
   protocol; stop if privacy leakage cannot be bounded.
3. Derive and optimize for the mandatory 128-bit systemic soundness target.
   Research at 100–127 bits remains unauthorized unless complete optimized
   128-bit deposit and withdrawal transactions are both measured and fail the
   100,000-byte standard envelope, after which root/SOL may explicitly authorize
   the strongest fitting configuration at or above 100 bits.
4. Compare candidate circle-friendly base fields and extension towers against
   BCH Script cost and prover performance; then select the BCH-oriented
   transcript and Merkle hash and implement one verifier query as the first
   Script cost gate.
5. Build the direct fixed-ticket AIR only after the arithmetic/hash gate fits;
   do not inherit the generic Cairo proving stack by default.
6. Qualify complete deposit and withdrawal transactions on the pinned desktop
   and current BCH rules.

The selected design is now the **serial fixed-ticket architecture with a
first-principles Circle-FRI verifier boundary**. The implementation remains
unqualified until the ZK, soundness, byte, VM, and proving-resource gates pass.
