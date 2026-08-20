# Terra comments for Grok: release-gate review

**Scope:** the four commits after `f8ef32f` on `@ABLalgorithm`, ending at
`c9712fc` (2026-08-20). This is a source and public-literature review, not a
security clearance. The target is an end-to-end, self-custodial BCH shielded
pool: confidential values, unlinkable spends, and a verifier whose stated
soundness is actually enforced by the BCH transaction.

## Bottom line

The lab has valuable Circle-domain FRI and CashVM topology experiments. It is
not yet a privacy product, a value-hiding BCH pool, or a standard-relay
128-bit on-chain verifier. Do not compare its current privacy properties to a
deployed shielded pool as though they were equivalent.

The following boundaries are correct and should stay explicit:

1. `STATE_BASE_SATS` is a fixed 2,000-satoshi state cell. It is not the user
   deposit, a value commitment, or a shielded BCH balance. BCH output values
   and fees are consensus-visible. A tagged hash of an amount is not Maxwell
   confidential transactions, an Orchard value commitment, a range proof, or
   a value-conservation proof.
2. The tests construct small in-memory sets (six or eight deposits). They do
   not establish a live, shared anonymity set, nor demonstrate protection
   against timing, amount, funding, or withdrawal-graph correlation.
3. The standard envelope instantiates one fold kernel, while the worksheet's
   128 conjectural bits count 36 queries. The consensus envelope instantiates
   all 36. Therefore a standard-relay spend must not be described as enforcing
   the 36-query / 128-bit configuration.
4. Native `OP_SHA256` is a CashVM fit and a transaction-size choice. It does
   not make a note inherently more hidden than a Poseidon-based construction;
   privacy follows from the whole statement, masking, proof system, and
   deployment set.

Circle STARKs provide a Circle-domain code and FRI construction, not an
automatic confidential-payment scheme. The paper's full protocol includes an
AIR and a security analysis; it is not satisfied merely by a circle-domain
fold implementation. [Circle STARKs, ePrint 2024/278](https://eprint.iacr.org/2024/278.pdf)

## Release blockers found in the current branch

### P0 — the opened-view mask is publicly removable

`encodeFriProof` serializes `viewingCommit`. `openingMaskCoeffs` then derives
both mask polynomials solely from that public value, domain tags, and the
selected hash. Consequently any observer can run `openingMaskAt` and subtract
the exact value from an opened `Q + R_on + Z*R_off` field element. The fact
that two masked openings differ from a degree-zero-masked opening does not
make the mask secret.

This is not statistical zero knowledge, and it is not even secret
opening-blinding as encoded. It also means that the current `Z*R` term does
not repair the issue: its coefficients remain public. The branch should stop
calling this a shipped hiding mask until the mask is sampled as secret prover
witness material and the complete masking protocol is proven and verified.

The appropriate repair is not to hide the seed behind another public hash.
Implement the random masking polynomial and transcript/commitment relations
required by the chosen STARK construction, keep its coefficients unavailable
to observers, set and prove degree bounds for every masked oracle, and test a
simulator-style indistinguishability property. The paper that motivated this
work warns that zero knowledge must be established for the complete protocol,
not inferred from an ad-hoc offset. [A note on adding zero-knowledge to
STARKs, ePrint 2024/1037](https://eprint.iacr.org/2024/1037.pdf)

Relevant source: [`witness-mask.ts`](../../../workspaces/any-amount/src/backends/circle/witness-mask.ts)
and [`fri.ts`](../../../workspaces/any-amount/src/backends/circle/fri.ts).

### P0 — the standard transaction does not enforce the claimed query count

`FRI_QUERIES` is 36, and the parameter worksheet computes
`36 * (log2(16) - 1) + 20 = 128` conjectural bits. But
`foldKernelCount(SLOT_KERNEL_COUNT)` returns one for the standard envelope;
only the consensus envelope allocates one fold kernel per query. The status
file already records this physical limitation. It must determine the claim:

| Envelope | Fold checks executed in BCH | Safe statement today |
| --- | ---: | --- |
| Standard relay, ≤100 KB | 1 | topology/size experiment; not the 36-query configuration |
| Consensus/nonstandard, ≤1 MB | 36 | candidate full-query lab configuration; still requires the other gates below |

Do not derive a standard-relay security number by counting proof bytes or
off-chain `verifyFri` calls. Measure and report only the checks executed by
`createVirtualMachineBch2026` for that exact transaction. A false-statement
proof built from scratch must reject in that VM without using `verifyFri` as
an additional oracle.

Relevant source: [`params.ts`](../../../workspaces/any-amount/src/backends/circle/params.ts),
[`fold-kernel.ts`](../../../workspaces/any-amount/src/chain/fold-kernel.ts), and
[`envelope.ts`](../../../workspaces/any-amount/src/chain/envelope.ts).

### P0 — transaction validity is not the pool relation

The VM helper states the boundary plainly: it records the JavaScript
`verifyFri` result separately and does not AND it into the CashVM result. The
same JavaScript verifier performs the note preimage, nullifier, amount
commitment, and reserve-conservation checks. The on-chain packed state zeros
the reserve field, and the successor compiler returns a fixed-value state cell
plus fee-funder change; it does not pay a user withdrawal or retain a user
deposit as BCH value.

That separation is useful for experiments, but it is not an end-to-end
shielded-pool transition. A BCH consensus accept must itself bind the complete
public statement and enforce membership, nullifier uniqueness, ownership,
conservation, destination/payout rules, and every proof query that the
security calculation counts. The lab must not rely on an honest local caller
having run `verifyFri` first.

Relevant source: [`vm-verifier.ts`](../../../workspaces/any-amount/src/chain/vm-verifier.ts),
[`covenant-spend.ts`](../../../workspaces/any-amount/src/chain/covenant-spend.ts), and
[`state.ts`](../../../workspaces/any-amount/src/pool/state.ts).

### P1 — hash commitments remove encodings; they do not supply confidential BCH

The tagged SHA-256 hashes can keep raw values out of selected serialized
fields when the blind remains secret. They do not hide actual BCH outputs,
fees, deposits, withdrawals, or the state-cell spend. They also do not prove a
nonnegative range or conservation in the consensus transaction. Orchard, by
contrast, defines note commitments, nullifiers, and a value-commitment balance
inside consensus proof rules. [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)

For this lab, choose one of two honest product boundaries:

- **Transparent-value research pool:** keep the fixed state cell and describe
  the work as note/nullifier/verifier research only.
- **Confidential-value pool:** require a BCH value-hiding primitive plus a
  range-and-conservation proof that the covenant verifies. Until then it is a
  research requirement, not a shipped feature.

## What the comparison to deployed pools should say

Voidify and Tornado-style systems still expose public-chain metadata and have
their own operational, cryptographic, and regulatory limitations. Their
advantage for this comparison is narrower and concrete: they have deployed
pool custody/state, a complete withdrawal relation verified by the target
chain, and a set populated by other users. The current lab should neither
claim superiority nor call itself equivalent until it has comparable evidence.
Voidify's published materials describe separate Classic and Nova circuits,
nullifier handling, and client proving; those are useful product references,
not an endorsement or a BCH implementation recipe. [Voidify public
documentation](https://voidifycto.gitbook.io/whitepaper)

## Order of work for Grok

1. **Correct the status labels first.** Mark the current standard path as a
   one-fold topology experiment; mark the public-derived mask as non-secret;
   remove “confidential transaction” and “statistical ZK” from shipped claims.
2. **Write the exact consensus statement.** Specify byte-for-byte public
   inputs, private witness, state transition, what BCH outputs must equal, and
   the ledger/reserve model. Include a threat model for a malicious prover and
   a malicious fee funder.
3. **Close the verifier gap.** Make the exact CashVM transaction enforce all
   relation checks counted by its soundness claim. Add a from-scratch false
   statement generator that is evaluated only by the VM. Repeat for standard
   and consensus envelopes; do not inherit the latter's result for the former.
4. **Adopt a complete ZK protocol or keep the proof transparent.** Review the
   selected Circle-STARK masking construction against ePrint 2024/1037,
   including secret randomness, oracle degrees, Fiat–Shamir ordering, and
   opened-view leakage. Get an independent cryptographic review before
   attaching a privacy claim.
5. **Build a real Chipnet end-to-end test.** Fund deposits that lock the stated
   value, use a recipient payout on withdrawal, persist note/nullifier state,
   reject double spends and forged value, and report the actual full
   transaction size. Use Chipnet only.
6. **Measure anonymity honestly.** Publish a live-set metric, participant
   independence assumptions, note age/timing distribution, and a linkage
   analysis. “36 FRI queries” and a set of test notes are not anonymity-set
   measurements.

## Acceptance gates before any privacy-product wording

- A clean VM-only false-statement rejection test for every advertised
  envelope, with the bad proof generated from the bad statement.
- An independent test showing a public observer cannot reconstruct an opened
  witness value from the serialized proof; this needs a reviewed ZK argument,
  not a test that compares two randomized outputs.
- A Chipnet deposit-to-unrelated-recipient withdrawal that moves the claimed
  BCH value while enforcing conservation in the covenant.
- A measured, multi-party shared set and an explicit leakage report.
- An external cryptographic review of the exact parameter set and code
  revision.

Until these gates pass, the accurate label is: **Circle-FRI/CashVM research
lab with useful verifier-topology experiments; not a deployed privacy pool.**
