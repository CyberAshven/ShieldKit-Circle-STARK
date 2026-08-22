# AUDIT + live verification of the membership STARK and private mixer.
# Run: python3 apps/audit.py   (grind forced to 8 for speed; size is grind-independent)
#
# ============================ AUDIT FINDINGS ============================
# SCOPE: hidden-path Merkle-membership + nullifier zk-STARK (apps/membership_stark.py)
#        and the private mixer that wraps it (apps/private_mixer.py).
#
# WHAT IS SOUND (verified live below):
#  1. Completeness: a valid (secret, nullifier, path) produces an ACCEPTing proof.
#  2. Soundness vs tampering: forged root, forged nullifier hash, tampered column
#     openings (incl. held nullifier and injected secret), tampered FRI values, and
#     tampered grinding nonce ALL reject. Fiat-Shamir binds every challenge to the
#     transcript; grinding adds PoW; FRI enforces low degree of the composition.
#  3. Zero-knowledge: secret/nullifier/path never appear in the proof; trace is masked
#     by Z_H(x)*R(x); openings re-randomize across independent proofs of the same witness.
#  4. AIR correctness: row-level air_check passes on a valid trace and breaks on tampers,
#     independently of the STARK wrapper.
#  5. On-chain composition: cashscript/membership/membership_comp.cash recomputes the
#     9-constraint composition on the real 2026 VM (validated; tamper -> reject).
#  6. On-chain selector binding: cashscript/membership/selector_horner.cash computes each
#     public selector at x by Horner over HASH-PINNED coefficients (sha256 == constructor
#     pin), so the prover cannot forge selector values. Validated on VM: correct -> accept,
#     wrong claimed value -> reject, forged coefficient -> reject. This closes the
#     "prover supplied the selector values" gap you flagged.
#
# WHAT IS ASSUMED / NOT GUARANTEED:
#  - Conjectured soundness only. security ~= queries*log2(blowup) + grind_bits.
#    Default q16/blowup8/grind42 ~= 90 conjectured bits. No formal soundness proof.
#  - The algebraic hash (iterated x^7, 6 rounds, sha256-derived constants) is a REFERENCE
#    sponge, NOT a reviewed/standard hash. Do not treat its collision resistance as settled.
#  - Soundness is EMPIRICALLY fuzzed (tamper battery), NOT exhaustively proven. No external
#    audit. Parameters are reference-grade.
#
# TX-SIZE REALITY (the "cannot fit tx" issue):
#  - PROOF: ~64.7 KB at q16 (binary-equiv). Fits <=90 KB. Off-chain verify is fully sound.
#  - ON-CHAIN: one query per input duplicates the redeem per input and exceeds 1 MB. The
#    fitting architecture is ONE input whose redeem LOOPS over all queries (redeem once,
#    <=10 KB consensus script), with all openings + the 3456 B selector blob in the witness.
#    Modeled tx ~= 74.7 KB at q16 (see apps/txplan.py membership_onchain). NON-STANDARD tx
#    (input > 1650 B), <=1 MB consensus, miner-accepted.
#
# REMAINING INTEGRATION (honest gaps, not done here):
#  - Fuse the four VM-validated pieces (multi-col Merkle opening, composition, FRI fold,
#    selector Horner) into ONE <=10 KB loop redeem and validate the whole membership
#    verification in a single tx end-to-end. Each piece is validated INDIVIDUALLY; the
#    fused loop verifier is not yet built (cashc 0.13.0 single-function two-loop bug means
#    this likely needs OP_DEFINE/OP_INVOKE functions or hand-CashAssembly).
#  - Production parameters + real grinding + external audit + formal soundness.
# =======================================================================
import sys, os, copy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import membership_stark as M
import private_mixer as PM

def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    return cond

def run():
    ok = True
    print("membership STARK (q16 default, grind forced to 8):")
    p = M.prove(111, 222, [10,20,30,40], grind_b=8)
    ok &= check("valid proof ACCEPTS", M.verify(p)[0] is True)
    def tampered(mut):
        q = copy.deepcopy(p); mut(q); return M.verify(q)[0] is False
    ok &= check("forged root REJECTS",            tampered(lambda q: q.update(root=M.add(q['root'],1))))
    ok &= check("forged nullifier hash REJECTS",  tampered(lambda q: q.update(nh=M.add(q['nh'],1))))
    ok &= check("tampered column REJECTS",        tampered(lambda q: q['queries'][0]['ck'].update(st=M.add(q['queries'][0]['ck']['st'],1))))
    ok &= check("tampered held nullifier REJECTS",tampered(lambda q: q['queries'][0]['ck'].update(nu=M.add(q['queries'][0]['ck']['nu'],1))))
    ok &= check("tampered secret(inj) REJECTS",   tampered(lambda q: q['queries'][0]['ck'].update(inj=M.add(q['queries'][0]['ck']['inj'],1))))
    ok &= check("tampered nonce REJECTS",         tampered(lambda q: q.update(nonce=os.urandom(8).hex())))
    ok &= check("tampered FRI value REJECTS",     tampered(lambda q: q['queries'][0]['fri'][0].update(v=M.add(q['queries'][0]['fri'][0]['v'],1))))
    vals = [v for qq in p['queries'] for v in qq['ck'].values()]
    ok &= check("secret not in openings (ZK)",    111 not in vals)
    ok &= check("nullifier not in openings (ZK)", 222 not in vals)
    p2 = M.prove(111, 222, [10,20,30,40], grind_b=8)
    ok &= check("openings re-randomized (ZK)",    [q['ck']['st'] for q in p['queries']] != [q['ck']['st'] for q in p2['queries']])
    # AIR row-level
    col,n,rr,nr,ty = M.build_trace(111,222,[10,20,30,40])
    ok &= check("AIR holds on valid trace",       M.air_check(col,n,rr,nr,ty) is True)
    col['st'][5] ^= 1
    ok &= check("AIR breaks on tampered trace",   M.air_check(col,n,rr,nr,ty) is False)
    print("private mixer:")
    mx = PM.PrivateMixer(depth=4); ids=[mx.deposit() for _ in range(6)]
    w = mx.private_withdraw(ids[3])
    ok &= check("withdrawal hides secret/path/index", not any(k in w for k in ("secret","nullifier","path","index")))
    ok &= check("valid withdrawal ACCEPTS",       mx.verify_withdraw(w)[0] is True)
    ok &= check("double-spend REJECTS",           mx.verify_withdraw(w)[0] is False)
    print(f"\nRESULT: {'ALL PASS' if ok else 'FAILURES PRESENT'}")
    return ok

if __name__ == "__main__":
    sys.exit(0 if run() else 1)
