# SOUNDNESS ANALYSIS + EMPIRICAL FUZZ for the membership zk-STARK.
# Run: python3 apps/soundness.py
#
# HONEST STATUS: this is a CONDITIONAL analysis + statistical evidence, NOT a formal,
# machine-checked proof. FRI-STARK soundness is proven only under conjectured bounds
# (proximity gaps / FRI soundness conjecture) and the random-oracle model for Fiat-Shamir.
# No such formal proof exists for THIS implementation, and none is claimed.
#
# ====================== CONDITIONAL SOUNDNESS THEOREM ======================
# Let C be the membership relation: exists (secret, nullifier, path) s.t.
#   leaf = Hh(secret+nullifier), folding up the path reaches the public root R,
#   and nullifierHash = Hh(nullifier+DOM).
# Claim (conditional): for the non-interactive proof produced by prove(), a prover that
# does NOT know a witness for public (R, nullifierHash) convinces verify() with
# probability at most  eps_total  (below), UNDER these assumptions:
#   A1. SHA256 is collision-resistant (binds the trace/FRI Merkle commitments & FS transcript).
#   A2. Fiat-Shamir instantiated with SHA256 is sound in the random-oracle model.
#   A3. FRI soundness conjecture holds for Goldilocks at the chosen rate (proximity gaps).
#   A4. The reference algebraic hash Hh (iterated x^7, 6 rounds) is collision/preimage
#       resistant at the targeted level. THIS IS THE WEAKEST ASSUMPTION: Hh is a REFERENCE
#       sponge, not a cryptanalyzed standard hash. Treat A4 as UNVERIFIED.
#
# SOUNDNESS-ERROR ACCOUNTING (standard deployed-STARK heuristic, e.g. ethSTARK):
#   rate          rho           = 1 / blowup
#   per-query err <= rho        (conservative, unique-decoding regime)
#   query term    = n_queries * log2(1/rho)  bits
#   grinding      = grind_bits  bits (proof-of-work on the FS transcript)
#   field/commit term: FRI folding challenges live in Goldilocks (~2^64); the commit-phase
#       and FS-collision terms are dominated by the query+grind terms at these sizes.
#   => conjectured security  ~=  n_queries*log2(blowup) + grind_bits  bits.
# Default q16 / blowup8 / grind42:  16*3 + 42 = 90 bits.
# ===========================================================================
import sys, os, copy, math, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import membership_stark as M

def accounting(blowup, q, grind):
    rho = 1.0/blowup
    per_query_bits = math.log2(1/rho)
    return {"rate": rho, "per_query_bits": per_query_bits,
            "query_term": q*per_query_bits, "grind_term": grind,
            "total_bits": q*per_query_bits + grind}

def fuzz(trials=12, tampers_per=40, seed=0):
    random.seed(seed)
    false_accepts = 0; reject_checks = 0; valid_ok = 0
    for _ in range(trials):
        s = random.randrange(2, M.P); nu = random.randrange(2, M.P)
        sibs = [random.randrange(0, M.P) for _ in range(4)]
        p = M.prove(s, nu, sibs, grind_b=8)
        if M.verify(p)[0] is True: valid_ok += 1
        # targeted + random tampers; every one MUST reject
        for _ in range(tampers_per):
            q = copy.deepcopy(p)
            choice = random.random()
            if choice < 0.2:    q['root'] = M.add(q['root'], random.randrange(1, M.P))
            elif choice < 0.4:  q['nh']   = M.add(q['nh'],   random.randrange(1, M.P))
            elif choice < 0.6:
                qi = random.randrange(len(q['queries'])); c = random.choice(M.COLS)
                q['queries'][qi]['ck'][c] = M.add(q['queries'][qi]['ck'][c], random.randrange(1, M.P))
            elif choice < 0.75:
                qi = random.randrange(len(q['queries']))
                if q['queries'][qi]['fri']:
                    fl = random.choice(q['queries'][qi]['fri']); fl['v'] = M.add(fl['v'], 1)
            elif choice < 0.9:  q['nonce'] = os.urandom(8).hex()
            else:
                qi = random.randrange(len(q['queries']))
                if q['queries'][qi]['pk']:
                    s0, b0 = q['queries'][qi]['pk'][0]
                    bb = bytearray(bytes.fromhex(s0)); bb[0] ^= 1
                    q['queries'][qi]['pk'][0] = (bb.hex(), b0)
            reject_checks += 1
            if M.verify(q)[0] is True: false_accepts += 1
    return valid_ok, trials, reject_checks, false_accepts

if __name__ == "__main__":
    print("conjectured security accounting:")
    a = accounting(M.blowup, M.queries, M.grind_bits)
    print(f"  blowup={M.blowup} queries={M.queries} grind={M.grind_bits}")
    print(f"  rate rho={a['rate']:.4f}  per-query={a['per_query_bits']:.2f} bits")
    print(f"  query term={a['query_term']:.0f} + grind={a['grind_term']} = {a['total_bits']:.0f} conjectured bits\n")
    print("empirical fuzz (every tamper MUST reject; false-accepts MUST be 0):")
    vok, tr, rc, fa = fuzz()
    print(f"  valid proofs accepted : {vok}/{tr}")
    print(f"  tamper trials         : {rc}")
    print(f"  false accepts         : {fa}")
    print(f"  empirical reject rate : {100.0*(rc-fa)/rc:.2f}%")
    print("  -> evidence of soundness vs these tamper classes; NOT a formal proof (see header).")
