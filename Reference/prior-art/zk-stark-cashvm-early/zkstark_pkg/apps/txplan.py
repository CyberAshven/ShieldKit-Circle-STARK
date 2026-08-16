# Transaction-size planner for the on-chain STARK verifier.
# Enforces the size bands you set: <=90KB safe (10KB margin under standard),
# 90-100KB danger, >100KB non-standard (still <=1MB consensus), >1MB fail.
#
# Coefficients are calibrated to a REAL libauth measurement of the current fused
# verifier (one query per input): redeem=3215B, ~1100B opening data per query.
# Measured: 18 inputs -> 78,616 B ; 24 inputs -> 104,800 B  (tx(n) = 64 + 4364*n).
# Swap or mixer predicates change redeem/opening sizes; re-measure, then re-plan.

# verified BCH limits
STD_TX, CONSENSUS_TX = 100_000, 1_000_000
STD_INPUT_SCRIPT, CONSENSUS_SCRIPT = 1_650, 10_000
SAFETY = 90_000                       # your ceiling (10KB margin under STD_TX)

REDEEM = 3215                         # fused verifier redeem (measured)
WITNESS_PER_QUERY = 1100              # per-query opening data (measured)
PER_INPUT = 4364                      # measured total bytes added per input
BASE = 64                             # measured tx overhead (version/counts/outputs/locktime)

def per_input_script():
    return REDEEM + WITNESS_PER_QUERY + 6   # +pushdata opcodes

def band(b):
    if b <= SAFETY:        return "SAFE (<=90KB)"
    if b <= STD_TX:        return "DANGER (90-100KB)"
    if b <= CONSENSUS_TX:  return "NON-STD (>100KB, <=1MB consensus, needs miner)"
    return "FAIL (>1MB consensus)"

def plan(queries, mode="nonstandard"):
    sc = per_input_script()
    tx = BASE + PER_INPUT * queries
    notes = []
    if mode == "standard" and sc > STD_INPUT_SCRIPT:
        notes.append(f"INFEASIBLE as standard: per-input script {sc}B > {STD_INPUT_SCRIPT}B "
                     f"standard limit. Shard the verifier into <=1650B pieces, or use nonstandard.")
    if sc > CONSENSUS_SCRIPT:
        notes.append(f"per-input script {sc}B exceeds {CONSENSUS_SCRIPT}B consensus script limit; "
                     f"reduce queries-per-input.")
    return {"queries": queries, "mode": mode, "per_input_script": sc,
            "tx_bytes": tx, "verdict": band(tx), "notes": notes}

def max_queries_under(ceiling=SAFETY):
    return (ceiling - BASE) // PER_INPUT

if __name__ == "__main__":
    print("verified limits: std_tx=100KB consensus_tx=1MB std_input=1650B consensus_script=10KB")
    print(f"safety ceiling : {SAFETY} B (your 10KB margin)\n")
    print(f"max queries (1/input) staying <=90KB: {max_queries_under()}\n")
    print(f"{'queries':>7} | {'in.script':>9} | {'tx bytes':>9} | verdict")
    for q in (3, 6, 9, 12, 18, 20, 24):
        p = plan(q)
        print(f"{q:>7} | {p['per_input_script']:>9} | {p['tx_bytes']:>9} | {p['verdict']}")
    print()
    cur = plan(18)
    print(f"current proof (18 queries, nonstandard): {cur['tx_bytes']} B -> {cur['verdict']}")
    std = plan(18, "standard")
    print("standard-tx mode:", std["notes"][0] if std["notes"] else "OK")

# ---- membership (private withdrawal) on-chain sizing ----
# The membership proof is bigger than the toy x^2+C proof, so the verifier is NOT one
# query per input (that duplicates the redeem per input and blows past 1MB). Instead:
# ONE input whose redeem LOOPS over all queries (redeem appears once, must stay <=10KB
# consensus script limit), and ALL opening data + the depth-fixed selector coefficient
# blob live in that input's witness. Non-standard tx (input > 1650B), <=1MB consensus.
#
# Measured pieces: per-query opening ~4016 B (6 cols x2 + 2 salts + trace paths + FRI
# paths, blowup 8 / N=1024); selector coeff blob 3456 B (pushed once); shared roots/final
# ~0.8 KB; loop verifier redeem est ~6 KB (composition+multi-merkle+FRI-fold+selector-Horner).
#   tx ~= 200(base) + 3456(coeffs) + 6000(redeem) + 800(shared) + queries*4016
MEMB_PER_QUERY = 4016
MEMB_COEFFS    = 3456
MEMB_REDEEM    = 6000      # estimate; the fused loop verifier is the remaining integration
MEMB_SHARED    = 800

def membership_onchain(queries=16):
    tx = 200 + MEMB_COEFFS + MEMB_REDEEM + MEMB_SHARED + MEMB_PER_QUERY*queries
    return {"queries": queries, "tx_bytes": tx, "verdict": band(tx),
            "security_note": "sec ~= queries*log2(blowup)+grind; q16,blowup8,grind42 ~= 90 bits"}

if __name__ == "__main__":
    for q in (12, 16, 18, 20):
        m = membership_onchain(q)
        print(f"membership q{q:>2}: {m['tx_bytes']:>6} B  {m['verdict']}")
