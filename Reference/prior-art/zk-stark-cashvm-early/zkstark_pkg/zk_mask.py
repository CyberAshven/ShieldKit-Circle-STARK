"""
zk_mask.py -- the ZERO-KNOWLEDGE layer (tested), proving the two properties your
spec requires that the soundness verifier does NOT provide on its own:

  (A) HIDING: masking the trace so that the evaluations revealed at FRI query
      points are uniformly random and independent of the secret witness.
  (B) CORRECTNESS PRESERVED: masking does not change the trace on its own domain,
      so the constraints / computation still hold (proof stays sound + complete).

Field: Goldilocks p = 2^64 - 2^32 + 1 (post-quantum: hash+field only, no EC).
"""
import secrets
P = 2**64 - 2**32 + 1

def inv(a): return pow(a % P, P - 2, P)

def find_generator():
    # p-1 = 2^32 * 3 * 5 * 17 * 257 * 65537
    factors = [2, 3, 5, 17, 257, 65537]
    for g in range(2, 200):
        if all(pow(g, (P - 1) // f, P) != 1 for f in factors):
            return g
    raise RuntimeError

G = find_generator()

def root_of_unity(order):
    assert (P - 1) % order == 0
    return pow(G, (P - 1) // order, P)

def poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % P
    return acc

def lagrange_interp(xs, ys):
    """Return coefficients of the polynomial through (xs[i], ys[i])."""
    n = len(xs)
    coeffs = [0] * n
    for i in range(n):
        # build basis poly L_i(x) = prod_{j!=i} (x - xs[j])/(xs[i]-xs[j])
        num = [1]
        denom = 1
        for j in range(n):
            if j == i: continue
            num = poly_mul(num, [(-xs[j]) % P, 1])
            denom = (denom * ((xs[i] - xs[j]) % P)) % P
        scale = (ys[i] * inv(denom)) % P
        for k in range(len(num)):
            coeffs[k] = (coeffs[k] + scale * num[k]) % P
    return coeffs

def poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * bj) % P
    return out

def matrix_rank_modp(M):
    M = [row[:] for row in M]
    rows, cols = len(M), len(M[0])
    rank = 0
    for c in range(cols):
        piv = next((r for r in range(rank, rows) if M[r][c] != 0), None)
        if piv is None: continue
        M[rank], M[piv] = M[piv], M[rank]
        pinv = inv(M[rank][c])
        M[rank] = [(v * pinv) % P for v in M[rank]]
        for r in range(rows):
            if r != rank and M[r][c] != 0:
                f = M[r][c]
                M[r] = [(M[r][k] - f * M[rank][k]) % P for k in range(cols)]
        rank += 1
    return rank

# --- parameters ---
n        = 8          # trace length (domain H = n-th roots of unity)
blowup   = 8
N        = n * blowup # evaluation (coset) domain size
queries  = 6          # how many openings the verifier will see (k)

omega_n = root_of_unity(n)
omega_N = root_of_unity(N)
H     = [pow(omega_n, i, P) for i in range(n)]                 # trace domain
coset = [(G * pow(omega_N, i, P)) % P for i in range(N)]        # eval domain (disjoint from H)
ZH    = lambda x: (pow(x, n, P) - 1) % P                        # vanishes on H

def make_masked_trace(secret_trace, mask_coeffs):
    """T'(x) = T(x) + Z_H(x) * R(x).  Returns evaluator over the coset."""
    Tc = lagrange_interp(H, secret_trace)                       # interpolate secret on H
    def Tprime(x):
        return (poly_eval(Tc, x) + ZH(x) * poly_eval(mask_coeffs, x)) % P
    return Tc, Tprime

# (B) masking preserves the trace on H (constraints unaffected)
secret = [secrets.randbelow(P) for _ in range(n)]
R = [secrets.randbelow(P) for _ in range(queries)]              # k random mask coeffs
Tc, Tp = make_masked_trace(secret, R)
assert all(Tp(H[i]) == secret[i] for i in range(n)), "masking changed the trace on H!"
print("(B) masking preserves trace on its domain H (constraints intact):  PASS")

# (A) HIDING: for any k distinct query points on the coset, the revealed values
#     T'(q_i) are a bijective (=uniform) function of the random mask R, hence
#     independent of the secret.  Test = the masking matrix has full rank k.
import random
random.seed(7)
allfull = True
for trial in range(20):
    qpts = random.sample(coset, queries)
    # offset_i = Z_H(q_i) * R(q_i) = sum_j Z_H(q_i) * q_i^j * R_j  -> matrix M[i][j]
    M = [[(ZH(q) * pow(q, j, P)) % P for j in range(queries)] for q in qpts]
    r = matrix_rank_modp(M)
    if r != queries: allfull = False
print(f"(A) hiding: masking matrix full-rank (k={queries}) over 20 random query sets:",
      "PASS" if allfull else "FAIL")

# Concrete independence check: two DIFFERENT secrets can yield the SAME revealed
# openings by choosing the appropriate mask -> revealed openings carry no secret info.
qpts = random.sample(coset, queries)
M = [[(ZH(q) * pow(q, j, P)) % P for j in range(queries)] for q in qpts]
def solve(M, b):  # solve M r = b mod P
    A = [row[:] + [b[i]] for i, row in enumerate(M)]
    k = len(M)
    for c in range(k):
        piv = next(r for r in range(c, k) if A[r][c] != 0)
        A[c], A[piv] = A[piv], A[c]
        pv = inv(A[c][c]); A[c] = [(v*pv) % P for v in A[c]]
        for r in range(k):
            if r != c and A[r][c]:
                f = A[r][c]; A[r] = [(A[r][j]-f*A[c][j]) % P for j in range(k+1)]
    return [A[i][k] for i in range(k)]

secret1 = [secrets.randbelow(P) for _ in range(n)]
secret2 = [secrets.randbelow(P) for _ in range(n)]
Tc1 = lagrange_interp(H, secret1); Tc2 = lagrange_interp(H, secret2)
target = [secrets.randbelow(P) for _ in range(queries)]          # the openings the verifier sees
# find masks making BOTH secrets reveal exactly `target` at qpts
b1 = [(target[i] - poly_eval(Tc1, qpts[i])) % P for i in range(queries)]
b2 = [(target[i] - poly_eval(Tc2, qpts[i])) % P for i in range(queries)]
R1 = solve(M, b1); R2 = solve(M, b2)
_, Tp1 = make_masked_trace(secret1, R1)
_, Tp2 = make_masked_trace(secret2, R2)
ok = all(Tp1(qpts[i]) == target[i] == Tp2(qpts[i]) for i in range(queries))
print("    same openings reachable from two different secrets (perfect hiding):",
      "PASS" if ok else "FAIL")
print("\nZK MASK LAYER:", "ALL PASS" if (allfull and ok) else "FAILURES")
print(f"(uses k={queries} mask coeffs to hide up to {queries} query openings;"
      f" real proofs set mask_coeffs >= queries)")
