# Tornado/Voidify-style mixer reference over the Goldilocks field (same field as the STARK).
# Uses MiMC (iterated x^7) as the zk-friendly hash, which arithmetizes with the same
# machinery as the STARK's iterated x^2+C, so the membership proof can later be moved
# INSIDE a STARK to hide the path (that hidden-path proof is the privacy property; this
# reference reveals the path to show correctness/data-flow and the on-chain-verifiable part).
import hashlib, os
P = (1 << 64) - (1 << 32) + 1            # Goldilocks
EXP = 7                                   # x^7 is a permutation mod P (7 coprime to P-1)
def _rc(i):                               # deterministic round constants
    return int.from_bytes(hashlib.sha256(b"MiMC-gl-%d" % i).digest()[:8], "little") % P
RC = [_rc(i) for i in range(64)]
def mimc_perm(x, k):
    x %= P
    for c in RC:
        x = pow((x + k + c) % P, EXP, P)
    return (x + k) % P
def H(a, b):                              # 2-to-1 hash
    return (mimc_perm(a % P, b % P) + (b % P)) % P

class Mixer:
    def __init__(self, depth=16, network=None):
        self.depth = depth
        self.leaves = []                  # commitments
        self.spent = set()                # spent nullifier hashes
        self.network = network
    # --- deposit: hide (secret, nullifier); publish commitment ---
    def deposit(self, secret=None, nullifier=None):
        secret = secret if secret is not None else int.from_bytes(os.urandom(8), "little") % P
        nullifier = nullifier if nullifier is not None else int.from_bytes(os.urandom(8), "little") % P
        commitment = H(secret, nullifier)
        idx = len(self.leaves)
        self.leaves.append(commitment)
        return {"secret": secret, "nullifier": nullifier, "commitment": commitment, "index": idx}
    # --- Merkle tree over current leaves (padded with 0) ---
    def _tree(self):
        size = 1 << self.depth
        level = self.leaves + [0] * (size - len(self.leaves))
        layers = [level]
        while len(level) > 1:
            level = [H(level[i], level[i + 1]) for i in range(0, len(level), 2)]
            layers.append(level)
        return layers
    def root(self):
        return self._tree()[-1][0]
    def _path(self, idx):
        layers = self._tree(); path = []
        for d in range(self.depth):
            sib = idx ^ 1
            path.append((layers[d][sib], idx & 1))
            idx >>= 1
        return path
    # --- withdraw: reveal nullifier_hash, prove membership ---
    def make_withdrawal(self, note, destination=None):
        # destination = where the withdrawn coin is paid. Defaults to the configured
        # Quantumroot vault (post-quantum hold). This is a destination standard only;
        # it does NOT change the proof or the mixer's privacy.
        if destination is None and self.network:
            destination = self.network.get("quantumroot_vault", "") or "(unset Quantumroot vault)"
        nh = H(note["nullifier"], 0)
        return {"root": self.root(), "nullifier_hash": nh, "destination": destination,
                "commitment": note["commitment"], "index": note["index"],
                "path": self._path(note["index"]),
                # in a ZK version secret/nullifier/path are hidden inside the proof:
                "_secret": note["secret"], "_nullifier": note["nullifier"]}
    def verify_withdrawal(self, w):
        if w["nullifier_hash"] in self.spent:
            return False, "double-spend (nullifier already used)"
        # recompute commitment from the (hidden-in-ZK) preimage
        if H(w["_secret"], w["_nullifier"]) != w["commitment"]:
            return False, "commitment != H(secret, nullifier)"
        if H(w["_nullifier"], 0) != w["nullifier_hash"]:
            return False, "nullifier_hash mismatch"
        cur = w["commitment"]
        for sib, bit in w["path"]:
            cur = H(sib, cur) if bit else H(cur, sib)
        if cur != w["root"]:
            return False, "Merkle path does not reach root"
        self.spent.add(w["nullifier_hash"])
        return True, "ok"

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    try:
        from networks import select
        net = select(sys.argv[1] if len(sys.argv) > 1 else "bch",
                     sys.argv[2] if len(sys.argv) > 2 else "chipnet")
    except Exception:
        net = {"chain": "bch", "network": "chipnet"}
    print(f"mixer target: {net['chain']}/{net['network']}  (depth=16, MiMC/Goldilocks)")
    m = Mixer(network=net)
    notes = [m.deposit() for _ in range(5)]            # 5 anonymous deposits
    print(f"deposited {len(m.leaves)} notes, root={hex(m.root())[:18]}...")
    w = m.make_withdrawal(notes[2])
    print("withdraw destination  :", w["destination"])
    print("valid withdrawal      :", m.verify_withdrawal(w))
    print("same note again       :", m.verify_withdrawal(m.make_withdrawal(notes[2])))
    bad = m.make_withdrawal(notes[3]); bad["_secret"] ^= 1
    print("wrong secret          :", m.verify_withdrawal(bad))
    forged = m.make_withdrawal(notes[4]); forged["nullifier_hash"] ^= 1
    print("forged nullifier hash :", m.verify_withdrawal(forged))
