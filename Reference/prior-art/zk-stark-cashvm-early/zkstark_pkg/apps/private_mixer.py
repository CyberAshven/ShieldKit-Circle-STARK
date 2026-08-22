# Private mixer: withdrawal proves membership + nullifier INSIDE the STARK, so the
# Merkle path, secret, and nullifier are NEVER revealed. The verifier learns only the
# public root, the nullifier hash (to stop double-spend), and the proof. This is the
# privacy property the transparent mixer.py reference lacked. Reference-grade.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import membership_stark as M

def h2_tree(leaves, depth):
    size = 1 << depth
    level = leaves + [0]*(size - len(leaves))
    layers = [level]
    while len(level) > 1:
        level = [M.H2(level[i], level[i+1]) for i in range(0, len(level), 2)]
        layers.append(level)
    return layers

def auth_path(layers, idx):
    sibs = []
    for d in range(len(layers)-1):
        sibs.append(layers[d][idx ^ 1]); idx >>= 1
    return sibs

class PrivateMixer:
    def __init__(self, depth=4):
        self.depth = depth
        self.notes = []          # (secret, nullifier) the user keeps; commitments are public
        self.spent = set()
    def deposit(self, secret=None, nullifier=None):
        secret = secret if secret is not None else int.from_bytes(os.urandom(8),"little")%M.P
        nullifier = nullifier if nullifier is not None else int.from_bytes(os.urandom(8),"little")%M.P
        commitment = M.H2(secret, nullifier)
        self.notes.append((secret, nullifier, commitment))
        return len(self.notes)-1
    def commitments(self): return [c for _,_,c in self.notes]
    def root(self): return h2_tree(self.commitments(), self.depth)[-1][0]
    def private_withdraw(self, idx, grind_b=8):
        secret, nullifier, _ = self.notes[idx]
        layers = h2_tree(self.commitments(), self.depth)
        sibs = auth_path(layers, idx)
        proof = M.prove(secret, nullifier, sibs, grind_b=grind_b)
        # reveal ONLY public root, nullifier hash, proof. No secret/nullifier/path/index.
        return {"root": proof["root"], "nullifier_hash": proof["nh"], "proof": proof}
    def verify_withdraw(self, w):
        if w["nullifier_hash"] in self.spent: return False, "double-spend"
        ok, msg = M.verify(w["proof"])
        if not ok: return False, f"proof invalid: {msg}"
        if w["proof"]["root"] != self.root(): return False, "root mismatch"
        if w["proof"]["nh"] != w["nullifier_hash"]: return False, "nullifier hash mismatch"
        self.spent.add(w["nullifier_hash"]); return True, "ok"

if __name__ == "__main__":
    mx = PrivateMixer(depth=4)
    ids = [mx.deposit() for _ in range(6)]
    print(f"{len(ids)} private deposits, root={hex(mx.root())[:18]}...")
    w = mx.private_withdraw(ids[3])
    print("withdrawal reveals keys:", sorted(w.keys()))
    print("  -> path/secret/nullifier in payload:",
          any(k in w for k in ("secret","nullifier","path","index")))
    print("valid private withdrawal :", mx.verify_withdraw(w))
    print("same nullifier again     :", mx.verify_withdraw(w))
    # forge: flip the public root
    bad = mx.private_withdraw(ids[4]); bad["proof"]["root"] = M.add(bad["proof"]["root"],1)
    print("forged root              :", mx.verify_withdraw(bad))
