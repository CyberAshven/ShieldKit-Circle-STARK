# Cross-chain atomic swap protocol + watcher simulation (BCH leg <-> Solana leg).
# Models the real HTLC flow: the SAME sha256 hashlock is locked on both chains;
# claiming one leg reveals the preimage, which the counterparty's watcher uses to
# claim the other leg. Timeouts let either party refund if the swap stalls.
#
# BCH leg = the VM-validated htlc.cash (claim/refund verified on the real 2026 VM).
# Solana leg = solana_htlc.rs (reference). This file simulates protocol LOGIC only;
# it does not broadcast. Live execution needs both chains + a real watcher.
import os, hashlib, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from networks import select

def sha256(b): return hashlib.sha256(b).digest()

class HTLC:
    def __init__(self, chain, recipient, sender, hashlock, timeout):
        self.chain, self.recipient, self.sender = chain, recipient, sender
        self.hashlock, self.timeout = hashlock, timeout
        self.funded = True; self.claimed_by = None; self.refunded = False
    def claim(self, who, preimage, now):
        assert self.funded and not self.refunded, "not claimable"
        if sha256(preimage) != self.hashlock: return False, "bad preimage"
        if who != self.recipient: return False, "not recipient"
        self.funded = False; self.claimed_by = who
        return True, preimage          # preimage now public on this chain
    def refund(self, who, now):
        if now < self.timeout: return False, "before timeout"
        if who != self.sender: return False, "not sender"
        self.funded = False; self.refunded = True
        return True, "refunded"

def swap(bch_net, sol_net, happy=True):
    print(f"swap: BCH[{bch_net}] <-> SOL[{sol_net}]")
    select("bch", bch_net); select("solana", sol_net)   # validate knobs resolve
    secret = os.urandom(32); H = sha256(secret)          # Alice generates the secret
    # Alice has BCH and wants SOL; Bob has SOL and wants BCH.
    # Alice locks BCH with the LONGER timeout (initiator is protected).
    bch = HTLC("bch", recipient="Bob", sender="Alice", hashlock=H, timeout=20)
    sol = HTLC("solana", recipient="Alice", sender="Bob", hashlock=H, timeout=10)
    print("  1. Alice locks BCH HTLC (recipient Bob, timeout 20)")
    print("  2. Bob locks SOL HTLC (recipient Alice, timeout 10)")
    if happy:
        ok, pre = sol.claim("Alice", secret, now=5)      # Alice claims SOL, reveals secret
        print("  3. Alice claims SOL revealing secret    :", ok)
        # Bob's watcher sees the preimage on Solana, claims BCH with it
        ok2, _ = bch.claim("Bob", pre, now=6)
        print("  4. Bob's watcher uses secret to claim BCH:", ok2)
        print("  result:", "SWAP COMPLETE" if (ok and ok2) else "FAILED")
    else:
        # stall: nobody claims; both refund after their timeouts
        print("  3. swap stalls; no claim")
        r1,_ = sol.refund("Bob", now=11); r2,_ = bch.refund("Alice", now=21)
        print("  4. Bob refunds SOL (t>=10):", r1, "| Alice refunds BCH (t>=20):", r2)
        print("  result:", "REFUNDED, no loss" if (r1 and r2) else "FAILED")

if __name__ == "__main__":
    bch_net = sys.argv[1] if len(sys.argv) > 1 else "chipnet"
    sol_net = sys.argv[2] if len(sys.argv) > 2 else "devnet"
    swap(bch_net, sol_net, happy=True); print()
    swap(bch_net, sol_net, happy=False)
