# Network selector ("knobs"). Pick chain + network; get its params.
# Endpoints are public/community defaults; verify before real use, they move.
# quantumroot_vault = default mixer withdrawal destination: a P2SH32 address of a
# Quantumroot Schnorr+LM-OTS vault (post-quantum). Empty until you compile the
# bitjson/quantumroot libauth template with your HD key. Mixer hides the link;
# this vault makes the resulting UTXO quantum-secure to hold/spend. Separate concerns.
# Template: apps/quantumroot/quantumroot-schnorr-lm-ots-vault.json (bitjson). Open it in
# libauth / ide.bitauth.com, set your HD key on the signer entity, compile receive_address
# to get the P2SH32 address, then paste it into quantumroot_vault above.
NETWORKS = {
    "bch": {
        "mainnet":  {"bchn_flag": "",          "electrum": "fulcrum.fountainhead.cash:50002",
                     "explorer": "https://blockchair.com/bitcoin-cash",            "p2sh32": True, "vm2026": True, "quantumroot_vault": ""},
        "chipnet":  {"bchn_flag": "-chipnet",   "electrum": "chipnet.imaginary.cash:50002",
                     "explorer": "https://chipnet.imaginary.cash",                 "p2sh32": True, "vm2026": True, "quantumroot_vault": "",
                     "note": "2026 upgrade (loops/functions/P2S) is live here; forks ~6 months ahead of mainnet"},
        "testnet4": {"bchn_flag": "-testnet4",  "electrum": "testnet4.imaginary.cash:50002",
                     "explorer": "https://testnet4.imaginary.cash",                "p2sh32": True, "vm2026": False, "quantumroot_vault": ""},
    },
    "solana": {
        "mainnet-beta": {"rpc": "https://api.mainnet-beta.solana.com", "explorer": "https://explorer.solana.com"},
        "devnet":       {"rpc": "https://api.devnet.solana.com",       "explorer": "https://explorer.solana.com/?cluster=devnet"},
        "testnet":      {"rpc": "https://api.testnet.solana.com",      "explorer": "https://explorer.solana.com/?cluster=testnet"},
        "localnet":     {"rpc": "http://localhost:8899",               "explorer": "(local validator)"},
    },
}

def select(chain, network):
    c = NETWORKS[chain]
    if network not in c:
        raise ValueError(f"{chain}: pick one of {list(c)}")
    cfg = dict(c[network]); cfg["chain"] = chain; cfg["network"] = network
    return cfg

if __name__ == "__main__":
    import sys
    chain = sys.argv[1] if len(sys.argv) > 1 else "bch"
    net   = sys.argv[2] if len(sys.argv) > 2 else "chipnet"
    cfg = select(chain, net)
    print(f"[{chain}/{net}]")
    for k, v in cfg.items():
        if k not in ("chain", "network"):
            print(f"  {k}: {v}")
