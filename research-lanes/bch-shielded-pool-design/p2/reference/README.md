# P2 Tranche-0 M31 reference

This directory contains an independent, dependency-light JavaScript reference
for the base field

```text
p = 2^31 - 1 = 2147483647
```

It is a control/reference artifact for the candidate rows
`field:m31-degree4-control`, `field:m31-degree5`, and `field:m31-degree6`. It
does not select an extension polynomial, tower, Circle domain, hash, AIR, or
proof profile, and it does not claim BCH Script or prover performance.

## Canonical representation

One element is exactly four unsigned little-endian bytes. Values `>= p`, any
other byte length, uppercase/non-hex text, and trailing bytes in a full decode
are rejected. Public arithmetic accepts `BigInt` only; JavaScript `Number`
inputs are rejected to prevent truncation. `m31-kat.json` contains expected
outputs derived independently of `m31.mjs`. Its pinned SHA-256 is
`603fd7283038b1e61d2fb92c82192a46d548b314dd9a0078540f2d2add11427f`.
The rejection corpus explicitly includes `00000080`: it is unsigned `p+1`,
but BCH `OP_BIN2NUM` would otherwise canonicalize it as ScriptNum negative
zero. The later Script decoder must reject that sign-bit alias before numeric
conversion.

The fixed wire format does not contradict the P0 artifacts: P0 freezes the
backend-neutral relation and leaves the cryptographic field selection
unselected. This module therefore remains measured-reference groundwork, not
a protocol choice.

## API and tests

`m31.mjs` provides strict encoding/decoding, full-consumption sequence helpers,
`add`, `sub`, `neg`, `mul`, `square`, extended-Euclidean `inverse`, and inverse
hint verification. Zero inversion and noncanonical elements are rejected.

`m31-corpus.json` is a content-pinned corpus with seven required operation
KATs, 24 SplitMix64 vectors, exhaustive `[0, 32)` pairs, and boundary values.
The corpus seed, 64-bit wraparound/mixing steps, sampling rule, final state,
and artifact SHA-256 are checked by `m31-corpus.test.mjs`. Metamorphic tests
cover commutativity, associativity, distributivity, square/multiply equality,
subtraction/addition inverses, and codec round trips.

Pinned artifact digests:

```text
m31-kat.json:     603fd7283038b1e61d2fb92c82192a46d548b314dd9a0078540f2d2add11427f
m31-corpus.json:  fa76c62cfd3fb2ea4898b0b42fda5f21edcd41cb023c84925237eb903fe0dcd9
```

Run from the repository root:

```bash
node --test research-lanes/bch-shielded-pool-design/p2/reference/m31.test.mjs
node --test research-lanes/bch-shielded-pool-design/p2/reference/m31-corpus.test.mjs
node --check research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs
node --check research-lanes/bch-shielded-pool-design/p2/reference/m31.test.mjs
node --check research-lanes/bch-shielded-pool-design/p2/reference/m31-corpus.test.mjs
sha256sum research-lanes/bch-shielded-pool-design/p2/reference/m31-kat.json
sha256sum research-lanes/bch-shielded-pool-design/p2/reference/m31-corpus.json
```

The KAT decimal values and wire outputs were independently derived with this
read-only Python command (the command is documentation only and is not used
by the Node implementation):

```bash
python3 - <<'PY'
p = 2**31 - 1
a, b = 0x12345678, 0x0f1e2d3c
print({
    "add": (a + b) % p,
    "sub": (a - b) % p,
    "neg": (-a) % p,
    "mul": (a * b) % p,
    "square": (a * a) % p,
    "inverse_a": pow(a, p - 2, p),
    "inverse_b": pow(b, p - 2, p),
})
PY
```

## Gate status

The canonical-reference gate is PASS for the base-field scope: deterministic
KATs, the content-pinned deterministic corpus, exhaustive low-range and
boundary subsets, metamorphic identities, boundary/rejection vectors,
inverse-hint checks, strict lowercase hex, and full-consumption behavior are
covered. The extension/Circle/Script gates remain `unmeasured`; no escalation
or candidate promotion is implied.
