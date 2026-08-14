# M29 control compositeness check — 2026-08-08

The candidate-matrix label `M29` was intended as the Mersenne modulus

```text
p = 2^29 - 1 = 536870911.
```

It is not prime:

```text
536870911 = 233 * 1103 * 2089.
```

All three factors are nontrivial, so the equality alone is a complete
compositeness certificate. The candidate therefore cannot define a base field
and is killed before encoding, Circle-domain, or BCH cost experiments. This
does not eliminate every approximately 29-bit prime; any replacement must be
introduced under a new, precisely named row with its own domain-order and
soundness analysis.

Reproduce with exact integer arithmetic:

```bash
node -e "const p=(1n<<29n)-1n; const q=233n*1103n*2089n; if(p!==q)process.exit(1); console.log(p.toString(), q.toString())"
```

