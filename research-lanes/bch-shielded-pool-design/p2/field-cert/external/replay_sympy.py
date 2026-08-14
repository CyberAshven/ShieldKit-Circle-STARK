#!/usr/bin/env python3
"""Replay the M89 quadratic-polynomial fixture through SymPy.

SymPy is used as an independent algebra system for polynomial irreducibility,
factorisation, the Legendre-symbol cross-check, and a source-pinned replay of
its deterministic Lucas--Lehmer routine. Its generic ``isprime`` result is
recorded only as probable-prime corroboration for this input size.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import sympy
from sympy import Integer, Poly, symbols
from sympy.functions.combinatorial.numbers import legendre_symbol
from sympy.ntheory import isprime
from sympy.ntheory.primetest import _lucas_lehmer_primality_test


DEFAULT_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "m89-x2-plus-1-rabin.v1.json"
)


def replay(fixture_path: Path) -> dict[str, object]:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    certificate = fixture["certificate"]
    prime_check = certificate["mersennePrimeCheck"]
    p = Integer(certificate["modulus"])
    exponent = int(prime_check["mersenneExponent"])
    x = symbols("x")
    polynomial = Poly(x**2 + 1, x, modulus=p)

    fixture_coefficients = [int(item) for item in certificate["polynomial"]]
    fixture_prime_proof = {
        "method": "deterministic-lucas-lehmer",
        "iterations": int(prime_check["lucasLehmer"]["iterations"]),
        "residue": int(prime_check["lucasLehmer"]["residue"]),
        "passed": prime_check["lucasLehmer"]["passed"] is True,
        "fixtureClassification": prime_check["classification"],
    }

    factor_constant, factors = polynomial.factor_list()
    factor_rows = [
        {"factor": str(factor.as_expr()), "multiplicity": int(multiplicity)}
        for factor, multiplicity in factors
    ]

    return {
        "labels": [
            "external-cas-replay",
            "component-only",
            "root-reviewed-component-pass",
            "not-selection",
            "not-protocol-qualification",
        ],
        "fixtureId": fixture["fixtureId"],
        "tool": "SymPy",
        "sympyVersion": sympy.__version__,
        "modulus": str(p),
        "mersenneExponent": exponent,
        "polynomial": "x**2 + 1",
        "fixturePolynomialCoefficientsAscending": fixture_coefficients,
        "checks": {
            "fixtureModulusMatches2Pow89Minus1": p == Integer(2) ** exponent - 1,
            "fixturePolynomialMatchesX2Plus1": fixture_coefficients == [1, 0, 1],
            "sympyIsPrime": {
                "value": bool(isprime(p)),
                "classification": "probable-prime-only-for-this-size",
            },
            "sympyLucasLehmerPrimeProof": {
                "value": bool(_lucas_lehmer_primality_test(exponent)),
                "classification": "deterministic-source-pinned-private-api",
                "iterations": exponent - 2,
            },
            "fixtureLucasLehmerPrimeProof": fixture_prime_proof,
            "legendreSymbolMinusOne": {
                "value": int(legendre_symbol(-1, p)),
                "irreducibleQuadraticCriterion": int(legendre_symbol(-1, p)) == -1,
            },
            "sympyDirectIrreducibility": bool(polynomial.is_irreducible),
            "sympyFactorization": {
                "constant": str(factor_constant),
                "factors": factor_rows,
                "singleIrreducibleFactor": (
                    factor_constant == 1
                    and len(factors) == 1
                    and int(factors[0][1]) == 1
                    and factors[0][0] == polynomial
                ),
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", nargs="?", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()
    print(json.dumps(replay(args.fixture), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
