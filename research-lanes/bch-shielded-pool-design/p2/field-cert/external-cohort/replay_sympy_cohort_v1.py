#!/usr/bin/env python3
"""Pinned SymPy challenge/search for the first arithmetic frontier cohort.

This is a deterministic search record, not a field or protocol selector.
Primality is bound to the existing deterministic Lucas--Lehmer fixture; the
external CAS independently supplies probable-prime corroboration, direct
irreducibility, and factorization for every tested predecessor and winner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from itertools import product
from pathlib import Path

import sympy
from sympy import Poly, symbols
from sympy.ntheory import isprime


ROOT = Path(__file__).resolve().parents[5]
PRIME_FIXTURE = ROOT / "research-lanes" / "bch-shielded-pool-design" / "p2" / "field-cert" / "fixtures" / "frontier-prime-checks.v1.json"
SEARCH_SPEC = {
    "coefficientEncoding": "unsigned-decimal-ascending-c0-to-cd",
    "monic": True,
    "constantCoefficient": "nonzero",
    "coefficientBounds": [1, 2, 3],
    "boundInterpretation": "max-lower-coefficient-exactly-equals-bound; no duplicate tuples",
    "order": "coefficientBound-then-nonzeroWeight-then-lexicographic-ascending-coefficient-tuple",
    "candidateForm": "x^d + sum(c_i*x^i for i=0..d-1)",
    "stop": "first-directly-irreducible-candidate-in-the-total-order",
}
TARGETS = ((31, 5), (31, 6), (61, 3))
CHALLENGE_CANDIDATES = (
    (31, 5, [-1, 2, 0, 0, 0, 1]),
    (31, 6, [-5, 0, 0, 0, 0, 0, 1]),
    (61, 3, [-5, 0, 0, 1]),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def coefficient_row(poly: Poly) -> list[str]:
    p = int(poly.get_modulus())
    return [str(int(poly.nth(i)) % p) for i in range(poly.degree() + 1)]


def factor_row(factor: Poly, multiplicity: int) -> dict[str, object]:
    return {
        "coefficientsAscending": coefficient_row(factor),
        "degree": factor.degree(),
        "multiplicity": multiplicity,
    }


def deterministic_lucas_lehmer(q: int, p: int) -> dict[str, object]:
    residue = 4
    for _ in range(q - 2):
        residue = (residue * residue - 2) % p
    return {"iterations": q - 2, "residue": residue, "passed": residue == 0}


def prime_record(prime_fixture: dict[str, object], q: int) -> dict[str, object]:
    check = next(item for item in prime_fixture["checks"] if int(item["mersenneExponent"]) == q)
    p = 2**q - 1
    external_ll = deterministic_lucas_lehmer(q, p)
    fixture_ll = check["lucasLehmer"]
    if str(p) != check["modulus"] or external_ll["residue"] != int(fixture_ll["residue"]):
        raise AssertionError(f"prime fixture mismatch for q={q}")
    return {
        "exponent": q,
        "modulus": str(p),
        "fixtureClassification": check["classification"],
        "fixtureLucasLehmer": {
            "iterations": int(fixture_ll["iterations"]),
            "residue": int(fixture_ll["residue"]),
            "passed": fixture_ll["passed"] is True,
        },
        "externalLucasLehmerReplay": external_ll,
        "sympyIsPrime": {
            "value": bool(isprime(p)),
            "classification": "probable-prime-only-for-this-size",
        },
    }


def search_target(q: int, degree: int, prime: dict[str, object]) -> dict[str, object]:
    p = int(prime["modulus"])
    x = symbols("x")
    tested: list[dict[str, object]] = []
    winner: dict[str, object] | None = None
    for bound in SEARCH_SPEC["coefficientBounds"]:
        tuples = []
        for coefficients in product(range(bound + 1), repeat=degree):
            if coefficients[0] == 0 or max(coefficients) != bound:
                continue
            tuples.append((sum(value != 0 for value in coefficients), coefficients))
        for weight, coefficients in sorted(tuples, key=lambda item: (item[0], item[1])):
            polynomial = Poly(
                x**degree + sum(coefficients[i] * x**i for i in range(degree)),
                x,
                modulus=p,
            )
            constant, factors = polynomial.factor_list()
            factor_rows = [factor_row(factor, multiplicity) for factor, multiplicity in factors]
            irreducible = bool(polynomial.is_irreducible)
            row = {
                "coefficientBound": bound,
                "nonzeroWeight": weight,
                "coefficientsAscending": [str(value) for value in (*coefficients, 1)],
                "directIrreducible": irreducible,
                "factorization": {
                    "constant": str(int(constant) % p),
                    "factors": factor_rows,
                    "singleIrreducibleFactor": (
                        int(constant) % p == 1
                        and len(factors) == 1
                        and factors[0][0] == polynomial
                        and factors[0][1] == 1
                    ),
                },
            }
            tested.append(row)
            if irreducible:
                winner = row
                break
        if winner is not None:
            break
    if winner is None:
        raise AssertionError(f"no sparse irreducible found for q={q}, degree={degree}")
    irreducible_small_window = []
    for bound in SEARCH_SPEC["coefficientBounds"]:
        tuples = []
        for coefficients in product(range(bound + 1), repeat=degree):
            if coefficients[0] == 0 or max(coefficients) != bound:
                continue
            weight = sum(value != 0 for value in coefficients)
            if weight > 3:
                continue
            tuples.append((weight, coefficients))
        for weight, coefficients in sorted(tuples, key=lambda item: (item[0], item[1])):
            polynomial = Poly(
                x**degree + sum(coefficients[i] * x**i for i in range(degree)),
                x,
                modulus=p,
            )
            if bool(polynomial.is_irreducible):
                irreducible_small_window.append({
                    "coefficientBound": bound,
                    "nonzeroWeight": weight,
                    "coefficientsAscending": [str(value) for value in (*coefficients, 1)],
                })
    return {
        "basePrimeExponent": q,
        "modulus": str(p),
        "degree": degree,
        "prime": prime,
        "winner": winner,
        "testedPredecessors": tested[:-1],
        "testedCountThroughWinner": len(tested),
        "irreducibleCandidatesInBoundedWeightThreeWindow": irreducible_small_window,
    }


def challenge_record(q: int, degree: int, coefficients: list[int], prime: dict[str, object]) -> dict[str, object]:
    p = int(prime["modulus"])
    if len(coefficients) != degree + 1 or coefficients[-1] != 1:
        raise AssertionError(f"invalid challenge shape for q={q}, degree={degree}")
    x = symbols("x")
    polynomial = Poly(sum(coefficients[i] * x**i for i in range(degree + 1)), x, modulus=p)
    constant, factors = polynomial.factor_list()
    return {
        "basePrimeExponent": q,
        "degree": degree,
        "signedCoefficientsAscending": [str(value) for value in coefficients],
        "coefficientsModuloPAscending": [str(value % p) for value in coefficients],
        "directIrreducible": bool(polynomial.is_irreducible),
        "factorization": {
            "constant": str(int(constant) % p),
            "factors": [factor_row(factor, multiplicity) for factor, multiplicity in factors],
            "singleIrreducibleFactor": int(constant) % p == 1 and len(factors) == 1 and factors[0][0] == polynomial and factors[0][1] == 1,
        },
        "primarySearchMembership": False,
        "primarySearchExclusion": "signed coefficient or coefficient magnitude outside the primary nonnegative bound-1..3 domain",
        "rejectedPredecessorsUnderPrimarySearchOrder": [],
    }


def replay(prime_fixture_path: Path = PRIME_FIXTURE) -> dict[str, object]:
    prime_bytes = prime_fixture_path.read_bytes()
    prime_fixture = json.loads(prime_bytes.decode("utf-8"))
    primes = {q: prime_record(prime_fixture, q) for q, _ in TARGETS}
    targets = [search_target(q, degree, primes[q]) for q, degree in TARGETS]
    challenges = [challenge_record(q, degree, coefficients, primes[q]) for q, degree, coefficients in CHALLENGE_CANDIDATES]
    return {
        "schema": "shieldkit-labs/field-cert/external-cohort-replay/v1",
        "labels": [
            "external-cas-replay",
            "external-cohort",
            "component-only",
            "root-review-pending",
            "not-selection",
            "not-protocol-qualification",
        ],
        "tool": "SymPy",
        "sympyVersion": sympy.__version__,
        "primeFixture": {
            "path": "p2/field-cert/fixtures/frontier-prime-checks.v1.json",
            "sha256": sha256(prime_bytes),
            "classification": "deterministic-lucas-lehmer-source-pinned-fixture; SymPy is corroboration only",
        },
        "searchSpec": SEARCH_SPEC,
        "targets": targets,
        "explicitRootChallengeCandidates": challenges,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", nargs="?", type=Path, default=PRIME_FIXTURE)
    args = parser.parse_args()
    print(json.dumps(replay(args.fixture), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
