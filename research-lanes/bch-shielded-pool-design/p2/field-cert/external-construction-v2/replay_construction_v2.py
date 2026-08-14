#!/usr/bin/env python3
"""Independent pinned-SymPy signed sparse construction search, v2."""

from __future__ import annotations

import argparse
import hashlib
import json
from itertools import combinations
from pathlib import Path

from sympy import Poly, symbols

import sympy


ROOT = Path(__file__).resolve().parents[5]
PRIME_FIXTURE = ROOT / "research-lanes" / "bch-shielded-pool-design" / "p2" / "field-cert" / "fixtures" / "frontier-prime-checks.v1.json"
TARGETS = ((31, 5), (31, 6), (61, 3))
K = 16
VALUES = tuple(value for magnitude in range(1, K + 1) for value in (-magnitude, magnitude))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def centered(value: int, p: int) -> int:
    residue = value % p
    return residue - p if residue > p // 2 else residue


def bit_length(value: int) -> int:
    return abs(value).bit_length()


def signed_rank(value: int) -> int:
    if value == 0:
        return 0
    magnitude = abs(value)
    return 2 * magnitude - 1 if value < 0 else 2 * magnitude


def row_for_power(power: int, degree: int, coefficients: tuple[int, ...], p: int) -> list[int]:
    if power < degree:
        return [1 if index == power else 0 for index in range(degree)]
    rows: dict[int, list[int]] = {}
    for current in range(degree, power + 1):
        accumulated = [0] * degree
        for index, coefficient in enumerate(coefficients):
            source = row_for_power(current - degree + index, degree, coefficients, p) if current - degree + index < degree else rows[current - degree + index]
            for column, value in enumerate(source):
                accumulated[column] -= coefficient * value
        rows[current] = [centered(value, p) for value in accumulated]
    return rows[power]


def reduction_rows(degree: int, coefficients: tuple[int, ...], p: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    previous: dict[int, list[int]] = {}
    for power in range(degree, 2 * degree - 1):
        accumulated = [0] * degree
        for index, coefficient in enumerate(coefficients):
            source_power = power - degree + index
            source = [1 if column == source_power else 0 for column in range(degree)] if source_power < degree else previous[source_power]
            for column, value in enumerate(source):
                accumulated[column] -= coefficient * value
        row = [centered(value, p) for value in accumulated]
        previous[power] = row
        rows.append({"power": power, "coefficientsCentered": row, "fanIn": sum(value != 0 for value in row)})
    return rows


def score_candidate(degree: int, coefficients: tuple[int, ...], rows: list[dict[str, object]]) -> list[object]:
    entries = [value for row in rows for value in row["coefficientsCentered"]]
    full_polynomial = (*coefficients, 1)
    ranks = [signed_rank(value) for value in coefficients]
    return [
        sum(abs(value) > 1 for value in entries),
        sum(value != 0 for value in entries),
        sum(bit_length(value) for value in entries),
        max((bit_length(value) for value in entries), default=0),
        max((int(row["fanIn"]) for row in rows), default=0),
        max(abs(value) for value in full_polynomial),
        sum(value != 0 for value in full_polynomial),
        sum(abs(value) for value in full_polynomial),
        *ranks,
    ]


def factor_rows(polynomial: Poly) -> tuple[int, list[dict[str, object]]]:
    constant, factors = polynomial.factor_list()
    p = int(polynomial.get_modulus())
    result = []
    for factor, multiplicity in factors:
        result.append({
            "coefficientsAscendingModuloP": [str(int(factor.nth(index)) % p) for index in range(factor.degree() + 1)],
            "degree": factor.degree(),
            "multiplicity": multiplicity,
        })
    return int(constant) % p, result


def candidate_rows(q: int, degree: int, p: int) -> list[tuple[int, ...]]:
    rows: list[tuple[int, ...]] = []
    for support_size in (1, 2):
        for secondary_index in ((None,) if support_size == 1 else tuple(range(1, degree))):
            for t0 in VALUES:
                if support_size == 1:
                    rows.append((t0, *([0] * (degree - 1))))
                else:
                    for secondary in VALUES:
                        coefficients = [0] * degree
                        coefficients[0] = t0
                        coefficients[secondary_index] = secondary
                        rows.append(tuple(coefficients))
    return rows


def replay(
    prime_fixture_path: Path = PRIME_FIXTURE,
    neutral_transcript_path: Path | None = None,
    checker_transcript_path: Path | None = None,
) -> dict[str, object]:
    prime_fixture = json.loads(prime_fixture_path.read_text(encoding="utf-8"))
    checks = {int(item["mersenneExponent"]): item for item in prime_fixture["checks"]}
    targets = []
    checker_transcript = []
    neutral_transcript = []
    global_order_index = 0
    for q, degree in TARGETS:
        p = 2**q - 1
        check = checks[q]
        if check["modulus"] != str(p) or not check["lucasLehmer"]["passed"]:
            raise AssertionError(f"prime fixture mismatch for M{q}")
        x = symbols("x")
        rows = candidate_rows(q, degree, p)
        irreducibles = []
        for ordinal, coefficients in enumerate(rows):
            polynomial = Poly(x**degree + sum(coefficients[index] * x**index for index in range(degree)), x, modulus=p)
            constant, factors = factor_rows(polynomial)
            direct_irreducible = bool(polynomial.is_irreducible)
            reduction = reduction_rows(degree, coefficients, p)
            score = score_candidate(degree, coefficients, reduction)
            row = {
                "basePrimeExponent": q,
                "degree": degree,
                "ordinal": ordinal,
                "supportSize": sum(value != 0 for value in coefficients),
                "coefficientsSignedAscending": list(coefficients),
                "coefficientsModuloPAscending": [str(value % p) for value in (*coefficients, 1)],
                "directIrreducible": direct_irreducible,
                "factorization": {"constant": str(constant), "factors": factors},
                "score": score,
                "reductionRows": reduction,
            }
            checker_transcript.append(row)
            neutral_transcript.append({
                "targetOrderIndex": TARGETS.index((q, degree)),
                "candidateIndex": ordinal,
                "globalOrderIndex": global_order_index,
                "support": row["supportSize"],
                "secondaryIndex": (None if row["supportSize"] == 1 else next(index for index, value in enumerate(coefficients) if index > 0 and value != 0)),
                "q": q,
                "degree": degree,
                "p": str(p),
                "tCentered": list(coefficients),
                "tCanonical": [str(value % p) for value in coefficients],
                "polynomialCanonical": [str(value % p) for value in (*coefficients, 1)],
                "irreducible": direct_irreducible,
                "reductionExponents": list(range(degree, 2 * degree - 1)),
                "reductionRows": [[str(value) for value in item["coefficientsCentered"]] for item in reduction],
                "score": {
                    "nonZeroNonSignedUnitEntryCount": score[0],
                    "nonZeroEntryCount": score[1],
                    "bitLengthSum": score[2],
                    "peakBitLength": score[3],
                    "peakRowFanIn": score[4],
                    "polynomialMaxAbsCoefficient": score[5],
                    "polynomialSupport": score[6],
                    "polynomialL1": score[7],
                    "signedLexRanks": score[8:],
                    "lexicographicTuple": score,
                },
            })
            global_order_index += 1
            if direct_irreducible:
                irreducibles.append(row)
        winner = min(irreducibles, key=lambda row: row["score"])
        targets.append({
            "basePrimeExponent": q,
            "modulus": str(p),
            "degree": degree,
            "testedCount": len(rows),
            "irreducibleCount": len(irreducibles),
            "winner": winner,
            "primeFixture": {
                "classification": check["classification"],
                "lucasLehmerIterations": int(check["lucasLehmer"]["iterations"]),
                "lucasLehmerResidue": int(check["lucasLehmer"]["residue"]),
            },
        })
    neutral = {
        "schema": "shieldkit-labs/p2/construction-freeze-normalized-transcript/v1",
        "transcriptId": "construction-freeze:normalized-decision-transcript-v1",
        "rows": neutral_transcript,
        "rowCount": len(neutral_transcript),
        "contentDigest": None,
    }
    neutral["contentDigest"] = sha256(json.dumps({key: value for key, value in neutral.items() if key != "contentDigest"}, sort_keys=True, separators=(",", ":")).encode())
    neutral_bytes = (json.dumps(neutral, separators=(",", ":")) + "\n").encode()
    checker = {
        "schema": "shieldkit-labs/field-cert/external-construction-v2-checker-transcript/v1",
        "rows": checker_transcript,
        "rowCount": len(checker_transcript),
        "contentDigest": None,
    }
    checker["contentDigest"] = sha256(json.dumps({key: value for key, value in checker.items() if key != "contentDigest"}, sort_keys=True, separators=(",", ":")).encode())
    checker_bytes = (json.dumps(checker, separators=(",", ":")) + "\n").encode()
    if neutral_transcript_path is not None:
        neutral_transcript_path.parent.mkdir(parents=True, exist_ok=True)
        neutral_transcript_path.write_bytes(neutral_bytes)
    if checker_transcript_path is not None:
        checker_transcript_path.parent.mkdir(parents=True, exist_ok=True)
        checker_transcript_path.write_bytes(checker_bytes)
    return {
        "schema": "shieldkit-labs/field-cert/external-construction-v2-replay/v1",
        "labels": ["heuristic", "construction-only", "not-family-elimination", "not-protocol-selection", "external-cross-check-complete-not-evidence"],
        "tool": "SymPy",
        "sympyVersion": sympy.__version__,
        "parameters": {
            "K": K,
            "valueOrder": "-1,+1,-2,+2,...,-16,+16",
            "supportOrder": "support1 then support2; secondary index ascending; t0 then secondary value",
            "irreducibilityFilter": "direct SymPy Poly.is_irreducible before lexicographic score minimization",
            "scoreFields": ["nonZeroNonSignedUnitEntryCount", "nonZeroEntryCount", "bitLengthSum", "peakBitLength", "peakRowFanIn", "polynomialMaxAbsCoefficient", "polynomialSupport", "polynomialL1", "signedLexRanks"],
            "centeredLift": "residue in [-(p-1)/2,(p-1)/2]",
            "recurrence": "R_k = centered(-sum_i(t_i * R_(k-d+i))) with R_j=e_j for j<d",
        },
        "primeFixture": {"path": "p2/field-cert/fixtures/frontier-prime-checks.v1.json", "sha256": sha256(prime_fixture_path.read_bytes())},
        "targets": targets,
        "neutralTranscript": {"path": "neutral-transcript.json", "sha256": sha256(neutral_bytes), "byteCount": len(neutral_bytes), "rowCount": len(neutral_transcript), "contentDigest": neutral["contentDigest"]},
        "checkerSpecificEvidence": {"path": "checker-transcript.json", "sha256": sha256(checker_bytes), "byteCount": len(checker_bytes), "rowCount": len(checker_transcript), "contentDigest": checker["contentDigest"]},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", nargs="?", type=Path, default=PRIME_FIXTURE)
    parser.add_argument("--neutral-transcript-out", type=Path, default=None)
    parser.add_argument("--checker-transcript-out", type=Path, default=None)
    args = parser.parse_args()
    print(json.dumps(replay(args.fixture, args.neutral_transcript_out, args.checker_transcript_out), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
