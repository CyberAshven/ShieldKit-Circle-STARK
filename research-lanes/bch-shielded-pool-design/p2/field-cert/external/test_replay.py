#!/usr/bin/env python3
"""Local conformance tests for the pinned SymPy replay."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from replay_sympy import DEFAULT_FIXTURE, replay


class SymPyReplayTests(unittest.TestCase):
    def test_fixture_matches_and_external_checks_pass(self) -> None:
        result = replay(DEFAULT_FIXTURE)
        self.assertEqual(result["fixtureId"], "fixture:m89-x2-plus-1-rabin-v1")
        checks = result["checks"]
        self.assertTrue(checks["fixtureModulusMatches2Pow89Minus1"])
        self.assertTrue(checks["fixturePolynomialMatchesX2Plus1"])
        self.assertTrue(checks["sympyIsPrime"]["value"])
        self.assertTrue(checks["sympyLucasLehmerPrimeProof"]["value"])
        self.assertEqual(
            checks["sympyLucasLehmerPrimeProof"]["classification"],
            "deterministic-source-pinned-private-api",
        )
        self.assertEqual(checks["sympyLucasLehmerPrimeProof"]["iterations"], 87)
        self.assertEqual(checks["legendreSymbolMinusOne"]["value"], -1)
        self.assertTrue(checks["legendreSymbolMinusOne"]["irreducibleQuadraticCriterion"])
        self.assertTrue(checks["sympyDirectIrreducibility"])
        self.assertTrue(checks["sympyFactorization"]["singleIrreducibleFactor"])

    def test_prime_proof_boundary_is_explicit(self) -> None:
        result = replay(DEFAULT_FIXTURE)
        prime = result["checks"]["sympyIsPrime"]
        external_proof = result["checks"]["sympyLucasLehmerPrimeProof"]
        proof = result["checks"]["fixtureLucasLehmerPrimeProof"]
        self.assertEqual(prime["classification"], "probable-prime-only-for-this-size")
        self.assertEqual(
            external_proof["classification"],
            "deterministic-source-pinned-private-api",
        )
        self.assertTrue(external_proof["value"])
        self.assertEqual(proof["method"], "deterministic-lucas-lehmer")
        self.assertTrue(proof["passed"])
        self.assertEqual(proof["residue"], 0)

    def test_raw_output_is_replayable_json(self) -> None:
        raw_path = Path(__file__).with_name("raw-output.json")
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        self.assertEqual(raw, replay(DEFAULT_FIXTURE))


if __name__ == "__main__":
    unittest.main()
