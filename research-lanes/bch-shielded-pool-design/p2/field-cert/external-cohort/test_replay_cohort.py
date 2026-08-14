#!/usr/bin/env python3
"""Conformance tests for the deterministic SymPy cohort replay."""

import json
import unittest
from pathlib import Path

from replay_sympy_cohort_v1 import PRIME_FIXTURE, TARGETS, replay


class SymPyCohortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = replay(PRIME_FIXTURE)
        cls.by_target = {(row["basePrimeExponent"], row["degree"]): row for row in cls.result["targets"]}

    def test_exact_target_winners_and_complete_predecessor_record(self) -> None:
        expected = {
            (31, 5): ["1", "0", "1", "1", "1", "1"],
            (31, 6): ["1", "1", "0", "1", "0", "1", "1"],
            (61, 3): ["2", "0", "1", "1"],
        }
        for target in TARGETS:
            row = self.by_target[target]
            self.assertEqual(row["winner"]["coefficientsAscending"], expected[target])
            self.assertEqual(row["winner"]["directIrreducible"], True)
            self.assertEqual(row["winner"]["factorization"]["singleIrreducibleFactor"], True)
            self.assertEqual(row["testedCountThroughWinner"], len(row["testedPredecessors"]) + 1)
            self.assertTrue(all(not item["directIrreducible"] for item in row["testedPredecessors"]))

    def test_prime_proof_boundary_and_exact_moduli(self) -> None:
        expected = {31: "2147483647", 61: "2305843009213693951"}
        for q, _degree in TARGETS:
            prime = self.by_target[(q, _degree)]["prime"]
            self.assertEqual(prime["modulus"], expected[q])
            self.assertEqual(prime["fixtureClassification"], "prime")
            self.assertTrue(prime["fixtureLucasLehmer"]["passed"])
            self.assertTrue(prime["externalLucasLehmerReplay"]["passed"])
            self.assertTrue(prime["sympyIsPrime"]["value"])
            self.assertEqual(prime["sympyIsPrime"]["classification"], "probable-prime-only-for-this-size")

    def test_explicit_root_challenges_are_not_silently_substituted(self) -> None:
        expected = {
            (31, 5): ["-1", "2", "0", "0", "0", "1"],
            (31, 6): ["-5", "0", "0", "0", "0", "0", "1"],
            (61, 3): ["-5", "0", "0", "1"],
        }
        challenges = {(row["basePrimeExponent"], row["degree"]): row for row in self.result["explicitRootChallengeCandidates"]}
        for key, coefficients in expected.items():
            row = challenges[key]
            self.assertEqual(row["signedCoefficientsAscending"], coefficients)
            self.assertTrue(row["directIrreducible"])
            self.assertTrue(row["factorization"]["singleIrreducibleFactor"])
            self.assertFalse(row["primarySearchMembership"])
            self.assertEqual(row["rejectedPredecessorsUnderPrimarySearchOrder"], [])

    def test_raw_output_is_canonical_and_replayable(self) -> None:
        raw_path = Path(__file__).with_name("raw-output.json")
        self.assertEqual(json.loads(raw_path.read_text(encoding="utf-8")), self.result)

    def test_manifest_hashes_are_exact(self) -> None:
        manifest = json.loads(Path(__file__).with_name("MANIFEST.json").read_text(encoding="utf-8"))
        for artifact in manifest["artifacts"]:
            data = Path(__file__).with_name(artifact["path"]).read_bytes()
            self.assertEqual(__import__("hashlib").sha256(data).hexdigest(), artifact["sha256"])


if __name__ == "__main__":
    unittest.main()
