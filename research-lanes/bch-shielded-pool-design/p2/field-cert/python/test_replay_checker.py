#!/usr/bin/env python3
"""Conformance tests for the standalone field-certificate replay checker."""

from __future__ import annotations

import copy
import pathlib
import sys
import unittest


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from replay_checker import CertificateError, verify_certificate  # noqa: E402


def tiny_non_evidence_fixture() -> dict:
    """q=3, p=7, f=X^2+1; deliberately not a frontier evidence artifact."""

    return {
        "base": {
            "q": "3",
            "p": "7",
            "exponentPrime": True,
            "lucasLehmer": {
                "passed": True,
                "sequence": ["4", "0"],
                "final": "0",
            },
        },
        "polynomial": {
            "degree": "2",
            "coefficients": ["1", "0", "1"],
            "rabin": {
                "h": [["0", "1"], ["0", "6"], ["0", "1"]],
                "gcd": [
                    {"r": "2", "g": ["0", "5"], "result": ["1"]},
                ],
                "bezout": [
                    {
                        "r": "2",
                        "u": ["1"],
                        "v": ["0", "4"],
                        "g": ["0", "5"],
                        "identity": ["1"],
                    },
                ],
            },
        },
    }


def shared_m89_envelope() -> dict:
    """A compact exact-shape M89 envelope for parser/mutation tests only."""

    p = (1 << 89) - 1
    half_plus_one = (p + 1) // 2
    prime_check = {
        "mersenneExponent": "89",
        "exponentPrime": True,
        "exponentPrimalityMethod": "deterministic-trial-division",
        "modulus": str(p),
        "lucasLehmer": {"iterations": "87", "residue": "0", "passed": True},
        "classification": "prime",
    }
    certificate = {
        "certificateId": "certificate:mersenne-q89-d2-rabin",
        "mersennePrimeCheck": prime_check,
        "modulus": str(p),
        "coefficientEncoding": "unsigned-decimal-c0-to-cd",
        "polynomial": ["1", "0", "1"],
        "degree": "2",
        "hPowers": [
            {"index": "0", "coefficients": ["0", "1"]},
            {"index": "1", "coefficients": ["0", str(p - 1)]},
            {"index": "2", "coefficients": ["0", "1"]},
        ],
        "primeDivisors": ["2"],
        "witnesses": [
            {
                "primeDivisor": "2",
                "hIndex": "1",
                "g": ["0", str(p - 2)],
                "gcd": ["1"],
                "bezoutU": ["1"],
                "bezoutV": ["0", str(half_plus_one)],
            },
        ],
        "finalResidue": ["0", "1"],
        "conclusion": "irreducible",
    }
    return {
        "schema": "shieldkit-labs/field-cert/v1",
        "fixtureId": "fixture:m89-x2-plus-1-rabin-v1",
        "kind": "rabin-irreducibility-fixture",
        "status": "generic-math-unqualified",
        "casReview": "not-cas-reviewed",
        "evidenceClassification": "not-evidence",
        "selection": "none",
        "notes": [
            "Analytical generic-math fixture only; it is not CAS-reviewed, implementation evidence, or a field-selection decision.",
            "The certificate records the exact Rabin residues, gcds, and Bezout witnesses for f = X^2 + 1 over M89.",
        ],
        "certificate": certificate,
    }


class ReplayCheckerTests(unittest.TestCase):
    def assert_rejects(self, mutation) -> None:
        fixture = copy.deepcopy(tiny_non_evidence_fixture())
        mutation(fixture)
        with self.assertRaises(CertificateError):
            verify_certificate(fixture)

    def test_inline_fixture_passes(self) -> None:
        summary = verify_certificate(tiny_non_evidence_fixture())
        self.assertEqual(summary["q"], 3)
        self.assertEqual(summary["p"], 7)
        self.assertEqual(summary["degree"], 2)
        self.assertEqual(summary["primeFactorsOfDegree"], [2])

    def test_wrong_mersenne_prime_rejects(self) -> None:
        self.assert_rejects(lambda cert: cert["base"].update(p="8"))

    def test_false_exponent_primality_claim_rejects(self) -> None:
        self.assert_rejects(lambda cert: cert["base"].update(exponentPrime=False))

    def test_lucas_lehmer_mutation_rejects(self) -> None:
        self.assert_rejects(lambda cert: cert["base"]["lucasLehmer"].update(final="1"))

    def test_polynomial_coefficient_mutation_rejects(self) -> None:
        self.assert_rejects(lambda cert: cert["polynomial"].update(coefficients=["1", "1", "1"]))

    def test_frobenius_residue_mutation_rejects(self) -> None:
        self.assert_rejects(lambda cert: cert["polynomial"]["rabin"]["h"][1].__setitem__(1, "5"))

    def test_gcd_witness_mutation_rejects(self) -> None:
        self.assert_rejects(lambda cert: cert["polynomial"]["rabin"]["gcd"][0].update(result=["0"]))

    def test_bezout_witness_mutation_rejects(self) -> None:
        self.assert_rejects(lambda cert: cert["polynomial"]["rabin"]["bezout"][0].update(v=["0", "3"]))

    def test_noncanonical_decimal_rejects(self) -> None:
        self.assert_rejects(lambda cert: cert["polynomial"]["coefficients"].__setitem__(0, "01"))

    def test_missing_certificate_component_rejects(self) -> None:
        self.assert_rejects(lambda cert: cert["polynomial"]["rabin"].pop("bezout"))

    def test_shared_envelope_fixture_passes(self) -> None:
        summary = verify_certificate(shared_m89_envelope())
        self.assertEqual(summary["q"], 89)
        self.assertEqual(summary["degree"], 2)

    def test_shared_envelope_value_mutation_rejects(self) -> None:
        fixture = shared_m89_envelope()
        fixture["status"] = "evidence"
        with self.assertRaises(CertificateError):
            verify_certificate(fixture)

    def test_shared_certificate_extra_key_rejects(self) -> None:
        fixture = shared_m89_envelope()
        fixture["certificate"]["unexpected"] = True
        with self.assertRaises(CertificateError):
            verify_certificate(fixture)

    def test_shared_coefficient_encoding_mutation_rejects(self) -> None:
        fixture = shared_m89_envelope()
        fixture["certificate"]["coefficientEncoding"] = "signed"
        with self.assertRaises(CertificateError):
            verify_certificate(fixture)

    def test_shared_noncanonical_index_rejects(self) -> None:
        fixture = shared_m89_envelope()
        fixture["certificate"]["hPowers"][1]["index"] = 1
        with self.assertRaises(CertificateError):
            verify_certificate(fixture)

    def test_shared_bezout_mutation_rejects(self) -> None:
        fixture = shared_m89_envelope()
        fixture["certificate"]["witnesses"][0]["bezoutV"][1] = str((int(fixture["certificate"]["witnesses"][0]["bezoutV"][1]) + 1) % ((1 << 89) - 1))
        with self.assertRaises(CertificateError):
            verify_certificate(fixture)


if __name__ == "__main__":
    unittest.main()
