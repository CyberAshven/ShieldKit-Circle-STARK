#!/usr/bin/env python3
"""Adversarial tests for the independent direct-construction review."""

import copy
import hashlib
import json
import re
import unittest
from pathlib import Path

import review_direct_construction_v2 as review


HERE = Path(__file__).parent


class DirectConstructionReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = review.review()
        cls.certificate = review.parse_json_strict(review.CERT_PATH)
        cls.report_bytes = (HERE / "external-review.v2.json").read_bytes()
        cls.report = json.loads(cls.report_bytes)

    def test_all_four_exact_results_and_statement_digests(self) -> None:
        expected = [
            (0, 89, 2, "33f149255b6b627e4c80f88e65482d8230f5183dfc44350865d04e5ae4b25d23", review.EXPECTED_CERT_DIGESTS["certificate-entry:m89-d2-x2-plus-1-v1"]),
            (1, 61, 3, "7298c92aa085b773cdfdf827536af3d9ac47a284720c8555e7c414bf7b47c6b6", review.EXPECTED_CERT_DIGESTS["certificate-entry:m61-d3-x3-minus-5-v1"]),
            (2, 31, 5, "99e59b920e81254d733b0e445665d06bb6aeed3bc292a0007c7a26f89a97c277", review.EXPECTED_CERT_DIGESTS["certificate-entry:m31-d5-x5-plus-2x-minus-1-v1"]),
            (3, 31, 6, "e87e021b53983eec0a22b7c83dcb349c9662287d90df825f940cda843815fff2", review.EXPECTED_CERT_DIGESTS["certificate-entry:m31-d6-x6-minus-5-v1"]),
        ]
        self.assertEqual(self.result, self.report)
        self.assertEqual((self.report["status"], self.report["finalVerdict"]), ("all-independent-replays-passed", "PASS"))
        for entry, expected_row in zip(self.report["entries"], expected, strict=True):
            index, q, degree, statement_digest, certificate_digest = expected_row
            self.assertEqual((entry["scheduleIndex"], entry["q"], entry["degree"], entry["statementDigest"], entry["recomputedCertificateDigest"]), (index, q, degree, statement_digest, certificate_digest))
            self.assertEqual(entry["repositoryCertificateDigest"], certificate_digest)
            self.assertEqual(entry["verdict"], "PASS")
            self.assertEqual(entry["statementDigest"], hashlib.sha256(review.canonical(entry["statement"])).hexdigest())

    def test_two_independent_checker_families_and_input_bindings(self) -> None:
        self.assertEqual(self.report["tool"]["checkerFamilies"], ["python-stdlib-certificate-replay", "sympy-cas-irreducibility"])
        self.assertEqual(self.report["boundary"], review.BOUNDARY)
        expected = {
            review.CERT_PATH.name: review.EXPECTED_INPUTS[review.CERT_PATH],
            review.SCHEMA_PATH.name: review.EXPECTED_INPUTS[review.SCHEMA_PATH],
            review.REPLAY_REPORT_PATH.name: review.EXPECTED_INPUTS[review.REPLAY_REPORT_PATH],
        }
        for binding in self.report["inputBindings"]:
            self.assertEqual(binding["sha256"], expected[Path(binding["path"]).name])
            self.assertEqual(binding["byteCount"], len((review.ROOT / binding["path"]).read_bytes()))
        self.assertEqual(self.report["repositoryReport"]["sha256"], review.EXPECTED_INPUTS[review.REPLAY_REPORT_PATH])

    def test_canonical_output_and_manifest_bindings(self) -> None:
        self.assertTrue(self.report_bytes.endswith(b"\n"))
        self.assertNotIn(b"\r", self.report_bytes)
        self.assertEqual(self.report_bytes.decode(), json.dumps(self.report, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        schema = json.loads((HERE / "external-review.v2.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["$id"], "https://shieldkit-labs.local/p2/field-cert/external-direct-construction-cohort-v2/external-review.v2.schema.json")
        raw_bytes = (HERE / "raw-output.json").read_bytes()
        self.assertEqual(raw_bytes, self.report_bytes)
        for filename in ("external-review.v2.schema.json", "raw-output.json"):
            content = (HERE / filename).read_bytes()
            self.assertTrue(content.endswith(b"\n"))
            self.assertNotIn(b"\r", content)
        sums = {}
        for line in (HERE / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            digest, path = line.split("  ", 1)
            sums[path] = digest
        manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(set(sums), {item["path"] for item in manifest["artifacts"]})
        for item in manifest["artifacts"]:
            actual = hashlib.sha256((HERE / item["path"]).read_bytes()).hexdigest()
            self.assertEqual(actual, item["sha256"])
            self.assertEqual(actual, sums[item["path"]])

    def test_adversarial_certificate_mutations_fail_closed(self) -> None:
        mutations = []
        mutated = copy.deepcopy(self.certificate); mutated["scheduleOrder"][0]["q"] = 90; mutations.append(mutated)
        mutated = copy.deepcopy(self.certificate); mutated["certificates"][0]["polynomialCanonical"][0] = "2"; mutations.append(mutated)
        mutated = copy.deepcopy(self.certificate); mutated["certificates"][0]["certificate"]["hPowers"][1]["coefficients"][1] = "0"; mutations.append(mutated)
        mutated = copy.deepcopy(self.certificate); mutated["certificates"][0]["certificate"]["witnesses"][0]["gcd"] = ["0"]; mutations.append(mutated)
        mutated = copy.deepcopy(self.certificate); mutated["certificates"][0]["certificate"]["witnesses"][0]["bezoutU"][0] = "0"; mutations.append(mutated)
        mutated = copy.deepcopy(self.certificate); mutated["certificates"][0]["certificate"]["finalResidue"] = ["1", "1"]; mutations.append(mutated)
        mutated = copy.deepcopy(self.certificate); mutated["certificates"][0]["certificateDigest"] = "0" * 64; mutations.append(mutated)
        for candidate in mutations:
            with self.assertRaises(review.ReviewFailure):
                review.validate_and_replay(candidate)

    def test_adversarial_report_mutations_and_input_hash_fail(self) -> None:
        bad = copy.deepcopy(self.report); bad["entries"][0]["statementDigest"] = "0" * 64
        self.assertNotEqual(bad["entries"][0]["statementDigest"], hashlib.sha256(review.canonical(bad["entries"][0]["statement"])).hexdigest())
        with self.assertRaises(review.ReviewFailure):
            review.validate_report(bad)
        for field, value in (("tool", {"checkerFamilies": ["python-stdlib-certificate-replay"]}), ("boundary", {"permittedConclusion": "selection", "prohibitedConclusion": ""}), ("finalVerdict", "FAIL"), ("status", "review-failed"), ("contentDigest", "0" * 64)):
            candidate = copy.deepcopy(self.report); candidate[field] = value
            self.assertNotEqual(candidate, self.report)
            with self.assertRaises(review.ReviewFailure):
                review.validate_report(candidate)
        source = (HERE / "review_direct_construction_v2.py").read_text(encoding="utf-8").lower()
        self.assertNotRegex(source, r"\b(node|subprocess|child_process|spawn|execfile)\b")
        bad_certificate = copy.deepcopy(self.certificate)
        bad_certificate["inputBindings"][0]["fileSha256"] = "0" * 64
        with self.assertRaises(review.ReviewFailure):
            review.check_input_bindings(bad_certificate)


if __name__ == "__main__":
    unittest.main()
