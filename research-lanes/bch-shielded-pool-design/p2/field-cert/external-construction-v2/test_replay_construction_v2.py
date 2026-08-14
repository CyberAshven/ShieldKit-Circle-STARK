#!/usr/bin/env python3
"""Independent v2 replay, serialization, and binding tests."""

import hashlib
import json
import re
import unittest
from pathlib import Path

from replay_construction_v2 import PRIME_FIXTURE, TARGETS, replay


HERE = Path(__file__).parent
FREEZE = HERE.parents[1] / "construction-freeze" / "construction-freeze.normalized-transcript.v1.json"
NEUTRAL = HERE / "neutral-transcript.json"
CHECKER = HERE / "checker-transcript.json"
EXPECTED_NEUTRAL_SHA = "58edd442a8700d9d2014f8d238ea6d7116e64baa427b3c89c33bc9d4878c20fe"
EXPECTED_CONTENT_DIGEST = "8eb2039920ae163c3584ca7a4b55ab5804f836760420b9cda185c4487ecf0dea"


def digest_without_content_digest(value: dict) -> str:
    body = {key: item for key, item in value.items() if key != "contentDigest"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ConstructionV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = replay(PRIME_FIXTURE)
        cls.targets = {(row["basePrimeExponent"], row["degree"]): row for row in cls.result["targets"]}
        cls.neutral_bytes = NEUTRAL.read_bytes()
        cls.neutral = json.loads(cls.neutral_bytes)
        cls.checker = json.loads(CHECKER.read_bytes())

    def test_expected_counts_winners_and_flat_scores(self) -> None:
        expected = {
            (31, 5): (4128, 752, [-1, 2, 0, 0, 0], [4, 8, 12, 2, 2, 2, 3, 4, 1, 4, 0, 0, 0]),
            (31, 6): (5152, 831, [-5, 0, 0, 0, 0, 0], [5, 5, 15, 3, 1, 5, 2, 6, 9, 0, 0, 0, 0, 0]),
            (61, 3): (2080, 650, [-5, 0, 0], [2, 2, 6, 3, 1, 5, 2, 6, 9, 0, 0]),
        }
        for target in TARGETS:
            row = self.targets[target]
            tested, irreducible, coefficients, score = expected[target]
            self.assertEqual((row["testedCount"], row["irreducibleCount"]), (tested, irreducible))
            self.assertEqual(row["winner"]["coefficientsSignedAscending"], coefficients)
            self.assertEqual(row["winner"]["score"], score)
            self.assertTrue(row["winner"]["directIrreducible"])

    def test_neutral_exact_frozen_bytes_and_digest(self) -> None:
        self.assertEqual(len(self.neutral["rows"]), 11360)
        self.assertEqual(self.neutral["rowCount"], 11360)
        self.assertEqual(len(self.neutral_bytes), 8260251)
        self.assertEqual(hashlib.sha256(self.neutral_bytes).hexdigest(), EXPECTED_NEUTRAL_SHA)
        self.assertEqual(self.neutral_bytes, FREEZE.read_bytes())
        self.assertEqual(self.neutral["contentDigest"], EXPECTED_CONTENT_DIGEST)
        self.assertEqual(digest_without_content_digest(self.neutral), EXPECTED_CONTENT_DIGEST)
        self.assertTrue(self.neutral_bytes.endswith(b"\n"))
        self.assertNotIn(b"\r", self.neutral_bytes)
        self.assertEqual(self.neutral_bytes[-2:-1], b"}")
        self.assertEqual(json.dumps(self.neutral, separators=(",", ":")) + "\n", self.neutral_bytes.decode())

    def test_order_score_and_recurrence_shape(self) -> None:
        first = self.neutral["rows"][0]
        self.assertEqual(first["tCentered"], [-1, 0, 0, 0, 0])
        self.assertEqual(first["support"], 1)
        self.assertEqual(self.neutral["rows"][32]["tCentered"], [-1, -1, 0, 0, 0])
        self.assertEqual(first["reductionExponents"], [5, 6, 7, 8])
        self.assertEqual(first["reductionRows"][0], ["1", "0", "0", "0", "0"])
        self.assertEqual(first["score"]["lexicographicTuple"], [0, 4, 4, 1, 1, 1, 2, 2, 1, 0, 0, 0, 0])
        self.assertEqual(first["score"]["signedLexRanks"], [1, 0, 0, 0, 0])

    def test_every_shared_classification_binds_checker_evidence(self) -> None:
        self.assertEqual(self.neutral["rowCount"], self.checker["rowCount"])
        for index, (shared, checked) in enumerate(zip(self.neutral["rows"], self.checker["rows"], strict=True)):
            self.assertEqual(shared["targetOrderIndex"], TARGETS.index((checked["basePrimeExponent"], checked["degree"])))
            self.assertEqual(shared["candidateIndex"], checked["ordinal"])
            self.assertEqual(shared["globalOrderIndex"], index)
            self.assertEqual(shared["irreducible"], checked["directIrreducible"])

    def test_checker_binding_and_raw_replay(self) -> None:
        raw = json.loads((HERE / "raw-output.json").read_text(encoding="utf-8"))
        self.assertEqual(raw, self.result)
        binding = raw["checkerSpecificEvidence"]
        checker_bytes = CHECKER.read_bytes()
        self.assertEqual(binding["sha256"], hashlib.sha256(checker_bytes).hexdigest())
        self.assertEqual(binding["byteCount"], len(checker_bytes))
        self.assertEqual(binding["rowCount"], 11360)
        self.assertEqual(binding["contentDigest"], self.checker["contentDigest"])
        self.assertEqual(digest_without_content_digest(self.checker), self.checker["contentDigest"])
        self.assertTrue(checker_bytes.endswith(b"\n"))
        self.assertNotIn(b"\r", checker_bytes)
        self.assertEqual(json.dumps(self.checker, separators=(",", ":")) + "\n", checker_bytes.decode())

    def test_mutation_negative_and_no_node_bridge(self) -> None:
        mutated = json.loads(self.neutral_bytes)
        mutated["rows"][0]["irreducible"] = not mutated["rows"][0]["irreducible"]
        mutated_bytes = (json.dumps(mutated, separators=(",", ":")) + "\n").encode()
        self.assertNotEqual(hashlib.sha256(mutated_bytes).hexdigest(), EXPECTED_NEUTRAL_SHA)
        source = (HERE / "replay_construction_v2.py").read_text(encoding="utf-8").lower()
        self.assertIsNone(re.search(r"\b(node|subprocess|child_process|spawn|execfile)\b", source))

    def test_manifest_and_sha256sums(self) -> None:
        manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
        sums = (HERE / "SHA256SUMS").read_text(encoding="utf-8")
        parsed_sums = {}
        for line in sums.splitlines():
            digest, path = line.split("  ", 1)
            parsed_sums[path] = digest
        self.assertEqual(set(parsed_sums), {artifact["path"] for artifact in manifest["artifacts"]})
        for artifact in manifest["artifacts"]:
            path = HERE / artifact["path"]
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(actual, artifact["sha256"])
            self.assertEqual(parsed_sums[artifact["path"]], actual)


if __name__ == "__main__":
    unittest.main()
