#!/usr/bin/env python3
"""Independent direct-construction certificate replay.

Only Python's standard library and SymPy's public polynomial API are used.
The repository JavaScript replay is an input binding, never an implementation
dependency or process bridge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
from pathlib import Path

from sympy import Poly, symbols
import sympy


ROOT = Path(__file__).resolve().parents[5]
INPUT_DIR = ROOT / "research-lanes/bch-shielded-pool-design/p2/field-cert/direct-construction-cohort-v2"
CERT_PATH = INPUT_DIR / "direct-construction-cohort-v2.v2.json"
SCHEMA_PATH = INPUT_DIR / "direct-construction-cohort-v2.v2.schema.json"
REPLAY_REPORT_PATH = INPUT_DIR / "repository-replay-report.v2.txt"
EXPECTED_INPUTS = {
    CERT_PATH: "f01cf39df0ee4d9b44e8ad5fda9c5d0c44648ee0a74d27ef5967506fd70827da",
    SCHEMA_PATH: "fb25c73f17c9aec50060daf9b73ec09b5219460013ac0c9539a215a567ba69db",
    REPLAY_REPORT_PATH: "7529af8adacb43ed38252f57fb0a807f5b235086325f45637e93dd054fc5c1f3",
}
EXPECTED_CERT_DIGESTS = {
    "certificate-entry:m89-d2-x2-plus-1-v1": "10969251c66cbabff787da8045bf0efa4a78673f21f117f3b075e02d763d72d1",
    "certificate-entry:m61-d3-x3-minus-5-v1": "a8b34cef2828c3de1a88e7a3b0f59c38e993a36b38bbc628d33a621331e5e62b",
    "certificate-entry:m31-d5-x5-plus-2x-minus-1-v1": "464ed194826e19d4bd3691935d096745decb7e1d9795d8f981915dd6f42e6e54",
    "certificate-entry:m31-d6-x6-minus-5-v1": "6ffdde71174f443005dbbc99693182dc13ffbdfc62da674dd5deb2a95accbb25",
}
EXPECTED_CERT_ARTIFACT_DIGEST = "907dde98933678a81d1623660f9eff0d2f3ddfcfdd417a395048c5531fd82943"
LOCAL_ARTIFACTS = ("review_direct_construction_v2.py", "requirements.lock", "COMMAND.txt", "environment.json")
BOUNDARY = {
    "permittedConclusion": "certificate-evidence-for-exact-prime-and-direct-polynomial-irreducibility-only",
    "prohibitedConclusion": "no-BCH-cost-field-family-proof-system-protocol-Circle-domain-systemic-soundness-tuple-or-selection-conclusion",
}
TARGETS = ((89, 2), (61, 3), (31, 5), (31, 6))


class ReviewFailure(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_json_strict(path: Path) -> object:
    def hook(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ReviewFailure(f"duplicate JSON key at {path}: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=hook)


def expect_keys(value: object, keys: list[str], where: str) -> None:
    if not isinstance(value, dict) or list(value) != keys:
        raise ReviewFailure(f"key/order mismatch at {where}")


def unsigned(value: object, where: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        raise ReviewFailure(f"non-canonical unsigned decimal at {where}")
    return int(value)


def identifier(value: object, where: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*){1,8}$", value):
        raise ReviewFailure(f"invalid identifier at {where}")
    return value


def mod_poly(values: list[int], p: int) -> list[int]:
    values = [value % p for value in values]
    while len(values) > 1 and values[-1] == 0:
        values.pop()
    return values or [0]


def poly_add(a: list[int], b: list[int], p: int) -> list[int]:
    return mod_poly([(a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0) for i in range(max(len(a), len(b)))], p)


def poly_sub(a: list[int], b: list[int], p: int) -> list[int]:
    return mod_poly([(a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0) for i in range(max(len(a), len(b)))], p)


def poly_mul(a: list[int], b: list[int], p: int) -> list[int]:
    result = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        for j, bv in enumerate(b):
            result[i + j] += av * bv
    return mod_poly(result, p)


def poly_divmod(a: list[int], b: list[int], p: int) -> tuple[list[int], list[int]]:
    dividend = mod_poly(a, p)
    divisor = mod_poly(b, p)
    if divisor == [0]:
        raise ReviewFailure("polynomial division by zero")
    quotient = [0] * max(1, len(dividend) - len(divisor) + 1)
    inverse = pow(divisor[-1], p - 2, p)
    while dividend != [0] and len(dividend) >= len(divisor):
        shift = len(dividend) - len(divisor)
        factor = dividend[-1] * inverse % p
        quotient[shift] = factor
        for index, coefficient in enumerate(divisor):
            dividend[shift + index] = (dividend[shift + index] - factor * coefficient) % p
        dividend = mod_poly(dividend, p)
    return mod_poly(quotient, p), dividend


def poly_gcd(a: list[int], b: list[int], p: int) -> list[int]:
    while b != [0]:
        _, remainder = poly_divmod(a, b, p)
        a, b = b, remainder
    inverse = pow(a[-1], p - 2, p)
    return mod_poly([coefficient * inverse for coefficient in a], p)


def poly_extended_gcd(a: list[int], b: list[int], p: int) -> tuple[list[int], list[int], list[int]]:
    old_r, r = a, b
    old_s, s = [1], [0]
    old_t, t = [0], [1]
    while r != [0]:
        quotient, remainder = poly_divmod(old_r, r, p)
        old_r, r = r, remainder
        old_s, s = s, poly_sub(old_s, poly_mul(quotient, s, p), p)
        old_t, t = t, poly_sub(old_t, poly_mul(quotient, t, p), p)
    scale = pow(old_r[-1], p - 2, p)
    return (
        mod_poly([coefficient * scale for coefficient in old_r], p),
        mod_poly([coefficient * scale for coefficient in old_s], p),
        mod_poly([coefficient * scale for coefficient in old_t], p),
    )


def poly_pow_mod(base: list[int], exponent: int, modulus: list[int], p: int) -> list[int]:
    result = [1]
    base = poly_divmod(base, modulus, p)[1]
    while exponent:
        if exponent & 1:
            result = poly_divmod(poly_mul(result, base, p), modulus, p)[1]
        base = poly_divmod(poly_mul(base, base, p), modulus, p)[1]
        exponent >>= 1
    return result


def is_prime_trial(n: int) -> bool:
    if n < 2:
        return False
    divisor = 2
    while divisor * divisor <= n:
        if n % divisor == 0:
            return n == divisor
        divisor = 3 if divisor == 2 else divisor + 2
    return True


def lucas_lehmer(q: int, p: int) -> tuple[int, int]:
    value = 4
    for _ in range(q - 2):
        value = (value * value - 2) % p
    return q - 2, value


def prime_divisors(n: int) -> list[int]:
    result = []
    divisor = 2
    while divisor * divisor <= n:
        if n % divisor == 0:
            result.append(divisor)
            while n % divisor == 0:
                n //= divisor
        divisor = 3 if divisor == 2 else divisor + 2
    if n > 1:
        result.append(n)
    return result


def decimal_coefficients(values: list[int]) -> list[str]:
    return [str(value) for value in values]


def check_input_bindings(data: dict) -> dict[str, dict[str, object]]:
    if len(data["inputBindings"]) != 3:
        raise ReviewFailure("repository input binding count mismatch")
    for index, item in enumerate(data["inputBindings"]):
        expect_keys(item, ["path", "schema", "schemaPath", "schemaSha256", "fileSha256", "contentDigest", "byteCount", "schemaByteCount"], f"inputBindings[{index}]")
        path = ROOT / item["path"]
        if not path.is_file() or sha256(path.read_bytes()) != item["fileSha256"] or len(path.read_bytes()) != item["byteCount"]:
            raise ReviewFailure(f"repository input binding mismatch {path}")
    result = {}
    for path, expected_sha in EXPECTED_INPUTS.items():
        actual = path.read_bytes()
        if sha256(actual) != expected_sha:
            raise ReviewFailure(f"input digest mismatch {path}")
        result[path.name] = {"path": path.relative_to(ROOT).as_posix(), "sha256": expected_sha, "byteCount": len(actual), "contentDigest": EXPECTED_CERT_ARTIFACT_DIGEST if path == CERT_PATH else None}
    report = REPLAY_REPORT_PATH.read_bytes()
    if data["replayReportBinding"] != {"path": "repository-replay-report.v2.txt", "byteCount": len(report), "sha256": EXPECTED_INPUTS[REPLAY_REPORT_PATH]}:
        raise ReviewFailure("replay report binding mismatch")
    return result


def validate_envelope(data: dict) -> None:
    expect_keys(data, ["schema", "artifactId", "status", "evidenceClassification", "selection", "tupleRef", "protocolBoundary", "boundary", "inputBindings", "scheduleOrder", "importedSourceBindings", "repositoryEnvironment", "toolBinding", "replayReportBinding", "certificates", "contentDigest"], "envelope")
    if data["schema"] != "shieldkit-labs/p2/direct-construction-cohort-v2/v2" or data["artifactId"] != "direct-construction-cohort-v2" or data["status"] != "generic-math-certificate-set-frozen" or data["evidenceClassification"] != "not-evidence" or data["selection"] != "none" or data["tupleRef"] is not None or data["protocolBoundary"] != "component-only" or data["boundary"] != {"permittedConclusion": "base-prime-and-direct-polynomial-irreducibility-only-if-replay-passes", "prohibitedConclusion": "no-BCH-cost-field-family-proof-system-protocol-Circle-domain-or-systemic-soundness-conclusion"}:
        raise ReviewFailure("envelope semantic mismatch")
    if not re.fullmatch(r"[0-9a-f]{64}", data["contentDigest"]):
        raise ReviewFailure("invalid envelope digest")
    body = {key: value for key, value in data.items() if key != "contentDigest"}
    if sha256(canonical(body)) != data["contentDigest"]:
        raise ReviewFailure("envelope content digest mismatch")
    expect_keys(data["replayReportBinding"], ["path", "byteCount", "sha256"], "replayReportBinding")
    if data["repositoryEnvironment"] != {"nodeVersion": "v22.23.1", "platform": "linux", "arch": "x64", "policy": "certificate bytes are frozen for this recorded environment; a runtime mismatch is diagnostic and fail-closed for promotion, never silently incorporated into canonical bytes"}:
        raise ReviewFailure("repository environment mismatch")


def validate_and_replay(data: dict) -> list[dict[str, object]]:
    expected_schedule = []
    for index, entry in enumerate(data["scheduleOrder"]):
        expect_keys(entry, ["constructionId", "certificateEntryId", "fieldSpecRef", "q", "degree", "polynomialCanonical"], f"scheduleOrder[{index}]")
        identifier(entry["constructionId"], f"scheduleOrder[{index}].constructionId")
        identifier(entry["certificateEntryId"], f"scheduleOrder[{index}].certificateEntryId")
        identifier(entry["fieldSpecRef"], f"scheduleOrder[{index}].fieldSpecRef")
        q, degree = entry["q"], entry["degree"]
        if not isinstance(q, int) or not isinstance(degree, int) or (q, degree) != TARGETS[index]:
            raise ReviewFailure("schedule order mismatch")
        p = 2**q - 1
        poly = [unsigned(value, f"scheduleOrder[{index}].polynomialCanonical") for value in entry["polynomialCanonical"]]
        if len(poly) != degree + 1 or poly[-1] != 1 or any(value >= p for value in poly):
            raise ReviewFailure("schedule polynomial range/monicity mismatch")
        expected_schedule.append((entry, q, degree, p, poly))
    if len(data["certificates"]) != 4:
        raise ReviewFailure("certificate count mismatch")
    results = []
    for index, (entry, q, degree, p, poly) in enumerate(expected_schedule):
        cert_entry = data["certificates"][index]
        expect_keys(cert_entry, ["certificateEntryId", "constructionId", "fieldSpecRef", "q", "degree", "p", "polynomialCanonical", "certificateId", "certificateDigest", "replayPassed", "establishes", "certificate"], f"certificates[{index}]")
        if cert_entry["certificateEntryId"] != entry["certificateEntryId"] or cert_entry["constructionId"] != entry["constructionId"] or cert_entry["fieldSpecRef"] != entry["fieldSpecRef"] or cert_entry["q"] != q or cert_entry["degree"] != degree or cert_entry["p"] != str(p) or cert_entry["polynomialCanonical"] != [str(value) for value in poly] or cert_entry["replayPassed"] is not True or cert_entry["establishes"] != "base-prime-and-direct-polynomial-irreducibility-only-if-replay-passes":
            raise ReviewFailure(f"certificate entry binding mismatch {index}")
        cert = cert_entry["certificate"]
        expect_keys(cert, ["certificateId", "mersennePrimeCheck", "modulus", "coefficientEncoding", "polynomial", "degree", "hPowers", "primeDivisors", "witnesses", "finalResidue", "conclusion"], f"certificate[{index}]")
        if cert["certificateId"] != cert_entry["certificateId"] or cert["modulus"] != str(p) or cert["coefficientEncoding"] != "unsigned-decimal-c0-to-cd" or cert["polynomial"] != [str(value) for value in poly] or cert["degree"] != str(degree) or cert["conclusion"] != "irreducible":
            raise ReviewFailure(f"nested certificate binding mismatch {index}")
        prime_check = cert["mersennePrimeCheck"]
        expect_keys(prime_check, ["mersenneExponent", "exponentPrime", "exponentPrimalityMethod", "modulus", "lucasLehmer", "classification"], f"primeCheck[{index}]")
        if prime_check["mersenneExponent"] != str(q) or prime_check["exponentPrime"] is not True or prime_check["exponentPrimalityMethod"] != "deterministic-trial-division" or prime_check["modulus"] != str(p) or prime_check["classification"] != "prime" or not is_prime_trial(q):
            raise ReviewFailure(f"exponent primality mismatch {index}")
        ll = prime_check["lucasLehmer"]
        expect_keys(ll, ["iterations", "residue", "passed"], f"lucasLehmer[{index}]")
        iterations, residue = lucas_lehmer(q, p)
        if ll != {"iterations": str(iterations), "residue": str(residue), "passed": residue == 0} or residue != 0:
            raise ReviewFailure(f"Lucas-Lehmer mismatch {index}")
        h_values = [[unsigned(v, f"h[{index}]") for v in item["coefficients"]] for item in cert["hPowers"]]
        if len(cert["hPowers"]) != degree + 1 or [item["index"] for item in cert["hPowers"]] != [str(i) for i in range(degree + 1)]:
            raise ReviewFailure(f"h-power inventory mismatch {index}")
        f = [value % p for value in poly]
        computed_h = [[0, 1]]
        for _ in range(degree):
            computed_h.append(poly_pow_mod(computed_h[-1], p, f, p))
        if h_values != computed_h:
            raise ReviewFailure(f"Frobenius replay mismatch {index}")
        divisors = prime_divisors(degree)
        if [unsigned(v, f"primeDivisors[{index}]") for v in cert["primeDivisors"]] != divisors:
            raise ReviewFailure(f"prime divisor inventory mismatch {index}")
        if len(cert["witnesses"]) != len(divisors):
            raise ReviewFailure(f"witness count mismatch {index}")
        witness_results = []
        for wi, divisor in enumerate(divisors):
            witness = cert["witnesses"][wi]
            expect_keys(witness, ["primeDivisor", "hIndex", "g", "gcd", "bezoutU", "bezoutV"], f"witness[{index},{wi}]")
            h_index = degree // divisor
            g = poly_sub(computed_h[h_index], [0, 1], p)
            gcd, bezout_u, bezout_v = poly_extended_gcd(f, g, p)
            observed = {"primeDivisor": str(divisor), "hIndex": str(h_index), "g": decimal_coefficients(g), "gcd": decimal_coefficients(gcd), "bezoutU": decimal_coefficients(bezout_u), "bezoutV": decimal_coefficients(bezout_v)}
            if witness != observed or gcd != [1] or poly_add(poly_mul(bezout_u, f, p), poly_mul(bezout_v, g, p), p) != [1]:
                raise ReviewFailure(f"gcd/Bezout mismatch {index},{wi}")
            witness_results.append(observed)
        final = [unsigned(v, f"final[{index}]") for v in cert["finalResidue"]]
        if final != computed_h[degree] or final != [0, 1]:
            raise ReviewFailure(f"final Frobenius residue mismatch {index}")
        x = symbols("x")
        expression = sum(poly[i] * x**i for i in range(degree + 1))
        sympy_poly = Poly(expression, x, modulus=p)
        factors = sympy_poly.factor_list()
        factor_observation = {"constant": str(int(factors[0]) % p), "factors": [{"coefficientsAscendingModuloP": [str(int(factor.nth(i)) % p) for i in range(factor.degree() + 1)], "degree": factor.degree(), "multiplicity": multiplicity} for factor, multiplicity in factors[1]]}
        if not bool(sympy_poly.is_irreducible) or factor_observation["constant"] != "1" or factor_observation["factors"] != [{"coefficientsAscendingModuloP": [str(value) for value in poly], "degree": degree, "multiplicity": 1}]:
            raise ReviewFailure(f"SymPy irreducibility/factorization mismatch {index}")
        statement = {"certificateEntryId": cert_entry["certificateEntryId"], "constructionId": cert_entry["constructionId"], "fieldSpecRef": cert_entry["fieldSpecRef"], "q": q, "p": str(p), "degree": degree, "polynomialCanonical": [str(value) for value in poly]}
        statement_digest = sha256(canonical(statement))
        cert_digest = sha256(canonical(cert))
        if cert_digest != cert_entry["certificateDigest"] or cert_digest != EXPECTED_CERT_DIGESTS[cert_entry["certificateEntryId"]]:
            raise ReviewFailure(f"certificate digest mismatch {index}")
        results.append({"scheduleIndex": index, "certificateEntryId": cert_entry["certificateEntryId"], "constructionId": cert_entry["constructionId"], "fieldSpecRef": cert_entry["fieldSpecRef"], "q": q, "p": str(p), "degree": degree, "polynomialCanonical": [str(value) for value in poly], "repositoryCertificateDigest": cert_entry["certificateDigest"], "recomputedCertificateDigest": cert_digest, "statement": statement, "statementDigest": statement_digest, "prime": {"qPrime": True, "modulus": str(p), "lucasLehmerIterations": iterations, "lucasLehmerResidue": residue}, "rabin": {"hPowers": [{"index": i, "coefficients": decimal_coefficients(values)} for i, values in enumerate(computed_h)], "primeDivisors": [str(v) for v in divisors], "witnesses": witness_results, "finalResidue": decimal_coefficients(final)}, "sympy": {"isIrreducible": True, "factorization": factor_observation}, "checkerVerdicts": {"python-stdlib-certificate-replay": "PASS", "sympy-cas-irreducibility": "PASS"}, "verdict": "PASS"})
    return results


def review(cert_path: Path = CERT_PATH, schema_path: Path = SCHEMA_PATH, report_path: Path = REPLAY_REPORT_PATH) -> dict:
    if cert_path != CERT_PATH or schema_path != SCHEMA_PATH or report_path != REPLAY_REPORT_PATH:
        raise ReviewFailure("review inputs must be the pinned direct-construction cohort files")
    data = parse_json_strict(cert_path)
    if not isinstance(data, dict):
        raise ReviewFailure("certificate envelope is not an object")
    validate_envelope(data)
    input_bindings = check_input_bindings(data)
    report_text = report_path.read_text(encoding="utf-8")
    if "certificateCount=4" not in report_text or "status=all-repository-replays-passed" not in report_text:
        raise ReviewFailure("repository report status/count mismatch")
    results = validate_and_replay(data)
    local_bindings = []
    for filename in LOCAL_ARTIFACTS:
        path = Path(__file__).with_name(filename)
        local_bindings.append({"path": f"research-lanes/bch-shielded-pool-design/p2/field-cert/external-direct-construction-cohort-v2/{filename}", "sha256": sha256(path.read_bytes()), "byteCount": len(path.read_bytes())})
    all_pass = all(r["verdict"] == "PASS" and all(value == "PASS" for value in r["checkerVerdicts"].values()) for r in results)
    output = {"schema": "shieldkit-labs/p2/field-cert/external-direct-construction-cohort-v2/external-review/v2", "reviewId": "external-direct-construction-cohort-v2", "status": "all-independent-replays-passed" if all_pass else "review-failed", "evidenceClassification": "certificate-evidence-only", "selection": "none", "tupleRef": None, "boundary": BOUNDARY, "tool": {"python": sys.version, "platform": platform.platform(), "sympy": sympy.__version__, "checkerFamilies": ["python-stdlib-certificate-replay", "sympy-cas-irreducibility"]}, "inputBindings": list(input_bindings.values()), "repositoryReport": {"path": report_path.relative_to(ROOT).as_posix(), "sha256": EXPECTED_INPUTS[REPLAY_REPORT_PATH], "byteCount": len(report_path.read_bytes())}, "sourceBindings": local_bindings, "entries": results, "finalVerdict": "PASS" if all_pass else "FAIL"}
    output["contentDigest"] = sha256(canonical(output))
    return output


def validate_report(output: dict) -> None:
    expected_keys = ["boundary", "contentDigest", "entries", "evidenceClassification", "finalVerdict", "inputBindings", "repositoryReport", "reviewId", "schema", "selection", "sourceBindings", "status", "tool", "tupleRef"]
    expect_keys(output, expected_keys, "external-review")
    if output["schema"] != "shieldkit-labs/p2/field-cert/external-direct-construction-cohort-v2/external-review/v2" or output["reviewId"] != "external-direct-construction-cohort-v2" or output["evidenceClassification"] != "certificate-evidence-only" or output["selection"] != "none" or output["tupleRef"] is not None or output["boundary"] != BOUNDARY or output["status"] != "all-independent-replays-passed" or output["finalVerdict"] != "PASS":
        raise ReviewFailure("external review envelope mismatch")
    if sha256(canonical({key: value for key, value in output.items() if key != "contentDigest"})) != output["contentDigest"]:
        raise ReviewFailure("external review content digest mismatch")
    if output["tool"]["checkerFamilies"] != ["python-stdlib-certificate-replay", "sympy-cas-irreducibility"]:
        raise ReviewFailure("checker family binding mismatch")
    if len(output["entries"]) != 4 or any(entry["verdict"] != "PASS" or entry["checkerVerdicts"] != {"python-stdlib-certificate-replay": "PASS", "sympy-cas-irreducibility": "PASS"} for entry in output["entries"]):
        raise ReviewFailure("per-checker verdict mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--raw-output", type=Path)
    args = parser.parse_args()
    try:
        output = review()
    except (ReviewFailure, KeyError, TypeError, ValueError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    data = canonical(output) + b"\n"
    validate_report(json.loads(data.decode("utf-8")))
    if args.output:
        args.output.write_bytes(data)
    if args.raw_output:
        args.raw_output.write_bytes(data)
    sys.stdout.buffer.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
