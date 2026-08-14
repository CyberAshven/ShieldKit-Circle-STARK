#!/usr/bin/env python3
"""Independent stdlib-only replay checker for field certificates.

This module deliberately has no dependency on the JavaScript reference or on a
CAS.  It replays the base Mersenne primality claims and a direct Rabin
irreducibility certificate over ``F_p[x]``.  The accepted JSON shape is
intentionally small and also accepts the common aliases used by the shared
certificate producer:

    {
      "base": {
        "q": "3",
        "p": "7",
        "exponentPrime": true,
        "lucasLehmer": {
          "passed": true,
          "sequence": ["4", "0"]
        }
      },
      "polynomial": {
        "degree": 2,
        "coefficients": ["1", "0", "1"],
        "rabin": {
          "h": [["0", "1"], ["0", "6"], ["0", "1"]],
          "gcd": [{"r": "2", "g": ["0", "5"], "result": ["1"]}],
          "bezout": [{"r": "2", "u": ["1"],
                      "v": ["0", "4"], "identity": ["1"]}]
        }
      }
    }

Polynomial coefficient arrays are ascending (constant term first) and use
canonical non-negative decimal values in ``[0, p)``.  Zero is represented as
``["0"]``; nonzero polynomial arrays may not have a trailing zero.  JSON
integers are accepted for convenience, while decimal strings must have no
leading zero, sign, whitespace, or alternate spelling.

The checker is an independent implementation, not an independent CAS.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Iterable, Mapping, Sequence


class CertificateError(ValueError):
    """Raised when a certificate is absent, non-canonical, or mathematically wrong."""


_MISSING = object()
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_MAX_SAFE_INTEGER = (1 << 53) - 1
_FRONTIER_NOTES = [
    "Deterministic generic-math fixture only; it is not a field, protocol, or proof-system selection.",
    "Lucas-Lehmer acceptance establishes the listed Mersenne modulus primality only and does not establish systemic soundness.",
]
_M89_NOTES = [
    "Analytical generic-math fixture only; it is not CAS-reviewed, implementation evidence, or a field-selection decision.",
    "The certificate records the exact Rabin residues, gcds, and Bezout witnesses for f = X^2 + 1 over M89.",
]


def _fail(message: str) -> None:
    raise CertificateError(message)


def _uint(value: Any, label: str) -> int:
    """Parse a canonical non-negative JSON integer or decimal string."""

    if isinstance(value, bool):
        _fail(f"{label}: boolean is not an integer")
    if isinstance(value, int):
        if value < 0:
            _fail(f"{label}: negative integer")
        return value
    if isinstance(value, str):
        if not _DECIMAL.fullmatch(value):
            _fail(f"{label}: non-canonical decimal integer {value!r}")
        return int(value, 10)
    _fail(f"{label}: expected an integer or decimal string")


def _strict_decimal(value: Any, label: str) -> int:
    """Parse the shared fixture's required canonical decimal-string form."""

    if not isinstance(value, str) or not _DECIMAL.fullmatch(value):
        _fail(f"{label}: expected canonical unsigned decimal string")
    return int(value, 10)


def _require_exact_keys(value: Any, keys: Sequence[str], label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        _fail(f"{label}: missing or unexpected keys")


def _strict_poly(value: Any, p: int, label: str) -> list[int]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        _fail(f"{label}: expected canonical decimal-string coefficients")
    return _parse_poly(value, p, label)


def _bool_claim(value: Any, label: str) -> bool | None:
    """Extract a boolean claim from a direct bool or a result object."""

    if isinstance(value, bool):
        return value
    if isinstance(value, Mapping):
        found: list[bool] = []
        for key in (
            "passed",
            "pass",
            "result",
            "isPrime",
            "prime",
            "valid",
            "ok",
        ):
            if key in value:
                if not isinstance(value[key], bool):
                    _fail(f"{label}.{key}: expected boolean")
                found.append(value[key])
        if found and any(item != found[0] for item in found[1:]):
            _fail(f"{label}: contradictory boolean claims")
        return found[0] if found else None
    if isinstance(value, list):
        return None
    _fail(f"{label}: expected boolean, result object, or sequence")


def _values(objects: Iterable[Any], names: Sequence[str]) -> list[Any]:
    found: list[Any] = []
    for obj in objects:
        if isinstance(obj, Mapping):
            for name in names:
                if name in obj:
                    found.append(obj[name])
    return found


def _one_int(objects: Iterable[Any], names: Sequence[str], label: str) -> int:
    raw = _values(objects, names)
    if not raw:
        _fail(f"{label}: missing field")
    parsed = [_uint(value, label) for value in raw]
    if any(value != parsed[0] for value in parsed[1:]):
        _fail(f"{label}: contradictory duplicate fields")
    return parsed[0]


def _one_claim(objects: Iterable[Any], names: Sequence[str], label: str) -> Any:
    raw = _values(objects, names)
    if not raw:
        _fail(f"{label}: missing field")
    claims = [_bool_claim(value, label) for value in raw]
    known = [claim for claim in claims if claim is not None]
    if known and any(claim != known[0] for claim in known[1:]):
        _fail(f"{label}: contradictory duplicate fields")
    return raw[0]


def _trim(poly: Sequence[int]) -> list[int]:
    result = list(poly)
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result or [0]


def _parse_poly(value: Any, p: int, label: str, *, degree: int | None = None) -> list[int]:
    """Parse an ascending, canonical polynomial coefficient array."""

    if isinstance(value, Mapping):
        nested = _values((value,), ("coefficients", "coeffs", "residue", "value", "polynomial"))
        if len(nested) != 1:
            _fail(f"{label}: expected coefficient array")
        value = nested[0]
    if not isinstance(value, list) or not value:
        _fail(f"{label}: expected non-empty coefficient array")
    coeffs = [_uint(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if any(item >= p for item in coeffs):
        _fail(f"{label}: coefficient outside canonical [0, p) range")
    if len(coeffs) > 1 and coeffs[-1] == 0:
        _fail(f"{label}: non-canonical trailing zero")
    if degree is not None and len(coeffs) != degree + 1:
        _fail(f"{label}: expected {degree + 1} coefficients, got {len(coeffs)}")
    return coeffs


def _poly_add(a: Sequence[int], b: Sequence[int], p: int) -> list[int]:
    result = [0] * max(len(a), len(b))
    for index in range(len(result)):
        result[index] = ((a[index] if index < len(a) else 0) +
                         (b[index] if index < len(b) else 0)) % p
    return _trim(result)


def _poly_sub(a: Sequence[int], b: Sequence[int], p: int) -> list[int]:
    result = [0] * max(len(a), len(b))
    for index in range(len(result)):
        result[index] = ((a[index] if index < len(a) else 0) -
                         (b[index] if index < len(b) else 0)) % p
    return _trim(result)


def _poly_neg(a: Sequence[int], p: int) -> list[int]:
    return _trim([(-item) % p for item in a])


def _poly_mul(a: Sequence[int], b: Sequence[int], p: int) -> list[int]:
    if a == [0] or b == [0]:
        return [0]
    result = [0] * (len(a) + len(b) - 1)
    for i, left in enumerate(a):
        for j, right in enumerate(b):
            result[i + j] = (result[i + j] + left * right) % p
    return _trim(result)


def _poly_divmod(numerator: Sequence[int], denominator: Sequence[int], p: int) -> tuple[list[int], list[int]]:
    denominator = _trim(denominator)
    if denominator == [0]:
        _fail("polynomial division by zero")
    remainder = _trim(numerator)
    quotient = [0] * max(1, len(remainder) - len(denominator) + 1)
    inverse_lead = pow(denominator[-1], p - 2, p)
    while remainder != [0] and len(remainder) >= len(denominator):
        shift = len(remainder) - len(denominator)
        factor = remainder[-1] * inverse_lead % p
        quotient[shift] = (quotient[shift] + factor) % p
        term = [0] * shift + [factor]
        remainder = _poly_sub(remainder, _poly_mul(term, denominator, p), p)
    return _trim(quotient), _trim(remainder)


def _poly_mod(value: Sequence[int], modulus: Sequence[int], p: int) -> list[int]:
    return _poly_divmod(value, modulus, p)[1]


def _poly_pow_mod(base: Sequence[int], exponent: int, modulus: Sequence[int], p: int) -> list[int]:
    result = [1]
    factor = _poly_mod(base, modulus, p)
    power = exponent
    while power:
        if power & 1:
            result = _poly_mod(_poly_mul(result, factor, p), modulus, p)
        factor = _poly_mod(_poly_mul(factor, factor, p), modulus, p)
        power >>= 1
    return result


def _poly_gcd(a: Sequence[int], b: Sequence[int], p: int) -> list[int]:
    left = _trim(a)
    right = _trim(b)
    while right != [0]:
        _, remainder = _poly_divmod(left, right, p)
        left, right = right, remainder
    if left == [0]:
        return [0]
    scale = pow(left[-1], p - 2, p)
    return _trim([(item * scale) % p for item in left])


def _poly_xgcd(a: Sequence[int], b: Sequence[int], p: int) -> tuple[list[int], list[int], list[int]]:
    """Match the shared reference's normalized extended-GCD witness exactly."""

    old_r, r = _trim(a), _trim(b)
    old_s, s = [1], [0]
    old_t, t = [0], [1]
    while r != [0]:
        quotient, remainder = _poly_divmod(old_r, r, p)
        old_r, r = r, remainder
        old_s, s = s, _poly_sub(old_s, _poly_mul(quotient, s, p), p)
        old_t, t = t, _poly_sub(old_t, _poly_mul(quotient, t, p), p)
    if old_r == [0]:
        return [0], [0], [0]
    scale = pow(old_r[-1], p - 2, p)
    return (
        _trim([(item * scale) % p for item in old_r]),
        _trim([(item * scale) % p for item in old_s]),
        _trim([(item * scale) % p for item in old_t]),
    )


def _prime_factors(n: int) -> list[int]:
    if n < 2:
        return []
    factors: list[int] = []
    divisor = 2
    remainder = n
    while divisor * divisor <= remainder:
        if remainder % divisor == 0:
            factors.append(divisor)
            while remainder % divisor == 0:
                remainder //= divisor
        divisor = 3 if divisor == 2 else divisor + 2
    if remainder > 1:
        factors.append(remainder)
    return factors


def _is_prime_deterministic(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2
    return True


def _ll_states(q: int, p: int) -> list[int]:
    state = 4 % p
    states = [state]
    if q == 2:
        return states
    for _ in range(q - 2):
        state = (state * state - 2) % p
        states.append(state)
    return states


def _ll_result(q: int, p: int) -> dict[str, int | bool]:
    """Return the exact scalar Lucas--Lehmer result used by the shared Node shape."""

    if q == 2:
        return {"iterations": 0, "residue": 0, "passed": True}
    state = 4
    for _ in range(q - 2):
        state = (state * state - 2) % p
    return {"iterations": q - 2, "residue": state, "passed": state == 0}


def _sequence(value: Any, label: str) -> list[Any]:
    if isinstance(value, Mapping):
        nested = _values((value,), ("values", "residues", "states", "sequence", "iterations"))
        if len(nested) != 1:
            _fail(f"{label}: expected a residue sequence")
        value = nested[0]
    if not isinstance(value, list):
        _fail(f"{label}: expected a residue sequence")
    return value


def _check_lucas_lehmer(q: int, p: int, raw: Any) -> None:
    expected = _ll_states(q, p)
    claim = _bool_claim(raw, "lucasLehmer")
    sequence_values: list[Any] | None = None
    iteration_values: list[Any] | None = None
    final_value: Any = _MISSING
    initial_value: Any = _MISSING

    if isinstance(raw, list):
        sequence_values = raw
    elif isinstance(raw, Mapping):
        for key in ("sequence", "states", "residues"):
            if key in raw:
                if sequence_values is not None:
                    _fail("lucasLehmer: duplicate sequence fields")
                sequence_values = _sequence(raw[key], f"lucasLehmer.{key}")
        if "iterations" in raw:
            iteration_values = _sequence(raw["iterations"], "lucasLehmer.iterations")
        for key in ("final", "finalResidue", "last"):
            if key in raw:
                if final_value is not _MISSING:
                    _fail("lucasLehmer: duplicate final fields")
                final_value = raw[key]
        for key in ("s0", "initial", "initialResidue"):
            if key in raw:
                if initial_value is not _MISSING:
                    _fail("lucasLehmer: duplicate initial fields")
                initial_value = raw[key]

    if q == 2:
        expected_iterations: list[int] = []
    else:
        expected_iterations = expected[1:]

    def parse_sequence(items: list[Any], label: str) -> list[int]:
        return [_uint(item, f"{label}[{index}]") for index, item in enumerate(items)]

    if sequence_values is not None:
        actual_sequence = parse_sequence(sequence_values, "lucasLehmer.sequence")
        if actual_sequence not in (expected, expected_iterations):
            _fail("lucasLehmer: sequence mismatch")
    if iteration_values is not None:
        actual_iterations = parse_sequence(iteration_values, "lucasLehmer.iterations")
        if actual_iterations != expected_iterations:
            _fail("lucasLehmer: iteration residues mismatch")
    if final_value is not _MISSING and _uint(final_value, "lucasLehmer.final") != expected[-1]:
        _fail("lucasLehmer: final residue mismatch")
    if initial_value is not _MISSING and _uint(initial_value, "lucasLehmer.initial") != expected[0]:
        _fail("lucasLehmer: initial residue mismatch")
    if claim is None and sequence_values is None and iteration_values is None and final_value is _MISSING:
        _fail("lucasLehmer: missing pass claim or replay data")
    if claim is not None and claim is not True:
        _fail("lucasLehmer: certificate claims failure")
    if expected[-1] != 0:
        _fail("lucasLehmer: recomputed sequence does not prove primality")


def _unwrap_entries(raw: Any, label: str) -> list[tuple[int | None, Any]]:
    """Turn list/map witness containers into optional-r-tagged entries."""

    if isinstance(raw, Mapping):
        for key in ("entries", "witnesses", "items", "certificates"):
            if key in raw:
                nested = raw[key]
                if not isinstance(nested, list):
                    _fail(f"{label}.{key}: expected list")
                return [(None, item) for item in nested]
        if any(key in raw for key in ("r", "prime", "factor", "divisor", "u", "v", "result", "gcd")):
            return [(None, raw)]
        entries: list[tuple[int | None, Any]] = []
        for key, value in raw.items():
            try:
                factor = _uint(key, f"{label} factor")
            except CertificateError:
                _fail(f"{label}: expected decimal prime-factor keys")
            entries.append((factor, value))
        if not entries:
            _fail(f"{label}: empty witness map")
        return entries
    if isinstance(raw, list):
        return [(None, item) for item in raw]
    # A single scalar is useful for the one-factor gcd result shape.
    return [(None, raw)]


def _entry_value(entry: Any, names: Sequence[str], label: str) -> Any:
    if not isinstance(entry, Mapping):
        return entry
    values = _values((entry,), names)
    if not values:
        _fail(f"{label}: missing field {names[0]!r}")
    first = values[0]
    for value in values[1:]:
        if value != first:
            _fail(f"{label}: contradictory duplicate fields")
    return first


def _entry_factor(entry: Any, hinted: int | None, factors: Sequence[int], label: str) -> int:
    explicit: list[int] = []
    if isinstance(entry, Mapping):
        for key in ("r", "prime", "factor", "divisor", "primeDivisor"):
            if key in entry:
                explicit.append(_uint(entry[key], f"{label}.{key}"))
    if hinted is not None:
        explicit.append(hinted)
    if explicit and any(item != explicit[0] for item in explicit[1:]):
        _fail(f"{label}: contradictory prime-factor tags")
    if explicit:
        factor = explicit[0]
    elif len(factors) == 1:
        factor = factors[0]
    else:
        _fail(f"{label}: missing prime-factor tag")
    if factor not in factors:
        _fail(f"{label}: unexpected factor {factor}")
    return factor


def _check_witnesses(
    sources: Sequence[Any],
    factors: Sequence[int],
    degree: int,
    modulus: Sequence[int],
    h: Sequence[Sequence[int]],
    p: int,
) -> None:
    gcd_raw_values = _values(sources, ("gcd", "gcdWitnesses", "gcds", "gcdCertificates"))
    bezout_raw_values = _values(sources, ("bezout", "bezoutWitnesses", "bezoutCertificates"))
    if not gcd_raw_values:
        _fail("rabin: missing gcd witnesses")
    # Some producers place u/v beside each gcd result.  Accept that shape as
    # long as it still contains a complete, independently checkable witness.
    if not bezout_raw_values:
        candidate_entries = _unwrap_entries(gcd_raw_values[0], "rabin.gcd")
        if candidate_entries and all(
            isinstance(entry, Mapping) and "u" in entry and "v" in entry
            for _, entry in candidate_entries
        ):
            bezout_entries = candidate_entries
        else:
            _fail("rabin: missing Bezout witnesses")
    else:
        bezout_entries = _unwrap_entries(bezout_raw_values[0], "rabin.bezout")
    gcd_entries = _unwrap_entries(gcd_raw_values[0], "rabin.gcd")

    def index_entries(entries: Sequence[tuple[int | None, Any]], label: str) -> dict[int, Any]:
        result: dict[int, Any] = {}
        for hinted, entry in entries:
            factor = _entry_factor(entry, hinted, factors, label)
            if factor in result:
                _fail(f"{label}: duplicate witness for factor {factor}")
            result[factor] = entry
        if set(result) != set(factors):
            _fail(f"{label}: factors do not match distinct prime divisors of degree")
        return result

    gcd_by_factor = index_entries(gcd_entries, "rabin.gcd")
    bezout_by_factor = index_entries(bezout_entries, "rabin.bezout")

    x = [0, 1]
    for factor in factors:
        index = degree // factor
        g_expected = _poly_sub(h[index], x, p)
        gcd_expected = _poly_gcd(modulus, g_expected, p)
        if gcd_expected != [1]:
            _fail(f"rabin: recomputed gcd for factor {factor} is {gcd_expected}, not 1")

        gcd_entry = gcd_by_factor[factor]
        gcd_value = _entry_value(
            gcd_entry,
            ("result", "gcd", "value", "residue", "polynomial", "coefficients"),
            "rabin.gcd",
        )
        if _parse_poly(gcd_value, p, f"rabin.gcd[{factor}]") != gcd_expected:
            _fail(f"rabin.gcd[{factor}]: result mismatch")
        if isinstance(gcd_entry, Mapping):
            for key in ("g", "argument", "input", "difference", "g_r"):
                if key in gcd_entry:
                    supplied_g = _parse_poly(gcd_entry[key], p, f"rabin.gcd[{factor}].{key}")
                    if supplied_g != g_expected:
                        _fail(f"rabin.gcd[{factor}].{key}: g_r mismatch")

        bezout_entry = bezout_by_factor[factor]
        u = _parse_poly(_entry_value(bezout_entry, ("u", "left", "bezoutU"), "rabin.bezout"), p,
                        f"rabin.bezout[{factor}].u")
        v = _parse_poly(_entry_value(bezout_entry, ("v", "right", "bezoutV"), "rabin.bezout"), p,
                        f"rabin.bezout[{factor}].v")
        identity = _poly_add(_poly_mul(u, modulus, p), _poly_mul(v, g_expected, p), p)
        if identity != [1]:
            _fail(f"rabin.bezout[{factor}]: u*f + v*g is {identity}, not 1")
        if isinstance(bezout_entry, Mapping):
            for key in ("g", "argument", "input", "difference", "g_r"):
                if key in bezout_entry:
                    supplied_g = _parse_poly(bezout_entry[key], p, f"rabin.bezout[{factor}].{key}")
                    if supplied_g != g_expected:
                        _fail(f"rabin.bezout[{factor}].{key}: g_r mismatch")
            for key in ("identity", "result"):
                if key in bezout_entry:
                    supplied_identity = _parse_poly(bezout_entry[key], p,
                                                    f"rabin.bezout[{factor}].{key}")
                    if supplied_identity != [1]:
                        _fail(f"rabin.bezout[{factor}].{key}: identity mismatch")


def _verify_shared_prime_check(stored: Any, label: str = "primeCheck") -> dict[str, Any]:
    """Replay the exact primeCheck object from certificate.schema.json."""

    _require_exact_keys(
        stored,
        (
            "mersenneExponent",
            "exponentPrime",
            "exponentPrimalityMethod",
            "modulus",
            "lucasLehmer",
            "classification",
        ),
        label,
    )
    _require_exact_keys(stored["lucasLehmer"], ("iterations", "residue", "passed"), f"{label}.lucasLehmer")
    q = _strict_decimal(stored["mersenneExponent"], f"{label}.mersenneExponent")
    if q < 2 or q > _MAX_SAFE_INTEGER:
        _fail(f"{label}.mersenneExponent: outside positive safe-integer range")
    if not _is_prime_deterministic(q):
        _fail(f"{label}.mersenneExponent: deterministic primality check failed")
    modulus = (1 << q) - 1
    expected_ll = _ll_result(q, modulus)
    expected = {
        "mersenneExponent": str(q),
        "exponentPrime": True,
        "exponentPrimalityMethod": "deterministic-trial-division",
        "modulus": str(modulus),
        "lucasLehmer": {
            "iterations": str(expected_ll["iterations"]),
            "residue": str(expected_ll["residue"]),
            "passed": expected_ll["passed"],
        },
        "classification": "prime" if expected_ll["passed"] else "rejected-composite",
    }
    if stored != expected:
        _fail(f"{label}: deterministic Mersenne/Lucas-Lehmer result mismatch")
    return {"q": q, "p": modulus, "passed": expected_ll["passed"]}


def _verify_shared_envelope(
    stored: Any,
    *,
    kind: str,
    fixture_id: str,
    payload_key: str,
    expected_notes: Sequence[str],
    label: str,
) -> Any:
    _require_exact_keys(
        stored,
        (
            "schema",
            "fixtureId",
            "kind",
            "status",
            "casReview",
            "evidenceClassification",
            "selection",
            "notes",
            payload_key,
        ),
        label,
    )
    if (
        stored["schema"] != "shieldkit-labs/field-cert/v1"
        or stored["fixtureId"] != fixture_id
        or stored["kind"] != kind
        or stored["status"] != "generic-math-unqualified"
        or stored["casReview"] != "not-cas-reviewed"
        or stored["evidenceClassification"] != "not-evidence"
        or stored["selection"] != "none"
        or stored["notes"] != list(expected_notes)
    ):
        _fail(f"{label}: envelope value mismatch")
    return stored[payload_key]


def _verify_shared_prime_fixture(stored: Any) -> dict[str, Any]:
    checks = _verify_shared_envelope(
        stored,
        kind="mersenne-prime-check-fixture",
        fixture_id="fixture:frontier-mersenne-prime-checks-v1",
        payload_key="checks",
        expected_notes=_FRONTIER_NOTES,
        label="prime fixture envelope",
    )
    expected_exponents = [13, 17, 19, 29, 31, 61, 89, 107, 127]
    if not isinstance(checks, list) or len(checks) != len(expected_exponents):
        _fail("prime fixture checks: expected the complete pinned frontier list")
    summaries = []
    for index, (check, expected_q) in enumerate(zip(checks, expected_exponents)):
        summary = _verify_shared_prime_check(check, f"checks[{index}]")
        if summary["q"] != expected_q:
            _fail(f"checks[{index}]: exponent order/content mismatch")
        summaries.append(summary)
    return {"status": "pass", "kind": "mersenne-prime-check-fixture", "checks": summaries}


def _verify_shared_rabin_certificate(stored: Any) -> dict[str, Any]:
    _require_exact_keys(
        stored,
        (
            "certificateId",
            "mersennePrimeCheck",
            "modulus",
            "coefficientEncoding",
            "polynomial",
            "degree",
            "hPowers",
            "primeDivisors",
            "witnesses",
            "finalResidue",
            "conclusion",
        ),
        "Rabin certificate",
    )
    prime_summary = _verify_shared_prime_check(stored["mersennePrimeCheck"], "mersennePrimeCheck")
    if not prime_summary["passed"]:
        _fail("Rabin certificate modulus is not prime")
    p = _strict_decimal(stored["modulus"], "certificate.modulus")
    if p != prime_summary["p"] or stored["modulus"] != stored["mersennePrimeCheck"]["modulus"]:
        _fail("certificate.modulus: differs from the Mersenne prime check")
    if stored["coefficientEncoding"] != "unsigned-decimal-c0-to-cd":
        _fail("certificate.coefficientEncoding: mismatch")
    polynomial = _strict_poly(stored["polynomial"], p, "certificate.polynomial")
    if len(polynomial) < 2 or polynomial[-1] != 1:
        _fail("certificate.polynomial: must be monic and nonconstant")
    degree = _strict_decimal(stored["degree"], "certificate.degree")
    if degree < 1 or degree > _MAX_SAFE_INTEGER or degree != len(polynomial) - 1:
        _fail("certificate.degree: mismatch or outside positive safe-integer range")
    expected_id = f"certificate:mersenne-q{stored['mersennePrimeCheck']['mersenneExponent']}-d{degree}-rabin"
    if stored["certificateId"] != expected_id:
        _fail("certificate.certificateId: identity mismatch")

    h_entries = stored["hPowers"]
    if not isinstance(h_entries, list) or len(h_entries) != degree + 1:
        _fail("certificate.hPowers: must retain exactly h_0 through h_d")
    x_residue = _poly_pow_mod([0, 1], 1, polynomial, p)
    h: list[list[int]] = []
    expected_h = [x_residue]
    for _ in range(degree):
        expected_h.append(_poly_pow_mod(expected_h[-1], p, polynomial, p))
    for index, entry in enumerate(h_entries):
        _require_exact_keys(entry, ("index", "coefficients"), f"hPowers[{index}]")
        if _strict_decimal(entry["index"], f"hPowers[{index}].index") != index:
            _fail(f"hPowers[{index}].index: mismatch")
        residue = _strict_poly(entry["coefficients"], p, f"hPowers[{index}].coefficients")
        if residue != expected_h[index]:
            _fail(f"hPowers[{index}]: residue mismatch")
        h.append(residue)

    final_residue = _strict_poly(stored["finalResidue"], p, "certificate.finalResidue")
    if final_residue != x_residue or h[-1] != final_residue:
        _fail("certificate.finalResidue: must equal X mod f and h_d")

    factors = _prime_factors(degree)
    prime_divisors = stored["primeDivisors"]
    if not isinstance(prime_divisors, list) or any(not isinstance(item, str) for item in prime_divisors):
        _fail("certificate.primeDivisors: expected canonical decimal strings")
    actual_factors = [_strict_decimal(item, f"primeDivisors[{index}]") for index, item in enumerate(prime_divisors)]
    if actual_factors != factors:
        _fail("certificate.primeDivisors: mismatch")

    witnesses = stored["witnesses"]
    if not isinstance(witnesses, list) or len(witnesses) != len(factors):
        _fail("certificate.witnesses: inventory mismatch")
    x = [0, 1]
    for index, factor in enumerate(factors):
        witness = witnesses[index]
        _require_exact_keys(
            witness,
            ("primeDivisor", "hIndex", "g", "gcd", "bezoutU", "bezoutV"),
            f"witness[{index}]",
        )
        if _strict_decimal(witness["primeDivisor"], f"witness[{index}].primeDivisor") != factor:
            _fail(f"witness[{index}].primeDivisor: mismatch")
        h_index = degree // factor
        if _strict_decimal(witness["hIndex"], f"witness[{index}].hIndex") != h_index:
            _fail(f"witness[{index}].hIndex: mismatch")
        g_expected = _poly_sub(h[h_index], x, p)
        g = _strict_poly(witness["g"], p, f"witness[{index}].g")
        if g != g_expected:
            _fail(f"witness[{index}].g: mismatch")
        gcd_expected = _poly_gcd(polynomial, g, p)
        gcd = _strict_poly(witness["gcd"], p, f"witness[{index}].gcd")
        if gcd != gcd_expected or gcd != [1]:
            _fail(f"witness[{index}].gcd: not exactly one")
        bezout_gcd, expected_u, expected_v = _poly_xgcd(polynomial, g, p)
        supplied_u = _strict_poly(witness["bezoutU"], p, f"witness[{index}].bezoutU")
        supplied_v = _strict_poly(witness["bezoutV"], p, f"witness[{index}].bezoutV")
        if bezout_gcd != [1] or supplied_u != expected_u or supplied_v != expected_v:
            _fail(f"witness[{index}]: deterministic Bezout mismatch")
        identity = _poly_add(_poly_mul(supplied_u, polynomial, p), _poly_mul(supplied_v, g, p), p)
        if identity != [1]:
            _fail(f"witness[{index}]: Bezout identity mismatch")
    if stored["conclusion"] != "irreducible":
        _fail("certificate.conclusion: mismatch")
    return {"status": "pass", "kind": "rabin-irreducibility-fixture", "q": prime_summary["q"],
            "p": p, "degree": degree, "primeFactorsOfDegree": factors}


def _verify_shared_fixture(stored: Mapping[str, Any]) -> dict[str, Any]:
    if stored.get("kind") == "mersenne-prime-check-fixture":
        return _verify_shared_prime_fixture(stored)
    if stored.get("kind") == "rabin-irreducibility-fixture":
        certificate = _verify_shared_envelope(
            stored,
            kind="rabin-irreducibility-fixture",
            fixture_id="fixture:m89-x2-plus-1-rabin-v1",
            payload_key="certificate",
            expected_notes=_M89_NOTES,
            label="Rabin fixture envelope",
        )
        return _verify_shared_rabin_certificate(certificate)
    _fail("shared fixture: unsupported kind")


def _objects_with_nested(root: Mapping[str, Any], names: Sequence[str]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for name in names:
        value = root.get(name)
        if isinstance(value, Mapping):
            result.append(value)
    return result


def verify_certificate(certificate: Mapping[str, Any]) -> dict[str, Any]:
    """Verify a certificate and return a small derived summary on success."""

    if not isinstance(certificate, Mapping):
        _fail("certificate: expected JSON object")
    if any(key in certificate for key in ("schema", "fixtureId", "kind")):
        if certificate.get("schema") != "shieldkit-labs/field-cert/v1":
            _fail("shared fixture: schema mismatch")
        return _verify_shared_fixture(certificate)

    base_objects = _objects_with_nested(certificate, ("base", "basePrime", "baseField"))
    base_sources: list[Mapping[str, Any]] = [certificate, *base_objects]
    q = _one_int(base_sources, ("q", "exponent", "basePrimeExponent"), "base.q")
    p = _one_int(base_sources, ("p", "basePrime"), "base.p")
    if q < 2:
        _fail("base.q: must be at least 2")
    if not _is_prime_deterministic(q):
        _fail("base.q: deterministic primality check failed")
    if p != (1 << q) - 1:
        _fail("base.p: does not equal 2^q - 1")

    exponent_claim = _one_claim(
        base_sources,
        ("exponentPrime", "exponent_prime", "qPrime", "qIsPrime", "isExponentPrime"),
        "base.exponentPrime",
    )
    if _bool_claim(exponent_claim, "base.exponentPrime") is not True:
        _fail("base.exponentPrime: claim is not true")
    ll_claim = _one_claim(base_sources, ("lucasLehmer", "lucas_lehmer", "ll"), "base.lucasLehmer")
    _check_lucas_lehmer(q, p, ll_claim)

    polynomial_objects = _objects_with_nested(
        certificate, ("polynomial", "extensionPolynomial", "modulus", "extension")
    )
    if not polynomial_objects:
        polynomial_objects = [certificate]
    rabin_objects = _objects_with_nested(polynomial_objects[0], ("rabin", "irreducibility", "certificate"))
    polynomial_sources: list[Mapping[str, Any]] = [*polynomial_objects, *rabin_objects, certificate]

    degree = _one_int(polynomial_sources, ("degree", "d"), "polynomial.degree")
    if degree < 1:
        _fail("polynomial.degree: must be positive")
    coefficient_values = _values(
        polynomial_sources,
        ("coefficients", "coeffs", "modulusCoefficients", "polynomialCoefficients", "f"),
    )
    if not coefficient_values:
        _fail("polynomial.coefficients: missing field")
    modulus = _parse_poly(coefficient_values[0], p, "polynomial.coefficients", degree=degree)
    for duplicate in coefficient_values[1:]:
        if _parse_poly(duplicate, p, "polynomial.coefficients") != modulus:
            _fail("polynomial.coefficients: contradictory duplicate fields")
    if modulus[-1] != 1:
        _fail("polynomial.coefficients: polynomial is not monic")

    h_values = _values(polynomial_sources, ("h", "h_i", "rabinH", "frobenius", "residues"))
    if not h_values:
        _fail("rabin.h: missing Frobenius residues")
    h_raw = h_values[0]
    h_entries: dict[int, Any] = {}
    if isinstance(h_raw, Mapping):
        for key, value in h_raw.items():
            index = _uint(key, "rabin.h index")
            if index in h_entries:
                _fail(f"rabin.h: duplicate index {index}")
            h_entries[index] = value
    elif isinstance(h_raw, list):
        h_entries = {index: value for index, value in enumerate(h_raw)}
    else:
        _fail("rabin.h: expected list or decimal-indexed map")
    if set(h_entries) != set(range(degree + 1)):
        _fail("rabin.h: expected exactly h_0 through h_d")
    h: list[list[int]] = []
    for index in range(degree + 1):
        h.append(_parse_poly(h_entries[index], p, f"rabin.h[{index}]"))

    x = [0, 1]
    if h[0] != x:
        _fail("rabin.h[0]: must equal X")
    expected_h: list[list[int]] = [x]
    for _ in range(degree):
        expected_h.append(_poly_pow_mod(expected_h[-1], p, modulus, p))
    if h != expected_h:
        _fail("rabin.h: one or more Frobenius residues mismatch")
    if h[-1] != x:
        _fail("rabin.h[d]: must equal X")

    factors = _prime_factors(degree)
    if not factors:
        _fail("polynomial.degree: no prime divisors")
    _check_witnesses(polynomial_sources, factors, degree, modulus, h, p)
    return {
        "q": q,
        "p": p,
        "degree": degree,
        "primeFactorsOfDegree": factors,
        "lucasLehmerFinal": _ll_states(q, p)[-1],
        "rabinResidues": degree + 1,
    }


def load_certificate(path: str) -> Mapping[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, Mapping):
        _fail("certificate JSON: expected object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay a Mersenne/Rabin field certificate")
    parser.add_argument("certificate", help="JSON certificate path, or - for stdin")
    args = parser.parse_args(argv)
    try:
        if args.certificate == "-":
            certificate = json.load(sys.stdin)
        else:
            certificate = load_certificate(args.certificate)
        summary = verify_certificate(certificate)
    except (OSError, json.JSONDecodeError, CertificateError) as error:
        print(f"REJECT: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "pass", **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
