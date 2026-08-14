# CPSB exact-673 quarantined diagnostic-v2 launcher

This source-only directory is a research-only, nonaccepting derivative of the
current `cpsb-exact27-v1` launcher. It has exactly two actions:
`verify-only` and `diagnose-unsealed`. It has no `validate-unsealed`,
sealed-validation, test, retry, fallback, arbitrary-program, alternate-argv,
acceptance, qualification, or publication path.

`verify-only` authenticates the exact production closure, emits one canonical
LF-terminated receipt, writes no stderr, returns zero, starts neither
Bubblewrap nor Node, and classifies only
`AUTHENTICATED_INPUT_CLOSURE_ONLY_NO_NODE`.

`diagnose-unsealed` retains the production manifest identity
`cpsb-exact27-v1`, all current 673-row/count/total/group-total/order-digest
and SSA checks, sealed-memfd capture, the exact Bubblewrap `--file` and root
remount construction, fixed Node path/cwd/argv, and the 30-second deadline.
It starts exactly one fixed child. Its receipt identifies
`cpsb-exact27-diagnostic-v2`, uses
`shieldkit-labs/external-launcher/cpsb-exact27-diagnostic/receipt/v2`, has
`authorization: "NONE"`, and always has `acceptanceAllowed`,
`validationClaim`, and `sealAllowed` false. It classifies only
`AUTHENTICATED_UNSEALED_STATIC_DIAGNOSTIC_ONLY_NONACCEPTING`, emits evidence,
and returns one even if the child exits zero.

Stdout and stderr are collected independently to 65,536 bytes. Byte 65,537
immediately kills and reaps the child. Complete evidence is possible only after
both EOFs and reap before the deadline; the diagnostic top-level
`captureComplete` is true only in that case, and it records exact lowercase
hex and raw SHA-256. Timeout makes `captureComplete` false and both streams
incomplete. On a stream limit the
limited stream records a 65,537-byte lower bound; its peer is explicitly
`peer-stream-limit` and records only its retained prefix and truthful lower
bound. Collector termination is separate from child exit code or signal.
Output is never parsed or compared as validation evidence. Spawn, pipe, reap,
receipt-size, and receipt-write failures produce no diagnostic receipt. A
canonical receipt may not exceed 400,000 bytes before writing.

## Reviewed source pins

These must be independently re-established from exact source bytes after every
edit. The manifest is intentionally not copied into this directory.

| Artifact | Bytes | Raw SHA-256 | Mode | Links |
| --- | ---: | --- | ---: | ---: |
| `stage0-literal.py` | `10667` | `296f5d71e24bfcb5fc0535bdfc1c1ef4c621379e2785973e1b815172167939cc` | `0644` | `1` |
| `verify-copy.py` | `44738` | `f404dc4704f496a3ea9a3396eb6bf767586949d2bd96b70a0f71000b1ca7c74a` | `0644` | `1` |
| production `../cpsb-exact27-v1/trust-manifest.v1.json` | `237511` | `4bf28ded94240574fe50278d33460bb2ae983823bd0333f5fc435f75d1e603b0` | `0644` | `1` |

## External caller and TCB boundary

The caller must independently review the exact `stage0-literal.py` bytes,
preserve them byte-for-byte including LF bytes, and supply those reviewed bytes
directly as the `-c` literal to `/usr/bin/python3.14 -I -S -B`. The caller
must supply the independently established v2 helper pin and the production
manifest pin; pathname execution is forbidden. Receipt canonicalization is
JSON with sorted keys, compact separators, UTF-8, and exactly one trailing LF.

The caller, literal-delivery path, Python/stdlib, Bubblewrap, kernel, loader,
host runtime libraries, hardware, and privileged or same-UID post-Bubblewrap
process injection are external TCB limitations. No receipt authorizes
publication, sealing, admission, qualification, or any production claim.

## Mandatory one-shot sequence

1. Complete an independent source gate for the stage-0 and helper bytes.
2. Perform a fresh `verify-only` invocation and independently gate its receipt.
3. Perform one `diagnose-unsealed` invocation only.
4. Stop. Do not retry, substitute an argv, run Node/JavaScript/tests separately,
   or treat any diagnostic receipt as acceptance.

This README grants no execution authority. It documents the required external
controls for a future separately authorized caller.
