# CPSB exact-673 quarantined diagnostic launcher

This directory is a research-only, nonaccepting variant of the reviewed
`cpsb-exact27-v1` launcher.  It has exactly two actions:

- `verify-only` authenticates the exact source closure and does not start Node.
- `diagnose-unsealed` uses the unchanged exact-673 capture, sealed-memfd,
  Bubblewrap, Node, working-directory, and fixed validator-argv path, then
  emits a bounded diagnostic receipt and exits `1` irrespective of the child
  outcome.

There is no `validate-unsealed` action, no accepting path, no retry, no test
action, and no caller-controlled program or argv.  This launcher does not
validate, seal, admit, qualify, or authorize anything.

## Boundary

The manifest remains the reviewed production artifact, whose manifest
`launcherId` is deliberately still `cpsb-exact27-v1`.  This diagnostic
launcher's receipts instead identify `cpsb-exact27-diagnostic-v1` and set:

```text
authorization       NONE
classification      AUTHENTICATED_UNSEALED_STATIC_DIAGNOSTIC_ONLY_NONACCEPTING
acceptanceAllowed   false
validationClaim     false
sealAllowed         false
```

`verify-only` retains its narrower no-Node closure classification and the same
three false policy flags.  An ordinary bootstrap/pre-spawn failure remains a
fixed outer rejection and produces no diagnostic receipt.  This includes pin,
source-closure, memfd, Bubblewrap-exec, pipe-setup, and unreapable-child
failures.

For `diagnose-unsealed`, the only child command remains exactly:

```text
/runtime/node --no-addons --no-global-search-paths validate-static.mjs --mode unsealed
```

It remains in the unchanged CPSB namespace cwd with the existing exact
Bubblewrap construction.  Stdout and stderr are separately read in 4,096-byte
increments with a 65,536-byte ceiling each and a 30-second wall deadline.  The
65,537th byte, or timeout, kills and reaps the child.  A complete EOF record
contains exact `bytes`, lowercase `bytesHex`, and `rawSha256`, plus exact exit
code, signal, and both output totals.  An incomplete record contains only its
retained prefix (`capturedPrefixBytes`, lowercase `prefixHex`, and
`observedPrefixRawSha256`), its `stream-limit` or `timeout` reason, limit, and
`observedAtLeastBytes`; it never calls the prefix a full-output hash.  On a
stream limit, exactly the first 65,536 bytes are retained, `limitedStream`
identifies stdout or stderr, and that stream reports
`observedAtLeastBytes:65537`.  Output bytes are not interpreted as a validator
success condition.

## Reviewed source pins

Only the following source artifacts belong to this diagnostic directory.  No
manifest copy, cache, compiled artifact, or pathname launcher is supplied.

| Artifact | Bytes | Raw SHA-256 | Mode | Links |
| --- | ---: | --- | ---: | ---: |
| `stage0-literal.py` | `10667` | `296f5d71e24bfcb5fc0535bdfc1c1ef4c621379e2785973e1b815172167939cc` | `0644` | `1` |
| `verify-copy.py` | `43078` | `e97071d551056226458c985bd47f96d06e1c0c8779efe311da82ec62ce408a68` | `0644` | `1` |
| production `trust-manifest.v1.json` | `237511` | `8c6ce4d08fd219accac6786257fb58ecd22936cb15dbc49b8de865bb73a9a0de` | `0644` | `1` |

The manifest source path is
`../cpsb-exact27-v1/trust-manifest.v1.json`; it is authenticated by its
unchanged production size/hash and by the copied helper's source-only manifest
checks.  The stage-0 delivery contract is unchanged except that the helper
path points here and the terminal action is one of the two names above.

## P0–P2 control-flow evidence

- **P0, action gate:** stage 0 and the in-memory helper each whitelist only
  `{verify-only, diagnose-unsealed}`.  `validate-unsealed` is absent.
- **P1, unchanged execution construction:** `bwrap_argv`, `parent_directories`,
  source-closure checks, 673 sealed captures, fixed Node path, fixed cwd, and
  the validator argv are retained from the production control flow.
- **P2, nonacceptance:** `diagnose-unsealed` never compares stdout/stderr to an
  expected value, never parses a result as a validation claim, emits its
  receipt, and returns `1` even when the child exits zero.  Limit and timeout
  outcomes are diagnostic receipts after kill/reap; they are never retries.

This directory has been source-inspected and pinned only.  No stage-0,
helper, Bubblewrap, Node, CPSB JavaScript, or test execution is authorized by
this README.
