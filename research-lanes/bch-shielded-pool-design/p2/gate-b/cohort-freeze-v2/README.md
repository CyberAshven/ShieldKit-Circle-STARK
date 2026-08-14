# Gate-B0 cohort freeze v2

This package freezes the inputs and execution order for the equal-relation
extension-field comparison. It does not contain BCH VM results, measurements,
rankings, a selected field, or a Circle-FRI parameter set.

The immutable comparison population is:

- four certified direct field constructions;
- fourteen canonical or optimized arithmetic arms;
- three relations per arm (`E-MAC`, `E-SQUARE-MAC`, and
  `E-INVERSE-CHECK`);
- 1,288 canonical construction cases;
- 4,732 arm/case fixtures per engine; and
- four engine surfaces, for 18,928 terminal work items.

Each fixture is an isolated one-input/one-output P2SH32 transaction derived
from exact raw operands and exact source-set-v1 bytecode. Fixture roster
records contain byte lengths and hashes, not raw transaction or operand hex.
They are component inputs, not complete pool-action transactions.

The shared epoch is deliberately unexecuted. Its physical policy is one
engine-major batch at a time, no warmups, no automatic retries, no timing
metrics, and fail-closed accounting for unsupported or incomplete cells. A
later executor must use these exact files and emit a new evidence package; it
may not mutate this package in response to observed results.

The 10,000-byte verified-script ceiling is applied as a preflight gate. At
least the M31 degree-6 direct-Toom-6 `E-MAC` plan is already ineligible for a
verified BCH path because its redeem bytecode is 10,374 bytes. This eliminates
that plan/action pairing only; it does not rank fields or select an
architecture.

Run the deterministic materialization and static validation with the command
in `COMMAND.txt`. No command in this package executes a BCH VM.
