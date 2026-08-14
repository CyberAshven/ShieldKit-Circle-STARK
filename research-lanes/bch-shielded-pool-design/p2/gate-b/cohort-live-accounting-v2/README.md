# Cohort live accounting v2

Authority-neutral, schema-first grammar for sealing an attempt-001 live failure or recovery from durable checkpoint bytes. It is not authorization, execution evidence, ranking, selection, result reuse, or an executor integration.

The sealed model fixes the five endpoint order, permits one controller or endpoint terminal followed by one recovery-sealed checkpoint, records selected-not-started suffixes, binds exact local authorization and claim copies, and prohibits endpoint reinvocation. Checkpoint digests are append-only and hash chained. Module prefixes bind completed LF rows plus any trailing fragment; external prefixes permit binary partial bytes. A recoverable prefix is deliberately smaller: its exact namespace is only `checkpoint-manifest.v2.json`, canonical checkpoint files, and the manifest-bound durable stream files; it contains neither a sealed root nor copied authorization/claim artifacts.

This package validates only a supplied local container. It reads pinned raw bytes of the fixed v3 authorization and claim schemas solely to enforce their complete closed shapes and framed content digests; it never reads or authenticates a current authorization, epoch, engine, retry wrapper, or run directory. A future authoritative v3 recovery wrapper must authenticate those inputs before calling this structural grammar.
