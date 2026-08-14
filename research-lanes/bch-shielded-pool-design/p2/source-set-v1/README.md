# Source set v1

This package mechanically emits deterministic BCH Script assembly, bytecode, and source maps from the exact refreshed lowering-arm IR package. It is source/bytecode artifact provenance only: it does not execute a BCH VM, run a campaign, produce metrics, establish limits or standardness, rank fields or arms, select a protocol, or qualify a construction.

Each of the 42 frozen physical plans has one complete source file, bytecode file, and source map under `plans/`. Every source line is one physical-plan instruction and is assembled only using the pinned Libauth `assembleBytecodeBCH` interface. The validator regenerates the complete authority rather than trusting compact indexes.

The source maps include source/bytecode byte partitions, LF-inclusive per-instruction source-fragment digests, raw per-instruction bytecode-fragment digests, and source-level symbolic stack microtraces. These are a mechanical source-lowering ledger, not BCH-VM execution or a VM-limit proof.
