# B checkpoint ≤ 300000 B

txBytes **298077**. Completeness: FRI9, q=36, vk `circle-fri-m31-t64-b16-q36-g20-fri9`, hash sha256.

Recompile/verify:

```bash
cd research-lanes/envelope-b-standard
npx tsx --test --test-name-pattern 'full-completeness B successor' test/hole-free-b.test.ts
npx tsx scripts/write-artifact-meters.ts
```

standard=true accept: false (Unable to verify standard transaction: transaction exceeds maximum standard byte length. This transaction is 298077 bytes, but the maximum standard transaction size is 100000 bytes.)
consensus accept: true
verifyFri: {"ok":true}
