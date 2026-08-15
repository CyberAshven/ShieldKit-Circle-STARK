import test from 'node:test';
import assert from 'node:assert/strict';

import {
  M31_MODULUS,
  bytesToHex,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  buildM31MerkleTree,
  openM31Merkle,
  verifyM31Merkle,
} from '../../src/circle-fri/commitment.mjs';

import {
  CircleFriTranscript,
  sampleUniformUint32,
} from '../../src/circle-fri/transcript.mjs';

test('domain-separated M31 Merkle tree has a fixed known root', () => {
  const values = [0n, 1n, 2n, 3n, 5n, 8n, 13n, M31_MODULUS - 1n];
  const tree = buildM31MerkleTree(values);
  assert.equal(tree.length, 8);
  assert.equal(bytesToHex(tree.root), '0faf1f54a22311b21705116b0fa2fe36b454b0f5e2198191bc44462bb168ddc3');
});

test('Merkle openings bind position, value, and complete path', () => {
  const values = Array.from({ length: 32 }, (_, index) => BigInt(index * index + 17));
  const tree = buildM31MerkleTree(values);
  for (const index of [0, 1, 7, 16, 31]) {
    const opening = openM31Merkle(tree, index);
    assert.equal(verifyM31Merkle({
      root: tree.root,
      length: tree.length,
      index,
      value: values[index],
      siblings: opening.siblings,
    }), true);
    assert.equal(verifyM31Merkle({
      root: tree.root,
      length: tree.length,
      index,
      value: values[index] + 1n,
      siblings: opening.siblings,
    }), false);
  }
  const reordered = values.slice();
  [reordered[3], reordered[4]] = [reordered[4], reordered[3]];
  assert.notDeepEqual(buildM31MerkleTree(reordered).root, tree.root);
});

test('Merkle verifier rejects malformed tree metadata and hashes', () => {
  const tree = buildM31MerkleTree([1n, 2n, 3n, 4n]);
  const opening = openM31Merkle(tree, 0);
  assert.throws(() => buildM31MerkleTree([1n, 2n, 3n]), /power of two/);
  assert.throws(() => openM31Merkle(tree, 4), /out of range/);
  assert.throws(() => verifyM31Merkle({
    root: tree.root,
    length: 4,
    index: 0,
    value: 1n,
    siblings: opening.siblings.slice(1),
  }), /path length/);
  const malformed = opening.siblings.slice();
  malformed[0] = new Uint8Array(31);
  assert.throws(() => verifyM31Merkle({
    root: tree.root,
    length: 4,
    index: 0,
    value: 1n,
    siblings: malformed,
  }), /exactly 32/);
});

test('transcript is deterministic and binds labels, order, and context', () => {
  const run = (context, reverse = false) => {
    const transcript = new CircleFriTranscript(Uint8Array.of(context));
    const items = reverse
      ? [['second', Uint8Array.of(4, 5)], ['first', Uint8Array.of(1, 2, 3)]]
      : [['first', Uint8Array.of(1, 2, 3)], ['second', Uint8Array.of(4, 5)]];
    for (const [label, bytes] of items) transcript.absorb(label, bytes);
    return {
      beta: transcript.challengeField('fold-beta-0'),
      index: transcript.challengeIndex('query-index-0', 1024),
      digest: bytesToHex(transcript.digest),
    };
  };
  assert.deepEqual(run(7), run(7));
  assert.notDeepEqual(run(7), run(8));
  assert.notDeepEqual(run(7), run(7, true));
});

test('field and index sampling rejects incomplete u32 tails without modulo bias', () => {
  const m31Draws = [0xffff_ffff, 0xffff_fffe, 0xffff_fffd];
  const m31 = sampleUniformUint32({
    upperBound: Number(M31_MODULUS),
    draw: (attempt) => m31Draws[attempt],
  });
  assert.deepEqual(m31, {
    value: Number(M31_MODULUS - 1n),
    candidate: 0xffff_fffd,
    attempt: 2,
    acceptanceBound: 0xffff_fffe,
  });

  const rangeTen = sampleUniformUint32({
    upperBound: 10,
    draw: (attempt) => [0xffff_ffff, 0xffff_fffa, 123][attempt],
  });
  assert.equal(rangeTen.value, 3);
  assert.equal(rangeTen.attempt, 2);
  assert.equal(rangeTen.acceptanceBound, 4_294_967_290);
});
