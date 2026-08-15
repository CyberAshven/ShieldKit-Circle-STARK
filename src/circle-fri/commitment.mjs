import {
  M31_MODULUS,
  encodeM31,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  assertBytes,
  concatBytes,
  equalBytes,
  hash256,
  utf8,
} from './bytes.mjs';

export const M31_MERKLE_LEAF_DOMAIN = utf8('ShieldKit/CircleFRI/M31Leaf/v1\0');
export const M31_MERKLE_NODE_DOMAIN = utf8('ShieldKit/CircleFRI/MerkleNode/v1\0');

const fail = (message) => {
  throw new TypeError(message);
};

const assertElement = (value, name) => {
  if (typeof value !== 'bigint' || value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be a canonical M31 element`);
  }
  return value;
};

const isPowerOfTwo = (value) => (
  Number.isSafeInteger(value)
  && value > 0
  && (value & (value - 1)) === 0
);

export const hashM31Leaf = (value) => hash256(concatBytes(
  M31_MERKLE_LEAF_DOMAIN,
  encodeM31(assertElement(value, 'leaf value')),
));

export const hashMerkleNode = (left, right) => {
  const a = assertBytes(left, 'left hash');
  const b = assertBytes(right, 'right hash');
  if (a.length !== 32 || b.length !== 32) fail('Merkle child hashes must be exactly 32 bytes');
  return hash256(concatBytes(M31_MERKLE_NODE_DOMAIN, a, b));
};

export const buildM31MerkleTree = (values) => {
  if (!Array.isArray(values) || !isPowerOfTwo(values.length)) {
    fail('Merkle codeword length must be a positive power of two');
  }
  const codeword = values.map((value, index) => assertElement(value, `values[${index}]`));
  const layers = [codeword.map(hashM31Leaf)];
  while (layers.at(-1).length > 1) {
    const current = layers.at(-1);
    const parent = new Array(current.length / 2);
    for (let index = 0; index < current.length; index += 2) {
      parent[index / 2] = hashMerkleNode(current[index], current[index + 1]);
    }
    layers.push(parent);
  }
  return Object.freeze({
    length: codeword.length,
    root: new Uint8Array(layers.at(-1)[0]),
    layers,
  });
};

export const openM31Merkle = (tree, index) => {
  if (tree === null || typeof tree !== 'object' || !isPowerOfTwo(tree.length) || !Array.isArray(tree.layers)) {
    fail('tree must be an M31 Merkle tree');
  }
  if (!Number.isSafeInteger(index) || index < 0 || index >= tree.length) fail('Merkle index is out of range');
  const siblings = [];
  let currentIndex = index;
  for (let level = 0; level < tree.layers.length - 1; level += 1) {
    const sibling = tree.layers[level][currentIndex ^ 1];
    siblings.push(new Uint8Array(sibling));
    currentIndex = Math.floor(currentIndex / 2);
  }
  return Object.freeze({ index, siblings });
};

export const verifyM31Merkle = ({ root, length, index, value, siblings }) => {
  const expectedRoot = assertBytes(root, 'root');
  if (expectedRoot.length !== 32) fail('Merkle root must be exactly 32 bytes');
  if (!isPowerOfTwo(length)) fail('Merkle length must be a positive power of two');
  if (!Number.isSafeInteger(index) || index < 0 || index >= length) fail('Merkle index is out of range');
  if (!Array.isArray(siblings) || siblings.length !== Math.log2(length)) {
    fail('Merkle path length does not match the committed codeword length');
  }

  let current = hashM31Leaf(assertElement(value, 'value'));
  let currentIndex = index;
  for (let level = 0; level < siblings.length; level += 1) {
    const sibling = assertBytes(siblings[level], `siblings[${level}]`);
    if (sibling.length !== 32) fail(`siblings[${level}] must be exactly 32 bytes`);
    current = (currentIndex & 1) === 0
      ? hashMerkleNode(current, sibling)
      : hashMerkleNode(sibling, current);
    currentIndex = Math.floor(currentIndex / 2);
  }
  return equalBytes(current, expectedRoot);
};
