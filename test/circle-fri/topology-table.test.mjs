import test from 'node:test';
import assert from 'node:assert/strict';

import { binToHex } from '@bitauth/libauth';

import {
  buildCircleFriTopologyTable,
  circleFriTopologyRecordBytes,
  decodeCircleFriTopologyRecord,
  encodeCircleFriTopologyRecord,
  openCircleFriTopologyTable,
  verifyCircleFriTopologyOpening,
} from '../../src/circle-fri/topology-table.mjs';

import { buildMultiQueryKat } from '../../tools/circle-fri-query-kat.mjs';

const parameters = Object.freeze({ logDegreeBound: 6, logBlowup: 3, queryCount: 4 });
const table = buildCircleFriTopologyTable(parameters);

test('fixed Circle-FRI topology table commits every possible query plan', () => {
  assert.equal(table.length, 512);
  assert.equal(table.recordBytes, circleFriTopologyRecordBytes(table.parameters));
  assert.equal(table.recordBytes, 140);
  assert.equal(binToHex(table.root), 'f39fba6d590dccfe807192b216d31f5505507ea7dbe1f039fb55f238263c0820');
});

test('topology records canonically round-trip and bind fold indices and coordinates', () => {
  for (const queryIndex of [0, 1, 161, 204, 371, 419, 511]) {
    const decoded = decodeCircleFriTopologyRecord(table.records[queryIndex]);
    assert.equal(decoded.queryIndex, queryIndex);
    assert.deepEqual(encodeCircleFriTopologyRecord(decoded), table.records[queryIndex]);
    let currentIndex = queryIndex;
    for (const round of decoded.rounds) {
      assert.equal(round.currentIndex, currentIndex);
      assert.ok(round.currentIndex === round.leftIndex || round.currentIndex === round.rightIndex);
      assert.equal(round.nextIndex, Math.min(round.leftIndex, round.rightIndex));
      assert.equal(round.continuitySide, round.round === 0 ? 0 : (round.currentIndex === round.leftIndex ? 1 : 2));
      currentIndex = round.nextIndex;
    }
  }
});

test('topology openings bind the record, query index, and complete path', () => {
  for (const queryIndex of [0, 161, 371, 511]) {
    const opening = openCircleFriTopologyTable(table, queryIndex);
    assert.equal(verifyCircleFriTopologyOpening({
      root: table.root,
      parameters: table.parameters,
      ...opening,
    }), true);

    const wrongRecord = new Uint8Array(opening.record);
    wrongRecord[10] ^= 1;
    assert.equal(verifyCircleFriTopologyOpening({
      root: table.root,
      parameters: table.parameters,
      ...opening,
      record: wrongRecord,
    }), false);

    const wrongPath = structuredClone(opening.siblings);
    wrongPath[0][0] ^= 1;
    assert.equal(verifyCircleFriTopologyOpening({
      root: table.root,
      parameters: table.parameters,
      ...opening,
      siblings: wrongPath,
    }), false);
  }
});

test('committed topology plans exactly match independently lowered query fixtures', () => {
  const kat = buildMultiQueryKat();
  for (const fixture of kat.fixtures) {
    const record = decodeCircleFriTopologyRecord(table.records[fixture.initialQueryIndex]);
    assert.equal(record.rounds.length, fixture.rounds.length);
    for (let round = 0; round < fixture.rounds.length; round += 1) {
      assert.equal(record.rounds[round].leftIndex, fixture.rounds[round].leftIndex);
      assert.equal(record.rounds[round].rightIndex, fixture.rounds[round].rightIndex);
      assert.equal(record.rounds[round].coordinate, fixture.rounds[round].coordinate);
      assert.equal(record.rounds[round].continuitySide, fixture.rounds[round].continuitySide === null
        ? 0
        : (fixture.rounds[round].continuitySide === 'left' ? 1 : 2));
    }
    assert.equal(record.rounds.at(-1).nextIndex, fixture.finalIndex);
  }
});
