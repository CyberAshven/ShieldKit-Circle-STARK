import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ENDPOINTS,
  SCHEMA_VERSION,
  assertObservationProjection,
  domainDigest,
  observationRequirementDigest,
} from './model.mjs';
import * as observationBoundary from './observation-boundary.mjs';
import { prepareSnapshotBinding } from './snapshot-boundary.mjs';

const digest = (label) => domainDigest('observation-boundary-test', label);

test('observation boundary exports structural requirements only, with no acceptance callback', () => {
  const binding = prepareSnapshotBinding({
    a0Digest: digest('a0'),
    a1Digest: digest('a1'),
    snapshotDigest: digest('snapshot'),
    valuesRootDigest: digest('root'),
    catalogBindingDigest: digest('catalog'),
    runtimeExecutable: {
      id: '/proc/self/exe',
      role: 'runtime-executable',
      rawSha256: digest('runtime-raw'),
      byteLength: 1,
      stat: { dev: '1', ino: '1', mode: '0600', uid: '1', gid: '1', nlink: '1', size: '1' },
    },
    stdinInputs: ENDPOINTS.map(({ ordinal, id, role }) => ({ ordinal, id, role, codec: 'rows-v1', readyRows: 4608, bytes: Uint8Array.of(ordinal) })),
  });
  const index = { jDigest: digest('j'), headDigest: digest('head'), completedEndpointPrefix: 0, streamBindings: [], indexDigest: digest('index') };
  const requirement = observationBoundary.structuralObservationRequirement(binding, [], index);
  assert.doesNotThrow(() => assertObservationProjection(requirement.projection));
  assert.equal(requirement.requirementDigest, observationRequirementDigest(requirement.projection));
  assert.equal('acceptObservation' in observationBoundary, false);
  assert.equal('mintLiveObservation' in observationBoundary, false);
  assert.equal('assertAcceptedObservation' in observationBoundary, false);
});
