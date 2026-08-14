/* Public safe façade. Production brands/writers remain private to
 * production-api.mjs, which owns the live filesystem opener. */
export {
  openRetainedDataflowSnapshot,
  isRuntimeAttestation,
  isAuthoritySnapshot,
  validateRuntimeAttestation,
  validateAuthoritySnapshot,
  deriveRecoveryStableProjection,
  deriveSnapshotDigestBinding,
  deriveFixtureRowsFromSnapshot,
  encodeAllEndpointStdin,
  SNAPSHOT_OPEN_BOUNDARY,
} from './production-api.mjs';
