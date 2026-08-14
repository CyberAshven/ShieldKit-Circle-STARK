import {
  observationProjection,
  observationRequirementDigest,
} from './model.mjs';

// Static v1 describes only what a future private observation brand must bind.
// It deliberately has no predicate, receipt acceptance, accepted-object shape,
// or brand-minting surface.
export function structuralObservationRequirement(binding, entries, journalIndex) {
  const projection = observationProjection(binding, entries, journalIndex);
  return Object.freeze({
    projection,
    requirementDigest: observationRequirementDigest(projection),
  });
}
