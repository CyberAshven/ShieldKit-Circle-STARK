import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateRabinCertificate } from '../node/generate.mjs';
import { replayRabinCertificate } from '../node/replay.mjs';

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
export const repoRoot = resolve(moduleDirectory, '../../../../../');

export const REPOSITORY_ENVIRONMENT = Object.freeze({
  nodeVersion: 'v22.23.1',
  platform: 'linux',
  arch: 'x64',
  policy: 'certificate bytes are frozen for this recorded environment; a runtime mismatch is diagnostic and fail-closed for promotion, never silently incorporated into canonical bytes'
});

export const currentEnvironmentMismatches = () => {
  const current = { nodeVersion: process.version, platform: process.platform, arch: process.arch };
  return Object.keys(current).filter((key) => current[key] !== REPOSITORY_ENVIRONMENT[key]).map((key) => `${key}:recorded=${REPOSITORY_ENVIRONMENT[key]} current=${current[key]}`);
};

export const CONSTRUCTIONS = Object.freeze([
  Object.freeze({ constructionId: 'algebra-construction:m89-d2-x2-plus-1-v1', certificateEntryId: 'certificate-entry:m89-d2-x2-plus-1-v1', fieldSpecRef: 'field-spec:m89-d2', q: 89, degree: 2, polynomial: Object.freeze(['1', '0', '1']) }),
  Object.freeze({ constructionId: 'algebra-construction:m61-d3-x3-minus-5-v1', certificateEntryId: 'certificate-entry:m61-d3-x3-minus-5-v1', fieldSpecRef: 'field-spec:m61-d3', q: 61, degree: 3, polynomial: Object.freeze(['2305843009213693946', '0', '0', '1']) }),
  Object.freeze({ constructionId: 'algebra-construction:m31-d5-x5-plus-2x-minus-1-v1', certificateEntryId: 'certificate-entry:m31-d5-x5-plus-2x-minus-1-v1', fieldSpecRef: 'field-spec:m31-d5', q: 31, degree: 5, polynomial: Object.freeze(['2147483646', '2', '0', '0', '0', '1']) }),
  Object.freeze({ constructionId: 'algebra-construction:m31-d6-x6-minus-5-v1', certificateEntryId: 'certificate-entry:m31-d6-x6-minus-5-v1', fieldSpecRef: 'field-spec:m31-d6', q: 31, degree: 6, polynomial: Object.freeze(['2147483642', '0', '0', '0', '0', '0', '1']) })
]);

export const INPUT_BINDINGS = Object.freeze([
  Object.freeze({ path: 'research-lanes/bch-shielded-pool-design/p2/construction-freeze/construction-freeze.v1.json', schema: 'shieldkit-labs/p2/construction-freeze/v1', schemaPath: 'research-lanes/bch-shielded-pool-design/p2/construction-freeze/construction-freeze.v1.schema.json', schemaSha256: '86fc5e3ca1f26e813a07c12975aec15f5421e6692ed2082eb1b8f40b8ce16fb6', fileSha256: '5b276ff979fdb61c5919ef74c324cd62295fec99a8f2e9f5455f3adfdac237bc', contentDigest: '9737fb064d3b706835e441ec0b4d15aefb743fb62b098d4d3692321050e83137' }),
  Object.freeze({ path: 'research-lanes/bch-shielded-pool-design/p2/construction-freeze/construction-freeze.normalized-transcript.v1.json', schema: 'shieldkit-labs/p2/construction-freeze-normalized-transcript/v1', schemaPath: 'research-lanes/bch-shielded-pool-design/p2/construction-freeze/construction-freeze-normalized-transcript.v1.schema.json', schemaSha256: '1d3ea6e7c1136f04e8bcebff211f57761c030add9f274c6b548596eead5492cf', fileSha256: '58edd442a8700d9d2014f8d238ea6d7116e64baa427b3c89c33bc9d4878c20fe', contentDigest: '8eb2039920ae163c3584ca7a4b55ab5804f836760420b9cda185c4487ecf0dea' }),
  Object.freeze({ path: 'research-lanes/bch-shielded-pool-design/p2/schedule-freeze/schedule-freeze.v1.json', schema: 'shieldkit-labs/p2/schedule-freeze/v1', schemaPath: 'research-lanes/bch-shielded-pool-design/p2/schedule-freeze/schedule-freeze.v1.schema.json', schemaSha256: 'ce75be25b66c8663c4d1f71e98485713afe66454fb8e283bab468834df719f6a', fileSha256: 'b96da97b99bcf45f34b77ea66c0e44192533634f10a48af1c889b8d0e1fdb173', contentDigest: '099bfc6ea2b571829985f74d62e5138a948d977c7f00e2a2eec94e7d643fae6c' })
]);

export const IMPORTED_SOURCE_BINDINGS = Object.freeze([
  Object.freeze({ path: 'research-lanes/bch-shielded-pool-design/p2/field-cert/node/generate.mjs', sha256: '664b06ebde52749620e506cdc6fd04e024b87e0753768d4644ee22303d6bae71' }),
  Object.freeze({ path: 'research-lanes/bch-shielded-pool-design/p2/field-cert/node/replay.mjs', sha256: 'b2ff5132e26c3c1aff24488cabf82664eb4ae17c80aa4a8e00c328100a0e7247' }),
  Object.freeze({ path: 'research-lanes/bch-shielded-pool-design/p2/field-cert/node/canonical.mjs', sha256: '396dbbc73d956d040dba952b3bb98b98898075fde24c4782badb87de800c0f23' }),
  Object.freeze({ path: 'research-lanes/bch-shielded-pool-design/p2/field-cert/node/fp-polynomial.mjs', sha256: 'a6b35ead871add9fe7ed3ae77497e9ba0111d17de20c8ad60537d277fba97cb9' }),
  Object.freeze({ path: 'research-lanes/bch-shielded-pool-design/p2/field-cert/node/mersenne.mjs', sha256: '8d9c5eaae0105c2b29d32c82d30532e89046a71a977cbf0c54feabbe393e077b' })
]);

const canonicalize = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
};

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const contentDigestFor = (value) => {
  const clone = structuredClone(value);
  delete clone.contentDigest;
  return sha256(canonicalize(clone));
};
export const canonicalJson = (value) => `${JSON.stringify(value, null, 2)}\n`;

const repoPath = (relativePath) => resolve(repoRoot, relativePath);
const readRepoJson = (relativePath) => JSON.parse(readFileSync(repoPath(relativePath), 'utf8'));
const assertEqual = (actual, expected, message) => {
  if (actual !== expected) throw new Error(`${message}: expected ${expected}, got ${actual}`);
};

export const verifyInputBindings = () => {
  const inputs = [];
  for (const binding of INPUT_BINDINGS) {
    const path = repoPath(binding.path);
    if (!existsSync(path)) throw new Error(`missing bound input ${binding.path}`);
    const bytes = readFileSync(path);
    const schemaPath = repoPath(binding.schemaPath);
    if (!existsSync(schemaPath)) throw new Error(`missing bound schema ${binding.schemaPath}`);
    const schemaBytes = readFileSync(schemaPath);
    assertEqual(sha256(schemaBytes), binding.schemaSha256, `${binding.schemaPath} schema digest`);
    JSON.parse(schemaBytes.toString('utf8'));
    assertEqual(sha256(bytes), binding.fileSha256, `${binding.path} file digest`);
    const value = JSON.parse(bytes.toString('utf8'));
    assertEqual(value.schema, binding.schema, `${binding.path} schema`);
    const storedContentDigest = typeof value.contentDigest === 'string' ? value.contentDigest : value.contentDigest?.value;
    assertEqual(storedContentDigest, binding.contentDigest, `${binding.path} content digest`);
    assertEqual(contentDigestFor(value), binding.contentDigest, `${binding.path} recomputed content digest`);
    inputs.push({ ...binding, byteCount: bytes.length, schemaByteCount: schemaBytes.length });
  }
  const schedule = readRepoJson(INPUT_BINDINGS[2].path);
  if (!Array.isArray(schedule.fieldConstructions) || schedule.fieldConstructions.length !== CONSTRUCTIONS.length) throw new Error('schedule field-construction inventory mismatch');
  for (let index = 0; index < CONSTRUCTIONS.length; index += 1) {
    const expected = CONSTRUCTIONS[index];
    const actual = schedule.fieldConstructions[index];
    assertEqual(actual.constructionId, expected.constructionId, `schedule construction ${index} id`);
    assertEqual(actual.fieldSpecRef, expected.fieldSpecRef, `schedule construction ${index} field spec`);
    assertEqual(actual.q, expected.q, `schedule construction ${index} q`);
    assertEqual(actual.degree, expected.degree, `schedule construction ${index} degree`);
    if (canonicalize(actual.definingPolynomialAscending) !== canonicalize(expected.polynomial)) throw new Error(`schedule construction ${index} polynomial mismatch`);
  }
  return inputs;
};

export const verifyImportedSourceBindings = () => {
  for (const binding of IMPORTED_SOURCE_BINDINGS) {
    const path = repoPath(binding.path);
    if (!existsSync(path)) throw new Error(`missing imported source ${binding.path}`);
    assertEqual(sha256(readFileSync(path)), binding.sha256, `${binding.path} source digest`);
  }
  return true;
};

const certificateEntry = (construction, certificate) => ({
  certificateEntryId: construction.certificateEntryId,
  constructionId: construction.constructionId,
  fieldSpecRef: construction.fieldSpecRef,
  q: construction.q,
  degree: construction.degree,
  p: certificate.modulus,
  polynomialCanonical: construction.polynomial,
  certificateId: certificate.certificateId,
  certificateDigest: sha256(canonicalize(certificate)),
  replayPassed: replayRabinCertificate(certificate),
  establishes: 'base-prime-and-direct-polynomial-irreducibility-only-if-replay-passes',
  certificate
});

export const generateCertificates = () => CONSTRUCTIONS.map((construction) => {
  const certificate = generateRabinCertificate({ mersenneExponent: String(construction.q), polynomialCoefficients: construction.polynomial });
  return certificateEntry(construction, certificate);
});

export const rawReplayReportFor = (artifact) => {
  const lines = [
    'DIRECT-CONSTRUCTION-COHORT-V2 REPOSITORY RAW REPLAY REPORT',
    `artifactId=${artifact.artifactId}`,
    `certificateCount=${artifact.certificates.length}`
  ];
  artifact.certificates.forEach((entry, index) => {
    const replayPassed = replayRabinCertificate(entry.certificate);
    lines.push(`${replayPassed ? 'PASS' : 'FAIL'} index=${index} constructionId=${entry.constructionId} certificateId=${entry.certificateId} certificateDigest=${entry.certificateDigest}`);
  });
  const allPassed = artifact.certificates.every((entry) => replayRabinCertificate(entry.certificate));
  lines.push(`status=${allPassed ? 'all-repository-replays-passed' : 'repository-replay-failed'}`);
  return `${lines.join('\n')}\n`;
};

export const generateCertificateSet = () => {
  const inputs = verifyInputBindings();
  const certificates = generateCertificates();
  if (certificates.some((entry) => entry.replayPassed !== true)) throw new Error('generated certificate set contains a failed repository replay');
  const report = rawReplayReportFor({ artifactId: 'direct-construction-cohort-v2', certificates });
  const artifact = {
    schema: 'shieldkit-labs/p2/direct-construction-cohort-v2/v2',
    artifactId: 'direct-construction-cohort-v2',
    status: 'generic-math-certificate-set-frozen',
    evidenceClassification: 'not-evidence',
    selection: 'none',
    tupleRef: null,
    protocolBoundary: 'component-only',
    boundary: {
      permittedConclusion: 'base-prime-and-direct-polynomial-irreducibility-only-if-replay-passes',
      prohibitedConclusion: 'no-BCH-cost-field-family-proof-system-protocol-Circle-domain-or-systemic-soundness-conclusion'
    },
    inputBindings: inputs,
    scheduleOrder: CONSTRUCTIONS.map(({ constructionId, certificateEntryId, fieldSpecRef, q, degree, polynomial }) => ({ constructionId, certificateEntryId, fieldSpecRef, q, degree, polynomialCanonical: polynomial })),
    importedSourceBindings: IMPORTED_SOURCE_BINDINGS,
    repositoryEnvironment: REPOSITORY_ENVIRONMENT,
    toolBinding: {
      generatorCommand: 'node generate.mjs',
      replayCommand: 'node repository-replay.mjs direct-construction-cohort-v2.v2.json'
    },
    replayReportBinding: {
      path: 'repository-replay-report.v2.txt',
      byteCount: Buffer.byteLength(report),
      sha256: sha256(Buffer.from(report, 'utf8'))
    },
    certificates,
    contentDigest: null
  };
  artifact.contentDigest = contentDigestFor(artifact);
  return { artifact, report };
};

export const verifyCertificateSet = (artifact) => {
  if (artifact.schema !== 'shieldkit-labs/p2/direct-construction-cohort-v2/v2' || artifact.status !== 'generic-math-certificate-set-frozen' || artifact.evidenceClassification !== 'not-evidence' || artifact.selection !== 'none' || artifact.tupleRef !== null || artifact.protocolBoundary !== 'component-only') throw new Error('certificate-set boundary mismatch');
  if (artifact.contentDigest !== contentDigestFor(artifact)) throw new Error('certificate-set content digest mismatch');
  if (canonicalize(artifact.repositoryEnvironment) !== canonicalize(REPOSITORY_ENVIRONMENT)) throw new Error('certificate-set repository environment mismatch');
  if (canonicalize(artifact.toolBinding) !== canonicalize({ generatorCommand: 'node generate.mjs', replayCommand: 'node repository-replay.mjs direct-construction-cohort-v2.v2.json' })) throw new Error('certificate-set tool binding mismatch');
  if (canonicalize(artifact.inputBindings) !== canonicalize(verifyInputBindings())) throw new Error('certificate-set input binding mismatch');
  if (canonicalize(artifact.importedSourceBindings) !== canonicalize(IMPORTED_SOURCE_BINDINGS)) throw new Error('certificate-set imported source binding mismatch');
  verifyImportedSourceBindings();
  if (canonicalize(artifact.scheduleOrder) !== canonicalize(CONSTRUCTIONS.map(({ constructionId, certificateEntryId, fieldSpecRef, q, degree, polynomial }) => ({ constructionId, certificateEntryId, fieldSpecRef, q, degree, polynomialCanonical: polynomial })))) throw new Error('certificate-set schedule binding mismatch');
  const expectedReport = rawReplayReportFor(artifact);
  if (artifact.replayReportBinding.path !== 'repository-replay-report.v2.txt' || artifact.replayReportBinding.byteCount !== Buffer.byteLength(expectedReport) || artifact.replayReportBinding.sha256 !== sha256(Buffer.from(expectedReport, 'utf8'))) throw new Error('certificate-set replay report binding mismatch');
  const reportPath = resolve(moduleDirectory, artifact.replayReportBinding.path);
  if (!existsSync(reportPath) || readFileSync(reportPath, 'utf8') !== expectedReport) throw new Error('repository replay report bytes mismatch');
  if (artifact.certificates.length !== CONSTRUCTIONS.length) throw new Error('certificate count mismatch');
  artifact.certificates.forEach((entry, index) => {
    const expected = CONSTRUCTIONS[index];
    assertEqual(entry.constructionId, expected.constructionId, `certificate ${index} construction`);
    assertEqual(entry.certificateEntryId, expected.certificateEntryId, `certificate ${index} entry identity`);
    assertEqual(entry.fieldSpecRef, expected.fieldSpecRef, `certificate ${index} field spec`);
    assertEqual(entry.q, expected.q, `certificate ${index} q`);
    assertEqual(entry.degree, expected.degree, `certificate ${index} degree`);
    assertEqual(entry.certificateId, entry.certificate.certificateId, `certificate ${index} certificate id binding`);
    assertEqual(entry.establishes, 'base-prime-and-direct-polynomial-irreducibility-only-if-replay-passes', `certificate ${index} establishes`);
    if (canonicalize(entry.polynomialCanonical) !== canonicalize(expected.polynomial)) throw new Error(`certificate ${index} polynomial binding mismatch`);
    if (entry.certificate.modulus !== entry.p || entry.certificate.mersennePrimeCheck.modulus !== entry.p) throw new Error(`certificate ${index} modulus binding mismatch`);
    if (canonicalize(entry.certificate.polynomial) !== canonicalize(expected.polynomial)) throw new Error(`certificate ${index} certificate polynomial mismatch`);
    if (entry.certificate.degree !== String(expected.degree) || entry.certificate.certificateId !== `certificate:mersenne-q${expected.q}-d${expected.degree}-rabin`) throw new Error(`certificate ${index} identity mismatch`);
    assertEqual(entry.certificateDigest, sha256(canonicalize(entry.certificate)), `certificate ${index} digest`);
    if (!replayRabinCertificate(entry.certificate) || entry.replayPassed !== true) throw new Error(`certificate ${index} repository replay failed`);
  });
  const regenerated = generateCertificateSet();
  if (canonicalize(artifact) !== canonicalize(regenerated.artifact)) throw new Error('certificate-set differs from independently regenerated expected artifact');
  if (expectedReport !== regenerated.report) throw new Error('certificate-set report differs from independently regenerated expected report');
  return true;
};
