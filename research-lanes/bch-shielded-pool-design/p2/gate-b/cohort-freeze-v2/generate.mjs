import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildCampaign, buildCorpus } from './campaign-corpus.mjs';
import {
  ENGINE_CAPABILITIES,
  buildExecutionEpoch,
  buildWorkItemRoster,
  canonicalJson,
  deriveArmCatalog,
  sha256,
} from './epoch.mjs';
import { FIXTURE_ARTIFACT_ID } from './execution-fixture.mjs';
import {
  buildAttestationRequirements,
  buildEngineArtifactRecords,
  snapshotExecutionSurfaces,
} from './engine-snapshot.mjs';
import { buildFixtureRoster } from './fixture-roster.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../../../../..');
const lane = resolve(here, '../../..');
const packagePrefix = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2';
const sourceSetRelative = 'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.json';
const sourceSetSchemaRelative = 'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.schema.json';
const profileRelative = 'research-lanes/bch-shielded-pool-design/profiles/bch-current-2026-08-08.json';
const campaignRelative = `${packagePrefix}/campaign.v2.json`;
const campaignSchemaRelative = `${packagePrefix}/campaign.v2.schema.json`;
const corpusRelative = `${packagePrefix}/canonical-corpus.v2.json`;
const corpusSchemaRelative = `${packagePrefix}/canonical-corpus.v2.schema.json`;
const fixtureDerivationRelative = `${packagePrefix}/execution-fixture.mjs`;
const fixtureRosterRelative = `${packagePrefix}/fixture-roster.v2.json`;
const fixtureRosterSchemaRelative = `${packagePrefix}/fixture-roster.v2.schema.json`;
const workRosterRelative = `${packagePrefix}/work-item-roster.v2.json`;
const workRosterSchemaRelative = `${packagePrefix}/work-item-roster.v2.schema.json`;
const epochRelative = `${packagePrefix}/execution-epoch.v2.json`;
const epochSchemaRelative = `${packagePrefix}/execution-epoch.v2.schema.json`;
const engineSchemaRelative = `${packagePrefix}/engine.v2.schema.json`;
const engineSchemaSha256 = () => rawSha(engineSchemaRelative);

const generatedPaths = Object.freeze([
  'campaign.v2.json',
  'canonical-corpus.v2.json',
  'engines/native.v2.json',
  'engines/libauth.v2.json',
  'engines/bchn.v2.json',
  'engines/leanbch.v2.json',
  'fixture-roster.v2.json',
  'work-item-roster.v2.json',
  'execution-epoch.v2.json',
]);

const staticPaths = Object.freeze([
  'README.md',
  'COMMAND.txt',
  'generate.mjs',
  'validate.mjs',
  'cohort-freeze-v2.test.mjs',
  'manifest.v1.schema.json',
  'campaign-corpus.mjs',
  'campaign-corpus.test.mjs',
  'campaign.v2.schema.json',
  'canonical-corpus.v2.schema.json',
  'epoch.mjs',
  'epoch.test.mjs',
  'execution-epoch.v2.schema.json',
  'work-item-roster.v2.schema.json',
  'execution-fixture.mjs',
  'execution-fixture.test.mjs',
  'engine-snapshot.mjs',
  'engine.v2.schema.json',
  'fixture-roster.mjs',
  'fixture-roster.test.mjs',
  'fixture-roster.v2.schema.json',
  'build-logs/preflight.txt',
  'build-logs/after.txt',
  'build-logs/native-libauth-integrity.txt',
  'build-logs/bchn-build.exitcode',
  'build-logs/bchn-build.stdout.log',
  'build-logs/bchn-build.stderr.log',
  'build-logs/lean-ffi-build.exitcode',
  'build-logs/lean-ffi-build.stdout.log',
  'build-logs/lean-ffi-build.stderr.log',
  'build-logs/lean-lake-build.exitcode',
  'build-logs/lean-lake-build.stdout.log',
  'build-logs/lean-lake-build.stderr.log',
]);

const fail = (message) => { throw new Error(`cohort-freeze-v2 generator: ${message}`); };
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const exactBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const canonicalBytes = (value) => Buffer.from(canonicalJson(value), 'utf8');
const rawDigest = (value) => ({ algorithm: 'sha256', preimage: 'exact-file-bytes', value: sha256(value) });

const assertContained = (root, candidatePath, { mustExist = true } = {}) => {
  if (typeof candidatePath !== 'string' || candidatePath.length === 0 || isAbsolute(candidatePath)) fail(`unsafe path ${String(candidatePath)}`);
  const rootReal = realpathSync(root);
  const absolute = resolve(rootReal, candidatePath);
  if (absolute !== rootReal && !absolute.startsWith(`${rootReal}${sep}`)) fail(`path escapes root: ${candidatePath}`);
  const parts = relative(rootReal, absolute).split(sep).filter(Boolean);
  let cursor = rootReal;
  for (let index = 0; index < parts.length - (mustExist ? 0 : 1); index += 1) {
    cursor = resolve(cursor, parts[index]);
    if (!existsSync(cursor)) fail(`missing path component: ${candidatePath}`);
    if (lstatSync(cursor).isSymbolicLink()) fail(`symlink component rejected: ${candidatePath}`);
  }
  if (mustExist) {
    if (!existsSync(absolute) || lstatSync(absolute).isSymbolicLink() || !lstatSync(absolute).isFile()) fail(`regular file required: ${candidatePath}`);
    const real = realpathSync(absolute);
    if (real !== rootReal && !real.startsWith(`${rootReal}${sep}`)) fail(`realpath escapes root: ${candidatePath}`);
    return real;
  }
  const parent = dirname(absolute);
  if (!existsSync(parent) || lstatSync(parent).isSymbolicLink()) fail(`safe output parent required: ${candidatePath}`);
  return absolute;
};

const repoFile = (relativePath) => assertContained(repo, relativePath);
const packageFile = (relativePath) => assertContained(here, relativePath);
const packageOutput = (relativePath) => assertContained(here, relativePath, { mustExist: false });
const rawSha = (relativePath) => sha256(readFileSync(repoFile(relativePath)));

const logBinding = (name) => {
  const value = readFileSync(packageFile(`build-logs/${name}`));
  return { name, byteLength: value.length, rawSha256: sha256(value) };
};
const exitCodeFromLog = (name) => {
  const line = readFileSync(packageFile(`build-logs/${name}`), 'utf8').split('\n', 1)[0];
  if (!/^\d+$/u.test(line)) fail(`${name} must begin with a decimal exit code`);
  return Number(line);
};
const domainDigest = (domain, value) => ({
  algorithm: 'sha256',
  canonicalization: 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1',
  domain,
  frame: 'utf8(domain)||0x00||canonical-json-utf8',
  value: sha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.of(0), canonicalBytes(value)])),
});

const buildAttestations = (snapshot) => {
  const requirements = buildAttestationRequirements({ snapshot });
  const record = (engineId, logNames, exitLogNames) => {
    const logs = logNames.map(logBinding);
    const domain = `shieldkit-labs/p2/gate-b/execution-epoch/v2/build-attestation/${engineId}/logs`;
    return {
      schema: 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/build-attestation/v1',
      engineId,
      status: 'fresh-build-attested-unexecuted',
      evidenceClassification: 'build-attestation-only-not-vm-evidence',
      executionAllowed: false,
      vmEvidence: null,
      ...requirements[engineId],
      exitCode: 0,
      exitCodes: exitLogNames.map(exitCodeFromLog),
      logs,
      logDigest: domainDigest(domain, logs),
    };
  };
  return {
    'engine:bchn': record(
      'engine:bchn',
      ['preflight.txt', 'bchn-build.exitcode', 'bchn-build.stdout.log', 'bchn-build.stderr.log', 'after.txt'],
      ['bchn-build.exitcode'],
    ),
    'engine:leanbch': record(
      'engine:leanbch',
      [
        'preflight.txt',
        'lean-ffi-build.exitcode',
        'lean-ffi-build.stdout.log',
        'lean-ffi-build.stderr.log',
        'lean-lake-build.exitcode',
        'lean-lake-build.stdout.log',
        'lean-lake-build.stderr.log',
        'after.txt',
      ],
      ['lean-ffi-build.exitcode', 'lean-lake-build.exitcode'],
    ),
  };
};

const descriptorMap = (sourceSet, campaign) => {
  const out = new Map();
  for (const arm of deriveArmCatalog(sourceSet).filter((entry) => entry.trackId === 'track:optimized')) {
    const descriptor = campaign.bindings.descriptors.find((entry) => entry.id.includes(arm.constructionTag));
    if (!descriptor) fail(`missing descriptor for ${arm.armId}`);
    out.set(arm.armId, descriptor.contentDigest);
  }
  return out;
};

const bindingInput = ({ value, artifactId, path, rawSha256, schemaSha256, contentDigest }) => ({
  ...value,
  artifactId,
  path,
  rawSha256,
  ...(schemaSha256 === undefined ? {} : { schemaSha256 }),
  ...(contentDigest === undefined ? {} : { contentDigest }),
});

const materializeArtifacts = ({ snapshot: providedSnapshot = null } = {}) => {
  const output = new Map();
  const campaign = buildCampaign();
  const corpus = buildCorpus(campaign);
  const campaignRaw = exactBytes(campaign);
  const corpusRaw = exactBytes(corpus);
  output.set('campaign.v2.json', campaignRaw);
  output.set('canonical-corpus.v2.json', corpusRaw);

  const sourceSet = readJson(repoFile(sourceSetRelative));
  const sourceSetRawSha256 = rawSha(sourceSetRelative);
  const sourceSetSchemaSha256 = rawSha(sourceSetSchemaRelative);
  const descriptors = descriptorMap(sourceSet, campaign);

  const snapshot = providedSnapshot ?? snapshotExecutionSurfaces();
  const engineArtifacts = buildEngineArtifactRecords({ snapshot, buildAttestations: buildAttestations(snapshot) });
  const engineBindings = [];
  for (const artifact of engineArtifacts) {
    const short = artifact.engineId.slice('engine:'.length);
    const path = `engines/${short}.v2.json`;
    const bytes = canonicalBytes(artifact);
    output.set(path, bytes);
    engineBindings.push({
      engineId: artifact.engineId,
      artifactId: artifact.artifactId,
      path: artifact.path,
      rawSha256: sha256(bytes),
      contentDigest: artifact.contentDigest.value,
      schemaSha256: engineSchemaSha256(),
      capabilityStatus: artifact.capabilityStatus,
      role: artifact.role,
      capabilities: structuredClone(ENGINE_CAPABILITIES),
    });
  }

  const workItemRosterSchemaSha256 = rawSha(workRosterSchemaRelative);
  const workItemRoster = buildWorkItemRoster({
    sourceSet,
    corpus,
    descriptors,
    engineRecords: engineBindings,
    schemaSha256: workItemRosterSchemaSha256,
  });
  const workItemRosterRaw = canonicalBytes(workItemRoster);
  output.set('work-item-roster.v2.json', workItemRosterRaw);

  const fixtureRoster = buildFixtureRoster({ sourceSet, corpus });
  const fixtureRosterRaw = canonicalBytes(fixtureRoster);
  output.set('fixture-roster.v2.json', fixtureRosterRaw);

  const sourceSetInput = bindingInput({
    value: sourceSet,
    artifactId: sourceSet.artifactId,
    path: sourceSetRelative,
    rawSha256: sourceSetRawSha256,
    schemaSha256: sourceSetSchemaSha256,
    contentDigest: sourceSet.contentDigest,
  });
  const campaignInput = bindingInput({
    value: campaign,
    artifactId: campaign.campaignId,
    path: campaignRelative,
    rawSha256: sha256(campaignRaw),
    schemaSha256: rawSha(campaignSchemaRelative),
    contentDigest: campaign.contentDigest,
  });
  const corpusInput = bindingInput({
    value: corpus,
    artifactId: corpus.corpusId,
    path: corpusRelative,
    rawSha256: sha256(corpusRaw),
    schemaSha256: rawSha(corpusSchemaRelative),
    contentDigest: corpus.contentDigest,
  });
  const executionProfile = bindingInput({
    value: readJson(repoFile(profileRelative)),
    artifactId: 'profile:bch-current-2026-08-08',
    path: profileRelative,
    rawSha256: rawSha(profileRelative),
  });
  const fixtureDerivation = {
    fixtureId: FIXTURE_ARTIFACT_ID,
    path: fixtureDerivationRelative,
    rawSha256: rawSha(fixtureDerivationRelative),
  };
  const fixtureRosterInput = bindingInput({
    value: fixtureRoster,
    artifactId: fixtureRoster.artifactId,
    path: fixtureRosterRelative,
    rawSha256: sha256(fixtureRosterRaw),
    schemaSha256: rawSha(fixtureRosterSchemaRelative),
    contentDigest: fixtureRoster.contentDigest,
  });

  const epoch = buildExecutionEpoch({
    sourceSet: sourceSetInput,
    campaign: campaignInput,
    corpus: corpusInput,
    executionProfile,
    engineRecords: engineBindings,
    fixtureDerivation,
    fixtureRoster: fixtureRosterInput,
    descriptors,
    workItemRosterRawSha256: sha256(workItemRosterRaw),
    workItemRosterSchemaSha256,
  });
  const epochRaw = canonicalBytes(epoch);
  output.set('execution-epoch.v2.json', epochRaw);

  return {
    output,
    artifacts: {
      sourceSet,
      campaign,
      corpus,
      engineArtifacts,
      engineBindings,
      fixtureRoster,
      workItemRoster,
      epoch,
      descriptors,
      bindings: {
        sourceSet: sourceSetInput,
        campaign: campaignInput,
        corpus: corpusInput,
        executionProfile,
        fixtureDerivation,
        fixtureRoster: fixtureRosterInput,
        workItemRosterRawSha256: sha256(workItemRosterRaw),
        workItemRosterSchemaSha256,
      },
    },
  };
};

const buildPackage = ({ snapshot = null } = {}) => {
  const { output, artifacts } = materializeArtifacts({ snapshot });
  const fileOrder = [...staticPaths, ...generatedPaths];
  const files = fileOrder.map((path, orderIndex) => {
    const value = output.get(path) ?? readFileSync(packageFile(path));
    return { orderIndex, path, byteCount: value.length, fileDigest: rawDigest(value) };
  });
  const manifest = {
    schema: 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/manifest/v1',
    packageId: 'package:gate-b0-cohort-freeze-v2',
    status: 'frozen-contract-only-unexecuted',
    evidenceClassification: 'not-execution-evidence',
    executionAllowed: false,
    metricsAllowed: false,
    ranking: null,
    selection: null,
    counts: {
      constructions: 4,
      arms: 14,
      plans: 42,
      corpusCases: artifacts.corpus.counts.total,
      uniquePlanCaseFixtures: artifacts.fixtureRoster.counts.uniquePlanCaseFixtures,
      terminalEnginePlanCells: artifacts.workItemRoster.counts.terminalEnginePlanCells,
      armCasesPerEngine: artifacts.workItemRoster.counts.armCasesPerEngine,
      workItems: artifacts.workItemRoster.counts.workItems,
      preflightLimitViolations: artifacts.fixtureRoster.counts.preflightLimitViolations,
    },
    contentDigests: {
      campaign: artifacts.campaign.contentDigest.value,
      corpus: artifacts.corpus.contentDigest.value,
      fixtureRoster: artifacts.fixtureRoster.contentDigest.value,
      workItemRoster: artifacts.workItemRoster.contentDigest.value,
      executionEpoch: artifacts.epoch.contentDigest.value,
    },
    files,
  };
  const manifestBytes = canonicalBytes(manifest);
  output.set('MANIFEST.json', manifestBytes);
  const sums = [
    ...files.map((record) => `${record.fileDigest.value}  ${record.path}`),
    `${sha256(manifestBytes)}  MANIFEST.json`,
  ].join('\n') + '\n';
  output.set('SHA256SUMS', Buffer.from(sums, 'utf8'));
  return { output, artifacts, manifest };
};

const writePackage = () => {
  mkdirSync(resolve(here, 'engines'), { recursive: true });
  const built = buildPackage();
  const { output } = built;
  for (const [path, value] of output) writeFileSync(packageOutput(path), value);
  return built;
};

const checkPackage = () => {
  const built = buildPackage();
  const { output } = built;
  const mismatches = [];
  for (const [path, expected] of output) {
    const absolute = packageFile(path);
    const actual = readFileSync(absolute);
    if (!actual.equals(expected)) mismatches.push(path);
  }
  if (mismatches.length > 0) fail(`generated package drift: ${mismatches.join(', ')}`);
  return built;
};

export { buildAttestations, buildPackage, checkPackage, materializeArtifacts, writePackage };

if (process.argv.includes('--write')) console.log(JSON.stringify(writePackage().manifest.counts));
else if (process.argv.includes('--check')) console.log(JSON.stringify(checkPackage().manifest.counts));
