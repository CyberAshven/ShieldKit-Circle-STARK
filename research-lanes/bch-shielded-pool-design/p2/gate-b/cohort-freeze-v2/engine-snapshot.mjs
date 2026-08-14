/** Read-only, fail-closed provenance snapshots for the four epoch surfaces. */

import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { DOMAIN_DIGEST_CANONICALIZATION, DOMAIN_DIGEST_FRAME, REPOSITORY_ROOT, SOURCE_SET_DIRECTORY, assertContainedRegularFile, canonicalJsonUtf8, domainSeparatedSha256, sha256 } from './execution-fixture.mjs';
import { ENGINE_CAPABILITIES } from './epoch.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const require = (condition, message) => { if (!condition) throw new TypeError(message); };
const digest = (value) => createHash('sha256').update(value).digest('hex');
const cleanPath = (value) => value.split(sep).join('/');

const roots = Object.freeze({
  labs: REPOSITORY_ROOT,
  bchn: '/home/toorik/Projects/BCH/bchn-src',
  conformance: '/home/toorik/Projects/BCH/bch-conformance',
  leanbch: '/home/toorik/Projects/ZK-Proofs/LeanBCH',
});

const git = (root, args) => {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'buffer' });
  require(result.status === 0, `git ${args.join(' ')} failed for ${root}`);
  return Buffer.from(result.stdout);
};

const repositorySnapshot = (root, authorityPaths) => {
  const realpath = realpathSync(root);
  require(Array.isArray(authorityPaths) && authorityPaths.length > 0, 'repository authority paths required');
  const informationalStatus = git(realpath, ['status', '--porcelain=v1', '-z']);
  const scopedStatus = git(realpath, ['status', '--porcelain=v1', '-z', '--', ...authorityPaths]);
  const scopedPatch = git(realpath, ['diff', '--binary', '--no-ext-diff', '--', ...authorityPaths]);
  const scopedUntracked = git(realpath, ['ls-files', '--others', '--exclude-standard', '-z', '--', ...authorityPaths]);
  return Object.freeze({
    root,
    realpath,
    headCommit: git(realpath, ['rev-parse', 'HEAD']).toString('utf8').trim(),
    headTree: git(realpath, ['rev-parse', 'HEAD^{tree}']).toString('utf8').trim(),
    authorityScope: Object.freeze({ paths: Object.freeze([...authorityPaths]), statusPorcelainSha256: digest(scopedStatus), trackedDiffSha256: digest(scopedPatch), untrackedPathListSha256: digest(scopedUntracked) }),
    informationalWorktree: Object.freeze({ dirty: informationalStatus.length !== 0, statusPorcelainSha256: digest(informationalStatus), excludedFromContentDigest: true }),
  });
};

const commandIdentity = (path, args = ['--version'], cwd = null) => {
  const result = spawnSync(path, args, { encoding: 'buffer', ...(cwd === null ? {} : { cwd }) });
  require(result.status === 0, `${path} ${args.join(' ')} failed`);
  const stdout = Buffer.from(result.stdout);
  return Object.freeze({ path, argv: Object.freeze([path, ...args]), cwd, stdoutSha256: digest(stdout), firstLine: stdout.toString('utf8').split('\n')[0] });
};

const noSymlinkFile = (root, relativePath) => {
  const path = assertContainedRegularFile(root, relativePath);
  return Object.freeze({
    path: cleanPath(relativePath),
    realpath: path,
    byteLength: readFileSync(path).length,
    rawSha256: sha256(readFileSync(path)),
  });
};

const aggregateTree = (root, relativeDirectory) => {
  const directory = resolve(realpathSync(root), relativeDirectory);
  const rel = relative(realpathSync(root), directory);
  require(rel !== '' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel), `directory escapes repository: ${relativeDirectory}`);
  const records = [];
  let totalByteLength = 0;
  const walk = (path, display) => {
    const stat = lstatSync(path);
    require(!stat.isSymbolicLink(), `symlink forbidden in package tree: ${display}`);
    if (stat.isDirectory()) for (const child of readdirSync(path).sort()) walk(resolve(path, child), `${display}/${child}`);
    else if (stat.isFile()) {
      const bytes = readFileSync(path);
      totalByteLength += bytes.length;
      records.push(`${display}\t${bytes.length}\t${sha256(bytes)}`);
    }
  };
  walk(directory, cleanPath(relativeDirectory));
  return Object.freeze({ fileCount: records.length, totalByteLength, fileManifestSha256: digest(Buffer.from(records.join('\n'))) });
};

const sourceSetBinding = () => {
  const rootFile = assertContainedRegularFile(SOURCE_SET_DIRECTORY, 'source-set.v1.json');
  const bytes = readFileSync(rootFile);
  const sourceSet = JSON.parse(bytes.toString('utf8'));
  require(sourceSet.artifactId === 'source-set:mechanical-bch-script-v1' && sourceSet.planIndex?.length === 42, 'source-set authority drift');
  return Object.freeze({
    rootPath: 'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.json',
    rootRawSha256: sha256(bytes),
    contentDigest: sourceSet.contentDigest?.value,
    plans: sourceSet.planIndex.length,
    planIndexSha256: digest(Buffer.from(JSON.stringify(sourceSet.planIndex))),
  });
};

const buildSnapshot = ({ attestation, inputs, commands = [], toolchain = [], binary = null, command = null, compiler = null, linker = null }) => Object.freeze({
  attestation,
  inputs: Object.freeze(inputs),
  commands: Object.freeze(commands),
  toolchain: Object.freeze(toolchain),
  binary,
  command,
  compiler,
  linker,
});

const moduleEntrypoint = (file, argv = null) => Object.freeze({ kind: 'module', file, argv });
const externalEntrypoint = (file, argv) => Object.freeze({ kind: 'external', file, argv: Object.freeze(argv) });
const buildCommand = (cwd, argv, environment = {}) => Object.freeze({ cwd, argv: Object.freeze(argv), environment: Object.freeze({ ...environment }) });

const capability = ({ category, supportPolicy, profile }) => Object.freeze({
  category,
  supportPolicy,
  terminalPolicy: 'supported-or-explicit-unsupported',
  executionStatus: 'execution-not-authorized',
  unsupportedCountsAsExecution: false,
  unsupportedCountsAsAgreement: false,
  outerRejectionPhasePolicy: 'explicit-outer-transaction-or-token-phase-never-script-engine-agreement',
  commonComparisonInput: 'exact-synthetic-one-input-one-output-p2sh32-transaction-v2',
  profile,
});

const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  return value;
};
export const canonicalPrettyJson = (value) => canonicalJsonUtf8(value).toString('utf8');
const domainDigest = domainSeparatedSha256;

export const snapshotExecutionSurfaces = () => {
  const nativeModule = noSymlinkFile(roots.labs, 'research-lanes/bch-shielded-pool-design/p2/reference/direct-extension.mjs');
  const fixtureAdapter = noSymlinkFile(roots.labs, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/execution-fixture.mjs');
  const snapshotAdapter = noSymlinkFile(roots.labs, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engine-snapshot.mjs');
  const epochContract = noSymlinkFile(roots.labs, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/epoch.mjs');
  const packageLock = noSymlinkFile(roots.labs, 'package-lock.json');
  const libauthPackage = noSymlinkFile(roots.labs, 'node_modules/@bitauth/libauth/package.json');
  const libauthVm = noSymlinkFile(roots.labs, 'node_modules/@bitauth/libauth/build/lib/vm/instruction-sets/bch/2026/bch-2026-vm.js');
  const libauthProgram = noSymlinkFile(roots.labs, 'node_modules/@bitauth/libauth/build/lib/vm/instruction-sets/xec/xec-types.js');
  const bchnLeg = noSymlinkFile(roots.conformance, 'legs/bchn/bchn-leg');
  const bchnAdapter = noSymlinkFile(roots.conformance, 'legs/bchn/bchn-leg.cpp');
  const bchnBuild = noSymlinkFile(roots.conformance, 'legs/bchn/build.sh');
  const bchnBuildNinja = noSymlinkFile(roots.bchn, 'build/build.ninja');
  const bchnConsensusLibrary = noSymlinkFile(roots.bchn, 'build/src/libbitcoinconsensus.a');
  const bchnInterpreter = noSymlinkFile(roots.bchn, 'src/script/interpreter.cpp');
  const bchnScript = noSymlinkFile(roots.bchn, 'src/script/script.h');
  const bchnVmLimits = noSymlinkFile(roots.bchn, 'src/script/vm_limits.h');
  const leanRunner = noSymlinkFile(roots.leanbch, 'conformance/Runner.lean');
  const leanCost = noSymlinkFile(roots.leanbch, 'conformance/CostProbe.lean');
  const leanVerify = noSymlinkFile(roots.leanbch, 'LeanBCH/VM/Verify.lean');
  const leanExtended = noSymlinkFile(roots.leanbch, 'LeanBCH/VM/Extended.lean');
  const leanVmbconf = noSymlinkFile(roots.leanbch, '.lake/build/bin/vmbconf');
  const leanCostprobe = noSymlinkFile(roots.leanbch, '.lake/build/bin/costprobe');
  const leanToolchain = noSymlinkFile(roots.leanbch, 'lean-toolchain');
  const leanLakefile = noSymlinkFile(roots.leanbch, 'lakefile.toml');
  const leanManifest = noSymlinkFile(roots.leanbch, 'lake-manifest.json');
  const leanFfiObject = noSymlinkFile(roots.leanbch, '.lake/ffi/secp256k1_shim.o');
  const leanFfiLibrary = noSymlinkFile(roots.leanbch, '.lake/ffi/libsecp256k1.a');
  const leanFfiBuild = noSymlinkFile(roots.leanbch, 'ffi/build.sh');
  const labs = repositorySnapshot(roots.labs, [nativeModule.path, fixtureAdapter.path, snapshotAdapter.path, epochContract.path, packageLock.path, libauthPackage.path, libauthVm.path, libauthProgram.path]);
  const bchn = repositorySnapshot(roots.bchn, [bchnInterpreter.path, bchnScript.path, bchnVmLimits.path, bchnBuildNinja.path, bchnConsensusLibrary.path]);
  const conformance = repositorySnapshot(roots.conformance, [bchnLeg.path, bchnAdapter.path, bchnBuild.path]);
  const leanbch = repositorySnapshot(roots.leanbch, [leanRunner.path, leanCost.path, leanVerify.path, leanExtended.path, leanVmbconf.path, leanCostprobe.path, leanToolchain.path, leanLakefile.path, leanManifest.path, leanFfiObject.path, leanFfiLibrary.path, leanFfiBuild.path]);
  const setBinding = sourceSetBinding();
  const bchnCompiler = commandIdentity('/usr/bin/g++');
  const bchnLinker = commandIdentity('/usr/bin/ld');
  const leanElan = commandIdentity('/home/toorik/.elan/bin/elan', ['--version']);
  const leanLake = commandIdentity('/home/toorik/.elan/bin/lake', ['--version'], roots.leanbch);
  const leanCompiler = commandIdentity('/home/toorik/.elan/bin/lean', ['--version'], roots.leanbch);
  const leanCCompiler = commandIdentity('/usr/bin/cc');
  const packageTree = aggregateTree(roots.labs, 'node_modules/@bitauth/libauth');
  const libauthVersion = JSON.parse(readFileSync(libauthPackage.realpath, 'utf8')).version;
  require(libauthVersion === '3.1.0-next.8', 'Libauth version drift');

  const engines = Object.freeze([
    Object.freeze({
      engineId: 'engine:native',
      repositorySnapshots: Object.freeze([labs]),
      entrypoint: moduleEntrypoint(nativeModule),
      stdinCodec: 'canonical-raw-operands-bottom-to-top-v2',
      environment: Object.freeze({ NODE_ENV: 'production' }),
      runtime: Object.freeze({ runtime: 'node', version: process.version, platform: process.platform, arch: process.arch }),
      modules: Object.freeze([nativeModule, epochContract]),
      adapters: Object.freeze([fixtureAdapter, snapshotAdapter]),
      build: buildSnapshot({ attestation: 'no-build-applicable', inputs: [nativeModule, fixtureAdapter, snapshotAdapter] }),
      capability: capability({ category: 'semantic-reference-only', supportPolicy: 'required', profile: 'host-direct-extension-semantic-reference-no-script-vm' }),
      sourceSetBinding: setBinding,
    }),
    Object.freeze({
      engineId: 'engine:libauth',
      repositorySnapshots: Object.freeze([labs]),
      entrypoint: moduleEntrypoint(libauthVm),
      stdinCodec: 'in-process-authentication-program-from-exact-synthetic-transaction-v2',
      environment: Object.freeze({ NODE_ENV: 'production' }),
      runtime: Object.freeze({ runtime: 'node', version: process.version, platform: process.platform, arch: process.arch }),
      modules: Object.freeze([packageLock, libauthPackage, libauthVm, libauthProgram, epochContract, Object.freeze({ path: 'node_modules/@bitauth/libauth', realpath: realpathSync(resolve(roots.labs, 'node_modules/@bitauth/libauth')), byteLength: packageTree.totalByteLength, rawSha256: packageTree.fileManifestSha256 })]),
      adapters: Object.freeze([fixtureAdapter, snapshotAdapter]),
      build: buildSnapshot({ attestation: 'package-integrity-source-pinned-ready', inputs: [packageLock, libauthPackage, libauthVm, libauthProgram, fixtureAdapter, snapshotAdapter] }),
      capability: capability({ category: 'bch-vm', supportPolicy: 'required', profile: 'BCH_2026_05-standard-true' }),
      sourceSetBinding: setBinding,
    }),
    Object.freeze({
      engineId: 'engine:bchn',
      repositorySnapshots: Object.freeze([labs, bchn, conformance]),
      entrypoint: externalEntrypoint(bchnLeg, [bchnLeg.realpath, '--mode', 'standard']),
      stdinCodec: 'vmb-json-array-transaction-and-source-outputs-v2',
      environment: Object.freeze({ BCHN_DEBUG: '0' }),
      runtime: Object.freeze({ runtime: 'native-bchn-leg', platform: process.platform, arch: process.arch }),
      modules: Object.freeze([bchnInterpreter, bchnScript, bchnVmLimits, bchnBuildNinja, bchnConsensusLibrary, epochContract]),
      adapters: Object.freeze([bchnAdapter, bchnBuild]),
      build: buildSnapshot({ attestation: 'fresh-build-attestation-pending', inputs: [bchnBuild, bchnAdapter, bchnInterpreter, bchnScript, bchnVmLimits, bchnBuildNinja, bchnConsensusLibrary], commands: [buildCommand(roots.conformance, ['/usr/bin/bash', '-x', bchnBuild.realpath], { PATH: '/home/toorik/.local/share/mise/installs/ninja/1.13.2:/usr/bin:/bin', NINJAFLAGS: '-j20', BCHN_SRC: roots.bchn, BCHN_BUILD: resolve(roots.bchn, 'build') })], toolchain: [bchnCompiler, bchnLinker], binary: bchnLeg, command: Object.freeze(['/usr/bin/bash', '-x', bchnBuild.realpath]), compiler: bchnCompiler, linker: bchnLinker }),
      capability: capability({ category: 'bch-vm', supportPolicy: 'required', profile: 'BCHN-2026-standard-script-only' }),
      sourceSetBinding: setBinding,
    }),
    Object.freeze({
      engineId: 'engine:leanbch',
      repositorySnapshots: Object.freeze([labs, leanbch]),
      entrypoint: externalEntrypoint(leanVmbconf, [leanVmbconf.realpath]),
      stdinCodec: 'expected-id-transaction-sourceOutputs-inputIndex-lines-v2',
      environment: Object.freeze({ LEANBCH_SECP: 'reject' }),
      runtime: Object.freeze({ runtime: 'lean', declaredToolchain: readFileSync(leanToolchain.realpath, 'utf8').trim(), platform: process.platform, arch: process.arch }),
      modules: Object.freeze([leanRunner, leanCost, leanVerify, leanExtended, leanToolchain, leanLakefile, leanManifest, leanFfiObject, leanFfiLibrary, leanFfiBuild, epochContract]),
      adapters: Object.freeze([leanRunner, leanCost, leanFfiBuild]),
      secondaryEntrypoints: Object.freeze([externalEntrypoint(leanCostprobe, [leanCostprobe.realpath])]),
      build: buildSnapshot({ attestation: 'fresh-build-attestation-pending', inputs: [leanRunner, leanCost, leanVerify, leanExtended, leanToolchain, leanLakefile, leanManifest, leanFfiObject, leanFfiLibrary, leanFfiBuild], commands: [buildCommand(roots.leanbch, [leanElan.path, 'run', 'leanprover/lean4:v4.31.0', 'bash', '-c', `SECP256K1_LIB_DIR=${resolve(roots.bchn, 'build/src/secp256k1')} SECP256K1_INCLUDE_DIR=${resolve(roots.bchn, 'src/secp256k1/include')} bash ffi/build.sh`]), buildCommand(roots.leanbch, [leanElan.path, 'run', 'leanprover/lean4:v4.31.0', 'env', 'LEAN_NUM_THREADS=20', 'NINJAFLAGS=-j20', 'lake', 'build', 'vmbconf', 'costprobe'])], toolchain: [leanElan, leanLake, leanCompiler, leanCCompiler], binary: leanVmbconf, command: Object.freeze([leanElan.path, 'run', 'leanprover/lean4:v4.31.0', 'env', 'LEAN_NUM_THREADS=20', 'NINJAFLAGS=-j20', 'lake', 'build', 'vmbconf', 'costprobe']), compiler: leanCompiler, linker: null }),
      capability: capability({ category: 'bch-vm', supportPolicy: 'required-or-explicit-unsupported', profile: 'LeanBCH-transaction-and-token-prechecks-plus-verifyInput' }),
      sourceSetBinding: setBinding,
    }),
  ]);
  return Object.freeze({
    schema: 'shieldkit-labs/p2/gate-b/engine-snapshot/v2',
    status: 'snapshot-only-no-vm-execution-no-build',
    sourceSetBinding: setBinding,
    engines,
  });
};

const engineIds = Object.freeze(['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);
const engineRoles = Object.freeze({
  'engine:native': 'native-direct-extension-semantic-reference',
  'engine:libauth': 'libauth-bch-2026-standard-vm',
  'engine:bchn': 'bchn-standard-script-only-leg',
  'engine:leanbch': 'leanbch-vmbconf-and-costprobe',
});
const engineBuildStatuses = Object.freeze({
  'engine:native': 'no-build-applicable',
  'engine:libauth': 'package-integrity-source-pinned-ready',
  'engine:bchn': 'fresh-build-attestation-pending',
  'engine:leanbch': 'fresh-build-attestation-pending',
});
const engineCapabilityStatuses = Object.freeze({
  'engine:native': 'required',
  'engine:libauth': 'required',
  'engine:bchn': 'required',
  'engine:leanbch': 'required-or-explicit-unsupported',
});
const BUILD_ATTESTATION_SCHEMA = 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/build-attestation/v1';
const FINAL_BUILD_STATUS = 'fresh-build-attested-unexecuted';
const BUILD_ATTESTATION_EVIDENCE = 'build-attestation-only-not-vm-evidence';
const exactKeys = (value, keys, label) => require(value !== null && typeof value === 'object' && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()), `${label} shape drift`);
const canonicalEqual = (left, right) => canonicalPrettyJson(left) === canonicalPrettyJson(right);
const logDomain = (engineId) => `shieldkit-labs/p2/gate-b/execution-epoch/v2/build-attestation/${engineId}/logs`;

const outputsFor = (engine) => {
  if (engine.engineId === 'engine:bchn') return Object.freeze([engine.build.binary]);
  if (engine.engineId === 'engine:leanbch') {
    const ffi = engine.modules.filter((file) => file.path === '.lake/ffi/secp256k1_shim.o' || file.path === '.lake/ffi/libsecp256k1.a');
    return Object.freeze([...ffi, engine.build.binary, ...engine.secondaryEntrypoints.map((entrypoint) => entrypoint.file)]);
  }
  return Object.freeze([]);
};

/** Exact values a non-executing build-attestation bundle must repeat. */
export const buildAttestationRequirements = ({ snapshot = snapshotExecutionSurfaces() } = {}) => {
  assertEngineSnapshotSet(snapshot);
  const requirements = {};
  for (const engine of snapshot.engines.filter((item) => item.engineId === 'engine:bchn' || item.engineId === 'engine:leanbch')) {
    require(engine.build.commands.length > 0 && engine.build.toolchain.length > 0, `${engine.engineId} build provenance incomplete`);
    requirements[engine.engineId] = Object.freeze({
      engineId: engine.engineId,
      cwd: engine.build.commands[0].cwd,
      commands: engine.build.commands,
      inputs: engine.build.inputs,
      outputs: outputsFor(engine),
      toolchain: engine.build.toolchain,
    });
  }
  return Object.freeze(requirements);
};

const assertLogRecords = (engineId, logs, logDigest) => {
  require(Array.isArray(logs) && logs.length > 0, `${engineId} build logs required`);
  const names = new Set();
  for (const log of logs) {
    exactKeys(log, ['name', 'byteLength', 'rawSha256'], `${engineId} log record`);
    require(typeof log.name === 'string' && /^[a-z0-9][a-z0-9.-]*$/u.test(log.name) && !names.has(log.name), `${engineId} log name drift`);
    names.add(log.name);
    require(Number.isInteger(log.byteLength) && log.byteLength >= 0, `${engineId} log byte length drift`);
    require(typeof log.rawSha256 === 'string' && /^[0-9a-f]{64}$/u.test(log.rawSha256), `${engineId} log SHA-256 drift`);
  }
  exactKeys(logDigest, ['algorithm', 'canonicalization', 'domain', 'frame', 'value'], `${engineId} log digest`);
  require(logDigest.algorithm === 'sha256' && logDigest.canonicalization === DOMAIN_DIGEST_CANONICALIZATION && logDigest.frame === DOMAIN_DIGEST_FRAME && logDigest.domain === logDomain(engineId), `${engineId} log digest metadata drift`);
  require(logDigest.value === domainDigest(logDomain(engineId), logs), `${engineId} log digest value drift`);
};

const finalizeBuildAttestation = (engine, attestation, requirement) => {
  exactKeys(attestation, ['schema', 'engineId', 'status', 'evidenceClassification', 'executionAllowed', 'vmEvidence', 'cwd', 'commands', 'exitCode', 'exitCodes', 'inputs', 'outputs', 'toolchain', 'logs', 'logDigest'], `${engine.engineId} build attestation`);
  require(attestation.schema === BUILD_ATTESTATION_SCHEMA && attestation.engineId === engine.engineId && attestation.status === FINAL_BUILD_STATUS, `${engine.engineId} build attestation identity drift`);
  require(attestation.evidenceClassification === BUILD_ATTESTATION_EVIDENCE && attestation.executionAllowed === false && attestation.vmEvidence === null, `${engine.engineId} build attestation must not contain VM evidence`);
  require(attestation.exitCode === 0 && Array.isArray(attestation.exitCodes) && attestation.exitCodes.length === requirement.commands.length && attestation.exitCodes.every((code) => code === 0), `${engine.engineId} build exit must be zero`);
  require(attestation.cwd === requirement.cwd && canonicalEqual(attestation.commands, requirement.commands), `${engine.engineId} build command or cwd drift`);
  require(canonicalEqual(attestation.inputs, requirement.inputs), `${engine.engineId} build input bytes drift`);
  require(canonicalEqual(attestation.outputs, requirement.outputs), `${engine.engineId} build output bytes drift`);
  require(canonicalEqual(attestation.toolchain, requirement.toolchain), `${engine.engineId} build toolchain drift`);
  assertLogRecords(engine.engineId, attestation.logs, attestation.logDigest);
  return Object.freeze(canonicalize(attestation));
};

const finalizedBuildAttestations = (snapshot, buildAttestations) => {
  if (buildAttestations === null || buildAttestations === undefined) return new Map();
  exactKeys(buildAttestations, ['engine:bchn', 'engine:leanbch'], 'buildAttestations');
  assertExactCurrentEngineSnapshot(snapshot);
  const requirements = buildAttestationRequirements({ snapshot });
  return new Map(['engine:bchn', 'engine:leanbch'].map((engineId) => {
    const engine = snapshot.engines.find((item) => item.engineId === engineId);
    return [engineId, finalizeBuildAttestation(engine, buildAttestations[engineId], requirements[engineId])];
  }));
};

const digestRepositorySnapshot = (repository) => {
  const { informationalWorktree: _informational, ...authority } = repository;
  return authority;
};
const artifactDigestProjection = (record) => {
  const { contentDigest: _contentDigest, ...authority } = record;
  return authority;
};

/**
 * Deterministically materialize four future engine-artifact records in memory.
 * This produces no files and is not evidence of VM execution or a fresh build.
 */
export const buildEngineArtifactRecords = ({ snapshot = snapshotExecutionSurfaces(), buildAttestations = null } = {}) => {
  assertEngineSnapshotSet(snapshot);
  const finalAttestations = finalizedBuildAttestations(snapshot, buildAttestations);
  return Object.freeze(snapshot.engines.map((engine) => {
    const domain = `shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/${engine.engineId}`;
    const buildAttestation = finalAttestations.get(engine.engineId) ?? null;
    const build = buildAttestation === null ? engine.build : Object.freeze({ ...engine.build, attestation: FINAL_BUILD_STATUS });
    const record = {
      schema: 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/engine-artifact/v2',
      artifactId: `artifact:gate-b:execution-epoch-v2:${engine.engineId.replace('engine:', '')}`,
      path: `research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engines/${engine.engineId.replace('engine:', '')}.v2.json`,
      status: buildAttestation === null ? engineBuildStatuses[engine.engineId] : FINAL_BUILD_STATUS,
      evidenceClassification: 'not-evidence',
      selection: null,
      executionAllowed: false,
      engineId: engine.engineId,
      role: engineRoles[engine.engineId],
      capabilityStatus: engineCapabilityStatuses[engine.engineId],
      capabilities: ENGINE_CAPABILITIES,
      sourceSetBinding: engine.sourceSetBinding,
      repositoryAuthority: engine.repositorySnapshots.map(digestRepositorySnapshot),
      entrypoint: engine.entrypoint,
      secondaryEntrypoints: engine.secondaryEntrypoints ?? [],
      stdinCodec: engine.stdinCodec,
      environment: engine.environment,
      runtime: engine.runtime,
      sourceInputs: engine.modules,
      adapterInputs: engine.adapters,
      build,
      buildAttestation,
      contentDigest: null,
    };
    record.contentDigest = Object.freeze({
      algorithm: 'sha256', domain,
      canonicalization: DOMAIN_DIGEST_CANONICALIZATION,
      frame: DOMAIN_DIGEST_FRAME,
      value: domainDigest(domain, artifactDigestProjection(record)),
    });
    return Object.freeze(canonicalize(record));
  }));
};

export const assertEngineSnapshotSet = (snapshot) => {
  require(snapshot?.schema === 'shieldkit-labs/p2/gate-b/engine-snapshot/v2', 'engine snapshot schema identity drift');
  require(snapshot.status === 'snapshot-only-no-vm-execution-no-build', 'engine snapshot status drift');
  require(Array.isArray(snapshot.engines) && snapshot.engines.length === engineIds.length, 'engine snapshot roster cardinality drift');
  require(snapshot.engines.map((engine) => engine.engineId).join(',') === engineIds.join(','), 'engine snapshot roster/order drift');
  for (const engine of snapshot.engines) {
    require(engine.capability.terminalPolicy === 'supported-or-explicit-unsupported', `${engine.engineId} terminal policy drift`);
    require(engine.capability.unsupportedCountsAsExecution === false && engine.capability.unsupportedCountsAsAgreement === false, `${engine.engineId} unsupported policy drift`);
    require(engine.capability.outerRejectionPhasePolicy === 'explicit-outer-transaction-or-token-phase-never-script-engine-agreement', `${engine.engineId} outer rejection phase policy drift`);
    require(engine.build.attestation === engineBuildStatuses[engine.engineId], `${engine.engineId} build attestation drift`);
    require(engine.sourceSetBinding.rootRawSha256 === snapshot.sourceSetBinding.rootRawSha256, `${engine.engineId} source-set substitution`);
    require(engine.repositorySnapshots.every((repository) => repository.root === repository.realpath && repository.authorityScope?.paths?.length > 0 && repository.informationalWorktree?.excludedFromContentDigest === true), `${engine.engineId} repository realpath containment drift`);
    const repositoryRoots = engine.repositorySnapshots.map((repository) => `${repository.realpath}${sep}`);
    const withinEngineRepository = (file) => repositoryRoots.some((root) => file.realpath.startsWith(root));
    require([...engine.modules, ...engine.adapters, engine.entrypoint.file, ...(engine.secondaryEntrypoints ?? []).map((entrypoint) => entrypoint.file)].every(withinEngineRepository), `${engine.engineId} module or entrypoint escapes declared repository root`);
    require(Object.hasOwn(engine.environment, 'NODE_ENV') || Object.hasOwn(engine.environment, 'BCHN_DEBUG') || Object.hasOwn(engine.environment, 'LEANBCH_SECP'), `${engine.engineId} exact environment missing`);
  }
  const native = snapshot.engines[0]; const libauth = snapshot.engines[1]; const bchn = snapshot.engines[2]; const lean = snapshot.engines[3];
  require(native.capability.category === 'semantic-reference-only', 'native capability drift');
  require(libauth.capability.category === 'bch-vm' && bchn.capability.category === 'bch-vm' && lean.capability.category === 'bch-vm', 'VM capability drift');
  require(lean.environment.LEANBCH_SECP === 'reject' || lean.environment.LEANBCH_SECP === 'native', 'LeanBCH exact oracle environment drift');
  return true;
};

/**
 * Canonical outcome classification for later engine-result generation. This is
 * intentionally transport-only: it does not execute, interpret, or infer a
 * BCH verdict. Outer transaction/token failures are never script agreement.
 */
export const classifyTerminalOutcome = ({ terminalStatus, phase }) => {
  require(terminalStatus === 'supported' || terminalStatus === 'explicit-unsupported', 'terminal status must be supported or explicit-unsupported');
  require(['semantic-reference', 'script-engine', 'outer-transaction-or-token'].includes(phase), 'explicit terminal phase required');
  if (terminalStatus === 'explicit-unsupported') {
    return Object.freeze({ terminalStatus, phase: 'explicit-unsupported', countsAsExecution: false, countsAsAgreement: false });
  }
  return Object.freeze({
    terminalStatus,
    phase,
    countsAsExecution: true,
    countsAsAgreement: phase === 'script-engine' || phase === 'semantic-reference',
  });
};

/** Re-read every declared byte and reject any source, binary, or status drift. */
export const assertExactCurrentEngineSnapshot = (snapshot) => {
  assertEngineSnapshotSet(snapshot);
  const current = snapshotExecutionSurfaces();
  const authorityProjection = (value) => canonicalize({
    ...value,
    engines: value.engines.map((engine) => ({ ...engine, repositorySnapshots: engine.repositorySnapshots.map(digestRepositorySnapshot) })),
  });
  require(JSON.stringify(authorityProjection(snapshot)) === JSON.stringify(authorityProjection(current)), 'engine snapshot exact source/binary/status drift');
  return true;
};
