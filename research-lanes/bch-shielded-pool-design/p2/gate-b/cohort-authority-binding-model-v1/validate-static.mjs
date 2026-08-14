import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const ROOT = dirname(fileURLToPath(import.meta.url));
const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/';
const IDENTIFIER = 'cohort-authority-binding-model-v1';
const STATUS = 'static-authority-binding-catalog-non-authorizing-external-origins-unavailable-unqualified';
const PACKAGE_DIRECTORY = 'cohort-authority-binding-model-v1';
const GATE_DIRECTORY = 'gate-b';
const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
const FRAME = 'utf8(domain)||0x00||canonical-json-utf8-lf-v1';
const ROOT_CONTENT_DIGEST = '58365b7e9c01cf43b3e7fd46b8d06c27506361bbff80659b032499562e23731a';
const DIRECTORIES = Object.freeze(['.', 'schemas', 'src', 'test']);
const FILES = Object.freeze([
  'COMMAND.txt',
  'README.md',
  'authority-binding-root.v1.json',
  'validate-static.mjs',
  'schemas/authority-dag.v1.schema.json',
  'schemas/dependency-catalog.v1.schema.json',
  'schemas/external-origin-catalog.v1.schema.json',
  'schemas/fact-catalog.v1.schema.json',
  'schemas/state-grammar.v1.schema.json',
  'schemas/digest.v1.schema.json',
  'schemas/model-root.v1.schema.json',
  'schemas/manifest.v1.schema.json',
  'src/canonical.mjs',
  'src/sha256.mjs',
  'src/model.mjs',
  'test/digest.kat.json',
  'test/digest.test.mjs',
  'test/model.test.mjs',
  'test/mutation.test.mjs',
  'test/package-boundary.test.mjs',
]);
const NODES = Object.freeze(['N', 'E', 'X', 'SOURCE', 'COHORT', 'R', 'K', 'F', 'P', 'Q', 'A', 'B', 'C', 'J', 'D', 'LIVE_F', 'WORKER_ROWS_ROOT']);
const EDGES = Object.freeze(['N→R', 'E→R', 'X→R', 'SOURCE→F', 'COHORT→F', 'R→P', 'K→P', 'F→P', 'Q→A', 'P→A', 'A→B', 'P→B', 'R→B', 'K→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D']);
const P_DOWNSTREAM = Object.freeze(['J→JOURNAL', 'D→JOURNAL', 'J→OBSERVATION', 'D→OBSERVATION', 'J→TERMINAL', 'D→TERMINAL']);
const STATIC_AUTHENTICATES = Object.freeze(['static-byte-pins', 'static-schema-types', 'static-catalog-types']);
const STATIC_DOES_NOT_AUTHENTICATE = Object.freeze(['concrete-retry-predecessor', 'live-private-capture', 'private-handles', 'worker-rows-root', 'activation', 'execution']);
const SOURCE_SHA256 = Object.freeze({
  'src/canonical.mjs': 'c8423c7501023c11548fb8a5173fe3a424dbae3171b3af574cd6a4ab245fc2d7',
  'src/sha256.mjs': 'cfbbb0a0c589c56cab4bfec57bbdae16772d151750f7071881ba6c1655403549',
  'src/model.mjs': 'c46d205194fd773bdb263884faa62a94c161f35afded1e9431521749401378c9',
});
const SCHEMA_SHA256 = Object.freeze({
  'schemas/authority-dag.v1.schema.json': '2c31bdfcaef510576dc71b3d205cc9af2b66a005d8a9e43c89a1c4a20f558fa6',
  'schemas/dependency-catalog.v1.schema.json': 'f06e9d8d9d17613b07715dd13c34e69815d4ba7fca4b471f4d7b56edb17e5a9f',
  'schemas/external-origin-catalog.v1.schema.json': 'ee81b500967c61e9f10f7dc02bd0bc3f0f2bfe3376add4f35af0d343de3063f9',
  'schemas/fact-catalog.v1.schema.json': 'ef4c54bae18ab1dffe8a2755ec9e0903e9fdc05cbbbfcdec217d823f7c1d5f23',
  'schemas/state-grammar.v1.schema.json': '04bfb8fe333df38420aae25e0cdd2e6c6834741c479e8b7cb63c2a83233ca2cb',
  'schemas/digest.v1.schema.json': '65a1cff91338cf6e95ed210f9f45df26f6d85cca1a6dda696169f177e9510ed4',
  'schemas/model-root.v1.schema.json': '867d6356033d0671100df77bad458a9b4d8aa71956240902024446403dd77abe',
  'schemas/manifest.v1.schema.json': '4f337badf486f5f0ff68b624a6c0fd2b6726daa9bfd5613378bd582ae80659ae',
});
const DEPENDENCY_SPECS = Object.freeze([
  {
    id: 'R',
    artifactId: 'artifact:gate-b:cohort-runtime-binding-v1',
    primaryRawSha256: 'b0ce9e0ec7b11770ed773b73a12ccb8a7d25a9ba3b4b38415dc1b90bf129d3dd',
    pins: [
      { id: 'manifest-raw-sha256', value: '2da4f55beba04efee8a019b1cac9493e7d6f099de91d36fe30d18e32cc5aa254' },
      { id: 'sha256sums-raw-sha256', value: 'c25438471cfbd6949a886d723facb29ec5d0538be48dec7d28a87243065759ea' },
      { id: 'root-content-digest', value: '8b73e8bbbfd97d8c451c5fd9466ff219ab36eeb65e3fb10c5f3629a89da36af1' },
      { id: 'binding-digest', value: 'dbdcc046adaac671b5c4ed6a990f2579b6990a39a205434a0f19de0ba139758d' },
      { id: 'runtime-authority-digest', value: 'fce66bed0f375e922e6b765a74f6b0dd81f784029df6079cee4668f89bb872d8' },
    ],
  },
  {
    id: 'K',
    artifactId: 'artifact:gate-b:cohort-runner-core-v1',
    primaryRawSha256: 'fc94be4544cf5e5e31c9f474a1ed3b95d47979fb23d46c55c9acffab9b690ea2',
    pins: [
      { id: 'manifest-raw-sha256', value: '913e5667c78de4f06a7ce34acfa13fb1393eeadbbf831641eab35ceddf3f01c4' },
      { id: 'sha256sums-raw-sha256', value: '27ffdc493af8e77ab89b22dde1b424f0d9733bf9491013943b8a63ccc87bb4db' },
      { id: 'manifest-package-root', value: '10850743e64bf8f453b2a446019edb095861d9876a5e7785e946c4661d1ddac2' },
      { id: 'manifest-root', value: '58928887efb9bffe5482eee0525854eaf08496e97ae890d7fb795c14995e98f1' },
      { id: 'entries-root', value: '88ce4c1d2e91630344329f734fe65e23b6817c89400b431833f995e7a509033b' },
      { id: 'binding-digest', value: 'cc5e254b496aa5c67946d24a6a5d9737b232ed054e4013377e198405a7852f5d' },
      { id: 'worker-row-schema-raw-sha256', value: '6ff74e986cc12ad7eea100455ad41dcfb918311636c9e77c3e8053442b3460a2' },
      { id: 'dispatch-plan-schema-raw-sha256', value: '821c60bd9385553e976bfad0d894ae6c0130a3085e1d9c367cb465cd878fb57b' },
      { id: 'worker-row-endpoint-id-aliases', value: 'native,libauth,bchn,leanbch-primary,leanbch-secondary' },
    ],
  },
  {
    id: 'F',
    artifactId: 'artifact:gate-b:cohort-frozen-inputs-v1',
    primaryRawSha256: '19d90ed575404fa332f82d4cc28f1e1c4b71d99cff7f0d3a914664a0b72a2bd5',
    pins: [
      { id: 'manifest-raw-sha256', value: 'f6b1dbf3f6757366c519e10f11e1fed80d071507445ad0085955aae164ad0867' },
      { id: 'sha256sums-raw-sha256', value: '4099e52c4acd2c2c34c49142bb28e6cb7ac31d048feb452e053038f3db578eff' },
      { id: 'root-content-digest', value: '7f00510e5c4b8b4959b572c9c9ece8e97ca95174b5715c2ee0852ef79f28b08f' },
      { id: 'binding-digest', value: '9d3b8267d166307424a44b126e001291f62bcf4c090fba10035d9083e8cd403a' },
      { id: 'source-native-semantic-digest', value: '58e7765b066b1917b1fa0b4b96182010ad7f5c8ce8bce601c083bc764845482e' },
      { id: 'freeze-artifact-semantic-digest', value: '6fcbaba3bb52d5e1eb9c6f1cb04b1d46cb65e2c91eba20ca38356dc323ebb11e' },
      { id: 'ordered-leaf-ids', value: 'source-set-v1,cohort-freeze-v2' },
      { id: 'frozen-four-surface-order', value: 'native,libauth,bchn,leanbch' },
    ],
  },
  {
    id: 'P',
    artifactId: 'artifact:gate-b:cohort-policy-authority-v1',
    primaryRawSha256: 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e',
    pins: [
      { id: 'manifest-raw-sha256', value: '60fbc7ffe72e41a4df60603d9d4b6b0f0e118e1577028643fc867fbe3cb06bb1' },
      { id: 'sha256sums-raw-sha256', value: '66a8e1437c4c8d78dfa7600f7d0e1b83a2c6321c3f86b3d3a3dc2678eba992bb' },
      { id: 'root-content-digest', value: '9f040a5bbafc56a71dcd19081262c5411eea91e1fc35707ae4a0c2aa784c3f50' },
      { id: 'binding-root', value: '36ab3e7ca0594ef20c9ac1ec9f4f2ec21a3ed415815bde51d1e0c63163e4a654' },
      { id: 'policy-content-digest', value: '179009bd062d3207a995ee68da150e5c1622d4ad1576a68474d1d8331594e0bf' },
      { id: 'causal-dag-root', value: '98a4ba8298744602e9979ce0e4fc28883953fecac467993d2196bcf279bbfd4d' },
      { id: 'live-f-template-digest', value: '083b7679437170c36083612d108206ed47329f432011439f8e4b38c61b5616be' },
      { id: 'worker-alias-map', value: 'native=>engine:native,libauth=>engine:libauth,bchn=>engine:bchn,leanbch-primary=>engine:leanbch:primary,leanbch-secondary=>engine:leanbch:secondary' },
      { id: 'q-initial-template-digest', value: '6d98c5d262ea3ed54c51ec8777a0a958440c20d39829116e451095b18f70505c' },
      { id: 'q-retry-template-digest', value: '173d022e56ef5d2ef76d05cd1db8ce25e5e775fad4f638660a8a98d22295ff35' },
      { id: 'q-abort-template-digest', value: 'dfa83c4e1226743a038894e6e21f0ee00e9e4b97729928c96a935c0e3af67697' },
      { id: 'a-initial-template-digest', value: 'aa5f3826e12491129baab9f48dc1b0bc0ace07cddb71ace2783c478ce2dfc0ed' },
      { id: 'a-retry-template-digest', value: '46f5f0475da9a631d0f488b98efdd87749a19e639bea58b35fe16f6403fcde75' },
      { id: 'a-abort-template-digest', value: '12b4eef4ca62e62d639e90274cefc4cd14800a489ebd65884241283eb30af9bb' },
      { id: 'b-subject-template-digest', value: '38e6fce775d508f8cc91b885fa622fedefa4e220fc9b64878372af230987a00a' },
      { id: 'b-envelope-template-digest', value: '30c20e86feb89317653b0bc14d84d90f95d86c4cc98d7cb030f1cdbf2ed8986a' },
    ],
  },
  {
    id: 'V2',
    artifactId: 'artifact:gate-b:cohort-live-executor-v2',
    primaryRawSha256: '45ddc12f0b44136a4f85e2800a47c8b9ed000ed0f33acc252b31b0758bdd2ebb',
    pins: [
      { id: 'root-content-digest', value: '67ed36e2b9f011de2dcd9794e33e3be8a1b1f00550357e6d7c5081bebf334a82' },
      { id: 'manifest-raw-sha256', value: 'ef03043f458915856b5c420e039208f6a0307633d20b21dac8238d73316fd98a' },
      { id: 'sha256sums-raw-sha256', value: '0ef72e260de7afdc9bb508739321418be95c48879b09992669af23e71e3d7285' },
      { id: 'validator-raw-sha256', value: '31ef0e6f22eb6f6b20e426ca5ae4da2c0c8f7ed64becb693ad1da3fa81d8973a' },
      { id: 'manifest-roster-digest', value: '4734b2c457b12a1f9efe87814c2f101065c8cb2a111062adbbd769e617167df9' },
      { id: 'p-semantic-binding-digest', value: 'd43c30388318e0ddf8700b30123467b8366aafc103dbda9c0f61d24834eda002' },
      { id: 'authority-dag-digest', value: 'b8d2a5b200799dc2a6cc57d4fc96b3eb9de5be0f91b99d2d1d9323fa5e7383af' },
      { id: 'transition-grammar-digest', value: 'dc4680aa570ac87fc3972c644405b4be0ab59e63637917ae846a650432c4553b' },
    ],
  },
]);
const EXPECTED_ORIGINS = Object.freeze({
  schema: `${PREFIX}external-origin-catalog/v1`,
  identifier: IDENTIFIER,
  entries: [
    { id: 'RETRY_PREDECESSOR', ownerClass: 'unavailable-recovery-chain-owner', originFor: 'Q:retry', staticAuthenticators: ['P', 'V2'], availability: 'unavailable', modelDisposition: 'BLOCKED_EXTERNAL', grantsAuthority: false },
    { id: 'LIVE_F_CAPTURE', ownerClass: 'unavailable-private-capture-owner', originFor: 'LIVE_F', staticAuthenticators: ['P', 'F', 'V2'], availability: 'unavailable', modelDisposition: 'UNAVAILABLE_EXTERNAL', grantsAuthority: false },
    { id: 'WORKER_ROWS_ROOT', ownerClass: 'unavailable-private-dispatch-owner', originFor: 'D', staticAuthenticators: ['R', 'K', 'F', 'P', 'V2'], availability: 'unavailable', modelDisposition: 'BLOCKED_EXTERNAL', grantsAuthority: false },
  ],
});
const EXPECTED_FACTS = Object.freeze({
  schema: `${PREFIX}fact-catalog/v1`,
  identifier: IDENTIFIER,
  entries: [
    { id: 'Q', requiredOwnerClass: 'unavailable-request-owner', staticAuthenticators: ['P', 'V2'], variants: ['initial', 'retry', 'abort'], statePredecessors: { initial: [], retry: ['RETRY_PREDECESSOR'], abort: [] }, originRequirements: { initial: [], retry: ['RETRY_PREDECESSOR'], abort: [] }, grantsAuthority: false },
    { id: 'A', requiredOwnerClass: 'unavailable-activation-owner', staticAuthenticators: ['P', 'V2'], variants: ['initial', 'retry', 'abort'], statePredecessors: { initial: ['Q'], retry: ['Q'], abort: ['Q'] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'LIVE_F', requiredOwnerClass: 'unavailable-private-capture-owner', staticAuthenticators: ['P', 'F', 'V2'], variants: ['initial'], statePredecessors: { initial: [], retry: [], abort: [] }, originRequirements: { initial: ['LIVE_F_CAPTURE'], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'B', requiredOwnerClass: 'unavailable-private-descriptor-owner', staticAuthenticators: ['R', 'K', 'P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['A', 'LIVE_F'], retry: [], abort: [] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'C', requiredOwnerClass: 'unavailable-exclusive-c-owner', staticAuthenticators: ['P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B'], retry: [], abort: [] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'J', requiredOwnerClass: 'none', staticAuthenticators: ['P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B', 'C'], retry: [], abort: [] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'D', requiredOwnerClass: 'unavailable-private-dispatch-owner', staticAuthenticators: ['R', 'K', 'F', 'P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'], retry: [], abort: [] }, originRequirements: { initial: ['WORKER_ROWS_ROOT'], retry: [], abort: [] }, grantsAuthority: false },
  ],
});
const EXPECTED_STATE_GRAMMAR = Object.freeze({
  schema: `${PREFIX}state-grammar/v1`,
  identifier: IDENTIFIER,
  variants: ['initial', 'retry', 'abort'],
  stateFacts: ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D'],
  initial: { modelDisposition: 'abstract-model-only', factOrder: ['Q', 'A', 'LIVE_F', 'B', 'C', 'J'], neverAdmitted: ['D'] },
  retry: { stateFacts: [], qPredecessors: ['RETRY_PREDECESSOR'], qDisposition: 'BLOCKED_EXTERNAL', aDisposition: 'DENY_PREREQUISITE', automaticRetry: false },
  abort: { qPredecessors: [], aPredecessors: ['Q'], closeDisposition: 'abstract-close-only', emitsFacts: [], synthesizesRetryPredecessor: false },
  d: { statePredecessors: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'], originRequirements: ['WORKER_ROWS_ROOT'], disposition: 'BLOCKED_EXTERNAL', neverAdmitted: true },
  capture: { templateId: 'LIVE_F_TEMPLATE', originId: 'LIVE_F_CAPTURE', factId: 'LIVE_F', templateSatisfiesOrigin: false, frozenInputSatisfiesOrigin: false, bToOriginAuthorityEdge: false, preB: 'immutable-private-capture-commitment', postB: 'retention-metadata-nonauthority' },
  aliasSeparation: { workerRowEndpointIds: ['native', 'libauth', 'bchn', 'leanbch-primary', 'leanbch-secondary'], frozenEngineOrder: ['native', 'libauth', 'bchn', 'leanbch'], leanbchExpansion: { frozenEngineId: 'leanbch', staticLabels: ['engine:leanbch:primary', 'engine:leanbch:secondary'] }, mayInterchange: false, acceptedRowOrder: null, workerRowsRootDomain: null },
  crashPolicy: { emitsFacts: [], createsRetryPredecessor: false, abortCloseSatisfiesRetry: false, jSatisfiesRetry: false, dSatisfiesRetry: false, automaticRetry: false, reuse: false },
});
const EXPECTED_CARDINALITY = Object.freeze({
  workloadTemplate: { source: 'P.kLaunchAuthority[*].workloads', value: 4608, unit: 'workloads-per-endpoint', endpointCount: 5 },
  workerRowSchema: { source: 'K.dispatch-plan.workerRows', minimum: 1, maximum: 4096, unit: 'worker-rows-per-dispatch-plan' },
  projection: { status: 'UNAVAILABLE_EXTERNAL', mayEquate: false, mayDerive: false, grantsAuthority: false },
});
const UPSTREAM_FILES = Object.freeze([
  { locator: '../cohort-runtime-binding-v1/runtime-binding-root.v1.json', rawSha256: 'b0ce9e0ec7b11770ed773b73a12ccb8a7d25a9ba3b4b38415dc1b90bf129d3dd' },
  { locator: '../cohort-runtime-binding-v1/MANIFEST.json', rawSha256: '2da4f55beba04efee8a019b1cac9493e7d6f099de91d36fe30d18e32cc5aa254' },
  { locator: '../cohort-runtime-binding-v1/SHA256SUMS', rawSha256: 'c25438471cfbd6949a886d723facb29ec5d0538be48dec7d28a87243065759ea' },
  { locator: '../cohort-runner-core-v1/runtime-core.v1.json', rawSha256: 'fc94be4544cf5e5e31c9f474a1ed3b95d47979fb23d46c55c9acffab9b690ea2' },
  { locator: '../cohort-runner-core-v1/MANIFEST.json', rawSha256: '913e5667c78de4f06a7ce34acfa13fb1393eeadbbf831641eab35ceddf3f01c4' },
  { locator: '../cohort-runner-core-v1/SHA256SUMS', rawSha256: '27ffdc493af8e77ab89b22dde1b424f0d9733bf9491013943b8a63ccc87bb4db' },
  { locator: '../cohort-runner-core-v1/schemas/worker-row.v1.schema.json', rawSha256: '6ff74e986cc12ad7eea100455ad41dcfb918311636c9e77c3e8053442b3460a2' },
  { locator: '../cohort-runner-core-v1/schemas/dispatch-plan.v1.schema.json', rawSha256: '821c60bd9385553e976bfad0d894ae6c0130a3085e1d9c367cb465cd878fb57b' },
  { locator: '../cohort-frozen-inputs-v1/frozen-inputs-root.v1.json', rawSha256: '19d90ed575404fa332f82d4cc28f1e1c4b71d99cff7f0d3a914664a0b72a2bd5' },
  { locator: '../cohort-frozen-inputs-v1/MANIFEST.json', rawSha256: 'f6b1dbf3f6757366c519e10f11e1fed80d071507445ad0085955aae164ad0867' },
  { locator: '../cohort-frozen-inputs-v1/SHA256SUMS', rawSha256: '4099e52c4acd2c2c34c49142bb28e6cb7ac31d048feb452e053038f3db578eff' },
  { locator: '../cohort-policy-authority-v1/policy-authority-root.v1.json', rawSha256: 'f037f88c311d29293e3d5f55999a58c3aada227510df5bb032d5590855189c6e' },
  { locator: '../cohort-policy-authority-v1/MANIFEST.json', rawSha256: '60fbc7ffe72e41a4df60603d9d4b6b0f0e118e1577028643fc867fbe3cb06bb1' },
  { locator: '../cohort-policy-authority-v1/SHA256SUMS', rawSha256: '66a8e1437c4c8d78dfa7600f7d0e1b83a2c6321c3f86b3d3a3dc2678eba992bb' },
  { locator: '../cohort-live-executor-v2/model-root.v2.json', rawSha256: '45ddc12f0b44136a4f85e2800a47c8b9ed000ed0f33acc252b31b0758bdd2ebb' },
  { locator: '../cohort-live-executor-v2/MANIFEST.json', rawSha256: 'ef03043f458915856b5c420e039208f6a0307633d20b21dac8238d73316fd98a' },
  { locator: '../cohort-live-executor-v2/SHA256SUMS', rawSha256: '0ef72e260de7afdc9bb508739321418be95c48879b09992669af23e71e3d7285' },
  { locator: '../cohort-live-executor-v2/validate-static.mjs', rawSha256: '31ef0e6f22eb6f6b20e426ca5ae4da2c0c8f7ed64becb693ad1da3fa81d8973a' },
]);

function fail(message) {
  throw new Error(`static validation failed: ${message}`);
}

function scalar(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) fail('lone surrogate in JSON');
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) fail('lone surrogate in JSON');
  }
}

function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    scalar(value);
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail('noncanonical number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('nonplain JSON record');
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function rawSha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function framedDigest(domain, value) {
  return createHash('sha256').update(Buffer.from(`${domain}\u0000${canonical(value)}\n`, 'utf8')).digest('hex');
}

function rawFileDigest(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('raw file digest input must be bytes');
  return createHash('sha256').update(Buffer.from(`${PREFIX}file\u0000`, 'utf8')).update(bytes).digest('hex');
}

function descriptor(domain, value) {
  return { algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value };
}

function read(root, locator) {
  return readFileSync(resolve(root, locator));
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(`${label} is not JSON`);
  }
}

function json(root, locator) {
  const bytes = read(root, locator);
  if (bytes.includes(0x0d)) fail(`${locator} has CR bytes`);
  const value = parseJson(bytes, locator);
  if (bytes.toString('utf8') !== `${canonical(value)}\n`) fail(`${locator} is not canonical JSON plus one final LF`);
  return value;
}

function equal(left, right, label) {
  if (canonical(left) !== canonical(right)) fail(`${label} differs`);
}

function exactKeys(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} is not an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has an unclosed key set`);
}

function collect(directory, prefix = '') {
  const files = [];
  const directories = [prefix || '.'];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const locator = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = join(directory, entry.name);
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) fail(`${locator} is a link`);
    if (stat.isDirectory()) {
      const nested = collect(absolute, locator);
      files.push(...nested.files);
      directories.push(...nested.directories);
    } else if (stat.isFile()) {
      files.push(locator);
    } else {
      fail(`${locator} is not a regular file or directory`);
    }
  }
  return { files, directories };
}

function checkFilesystem(root) {
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || rootStat.nlink !== 1 || (rootStat.mode & 0o7777) !== 0o755) fail('package root is not a 0755 single-link directory');
  const found = collect(root);
  equal(found.directories.sort(), [...DIRECTORIES].sort(), 'package directories');
  const expected = [...FILES, 'MANIFEST.json', 'SHA256SUMS'].sort();
  equal(found.files.sort(), expected, 'package closure');
  for (const locator of DIRECTORIES) {
    const stat = lstatSync(resolve(root, locator));
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o7777) !== 0o755) fail(`${locator} is not a 0755 single-link directory`);
  }
  for (const locator of expected) {
    const stat = lstatSync(resolve(root, locator));
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o7777) !== 0o644) fail(`${locator} is not a 0644 single-link regular file`);
    if (read(root, locator).includes(0x0d)) fail(`${locator} has CR bytes`);
  }
}

function isContained(parent, target) {
  const remainder = relative(parent, target);
  return remainder !== '' && remainder !== '..' && !remainder.startsWith(`..${sep}`) && !isAbsolute(remainder);
}

function safeUpstreamPath(root, locator) {
  const packageRoot = resolve(root);
  const gateRoot = dirname(packageRoot);
  if (basename(packageRoot) !== PACKAGE_DIRECTORY || basename(gateRoot) !== GATE_DIRECTORY) fail('upstream anchor is not the expected gate-b parent');
  const packageStat = lstatSync(packageRoot);
  const gateStat = lstatSync(gateRoot);
  if (!packageStat.isDirectory() || packageStat.isSymbolicLink() || !gateStat.isDirectory() || gateStat.isSymbolicLink()) fail('upstream anchor contains a link');
  if (realpathSync(packageRoot) !== packageRoot || realpathSync(gateRoot) !== gateRoot) fail('upstream anchor is noncanonical');
  const parts = locator.split('/');
  if (parts.length < 3 || parts[0] !== '..' || parts.slice(1).some((part) => part === '' || part === '.' || part === '..' || part.includes('\\') || part.includes('\u0000'))) fail(`${locator} is not an approved relative upstream locator`);
  const target = resolve(gateRoot, ...parts.slice(1));
  if (!isContained(gateRoot, target)) fail(`${locator} escapes the gate-b parent`);
  const relativeParts = relative(gateRoot, target).split(sep);
  let current = gateRoot;
  for (let index = 0; index < relativeParts.length; index += 1) {
    current = join(current, relativeParts[index]);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) fail(`${locator} contains a symlinked component`);
    if (index + 1 < relativeParts.length) {
      if (!stat.isDirectory()) fail(`${locator} has a non-directory intermediate component`);
    } else if (!stat.isFile() || stat.nlink !== 1) {
      fail(`${locator} is not a single-link regular pinned leaf`);
    }
  }
  const physicalTarget = realpathSync(target);
  if (physicalTarget !== target || !isContained(realpathSync(gateRoot), physicalTarget)) fail(`${locator} resolves outside its canonical gate-b parent`);
  return target;
}

function readUpstream(root, locator) {
  return readFileSync(safeUpstreamPath(root, locator));
}

function staticImports(source) {
  return [
    ...source.matchAll(/\bimport\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/g),
    ...source.matchAll(/\bexport\s+(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/g),
  ].map((match) => match[1]);
}

function checkPureClosure(root) {
  const imports = {
    'src/canonical.mjs': [],
    'src/sha256.mjs': [],
    'src/model.mjs': ['./canonical.mjs', './sha256.mjs'],
  };
  const exports = {
    'src/canonical.mjs': ['canonicalJson', 'utf8Encode'],
    'src/sha256.mjs': ['sha256Hex'],
    'src/model.mjs': ['AUTHORITY_DAG', 'DEPENDENCY_CATALOG', 'EXTERNAL_ORIGINS', 'FACT_CATALOG', 'STATE_GRAMMAR', 'DISPOSITIONS', 'assertAuthorityDag', 'assertDependencyCatalog', 'assertExternalOrigins', 'assertFactCatalog', 'assertStateGrammar', 'requiredPredecessors', 'ownerOf', 'availabilityOf', 'authorityDisposition', 'authorityDagDigest', 'dependencyCatalogDigest', 'externalOriginsDigest', 'factCatalogDigest', 'stateGrammarDigest', 'modelRootDigest'],
  };
  const forbidden = /node:|\bimport\.meta\b|\bimport\s*\(|\brequire\s*\(|\b(?:eval|Function|globalThis|WebAssembly|Deno|Bun|Worker|SharedWorker|process|setTimeout|setInterval|queueMicrotask|fetch|WebSocket|XMLHttpRequest|child_process|vm|net|http|https|writeFile|appendFile|mkdir|chmod|link|symlink|spawn|exec|fork|admitDispatch|advanceLifecycle|appendJournalEntry|canonicalWorkerEnvelope|workerRowsRoot)\b/;
  for (const [locator, expectedImports] of Object.entries(imports)) {
    const source = read(root, locator).toString('utf8');
    if (rawSha256(Buffer.from(source, 'utf8')) !== SOURCE_SHA256[locator]) fail(`${locator} differs from its sealed source`);
    if (forbidden.test(source)) fail(`${locator} has a forbidden pure-surface token`);
    const actualImports = staticImports(source);
    if (actualImports.some((specifier) => !specifier.startsWith('./'))) fail(`${locator} has a nonrelative import specifier`);
    equal(actualImports, expectedImports, `${locator} imports`);
    const terminal = source.match(/export\s*\{([\s\S]*?)\};\s*$/);
    if (!terminal) fail(`${locator} lacks a terminal exact export list`);
    if (/\bexport\b/.test(source.slice(0, terminal.index))) fail(`${locator} has an additional export surface`);
    const actualExports = terminal[1].split(',').map((name) => name.trim()).filter(Boolean);
    equal(actualExports, exports[locator], `${locator} exports`);
  }
}

function pinValue(id, pinId) {
  const dependency = DEPENDENCY_SPECS.find((entry) => entry.id === id);
  const pin = dependency?.pins.find((entry) => entry.id === pinId);
  if (!pin) fail(`internal missing ${id}.${pinId} pin`);
  return pin.value;
}

function requireValue(value, label) {
  if (typeof value !== 'string') fail(`${label} is absent`);
  return value;
}

function checkBindingRecord(record, id, expected) {
  if (!record || typeof record !== 'object') fail(`P ${id} binding is absent`);
  if (record.id !== id) fail(`P ${id} binding id`);
  for (const [path, value] of Object.entries(expected)) {
    const parts = path.split('.');
    let actual = record;
    for (const part of parts) actual = actual?.[part];
    if (actual !== value) fail(`P ${id} binding ${path}`);
  }
}

function checkUpstream(root) {
  const bytesByLocator = new Map();
  for (const pin of UPSTREAM_FILES) {
    const bytes = readUpstream(root, pin.locator);
    if (rawSha256(bytes) !== pin.rawSha256) fail(`${pin.locator} raw pin`);
    bytesByLocator.set(pin.locator, bytes);
  }
  const upstreamJson = (locator) => parseJson(bytesByLocator.get(locator), locator);
  const r = upstreamJson('../cohort-runtime-binding-v1/runtime-binding-root.v1.json');
  const kManifest = upstreamJson('../cohort-runner-core-v1/MANIFEST.json');
  const kWorkerSchema = upstreamJson('../cohort-runner-core-v1/schemas/worker-row.v1.schema.json');
  const f = upstreamJson('../cohort-frozen-inputs-v1/frozen-inputs-root.v1.json');
  const p = upstreamJson('../cohort-policy-authority-v1/policy-authority-root.v1.json');
  const v2 = upstreamJson('../cohort-live-executor-v2/model-root.v2.json');
  const v2Manifest = upstreamJson('../cohort-live-executor-v2/MANIFEST.json');
  if (requireValue(r.contentDigest?.value, 'R content digest') !== pinValue('R', 'root-content-digest')) fail('R content digest projection');
  if (requireValue(r.runtimeAuthority?.digest, 'R runtime authority digest') !== pinValue('R', 'runtime-authority-digest')) fail('R runtime authority projection');
  if (kManifest.packageRoot !== pinValue('K', 'manifest-package-root') || kManifest.manifestRoot !== pinValue('K', 'manifest-root') || kManifest.entriesRoot !== pinValue('K', 'entries-root')) fail('K manifest root projection');
  const endpointPattern = kWorkerSchema?.properties?.endpointId?.pattern;
  if (endpointPattern !== '^[a-z][a-z0-9-]{2,63}$' || canonical(kWorkerSchema).includes('engine:')) fail('K worker endpoint schema is not alias-only');
  if (requireValue(f.contentDigest?.value, 'F content digest') !== pinValue('F', 'root-content-digest')) fail('F content digest projection');
  const leaves = f.leafClosure?.leaves;
  if (!Array.isArray(leaves) || leaves.length !== 2 || leaves[0]?.id !== 'source-set-v1' || leaves[1]?.id !== 'cohort-freeze-v2') fail('F ordered leaf closure');
  if (leaves[0]?.nativeSemanticDigest?.value !== pinValue('F', 'source-native-semantic-digest') || leaves[1]?.artifactSemanticDigest?.value !== pinValue('F', 'freeze-artifact-semantic-digest')) fail('F leaf semantic projection');
  if (p.contentDigest?.value !== pinValue('P', 'root-content-digest') || p.bindingRoot?.value !== pinValue('P', 'binding-root') || p.policy?.contentDigest?.value !== pinValue('P', 'policy-content-digest') || p.causalDagRoot?.value !== pinValue('P', 'causal-dag-root') || p.policy?.liveF?.contentDigest?.value !== pinValue('P', 'live-f-template-digest')) fail('P semantic projection');
  equal(p.causalDag?.nodes?.slice(0, NODES.length), NODES, 'P authority DAG node prefix');
  equal(p.causalDag?.edges?.slice(0, EDGES.length), EDGES, 'P authority DAG edge prefix');
  equal(p.causalDag?.edges?.slice(EDGES.length), P_DOWNSTREAM, 'P authority DAG downstream closure');
  equal(p.policy?.aliasMap, { native: 'engine:native', libauth: 'engine:libauth', bchn: 'engine:bchn', 'leanbch-primary': 'engine:leanbch:primary', 'leanbch-secondary': 'engine:leanbch:secondary' }, 'P worker alias map');
  const pBindings = new Map((Array.isArray(p.dependencyBindings) ? p.dependencyBindings : []).map((binding) => [binding.id, binding]));
  checkBindingRecord(pBindings.get('R'), 'R', {
    'root.rawSha256': DEPENDENCY_SPECS[0].primaryRawSha256,
    'manifest.rawSha256': pinValue('R', 'manifest-raw-sha256'),
    'sums.rawSha256': pinValue('R', 'sha256sums-raw-sha256'),
    nativeContentDigest: pinValue('R', 'root-content-digest'),
    'bindingDigest.value': pinValue('R', 'binding-digest'),
    runtimeAuthorityDigest: pinValue('R', 'runtime-authority-digest'),
  });
  checkBindingRecord(pBindings.get('K'), 'K', {
    'root.rawSha256': DEPENDENCY_SPECS[1].primaryRawSha256,
    'manifest.rawSha256': pinValue('K', 'manifest-raw-sha256'),
    'sums.rawSha256': pinValue('K', 'sha256sums-raw-sha256'),
    manifestPackageRoot: pinValue('K', 'manifest-package-root'),
    manifestRoot: pinValue('K', 'manifest-root'),
    entriesRoot: pinValue('K', 'entries-root'),
    'bindingDigest.value': pinValue('K', 'binding-digest'),
  });
  checkBindingRecord(pBindings.get('F'), 'F', {
    'root.rawSha256': DEPENDENCY_SPECS[2].primaryRawSha256,
    'manifest.rawSha256': pinValue('F', 'manifest-raw-sha256'),
    'sums.rawSha256': pinValue('F', 'sha256sums-raw-sha256'),
    nativeContentDigest: pinValue('F', 'root-content-digest'),
    'bindingDigest.value': pinValue('F', 'binding-digest'),
    sourceNativeSemanticDigest: pinValue('F', 'source-native-semantic-digest'),
    freezeArtifactSemanticDigest: pinValue('F', 'freeze-artifact-semantic-digest'),
  });
  if (v2.contentDigest?.value !== pinValue('V2', 'root-content-digest') || v2Manifest.rosterDigest !== pinValue('V2', 'manifest-roster-digest') || v2.authority?.semanticBindingDigest !== pinValue('V2', 'p-semantic-binding-digest')) fail('V2 semantic projection');
  if (framedDigest('shieldkit-labs/p2/gate-b/cohort-live-executor/v2/authority-dag', v2.authorityDag) !== pinValue('V2', 'authority-dag-digest')) fail('V2 authority DAG projection');
  if (framedDigest('shieldkit-labs/p2/gate-b/cohort-live-executor/v2/transition-grammar', v2.transitionGrammar) !== pinValue('V2', 'transition-grammar-digest')) fail('V2 transition grammar projection');
  const v2P = v2.authority?.pRoot;
  if (v2P?.rawSha256 !== DEPENDENCY_SPECS[3].primaryRawSha256 || v2P?.contentDigest !== pinValue('P', 'root-content-digest') || v2P?.bindingDigest !== pinValue('P', 'binding-root') || v2P?.policyDigest !== pinValue('P', 'policy-content-digest') || v2P?.authorityDagDigest !== pinValue('P', 'causal-dag-root') || v2P?.liveFDigest !== pinValue('P', 'live-f-template-digest')) fail('V2 P projection');
}

function checkSemantic(document) {
  exactKeys(document, ['schema', 'identifier', 'status', 'staticDependencies', 'pinnedAuthorityDag', 'externalOrigins', 'facts', 'stateGrammar', 'cardinalitySeparation', 'contentDigest'], 'root');
  if (document.schema !== `${PREFIX}model-root/v1` || document.identifier !== IDENTIFIER || document.status !== STATUS) fail('root identity');
  equal(document.pinnedAuthorityDag, { nodes: NODES, edges: EDGES }, 'pinned authority DAG');
  const dependencies = document.staticDependencies;
  exactKeys(dependencies, ['schema', 'identifier', 'entries'], 'static dependencies');
  if (dependencies.schema !== `${PREFIX}dependency-catalog/v1` || dependencies.identifier !== IDENTIFIER || !Array.isArray(dependencies.entries)) fail('static dependency identity');
  equal(dependencies.entries.map((entry) => entry.id), DEPENDENCY_SPECS.map((entry) => entry.id), 'static dependency order');
  for (let index = 0; index < DEPENDENCY_SPECS.length; index += 1) {
    const expected = DEPENDENCY_SPECS[index];
    const entry = dependencies.entries[index];
    exactKeys(entry, ['id', 'artifactId', 'primaryRawSha256', 'pins', 'authenticates', 'doesNotAuthenticate'], `static dependency ${expected.id}`);
    if (entry.id !== expected.id || entry.artifactId !== expected.artifactId || entry.primaryRawSha256 !== expected.primaryRawSha256) fail(`static dependency ${expected.id} identity`);
    equal(entry.pins, expected.pins, `static dependency ${expected.id} pins`);
    equal(entry.authenticates, STATIC_AUTHENTICATES, `static dependency ${expected.id} authenticates`);
    equal(entry.doesNotAuthenticate, STATIC_DOES_NOT_AUTHENTICATE, `static dependency ${expected.id} does-not-authenticate`);
  }
  equal(document.externalOrigins, EXPECTED_ORIGINS, 'external origins');
  equal(document.facts, EXPECTED_FACTS, 'facts');
  equal(document.stateGrammar, EXPECTED_STATE_GRAMMAR, 'state grammar');
  equal(document.cardinalitySeparation, EXPECTED_CARDINALITY, 'cardinality separation');
}

function checkSchemas(root, document, manifest) {
  const schemas = Object.fromEntries(Object.keys(SCHEMA_SHA256).map((locator) => [locator, json(root, locator)]));
  for (const [locator, expected] of Object.entries(SCHEMA_SHA256)) {
    if (rawSha256(read(root, locator)) !== expected) fail(`${locator} differs from its sealed schema`);
  }
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const schema of Object.values(schemas)) ajv.addSchema(schema);
  const validateRoot = ajv.getSchema(schemas['schemas/model-root.v1.schema.json'].$id);
  const validateManifest = ajv.getSchema(schemas['schemas/manifest.v1.schema.json'].$id);
  if (!validateRoot?.(document)) fail(`model root schema: ${ajv.errorsText(validateRoot?.errors)}`);
  if (!validateManifest?.(manifest)) fail(`manifest schema: ${ajv.errorsText(validateManifest?.errors)}`);
}

function checkEnvelope(root, document, manifest) {
  const payload = {
    schema: document.schema,
    identifier: document.identifier,
    status: document.status,
    staticDependencies: document.staticDependencies,
    pinnedAuthorityDag: document.pinnedAuthorityDag,
    externalOrigins: document.externalOrigins,
    facts: document.facts,
    stateGrammar: document.stateGrammar,
    cardinalitySeparation: document.cardinalitySeparation,
  };
  const digest = framedDigest(`${PREFIX}root`, payload);
  if (digest !== ROOT_CONTENT_DIGEST) fail('root semantic digest pin');
  equal(document.contentDigest, descriptor(`${PREFIX}root`, digest), 'root content digest descriptor');
  const entries = FILES.map((locator) => {
    const bytes = read(root, locator);
    return { locator, bytes: bytes.length, sha256: rawSha256(bytes), fileDigest: rawFileDigest(bytes) };
  });
  const locators = manifest.entries?.map((entry) => entry.locator);
  equal(locators, FILES, 'manifest locator order');
  if (new Set(locators).size !== FILES.length) fail('manifest locators are not unique');
  const expectedManifest = {
    schema: `${PREFIX}manifest/v1`,
    format: `${PREFIX}manifest/1`,
    package: IDENTIFIER,
    entryCount: FILES.length,
    entries,
    rosterDigest: framedDigest(`${PREFIX}manifest-roster`, { package: IDENTIFIER, entries }),
  };
  equal(manifest, expectedManifest, 'manifest');
  const sums = [...entries, { locator: 'MANIFEST.json', sha256: rawSha256(read(root, 'MANIFEST.json')) }]
    .map((entry) => `${entry.sha256}  ${entry.locator}`).join('\n');
  if (read(root, 'SHA256SUMS').toString('utf8') !== `${sums}\n`) fail('SHA256SUMS differs');
}

function validateStatic({ root = ROOT } = {}) {
  checkFilesystem(root);
  const document = json(root, 'authority-binding-root.v1.json');
  const manifest = json(root, 'MANIFEST.json');
  checkSemantic(document);
  checkUpstream(root);
  checkSchemas(root, document, manifest);
  checkPureClosure(root);
  checkEnvelope(root, document, manifest);
  return true;
}

function cliRoot() {
  const index = process.argv.indexOf('--root');
  if (index === -1) return ROOT;
  if (index + 1 >= process.argv.length || process.argv.length !== index + 2) fail('usage: node validate-static.mjs [--root directory]');
  return resolve(process.argv[index + 1]);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    validateStatic({ root: cliRoot() });
    process.stdout.write('static validation: PASS\n');
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

export { rawFileDigest, validateStatic };
