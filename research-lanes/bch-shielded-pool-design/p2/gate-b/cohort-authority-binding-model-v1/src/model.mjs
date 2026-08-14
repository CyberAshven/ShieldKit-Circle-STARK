import { canonicalJson, utf8Encode } from './canonical.mjs';
import { sha256Hex } from './sha256.mjs';

const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/';
const IDENTIFIER = 'cohort-authority-binding-model-v1';
const ROOT_SCHEMA = `${PREFIX}model-root/v1`;
const ROOT_STATUS = 'static-authority-binding-catalog-non-authorizing-external-origins-unavailable-unqualified';
const VARIANTS = ['initial', 'retry', 'abort'];
const FACT_IDS = ['Q', 'A', 'LIVE_F', 'B', 'C', 'J', 'D'];

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const key of Reflect.ownKeys(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
}

function fail(message) {
  throw new TypeError(`cohort-authority-binding-model-v1 model: ${message}`);
}

function exactRecord(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be a record`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail(`${label} must be a plain record`);
  const ownKeys = Reflect.ownKeys(value);
  for (const key of ownKeys) {
    if (typeof key !== 'string') fail(`${label} has a symbol key`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail(`${label} has a non-data or non-enumerable key`);
  }
  const actual = ownKeys.sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has an unclosed key set`);
  return value;
}

function exactArray(value, expected, label) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length !== expected.length) fail(`${label} is not exact`);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== value.length + 1 || !ownKeys.includes('length')) fail(`${label} has an extended array shape`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || descriptor.value !== expected[index]) fail(`${label} is not exact`);
  }
  return value;
}

function digest(suffix, value) {
  return sha256Hex(utf8Encode(`${PREFIX}${suffix}\u0000${canonicalJson(value)}\n`));
}

const AUTHORITY_DAG = deepFreeze({
  nodes: ['N', 'E', 'X', 'SOURCE', 'COHORT', 'R', 'K', 'F', 'P', 'Q', 'A', 'B', 'C', 'J', 'D', 'LIVE_F', 'WORKER_ROWS_ROOT'],
  edges: ['N→R', 'E→R', 'X→R', 'SOURCE→F', 'COHORT→F', 'R→P', 'K→P', 'F→P', 'Q→A', 'P→A', 'A→B', 'P→B', 'R→B', 'K→B', 'LIVE_F→B', 'B→C', 'B→J', 'C→J', 'B→D', 'C→D', 'J→D', 'WORKER_ROWS_ROOT→D'],
});

const STATIC_AUTHENTICATES = ['static-byte-pins', 'static-schema-types', 'static-catalog-types'];
const STATIC_DOES_NOT_AUTHENTICATE = ['concrete-retry-predecessor', 'live-private-capture', 'private-handles', 'worker-rows-root', 'activation', 'execution'];

const DEPENDENCY_CATALOG = deepFreeze({
  schema: `${PREFIX}dependency-catalog/v1`,
  identifier: IDENTIFIER,
  entries: [
    {
      id: 'R',
      artifactId: 'artifact:gate-b:cohort-runtime-binding-v1',
      primaryRawSha256: 'b0ce9e0ec7b11770ed773b73a12ccb8a7d25a9ba3b4b38415dc1b90bf129d3dd',
      pins: [
        { id: 'manifest-raw-sha256', value: '2da4f55beba04efee8a019b1cac9493e7d6f099de91d36fe30d18e32cc5aa254' },
        { id: 'sha256sums-raw-sha256', value: 'c25438471cfbd6949a886d723facb29ec5d0538be48dec7d28a87243065759ea' },
        { id: 'root-content-digest', value: '8b73e8bbbfd97d8c451c5fd9466ff219ab36eeb65e3fb10c5f3629a89da36af1' },
        { id: 'binding-digest', value: 'dbdcc046adaac671b5c4ed6a990f2579b6990a39a205434a0f19de0ba139758d' },
        { id: 'runtime-authority-digest', value: 'fce66bed0f375e922e6b765a74f6b0dd81f784029df6079cee4668f89bb872d8' }
      ],
      authenticates: [...STATIC_AUTHENTICATES],
      doesNotAuthenticate: [...STATIC_DOES_NOT_AUTHENTICATE]
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
        { id: 'worker-row-endpoint-id-aliases', value: 'native,libauth,bchn,leanbch-primary,leanbch-secondary' }
      ],
      authenticates: [...STATIC_AUTHENTICATES],
      doesNotAuthenticate: [...STATIC_DOES_NOT_AUTHENTICATE]
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
        { id: 'frozen-four-surface-order', value: 'native,libauth,bchn,leanbch' }
      ],
      authenticates: [...STATIC_AUTHENTICATES],
      doesNotAuthenticate: [...STATIC_DOES_NOT_AUTHENTICATE]
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
        { id: 'b-envelope-template-digest', value: '30c20e86feb89317653b0bc14d84d90f95d86c4cc98d7cb030f1cdbf2ed8986a' }
      ],
      authenticates: [...STATIC_AUTHENTICATES],
      doesNotAuthenticate: [...STATIC_DOES_NOT_AUTHENTICATE]
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
        { id: 'transition-grammar-digest', value: 'dc4680aa570ac87fc3972c644405b4be0ab59e63637917ae846a650432c4553b' }
      ],
      authenticates: [...STATIC_AUTHENTICATES],
      doesNotAuthenticate: [...STATIC_DOES_NOT_AUTHENTICATE]
    }
  ]
});

const DEPENDENCY_PIN_IDS = deepFreeze({
  R: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'root-content-digest', 'binding-digest', 'runtime-authority-digest'],
  K: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'manifest-package-root', 'manifest-root', 'entries-root', 'binding-digest', 'worker-row-schema-raw-sha256', 'dispatch-plan-schema-raw-sha256', 'worker-row-endpoint-id-aliases'],
  F: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'root-content-digest', 'binding-digest', 'source-native-semantic-digest', 'freeze-artifact-semantic-digest', 'ordered-leaf-ids', 'frozen-four-surface-order'],
  P: ['manifest-raw-sha256', 'sha256sums-raw-sha256', 'root-content-digest', 'binding-root', 'policy-content-digest', 'causal-dag-root', 'live-f-template-digest', 'worker-alias-map', 'q-initial-template-digest', 'q-retry-template-digest', 'q-abort-template-digest', 'a-initial-template-digest', 'a-retry-template-digest', 'a-abort-template-digest', 'b-subject-template-digest', 'b-envelope-template-digest'],
  V2: ['root-content-digest', 'manifest-raw-sha256', 'sha256sums-raw-sha256', 'validator-raw-sha256', 'manifest-roster-digest', 'p-semantic-binding-digest', 'authority-dag-digest', 'transition-grammar-digest'],
});

const EXTERNAL_ORIGINS = deepFreeze({
  schema: `${PREFIX}external-origin-catalog/v1`,
  identifier: IDENTIFIER,
  entries: [
    { id: 'RETRY_PREDECESSOR', ownerClass: 'unavailable-recovery-chain-owner', originFor: 'Q:retry', staticAuthenticators: ['P', 'V2'], availability: 'unavailable', modelDisposition: 'BLOCKED_EXTERNAL', grantsAuthority: false },
    { id: 'LIVE_F_CAPTURE', ownerClass: 'unavailable-private-capture-owner', originFor: 'LIVE_F', staticAuthenticators: ['P', 'F', 'V2'], availability: 'unavailable', modelDisposition: 'UNAVAILABLE_EXTERNAL', grantsAuthority: false },
    { id: 'WORKER_ROWS_ROOT', ownerClass: 'unavailable-private-dispatch-owner', originFor: 'D', staticAuthenticators: ['R', 'K', 'F', 'P', 'V2'], availability: 'unavailable', modelDisposition: 'BLOCKED_EXTERNAL', grantsAuthority: false }
  ]
});

const FACT_CATALOG = deepFreeze({
  schema: `${PREFIX}fact-catalog/v1`,
  identifier: IDENTIFIER,
  entries: [
    { id: 'Q', requiredOwnerClass: 'unavailable-request-owner', staticAuthenticators: ['P', 'V2'], variants: ['initial', 'retry', 'abort'], statePredecessors: { initial: [], retry: ['RETRY_PREDECESSOR'], abort: [] }, originRequirements: { initial: [], retry: ['RETRY_PREDECESSOR'], abort: [] }, grantsAuthority: false },
    { id: 'A', requiredOwnerClass: 'unavailable-activation-owner', staticAuthenticators: ['P', 'V2'], variants: ['initial', 'retry', 'abort'], statePredecessors: { initial: ['Q'], retry: ['Q'], abort: ['Q'] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'LIVE_F', requiredOwnerClass: 'unavailable-private-capture-owner', staticAuthenticators: ['P', 'F', 'V2'], variants: ['initial'], statePredecessors: { initial: [], retry: [], abort: [] }, originRequirements: { initial: ['LIVE_F_CAPTURE'], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'B', requiredOwnerClass: 'unavailable-private-descriptor-owner', staticAuthenticators: ['R', 'K', 'P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['A', 'LIVE_F'], retry: [], abort: [] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'C', requiredOwnerClass: 'unavailable-exclusive-c-owner', staticAuthenticators: ['P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B'], retry: [], abort: [] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'J', requiredOwnerClass: 'none', staticAuthenticators: ['P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B', 'C'], retry: [], abort: [] }, originRequirements: { initial: [], retry: [], abort: [] }, grantsAuthority: false },
    { id: 'D', requiredOwnerClass: 'unavailable-private-dispatch-owner', staticAuthenticators: ['R', 'K', 'F', 'P', 'V2'], variants: ['initial'], statePredecessors: { initial: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'], retry: [], abort: [] }, originRequirements: { initial: ['WORKER_ROWS_ROOT'], retry: [], abort: [] }, grantsAuthority: false }
  ]
});

const STATE_GRAMMAR = deepFreeze({
  schema: `${PREFIX}state-grammar/v1`,
  identifier: IDENTIFIER,
  variants: [...VARIANTS],
  stateFacts: [...FACT_IDS],
  initial: { modelDisposition: 'abstract-model-only', factOrder: ['Q', 'A', 'LIVE_F', 'B', 'C', 'J'], neverAdmitted: ['D'] },
  retry: { stateFacts: [], qPredecessors: ['RETRY_PREDECESSOR'], qDisposition: 'BLOCKED_EXTERNAL', aDisposition: 'DENY_PREREQUISITE', automaticRetry: false },
  abort: { qPredecessors: [], aPredecessors: ['Q'], closeDisposition: 'abstract-close-only', emitsFacts: [], synthesizesRetryPredecessor: false },
  d: { statePredecessors: ['B', 'C', 'J', 'WORKER_ROWS_ROOT'], originRequirements: ['WORKER_ROWS_ROOT'], disposition: 'BLOCKED_EXTERNAL', neverAdmitted: true },
  capture: {
    templateId: 'LIVE_F_TEMPLATE',
    originId: 'LIVE_F_CAPTURE',
    factId: 'LIVE_F',
    templateSatisfiesOrigin: false,
    frozenInputSatisfiesOrigin: false,
    bToOriginAuthorityEdge: false,
    preB: 'immutable-private-capture-commitment',
    postB: 'retention-metadata-nonauthority'
  },
  aliasSeparation: {
    workerRowEndpointIds: ['native', 'libauth', 'bchn', 'leanbch-primary', 'leanbch-secondary'],
    frozenEngineOrder: ['native', 'libauth', 'bchn', 'leanbch'],
    leanbchExpansion: { frozenEngineId: 'leanbch', staticLabels: ['engine:leanbch:primary', 'engine:leanbch:secondary'] },
    mayInterchange: false,
    acceptedRowOrder: null,
    workerRowsRootDomain: null
  },
  crashPolicy: {
    emitsFacts: [],
    createsRetryPredecessor: false,
    abortCloseSatisfiesRetry: false,
    jSatisfiesRetry: false,
    dSatisfiesRetry: false,
    automaticRetry: false,
    reuse: false
  }
});

const CARDINALITY_SEPARATION = deepFreeze({
  workloadTemplate: { source: 'P.kLaunchAuthority[*].workloads', value: 4608, unit: 'workloads-per-endpoint', endpointCount: 5 },
  workerRowSchema: { source: 'K.dispatch-plan.workerRows', minimum: 1, maximum: 4096, unit: 'worker-rows-per-dispatch-plan' },
  projection: { status: 'UNAVAILABLE_EXTERNAL', mayEquate: false, mayDerive: false, grantsAuthority: false }
});

const DISPOSITIONS = deepFreeze({
  catalogOnly: 'CATALOG_ONLY',
  blockedExternal: 'BLOCKED_EXTERNAL',
  unavailableExternal: 'UNAVAILABLE_EXTERNAL',
  deniedPrerequisite: 'DENY_PREREQUISITE'
});

function assertAuthorityDag(candidate = AUTHORITY_DAG) {
  exactRecord(candidate, ['nodes', 'edges'], 'authority requirement DAG');
  if (!Array.isArray(candidate.nodes) || !Array.isArray(candidate.edges)) fail('authority requirement DAG fields must be arrays');
  const nodes = new Set(candidate.nodes);
  if (nodes.size !== candidate.nodes.length || candidate.nodes.some((node) => typeof node !== 'string')) fail('authority requirement DAG nodes are not unique identifiers');
  const edges = new Set();
  const adjacency = new Map(candidate.nodes.map((node) => [node, []]));
  for (const edge of candidate.edges) {
    if (typeof edge !== 'string' || !edge.includes('→')) fail('authority requirement DAG edge is malformed');
    if (edges.has(edge)) fail('authority requirement DAG has a duplicate edge');
    edges.add(edge);
    const parts = edge.split('→');
    if (parts.length !== 2 || !nodes.has(parts[0]) || !nodes.has(parts[1])) fail('authority requirement DAG edge has an unknown endpoint');
    adjacency.get(parts[0]).push(parts[1]);
  }
  const visiting = new Set();
  const visited = new Set();
  const visit = (node) => {
    if (visiting.has(node)) fail('authority requirement DAG contains a cycle');
    if (visited.has(node)) return;
    visiting.add(node);
    for (const next of adjacency.get(node)) visit(next);
    visiting.delete(node);
    visited.add(node);
  };
  for (const node of candidate.nodes) visit(node);
  exactArray(candidate.nodes, AUTHORITY_DAG.nodes, 'authority requirement DAG nodes');
  exactArray(candidate.edges, AUTHORITY_DAG.edges, 'authority requirement DAG edges');
  return AUTHORITY_DAG;
}

function assertDependencyCatalog(candidate = DEPENDENCY_CATALOG) {
  exactRecord(candidate, ['schema', 'identifier', 'entries'], 'dependency catalog');
  if (!Array.isArray(candidate.entries)) fail('dependency catalog entries must be an array');
  exactArray(candidate.entries.map((entry) => entry.id), ['R', 'K', 'F', 'P', 'V2'], 'dependency catalog entry order');
  for (const entry of candidate.entries) {
    exactRecord(entry, ['id', 'artifactId', 'primaryRawSha256', 'pins', 'authenticates', 'doesNotAuthenticate'], `dependency ${entry.id}`);
    if (!Array.isArray(entry.pins)) fail(`dependency ${entry.id} pins must be an array`);
    exactArray(entry.pins.map((pin) => pin.id), DEPENDENCY_PIN_IDS[entry.id], `dependency ${entry.id} pin order`);
  }
  if (canonicalJson(candidate) !== canonicalJson(DEPENDENCY_CATALOG)) fail('dependency catalog is not exact');
  return DEPENDENCY_CATALOG;
}

function assertExternalOrigins(candidate = EXTERNAL_ORIGINS) {
  if (canonicalJson(candidate) !== canonicalJson(EXTERNAL_ORIGINS)) fail('external origin catalog is not exact');
  return EXTERNAL_ORIGINS;
}

function assertFactCatalog(candidate = FACT_CATALOG) {
  if (canonicalJson(candidate) !== canonicalJson(FACT_CATALOG)) fail('fact catalog is not exact');
  return FACT_CATALOG;
}

function assertStateGrammar(candidate = STATE_GRAMMAR) {
  if (canonicalJson(candidate) !== canonicalJson(STATE_GRAMMAR)) fail('state grammar is not exact');
  return STATE_GRAMMAR;
}

function requiredPredecessors(fact, variant = 'initial') {
  if (!VARIANTS.includes(variant)) fail('unknown variant');
  const entry = FACT_CATALOG.entries.find((item) => item.id === fact);
  if (!entry) fail('unknown fact');
  return deepFreeze([...entry.statePredecessors[variant]]);
}

function ownerOf(id) {
  const fact = FACT_CATALOG.entries.find((item) => item.id === id);
  const origin = EXTERNAL_ORIGINS.entries.find((item) => item.id === id);
  if (!fact && !origin) fail('unknown authority item');
  return fact ? fact.requiredOwnerClass : origin.ownerClass;
}

function availabilityOf(id) {
  const origin = EXTERNAL_ORIGINS.entries.find((item) => item.id === id);
  if (origin) return origin.availability;
  if (FACT_CATALOG.entries.some((item) => item.id === id)) return 'abstract';
  fail('unknown authority item');
}

function authorityDisposition(id) {
  const origin = EXTERNAL_ORIGINS.entries.find((item) => item.id === id);
  if (origin) return origin.modelDisposition;
  if (!FACT_CATALOG.entries.some((item) => item.id === id)) fail('unknown authority item');
  return id === 'D' ? DISPOSITIONS.blockedExternal : DISPOSITIONS.catalogOnly;
}

function authorityDagDigest() {
  assertAuthorityDag();
  return digest('authority-requirement-dag', AUTHORITY_DAG);
}

function dependencyCatalogDigest() {
  assertDependencyCatalog();
  return digest('dependency-catalog', DEPENDENCY_CATALOG);
}

function externalOriginsDigest() {
  assertExternalOrigins();
  return digest('external-origin-catalog', EXTERNAL_ORIGINS);
}

function factCatalogDigest() {
  assertFactCatalog();
  return digest('fact-catalog', FACT_CATALOG);
}

function stateGrammarDigest() {
  assertStateGrammar();
  return digest('state-grammar', STATE_GRAMMAR);
}

function modelRootDigest() {
  return digest('root', {
    schema: ROOT_SCHEMA,
    identifier: IDENTIFIER,
    status: ROOT_STATUS,
    staticDependencies: DEPENDENCY_CATALOG,
    pinnedAuthorityDag: AUTHORITY_DAG,
    externalOrigins: EXTERNAL_ORIGINS,
    facts: FACT_CATALOG,
    stateGrammar: STATE_GRAMMAR,
    cardinalitySeparation: CARDINALITY_SEPARATION
  });
}

export {
  AUTHORITY_DAG,
  DEPENDENCY_CATALOG,
  EXTERNAL_ORIGINS,
  FACT_CATALOG,
  STATE_GRAMMAR,
  DISPOSITIONS,
  assertAuthorityDag,
  assertDependencyCatalog,
  assertExternalOrigins,
  assertFactCatalog,
  assertStateGrammar,
  requiredPredecessors,
  ownerOf,
  availabilityOf,
  authorityDisposition,
  authorityDagDigest,
  dependencyCatalogDigest,
  externalOriginsDigest,
  factCatalogDigest,
  stateGrammarDigest,
  modelRootDigest,
};
