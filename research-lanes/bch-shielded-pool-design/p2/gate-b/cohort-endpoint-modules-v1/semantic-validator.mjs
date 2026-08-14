/* Static package validator. It reads endpoint bytes but never imports, links,
 * evaluates, or invokes them; it also never starts a process or writes state. */
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(here);
/* Immutable reviewed-source authority. These exact bytes are accepted; the
 * controller grammar below is defense in depth, not a proof over arbitrary JS. */
const REVIEWED_ENDPOINT_SOURCES = Object.freeze({
  native: Object.freeze({
    module: Object.freeze({ bytes: 8681, rawSha256: 'cfce38c363bb640337c655b005c4d7356691bf53feb335744b7a62578bf400a1' }),
    kernel: Object.freeze({ bytes: 5054, rawSha256: '340d7689ea68cf889429cdd39b13ce880990b38c1615879d6995935eba48ea4e' }),
    controller: Object.freeze({ bytes: 3627, rawSha256: '5b5d16a7d9d5664adeb32871ce25fa932fc88055facb5d4c0e080bac75c74e10' }),
    frozenSource: Object.freeze({ bytes: 5055, rawSha256: '0fda97077946b2b9a220205155087fd74369a7ece937adc5d1052e22e1924a1c' }),
  }),
  libauth: Object.freeze({
    module: Object.freeze({ bytes: 598489, rawSha256: '1ab077926b7e5b2c11bc04f7610d2bfad96d8f51274feb57dc792823bc030575' }),
    bundle: Object.freeze({ bytes: 593066, rawSha256: 'ffbee87e074d6df03a03a2068a8f77fe6776f8139cd9bd2cb5e3ac70091bf68f' }),
    controller: Object.freeze({ bytes: 5423, rawSha256: '4f28e4500e79655ec252be86cc78765f96a21db448601fe7c3717c72245f39fd' }),
  }),
});
const BUNDLE_BYTES = REVIEWED_ENDPOINT_SOURCES.libauth.bundle.bytes;
const BUNDLE_SHA256 = REVIEWED_ENDPOINT_SOURCES.libauth.bundle.rawSha256;
const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const ROOT_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/root';
const FILE_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/file-content';
const PACKAGE_ROSTER_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/package-roster';
const ROOT_FILE = 'cohort-endpoint-modules.v1.json';
const VALIDATOR_FILE = 'semantic-validator.mjs';
const PACKAGE_ENVELOPE_RULE = 'root-binds-manifest-sha256sums-and-validator; manifest-excludes-root-manifest-and-sha256sums; sha256sums-covers-manifest-and-manifest-roster-excludes-root-and-self-v1';
const SCHEMA_BINDINGS = Object.freeze([
  { name: 'root', path: 'schemas/root.v1.schema.json', id: 'https://shieldkit-labs.local/p2/gate-b/cohort-endpoint-modules/v1/root.v1.schema.json', rawSha256: 'd2969da2dd8911a7f9822c7474d5176ab5e0f256e11980eb4be643f427159788' },
  { name: 'contract', path: 'schemas/endpoint-contract.v1.schema.json', id: 'https://shieldkit-labs.local/p2/gate-b/cohort-endpoint-modules/v1/endpoint-contract.v1.schema.json', rawSha256: 'cce33dc8fb534ea8d5c7db84cad846e7ce4e160fc66ada550c22d033a80b4dc5' },
  { name: 'endpoint', path: 'schemas/endpoint-module.v1.schema.json', id: 'https://shieldkit-labs.local/p2/gate-b/cohort-endpoint-modules/v1/endpoint-module.v1.schema.json', rawSha256: '3a1d57302b202dada7d2139abe5f45139981c72fdde6110fbd09399af9be2965' },
  { name: 'materialization', path: 'schemas/materialization.v1.schema.json', id: 'https://shieldkit-labs.local/p2/gate-b/cohort-endpoint-modules/v1/materialization.v1.schema.json', rawSha256: '7e4e550b9d62c7f8e8e1f5b4911cf2b6393c5f095dd35eaac57113b61fa07b63' },
  { name: 'manifest', path: 'schemas/manifest.v1.schema.json', id: 'https://shieldkit-labs.local/p2/gate-b/cohort-endpoint-modules/v1/manifest.v1.schema.json', rawSha256: '22943eee4bd80d1025c479002c9b93c3bc3b0b60e757c7d6d7248f1785af7d6a' },
]);
const endpointNames = Object.freeze(['engine:native', 'engine:libauth']);
const exact = (value, keys, label) => requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()), `${label} exact keys`);
const requireCondition = (condition, message) => { if (!condition) throw new Error(`cohort-endpoint-modules-v1: ${message}`); };
const sha256 = value => createHash('sha256').update(value).digest('hex');
const canonicalize = value => Array.isArray(value) ? value.map(canonicalize) : value !== null && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])])) : value;
const canonicalJson = value => Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8');
const domainDigest = (domain, value) => sha256(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.of(0), Buffer.isBuffer(value) ? value : canonicalJson(value)]));
const assertReviewedBytes = (raw, identity, label) => requireCondition(raw.length === identity.bytes && sha256(raw) === identity.rawSha256, `fixed reviewed ${label} identity`);
const assertReviewedEndpointSource = (endpointId, raw) => {
  if (endpointId === 'engine:native') {
    const reviewed = REVIEWED_ENDPOINT_SOURCES.native;
    assertReviewedBytes(raw.subarray(0, reviewed.kernel.bytes), reviewed.kernel, 'engine:native kernel');
    assertReviewedBytes(raw.subarray(reviewed.kernel.bytes), reviewed.controller, 'engine:native controller suffix');
    assertReviewedBytes(raw, reviewed.module, 'engine:native module');
    return;
  }
  requireCondition(endpointId === 'engine:libauth', 'reviewed endpoint identity');
  const reviewed = REVIEWED_ENDPOINT_SOURCES.libauth;
  assertReviewedBytes(raw.subarray(0, reviewed.bundle.bytes), reviewed.bundle, 'engine:libauth bundle prefix');
  assertReviewedBytes(raw.subarray(reviewed.bundle.bytes), reviewed.controller, 'engine:libauth controller suffix');
  assertReviewedBytes(raw, reviewed.module, 'engine:libauth module');
};
const local = (root, file) => resolve(root, file);
const packagePrefix = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-endpoint-modules-v1/';

const json = (root, file) => {
  const raw = readFileSync(local(root, file));
  requireCondition(raw.length > 0 && raw.at(-1) === 0x0a && !raw.includes(0x0d), `${file} canonical LF bytes`);
  try { return { raw, value: JSON.parse(raw.toString('utf8')) }; } catch (error) { throw new Error(`cohort-endpoint-modules-v1: ${file} invalid JSON: ${error.message}`); }
};
const readonlyRegular = (root, file, label) => {
  const stat = lstatSync(local(root, file));
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o777) === 0o444, `${label} readonly regular single-link file`);
  return stat;
};
const walk = (root, directory = '') => {
  const files = []; const directories = [];
  const current = local(root, directory || '.');
  for (const entry of readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const path = directory ? `${directory}/${entry.name}` : entry.name;
    const stat = lstatSync(local(root, path));
    requireCondition(!stat.isSymbolicLink(), `link forbidden: ${path}`);
    if (stat.isDirectory()) { directories.push({ path, mode: stat.mode & 0o777 }); const nested = walk(root, path); files.push(...nested.files); directories.push(...nested.directories); }
    else { requireCondition(stat.isFile(), `non-regular package node: ${path}`); files.push({ path, mode: stat.mode & 0o777, bytes: stat.size, sha256: sha256(readFileSync(local(root, path))), nlink: stat.nlink }); }
  }
  return { files, directories };
};

const isIdentStart = value => /[A-Za-z_$]/u.test(value);
const isIdent = value => /[A-Za-z0-9_$]/u.test(value);
const skipQuoted = (source, start, quote) => { let index = start + 1; while (index < source.length) { if (source[index] === '\\') { index += 2; continue; } if (source[index] === quote) return index + 1; index += 1; } throw new Error('unterminated string literal'); };
const decodeQuotedLiteral = (source, start, end) => {
  let value = '';
  for (let index = start + 1; index < end - 1; index += 1) {
    const character = source[index];
    if (character !== '\\') { value += character; continue; }
    requireCondition(index + 1 < end - 1, 'unterminated string escape');
    index += 1; const escaped = source[index];
    const simple = { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', 0: '\0' };
    if (Object.hasOwn(simple, escaped)) { value += simple[escaped]; continue; }
    if (escaped === '\n') continue;
    if (escaped === '\r') { if (source[index + 1] === '\n') index += 1; continue; }
    if (escaped === 'x') {
      const hex = source.slice(index + 1, index + 3); requireCondition(/^[0-9a-fA-F]{2}$/u.test(hex), 'invalid hexadecimal string escape');
      value += String.fromCharCode(Number.parseInt(hex, 16)); index += 2; continue;
    }
    if (escaped === 'u') {
      if (source[index + 1] === '{') {
        const close = source.indexOf('}', index + 2); const hex = close < 0 ? '' : source.slice(index + 2, close);
        requireCondition(/^[0-9a-fA-F]{1,6}$/u.test(hex) && Number.parseInt(hex, 16) <= 0x10ffff, 'invalid Unicode code-point string escape');
        value += String.fromCodePoint(Number.parseInt(hex, 16)); index = close; continue;
      }
      const hex = source.slice(index + 1, index + 5); requireCondition(/^[0-9a-fA-F]{4}$/u.test(hex), 'invalid Unicode string escape');
      value += String.fromCharCode(Number.parseInt(hex, 16)); index += 4; continue;
    }
    value += escaped;
  }
  return value;
};
const startsRegex = (tokens) => {
  const previous = tokens.at(-1)?.value;
  return previous === undefined || ['(', '[', '{', ',', ';', ':', '=', '!', '&', '|', '?', '+', '-', '*', '%', '^', '~', '<', '>'].includes(previous) || ['return', 'throw', 'case', 'delete', 'void', 'typeof', 'new', 'in', 'instanceof', 'yield', 'await'].includes(previous);
};
/* Closed JavaScript tokenization for capability policy. It retains opaque
 * string/template tokens (so computed-property escapes are visible), skips
 * comments, recursively scans template substitutions, and accepts no import
 * grammar. This is inspection only: endpoint source is never linked/evaluated. */
const codeTokens = (source, start = 0, untilTemplateClose = false, tokens = []) => {
  let index = start; let braces = 0;
  while (index < source.length) {
    const character = source[index];
    if (/\s/u.test(character)) { index += 1; continue; }
    if (character === '/' && source[index + 1] === '/') { index = source.indexOf('\n', index + 2); if (index < 0) return { tokens, index: source.length }; continue; }
    if (character === '/' && source[index + 1] === '*') { const end = source.indexOf('*/', index + 2); requireCondition(end >= 0, 'unterminated block comment'); index = end + 2; continue; }
    if (character === '\'' || character === '"') { const at = index; index = skipQuoted(source, index, character); tokens.push({ type: 'string', value: '@string', literal: decodeQuotedLiteral(source, at, index), at }); continue; }
    if (character === '\\') requireCondition(false, 'escaped identifier or host-syntax capability');
    if (character === '`') {
      const at = index; const template = { type: 'template', value: '@template', literal: '', at }; tokens.push(template);
      index += 1;
      while (index < source.length && source[index] !== '`') {
        if (source[index] === '\\') { index += 2; continue; }
        if (source[index] === '$' && source[index + 1] === '{') { const parsed = codeTokens(source, index + 2, true, tokens); index = parsed.index; continue; }
        index += 1;
      }
      requireCondition(index < source.length, 'unterminated template literal'); template.literal = source.slice(at + 1, index); index += 1; continue;
    }
    if (character === '/' && startsRegex(tokens)) {
      index += 1; let inClass = false;
      while (index < source.length) { if (source[index] === '\\') { index += 2; continue; } if (source[index] === '[') inClass = true; if (source[index] === ']') inClass = false; if (source[index] === '/' && !inClass) { index += 1; while (/[A-Za-z]/u.test(source[index] ?? '')) index += 1; break; } index += 1; }
      continue;
    }
    if (untilTemplateClose && character === '}' && braces === 0) return { tokens, index: index + 1 };
    if (isIdentStart(character)) { const at = index; index += 1; while (isIdent(source[index] ?? '')) index += 1; tokens.push({ type: 'identifier', value: source.slice(at, index), at }); continue; }
    if (/[0-9]/u.test(character)) { index += 1; while (/[A-Za-z0-9_.]/u.test(source[index] ?? '')) index += 1; tokens.push({ type: 'number', value: '#', at: index }); continue; }
    if (character === '{') braces += 1; if (character === '}') braces -= 1;
    tokens.push({ type: 'punctuation', value: character, at: index }); index += 1;
  }
  requireCondition(!untilTemplateClose, 'unterminated template substitution'); return { tokens, index };
};
const hasTokens = (tokens, sequence) => tokens.some((_, offset) => sequence.every((item, index) => tokens[offset + index]?.value === item));
const tokenValues = tokens => tokens.map(token => token.value);
const sameTokens = (tokens, sequence) => JSON.stringify(tokenValues(tokens)) === JSON.stringify(sequence);
const matchingBracket = (tokens, start, close = ']') => {
  let depth = 0;
  for (let index = start; index < tokens.length; index += 1) {
    if (tokens[index].value === '[') depth += 1;
    if (tokens[index].value === close) { depth -= 1; if (depth === 0) return index; }
  }
  throw new Error('cohort-endpoint-modules-v1: unclosed bracket expression');
};
const topLevelStatements = (body, label) => {
  requireCondition(body[0]?.value === '{' && body.at(-1)?.value === '}', `${label} body delimiters`);
  const statements = []; let current = []; let braces = 0; let parens = 0; let brackets = 0;
  for (const token of body.slice(1, -1)) {
    if (token.value === '{') braces += 1;
    if (token.value === '}') braces -= 1;
    if (token.value === '(') parens += 1;
    if (token.value === ')') parens -= 1;
    if (token.value === '[') brackets += 1;
    if (token.value === ']') brackets -= 1;
    requireCondition(braces >= 0 && parens >= 0 && brackets >= 0, `${label} unbalanced statement`);
    if (token.value === ';' && braces === 0 && parens === 0 && brackets === 0) { statements.push(current); current = []; }
    else current.push(token);
  }
  requireCondition(current.length === 0 && braces === 0 && parens === 0 && brackets === 0, `${label} unterminated statement`);
  return statements;
};
const requireStatement = (statements, sequence, label) => requireCondition(statements.some(statement => sameTokens(statement, sequence)), label);
const bindingCount = (tokens, name) => tokens.filter((token, index) => (token.value === 'function' && tokens[index + 1]?.value === name) || (token.value === name && tokens[index + 1]?.value === '=')).length;
const controllerForbidden = new Set(['expected', 'caseEntry', 'snapshotBrand', 'capability', '__proto__', 'prototype']);
const reflectionApis = new Set(['Reflect', 'Proxy', 'getOwnPropertyDescriptor', 'getOwnPropertyDescriptors', 'getOwnPropertyNames', 'getOwnPropertySymbols', 'getPrototypeOf', 'setPrototypeOf', 'defineProperty', 'defineProperties', 'isExtensible', 'preventExtensions']);
const sensitiveControllerLiteralFragments = Object.freeze(['__proto__', 'constructor', 'prototype', 'globalThis', 'process', 'require', 'eval', 'Function', 'import']);
const assertControllerAuthorityTokens = (tokens, label) => {
  for (const token of tokens) requireCondition(!controllerForbidden.has(token.value), `${label} forbidden WorkerRow authority: ${token.value}`);
};
const assertControllerLiteralAndReflectionPolicy = (tokens, label) => {
  for (const token of tokens) {
    requireCondition(!reflectionApis.has(token.value), `${label} reflection API: ${token.value}`);
    if (token.type === 'string' || token.type === 'template') {
      requireCondition(!sensitiveControllerLiteralFragments.some(fragment => token.literal.includes(fragment)), `${label} sensitive string literal`);
    }
  }
};
const assertNoComputedControllerProperty = (tokens, label, allowNativeArrayIndex = false) => {
  const declarationPredecessors = new Set(['const', 'let', 'var', 'return', 'throw', 'case', 'new', 'typeof', 'void', 'delete', 'yield', 'await', 'in', 'of', 'instanceof', 'if', 'for', 'while', 'switch', 'catch', 'function', 'class', 'export']);
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].value !== '[') continue;
    const previous = tokens[index - 1];
    if (previous === undefined || previous.type !== 'identifier' || declarationPredecessors.has(previous.value)) continue;
    const close = matchingBracket(tokens, index); const inner = tokenValues(tokens.slice(index + 1, close));
    const nativeOperand = tokenValues(tokens.slice(index - 5, index));
    const allowed = allowNativeArrayIndex && JSON.stringify(inner) === JSON.stringify(['index']) && (JSON.stringify(nativeOperand) === JSON.stringify(['row', '.', 'inputs', '.', 'operandsBottomToTop']) || JSON.stringify(nativeOperand) === JSON.stringify(['row', '.', 'byteBindings', '.', 'operandsBottomToTop']));
    requireCondition(allowed, `${label} computed or dynamic property access`);
  }
};
const bodyTokens = (tokens, name) => {
  let start = -1;
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].value === 'function' && tokens[index + 1]?.value === name) { start = index + 2; break; }
    if (tokens[index].value === name && tokens[index + 1]?.value === '=') {
      let arrow = index + 2;
      while (arrow < tokens.length && !(tokens[arrow].value === '=' && tokens[arrow + 1]?.value === '>')) arrow += 1;
      if (tokens[arrow]?.value === '=' && tokens[arrow + 1]?.value === '>') { start = arrow + 2; break; }
    }
  }
  requireCondition(start >= 0, `controller function absent: ${name}`);
  while (start < tokens.length && tokens[start].value !== '{') start += 1;
  requireCondition(start < tokens.length, `controller body absent: ${name}`);
  let depth = 0; const body = [];
  for (let index = start; index < tokens.length; index += 1) { if (tokens[index].value === '{') depth += 1; if (tokens[index].value === '}') depth -= 1; body.push(tokens[index]); if (depth === 0) return body; }
  throw new Error(`cohort-endpoint-modules-v1: unclosed controller body: ${name}`);
};
export const assertClosedEndpointSource = (source, label) => {
  const tokens = codeTokens(source).tokens;
  const forbidden = new Set(['eval', 'Function', 'process', 'globalThis', 'Worker', 'worker_threads', 'child_process', 'fs', 'net', 'http', 'https', 'dgram', 'tls', 'fetch', 'XMLHttpRequest', 'WebSocket', 'Deno', 'Bun', 'module', 'exports', 'constructor']);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]; const previous = tokens[index - 1]?.value; const next = tokens[index + 1]?.value;
    requireCondition(!reflectionApis.has(token.value), `${label} reflection API: ${token.value}`);
    if (token.value === 'import') requireCondition(false, `${label} import capability`);
    if (token.value === 'export') {
      requireCondition(next === '{' || next === 'function', `${label} export form`);
      if (next === '{') {
        let cursor = index + 1; let depth = 0;
        while (cursor < tokens.length) { if (tokens[cursor].value === '{') depth += 1; if (tokens[cursor].value === '}') { depth -= 1; if (depth === 0) break; } requireCondition(tokens[cursor].value !== '*' && tokens[cursor].value !== 'from', `${label} export-from capability`); cursor += 1; }
        requireCondition(tokens[cursor]?.value === '}' && tokens[cursor + 1]?.value !== 'from', `${label} export-from capability`);
      }
    }
    if (token.value === 'global') requireCondition(next === ':', `${label} global capability`);
    else requireCondition((token.value === 'exports' && previous === '.') || (!forbidden.has(token.value) && token.value !== 'require'), `${label} forbidden capability: ${token.value}`);
  }
  requireCondition(!tokens.some(token => token.value === 'expectedCorpusValues' || token.value === 'expectedCorpus'), `${label} expected corpus input`);
  return tokens;
};
const assertLibauthControllerPath = (suffix) => {
  const tokens = assertClosedEndpointSource(suffix, 'engine:libauth controller');
  assertControllerAuthorityTokens(tokens, 'Libauth controller'); assertControllerLiteralAndReflectionPolicy(tokens, 'Libauth controller'); assertNoComputedControllerProperty(tokens, 'Libauth controller');
  requireCondition(bindingCount(tokens, 'endpointProgramFromWorkerRow') === 1 && bindingCount(tokens, 'evaluateLibauthRow') === 1, 'Libauth controller binding cardinality');
  const evaluator = bodyTokens(tokens, 'evaluateLibauthRow'); const program = bodyTokens(tokens, 'endpointProgramFromWorkerRow');
  const evaluatorStatements = topLevelStatements(evaluator, 'Libauth evaluator'); const programStatements = topLevelStatements(program, 'Libauth program');
  const evaluatorPrefix = [
    ['const', 'program', '=', 'endpointProgramFromWorkerRow', '(', 'row', ')'],
    ['const', 'vm', '=', 'createVirtualMachineBch2026', '(', 'true', ')'],
    ['const', 'state', '=', 'vm', '.', 'evaluate', '(', 'program', ')'],
    ['const', 'success', '=', 'vm', '.', 'stateSuccess', '(', 'state', ')'],
    ['const', 'accepted', '=', 'success', '=', '=', '=', 'true'],
  ];
  const vmUses = evaluator.flatMap((token, index) => token.value === 'vm' ? [index] : []);
  for (const index of vmUses) {
    const declaration = evaluator[index - 1]?.value === 'const' && evaluator[index + 1]?.value === '=';
    const evaluate = hasTokens(evaluator.slice(index), ['vm', '.', 'evaluate', '(', 'program', ')']);
    const stateSuccess = hasTokens(evaluator.slice(index), ['vm', '.', 'stateSuccess', '(', 'state', ')']);
    requireCondition(declaration || evaluate || stateSuccess, 'controller vm escape or forbidden verify');
  }
  requireCondition(evaluatorStatements.length >= evaluatorPrefix.length + 2 && evaluatorPrefix.every((statement, index) => sameTokens(evaluatorStatements[index], statement)), 'controller unconditional decode-to-stateSuccess dataflow');
  requireCondition(vmUses.length === 3, 'controller vm escape or duplicate path');
  requireCondition(tokenValues(evaluator).filter(value => value === 'createVirtualMachineBch2026').length === 1, 'controller VM factory escape');
  const evaluatorReturn = evaluatorStatements.at(-1);
  requireCondition(evaluatorReturn?.[0]?.value === 'return' && hasTokens(evaluatorReturn, ['verdict', ':', 'accepted', '?']) && hasTokens(evaluatorReturn, ['workItemId', ':', 'row', '.', 'work', '.', 'workItemId']), 'controller return is stateSuccess-attributed');
  requireStatement(programStatements, ['const', 'transaction', '=', 'decodeTransaction', '(', 'transactionBytes', ')'], 'controller transaction decode dataflow');
  requireStatement(programStatements, ['const', 'sourceOutputs', '=', 'decodeTransactionOutputs', '(', 'sourceOutputsBytes', ')'], 'controller source-output decode dataflow');
  requireCondition(tokenValues(program).filter(value => value === 'decodeTransaction').length === 1 && tokenValues(program).filter(value => value === 'decodeTransactionOutputs').length === 1, 'controller decode escape or duplicate path');
  const programReturn = programStatements.at(-1);
  requireCondition(programReturn?.[0]?.value === 'return' && hasTokens(programReturn, ['inputIndex', ':', '#']) && hasTokens(programReturn, ['transaction']) && hasTokens(programReturn, ['sourceOutputs']), 'controller decoded-program return dataflow');
  return true;
};
export const assertLibauthControllerSuffix = suffix => assertLibauthControllerPath(suffix);
const NATIVE_CONTROLLER_MARKER = Buffer.from('\n/* WorkerRow controller boundary.', 'utf8');
const normalizeFrozenNativeKernel = (source) => {
  const markerOffset = source.indexOf(NATIVE_CONTROLLER_MARKER);
  requireCondition(markerOffset > 0, 'Native controller marker');
  const kernel = source.subarray(0, markerOffset).toString('utf8');
  const needle = 'function evaluateNativeKernelRow(';
  requireCondition(kernel.split(needle).length === 2, 'Native frozen-kernel rename cardinality');
  return {
    controllerStartOffset: markerOffset,
    frozenForm: Buffer.from(kernel.replace(needle, 'export function evaluateNativeRow('), 'utf8'),
  };
};
const assertNativeControllerPath = (suffix) => {
  const tokens = assertClosedEndpointSource(suffix, 'engine:native controller');
  assertControllerAuthorityTokens(tokens, 'Native controller'); assertControllerLiteralAndReflectionPolicy(tokens, 'Native controller'); assertNoComputedControllerProperty(tokens, 'Native controller', true);
  requireCondition(bindingCount(tokens, 'nativeWorkerProjection') === 1 && bindingCount(tokens, 'evaluateNativeRow') === 1, 'Native controller binding cardinality');
  const projection = bodyTokens(tokens, 'nativeWorkerProjection');
  const endpoint = bodyTokens(tokens, 'evaluateNativeRow');
  requireCondition(hasTokens(projection, ['nativeExactKeys', '(', 'row', ',']) && hasTokens(projection, ['row', '.', 'rowDigest']), 'Native WorkerRow projection path');
  const endpointStatements = topLevelStatements(endpoint, 'Native evaluator');
  requireCondition(endpointStatements.length === 1 && sameTokens(endpointStatements[0], ['return', 'evaluateNativeKernelRow', '(', 'nativeWorkerProjection', '(', 'row', ')', ')']), 'Native unconditional controller-to-kernel path');
  return true;
};
export const assertNativeControllerSuffix = suffix => assertNativeControllerPath(suffix);

const jsonType = value => Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
const validateSchemaValue = (schema, value, label) => {
  if (Object.hasOwn(schema, 'const')) requireCondition(JSON.stringify(value) === JSON.stringify(schema.const), `${label} schema const`);
  if (schema.enum !== undefined) requireCondition(schema.enum.some(item => JSON.stringify(item) === JSON.stringify(value)), `${label} schema enum`);
  if (schema.type !== undefined) {
    const expected = schema.type === 'integer' ? Number.isInteger(value) : jsonType(value) === schema.type;
    requireCondition(expected, `${label} schema type ${schema.type}`);
  }
  if (schema.type === 'object') {
    requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value), `${label} schema object`);
    for (const key of schema.required ?? []) requireCondition(Object.hasOwn(value, key), `${label} schema missing ${key}`);
    if (schema.additionalProperties === false) for (const key of Object.keys(value)) requireCondition(Object.hasOwn(schema.properties ?? {}, key), `${label} schema additional ${key}`);
    for (const [key, child] of Object.entries(schema.properties ?? {})) if (Object.hasOwn(value, key)) validateSchemaValue(child, value[key], `${label}.${key}`);
  }
  if (schema.type === 'array') {
    requireCondition(Array.isArray(value), `${label} schema array`);
    if (schema.minItems !== undefined) requireCondition(value.length >= schema.minItems, `${label} schema minItems`);
    if (schema.maxItems !== undefined) requireCondition(value.length <= schema.maxItems, `${label} schema maxItems`);
    if (schema.items !== undefined) for (const [index, item] of value.entries()) validateSchemaValue(schema.items, item, `${label}[${index}]`);
  }
  if (schema.minimum !== undefined) requireCondition(value >= schema.minimum, `${label} schema minimum`);
};
const loadPinnedSchemas = (root) => {
  const loaded = new Map();
  for (const binding of SCHEMA_BINDINGS) {
    const document = json(root, binding.path); const schema = document.value;
    requireCondition(document.raw.length > 0 && sha256(document.raw) === binding.rawSha256, `pinned schema raw identity ${binding.path}`);
    exact(schema, ['$id', '$schema', 'additionalProperties', 'required', 'type', 'properties'], `schema document ${binding.path}`);
    requireCondition(schema.$id === binding.id && schema.$schema === 'https://json-schema.org/draft/2020-12/schema' && schema.type === 'object' && schema.additionalProperties === false, `pinned schema domain ${binding.path}`);
    loaded.set(binding.name, schema);
  }
  return loaded;
};
const validateAgainstPinnedSchema = (schemas, name, value, label) => {
  const schema = schemas.get(name); requireCondition(schema !== undefined, `missing pinned schema ${name}`); validateSchemaValue(schema, value, label);
};

const validatePackageClosure = (root, closure) => {
  exact(closure, ['endpointBindings', 'envelopeRule', 'manifest', 'sha256sums', 'validator'], 'root package closure');
  requireCondition(closure.envelopeRule === PACKAGE_ENVELOPE_RULE, 'root package closure envelope rule');
  const manifest = json(root, 'MANIFEST.json'); const sumsRaw = readFileSync(local(root, 'SHA256SUMS')); const validatorRaw = readFileSync(local(root, VALIDATOR_FILE));
  const manifestSchema = SCHEMA_BINDINGS.find(binding => binding.name === 'manifest');
  exact(closure.manifest, ['bytes', 'contentDigest', 'path', 'rawSha256', 'rosterDigest', 'schemaRawSha256'], 'root package closure manifest');
  exact(closure.manifest.contentDigest, ['algorithm', 'domain', 'value'], 'root package closure manifest content digest');
  exact(closure.manifest.rosterDigest, ['algorithm', 'domain', 'value'], 'root package closure roster digest');
  requireCondition(closure.manifest.path === 'MANIFEST.json' && closure.manifest.bytes === manifest.raw.length && closure.manifest.rawSha256 === sha256(manifest.raw) && closure.manifest.schemaRawSha256 === manifestSchema.rawSha256 && closure.manifest.contentDigest.algorithm === 'sha256' && closure.manifest.contentDigest.domain === FILE_DOMAIN && closure.manifest.contentDigest.value === domainDigest(FILE_DOMAIN, manifest.raw) && closure.manifest.rosterDigest.algorithm === 'sha256' && closure.manifest.rosterDigest.domain === PACKAGE_ROSTER_DOMAIN && closure.manifest.rosterDigest.value === domainDigest(PACKAGE_ROSTER_DOMAIN, manifest.value.files), 'root package closure manifest binding');
  requireCondition(!manifest.value.files.some(file => [ROOT_FILE, 'MANIFEST.json', 'SHA256SUMS'].includes(file.path)), 'root package closure acyclic manifest roster');
  exact(closure.sha256sums, ['bytes', 'path', 'rawSha256'], 'root package closure checksums');
  requireCondition(closure.sha256sums.path === 'SHA256SUMS' && closure.sha256sums.bytes === sumsRaw.length && closure.sha256sums.rawSha256 === sha256(sumsRaw), 'root package closure checksums binding');
  exact(closure.validator, ['bytes', 'contentDigest', 'path', 'rawSha256'], 'root package closure validator');
  const manifestValidator = manifest.value.files.find(file => file.path === VALIDATOR_FILE);
  requireCondition(manifestValidator !== undefined && closure.validator.path === VALIDATOR_FILE && closure.validator.bytes === validatorRaw.length && closure.validator.rawSha256 === sha256(validatorRaw) && closure.validator.contentDigest === domainDigest(FILE_DOMAIN, validatorRaw) && manifestValidator.bytes === closure.validator.bytes && manifestValidator.rawSha256 === closure.validator.rawSha256 && manifestValidator.contentDigest === closure.validator.contentDigest, 'root package closure validator binding');
  const expected = [
    { endpointId: 'engine:native', descriptorPath: 'endpoints/native-endpoint.v1.json', modulePath: 'endpoints/native-endpoint.mjs' },
    { endpointId: 'engine:libauth', descriptorPath: 'endpoints/libauth-endpoint.v1.json', modulePath: 'endpoints/libauth-endpoint.mjs' },
  ];
  requireCondition(Array.isArray(closure.endpointBindings) && closure.endpointBindings.length === expected.length, 'root package closure endpoint cardinality');
  for (const [index, endpoint] of expected.entries()) {
    const binding = closure.endpointBindings[index]; const descriptor = json(root, endpoint.descriptorPath); const module = readFileSync(local(root, endpoint.modulePath));
    exact(binding, ['controller', 'descriptor', 'endpointId', 'module'], `root package closure endpoint ${index}`);
    exact(binding.descriptor, ['bytes', 'path', 'rawSha256'], `root package closure descriptor ${endpoint.endpointId}`);
    exact(binding.module, ['bytes', 'contentDigest', 'path', 'rawSha256'], `root package closure module ${endpoint.endpointId}`);
    exact(binding.controller, ['bytes', 'contentDigest', 'domain', 'rawSha256', 'startOffset'], `root package closure controller ${endpoint.endpointId}`);
    requireCondition(binding.endpointId === endpoint.endpointId && binding.descriptor.path === endpoint.descriptorPath && binding.descriptor.bytes === descriptor.raw.length && binding.descriptor.rawSha256 === sha256(descriptor.raw) && binding.module.path === endpoint.modulePath && binding.module.bytes === module.length && binding.module.rawSha256 === sha256(module) && binding.module.contentDigest === domainDigest(FILE_DOMAIN, module) && JSON.stringify(binding.controller) === JSON.stringify(descriptor.value.controller), `root package closure endpoint binding ${endpoint.endpointId}`);
  }
  return true;
};

function validateRoot(root, schemas) {
  const rootStat = lstatSync(root); requireCondition(rootStat.isDirectory() && !rootStat.isSymbolicLink() && (rootStat.mode & 0o777) === 0o555, 'package root readonly directory');
  readonlyRegular(root, ROOT_FILE, 'root'); readonlyRegular(root, 'MANIFEST.json', 'manifest'); readonlyRegular(root, 'SHA256SUMS', 'checksums');
  const { value } = json(root, ROOT_FILE);
  validateAgainstPinnedSchema(schemas, 'root', value, 'root');
  exact(value, ['artifactId', 'attempt', 'authorization', 'claim', 'contentDigest', 'cohort', 'endpointContract', 'endpoints', 'evidence', 'executionAllowed', 'metrics', 'packageClosure', 'packageId', 'ranking', 'run', 'schema', 'schemaBindings', 'selection', 'semanticExecutionPerformed', 'status', 'tests'], 'root');
  requireCondition(value.schema === 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/root' && value.artifactId === 'artifact:gate-b:cohort-endpoint-modules-v1', 'root identity');
  for (const field of ['attempt', 'authorization', 'claim', 'evidence', 'metrics', 'ranking', 'run', 'selection']) requireCondition(value[field] === null, `root ${field} must be null`);
  requireCondition(value.executionAllowed === false && value.semanticExecutionPerformed === false, 'root execution boundary');
  exact(value.contentDigest, ['algorithm', 'canonicalization', 'domain', 'frame', 'value'], 'root content digest');
  const projection = { ...value }; delete projection.contentDigest;
  requireCondition(value.contentDigest.algorithm === 'sha256' && value.contentDigest.domain === ROOT_DOMAIN && value.contentDigest.value === domainDigest(ROOT_DOMAIN, projection), 'root content digest binding');
  validatePackageClosure(root, value.packageClosure);
  exact(value.cohort, ['engineOrder', 'frozenEpochPath', 'frozenEpochRawSha256', 'readyRowsPerModuleEndpoint'], 'cohort');
  requireCondition(JSON.stringify(value.cohort.engineOrder) === JSON.stringify(['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']) && value.cohort.readyRowsPerModuleEndpoint === 4608, 'fixed four-engine cohort');
  requireCondition(value.cohort.frozenEpochRawSha256 === sha256(readFileSync(resolve(root, '../cohort-freeze-v2/execution-epoch.v2.json'))), 'frozen epoch binding');
  requireCondition(JSON.stringify(value.endpoints) === JSON.stringify(['endpoints/native-endpoint.v1.json', 'endpoints/libauth-endpoint.v1.json']), 'endpoint descriptor roster');
  requireCondition(value.schemaBindings.length === SCHEMA_BINDINGS.length, 'schema binding cardinality');
  for (const [index, binding] of SCHEMA_BINDINGS.entries()) { const item = value.schemaBindings[index]; exact(item, ['id', 'path', 'rawSha256'], `root schema binding ${index}`); requireCondition(item.id === binding.id && item.path === binding.path && item.rawSha256 === binding.rawSha256, `root schema binding ${binding.name}`); }
  return value;
}

function validateContract(root, schemas) {
  const { value } = json(root, 'endpoint-contract.v1.json');
  validateAgainstPinnedSchema(schemas, 'contract', value, 'contract');
  exact(value, ['abi', 'canonicalOutput', 'deadlineAndCap', 'executionAllowed', 'expectedCorpusValues', 'isolation', 'parser', 'rowSet', 'runtimeRef', 'schema', 'semanticExecutionPerformed', 'stderrAuthority'], 'contract');
  requireCondition(value.schema === 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/endpoint-contract' && value.executionAllowed === false && value.semanticExecutionPerformed === false, 'contract execution boundary');
  requireCondition(value.expectedCorpusValues === 'forbidden' && value.isolation === 'worker-thread' && value.runtimeRef === 'controller-node', 'contract endpoint boundary');
  exact(value.abi, ['brandTransit', 'controllerAdmission', 'forbiddenWorkerRowKeys', 'inputAuthority', 'libauthInputKeys', 'nativeInputKeys', 'workerRowKeys'], 'WorkerRow ABI');
  requireCondition(value.abi.brandTransit === 'forbidden-across-structured-clone' && value.abi.controllerAdmission === 'future-private-controller-WeakSet-AdmittedDispatch-only' && value.abi.inputAuthority === 'private-controller-admitted-row-projection', 'WorkerRow private-controller boundary');
  requireCondition(JSON.stringify(value.abi.forbiddenWorkerRowKeys) === JSON.stringify(['snapshotBrand', 'expected', 'caseEntry', 'capability']) && JSON.stringify(value.abi.workerRowKeys) === JSON.stringify(['byteBindings', 'case', 'endpoint', 'endpointOrdinal', 'fixture', 'inputs', 'plan', 'rowDigest', 'rowIndex', 'work']) && JSON.stringify(value.abi.nativeInputKeys) === JSON.stringify(['constructionId', 'operandsBottomToTop', 'relationId']) && JSON.stringify(value.abi.libauthInputKeys) === JSON.stringify(['sourceOutputs', 'transaction']), 'WorkerRow ABI vocabulary');
  exact(value.canonicalOutput, ['emptyStderr', 'exactRowKeys', 'format', 'lineTerminator', 'outputCardinality', 'rowVocabulary', 'stdout'], 'canonical output');
  requireCondition(value.canonicalOutput.outputCardinality === 4608 && value.canonicalOutput.format === 'canonical-lf-ndjson-v1' && value.canonicalOutput.lineTerminator === 'LF' && value.canonicalOutput.emptyStderr.bytes === 0 && value.canonicalOutput.emptyStderr.sha256 === EMPTY_SHA256, 'canonical NDJSON contract');
  requireCondition(JSON.stringify(value.canonicalOutput.exactRowKeys) === JSON.stringify(['workItemId', 'verdict', 'failureStage', 'metrics', 'txChecks', 'phase', 'terminalStatus']), 'canonical output keys');
  exact(value.canonicalOutput.rowVocabulary, ['failureStage', 'metrics', 'phase', 'terminalStatus', 'txChecks', 'verdict'], 'canonical output vocabulary');
  requireCondition(value.canonicalOutput.rowVocabulary.failureStage === 'null-or-nonempty-string; accept-requires-accept' && value.canonicalOutput.rowVocabulary.metrics === 'null-or-flat-object-with-finite-number-values' && value.canonicalOutput.rowVocabulary.terminalStatus === 'observed' && value.canonicalOutput.rowVocabulary.txChecks === 'unsupported' && JSON.stringify(value.canonicalOutput.rowVocabulary.verdict) === JSON.stringify(['accept', 'reject']) && JSON.stringify(value.canonicalOutput.rowVocabulary.phase) === JSON.stringify({ 'engine:libauth': 'script-engine', 'engine:native': 'semantic-reference' }), 'closed output vocabulary');
  requireCondition(value.deadlineAndCap.deadlineMilliseconds === 600000 && value.deadlineAndCap.monotonicDeadline === true && value.deadlineAndCap.combinedOutputCapBytes === 134217728 && value.deadlineAndCap.policyStatus === 'future-isolation-policy-only', 'deadline/cap contract');
  exact(value.deadlineAndCap, ['combinedOutputCapBytes', 'deadlineMilliseconds', 'monotonicDeadline', 'policyStatus'], 'deadline/cap keys');
  exact(value.rowSet, ['cardinalityPerEndpoint', 'controllerRule', 'executionContract', 'moduleBootstrap', 'orderRoots', 'repeatedCopyAndRehash', 'resultAttributionTuple', 'rowDigestDomain'], 'row-set policy');
  requireCondition(value.rowSet.cardinalityPerEndpoint === 4608 && value.rowSet.controllerRule === 'derive-exact-ready-rows-then-private-admit-before-every-copy-or-worker-dispatch' && value.rowSet.moduleBootstrap === 'recheck-module-file-raw-sha256-and-controller-suffix-before-worker-construction' && value.rowSet.repeatedCopyAndRehash === 'rehash-every-byte-field-and-rowDigest-after-construction-and-before-postMessage; reject-any-drift' && value.rowSet.rowDigestDomain === 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/worker-row', 'row-set immutable policy');
  exact(value.rowSet.executionContract, ['path', 'rawSha256'], 'row-set execution contract');
  requireCondition(value.rowSet.executionContract.path === 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v3/execution-contract.v3.json' && value.rowSet.executionContract.rawSha256 === 'd44efe80610257fc40bb82845f5cc7c2eb1e09cf7848b429d0d688be0a771ef2' && value.rowSet.executionContract.rawSha256 === sha256(readFileSync(resolve(root, '../cohort-execution-v3/execution-contract.v3.json'))), 'row-set execution contract binding');
  requireCondition(JSON.stringify(value.rowSet.resultAttributionTuple) === JSON.stringify(['runNonce', 'endpoint', 'rowIndex', 'rowDigest', 'workItemId']), 'row attribution tuple');
  requireCondition(Array.isArray(value.rowSet.orderRoots) && value.rowSet.orderRoots.length === 2, 'row-set order-root cardinality');
  const orderRoots = value.rowSet.orderRoots;
  for (const [index, item] of orderRoots.entries()) exact(item, ['endpoint', 'endpointOrdinal', 'value'], `row-set order root ${index}`);
  requireCondition(JSON.stringify(orderRoots) === JSON.stringify([{ endpoint: 'engine:native', endpointOrdinal: 0, value: '9381bacc18284f4ff0361b85a1eafcf5193f7e0049d7f059025aa62f9514f3b9' }, { endpoint: 'engine:libauth', endpointOrdinal: 1, value: 'b370800596f36923d27fb6c100afd8b46410b7175d3a9a3025dbfcb61c4a9795' }]), 'row-set order roots');
  return value;
}

function validateEndpoint(root, schemas, descriptorPath, expected) {
  const { value } = json(root, descriptorPath);
  validateAgainstPinnedSchema(schemas, 'endpoint', value, `${expected.endpointId} descriptor`);
  const allowed = expected.endpointId === 'engine:libauth'
    ? ['controller', 'dependencyClosure', 'endpointId', 'executionAllowed', 'expectedCorpusValues', 'export', 'file', 'inputAuthority', 'isolation', 'moduleMode', 'runtimeRef', 'schema', 'semanticExecutionPerformed', 'vmContract']
    : ['controller', 'dependencyClosure', 'endpointId', 'executionAllowed', 'expectedCorpusValues', 'export', 'file', 'inputAuthority', 'isolation', 'moduleMode', 'runtimeRef', 'schema', 'semanticExecutionPerformed'];
  exact(value, allowed, `${expected.endpointId} descriptor`);
  requireCondition(value.schema === 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/endpoint-module' && value.endpointId === expected.endpointId && value.export === expected.export, `${expected.endpointId} descriptor identity`);
  requireCondition(value.executionAllowed === false && value.semanticExecutionPerformed === false && value.expectedCorpusValues === 'forbidden' && value.inputAuthority === 'private-controller-admitted-row-projection' && value.isolation === 'worker-thread' && value.runtimeRef === 'controller-node', `${expected.endpointId} authority boundary`);
  exact(value.file, ['bytes', 'mode', 'nlink', 'path', 'rawSha256'], `${expected.endpointId} file descriptor`);
  requireCondition(value.file.path === expected.path && value.file.mode === 0o444 && value.file.nlink === 1, `${expected.endpointId} file projection`);
  const file = local(root, value.file.path); const stat = lstatSync(file); const raw = readFileSync(file);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o777) === 0o444, `${expected.endpointId} regular readonly single-link module`);
  /* Fixed reviewed bytes are the authority. Grammar checks below only audit the
   * already-pinned source and cannot authorize a newly resealed JS variant. */
  assertReviewedEndpointSource(expected.endpointId, raw);
  requireCondition(raw.length === value.file.bytes && sha256(raw) === value.file.rawSha256, `${expected.endpointId} raw module identity`);
  const source = raw.toString('utf8'); const tokens = assertClosedEndpointSource(source, expected.endpointId);
  requireCondition(tokens.filter((token, index) => token.value === 'function' && tokens[index + 1]?.value === expected.export).length === 1, `${expected.endpointId} endpoint export identity`);
  if (expected.endpointId === 'engine:native') {
    requireCondition(tokens.filter(token => token.value === 'export').length === 1 && hasTokens(tokens, ['export', 'function', 'evaluateNativeRow']), 'native ambiguous endpoint export');
    exact(value.dependencyClosure, ['embeddedArtifacts', 'externalDependencies', 'moduleEdges'], 'native dependency closure');
    requireCondition(value.dependencyClosure.embeddedArtifacts.length === 0 && value.dependencyClosure.externalDependencies.length === 0 && value.dependencyClosure.moduleEdges.length === 0, 'native closed dependency closure');
    exact(value.controller, ['bytes', 'contentDigest', 'domain', 'rawSha256', 'startOffset'], 'Native controller binding');
    const normalized = normalizeFrozenNativeKernel(raw); const suffix = raw.subarray(value.controller.startOffset);
    requireCondition(value.controller.startOffset === normalized.controllerStartOffset && value.controller.bytes === suffix.length && value.controller.rawSha256 === sha256(suffix) && value.controller.domain === FILE_DOMAIN && value.controller.contentDigest === domainDigest(FILE_DOMAIN, suffix), 'Native controller suffix identity');
    assertNativeControllerPath(suffix.toString('utf8'));
    requireCondition(!tokens.some(token => token.value === 'caseEntry' || token.value === 'expected'), 'native expected value authority');
  } else {
    requireCondition(tokens.filter(token => token.value === 'export').length === 2 && hasTokens(tokens, ['export', 'function', 'evaluateLibauthRow']), 'libauth ambiguous endpoint export');
    exact(value.dependencyClosure, ['embeddedArtifacts', 'externalDependencies', 'moduleEdges'], 'libauth dependency closure');
    requireCondition(value.dependencyClosure.externalDependencies.length === 0 && value.dependencyClosure.moduleEdges.length === 0 && value.dependencyClosure.embeddedArtifacts.length === 1, 'libauth closed dependency closure');
    const embedded = value.dependencyClosure.embeddedArtifacts[0];
    exact(embedded, ['bytes', 'prefixBytes', 'rawSha256', 'source'], 'libauth embedded bundle binding');
    requireCondition(embedded.bytes === BUNDLE_BYTES && embedded.prefixBytes === BUNDLE_BYTES && embedded.rawSha256 === BUNDLE_SHA256 && raw.subarray(0, BUNDLE_BYTES).length === BUNDLE_BYTES && sha256(raw.subarray(0, BUNDLE_BYTES)) === BUNDLE_SHA256, 'exact materialized Libauth prefix');
    exact(value.controller, ['bytes', 'contentDigest', 'domain', 'rawSha256', 'startOffset'], 'Libauth controller binding');
    const suffix = raw.subarray(value.controller.startOffset);
    requireCondition(value.controller.startOffset === BUNDLE_BYTES && value.controller.bytes === suffix.length && value.controller.rawSha256 === sha256(suffix) && value.controller.domain === FILE_DOMAIN && value.controller.contentDigest === domainDigest(FILE_DOMAIN, suffix), 'Libauth controller suffix identity');
    assertLibauthControllerPath(suffix.toString('utf8'));
    exact(value.vmContract, ['factory', 'stateSuccessRequired', 'standard', 'verifyCall', 'vmEvaluateRequired'], 'Libauth VM contract');
    requireCondition(value.vmContract.factory === 'createVirtualMachineBch2026(true)' && value.vmContract.standard === true && value.vmContract.verifyCall === false && value.vmContract.vmEvaluateRequired === true && value.vmContract.stateSuccessRequired === true, 'Libauth VM descriptor');
    requireCondition(!tokens.some(token => token.value === 'snapshotBrand' || token.value === 'expected' || token.value === 'caseEntry'), 'Libauth WorkerRow/no expected authority');
  }
  return { endpointId: expected.endpointId, bytes: raw.length, sha256: sha256(raw) };
}

function validateMaterialization(root, schemas) {
  const { value } = json(root, 'materialization.v1.json');
  validateAgainstPinnedSchema(schemas, 'materialization', value, 'materialization');
  exact(value, ['bundle', 'executionAllowed', 'materialization', 'nativeController', 'nativeSource', 'semanticExecutionPerformed', 'status', 'targetModules'], 'materialization');
  requireCondition(value.executionAllowed === false && value.semanticExecutionPerformed === false && value.status === 'materialized-static-only', 'materialization execution boundary');
  requireCondition(value.bundle.bytes === BUNDLE_BYTES && value.bundle.rawSha256 === BUNDLE_SHA256 && value.bundle.sourcePath === 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-engine-runtime-materialized-v1/bundle/libauth-bundle.mjs', 'materialized bundle receipt');
  requireCondition(value.nativeSource.bytes === REVIEWED_ENDPOINT_SOURCES.native.frozenSource.bytes && value.nativeSource.rawSha256 === REVIEWED_ENDPOINT_SOURCES.native.frozenSource.rawSha256 && value.nativeSource.sourcePath === 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-engine-runtime-v1/native-evaluator.mjs', 'materialized native receipt');
  exact(value.nativeController, ['marker', 'normalization'], 'native controller materialization');
  requireCondition(value.nativeController.marker === '\\n/* WorkerRow controller boundary.' && value.nativeController.normalization === 'replace-single-function-evaluateNativeKernelRow-with-export-function-evaluateNativeRow-before-byte-provenance-compare-v1', 'native controller materialization policy');
  const frozenNative = readFileSync(resolve(root, '../cohort-engine-runtime-v1/native-evaluator.mjs'));
  const frozenBundle = readFileSync(resolve(root, '../cohort-engine-runtime-materialized-v1/bundle/libauth-bundle.mjs'));
  const localNative = readFileSync(local(root, 'endpoints/native-endpoint.mjs'));
  const localLibauth = readFileSync(local(root, 'endpoints/libauth-endpoint.mjs'));
  assertReviewedEndpointSource('engine:native', localNative);
  assertReviewedEndpointSource('engine:libauth', localLibauth);
  const nativeKernel = normalizeFrozenNativeKernel(localNative);
  assertReviewedBytes(frozenNative, REVIEWED_ENDPOINT_SOURCES.native.frozenSource, 'frozen Native source');
  assertReviewedBytes(frozenBundle, REVIEWED_ENDPOINT_SOURCES.libauth.bundle, 'frozen Libauth bundle');
  requireCondition(frozenNative.length === value.nativeSource.bytes && sha256(frozenNative) === value.nativeSource.rawSha256 && frozenNative.equals(nativeKernel.frozenForm), 'exact frozen Native byte provenance');
  requireCondition(frozenBundle.length === value.bundle.bytes && sha256(frozenBundle) === value.bundle.rawSha256 && frozenBundle.equals(localLibauth.subarray(0, BUNDLE_BYTES)), 'exact frozen Libauth bundle provenance');
  requireCondition(JSON.stringify(value.targetModules) === JSON.stringify(['endpoints/native-endpoint.mjs', 'endpoints/libauth-endpoint.mjs']), 'materialization target roster');
  return value;
}

function validateManifest(root, schemas) {
  const { value } = json(root, 'MANIFEST.json');
  validateAgainstPinnedSchema(schemas, 'manifest', value, 'manifest');
  exact(value, ['directoryCount', 'directoryMode', 'domainSeparator', 'fileCount', 'fileMode', 'files', 'packageRoot', 'schema', 'status'], 'manifest');
  requireCondition(value.schema === 'shieldkit-labs/p2/gate-b/cohort-endpoint-modules/v1/manifest' && value.status === 'static-content-addressed', 'manifest identity');
  const walked = walk(root); const files = walked.files.filter(file => ![ROOT_FILE, 'MANIFEST.json', 'SHA256SUMS'].includes(file.path));
  requireCondition(value.fileCount === files.length && value.directoryCount === walked.directories.length && value.fileMode === 0o444 && value.directoryMode === 0o555, 'manifest counts/modes');
  requireCondition(JSON.stringify(value.files.map(file => file.path)) === JSON.stringify(files.map(file => file.path)), 'manifest roster');
  for (const file of walked.files) requireCondition(file.mode === 0o444 && file.nlink === 1, `writable or linked package file: ${file.path}`);
  for (const item of value.files) {
    exact(item, ['bytes', 'contentDigest', 'mode', 'nlink', 'path', 'rawSha256'], `manifest file ${item.path}`);
    const raw = readFileSync(local(root, item.path)); const stat = statSync(local(root, item.path));
    requireCondition(item.bytes === raw.length && item.rawSha256 === sha256(raw) && item.contentDigest === domainDigest(value.domainSeparator, raw) && item.mode === 0o444 && item.nlink === 1 && (stat.mode & 0o777) === 0o444 && stat.nlink === 1, `manifest identity ${item.path}`);
  }
  for (const directory of walked.directories) requireCondition(directory.mode === 0o555, `writable package directory: ${directory.path}`);
  const lines = readFileSync(local(root, 'SHA256SUMS'), 'utf8').trimEnd().split('\n');
  const names = ['MANIFEST.json', ...value.files.map(file => file.path)];
  requireCondition(lines.length === names.length, 'checksum coverage');
  for (let index = 0; index < names.length; index += 1) {
    const [digest, printed] = lines[index].split('  ');
    requireCondition(digest === sha256(readFileSync(local(root, names[index]))) && printed === `${packagePrefix}${names[index]}`, `checksum drift ${names[index]}`);
  }
  return { files: files.length, directories: walked.directories.length };
}

export function parseCanonicalEndpointNdjson(bytes, { engineId, workItemIds } = {}) {
  requireCondition(engineId === 'engine:native' || engineId === 'engine:libauth', 'NDJSON engine identity');
  requireCondition(Array.isArray(workItemIds) && workItemIds.length === 4608 && new Set(workItemIds).size === 4608 && workItemIds.every(value => typeof value === 'string' && value.length > 0), 'NDJSON work-item authority');
  let text; try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (error) { throw new Error(`cohort-endpoint-modules-v1: NDJSON UTF-8: ${error.message}`); }
  requireCondition(text.endsWith('\n') && !text.includes('\r'), 'NDJSON canonical LF');
  const lines = text.slice(0, -1).split('\n'); requireCondition(lines.length === 4608 && lines.every(line => line.length > 0), 'NDJSON output cardinality');
  const expectedIds = new Set(workItemIds); const seen = new Set(); const rows = [];
  for (const [index, line] of lines.entries()) {
    let row; try { row = JSON.parse(line); } catch (error) { throw new Error(`cohort-endpoint-modules-v1: NDJSON JSON ${index}: ${error.message}`); }
    requireCondition(JSON.stringify(Object.keys(row)) === JSON.stringify(['workItemId', 'verdict', 'failureStage', 'metrics', 'txChecks', 'phase', 'terminalStatus']), `NDJSON row keys ${index}`);
    requireCondition(typeof row.workItemId === 'string' && expectedIds.has(row.workItemId) && !seen.has(row.workItemId), `NDJSON row identity ${index}`); seen.add(row.workItemId);
    requireCondition(row.verdict === 'accept' || row.verdict === 'reject', `NDJSON verdict ${index}`);
    requireCondition(row.failureStage === null || (typeof row.failureStage === 'string' && row.failureStage.length > 0), `NDJSON failure stage ${index}`);
    requireCondition(row.verdict !== 'accept' || row.failureStage === 'accept', `NDJSON accept stage ${index}`);
    requireCondition(row.metrics === null || (row.metrics !== null && typeof row.metrics === 'object' && !Array.isArray(row.metrics) && Object.values(row.metrics).every(value => typeof value === 'number' && Number.isFinite(value))), `NDJSON finite metrics ${index}`);
    requireCondition(row.txChecks === 'unsupported' && row.phase === (engineId === 'engine:native' ? 'semantic-reference' : 'script-engine') && row.terminalStatus === 'observed', `NDJSON endpoint vocabulary ${index}`);
    requireCondition(JSON.stringify(row) === line, `NDJSON canonical JSON ${index}`);
    rows.push(Object.freeze(row));
  }
  return Object.freeze(rows);
}

export function validatePackage(root = PACKAGE_ROOT) {
  const schemas = loadPinnedSchemas(root); const rootData = validateRoot(root, schemas); const contract = validateContract(root, schemas); const materialization = validateMaterialization(root, schemas);
  const native = validateEndpoint(root, schemas, 'endpoints/native-endpoint.v1.json', { endpointId: 'engine:native', export: 'evaluateNativeRow', path: 'endpoints/native-endpoint.mjs' });
  const libauth = validateEndpoint(root, schemas, 'endpoints/libauth-endpoint.v1.json', { endpointId: 'engine:libauth', export: 'evaluateLibauthRow', path: 'endpoints/libauth-endpoint.mjs' });
  requireCondition(new Set([native.endpointId, libauth.endpointId]).size === endpointNames.length, 'ambiguous or duplicate endpoints');
  const manifest = validateManifest(root, schemas);
  return Object.freeze({ status: 'PASS', rootContentSha256: rootData.contentDigest.value, outputCardinality: contract.canonicalOutput.outputCardinality, native, libauth, materialization: materialization.status, manifest });
}

export function verifyMaterializationOnly(root = PACKAGE_ROOT) { const schemas = loadPinnedSchemas(root); validateRoot(root, schemas); return validateMaterialization(root, schemas); }
