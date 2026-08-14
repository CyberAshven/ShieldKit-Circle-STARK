import Ajv2020 from "ajv/dist/2020.js";
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const PREFIX =
  "shieldkit-labs/p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge/v1";
const AUTHORED_FILES = Object.freeze([
  "COMMAND.txt",
  "README.md",
  "external-authority-control-plane-schema-bridge-root.v1.json",
  "schemas/artifact-dependency-dag.v1.schema.json",
  "schemas/b0-execution-authorization.v1.schema.json",
  "schemas/binding-creation-authorization-g0.v1.schema.json",
  "schemas/control-plane-transition.v2.schema.json",
  "schemas/dependency-binding.v1.schema.json",
  "schemas/digest.v1.schema.json",
  "schemas/external-authority-contract.v2.schema.json",
  "schemas/governance-authorization-g1.v1.schema.json",
  "schemas/instance-creation-event.v1.schema.json",
  "schemas/issuer-decision.v1.schema.json",
  "schemas/manifest.v1.schema.json",
  "schemas/non-authority-boundary.v1.schema.json",
  "schemas/principal-identity-ref.v1.schema.json",
  "schemas/provider-binding-catalog.v1.schema.json",
  "schemas/provider-binding.v2.schema.json",
  "schemas/provider-contract.v1.schema.json",
  "schemas/root.v1.schema.json",
  "schemas/source-collision-decision.v2.schema.json",
  "test/digest.kat.json",
  "test/future-schema.test.mjs",
  "test/mutation.test.mjs",
  "test/package-boundary.test.mjs",
  "test/static.test.mjs",
  "validate-static.mjs",
]);
const PACKAGE_ID = "gate-b0-external-authority-control-plane-schema-bridge-v1";
const ROOT_FILE = "external-authority-control-plane-schema-bridge-root.v1.json";
const SCHEMA_PREFIX =
  "https://shieldkit-labs.local/p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge/v1/";
const SCHEMAS = Object.freeze(
  AUTHORED_FILES.filter((locator) => locator.startsWith("schemas/")),
);
const SCHEMA_SEMANTIC_FINGERPRINTS = Object.freeze([
  ["schemas/artifact-dependency-dag.v1.schema.json", "92aa271a18deae92e1170716bd70416d50675a934d9b80bca09d382a63eac41f"],
  ["schemas/b0-execution-authorization.v1.schema.json", "f4799a10c5e3501ef1891cd971028b82c955d588079be76a40ff26f6c31e40c6"],
  ["schemas/binding-creation-authorization-g0.v1.schema.json", "57193e970c2efd749fe80b80396d2a3ed160daa7317d3ac8ef42d88ff85fdad9"],
  ["schemas/control-plane-transition.v2.schema.json", "644ef8d80c30dbb81b5d1454345aca0a2bd7ba68659b6201cd19f0d81ea82662"],
  ["schemas/dependency-binding.v1.schema.json", "717ec19843137cc9479c4afacb99374b7a1137594151de5f65a8cb0751a4b3ef"],
  ["schemas/digest.v1.schema.json", "f390bdf943fca1373480de4e5c99c4feab22ffa6444999a3a90e66cc5a4c93de"],
  ["schemas/external-authority-contract.v2.schema.json", "259c8199f11c9da9e14877fa2a020966595d865190fbad4fddc47eb3036b3122"],
  ["schemas/governance-authorization-g1.v1.schema.json", "da0c72980f533e22806de4cf6f93eba035a892bda54025214b0b03da57458a2b"],
  ["schemas/instance-creation-event.v1.schema.json", "10319765e00533172d7bd0fa7ec9fa3ba08aa35c69072ab86c89c0ced53dd8f5"],
  ["schemas/issuer-decision.v1.schema.json", "3c7ee14baeb564fe5b8aaf05135b946d3c9092d0fdaebfca32ba1cde5f23184f"],
  ["schemas/manifest.v1.schema.json", "ce27c7af74af09e17b9b4e4ad3f57b81a856ca513d856d04b6230ce1250f4341"],
  ["schemas/non-authority-boundary.v1.schema.json", "c23def02588e8e0730782c847adb0b7e1c2bb5e96325983902b0e1e73c7740a9"],
  ["schemas/principal-identity-ref.v1.schema.json", "0d407c4a4e141bd9b1cbb4a21bd6afe58f6d0a9750bd9fed37cf27b2ae9a8a05"],
  ["schemas/provider-binding-catalog.v1.schema.json", "96123e6b2bc237a29f5b16346dabbcf774b2ef7d8350efabb5fa78d46485ac2c"],
  ["schemas/provider-binding.v2.schema.json", "f93755c655792186d647970e7305a30ebf6c49cef999b6cf05b74c5a52b0889a"],
  ["schemas/provider-contract.v1.schema.json", "9ece1a23807d3398c2ff53949b9d3d886c460f375409c8532a0bfcc5bc164838"],
  ["schemas/root.v1.schema.json", "a4b2ac7819a2361da0d556e7dbdfe42edc3b00f1791dcf5fcae16b5c384333c3"],
  ["schemas/source-collision-decision.v2.schema.json", "06d958ee3833dd986e6a5130f854beff689d8af6bc2ee17e143ef22e29ca1153"],
]);
const ROOT_KEYS = Object.freeze([
  "schema",
  "artifactId",
  "packageId",
  "status",
  "purpose",
  "executionAllowed",
  "measurementAdmissionAllowed",
  "dependencyBinding",
  "eappV1Disposition",
  "futureRecordContracts",
  "controlPlaneTransition",
  "artifactDependencyDag",
  "nonAuthorityBoundary",
  "runtimeBoundary",
  "schemaBindings",
  "componentDigests",
  "contentDigest",
]);
const COMPONENTS = Object.freeze([
  ["dependencyBinding", "dependency-binding"],
  ["eappV1Disposition", "eapp-v1-disposition"],
  ["futureRecordContracts", "future-record-contracts"],
  ["controlPlaneTransition", "control-plane-transition"],
  ["artifactDependencyDag", "artifact-dependency-dag"],
  ["nonAuthorityBoundary", "nonauthority-boundary"],
  ["runtimeBoundary", "runtime-boundary"],
  ["schemaBindings", "schema-bindings"],
]);
const COMPONENT_VALUE = (value) => {
  if (Array.isArray(value)) return value;
  const copy = { ...value };
  delete copy.contentDigest;
  return copy;
};
const pointerValue = (value, pointer) => {
  if (pointer === "") return value;
  check(pointer.startsWith("/"), "SCHEMA_REF", pointer);
  let cursor = value;
  for (const encoded of pointer.slice(1).split("/")) {
    const key = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    check(
      cursor !== null && cursor !== undefined && Object.hasOwn(cursor, key),
      "SCHEMA_REF",
      pointer,
    );
    cursor = cursor[key];
  }
  return cursor;
};
const SCHEMA_BINDING_POINTERS = Object.freeze([
  ["/artifactDependencyDag"],
  ["/futureRecordContracts/entries/9"],
  ["/futureRecordContracts/entries/5"],
  ["/controlPlaneTransition"],
  ["/dependencyBinding"],
  ["/componentDigests", "/contentDigest"],
  ["/futureRecordContracts/entries/2"],
  ["/futureRecordContracts/entries/8"],
  ["/futureRecordContracts/entries/10"],
  ["/futureRecordContracts/entries/1"],
  [],
  ["/nonAuthorityBoundary", "/runtimeBoundary"],
  ["/futureRecordContracts/entries/0"],
  ["/futureRecordContracts/entries/7"],
  ["/futureRecordContracts/entries/6"],
  ["/futureRecordContracts/entries/3"],
  [""],
  ["/futureRecordContracts/entries/4"],
]);
const SEMANTIC_FINGERPRINTS = Object.freeze({
  identity: "3e7d6c8d9cd78a59da700dbae8ba76c298ead52b8fc19b2e96c4274e941447b6",
  dependencyBinding:
    "f78ab680bcb83749b00b107b6e42e739abfe671d691cd2f984c913a5eedfc9dc",
  eappV1Disposition:
    "84f8ea629f18fd325ba7f51d67df7ae7e766e798860dc643bc670f813e8660f3",
  futureRecordContracts:
    "f188b6c0c05432446eeb36141fe92b92d0b6557af17cb1ce1723f0f744025f8c",
  controlPlaneTransition:
    "20345c57dc1b43e2c52deba813a0d3840500ccaea27a66bc734a04a880957393",
  artifactDependencyDag:
    "722370a96ca987a57269d0cb60731767a9ba22cab217792a524694d46379babf",
  nonAuthorityBoundary:
    "c94885c19404285215d4395b05a61bafc17e828f18c55a4c667ea1de659d20bd",
  runtimeBoundary:
    "eccf428aedbc363d2de4f7f4a7ffc7f14cd33a48c75c258e998e430ae45b1b72",
  schemaBindings:
    "90f405a32207293ef3191fc691a200ec5b96495a8261e7c879360c8c07d9d267",
});
const semanticFingerprint = (value) =>
  sha256(Buffer.from(canonicalJson(value)));
const TOKENS = new Set([
  "CLI_ARGS",
  "PACKAGE_MODE",
  "PACKAGE_CLOSURE",
  "FILE_MODE",
  "DIR_MODE",
  "LINK",
  "SPECIAL_FILE",
  "PATH",
  "UTF8",
  "NON_NFC",
  "DUPLICATE_KEY",
  "ANCHOR_REQUIRED",
  "ANCHOR_LOCATION",
  "ANCHOR_PIN",
  "ANCHOR_RAW",
  "ANCHOR_SCHEMA",
  "ANCHOR_CLOSURE",
  "MANIFEST",
  "SUMS",
  "IMPORT_BOUNDARY",
  "EXPORT_BOUNDARY",
  "ACTIVATION_BOUNDARY",
  "DEPENDENCY_RAW",
  "DEPENDENCY_SEMANTIC",
  "EAPP_CLOSURE",
  "EAPP_COMPONENT",
  "SSA_CLOSURE",
  "SSA_SOURCE_RAW",
  "SSA_SOURCE_SEMANTIC",
  "DIRECT_SOURCE_RAW",
  "DIRECT_SOURCE_SEMANTIC",
  "SCHEMA_RAW",
  "SCHEMA_ID",
  "SCHEMA_REF",
  "SCHEMA_REACHABILITY",
  "SCHEMA_COMPILE",
  "ROOT_SCHEMA",
  "ROOT_KEYS",
  "ROOT_ID",
  "STATUS",
  "NONAUTHORITY",
  "EAPP_V1_DISPOSITION",
  "FUTURE_RECORD_ROSTER",
  "FUTURE_RECORD_SCHEMA",
  "IDENTITY_SCHEMA",
  "ISSUER_DECISION_SCHEMA",
  "AUTHORITY_CONTRACT_SCHEMA",
  "PROVIDER_CONTRACT_SCHEMA",
  "COLLISION_DECISION_SCHEMA",
  "G0_SCHEMA",
  "PROVIDER_BINDING_SCHEMA",
  "CATALOG_SCHEMA",
  "G1_SCHEMA",
  "B0_AUTH_SCHEMA",
  "INSTANCE_EVENT_SCHEMA",
  "TRANSITION",
  "DAG",
  "DIGEST",
  "CONTENT_DIGEST",
  "RUNTIME_BOUNDARY",
  "DOCUMENTATION",
]);
const here = dirname(fileURLToPath(import.meta.url));
const fail = (token, detail) => {
  if (!TOKENS.has(token)) throw new Error("CPSB_INTERNAL");
  throw new Error(`CPSB_${token}${detail === undefined ? "" : `:${detail}`}`);
};
const check = (condition, token, detail) => {
  if (!condition) fail(token, detail);
};
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const ACORN_REGION_BEGIN =
  ["// BEGIN VENDORED_ACORN_DIST_ACORN_MJS_", "8_18_0"].join("");
const ACORN_REGION_END =
  ["// END VENDORED_ACORN_DIST_ACORN_MJS_", "8_18_0"].join("");
const ACORN_REGION_BYTES = 233033;
const ACORN_REGION_SHA256 =
  "911d0d07a4c669f2ed2a30d63ed839dee63b13bd176e611e13848878036cb2dc";

/*
Vendored parser provenance: acorn@8.18.0 dist/acorn.mjs, 233301 bytes,
SHA-256 953573b8fdab71599749ea5f2b33d3e760c2116178f9423ee7458dbe39d59453.
The exact terminal 316-byte ESM export declaration is removed, then the
remaining bytes are wrapped as the acornParse initializer pinned above.

MIT License

Copyright (C) 2012-2022 by various contributors (see AUTHORS)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
// BEGIN VENDORED_ACORN_DIST_ACORN_MJS_8_18_0
const acornParse = (() => {
// This file was generated. Do not modify manually!
var astralIdentifierCodes = [509, 0, 227, 0, 150, 4, 294, 9, 1368, 2, 2, 1, 6, 3, 41, 2, 5, 0, 166, 1, 574, 3, 9, 9, 7, 9, 32, 4, 318, 1, 78, 5, 71, 10, 50, 3, 123, 2, 54, 14, 32, 10, 3, 1, 11, 3, 46, 10, 8, 0, 46, 9, 7, 2, 37, 13, 2, 9, 6, 1, 45, 0, 13, 2, 49, 13, 9, 3, 2, 11, 83, 11, 7, 0, 3, 0, 158, 11, 6, 9, 7, 3, 56, 1, 2, 6, 3, 1, 3, 2, 10, 0, 11, 1, 3, 6, 4, 4, 68, 8, 2, 0, 3, 0, 2, 3, 2, 4, 2, 0, 15, 1, 83, 17, 10, 9, 5, 0, 82, 19, 13, 9, 214, 6, 3, 8, 28, 1, 83, 16, 16, 9, 82, 12, 9, 9, 7, 19, 58, 14, 5, 9, 243, 14, 166, 9, 71, 5, 2, 1, 3, 3, 2, 0, 2, 1, 13, 9, 120, 6, 3, 6, 4, 0, 29, 9, 41, 6, 2, 3, 9, 0, 10, 10, 47, 15, 199, 7, 137, 9, 54, 7, 2, 7, 17, 9, 57, 21, 2, 13, 123, 5, 4, 0, 2, 1, 2, 6, 2, 0, 9, 9, 49, 4, 2, 1, 2, 4, 9, 9, 55, 9, 266, 3, 10, 1, 2, 0, 49, 6, 4, 4, 14, 10, 5350, 0, 7, 14, 11465, 27, 2343, 9, 87, 9, 39, 4, 60, 6, 26, 9, 535, 9, 470, 0, 2, 54, 8, 3, 82, 0, 12, 1, 19628, 1, 4178, 9, 519, 45, 3, 22, 543, 4, 4, 5, 9, 7, 3, 6, 31, 3, 149, 2, 1418, 49, 513, 54, 5, 49, 9, 0, 15, 0, 23, 4, 2, 14, 1361, 6, 2, 16, 3, 6, 2, 1, 2, 4, 101, 0, 161, 6, 10, 9, 357, 0, 62, 13, 499, 13, 245, 1, 2, 9, 233, 0, 3, 0, 8, 1, 6, 0, 475, 6, 110, 6, 6, 9, 4759, 9, 787719, 239];

// This file was generated. Do not modify manually!
var astralIdentifierStartCodes = [0, 11, 2, 25, 2, 18, 2, 1, 2, 14, 3, 13, 35, 122, 70, 52, 268, 28, 4, 48, 48, 31, 14, 29, 6, 37, 11, 29, 3, 35, 5, 7, 2, 4, 43, 157, 19, 35, 5, 35, 5, 39, 9, 51, 13, 10, 2, 14, 2, 6, 2, 1, 2, 10, 2, 14, 2, 6, 2, 1, 4, 51, 13, 310, 10, 21, 11, 7, 25, 5, 2, 41, 2, 8, 70, 5, 3, 0, 2, 43, 2, 1, 4, 0, 3, 22, 11, 22, 10, 30, 66, 18, 2, 1, 11, 21, 11, 25, 7, 25, 39, 55, 7, 1, 65, 0, 16, 3, 2, 2, 2, 28, 43, 28, 4, 28, 36, 7, 2, 27, 28, 53, 11, 21, 11, 18, 14, 17, 111, 72, 56, 50, 14, 50, 14, 35, 39, 27, 10, 22, 251, 41, 7, 1, 17, 5, 57, 28, 11, 0, 9, 21, 43, 17, 47, 20, 28, 22, 13, 52, 58, 1, 3, 0, 14, 44, 33, 24, 27, 35, 30, 0, 3, 0, 9, 34, 4, 0, 13, 47, 15, 3, 22, 0, 2, 0, 36, 17, 2, 24, 20, 1, 64, 6, 2, 0, 2, 3, 2, 14, 2, 9, 8, 46, 39, 7, 3, 1, 3, 21, 2, 6, 2, 1, 2, 4, 4, 0, 19, 0, 13, 4, 31, 9, 2, 0, 3, 0, 2, 37, 2, 0, 26, 0, 2, 0, 45, 52, 19, 3, 21, 2, 31, 47, 21, 1, 2, 0, 185, 46, 42, 3, 37, 47, 21, 0, 60, 42, 14, 0, 72, 26, 38, 6, 186, 43, 117, 63, 32, 7, 3, 0, 3, 7, 2, 1, 2, 23, 16, 0, 2, 0, 95, 7, 3, 38, 17, 0, 2, 0, 29, 0, 11, 39, 8, 0, 22, 0, 12, 45, 20, 0, 19, 72, 200, 32, 32, 8, 2, 36, 18, 0, 50, 29, 113, 6, 2, 1, 2, 37, 22, 0, 26, 5, 2, 1, 2, 31, 15, 0, 24, 43, 261, 18, 16, 0, 2, 12, 2, 33, 125, 0, 80, 921, 103, 110, 18, 195, 2637, 96, 16, 1071, 18, 5, 26, 3994, 6, 582, 6842, 29, 1763, 568, 8, 30, 18, 78, 18, 29, 19, 47, 17, 3, 32, 20, 6, 18, 433, 44, 212, 63, 33, 24, 3, 24, 45, 74, 6, 0, 67, 12, 65, 1, 2, 0, 15, 4, 10, 7381, 42, 31, 98, 114, 8702, 3, 2, 6, 2, 1, 2, 290, 16, 0, 30, 2, 3, 0, 15, 3, 9, 395, 2309, 106, 6, 12, 4, 8, 8, 9, 5991, 84, 2, 70, 2, 1, 3, 0, 3, 1, 3, 3, 2, 11, 2, 0, 2, 6, 2, 64, 2, 3, 3, 7, 2, 6, 2, 27, 2, 3, 2, 4, 2, 0, 4, 6, 2, 339, 3, 24, 2, 24, 2, 30, 2, 24, 2, 30, 2, 24, 2, 30, 2, 24, 2, 30, 2, 24, 2, 7, 1845, 30, 7, 5, 262, 61, 147, 44, 11, 6, 17, 0, 322, 29, 19, 43, 485, 27, 229, 29, 3, 0, 208, 30, 2, 2, 2, 1, 2, 6, 3, 4, 10, 1, 225, 6, 2, 3, 2, 1, 2, 14, 2, 196, 60, 67, 8, 0, 1205, 3, 2, 26, 2, 1, 2, 0, 3, 0, 2, 9, 2, 3, 2, 0, 2, 0, 7, 0, 5, 0, 2, 0, 2, 0, 2, 2, 2, 1, 2, 0, 3, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 1, 2, 0, 3, 3, 2, 6, 2, 3, 2, 3, 2, 0, 2, 9, 2, 16, 6, 2, 2, 4, 2, 16, 4421, 42719, 33, 4381, 3, 5773, 3, 7472, 16, 621, 2467, 541, 1507, 4938, 6, 8489];

// This file was generated. Do not modify manually!
var nonASCIIidentifierChars = "\u200c\u200d\xb7\u0300-\u036f\u0387\u0483-\u0487\u0591-\u05bd\u05bf\u05c1\u05c2\u05c4\u05c5\u05c7\u0610-\u061a\u064b-\u0669\u0670\u06d6-\u06dc\u06df-\u06e4\u06e7\u06e8\u06ea-\u06ed\u06f0-\u06f9\u0711\u0730-\u074a\u07a6-\u07b0\u07c0-\u07c9\u07eb-\u07f3\u07fd\u0816-\u0819\u081b-\u0823\u0825-\u0827\u0829-\u082d\u0859-\u085b\u0897-\u089f\u08ca-\u08e1\u08e3-\u0903\u093a-\u093c\u093e-\u094f\u0951-\u0957\u0962\u0963\u0966-\u096f\u0981-\u0983\u09bc\u09be-\u09c4\u09c7\u09c8\u09cb-\u09cd\u09d7\u09e2\u09e3\u09e6-\u09ef\u09fe\u0a01-\u0a03\u0a3c\u0a3e-\u0a42\u0a47\u0a48\u0a4b-\u0a4d\u0a51\u0a66-\u0a71\u0a75\u0a81-\u0a83\u0abc\u0abe-\u0ac5\u0ac7-\u0ac9\u0acb-\u0acd\u0ae2\u0ae3\u0ae6-\u0aef\u0afa-\u0aff\u0b01-\u0b03\u0b3c\u0b3e-\u0b44\u0b47\u0b48\u0b4b-\u0b4d\u0b55-\u0b57\u0b62\u0b63\u0b66-\u0b6f\u0b82\u0bbe-\u0bc2\u0bc6-\u0bc8\u0bca-\u0bcd\u0bd7\u0be6-\u0bef\u0c00-\u0c04\u0c3c\u0c3e-\u0c44\u0c46-\u0c48\u0c4a-\u0c4d\u0c55\u0c56\u0c62\u0c63\u0c66-\u0c6f\u0c81-\u0c83\u0cbc\u0cbe-\u0cc4\u0cc6-\u0cc8\u0cca-\u0ccd\u0cd5\u0cd6\u0ce2\u0ce3\u0ce6-\u0cef\u0cf3\u0d00-\u0d03\u0d3b\u0d3c\u0d3e-\u0d44\u0d46-\u0d48\u0d4a-\u0d4d\u0d57\u0d62\u0d63\u0d66-\u0d6f\u0d81-\u0d83\u0dca\u0dcf-\u0dd4\u0dd6\u0dd8-\u0ddf\u0de6-\u0def\u0df2\u0df3\u0e31\u0e34-\u0e3a\u0e47-\u0e4e\u0e50-\u0e59\u0eb1\u0eb4-\u0ebc\u0ec8-\u0ece\u0ed0-\u0ed9\u0f18\u0f19\u0f20-\u0f29\u0f35\u0f37\u0f39\u0f3e\u0f3f\u0f71-\u0f84\u0f86\u0f87\u0f8d-\u0f97\u0f99-\u0fbc\u0fc6\u102b-\u103e\u1040-\u1049\u1056-\u1059\u105e-\u1060\u1062-\u1064\u1067-\u106d\u1071-\u1074\u1082-\u108d\u108f-\u109d\u135d-\u135f\u1369-\u1371\u1712-\u1715\u1732-\u1734\u1752\u1753\u1772\u1773\u17b4-\u17d3\u17dd\u17e0-\u17e9\u180b-\u180d\u180f-\u1819\u18a9\u1920-\u192b\u1930-\u193b\u1946-\u194f\u19d0-\u19da\u1a17-\u1a1b\u1a55-\u1a5e\u1a60-\u1a7c\u1a7f-\u1a89\u1a90-\u1a99\u1ab0-\u1abd\u1abf-\u1add\u1ae0-\u1aeb\u1b00-\u1b04\u1b34-\u1b44\u1b50-\u1b59\u1b6b-\u1b73\u1b80-\u1b82\u1ba1-\u1bad\u1bb0-\u1bb9\u1be6-\u1bf3\u1c24-\u1c37\u1c40-\u1c49\u1c50-\u1c59\u1cd0-\u1cd2\u1cd4-\u1ce8\u1ced\u1cf4\u1cf7-\u1cf9\u1dc0-\u1dff\u200c\u200d\u203f\u2040\u2054\u20d0-\u20dc\u20e1\u20e5-\u20f0\u2cef-\u2cf1\u2d7f\u2de0-\u2dff\u302a-\u302f\u3099\u309a\u30fb\ua620-\ua629\ua66f\ua674-\ua67d\ua69e\ua69f\ua6f0\ua6f1\ua802\ua806\ua80b\ua823-\ua827\ua82c\ua880\ua881\ua8b4-\ua8c5\ua8d0-\ua8d9\ua8e0-\ua8f1\ua8ff-\ua909\ua926-\ua92d\ua947-\ua953\ua980-\ua983\ua9b3-\ua9c0\ua9d0-\ua9d9\ua9e5\ua9f0-\ua9f9\uaa29-\uaa36\uaa43\uaa4c\uaa4d\uaa50-\uaa59\uaa7b-\uaa7d\uaab0\uaab2-\uaab4\uaab7\uaab8\uaabe\uaabf\uaac1\uaaeb-\uaaef\uaaf5\uaaf6\uabe3-\uabea\uabec\uabed\uabf0-\uabf9\ufb1e\ufe00-\ufe0f\ufe20-\ufe2f\ufe33\ufe34\ufe4d-\ufe4f\uff10-\uff19\uff3f\uff65";

// This file was generated. Do not modify manually!
var nonASCIIidentifierStartChars = "\xaa\xb5\xba\xc0-\xd6\xd8-\xf6\xf8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0370-\u0374\u0376\u0377\u037a-\u037d\u037f\u0386\u0388-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u048a-\u052f\u0531-\u0556\u0559\u0560-\u0588\u05d0-\u05ea\u05ef-\u05f2\u0620-\u064a\u066e\u066f\u0671-\u06d3\u06d5\u06e5\u06e6\u06ee\u06ef\u06fa-\u06fc\u06ff\u0710\u0712-\u072f\u074d-\u07a5\u07b1\u07ca-\u07ea\u07f4\u07f5\u07fa\u0800-\u0815\u081a\u0824\u0828\u0840-\u0858\u0860-\u086a\u0870-\u0887\u0889-\u088f\u08a0-\u08c9\u0904-\u0939\u093d\u0950\u0958-\u0961\u0971-\u0980\u0985-\u098c\u098f\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bd\u09ce\u09dc\u09dd\u09df-\u09e1\u09f0\u09f1\u09fc\u0a05-\u0a0a\u0a0f\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32\u0a33\u0a35\u0a36\u0a38\u0a39\u0a59-\u0a5c\u0a5e\u0a72-\u0a74\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2\u0ab3\u0ab5-\u0ab9\u0abd\u0ad0\u0ae0\u0ae1\u0af9\u0b05-\u0b0c\u0b0f\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32\u0b33\u0b35-\u0b39\u0b3d\u0b5c\u0b5d\u0b5f-\u0b61\u0b71\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99\u0b9a\u0b9c\u0b9e\u0b9f\u0ba3\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bd0\u0c05-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c39\u0c3d\u0c58-\u0c5a\u0c5c\u0c5d\u0c60\u0c61\u0c80\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbd\u0cdc-\u0cde\u0ce0\u0ce1\u0cf1\u0cf2\u0d04-\u0d0c\u0d0e-\u0d10\u0d12-\u0d3a\u0d3d\u0d4e\u0d54-\u0d56\u0d5f-\u0d61\u0d7a-\u0d7f\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0e01-\u0e30\u0e32\u0e33\u0e40-\u0e46\u0e81\u0e82\u0e84\u0e86-\u0e8a\u0e8c-\u0ea3\u0ea5\u0ea7-\u0eb0\u0eb2\u0eb3\u0ebd\u0ec0-\u0ec4\u0ec6\u0edc-\u0edf\u0f00\u0f40-\u0f47\u0f49-\u0f6c\u0f88-\u0f8c\u1000-\u102a\u103f\u1050-\u1055\u105a-\u105d\u1061\u1065\u1066\u106e-\u1070\u1075-\u1081\u108e\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u1380-\u138f\u13a0-\u13f5\u13f8-\u13fd\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f8\u1700-\u1711\u171f-\u1731\u1740-\u1751\u1760-\u176c\u176e-\u1770\u1780-\u17b3\u17d7\u17dc\u1820-\u1878\u1880-\u18a8\u18aa\u18b0-\u18f5\u1900-\u191e\u1950-\u196d\u1970-\u1974\u1980-\u19ab\u19b0-\u19c9\u1a00-\u1a16\u1a20-\u1a54\u1aa7\u1b05-\u1b33\u1b45-\u1b4c\u1b83-\u1ba0\u1bae\u1baf\u1bba-\u1be5\u1c00-\u1c23\u1c4d-\u1c4f\u1c5a-\u1c7d\u1c80-\u1c8a\u1c90-\u1cba\u1cbd-\u1cbf\u1ce9-\u1cec\u1cee-\u1cf3\u1cf5\u1cf6\u1cfa\u1d00-\u1dbf\u1e00-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u2071\u207f\u2090-\u209c\u2102\u2107\u210a-\u2113\u2115\u2118-\u211d\u2124\u2126\u2128\u212a-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2ce4\u2ceb-\u2cee\u2cf2\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d80-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u3005-\u3007\u3021-\u3029\u3031-\u3035\u3038-\u303c\u3041-\u3096\u309b-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312f\u3131-\u318e\u31a0-\u31bf\u31f0-\u31ff\u3400-\u4dbf\u4e00-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua61f\ua62a\ua62b\ua640-\ua66e\ua67f-\ua69d\ua6a0-\ua6ef\ua717-\ua71f\ua722-\ua788\ua78b-\ua7dc\ua7f1-\ua801\ua803-\ua805\ua807-\ua80a\ua80c-\ua822\ua840-\ua873\ua882-\ua8b3\ua8f2-\ua8f7\ua8fb\ua8fd\ua8fe\ua90a-\ua925\ua930-\ua946\ua960-\ua97c\ua984-\ua9b2\ua9cf\ua9e0-\ua9e4\ua9e6-\ua9ef\ua9fa-\ua9fe\uaa00-\uaa28\uaa40-\uaa42\uaa44-\uaa4b\uaa60-\uaa76\uaa7a\uaa7e-\uaaaf\uaab1\uaab5\uaab6\uaab9-\uaabd\uaac0\uaac2\uaadb-\uaadd\uaae0-\uaaea\uaaf2-\uaaf4\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uab30-\uab5a\uab5c-\uab69\uab70-\uabe2\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d\ufb1f-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40\ufb41\ufb43\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe70-\ufe74\ufe76-\ufefc\uff21-\uff3a\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc";

// These are a run-length and offset encoded representation of the
// >0xffff code points that are a valid part of identifiers. The
// offset starts at 0x10000, and each pair of numbers represents an
// offset to the next range, and then a size of the range.

// Reserved word lists for various dialects of the language

var reservedWords = {
  3: "abstract boolean byte char class double enum export extends final float goto implements import int interface long native package private protected public short static super synchronized throws transient volatile",
  5: "class enum extends super const export import",
  6: "enum",
  strict: "implements interface let package private protected public static yield",
  strictBind: "eval arguments"
};

// And the keywords

var ecma5AndLessKeywords = "break case catch continue debugger default do else finally for function if return switch throw try var while with null true false instanceof typeof void delete new in this";

var keywords$1 = {
  5: ecma5AndLessKeywords,
  "5module": ecma5AndLessKeywords + " export import",
  6: ecma5AndLessKeywords + " const class extends export import super"
};

var keywordRelationalOperator = /^in(stanceof)?$/;

// ## Character categories

var nonASCIIidentifierStart = new RegExp("[" + nonASCIIidentifierStartChars + "]");
var nonASCIIidentifier = new RegExp("[" + nonASCIIidentifierStartChars + nonASCIIidentifierChars + "]");

// This has a complexity linear to the value of the code. The
// assumption is that looking up astral identifier characters is
// rare.
function isInAstralSet(code, set) {
  var pos = 0x10000;
  for (var i = 0; i < set.length; i += 2) {
    pos += set[i];
    if (pos > code) { return false }
    pos += set[i + 1];
    if (pos >= code) { return true }
  }
  return false
}

// Test whether a given character code starts an identifier.

function isIdentifierStart(code, astral) {
  if (code < 65) { return code === 36 }
  if (code < 91) { return true }
  if (code < 97) { return code === 95 }
  if (code < 123) { return true }
  if (code <= 0xffff) { return code >= 0xaa && nonASCIIidentifierStart.test(String.fromCharCode(code)) }
  if (astral === false) { return false }
  return isInAstralSet(code, astralIdentifierStartCodes)
}

// Test whether a given character is part of an identifier.

function isIdentifierChar(code, astral) {
  if (code < 48) { return code === 36 }
  if (code < 58) { return true }
  if (code < 65) { return false }
  if (code < 91) { return true }
  if (code < 97) { return code === 95 }
  if (code < 123) { return true }
  if (code <= 0xffff) { return code >= 0xaa && nonASCIIidentifier.test(String.fromCharCode(code)) }
  if (astral === false) { return false }
  return isInAstralSet(code, astralIdentifierStartCodes) || isInAstralSet(code, astralIdentifierCodes)
}

// ## Token types

// The assignment of fine-grained, information-carrying type objects
// allows the tokenizer to store the information it has about a
// token in a way that is very cheap for the parser to look up.

// All token type variables start with an underscore, to make them
// easy to recognize.

// The `beforeExpr` property is used to disambiguate between regular
// expressions and divisions. It is set on all token types that can
// be followed by an expression (thus, a slash after them would be a
// regular expression).
//
// The `startsExpr` property is used to check if the token ends a
// `yield` expression. It is set on all token types that either can
// directly start an expression (like a quotation mark) or can
// continue an expression (like the body of a string).
//
// `isLoop` marks a keyword as starting a loop, which is important
// to know when parsing a label, in order to allow or disallow
// continue jumps to that label.

var TokenType = function TokenType(label, conf) {
  if ( conf === void 0 ) conf = {};

  this.label = label;
  this.keyword = conf.keyword;
  this.beforeExpr = !!conf.beforeExpr;
  this.startsExpr = !!conf.startsExpr;
  this.isLoop = !!conf.isLoop;
  this.isAssign = !!conf.isAssign;
  this.prefix = !!conf.prefix;
  this.postfix = !!conf.postfix;
  this.binop = conf.binop || null;
  this.updateContext = null;
};

function binop(name, prec) {
  return new TokenType(name, {beforeExpr: true, binop: prec})
}
var beforeExpr = {beforeExpr: true}, startsExpr = {startsExpr: true};

// Map keyword names to token types.

var keywords = {};

// Succinct definitions of keyword token types
function kw(name, options) {
  if ( options === void 0 ) options = {};

  options.keyword = name;
  return keywords[name] = new TokenType(name, options)
}

var types$1 = {
  num: new TokenType("num", startsExpr),
  regexp: new TokenType("regexp", startsExpr),
  string: new TokenType("string", startsExpr),
  name: new TokenType("name", startsExpr),
  privateId: new TokenType("privateId", startsExpr),
  eof: new TokenType("eof"),

  // Punctuation token types.
  bracketL: new TokenType("[", {beforeExpr: true, startsExpr: true}),
  bracketR: new TokenType("]"),
  braceL: new TokenType("{", {beforeExpr: true, startsExpr: true}),
  braceR: new TokenType("}"),
  parenL: new TokenType("(", {beforeExpr: true, startsExpr: true}),
  parenR: new TokenType(")"),
  comma: new TokenType(",", beforeExpr),
  semi: new TokenType(";", beforeExpr),
  colon: new TokenType(":", beforeExpr),
  dot: new TokenType("."),
  question: new TokenType("?", beforeExpr),
  questionDot: new TokenType("?."),
  arrow: new TokenType("=>", beforeExpr),
  template: new TokenType("template"),
  invalidTemplate: new TokenType("invalidTemplate"),
  ellipsis: new TokenType("...", beforeExpr),
  backQuote: new TokenType("`", startsExpr),
  dollarBraceL: new TokenType("${", {beforeExpr: true, startsExpr: true}),

  // Operators. These carry several kinds of properties to help the
  // parser use them properly (the presence of these properties is
  // what categorizes them as operators).
  //
  // `binop`, when present, specifies that this operator is a binary
  // operator, and will refer to its precedence.
  //
  // `prefix` and `postfix` mark the operator as a prefix or postfix
  // unary operator.
  //
  // `isAssign` marks all of `=`, `+=`, `-=` etcetera, which act as
  // binary operators with a very low precedence, that should result
  // in AssignmentExpression nodes.

  eq: new TokenType("=", {beforeExpr: true, isAssign: true}),
  assign: new TokenType("_=", {beforeExpr: true, isAssign: true}),
  incDec: new TokenType("++/--", {prefix: true, postfix: true, startsExpr: true}),
  prefix: new TokenType("!/~", {beforeExpr: true, prefix: true, startsExpr: true}),
  logicalOR: binop("||", 1),
  logicalAND: binop("&&", 2),
  bitwiseOR: binop("|", 3),
  bitwiseXOR: binop("^", 4),
  bitwiseAND: binop("&", 5),
  equality: binop("==/!=/===/!==", 6),
  relational: binop("</>/<=/>=", 7),
  bitShift: binop("<</>>/>>>", 8),
  plusMin: new TokenType("+/-", {beforeExpr: true, binop: 9, prefix: true, startsExpr: true}),
  modulo: binop("%", 10),
  star: binop("*", 10),
  slash: binop("/", 10),
  starstar: new TokenType("**", {beforeExpr: true}),
  coalesce: binop("??", 1),

  // Keyword token types.
  _break: kw("break"),
  _case: kw("case", beforeExpr),
  _catch: kw("catch"),
  _continue: kw("continue"),
  _debugger: kw("debugger"),
  _default: kw("default", beforeExpr),
  _do: kw("do", {isLoop: true, beforeExpr: true}),
  _else: kw("else", beforeExpr),
  _finally: kw("finally"),
  _for: kw("for", {isLoop: true}),
  _function: kw("function", startsExpr),
  _if: kw("if"),
  _return: kw("return", beforeExpr),
  _switch: kw("switch"),
  _throw: kw("throw", beforeExpr),
  _try: kw("try"),
  _var: kw("var"),
  _const: kw("const"),
  _while: kw("while", {isLoop: true}),
  _with: kw("with"),
  _new: kw("new", {beforeExpr: true, startsExpr: true}),
  _this: kw("this", startsExpr),
  _super: kw("super", startsExpr),
  _class: kw("class", startsExpr),
  _extends: kw("extends", beforeExpr),
  _export: kw("export"),
  _import: kw("import", startsExpr),
  _null: kw("null", startsExpr),
  _true: kw("true", startsExpr),
  _false: kw("false", startsExpr),
  _in: kw("in", {beforeExpr: true, binop: 7}),
  _instanceof: kw("instanceof", {beforeExpr: true, binop: 7}),
  _typeof: kw("typeof", {beforeExpr: true, prefix: true, startsExpr: true}),
  _void: kw("void", {beforeExpr: true, prefix: true, startsExpr: true}),
  _delete: kw("delete", {beforeExpr: true, prefix: true, startsExpr: true})
};

// Matches a whole line break (where CRLF is considered a single
// line break). Used to count lines.

var lineBreak = /\r\n?|\n|\u2028|\u2029/;
var lineBreakG = new RegExp(lineBreak.source, "g");

function isNewLine(code) {
  return code === 10 || code === 13 || code === 0x2028 || code === 0x2029
}

function nextLineBreak(code, from, end) {
  if ( end === void 0 ) end = code.length;

  for (var i = from; i < end; i++) {
    var next = code.charCodeAt(i);
    if (isNewLine(next))
      { return i < end - 1 && next === 13 && code.charCodeAt(i + 1) === 10 ? i + 2 : i + 1 }
  }
  return -1
}

var nonASCIIwhitespace = /[\u1680\u2000-\u200a\u202f\u205f\u3000\ufeff]/;

var skipWhiteSpace = /(?:\s|\/\/.*|\/\*[^]*?\*\/)*/g;

var ref = Object.prototype;
var hasOwnProperty = ref.hasOwnProperty;
var toString = ref.toString;

var hasOwn = Object.hasOwn || (function (obj, propName) { return (
  hasOwnProperty.call(obj, propName)
); });

var isArray = Array.isArray || (function (obj) { return (
  toString.call(obj) === "[object Array]"
); });

var regexpCache = Object.create(null);

function wordsRegexp(words) {
  return regexpCache[words] || (regexpCache[words] = new RegExp("^(?:" + words.replace(/ /g, "|") + ")$"))
}

function codePointToString(code) {
  // UTF-16 Decoding
  if (code <= 0xFFFF) { return String.fromCharCode(code) }
  code -= 0x10000;
  return String.fromCharCode((code >> 10) + 0xD800, (code & 1023) + 0xDC00)
}

var loneSurrogate = /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF])/;

// These are used when `options.locations` is on, for the
// `startLoc` and `endLoc` properties.

var Position = function Position(line, col) {
  this.line = line;
  this.column = col;
};

Position.prototype.offset = function offset (n) {
  return new Position(this.line, this.column + n)
};

var SourceLocation = function SourceLocation(p, start, end) {
  this.start = start;
  this.end = end;
  if (p.sourceFile !== null) { this.source = p.sourceFile; }
};

// The `getLineInfo` function is mostly useful when the
// `locations` option is off (for performance reasons) and you
// want to find the line/column position for a given character
// offset. `input` should be the code string that the offset refers
// into.

function getLineInfo(input, offset) {
  for (var line = 1, cur = 0;;) {
    var nextBreak = nextLineBreak(input, cur, offset);
    if (nextBreak < 0) { return new Position(line, offset - cur) }
    ++line;
    cur = nextBreak;
  }
}

// A second argument must be given to configure the parser process.
// These options are recognized (only `ecmaVersion` is required):

var defaultOptions = {
  // `ecmaVersion` indicates the ECMAScript version to parse. Must be
  // either 3, 5, 6 (or 2015), 7 (2016), 8 (2017), 9 (2018), 10
  // (2019), 11 (2020), 12 (2021), 13 (2022), 14 (2023), or `"latest"`
  // (the latest version the library supports). This influences
  // support for strict mode, the set of reserved words, and support
  // for new syntax features.
  ecmaVersion: null,
  // `sourceType` indicates the mode the code should be parsed in.
  // Can be either `"script"`, `"module"` or `"commonjs"`. This influences global
  // strict mode and parsing of `import` and `export` declarations.
  sourceType: "script",
  // When set to true, enable strict parsing mode even if `sourceType`
  // is `"script"`.
  strict: false,
  // `onInsertedSemicolon` can be a callback that will be called when
  // a semicolon is automatically inserted. It will be passed the
  // position of the inserted semicolon as an offset, and if
  // `locations` is enabled, it is given the location as a `{line,
  // column}` object as second argument.
  onInsertedSemicolon: null,
  // `onTrailingComma` is similar to `onInsertedSemicolon`, but for
  // trailing commas.
  onTrailingComma: null,
  // By default, reserved words are only enforced if ecmaVersion >= 5.
  // Set `allowReserved` to a boolean value to explicitly turn this on
  // an off. When this option has the value "never", reserved words
  // and keywords can also not be used as property names.
  allowReserved: null,
  // When enabled, a return at the top level is not considered an
  // error.
  allowReturnOutsideFunction: false,
  // When enabled, import/export statements are not constrained to
  // appearing at the top of the program, and an import.meta expression
  // in a script isn't considered an error.
  allowImportExportEverywhere: false,
  // By default, await identifiers are allowed to appear at the top-level scope only if ecmaVersion >= 2022.
  // When enabled, await identifiers are allowed to appear at the top-level scope,
  // but they are still not allowed in non-async functions.
  allowAwaitOutsideFunction: null,
  // When enabled, super identifiers are not constrained to
  // appearing in methods and do not raise an error when they appear elsewhere.
  allowSuperOutsideMethod: null,
  // When enabled, hashbang directive in the beginning of file is
  // allowed and treated as a line comment. Enabled by default when
  // `ecmaVersion` >= 2023.
  allowHashBang: false,
  // By default, the parser will verify that private properties are
  // only used in places where they are valid and have been declared.
  // Set this to false to turn such checks off.
  checkPrivateFields: true,
  // When `locations` is on, `loc` properties holding objects with
  // `start` and `end` properties in `{line, column}` form (with
  // line being 1-based and column 0-based) will be attached to the
  // nodes.
  locations: false,
  // Pass an optional `{line, column}` object to use for the start of
  // the parse. This is mostly useful when using `parseExpressionAt`
  // with `locations: true`, to prevent the parser from having to
  // determine the line position at the start position.
  startLocation: null,
  // A function can be passed as `onToken` option, which will
  // cause Acorn to call that function with object in the same
  // format as tokens returned from `tokenizer().getToken()`. Note
  // that you are not allowed to call the parser from the
  // callback—that will corrupt its internal state.
  onToken: null,
  // A function can be passed as `onComment` option, which will
  // cause Acorn to call that function with `(block, text, start,
  // end)` parameters whenever a comment is skipped. `block` is a
  // boolean indicating whether this is a block (`/* */`) comment,
  // `text` is the content of the comment, and `start` and `end` are
  // character offsets that denote the start and end of the comment.
  // When the `locations` option is on, two more parameters are
  // passed, the full `{line, column}` locations of the start and
  // end of the comments. Note that you are not allowed to call the
  // parser from the callback—that will corrupt its internal state.
  // When this option has an array as value, objects representing the
  // comments are pushed to it.
  onComment: null,
  // Nodes have their start and end characters offsets recorded in
  // `start` and `end` properties (directly on the node, rather than
  // the `loc` object, which holds line/column data. To also add a
  // [semi-standardized][range] `range` property holding a `[start,
  // end]` array with the same numbers, set the `ranges` option to
  // `true`.
  //
  // [range]: https://bugzilla.mozilla.org/show_bug.cgi?id=745678
  ranges: false,
  // It is possible to parse multiple files into a single AST by
  // passing the tree produced by parsing the first file as
  // `program` option in subsequent parses. This will add the
  // toplevel forms of the parsed file to the `Program` (top) node
  // of an existing parse tree.
  program: null,
  // When `locations` is on, you can pass this to record the source
  // file in every node's `loc` object.
  sourceFile: null,
  // This value, if given, is stored in every node, whether
  // `locations` is on or off.
  directSourceFile: null,
  // When enabled, parenthesized expressions are represented by
  // (non-standard) ParenthesizedExpression nodes
  preserveParens: false
};

// Interpret and default an options object

var warnedAboutEcmaVersion = false;

function getOptions(opts) {
  var options = {};

  for (var opt in defaultOptions)
    { options[opt] = opts && hasOwn(opts, opt) ? opts[opt] : defaultOptions[opt]; }

  if (options.ecmaVersion === "latest") {
    options.ecmaVersion = 1e8;
  } else if (options.ecmaVersion == null) {
    if (!warnedAboutEcmaVersion && typeof console === "object" && console.warn) {
      warnedAboutEcmaVersion = true;
      console.warn("Since Acorn 8.0.0, options.ecmaVersion is required.\nDefaulting to 2020, but this will stop working in the future.");
    }
    options.ecmaVersion = 11;
  } else if (options.ecmaVersion >= 2015) {
    options.ecmaVersion -= 2009;
  }

  if (options.allowReserved == null)
    { options.allowReserved = options.ecmaVersion < 5; }

  if (!opts || opts.allowHashBang == null)
    { options.allowHashBang = options.ecmaVersion >= 14; }

  if (isArray(options.onToken)) {
    var tokens = options.onToken;
    options.onToken = function (token) { return tokens.push(token); };
  }
  if (isArray(options.onComment))
    { options.onComment = pushComment(options, options.onComment); }

  if (options.sourceType === "commonjs" && options.allowAwaitOutsideFunction)
    { throw new Error("Cannot use allowAwaitOutsideFunction with sourceType: commonjs") }

  return options
}

function pushComment(options, array) {
  return function(block, text, start, end, startLoc, endLoc) {
    var comment = {
      type: block ? "Block" : "Line",
      value: text,
      start: start,
      end: end
    };
    if (options.locations)
      { comment.loc = new SourceLocation(this, startLoc, endLoc); }
    if (options.ranges)
      { comment.range = [start, end]; }
    array.push(comment);
  }
}

// Each scope gets a bitset that may contain these flags
var
    SCOPE_TOP = 1,
    SCOPE_FUNCTION = 2,
    SCOPE_ASYNC = 4,
    SCOPE_GENERATOR = 8,
    SCOPE_ARROW = 16,
    SCOPE_SIMPLE_CATCH = 32,
    SCOPE_SUPER = 64,
    SCOPE_DIRECT_SUPER = 128,
    SCOPE_CLASS_STATIC_BLOCK = 256,
    SCOPE_CLASS_FIELD_INIT = 512,
    SCOPE_SWITCH = 1024,
    SCOPE_VAR = SCOPE_TOP | SCOPE_FUNCTION | SCOPE_CLASS_STATIC_BLOCK;

function functionFlags(async, generator) {
  return SCOPE_FUNCTION | (async ? SCOPE_ASYNC : 0) | (generator ? SCOPE_GENERATOR : 0)
}

// Used in checkLVal* and declareName to determine the type of a binding
var
    BIND_NONE = 0, // Not a binding
    BIND_VAR = 1, // Var-style binding
    BIND_LEXICAL = 2, // Let- or const-style binding
    BIND_FUNCTION = 3, // Function declaration
    BIND_SIMPLE_CATCH = 4, // Simple (identifier pattern) catch binding
    BIND_OUTSIDE = 5; // Special case for function names as bound inside the function

var Parser = function Parser(options, input, startPos) {
  this.options = options = getOptions(options);
  this.sourceFile = options.sourceFile;
  this.keywords = wordsRegexp(keywords$1[options.ecmaVersion >= 6 ? 6 : options.sourceType === "module" ? "5module" : 5]);
  var reserved = "";
  if (options.allowReserved !== true) {
    reserved = reservedWords[options.ecmaVersion >= 6 ? 6 : options.ecmaVersion === 5 ? 5 : 3];
    if (options.sourceType === "module") { reserved += " await"; }
  }
  this.reservedWords = wordsRegexp(reserved);
  var reservedStrict = (reserved ? reserved + " " : "") + reservedWords.strict;
  this.reservedWordsStrict = wordsRegexp(reservedStrict);
  this.reservedWordsStrictBind = wordsRegexp(reservedStrict + " " + reservedWords.strictBind);
  this.input = String(input);

  // Used to signal to callers of `readWord1` whether the word
  // contained any escape sequences. This is needed because words with
  // escape sequences must not be interpreted as keywords.
  this.containsEsc = false;

  // Set up token state

  // The current position of the tokenizer in the input.
  this.pos = startPos || 0;
  this.curLine = 1;
  if (options.startLocation) {
    this.lineStart = this.pos - options.startLocation.column;
    this.curLine = options.startLocation.line;
  } else if (startPos) {
    this.lineStart = this.input.lastIndexOf("\n", startPos - 1) + 1;
    if (this.options.locations)
      { this.curLine = this.input.slice(0, this.lineStart).split(lineBreak).length; }
  } else {
    this.lineStart = 0;
  }

  // Properties of the current token:
  // Its type
  this.type = types$1.eof;
  // For tokens that include more information than their type, the value
  this.value = null;
  // Its start and end offset
  this.start = this.end = this.pos;
  // And, if locations are used, the {line, column} object
  // corresponding to those offsets
  this.startLoc = this.endLoc = this.curPosition();

  // Position information for the previous token
  this.lastTokEndLoc = this.lastTokStartLoc = null;
  this.lastTokStart = this.lastTokEnd = this.pos;

  // The context stack is used to superficially track syntactic
  // context to predict whether a regular expression is allowed in a
  // given position.
  this.context = this.initialContext();
  this.exprAllowed = true;

  // Figure out if it's a module code.
  this.inModule = options.sourceType === "module";
  this.strict = this.inModule || options.strict === true || this.strictDirective(this.pos);

  // Used to signify the start of a potential arrow function
  this.potentialArrowAt = -1;
  this.potentialArrowInForAwait = false;

  // Positions to delayed-check that yield/await does not exist in default parameters.
  this.yieldPos = this.awaitPos = this.awaitIdentPos = 0;
  // Labels in scope.
  this.labels = [];
  // Thus-far undefined exports.
  this.undefinedExports = Object.create(null);

  // If enabled, skip leading hashbang line.
  if (this.pos === 0 && options.allowHashBang && this.input.slice(0, 2) === "#!")
    { this.skipLineComment(2); }

  // Scope tracking for duplicate variable names (see scope.js)
  this.scopeStack = [];
  this.enterScope(
    this.options.sourceType === "commonjs"
      // In commonjs, the top-level scope behaves like a function scope
      ? SCOPE_FUNCTION
      : SCOPE_TOP
  );

  // For RegExp validation
  this.regexpState = null;

  // The stack of private names.
  // Each element has two properties: 'declared' and 'used'.
  // When it exited from the outermost class definition, all used private names must be declared.
  this.privateNameStack = [];
};

var prototypeAccessors = { inFunction: { configurable: true },inGenerator: { configurable: true },inAsync: { configurable: true },canAwait: { configurable: true },allowReturn: { configurable: true },allowSuper: { configurable: true },allowDirectSuper: { configurable: true },treatFunctionsAsVar: { configurable: true },allowNewDotTarget: { configurable: true },allowUsing: { configurable: true },inClassStaticBlock: { configurable: true } };

Parser.prototype.parse = function parse () {
    var this$1$1 = this;

  var node = this.options.program || this.startNode();
  this.nextToken();
  return this.catchStackOverflow(function () { return this$1$1.parseTopLevel(node); })
};

prototypeAccessors.inFunction.get = function () { return (this.currentVarScope().flags & SCOPE_FUNCTION) > 0 };

prototypeAccessors.inGenerator.get = function () { return (this.currentVarScope().flags & SCOPE_GENERATOR) > 0 };

prototypeAccessors.inAsync.get = function () { return (this.currentVarScope().flags & SCOPE_ASYNC) > 0 };

prototypeAccessors.canAwait.get = function () {
  for (var i = this.scopeStack.length - 1; i >= 0; i--) {
    var ref = this.scopeStack[i];
      var flags = ref.flags;
    if (flags & (SCOPE_CLASS_STATIC_BLOCK | SCOPE_CLASS_FIELD_INIT)) { return false }
    if (flags & SCOPE_FUNCTION) { return (flags & SCOPE_ASYNC) > 0 }
  }
  return (this.inModule && this.options.ecmaVersion >= 13) || this.options.allowAwaitOutsideFunction
};

prototypeAccessors.allowReturn.get = function () {
  if (this.inFunction) { return true }
  if (this.options.allowReturnOutsideFunction && this.currentVarScope().flags & SCOPE_TOP) { return true }
  return false
};

prototypeAccessors.allowSuper.get = function () {
  var ref = this.currentThisScope();
    var flags = ref.flags;
  return (flags & SCOPE_SUPER) > 0 || this.options.allowSuperOutsideMethod
};

prototypeAccessors.allowDirectSuper.get = function () { return (this.currentThisScope().flags & SCOPE_DIRECT_SUPER) > 0 };

prototypeAccessors.treatFunctionsAsVar.get = function () { return this.treatFunctionsAsVarInScope(this.currentScope()) };

prototypeAccessors.allowNewDotTarget.get = function () {
  for (var i = this.scopeStack.length - 1; i >= 0; i--) {
    var ref = this.scopeStack[i];
      var flags = ref.flags;
    if (flags & (SCOPE_CLASS_STATIC_BLOCK | SCOPE_CLASS_FIELD_INIT) ||
        ((flags & SCOPE_FUNCTION) && !(flags & SCOPE_ARROW))) { return true }
  }
  return false
};

prototypeAccessors.allowUsing.get = function () {
  var ref = this.currentScope();
    var flags = ref.flags;
  if (flags & SCOPE_SWITCH) { return false }
  if (!this.inModule && flags & SCOPE_TOP) { return false }
  return true
};

prototypeAccessors.inClassStaticBlock.get = function () {
  return (this.currentVarScope().flags & SCOPE_CLASS_STATIC_BLOCK) > 0
};

Parser.extend = function extend () {
    var plugins = [], len = arguments.length;
    while ( len-- ) plugins[ len ] = arguments[ len ];

  var cls = this;
  for (var i = 0; i < plugins.length; i++) { cls = plugins[i](cls); }
  return cls
};

Parser.parse = function parse (input, options) {
  return new this(options, input).parse()
};

Parser.parseExpressionAt = function parseExpressionAt (input, pos, options) {
  var parser = new this(options, input, pos);
  parser.nextToken();
  return parser.parseExpression()
};

Parser.tokenizer = function tokenizer (input, options) {
  return new this(options, input)
};

Object.defineProperties( Parser.prototype, prototypeAccessors );

var pp$9 = Parser.prototype;

// ## Parser utilities

var literal = /^(?:'((?:\\[^]|[^'\\])*?)'|"((?:\\[^]|[^"\\])*?)")/;
pp$9.strictDirective = function(start) {
  if (this.options.ecmaVersion < 5) { return false }
  for (;;) {
    // Try to find string literal.
    skipWhiteSpace.lastIndex = start;
    start += skipWhiteSpace.exec(this.input)[0].length;
    var match = literal.exec(this.input.slice(start));
    if (!match) { return false }
    if ((match[1] || match[2]) === "use strict") {
      skipWhiteSpace.lastIndex = start + match[0].length;
      var spaceAfter = skipWhiteSpace.exec(this.input), end = spaceAfter.index + spaceAfter[0].length;
      var next = this.input.charAt(end);
      return next === ";" || next === "}" ||
        (lineBreak.test(spaceAfter[0]) &&
         !(/[(`.[+\-/*%<>=,?^&]/.test(next) || next === "!" && this.input.charAt(end + 1) === "="))
    }
    start += match[0].length;

    // Skip semicolon, if any.
    skipWhiteSpace.lastIndex = start;
    start += skipWhiteSpace.exec(this.input)[0].length;
    if (this.input[start] === ";")
      { start++; }
  }
};

// Predicate that tests whether the next token is of the given
// type, and if yes, consumes it as a side effect.

pp$9.eat = function(type) {
  if (this.type === type) {
    this.next();
    return true
  } else {
    return false
  }
};

// Tests whether parsed token is a contextual keyword.

pp$9.isContextual = function(name) {
  return this.type === types$1.name && this.value === name && !this.containsEsc
};

// Consumes contextual keyword if possible.

pp$9.eatContextual = function(name) {
  if (!this.isContextual(name)) { return false }
  this.next();
  return true
};

pp$9.catchStackOverflow = function(f) {
  try {
    return f()
  } catch (e) {
    if (e instanceof Error && (/\bstack\b.*\b(exceeded|overflow)\b/i.test(e.message) || /\btoo much recursion\b/i.test(e.message)))
      { this.raise(this.start, "Not enough stack space to parse input"); }
    else
      { throw e }
  }
};

// Asserts that following token is given contextual keyword.

pp$9.expectContextual = function(name) {
  if (!this.eatContextual(name)) { this.unexpected(); }
};

// Test whether a semicolon can be inserted at the current position.

pp$9.canInsertSemicolon = function() {
  return this.type === types$1.eof ||
    this.type === types$1.braceR ||
    lineBreak.test(this.input.slice(this.lastTokEnd, this.start))
};

pp$9.insertSemicolon = function() {
  if (this.canInsertSemicolon()) {
    if (this.options.onInsertedSemicolon)
      { this.options.onInsertedSemicolon(this.lastTokEnd, this.lastTokEndLoc); }
    return true
  }
};

// Consume a semicolon, or, failing that, see if we are allowed to
// pretend that there is a semicolon at this position.

pp$9.semicolon = function() {
  if (!this.eat(types$1.semi) && !this.insertSemicolon()) { this.unexpected(); }
};

pp$9.afterTrailingComma = function(tokType, notNext) {
  if (this.type === tokType) {
    if (this.options.onTrailingComma)
      { this.options.onTrailingComma(this.lastTokStart, this.lastTokStartLoc); }
    if (!notNext)
      { this.next(); }
    return true
  }
};

// Expect a token of a given type. If found, consume it, otherwise,
// raise an unexpected token error.

pp$9.expect = function(type) {
  this.eat(type) || this.unexpected();
};

// Raise an unexpected token error.

pp$9.unexpected = function(pos) {
  this.raise(pos != null ? pos : this.start, "Unexpected token");
};

var DestructuringErrors = function DestructuringErrors() {
  this.shorthandAssign =
  this.trailingComma =
  this.parenthesizedAssign =
  this.parenthesizedBind =
  this.doubleProto =
    -1;
};

pp$9.checkPatternErrors = function(refDestructuringErrors, isAssign) {
  if (!refDestructuringErrors) { return }
  if (refDestructuringErrors.trailingComma > -1)
    { this.raiseRecoverable(refDestructuringErrors.trailingComma, "Comma is not permitted after the rest element"); }
  var parens = isAssign ? refDestructuringErrors.parenthesizedAssign : refDestructuringErrors.parenthesizedBind;
  if (parens > -1) { this.raiseRecoverable(parens, isAssign ? "Assigning to rvalue" : "Parenthesized pattern"); }
};

pp$9.checkExpressionErrors = function(refDestructuringErrors, andThrow) {
  if (!refDestructuringErrors) { return false }
  var shorthandAssign = refDestructuringErrors.shorthandAssign;
  var doubleProto = refDestructuringErrors.doubleProto;
  if (!andThrow) { return shorthandAssign >= 0 || doubleProto >= 0 }
  if (shorthandAssign >= 0)
    { this.raise(shorthandAssign, "Shorthand property assignments are valid only in destructuring patterns"); }
  if (doubleProto >= 0)
    { this.raiseRecoverable(doubleProto, "Redefinition of __proto__ property"); }
};

pp$9.checkYieldAwaitInDefaultParams = function() {
  if (this.yieldPos && (!this.awaitPos || this.yieldPos < this.awaitPos))
    { this.raise(this.yieldPos, "Yield expression cannot be a default value"); }
  if (this.awaitPos)
    { this.raise(this.awaitPos, "Await expression cannot be a default value"); }
};

pp$9.isSimpleAssignTarget = function(expr) {
  if (expr.type === "ParenthesizedExpression")
    { return this.isSimpleAssignTarget(expr.expression) }
  return expr.type === "Identifier" || expr.type === "MemberExpression"
};

var pp$8 = Parser.prototype;

// ### Statement parsing

// Parse a program. Initializes the parser, reads any number of
// statements, and wraps them in a Program node.  Optionally takes a
// `program` argument.  If present, the statements will be appended
// to its body instead of creating a new node.

pp$8.parseTopLevel = function(node) {
  var exports$1 = Object.create(null);
  if (!node.body) { node.body = []; }
  while (this.type !== types$1.eof) {
    var stmt = this.parseStatement(null, true, exports$1);
    node.body.push(stmt);
  }
  if (this.inModule)
    { for (var i = 0, list = Object.keys(this.undefinedExports); i < list.length; i += 1)
      {
        var name = list[i];

        this.raiseRecoverable(this.undefinedExports[name].start, ("Export '" + name + "' is not defined"));
      } }
  this.adaptDirectivePrologue(node.body);
  this.next();
  node.sourceType = this.options.sourceType === "commonjs" ? "script" : this.options.sourceType;
  return this.finishNode(node, "Program")
};

var loopLabel = {kind: "loop"}, switchLabel = {kind: "switch"};

pp$8.isLet = function(context) {
  if (this.options.ecmaVersion < 6 || !this.isContextual("let")) { return false }
  skipWhiteSpace.lastIndex = this.pos;
  var skip = skipWhiteSpace.exec(this.input);
  var next = this.pos + skip[0].length, nextCh = this.fullCharCodeAt(next);
  // For ambiguous cases, determine if a LexicalDeclaration (or only a
  // Statement) is allowed here. If context is not empty then only a Statement
  // is allowed. However, `let [` is an explicit negative lookahead for
  // ExpressionStatement, so special-case it first.
  if (nextCh === 91 || nextCh === 92) { return true } // '[', '\'
  if (context) { return false }

  if (nextCh === 123) { return true } // '{'
  if (isIdentifierStart(nextCh)) {
    var start = next;
    do { next += nextCh <= 0xffff ? 1 : 2; }
    while (isIdentifierChar(nextCh = this.fullCharCodeAt(next)))
    if (nextCh === 92) { return true }
    var ident = this.input.slice(start, next);
    if (!keywordRelationalOperator.test(ident)) { return true }
  }
  return false
};

// check 'async [no LineTerminator here] function'
// - 'async /*foo*/ function' is OK.
// - 'async /*\n*/ function' is invalid.
pp$8.isAsyncFunction = function() {
  if (this.options.ecmaVersion < 8 || !this.isContextual("async"))
    { return false }

  skipWhiteSpace.lastIndex = this.pos;
  var skip = skipWhiteSpace.exec(this.input);
  var next = this.pos + skip[0].length, after;
  return !lineBreak.test(this.input.slice(this.pos, next)) &&
    this.input.slice(next, next + 8) === "function" &&
    (next + 8 === this.input.length ||
     !(isIdentifierChar(after = this.fullCharCodeAt(next + 8)) || after === 92 /* '\' */))
};

pp$8.isUsingKeyword = function(isAwaitUsing, isFor) {
  if (this.options.ecmaVersion < 17 || !this.isContextual(isAwaitUsing ? "await" : "using"))
    { return false }

  skipWhiteSpace.lastIndex = this.pos;
  var skip = skipWhiteSpace.exec(this.input);
  var next = this.pos + skip[0].length;

  if (lineBreak.test(this.input.slice(this.pos, next))) { return false }

  if (isAwaitUsing) {
    var usingEndPos = next + 5 /* using */, after;
    if (this.input.slice(next, usingEndPos) !== "using" ||
      usingEndPos === this.input.length ||
      isIdentifierChar(after = this.fullCharCodeAt(usingEndPos)) ||
      after === 92 /* '\' */
    ) { return false }

    skipWhiteSpace.lastIndex = usingEndPos;
    var skipAfterUsing = skipWhiteSpace.exec(this.input);
    next = usingEndPos + skipAfterUsing[0].length;
    if (skipAfterUsing && lineBreak.test(this.input.slice(usingEndPos, next))) { return false }
  }

  var ch = this.fullCharCodeAt(next);
  if (!isIdentifierStart(ch) && ch !== 92 /* '\' */) { return false }
  var idStart = next;
  do { next += ch <= 0xffff ? 1 : 2; }
  while (isIdentifierChar(ch = this.fullCharCodeAt(next)))
  if (ch === 92) { return true }
  var id = this.input.slice(idStart, next);
  if (keywordRelationalOperator.test(id)) { return false }
  if (isFor && !isAwaitUsing && id === "of") {
    // Look ahead for using declaration with initializer, i.e., `for (using of = ...)`
    skipWhiteSpace.lastIndex = next;
    var skipAfterOf = skipWhiteSpace.exec(this.input);
    next = next + skipAfterOf[0].length;
    if (this.input.charCodeAt(next) !== 61 /* '=' */ ||
      // Check for ==, === and => operators
      (ch = this.input.charCodeAt(next + 1)) === 61 /* '=' */ || ch === 62 /* '>' */) {
      return false
    }
  }
  return true
};

pp$8.isAwaitUsing = function(isFor) {
  return this.isUsingKeyword(true, isFor)
};

pp$8.isUsing = function(isFor) {
  return this.isUsingKeyword(false, isFor)
};

// Parse a single statement.
//
// If expecting a statement and finding a slash operator, parse a
// regular expression literal. This is to handle cases like
// `if (foo) /blah/.exec(foo)`, where looking at the previous token
// does not help.

pp$8.parseStatement = function(context, topLevel, exports$1) {
  var starttype = this.type, node = this.startNode(), kind;

  if (this.isLet(context)) {
    starttype = types$1._var;
    kind = "let";
  }

  // Most types of statements are recognized by the keyword they
  // start with. Many are trivial to parse, some require a bit of
  // complexity.

  switch (starttype) {
  case types$1._break: case types$1._continue: return this.parseBreakContinueStatement(node, starttype.keyword)
  case types$1._debugger: return this.parseDebuggerStatement(node)
  case types$1._do: return this.parseDoStatement(node)
  case types$1._for: return this.parseForStatement(node)
  case types$1._function:
    // Function as sole body of either an if statement or a labeled statement
    // works, but not when it is part of a labeled statement that is the sole
    // body of an if statement.
    if ((context && (this.strict || context !== "if" && context !== "label")) && this.options.ecmaVersion >= 6) { this.unexpected(); }
    return this.parseFunctionStatement(node, false, !context)
  case types$1._class:
    if (context) { this.unexpected(); }
    return this.parseClass(node, true)
  case types$1._if: return this.parseIfStatement(node)
  case types$1._return: return this.parseReturnStatement(node)
  case types$1._switch: return this.parseSwitchStatement(node)
  case types$1._throw: return this.parseThrowStatement(node)
  case types$1._try: return this.parseTryStatement(node)
  case types$1._const: case types$1._var:
    kind = kind || this.value;
    if (context && kind !== "var") { this.unexpected(); }
    return this.parseVarStatement(node, kind)
  case types$1._while: return this.parseWhileStatement(node)
  case types$1._with: return this.parseWithStatement(node)
  case types$1.braceL: return this.parseBlock(true, node)
  case types$1.semi: return this.parseEmptyStatement(node)
  case types$1._export:
  case types$1._import:
    if (this.options.ecmaVersion > 10 && starttype === types$1._import) {
      skipWhiteSpace.lastIndex = this.pos;
      var skip = skipWhiteSpace.exec(this.input);
      var next = this.pos + skip[0].length, nextCh = this.input.charCodeAt(next);
      if (nextCh === 40 || nextCh === 46) // '(' or '.'
        { return this.parseExpressionStatement(node, this.parseExpression()) }
    }

    if (!this.options.allowImportExportEverywhere) {
      if (!topLevel)
        { this.raise(this.start, "'import' and 'export' may only appear at the top level"); }
      if (!this.inModule)
        { this.raise(this.start, "'import' and 'export' may appear only with 'sourceType: module'"); }
    }
    return starttype === types$1._import ? this.parseImport(node) : this.parseExport(node, exports$1)

    // If the statement does not start with a statement keyword or a
    // brace, it's an ExpressionStatement or LabeledStatement. We
    // simply start parsing an expression, and afterwards, if the
    // next token is a colon and the expression was a simple
    // Identifier node, we switch to interpreting it as a label.
  default:
    if (this.isAsyncFunction()) {
      if (context) { this.unexpected(); }
      this.next();
      return this.parseFunctionStatement(node, true, !context)
    }

    var usingKind = this.isAwaitUsing(false) ? "await using" : this.isUsing(false) ? "using" : null;
    if (usingKind) {
      if (!this.allowUsing) {
        this.raise(this.start, "Using declaration cannot appear in the top level when source type is `script` or in the bare case statement");
      }
      if (context) {
        // Cases like `for (;;) using x = ...;`, `if (true) await using x = ...;`, etc. are not allowed.
        this.raise(this.start, "Using declaration is not allowed in single-statement positions");
      }
      if (usingKind === "await using") {
        if (!this.canAwait) {
          this.raise(this.start, "Await using cannot appear outside of async function");
        }
        this.next();
      }
      this.next();
      this.parseVar(node, false, usingKind);
      this.semicolon();
      return this.finishNode(node, "VariableDeclaration")
    }

    var maybeName = this.value, expr = this.parseExpression();
    if (starttype === types$1.name && expr.type === "Identifier" && this.eat(types$1.colon))
      { return this.parseLabeledStatement(node, maybeName, expr, context) }
    else { return this.parseExpressionStatement(node, expr) }
  }
};

pp$8.parseBreakContinueStatement = function(node, keyword) {
  var isBreak = keyword === "break";
  this.next();
  if (this.eat(types$1.semi) || this.insertSemicolon()) { node.label = null; }
  else if (this.type !== types$1.name) { this.unexpected(); }
  else {
    node.label = this.parseIdent();
    this.semicolon();
  }

  // Verify that there is an actual destination to break or
  // continue to.
  var i = 0;
  for (; i < this.labels.length; ++i) {
    var lab = this.labels[i];
    if (node.label == null || lab.name === node.label.name) {
      if (lab.kind != null && (isBreak || lab.kind === "loop")) { break }
      if (node.label && isBreak) { break }
    }
  }
  if (i === this.labels.length) { this.raise(node.start, "Unsyntactic " + keyword); }
  return this.finishNode(node, isBreak ? "BreakStatement" : "ContinueStatement")
};

pp$8.parseDebuggerStatement = function(node) {
  this.next();
  this.semicolon();
  return this.finishNode(node, "DebuggerStatement")
};

pp$8.parseDoStatement = function(node) {
  this.next();
  this.labels.push(loopLabel);
  node.body = this.parseStatement("do");
  this.labels.pop();
  this.expect(types$1._while);
  node.test = this.parseParenExpression();
  if (this.options.ecmaVersion >= 6)
    { this.eat(types$1.semi); }
  else
    { this.semicolon(); }
  return this.finishNode(node, "DoWhileStatement")
};

// Disambiguating between a `for` and a `for`/`in` or `for`/`of`
// loop is non-trivial. Basically, we have to parse the init `var`
// statement or expression, disallowing the `in` operator (see
// the second parameter to `parseExpression`), and then check
// whether the next token is `in` or `of`. When there is no init
// part (semicolon immediately after the opening parenthesis), it
// is a regular `for` loop.

pp$8.parseForStatement = function(node) {
  this.next();
  var awaitAt = (this.options.ecmaVersion >= 9 && this.canAwait && this.eatContextual("await")) ? this.lastTokStart : -1;
  this.labels.push(loopLabel);
  this.enterScope(0);
  this.expect(types$1.parenL);
  if (this.type === types$1.semi) {
    if (awaitAt > -1) { this.unexpected(awaitAt); }
    return this.parseFor(node, null)
  }
  var isLet = this.isLet();
  if (this.type === types$1._var || this.type === types$1._const || isLet) {
    var init$1 = this.startNode(), kind = isLet ? "let" : this.value;
    this.next();
    this.parseVar(init$1, true, kind);
    this.finishNode(init$1, "VariableDeclaration");
    return this.parseForAfterInit(node, init$1, awaitAt)
  }
  var startsWithLet = this.isContextual("let"), isForOf = false;

  var usingKind = this.isUsing(true) ? "using" : this.isAwaitUsing(true) ? "await using" : null;
  if (usingKind) {
    var init$2 = this.startNode();
    this.next();
    if (usingKind === "await using") {
      if (!this.canAwait) {
        this.raise(this.start, "Await using cannot appear outside of async function");
      }
      this.next();
    }
    this.parseVar(init$2, true, usingKind);
    this.finishNode(init$2, "VariableDeclaration");
    return this.parseForAfterInit(node, init$2, awaitAt)
  }
  var containsEsc = this.containsEsc;
  var refDestructuringErrors = new DestructuringErrors;
  var initPos = this.start;
  var init = awaitAt > -1
    ? this.parseExprSubscripts(refDestructuringErrors, "await")
    : this.parseExpression(true, refDestructuringErrors);
  if (this.type === types$1._in || (isForOf = this.options.ecmaVersion >= 6 && this.isContextual("of"))) {
    if (awaitAt > -1) { // implies `ecmaVersion >= 9` (see declaration of awaitAt)
      if (this.type === types$1._in) { this.unexpected(awaitAt); }
      node.await = true;
    } else if (isForOf && this.options.ecmaVersion >= 8) {
      if (init.start === initPos && !containsEsc && init.type === "Identifier" && init.name === "async") { this.unexpected(); }
      else if (this.options.ecmaVersion >= 9) { node.await = false; }
    }
    if (startsWithLet && isForOf) { this.raise(init.start, "The left-hand side of a for-of loop may not start with 'let'."); }
    this.toAssignable(init, false, refDestructuringErrors);
    this.checkLValPattern(init);
    return this.parseForIn(node, init)
  } else {
    this.checkExpressionErrors(refDestructuringErrors, true);
  }
  if (awaitAt > -1) { this.unexpected(awaitAt); }
  return this.parseFor(node, init)
};

// Helper method to parse for loop after variable initialization
pp$8.parseForAfterInit = function(node, init, awaitAt) {
  if ((this.type === types$1._in || (this.options.ecmaVersion >= 6 && this.isContextual("of"))) && init.declarations.length === 1) {
    if (this.type === types$1._in) {
      if ((init.kind === "using" || init.kind === "await using") && !init.declarations[0].init) {
        this.raise(this.start, "Using declaration is not allowed in for-in loops");
      }
      if (this.options.ecmaVersion >= 9 && awaitAt > -1) { this.unexpected(awaitAt); }
    } else if (this.options.ecmaVersion >= 9) { node.await = awaitAt > -1; }
    return this.parseForIn(node, init)
  }
  if (awaitAt > -1) { this.unexpected(awaitAt); }
  return this.parseFor(node, init)
};

pp$8.parseFunctionStatement = function(node, isAsync, declarationPosition) {
  this.next();
  return this.parseFunction(node, FUNC_STATEMENT | (declarationPosition ? 0 : FUNC_HANGING_STATEMENT), false, isAsync)
};

pp$8.parseIfStatement = function(node) {
  this.next();
  node.test = this.parseParenExpression();
  // allow function declarations in branches, but only in non-strict mode
  node.consequent = this.parseStatement("if");
  node.alternate = this.eat(types$1._else) ? this.parseStatement("if") : null;
  return this.finishNode(node, "IfStatement")
};

pp$8.parseReturnStatement = function(node) {
  if (!this.allowReturn)
    { this.raise(this.start, "'return' outside of function"); }
  this.next();

  // In `return` (and `break`/`continue`), the keywords with
  // optional arguments, we eagerly look for a semicolon or the
  // possibility to insert one.

  if (this.eat(types$1.semi) || this.insertSemicolon()) { node.argument = null; }
  else { node.argument = this.parseExpression(); this.semicolon(); }
  return this.finishNode(node, "ReturnStatement")
};

pp$8.parseSwitchStatement = function(node) {
  this.next();
  node.discriminant = this.parseParenExpression();
  node.cases = [];
  this.expect(types$1.braceL);
  this.labels.push(switchLabel);
  this.enterScope(SCOPE_SWITCH);

  // Statements under must be grouped (by label) in SwitchCase
  // nodes. `cur` is used to keep the node that we are currently
  // adding statements to.

  var cur;
  for (var sawDefault = false; this.type !== types$1.braceR;) {
    if (this.type === types$1._case || this.type === types$1._default) {
      var isCase = this.type === types$1._case;
      if (cur) { this.finishNode(cur, "SwitchCase"); }
      node.cases.push(cur = this.startNode());
      cur.consequent = [];
      this.next();
      if (isCase) {
        cur.test = this.parseExpression();
      } else {
        if (sawDefault) { this.raiseRecoverable(this.lastTokStart, "Multiple default clauses"); }
        sawDefault = true;
        cur.test = null;
      }
      this.expect(types$1.colon);
    } else {
      if (!cur) { this.unexpected(); }
      cur.consequent.push(this.parseStatement(null));
    }
  }
  this.exitScope();
  if (cur) { this.finishNode(cur, "SwitchCase"); }
  this.next(); // Closing brace
  this.labels.pop();
  return this.finishNode(node, "SwitchStatement")
};

pp$8.parseThrowStatement = function(node) {
  this.next();
  if (lineBreak.test(this.input.slice(this.lastTokEnd, this.start)))
    { this.raise(this.lastTokEnd, "Illegal newline after throw"); }
  node.argument = this.parseExpression();
  this.semicolon();
  return this.finishNode(node, "ThrowStatement")
};

// Reused empty array added for node fields that are always empty.

var empty$1 = [];

pp$8.parseCatchClauseParam = function() {
  var param = this.parseBindingAtom();
  var simple = param.type === "Identifier";
  this.enterScope(simple ? SCOPE_SIMPLE_CATCH : 0);
  this.checkLValPattern(param, simple ? BIND_SIMPLE_CATCH : BIND_LEXICAL);
  this.expect(types$1.parenR);

  return param
};

pp$8.parseTryStatement = function(node) {
  this.next();
  node.block = this.parseBlock();
  node.handler = null;
  if (this.type === types$1._catch) {
    var clause = this.startNode();
    this.next();
    if (this.eat(types$1.parenL)) {
      clause.param = this.parseCatchClauseParam();
    } else {
      if (this.options.ecmaVersion < 10) { this.unexpected(); }
      clause.param = null;
      this.enterScope(0);
    }
    clause.body = this.parseBlock(false);
    this.exitScope();
    node.handler = this.finishNode(clause, "CatchClause");
  }
  node.finalizer = this.eat(types$1._finally) ? this.parseBlock() : null;
  if (!node.handler && !node.finalizer)
    { this.raise(node.start, "Missing catch or finally clause"); }
  return this.finishNode(node, "TryStatement")
};

pp$8.parseVarStatement = function(node, kind, allowMissingInitializer) {
  this.next();
  this.parseVar(node, false, kind, allowMissingInitializer);
  this.semicolon();
  return this.finishNode(node, "VariableDeclaration")
};

pp$8.parseWhileStatement = function(node) {
  this.next();
  node.test = this.parseParenExpression();
  this.labels.push(loopLabel);
  node.body = this.parseStatement("while");
  this.labels.pop();
  return this.finishNode(node, "WhileStatement")
};

pp$8.parseWithStatement = function(node) {
  if (this.strict) { this.raise(this.start, "'with' in strict mode"); }
  this.next();
  node.object = this.parseParenExpression();
  node.body = this.parseStatement("with");
  return this.finishNode(node, "WithStatement")
};

pp$8.parseEmptyStatement = function(node) {
  this.next();
  return this.finishNode(node, "EmptyStatement")
};

pp$8.parseLabeledStatement = function(node, maybeName, expr, context) {
  for (var i$1 = 0, list = this.labels; i$1 < list.length; i$1 += 1)
    {
    var label = list[i$1];

    if (label.name === maybeName)
      { this.raise(expr.start, "Label '" + maybeName + "' is already declared");
  } }
  var kind = this.type.isLoop ? "loop" : this.type === types$1._switch ? "switch" : null;
  for (var i = this.labels.length - 1; i >= 0; i--) {
    var label$1 = this.labels[i];
    if (label$1.statementStart === node.start) {
      // Update information about previous labels on this node
      label$1.statementStart = this.start;
      label$1.kind = kind;
    } else { break }
  }
  this.labels.push({name: maybeName, kind: kind, statementStart: this.start});
  node.body = this.parseStatement(context ? context.indexOf("label") === -1 ? context + "label" : context : "label");
  this.labels.pop();
  node.label = expr;
  return this.finishNode(node, "LabeledStatement")
};

pp$8.parseExpressionStatement = function(node, expr) {
  node.expression = expr;
  this.semicolon();
  return this.finishNode(node, "ExpressionStatement")
};

// Parse a semicolon-enclosed block of statements, handling `"use
// strict"` declarations when `allowStrict` is true (used for
// function bodies).

pp$8.parseBlock = function(createNewLexicalScope, node, exitStrict) {
  if ( createNewLexicalScope === void 0 ) createNewLexicalScope = true;
  if ( node === void 0 ) node = this.startNode();

  node.body = [];
  this.expect(types$1.braceL);
  if (createNewLexicalScope) { this.enterScope(0); }
  while (this.type !== types$1.braceR) {
    var stmt = this.parseStatement(null);
    node.body.push(stmt);
  }
  if (exitStrict) { this.strict = false; }
  this.next();
  if (createNewLexicalScope) { this.exitScope(); }
  return this.finishNode(node, "BlockStatement")
};

// Parse a regular `for` loop. The disambiguation code in
// `parseStatement` will already have parsed the init statement or
// expression.

pp$8.parseFor = function(node, init) {
  node.init = init;
  this.expect(types$1.semi);
  node.test = this.type === types$1.semi ? null : this.parseExpression();
  this.expect(types$1.semi);
  node.update = this.type === types$1.parenR ? null : this.parseExpression();
  this.expect(types$1.parenR);
  node.body = this.parseStatement("for");
  this.exitScope();
  this.labels.pop();
  return this.finishNode(node, "ForStatement")
};

// Parse a `for`/`in` and `for`/`of` loop, which are almost
// same from parser's perspective.

pp$8.parseForIn = function(node, init) {
  var isForIn = this.type === types$1._in;
  this.next();

  if (
    init.type === "VariableDeclaration" &&
    init.declarations[0].init != null &&
    (
      !isForIn ||
      this.options.ecmaVersion < 8 ||
      this.strict ||
      init.kind !== "var" ||
      init.declarations[0].id.type !== "Identifier"
    )
  ) {
    this.raise(
      init.start,
      ((isForIn ? "for-in" : "for-of") + " loop variable declaration may not have an initializer")
    );
  }
  node.left = init;
  node.right = isForIn ? this.parseExpression() : this.parseMaybeAssign();
  this.expect(types$1.parenR);
  node.body = this.parseStatement("for");
  this.exitScope();
  this.labels.pop();
  return this.finishNode(node, isForIn ? "ForInStatement" : "ForOfStatement")
};

// Parse a list of variable declarations.

pp$8.parseVar = function(node, isFor, kind, allowMissingInitializer) {
  node.declarations = [];
  node.kind = kind;
  for (;;) {
    var decl = this.startNode();
    this.parseVarId(decl, kind);
    if (this.eat(types$1.eq)) {
      decl.init = this.parseMaybeAssign(isFor);
    } else if (!allowMissingInitializer && kind === "const" && !(this.type === types$1._in || (this.options.ecmaVersion >= 6 && this.isContextual("of")))) {
      this.unexpected();
    } else if (!allowMissingInitializer && (kind === "using" || kind === "await using") && this.options.ecmaVersion >= 17 && this.type !== types$1._in && !this.isContextual("of")) {
      this.raise(this.lastTokEnd, ("Missing initializer in " + kind + " declaration"));
    } else if (!allowMissingInitializer && decl.id.type !== "Identifier" && !(isFor && (this.type === types$1._in || this.isContextual("of")))) {
      this.raise(this.lastTokEnd, "Complex binding patterns require an initialization value");
    } else {
      decl.init = null;
    }
    node.declarations.push(this.finishNode(decl, "VariableDeclarator"));
    if (!this.eat(types$1.comma)) { break }
  }
  return node
};

pp$8.parseVarId = function(decl, kind) {
  decl.id = kind === "using" || kind === "await using"
    ? this.parseIdent()
    : this.parseBindingAtom();

  this.checkLValPattern(decl.id, kind === "var" ? BIND_VAR : BIND_LEXICAL, false);
};

var FUNC_STATEMENT = 1, FUNC_HANGING_STATEMENT = 2, FUNC_NULLABLE_ID = 4;

// Parse a function declaration or literal (depending on the
// `statement & FUNC_STATEMENT`).

// Remove `allowExpressionBody` for 7.0.0, as it is only called with false
pp$8.parseFunction = function(node, statement, allowExpressionBody, isAsync, forInit) {
  this.initFunction(node);
  if (this.options.ecmaVersion >= 9 || this.options.ecmaVersion >= 6 && !isAsync) {
    if (this.type === types$1.star && (statement & FUNC_HANGING_STATEMENT))
      { this.unexpected(); }
    node.generator = this.eat(types$1.star);
  }
  if (this.options.ecmaVersion >= 8)
    { node.async = !!isAsync; }

  if (statement & FUNC_STATEMENT) {
    node.id = (statement & FUNC_NULLABLE_ID) && this.type !== types$1.name ? null : this.parseIdent();
    if (node.id && !(statement & FUNC_HANGING_STATEMENT))
      // If it is a regular function declaration in sloppy mode, then it is
      // subject to Annex B semantics (BIND_FUNCTION). Otherwise, the binding
      // mode depends on properties of the current scope (see
      // treatFunctionsAsVar).
      { this.checkLValSimple(node.id, (this.strict || node.generator || node.async) ? this.treatFunctionsAsVar ? BIND_VAR : BIND_LEXICAL : BIND_FUNCTION); }
  }

  var oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, oldAwaitIdentPos = this.awaitIdentPos;
  this.yieldPos = 0;
  this.awaitPos = 0;
  this.awaitIdentPos = 0;
  this.enterScope(functionFlags(node.async, node.generator));

  if (!(statement & FUNC_STATEMENT))
    { node.id = this.type === types$1.name ? this.parseIdent() : null; }

  this.parseFunctionParams(node);
  this.parseFunctionBody(node, allowExpressionBody, false, forInit);

  this.yieldPos = oldYieldPos;
  this.awaitPos = oldAwaitPos;
  this.awaitIdentPos = oldAwaitIdentPos;
  return this.finishNode(node, (statement & FUNC_STATEMENT) ? "FunctionDeclaration" : "FunctionExpression")
};

pp$8.parseFunctionParams = function(node) {
  this.expect(types$1.parenL);
  node.params = this.parseBindingList(types$1.parenR, false, this.options.ecmaVersion >= 8);
  this.checkYieldAwaitInDefaultParams();
};

// Parse a class declaration or literal (depending on the
// `isStatement` parameter).

pp$8.parseClass = function(node, isStatement) {
  this.next();

  // ecma-262 14.6 Class Definitions
  // A class definition is always strict mode code.
  var oldStrict = this.strict;
  this.strict = true;

  this.parseClassId(node, isStatement);
  this.parseClassSuper(node);
  var privateNameMap = this.enterClassBody();
  var classBody = this.startNode();
  var hadConstructor = false;
  classBody.body = [];
  this.expect(types$1.braceL);
  while (this.type !== types$1.braceR) {
    var element = this.parseClassElement(node.superClass !== null);
    if (element) {
      classBody.body.push(element);
      if (element.type === "MethodDefinition" && element.kind === "constructor") {
        if (hadConstructor) { this.raiseRecoverable(element.start, "Duplicate constructor in the same class"); }
        hadConstructor = true;
      } else if (element.key && element.key.type === "PrivateIdentifier" && isPrivateNameConflicted(privateNameMap, element)) {
        this.raiseRecoverable(element.key.start, ("Identifier '#" + (element.key.name) + "' has already been declared"));
      }
    }
  }
  this.strict = oldStrict;
  this.next();
  node.body = this.finishNode(classBody, "ClassBody");
  this.exitClassBody();
  return this.finishNode(node, isStatement ? "ClassDeclaration" : "ClassExpression")
};

pp$8.parseClassElement = function(constructorAllowsSuper) {
  if (this.eat(types$1.semi)) { return null }

  var ecmaVersion = this.options.ecmaVersion;
  var node = this.startNode();
  var keyName = "";
  var isGenerator = false;
  var isAsync = false;
  var kind = "method";
  var isStatic = false;

  if (this.eatContextual("static")) {
    // Parse static init block
    if (ecmaVersion >= 13 && this.eat(types$1.braceL)) {
      this.parseClassStaticBlock(node);
      return node
    }
    if (this.isClassElementNameStart() || this.type === types$1.star) {
      isStatic = true;
    } else {
      keyName = "static";
    }
  }
  node.static = isStatic;
  if (!keyName && ecmaVersion >= 8 && this.eatContextual("async")) {
    if ((this.isClassElementNameStart() || this.type === types$1.star) && !this.canInsertSemicolon()) {
      isAsync = true;
    } else {
      keyName = "async";
    }
  }
  if (!keyName && (ecmaVersion >= 9 || !isAsync) && this.eat(types$1.star)) {
    isGenerator = true;
  }
  if (!keyName && !isAsync && !isGenerator) {
    var lastValue = this.value;
    if (this.eatContextual("get") || this.eatContextual("set")) {
      if (this.isClassElementNameStart()) {
        kind = lastValue;
      } else {
        keyName = lastValue;
      }
    }
  }

  // Parse element name
  if (keyName) {
    // 'async', 'get', 'set', or 'static' were not a keyword contextually.
    // The last token is any of those. Make it the element name.
    node.computed = false;
    node.key = this.startNodeAt(this.lastTokStart, this.lastTokStartLoc);
    node.key.name = keyName;
    this.finishNode(node.key, "Identifier");
  } else {
    this.parseClassElementName(node);
  }

  // Parse element value
  if (ecmaVersion < 13 || this.type === types$1.parenL || kind !== "method" || isGenerator || isAsync) {
    var isConstructor = !node.static && checkKeyName(node, "constructor");
    var allowsDirectSuper = isConstructor && constructorAllowsSuper;
    // Couldn't move this check into the 'parseClassMethod' method for backward compatibility.
    if (isConstructor && kind !== "method") { this.raise(node.key.start, "Constructor can't have get/set modifier"); }
    node.kind = isConstructor ? "constructor" : kind;
    this.parseClassMethod(node, isGenerator, isAsync, allowsDirectSuper);
  } else {
    this.parseClassField(node);
  }

  return node
};

pp$8.isClassElementNameStart = function() {
  return (
    this.type === types$1.name ||
    this.type === types$1.privateId ||
    this.type === types$1.num ||
    this.type === types$1.string ||
    this.type === types$1.bracketL ||
    this.type.keyword
  )
};

pp$8.parseClassElementName = function(element) {
  if (this.type === types$1.privateId) {
    if (this.value === "constructor") {
      this.raise(this.start, "Classes can't have an element named '#constructor'");
    }
    element.computed = false;
    element.key = this.parsePrivateIdent();
  } else {
    this.parsePropertyName(element);
  }
};

pp$8.parseClassMethod = function(method, isGenerator, isAsync, allowsDirectSuper) {
  // Check key and flags
  var key = method.key;
  if (method.kind === "constructor") {
    if (isGenerator) { this.raise(key.start, "Constructor can't be a generator"); }
    if (isAsync) { this.raise(key.start, "Constructor can't be an async method"); }
  } else if (method.static && checkKeyName(method, "prototype")) {
    this.raise(key.start, "Classes may not have a static property named prototype");
  }

  // Parse value
  var value = method.value = this.parseMethod(isGenerator, isAsync, allowsDirectSuper);

  // Check value
  if (method.kind === "get" && value.params.length !== 0)
    { this.raiseRecoverable(value.start, "getter should have no params"); }
  if (method.kind === "set" && value.params.length !== 1)
    { this.raiseRecoverable(value.start, "setter should have exactly one param"); }
  if (method.kind === "set" && value.params[0].type === "RestElement")
    { this.raiseRecoverable(value.params[0].start, "Setter cannot use rest params"); }

  return this.finishNode(method, "MethodDefinition")
};

pp$8.parseClassField = function(field) {
  if (checkKeyName(field, "constructor")) {
    this.raise(field.key.start, "Classes can't have a field named 'constructor'");
  } else if (field.static && checkKeyName(field, "prototype")) {
    this.raise(field.key.start, "Classes can't have a static field named 'prototype'");
  }

  if (this.eat(types$1.eq)) {
    // To raise SyntaxError if 'arguments' exists in the initializer.
    this.enterScope(SCOPE_CLASS_FIELD_INIT | SCOPE_SUPER);
    field.value = this.parseMaybeAssign();
    this.exitScope();
  } else {
    field.value = null;
  }
  this.semicolon();

  return this.finishNode(field, "PropertyDefinition")
};

pp$8.parseClassStaticBlock = function(node) {
  node.body = [];

  var oldLabels = this.labels;
  this.labels = [];
  this.enterScope(SCOPE_CLASS_STATIC_BLOCK | SCOPE_SUPER);
  while (this.type !== types$1.braceR) {
    var stmt = this.parseStatement(null);
    node.body.push(stmt);
  }
  this.next();
  this.exitScope();
  this.labels = oldLabels;

  return this.finishNode(node, "StaticBlock")
};

pp$8.parseClassId = function(node, isStatement) {
  if (this.type === types$1.name) {
    node.id = this.parseIdent();
    if (isStatement)
      { this.checkLValSimple(node.id, BIND_LEXICAL, false); }
  } else {
    if (isStatement === true)
      { this.unexpected(); }
    node.id = null;
  }
};

pp$8.parseClassSuper = function(node) {
  node.superClass = this.eat(types$1._extends) ? this.parseExprSubscripts(null, false) : null;
};

pp$8.enterClassBody = function() {
  var element = {declared: Object.create(null), used: []};
  this.privateNameStack.push(element);
  return element.declared
};

pp$8.exitClassBody = function() {
  var ref = this.privateNameStack.pop();
  var declared = ref.declared;
  var used = ref.used;
  if (!this.options.checkPrivateFields) { return }
  var len = this.privateNameStack.length;
  var parent = len === 0 ? null : this.privateNameStack[len - 1];
  for (var i = 0; i < used.length; ++i) {
    var id = used[i];
    if (!hasOwn(declared, id.name)) {
      if (parent) {
        parent.used.push(id);
      } else {
        this.raiseRecoverable(id.start, ("Private field '#" + (id.name) + "' must be declared in an enclosing class"));
      }
    }
  }
};

function isPrivateNameConflicted(privateNameMap, element) {
  var name = element.key.name;
  var curr = privateNameMap[name];

  var next = "true";
  if (element.type === "MethodDefinition" && (element.kind === "get" || element.kind === "set")) {
    next = (element.static ? "s" : "i") + element.kind;
  }

  // `class { get #a(){}; static set #a(_){} }` is also conflict.
  if (
    curr === "iget" && next === "iset" ||
    curr === "iset" && next === "iget" ||
    curr === "sget" && next === "sset" ||
    curr === "sset" && next === "sget"
  ) {
    privateNameMap[name] = "true";
    return false
  } else if (!curr) {
    privateNameMap[name] = next;
    return false
  } else {
    return true
  }
}

function checkKeyName(node, name) {
  var computed = node.computed;
  var key = node.key;
  return !computed && (
    key.type === "Identifier" && key.name === name ||
    key.type === "Literal" && key.value === name
  )
}

// Parses module export declaration.

pp$8.parseExportAllDeclaration = function(node, exports$1) {
  if (this.options.ecmaVersion >= 11) {
    if (this.eatContextual("as")) {
      node.exported = this.parseModuleExportName();
      this.checkExport(exports$1, node.exported, this.lastTokStart);
    } else {
      node.exported = null;
    }
  }
  this.expectContextual("from");
  if (this.type !== types$1.string) { this.unexpected(); }
  node.source = this.parseExprAtom();
  if (this.options.ecmaVersion >= 16)
    { node.attributes = this.parseWithClause(); }
  this.semicolon();
  return this.finishNode(node, "ExportAllDeclaration")
};

pp$8.parseExport = function(node, exports$1) {
  this.next();
  // export * from '...'
  if (this.eat(types$1.star)) {
    return this.parseExportAllDeclaration(node, exports$1)
  }
  if (this.eat(types$1._default)) { // export default ...
    this.checkExport(exports$1, "default", this.lastTokStart);
    node.declaration = this.parseExportDefaultDeclaration();
    return this.finishNode(node, "ExportDefaultDeclaration")
  }
  // export var|const|let|function|class ...
  if (this.shouldParseExportStatement()) {
    node.declaration = this.parseExportDeclaration(node);
    if (node.declaration.type === "VariableDeclaration")
      { this.checkVariableExport(exports$1, node.declaration.declarations); }
    else
      { this.checkExport(exports$1, node.declaration.id, node.declaration.id.start); }
    node.specifiers = [];
    node.source = null;
    if (this.options.ecmaVersion >= 16)
      { node.attributes = []; }
  } else { // export { x, y as z } [from '...']
    node.declaration = null;
    node.specifiers = this.parseExportSpecifiers(exports$1);
    if (this.eatContextual("from")) {
      if (this.type !== types$1.string) { this.unexpected(); }
      node.source = this.parseExprAtom();
      if (this.options.ecmaVersion >= 16)
        { node.attributes = this.parseWithClause(); }
    } else {
      for (var i = 0, list = node.specifiers; i < list.length; i += 1) {
        // check for keywords used as local names
        var spec = list[i];

        this.checkUnreserved(spec.local);
        // check if export is defined
        this.checkLocalExport(spec.local);

        if (spec.local.type === "Literal") {
          this.raise(spec.local.start, "A string literal cannot be used as an exported binding without `from`.");
        }
      }

      node.source = null;
      if (this.options.ecmaVersion >= 16)
        { node.attributes = []; }
    }
    this.semicolon();
  }
  return this.finishNode(node, "ExportNamedDeclaration")
};

pp$8.parseExportDeclaration = function(node) {
  return this.parseStatement(null)
};

pp$8.parseExportDefaultDeclaration = function() {
  var isAsync;
  if (this.type === types$1._function || (isAsync = this.isAsyncFunction())) {
    var fNode = this.startNode();
    this.next();
    if (isAsync) { this.next(); }
    return this.parseFunction(fNode, FUNC_STATEMENT | FUNC_NULLABLE_ID, false, isAsync)
  } else if (this.type === types$1._class) {
    var cNode = this.startNode();
    return this.parseClass(cNode, "nullableID")
  } else {
    var declaration = this.parseMaybeAssign();
    this.semicolon();
    return declaration
  }
};

pp$8.checkExport = function(exports$1, name, pos) {
  if (!exports$1) { return }
  if (typeof name !== "string")
    { name = name.type === "Identifier" ? name.name : name.value; }
  if (hasOwn(exports$1, name))
    { this.raiseRecoverable(pos, "Duplicate export '" + name + "'"); }
  exports$1[name] = true;
};

pp$8.checkPatternExport = function(exports$1, pat) {
  var type = pat.type;
  if (type === "Identifier")
    { this.checkExport(exports$1, pat, pat.start); }
  else if (type === "ObjectPattern")
    { for (var i = 0, list = pat.properties; i < list.length; i += 1)
      {
        var prop = list[i];

        this.checkPatternExport(exports$1, prop);
      } }
  else if (type === "ArrayPattern")
    { for (var i$1 = 0, list$1 = pat.elements; i$1 < list$1.length; i$1 += 1) {
      var elt = list$1[i$1];

        if (elt) { this.checkPatternExport(exports$1, elt); }
    } }
  else if (type === "Property")
    { this.checkPatternExport(exports$1, pat.value); }
  else if (type === "AssignmentPattern")
    { this.checkPatternExport(exports$1, pat.left); }
  else if (type === "RestElement")
    { this.checkPatternExport(exports$1, pat.argument); }
};

pp$8.checkVariableExport = function(exports$1, decls) {
  if (!exports$1) { return }
  for (var i = 0, list = decls; i < list.length; i += 1)
    {
    var decl = list[i];

    this.checkPatternExport(exports$1, decl.id);
  }
};

pp$8.shouldParseExportStatement = function() {
  return this.type.keyword === "var" ||
    this.type.keyword === "const" ||
    this.type.keyword === "class" ||
    this.type.keyword === "function" ||
    this.isLet() ||
    this.isAsyncFunction()
};

// Parses a comma-separated list of module exports.

pp$8.parseExportSpecifier = function(exports$1) {
  var node = this.startNode();
  node.local = this.parseModuleExportName();

  node.exported = this.eatContextual("as") ? this.parseModuleExportName() : node.local;
  this.checkExport(
    exports$1,
    node.exported,
    node.exported.start
  );

  return this.finishNode(node, "ExportSpecifier")
};

pp$8.parseExportSpecifiers = function(exports$1) {
  var nodes = [], first = true;
  // export { x, y as z } [from '...']
  this.expect(types$1.braceL);
  while (!this.eat(types$1.braceR)) {
    if (!first) {
      this.expect(types$1.comma);
      if (this.afterTrailingComma(types$1.braceR)) { break }
    } else { first = false; }

    nodes.push(this.parseExportSpecifier(exports$1));
  }
  return nodes
};

// Parses import declaration.

pp$8.parseImport = function(node) {
  this.next();

  // import '...'
  if (this.type === types$1.string) {
    node.specifiers = empty$1;
    node.source = this.parseExprAtom();
  } else {
    node.specifiers = this.parseImportSpecifiers();
    this.expectContextual("from");
    node.source = this.type === types$1.string ? this.parseExprAtom() : this.unexpected();
  }
  if (this.options.ecmaVersion >= 16)
    { node.attributes = this.parseWithClause(); }
  this.semicolon();
  return this.finishNode(node, "ImportDeclaration")
};

// Parses a comma-separated list of module imports.

pp$8.parseImportSpecifier = function() {
  var node = this.startNode();
  node.imported = this.parseModuleExportName();

  if (this.eatContextual("as")) {
    node.local = this.parseIdent();
  } else {
    this.checkUnreserved(node.imported);
    node.local = node.imported;
  }
  this.checkLValSimple(node.local, BIND_LEXICAL);

  return this.finishNode(node, "ImportSpecifier")
};

pp$8.parseImportDefaultSpecifier = function() {
  // import defaultObj, { x, y as z } from '...'
  var node = this.startNode();
  node.local = this.parseIdent();
  this.checkLValSimple(node.local, BIND_LEXICAL);
  return this.finishNode(node, "ImportDefaultSpecifier")
};

pp$8.parseImportNamespaceSpecifier = function() {
  var node = this.startNode();
  this.next();
  this.expectContextual("as");
  node.local = this.parseIdent();
  this.checkLValSimple(node.local, BIND_LEXICAL);
  return this.finishNode(node, "ImportNamespaceSpecifier")
};

pp$8.parseImportSpecifiers = function() {
  var nodes = [], first = true;
  if (this.type === types$1.name) {
    nodes.push(this.parseImportDefaultSpecifier());
    if (!this.eat(types$1.comma)) { return nodes }
  }
  if (this.type === types$1.star) {
    nodes.push(this.parseImportNamespaceSpecifier());
    return nodes
  }
  this.expect(types$1.braceL);
  while (!this.eat(types$1.braceR)) {
    if (!first) {
      this.expect(types$1.comma);
      if (this.afterTrailingComma(types$1.braceR)) { break }
    } else { first = false; }

    nodes.push(this.parseImportSpecifier());
  }
  return nodes
};

pp$8.parseWithClause = function() {
  var nodes = [];
  if (!this.eat(types$1._with)) {
    return nodes
  }
  this.expect(types$1.braceL);
  var attributeKeys = {};
  var first = true;
  while (!this.eat(types$1.braceR)) {
    if (!first) {
      this.expect(types$1.comma);
      if (this.afterTrailingComma(types$1.braceR)) { break }
    } else { first = false; }

    var attr = this.parseImportAttribute();
    var keyName = attr.key.type === "Identifier" ? attr.key.name : attr.key.value;
    if (hasOwn(attributeKeys, keyName))
      { this.raiseRecoverable(attr.key.start, "Duplicate attribute key '" + keyName + "'"); }
    attributeKeys[keyName] = true;
    nodes.push(attr);
  }
  return nodes
};

pp$8.parseImportAttribute = function() {
  var node = this.startNode();
  node.key = this.type === types$1.string ? this.parseExprAtom() : this.parseIdent(this.options.allowReserved !== "never");
  this.expect(types$1.colon);
  if (this.type !== types$1.string) {
    this.unexpected();
  }
  node.value = this.parseExprAtom();
  return this.finishNode(node, "ImportAttribute")
};

pp$8.parseModuleExportName = function() {
  if (this.options.ecmaVersion >= 13 && this.type === types$1.string) {
    var stringLiteral = this.parseLiteral(this.value);
    if (loneSurrogate.test(stringLiteral.value)) {
      this.raise(stringLiteral.start, "An export name cannot include a lone surrogate.");
    }
    return stringLiteral
  }
  return this.parseIdent(true)
};

// Set `ExpressionStatement#directive` property for directive prologues.
pp$8.adaptDirectivePrologue = function(statements) {
  for (var i = 0; i < statements.length && this.isDirectiveCandidate(statements[i]); ++i) {
    statements[i].directive = statements[i].expression.raw.slice(1, -1);
  }
};
pp$8.isDirectiveCandidate = function(statement) {
  return (
    this.options.ecmaVersion >= 5 &&
    statement.type === "ExpressionStatement" &&
    statement.expression.type === "Literal" &&
    typeof statement.expression.value === "string" &&
    // Reject parenthesized strings.
    (this.input[statement.start] === "\"" || this.input[statement.start] === "'")
  )
};

var pp$7 = Parser.prototype;

// Convert existing expression atom to assignable pattern
// if possible.

pp$7.toAssignable = function(node, isBinding, refDestructuringErrors) {
  if (this.options.ecmaVersion >= 6 && node) {
    switch (node.type) {
    case "Identifier":
      if (this.inAsync && node.name === "await")
        { this.raise(node.start, "Cannot use 'await' as identifier inside an async function"); }
      break

    case "ObjectPattern":
    case "ArrayPattern":
    case "AssignmentPattern":
    case "RestElement":
      break

    case "ObjectExpression":
      node.type = "ObjectPattern";
      if (refDestructuringErrors) { this.checkPatternErrors(refDestructuringErrors, true); }
      for (var i = 0, list = node.properties; i < list.length; i += 1) {
        var prop = list[i];

      this.toAssignable(prop, isBinding);
        // Early error:
        //   AssignmentRestProperty[Yield, Await] :
        //     `...` DestructuringAssignmentTarget[Yield, Await]
        //
        //   It is a Syntax Error if |DestructuringAssignmentTarget| is an |ArrayLiteral| or an |ObjectLiteral|.
        if (
          prop.type === "RestElement" &&
          (prop.argument.type === "ArrayPattern" || prop.argument.type === "ObjectPattern")
        ) {
          this.raise(prop.argument.start, "Unexpected token");
        }
      }
      break

    case "Property":
      // AssignmentProperty has type === "Property"
      if (node.kind !== "init") { this.raise(node.key.start, "Object pattern can't contain getter or setter"); }
      this.toAssignable(node.value, isBinding);
      break

    case "ArrayExpression":
      node.type = "ArrayPattern";
      if (refDestructuringErrors) { this.checkPatternErrors(refDestructuringErrors, true); }
      this.toAssignableList(node.elements, isBinding);
      break

    case "SpreadElement":
      node.type = "RestElement";
      this.toAssignable(node.argument, isBinding);
      if (node.argument.type === "AssignmentPattern")
        { this.raise(node.argument.start, "Rest elements cannot have a default value"); }
      break

    case "AssignmentExpression":
      if (node.operator !== "=") { this.raise(node.left.end, "Only '=' operator can be used for specifying default value."); }
      node.type = "AssignmentPattern";
      delete node.operator;
      this.toAssignable(node.left, isBinding);
      break

    case "ParenthesizedExpression":
      this.toAssignable(node.expression, isBinding, refDestructuringErrors);
      break

    case "ChainExpression":
      this.raiseRecoverable(node.start, "Optional chaining cannot appear in left-hand side");
      break

    case "MemberExpression":
      if (!isBinding) { break }

    default:
      this.raise(node.start, "Assigning to rvalue");
    }
  } else if (refDestructuringErrors) { this.checkPatternErrors(refDestructuringErrors, true); }
  return node
};

// Convert list of expression atoms to binding list.

pp$7.toAssignableList = function(exprList, isBinding) {
  var end = exprList.length;
  for (var i = 0; i < end; i++) {
    var elt = exprList[i];
    if (elt) { this.toAssignable(elt, isBinding); }
  }
  if (end) {
    var last = exprList[end - 1];
    if (this.options.ecmaVersion === 6 && isBinding && last && last.type === "RestElement" && last.argument.type !== "Identifier")
      { this.unexpected(last.argument.start); }
  }
  return exprList
};

// Parses spread element.

pp$7.parseSpread = function(refDestructuringErrors) {
  var node = this.startNode();
  this.next();
  node.argument = this.parseMaybeAssign(false, refDestructuringErrors);
  return this.finishNode(node, "SpreadElement")
};

pp$7.parseRestBinding = function() {
  var node = this.startNode();
  this.next();

  // RestElement inside of a function parameter must be an identifier
  if (this.options.ecmaVersion === 6 && this.type !== types$1.name)
    { this.unexpected(); }

  node.argument = this.parseBindingAtom();

  return this.finishNode(node, "RestElement")
};

// Parses lvalue (assignable) atom.

pp$7.parseBindingAtom = function() {
  if (this.options.ecmaVersion >= 6) {
    switch (this.type) {
    case types$1.bracketL:
      var node = this.startNode();
      this.next();
      node.elements = this.parseBindingList(types$1.bracketR, true, true);
      return this.finishNode(node, "ArrayPattern")

    case types$1.braceL:
      return this.parseObj(true)
    }
  }
  return this.parseIdent()
};

pp$7.parseBindingList = function(close, allowEmpty, allowTrailingComma, allowModifiers) {
  var elts = [], first = true;
  while (!this.eat(close)) {
    if (first) { first = false; }
    else { this.expect(types$1.comma); }
    if (allowEmpty && this.type === types$1.comma) {
      elts.push(null);
    } else if (allowTrailingComma && this.afterTrailingComma(close)) {
      break
    } else if (this.type === types$1.ellipsis) {
      var rest = this.parseRestBinding();
      this.parseBindingListItem(rest);
      elts.push(rest);
      if (this.type === types$1.comma) { this.raiseRecoverable(this.start, "Comma is not permitted after the rest element"); }
      this.expect(close);
      break
    } else {
      elts.push(this.parseAssignableListItem(allowModifiers));
    }
  }
  return elts
};

pp$7.parseAssignableListItem = function(allowModifiers) {
  var elem = this.parseMaybeDefault(this.start, this.startLoc);
  this.parseBindingListItem(elem);
  return elem
};

pp$7.parseBindingListItem = function(param) {
  return param
};

// Parses assignment pattern around given atom if possible.

pp$7.parseMaybeDefault = function(startPos, startLoc, left) {
  left = left || this.parseBindingAtom();
  if (this.options.ecmaVersion < 6 || !this.eat(types$1.eq)) { return left }
  var node = this.startNodeAt(startPos, startLoc);
  node.left = left;
  node.right = this.parseMaybeAssign();
  return this.finishNode(node, "AssignmentPattern")
};

// The following three functions all verify that a node is an lvalue —
// something that can be bound, or assigned to. In order to do so, they perform
// a variety of checks:
//
// - Check that none of the bound/assigned-to identifiers are reserved words.
// - Record name declarations for bindings in the appropriate scope.
// - Check duplicate argument names, if checkClashes is set.
//
// If a complex binding pattern is encountered (e.g., object and array
// destructuring), the entire pattern is recursively checked.
//
// There are three versions of checkLVal*() appropriate for different
// circumstances:
//
// - checkLValSimple() shall be used if the syntactic construct supports
//   nothing other than identifiers and member expressions. Parenthesized
//   expressions are also correctly handled. This is generally appropriate for
//   constructs for which the spec says
//
//   > It is a Syntax Error if AssignmentTargetType of [the production] is not
//   > simple.
//
//   It is also appropriate for checking if an identifier is valid and not
//   defined elsewhere, like import declarations or function/class identifiers.
//
//   Examples where this is used include:
//     a += …;
//     import a from '…';
//   where a is the node to be checked.
//
// - checkLValPattern() shall be used if the syntactic construct supports
//   anything checkLValSimple() supports, as well as object and array
//   destructuring patterns. This is generally appropriate for constructs for
//   which the spec says
//
//   > It is a Syntax Error if [the production] is neither an ObjectLiteral nor
//   > an ArrayLiteral and AssignmentTargetType of [the production] is not
//   > simple.
//
//   Examples where this is used include:
//     (a = …);
//     const a = …;
//     try { … } catch (a) { … }
//   where a is the node to be checked.
//
// - checkLValInnerPattern() shall be used if the syntactic construct supports
//   anything checkLValPattern() supports, as well as default assignment
//   patterns, rest elements, and other constructs that may appear within an
//   object or array destructuring pattern.
//
//   As a special case, function parameters also use checkLValInnerPattern(),
//   as they also support defaults and rest constructs.
//
// These functions deliberately support both assignment and binding constructs,
// as the logic for both is exceedingly similar. If the node is the target of
// an assignment, then bindingType should be set to BIND_NONE. Otherwise, it
// should be set to the appropriate BIND_* constant, like BIND_VAR or
// BIND_LEXICAL.
//
// If the function is called with a non-BIND_NONE bindingType, then
// additionally a checkClashes object may be specified to allow checking for
// duplicate argument names. checkClashes is ignored if the provided construct
// is an assignment (i.e., bindingType is BIND_NONE).

pp$7.checkLValSimple = function(expr, bindingType, checkClashes) {
  if ( bindingType === void 0 ) bindingType = BIND_NONE;

  var isBind = bindingType !== BIND_NONE;

  switch (expr.type) {
  case "Identifier":
    if (this.strict && this.reservedWordsStrictBind.test(expr.name))
      { this.raiseRecoverable(expr.start, (isBind ? "Binding " : "Assigning to ") + expr.name + " in strict mode"); }
    if (isBind) {
      if (bindingType === BIND_LEXICAL && expr.name === "let")
        { this.raiseRecoverable(expr.start, "let is disallowed as a lexically bound name"); }
      if (checkClashes) {
        if (hasOwn(checkClashes, expr.name))
          { this.raiseRecoverable(expr.start, "Argument name clash"); }
        checkClashes[expr.name] = true;
      }
      if (bindingType !== BIND_OUTSIDE) { this.declareName(expr.name, bindingType, expr.start); }
    }
    break

  case "ChainExpression":
    this.raiseRecoverable(expr.start, "Optional chaining cannot appear in left-hand side");
    break

  case "MemberExpression":
    if (isBind) { this.raiseRecoverable(expr.start, "Binding member expression"); }
    break

  case "ParenthesizedExpression":
    if (isBind) { this.raiseRecoverable(expr.start, "Binding parenthesized expression"); }
    return this.checkLValSimple(expr.expression, bindingType, checkClashes)

  default:
    this.raise(expr.start, (isBind ? "Binding" : "Assigning to") + " rvalue");
  }
};

pp$7.checkLValPattern = function(expr, bindingType, checkClashes) {
  if ( bindingType === void 0 ) bindingType = BIND_NONE;

  switch (expr.type) {
  case "ObjectPattern":
    for (var i = 0, list = expr.properties; i < list.length; i += 1) {
      var prop = list[i];

    this.checkLValInnerPattern(prop, bindingType, checkClashes);
    }
    break

  case "ArrayPattern":
    for (var i$1 = 0, list$1 = expr.elements; i$1 < list$1.length; i$1 += 1) {
      var elem = list$1[i$1];

    if (elem) { this.checkLValInnerPattern(elem, bindingType, checkClashes); }
    }
    break

  default:
    this.checkLValSimple(expr, bindingType, checkClashes);
  }
};

pp$7.checkLValInnerPattern = function(expr, bindingType, checkClashes) {
  if ( bindingType === void 0 ) bindingType = BIND_NONE;

  switch (expr.type) {
  case "Property":
    // AssignmentProperty has type === "Property"
    this.checkLValInnerPattern(expr.value, bindingType, checkClashes);
    break

  case "AssignmentPattern":
    this.checkLValPattern(expr.left, bindingType, checkClashes);
    break

  case "RestElement":
    this.checkLValPattern(expr.argument, bindingType, checkClashes);
    break

  default:
    this.checkLValPattern(expr, bindingType, checkClashes);
  }
};

// The algorithm used to determine whether a regexp can appear at a
// given point in the program is loosely based on sweet.js' approach.
// See https://github.com/mozilla/sweet.js/wiki/design


var TokContext = function TokContext(token, isExpr, preserveSpace, override, generator) {
  this.token = token;
  this.isExpr = !!isExpr;
  this.preserveSpace = !!preserveSpace;
  this.override = override;
  this.generator = !!generator;
};

var types = {
  b_stat: new TokContext("{", false),
  b_expr: new TokContext("{", true),
  b_tmpl: new TokContext("${", false),
  p_stat: new TokContext("(", false),
  p_expr: new TokContext("(", true),
  q_tmpl: new TokContext("`", true, true, function (p) { return p.tryReadTemplateToken(); }),
  f_stat: new TokContext("function", false),
  f_expr: new TokContext("function", true),
  f_expr_gen: new TokContext("function", true, false, null, true),
  f_gen: new TokContext("function", false, false, null, true)
};

var pp$6 = Parser.prototype;

pp$6.initialContext = function() {
  return [types.b_stat]
};

pp$6.curContext = function() {
  return this.context[this.context.length - 1]
};

pp$6.braceIsBlock = function(prevType) {
  var parent = this.curContext();
  if (parent === types.f_expr || parent === types.f_stat)
    { return true }
  if (prevType === types$1.colon && (parent === types.b_stat || parent === types.b_expr))
    { return !parent.isExpr }

  // The check for `tt.name && exprAllowed` detects whether we are
  // after a `yield` or `of` construct. See the `updateContext` for
  // `tt.name`.
  if (prevType === types$1._return || prevType === types$1.name && this.exprAllowed)
    { return lineBreak.test(this.input.slice(this.lastTokEnd, this.start)) }
  if (prevType === types$1._else || prevType === types$1.semi || prevType === types$1.eof || prevType === types$1.parenR || prevType === types$1.arrow)
    { return true }
  if (prevType === types$1.braceL)
    { return parent === types.b_stat }
  if (prevType === types$1._var || prevType === types$1._const || prevType === types$1.name)
    { return false }
  return !this.exprAllowed
};

pp$6.inGeneratorContext = function() {
  for (var i = this.context.length - 1; i >= 1; i--) {
    var context = this.context[i];
    if (context.token === "function")
      { return context.generator }
  }
  return false
};

pp$6.updateContext = function(prevType) {
  var update, type = this.type;
  if (type.keyword && prevType === types$1.dot)
    { this.exprAllowed = false; }
  else if (update = type.updateContext)
    { update.call(this, prevType); }
  else
    { this.exprAllowed = type.beforeExpr; }
};

// Used to handle edge cases when token context could not be inferred correctly during tokenization phase

pp$6.overrideContext = function(tokenCtx) {
  if (this.curContext() !== tokenCtx) {
    this.context[this.context.length - 1] = tokenCtx;
  }
};

// Token-specific context update code

types$1.parenR.updateContext = types$1.braceR.updateContext = function() {
  if (this.context.length === 1) {
    this.exprAllowed = true;
    return
  }
  var out = this.context.pop();
  if (out === types.b_stat && this.curContext().token === "function") {
    out = this.context.pop();
  }
  this.exprAllowed = !out.isExpr;
};

types$1.braceL.updateContext = function(prevType) {
  this.context.push(this.braceIsBlock(prevType) ? types.b_stat : types.b_expr);
  this.exprAllowed = true;
};

types$1.dollarBraceL.updateContext = function() {
  this.context.push(types.b_tmpl);
  this.exprAllowed = true;
};

types$1.parenL.updateContext = function(prevType) {
  var statementParens = prevType === types$1._if || prevType === types$1._for || prevType === types$1._with || prevType === types$1._while;
  this.context.push(statementParens ? types.p_stat : types.p_expr);
  this.exprAllowed = true;
};

types$1.incDec.updateContext = function() {
  // tokExprAllowed stays unchanged
};

types$1._function.updateContext = types$1._class.updateContext = function(prevType) {
  if (prevType.beforeExpr && prevType !== types$1._else &&
      !(prevType === types$1.semi && this.curContext() !== types.p_stat) &&
      !(prevType === types$1._return && lineBreak.test(this.input.slice(this.lastTokEnd, this.start))) &&
      !((prevType === types$1.colon || prevType === types$1.braceL) && this.curContext() === types.b_stat))
    { this.context.push(types.f_expr); }
  else
    { this.context.push(types.f_stat); }
  this.exprAllowed = false;
};

types$1.colon.updateContext = function() {
  if (this.curContext().token === "function") { this.context.pop(); }
  this.exprAllowed = true;
};

types$1.backQuote.updateContext = function() {
  if (this.curContext() === types.q_tmpl)
    { this.context.pop(); }
  else
    { this.context.push(types.q_tmpl); }
  this.exprAllowed = false;
};

types$1.star.updateContext = function(prevType) {
  if (prevType === types$1._function) {
    var index = this.context.length - 1;
    if (this.context[index] === types.f_expr)
      { this.context[index] = types.f_expr_gen; }
    else
      { this.context[index] = types.f_gen; }
  }
  this.exprAllowed = true;
};

types$1.name.updateContext = function(prevType) {
  var allowed = false;
  if (this.options.ecmaVersion >= 6 && prevType !== types$1.dot) {
    if (this.value === "of" && !this.exprAllowed ||
        this.value === "yield" && this.inGeneratorContext())
      { allowed = true; }
  }
  this.exprAllowed = allowed;
};

// A recursive descent parser operates by defining functions for all
// syntactic elements, and recursively calling those, each function
// advancing the input stream and returning an AST node. Precedence
// of constructs (for example, the fact that `!x[1]` means `!(x[1])`
// instead of `(!x)[1]` is handled by the fact that the parser
// function that parses unary prefix operators is called first, and
// in turn calls the function that parses `[]` subscripts — that
// way, it'll receive the node for `x[1]` already parsed, and wraps
// *that* in the unary operator node.
//
// Acorn uses an [operator precedence parser][opp] to handle binary
// operator precedence, because it is much more compact than using
// the technique outlined above, which uses different, nesting
// functions to specify precedence, for all of the ten binary
// precedence levels that JavaScript defines.
//
// [opp]: http://en.wikipedia.org/wiki/Operator-precedence_parser


var pp$5 = Parser.prototype;

// Check if property name clashes with already added.
// Object/class getters and setters are not allowed to clash —
// either with each other or with an init property — and in
// strict mode, init properties are also not allowed to be repeated.

pp$5.checkPropClash = function(prop, propHash, refDestructuringErrors) {
  if (this.options.ecmaVersion >= 9 && prop.type === "SpreadElement")
    { return }
  if (this.options.ecmaVersion >= 6 && (prop.computed || prop.method || prop.shorthand))
    { return }
  var key = prop.key;
  var name;
  switch (key.type) {
  case "Identifier": name = key.name; break
  case "Literal": name = String(key.value); break
  default: return
  }
  var kind = prop.kind;
  if (this.options.ecmaVersion >= 6) {
    if (name === "__proto__" && kind === "init") {
      if (propHash.proto) {
        if (refDestructuringErrors) {
          if (refDestructuringErrors.doubleProto < 0) {
            refDestructuringErrors.doubleProto = key.start;
          }
        } else {
          this.raiseRecoverable(key.start, "Redefinition of __proto__ property");
        }
      }
      propHash.proto = true;
    }
    return
  }
  name = "$" + name;
  var other = propHash[name];
  if (other) {
    var redefinition;
    if (kind === "init") {
      redefinition = this.strict && other.init || other.get || other.set;
    } else {
      redefinition = other.init || other[kind];
    }
    if (redefinition)
      { this.raiseRecoverable(key.start, "Redefinition of property"); }
  } else {
    other = propHash[name] = {
      init: false,
      get: false,
      set: false
    };
  }
  other[kind] = true;
};

// ### Expression parsing

// These nest, from the most general expression type at the top to
// 'atomic', nondivisible expression types at the bottom. Most of
// the functions will simply let the function(s) below them parse,
// and, *if* the syntactic construct they handle is present, wrap
// the AST node that the inner parser gave them in another node.

// Parse a full expression. The optional arguments are used to
// forbid the `in` operator (in for loops initalization expressions)
// and provide reference for storing '=' operator inside shorthand
// property assignment in contexts where both object expression
// and object pattern might appear (so it's possible to raise
// delayed syntax error at correct position).

pp$5.parseExpression = function(forInit, refDestructuringErrors) {
  var this$1$1 = this;

  return this.catchStackOverflow(function () {
    var startPos = this$1$1.start, startLoc = this$1$1.startLoc;
    var expr = this$1$1.parseMaybeAssign(forInit, refDestructuringErrors);
    if (this$1$1.type === types$1.comma) {
      var node = this$1$1.startNodeAt(startPos, startLoc);
      node.expressions = [expr];
      while (this$1$1.eat(types$1.comma)) { node.expressions.push(this$1$1.parseMaybeAssign(forInit, refDestructuringErrors)); }
      return this$1$1.finishNode(node, "SequenceExpression")
    }
    return expr
  })
};

// Parse an assignment expression. This includes applications of
// operators like `+=`.

pp$5.parseMaybeAssign = function(forInit, refDestructuringErrors, afterLeftParse) {
  if (this.isContextual("yield")) {
    if (this.inGenerator) { return this.parseYield(forInit) }
    // The tokenizer will assume an expression is allowed after
    // `yield`, but this isn't that kind of yield
    else { this.exprAllowed = false; }
  }

  var ownDestructuringErrors = false, oldParenAssign = -1, oldTrailingComma = -1, oldDoubleProto = -1;
  if (refDestructuringErrors) {
    oldParenAssign = refDestructuringErrors.parenthesizedAssign;
    oldTrailingComma = refDestructuringErrors.trailingComma;
    oldDoubleProto = refDestructuringErrors.doubleProto;
    refDestructuringErrors.parenthesizedAssign = refDestructuringErrors.trailingComma = -1;
  } else {
    refDestructuringErrors = new DestructuringErrors;
    ownDestructuringErrors = true;
  }

  var startPos = this.start, startLoc = this.startLoc;
  if (this.type === types$1.parenL || this.type === types$1.name) {
    this.potentialArrowAt = this.start;
    this.potentialArrowInForAwait = forInit === "await";
  }
  var left = this.parseMaybeConditional(forInit, refDestructuringErrors);
  if (afterLeftParse) { left = afterLeftParse.call(this, left, startPos, startLoc); }
  if (this.type.isAssign) {
    var node = this.startNodeAt(startPos, startLoc);
    node.operator = this.value;
    if (this.type === types$1.eq)
      { left = this.toAssignable(left, false, refDestructuringErrors); }
    if (!ownDestructuringErrors) {
      refDestructuringErrors.parenthesizedAssign = refDestructuringErrors.trailingComma = refDestructuringErrors.doubleProto = -1;
    }
    if (refDestructuringErrors.shorthandAssign >= left.start)
      { refDestructuringErrors.shorthandAssign = -1; } // reset because shorthand default was used correctly
    if (this.type === types$1.eq)
      { this.checkLValPattern(left); }
    else
      { this.checkLValSimple(left); }
    node.left = left;
    this.next();
    node.right = this.parseMaybeAssign(forInit);
    if (oldDoubleProto > -1) { refDestructuringErrors.doubleProto = oldDoubleProto; }
    return this.finishNode(node, "AssignmentExpression")
  } else {
    if (ownDestructuringErrors) { this.checkExpressionErrors(refDestructuringErrors, true); }
  }
  if (oldParenAssign > -1) { refDestructuringErrors.parenthesizedAssign = oldParenAssign; }
  if (oldTrailingComma > -1) { refDestructuringErrors.trailingComma = oldTrailingComma; }
  return left
};

// Parse a ternary conditional (`?:`) operator.

pp$5.parseMaybeConditional = function(forInit, refDestructuringErrors) {
  var startPos = this.start, startLoc = this.startLoc;
  var expr = this.parseExprOps(forInit, refDestructuringErrors);
  if (this.checkExpressionErrors(refDestructuringErrors)) { return expr }
  if (!(expr.type === "ArrowFunctionExpression" && expr.start === startPos) && this.eat(types$1.question)) {
    var node = this.startNodeAt(startPos, startLoc);
    node.test = expr;
    node.consequent = this.parseMaybeAssign();
    this.expect(types$1.colon);
    node.alternate = this.parseMaybeAssign(forInit);
    return this.finishNode(node, "ConditionalExpression")
  }
  return expr
};

// Start the precedence parser.

pp$5.parseExprOps = function(forInit, refDestructuringErrors) {
  var startPos = this.start, startLoc = this.startLoc;
  var expr = this.parseMaybeUnary(refDestructuringErrors, false, false, forInit);
  if (this.checkExpressionErrors(refDestructuringErrors)) { return expr }
  return expr.start === startPos && expr.type === "ArrowFunctionExpression" ? expr : this.parseExprOp(expr, startPos, startLoc, -1, forInit)
};

// Parse binary operators with the operator precedence parsing
// algorithm. `left` is the left-hand side of the operator.
// `minPrec` provides context that allows the function to stop and
// defer further parser to one of its callers when it encounters an
// operator that has a lower precedence than the set it is parsing.

pp$5.parseExprOp = function(left, leftStartPos, leftStartLoc, minPrec, forInit) {
  var prec = this.type.binop;
  if (prec != null && (!forInit || this.type !== types$1._in)) {
    if (prec > minPrec) {
      var logical = this.type === types$1.logicalOR || this.type === types$1.logicalAND;
      var coalesce = this.type === types$1.coalesce;
      if (coalesce) {
        // Handle the precedence of `tt.coalesce` as equal to the range of logical expressions.
        // In other words, `node.right` shouldn't contain logical expressions in order to check the mixed error.
        prec = types$1.logicalAND.binop;
      }
      var op = this.value;
      this.next();
      var startPos = this.start, startLoc = this.startLoc;
      var right = this.parseExprOp(this.parseMaybeUnary(null, false, false, forInit), startPos, startLoc, prec, forInit);
      var node = this.buildBinary(leftStartPos, leftStartLoc, left, right, op, logical || coalesce);
      if ((logical && this.type === types$1.coalesce) || (coalesce && (this.type === types$1.logicalOR || this.type === types$1.logicalAND))) {
        this.raiseRecoverable(this.start, "Logical expressions and coalesce expressions cannot be mixed. Wrap either by parentheses");
      }
      return this.parseExprOp(node, leftStartPos, leftStartLoc, minPrec, forInit)
    }
  }
  return left
};

pp$5.buildBinary = function(startPos, startLoc, left, right, op, logical) {
  if (right.type === "PrivateIdentifier") { this.raise(right.start, "Private identifier can only be left side of binary expression"); }
  var node = this.startNodeAt(startPos, startLoc);
  node.left = left;
  node.operator = op;
  node.right = right;
  return this.finishNode(node, logical ? "LogicalExpression" : "BinaryExpression")
};

// Parse unary operators, both prefix and postfix.

pp$5.parseMaybeUnary = function(refDestructuringErrors, sawUnary, incDec, forInit) {
  var startPos = this.start, startLoc = this.startLoc, expr;
  if (this.isContextual("await") && this.canAwait) {
    expr = this.parseAwait(forInit);
    sawUnary = true;
  } else if (this.type.prefix) {
    var node = this.startNode(), update = this.type === types$1.incDec;
    node.operator = this.value;
    node.prefix = true;
    this.next();
    node.argument = this.parseMaybeUnary(null, true, update, forInit);
    this.checkExpressionErrors(refDestructuringErrors, true);
    if (update) { this.checkLValSimple(node.argument); }
    else if (this.strict && node.operator === "delete" && isLocalVariableAccess(node.argument))
      { this.raiseRecoverable(node.start, "Deleting local variable in strict mode"); }
    else if (node.operator === "delete" && isPrivateFieldAccess(node.argument))
      { this.raiseRecoverable(node.start, "Private fields can not be deleted"); }
    else { sawUnary = true; }
    expr = this.finishNode(node, update ? "UpdateExpression" : "UnaryExpression");
  } else if (!sawUnary && this.type === types$1.privateId) {
    if ((forInit || this.privateNameStack.length === 0) && this.options.checkPrivateFields) { this.unexpected(); }
    expr = this.parsePrivateIdent();
    // only could be private fields in 'in', such as #x in obj
    if (this.type !== types$1._in) { this.unexpected(); }
  } else {
    expr = this.parseExprSubscripts(refDestructuringErrors, forInit);
    if (this.checkExpressionErrors(refDestructuringErrors)) { return expr }
    while (this.type.postfix && !this.canInsertSemicolon()) {
      var node$1 = this.startNodeAt(startPos, startLoc);
      node$1.operator = this.value;
      node$1.prefix = false;
      node$1.argument = expr;
      this.checkLValSimple(expr);
      this.next();
      expr = this.finishNode(node$1, "UpdateExpression");
    }
  }

  if (!incDec && !(expr.type === "ArrowFunctionExpression" && expr.start === startPos) && this.eat(types$1.starstar)) {
    if (sawUnary)
      { this.unexpected(this.lastTokStart); }
    else
      { return this.buildBinary(startPos, startLoc, expr, this.parseMaybeUnary(null, false, false, forInit), "**", false) }
  } else {
    return expr
  }
};

function isLocalVariableAccess(node) {
  return (
    node.type === "Identifier" ||
    node.type === "ParenthesizedExpression" && isLocalVariableAccess(node.expression)
  )
}

function isPrivateFieldAccess(node) {
  return (
    node.type === "MemberExpression" && node.property.type === "PrivateIdentifier" ||
    node.type === "ChainExpression" && isPrivateFieldAccess(node.expression) ||
    node.type === "ParenthesizedExpression" && isPrivateFieldAccess(node.expression)
  )
}

// Parse call, dot, and `[]`-subscript expressions.

pp$5.parseExprSubscripts = function(refDestructuringErrors, forInit) {
  var startPos = this.start, startLoc = this.startLoc;
  var expr = this.parseExprAtom(refDestructuringErrors, forInit);
  if (expr.type === "ArrowFunctionExpression" && this.input.slice(this.lastTokStart, this.lastTokEnd) !== ")")
    { return expr }
  var result = this.parseSubscripts(expr, startPos, startLoc, false, forInit);
  if (refDestructuringErrors && result.type === "MemberExpression") {
    if (refDestructuringErrors.parenthesizedAssign >= result.start) { refDestructuringErrors.parenthesizedAssign = -1; }
    if (refDestructuringErrors.parenthesizedBind >= result.start) { refDestructuringErrors.parenthesizedBind = -1; }
    if (refDestructuringErrors.trailingComma >= result.start) { refDestructuringErrors.trailingComma = -1; }
  }
  return result
};

pp$5.parseSubscripts = function(base, startPos, startLoc, noCalls, forInit) {
  var maybeAsyncArrow = this.options.ecmaVersion >= 8 && base.type === "Identifier" && base.name === "async" &&
      this.lastTokEnd === base.end && !this.canInsertSemicolon() && base.end - base.start === 5 &&
      this.potentialArrowAt === base.start;
  var optionalChained = false;

  while (true) {
    var element = this.parseSubscript(base, startPos, startLoc, noCalls, maybeAsyncArrow, optionalChained, forInit);

    if (element.optional) { optionalChained = true; }
    if (element === base || element.type === "ArrowFunctionExpression") {
      if (optionalChained) {
        var chainNode = this.startNodeAt(startPos, startLoc);
        chainNode.expression = element;
        element = this.finishNode(chainNode, "ChainExpression");
      }
      return element
    }

    base = element;
  }
};

pp$5.shouldParseAsyncArrow = function() {
  return !this.canInsertSemicolon() && this.eat(types$1.arrow)
};

pp$5.parseSubscriptAsyncArrow = function(startPos, startLoc, exprList, forInit) {
  return this.parseArrowExpression(this.startNodeAt(startPos, startLoc), exprList, true, forInit)
};

pp$5.parseSubscript = function(base, startPos, startLoc, noCalls, maybeAsyncArrow, optionalChained, forInit) {
  var optionalSupported = this.options.ecmaVersion >= 11;
  var optional = optionalSupported && this.eat(types$1.questionDot);
  if (noCalls && optional) { this.raise(this.lastTokStart, "Optional chaining cannot appear in the callee of new expressions"); }

  var computed = this.eat(types$1.bracketL);
  if (computed || (optional && this.type !== types$1.parenL && this.type !== types$1.backQuote) || this.eat(types$1.dot)) {
    var node = this.startNodeAt(startPos, startLoc);
    node.object = base;
    if (computed) {
      node.property = this.parseExpression();
      this.expect(types$1.bracketR);
    } else if (this.type === types$1.privateId && base.type !== "Super") {
      node.property = this.parsePrivateIdent();
    } else {
      node.property = this.parseIdent(this.options.allowReserved !== "never");
    }
    node.computed = !!computed;
    if (optionalSupported) {
      node.optional = optional;
    }
    base = this.finishNode(node, "MemberExpression");
  } else if (!noCalls && this.eat(types$1.parenL)) {
    var refDestructuringErrors = new DestructuringErrors, oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, oldAwaitIdentPos = this.awaitIdentPos;
    this.yieldPos = 0;
    this.awaitPos = 0;
    this.awaitIdentPos = 0;
    var exprList = this.parseExprList(types$1.parenR, this.options.ecmaVersion >= 8, false, refDestructuringErrors);
    if (maybeAsyncArrow && !optional && this.shouldParseAsyncArrow()) {
      this.checkPatternErrors(refDestructuringErrors, false);
      this.checkYieldAwaitInDefaultParams();
      if (this.awaitIdentPos > 0)
        { this.raise(this.awaitIdentPos, "Cannot use 'await' as identifier inside an async function"); }
      this.yieldPos = oldYieldPos;
      this.awaitPos = oldAwaitPos;
      this.awaitIdentPos = oldAwaitIdentPos;
      return this.parseSubscriptAsyncArrow(startPos, startLoc, exprList, forInit)
    }
    this.checkExpressionErrors(refDestructuringErrors, true);
    this.yieldPos = oldYieldPos || this.yieldPos;
    this.awaitPos = oldAwaitPos || this.awaitPos;
    this.awaitIdentPos = oldAwaitIdentPos || this.awaitIdentPos;
    var node$1 = this.startNodeAt(startPos, startLoc);
    node$1.callee = base;
    node$1.arguments = exprList;
    if (optionalSupported) {
      node$1.optional = optional;
    }
    base = this.finishNode(node$1, "CallExpression");
  } else if (this.type === types$1.backQuote) {
    if (optional || optionalChained) {
      this.raise(this.start, "Optional chaining cannot appear in the tag of tagged template expressions");
    }
    var node$2 = this.startNodeAt(startPos, startLoc);
    node$2.tag = base;
    node$2.quasi = this.parseTemplate({isTagged: true});
    base = this.finishNode(node$2, "TaggedTemplateExpression");
  }
  return base
};

// Parse an atomic expression — either a single token that is an
// expression, an expression started by a keyword like `function` or
// `new`, or an expression wrapped in punctuation like `()`, `[]`,
// or `{}`.

pp$5.parseExprAtom = function(refDestructuringErrors, forInit, forNew) {
  // If a division operator appears in an expression position, the
  // tokenizer got confused, and we force it to read a regexp instead.
  if (this.type === types$1.slash) { this.readRegexp(); }

  var node, canBeArrow = this.potentialArrowAt === this.start;
  switch (this.type) {
  case types$1._super:
    if (!this.allowSuper)
      { this.raise(this.start, "'super' keyword outside a method"); }
    node = this.startNode();
    this.next();
    if (this.type === types$1.parenL && !this.allowDirectSuper)
      { this.raise(node.start, "super() call outside constructor of a subclass"); }
    // The `super` keyword can appear at below:
    // SuperProperty:
    //     super [ Expression ]
    //     super . IdentifierName
    // SuperCall:
    //     super ( Arguments )
    if (this.type !== types$1.dot && this.type !== types$1.bracketL && this.type !== types$1.parenL)
      { this.unexpected(); }
    return this.finishNode(node, "Super")

  case types$1._this:
    node = this.startNode();
    this.next();
    return this.finishNode(node, "ThisExpression")

  case types$1.name:
    var startPos = this.start, startLoc = this.startLoc, containsEsc = this.containsEsc;
    var id = this.parseIdent(false);
    if (this.options.ecmaVersion >= 8 && !containsEsc && id.name === "async" && !this.canInsertSemicolon() && this.eat(types$1._function)) {
      this.overrideContext(types.f_expr);
      return this.parseFunction(this.startNodeAt(startPos, startLoc), 0, false, true, forInit)
    }
    if (canBeArrow && !this.canInsertSemicolon()) {
      if (this.eat(types$1.arrow))
        { return this.parseArrowExpression(this.startNodeAt(startPos, startLoc), [id], false, forInit) }
      if (this.options.ecmaVersion >= 8 && id.name === "async" && this.type === types$1.name && !containsEsc &&
          (!this.potentialArrowInForAwait || this.value !== "of" || this.containsEsc)) {
        id = this.parseIdent(false);
        if (this.canInsertSemicolon() || !this.eat(types$1.arrow))
          { this.unexpected(); }
        return this.parseArrowExpression(this.startNodeAt(startPos, startLoc), [id], true, forInit)
      }
    }
    return id

  case types$1.regexp:
    var value = this.value;
    node = this.parseLiteral(value.value);
    node.regex = {pattern: value.pattern, flags: value.flags};
    return node

  case types$1.num: case types$1.string:
    return this.parseLiteral(this.value)

  case types$1._null: case types$1._true: case types$1._false:
    node = this.startNode();
    node.value = this.type === types$1._null ? null : this.type === types$1._true;
    node.raw = this.type.keyword;
    this.next();
    return this.finishNode(node, "Literal")

  case types$1.parenL:
    var start = this.start, expr = this.parseParenAndDistinguishExpression(canBeArrow, forInit);
    if (refDestructuringErrors) {
      if (refDestructuringErrors.parenthesizedAssign < 0 && !this.isSimpleAssignTarget(expr))
        { refDestructuringErrors.parenthesizedAssign = start; }
      if (refDestructuringErrors.parenthesizedBind < 0)
        { refDestructuringErrors.parenthesizedBind = start; }
    }
    return expr

  case types$1.bracketL:
    node = this.startNode();
    this.next();
    node.elements = this.parseExprList(types$1.bracketR, true, true, refDestructuringErrors);
    return this.finishNode(node, "ArrayExpression")

  case types$1.braceL:
    this.overrideContext(types.b_expr);
    return this.parseObj(false, refDestructuringErrors)

  case types$1._function:
    node = this.startNode();
    this.next();
    return this.parseFunction(node, 0)

  case types$1._class:
    return this.parseClass(this.startNode(), false)

  case types$1._new:
    return this.parseNew()

  case types$1.backQuote:
    return this.parseTemplate()

  case types$1._import:
    if (this.options.ecmaVersion >= 11) {
      return this.parseExprImport(forNew)
    } else {
      return this.unexpected()
    }

  default:
    return this.parseExprAtomDefault()
  }
};

pp$5.parseExprAtomDefault = function() {
  this.unexpected();
};

pp$5.parseExprImport = function(forNew) {
  var node = this.startNode();

  // Consume `import` as an identifier for `import.meta`.
  // Because `this.parseIdent(true)` doesn't check escape sequences, it needs the check of `this.containsEsc`.
  if (this.containsEsc) { this.raiseRecoverable(this.start, "Escape sequence in keyword import"); }
  this.next();

  if (this.type === types$1.parenL && !forNew) {
    return this.parseDynamicImport(node)
  } else if (this.type === types$1.dot) {
    var meta = this.startNodeAt(node.start, node.loc && node.loc.start);
    meta.name = "import";
    node.meta = this.finishNode(meta, "Identifier");
    return this.parseImportMeta(node)
  } else {
    this.unexpected();
  }
};

pp$5.parseDynamicImport = function(node) {
  this.next(); // skip `(`

  // Parse node.source.
  node.source = this.parseMaybeAssign();

  if (this.options.ecmaVersion >= 16) {
    if (!this.eat(types$1.parenR)) {
      this.expect(types$1.comma);
      if (!this.afterTrailingComma(types$1.parenR)) {
        node.options = this.parseMaybeAssign();
        if (!this.eat(types$1.parenR)) {
          this.expect(types$1.comma);
          if (!this.afterTrailingComma(types$1.parenR)) {
            this.unexpected();
          }
        }
      } else {
        node.options = null;
      }
    } else {
      node.options = null;
    }
  } else {
    // Verify ending.
    if (!this.eat(types$1.parenR)) {
      var errorPos = this.start;
      if (this.eat(types$1.comma) && this.eat(types$1.parenR)) {
        this.raiseRecoverable(errorPos, "Trailing comma is not allowed in import()");
      } else {
        this.unexpected(errorPos);
      }
    }
  }

  return this.finishNode(node, "ImportExpression")
};

pp$5.parseImportMeta = function(node) {
  this.next(); // skip `.`

  var containsEsc = this.containsEsc;
  node.property = this.parseIdent(true);

  if (node.property.name !== "meta")
    { this.raiseRecoverable(node.property.start, "The only valid meta property for import is 'import.meta'"); }
  if (containsEsc)
    { this.raiseRecoverable(node.start, "'import.meta' must not contain escaped characters"); }
  if (this.options.sourceType !== "module" && !this.options.allowImportExportEverywhere)
    { this.raiseRecoverable(node.start, "Cannot use 'import.meta' outside a module"); }

  return this.finishNode(node, "MetaProperty")
};

pp$5.parseLiteral = function(value) {
  var node = this.startNode();
  node.value = value;
  node.raw = this.input.slice(this.start, this.end);
  if (node.raw.charCodeAt(node.raw.length - 1) === 110)
    { node.bigint = node.value != null ? node.value.toString() : node.raw.slice(0, -1).replace(/_/g, ""); }
  this.next();
  return this.finishNode(node, "Literal")
};

pp$5.parseParenExpression = function() {
  this.expect(types$1.parenL);
  var val = this.parseExpression();
  this.expect(types$1.parenR);
  return val
};

pp$5.shouldParseArrow = function(exprList) {
  return !this.canInsertSemicolon()
};

pp$5.parseParenAndDistinguishExpression = function(canBeArrow, forInit) {
  var startPos = this.start, startLoc = this.startLoc, val, allowTrailingComma = this.options.ecmaVersion >= 8;
  if (this.options.ecmaVersion >= 6) {
    this.next();

    var innerStartPos = this.start, innerStartLoc = this.startLoc;
    var exprList = [], first = true, lastIsComma = false;
    var refDestructuringErrors = new DestructuringErrors, oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, spreadStart;
    this.yieldPos = 0;
    this.awaitPos = 0;
    // Do not save awaitIdentPos to allow checking awaits nested in parameters
    while (this.type !== types$1.parenR) {
      first ? first = false : this.expect(types$1.comma);
      if (allowTrailingComma && this.afterTrailingComma(types$1.parenR, true)) {
        lastIsComma = true;
        break
      } else if (this.type === types$1.ellipsis) {
        spreadStart = this.start;
        exprList.push(this.parseParenItem(this.parseRestBinding()));
        if (this.type === types$1.comma) {
          this.raiseRecoverable(
            this.start,
            "Comma is not permitted after the rest element"
          );
        }
        break
      } else {
        exprList.push(this.parseMaybeAssign(false, refDestructuringErrors, this.parseParenItem));
      }
    }
    var innerEndPos = this.lastTokEnd, innerEndLoc = this.lastTokEndLoc;
    this.expect(types$1.parenR);

    if (canBeArrow && this.shouldParseArrow(exprList) && this.eat(types$1.arrow)) {
      this.checkPatternErrors(refDestructuringErrors, false);
      this.checkYieldAwaitInDefaultParams();
      this.yieldPos = oldYieldPos;
      this.awaitPos = oldAwaitPos;
      return this.parseParenArrowList(startPos, startLoc, exprList, forInit)
    }

    if (!exprList.length || lastIsComma) { this.unexpected(this.lastTokStart); }
    if (spreadStart) { this.unexpected(spreadStart); }
    this.checkExpressionErrors(refDestructuringErrors, true);
    this.yieldPos = oldYieldPos || this.yieldPos;
    this.awaitPos = oldAwaitPos || this.awaitPos;

    if (exprList.length > 1) {
      val = this.startNodeAt(innerStartPos, innerStartLoc);
      val.expressions = exprList;
      this.finishNodeAt(val, "SequenceExpression", innerEndPos, innerEndLoc);
    } else {
      val = exprList[0];
    }
  } else {
    val = this.parseParenExpression();
  }

  if (this.options.preserveParens) {
    var par = this.startNodeAt(startPos, startLoc);
    par.expression = val;
    return this.finishNode(par, "ParenthesizedExpression")
  } else {
    return val
  }
};

pp$5.parseParenItem = function(item) {
  return item
};

pp$5.parseParenArrowList = function(startPos, startLoc, exprList, forInit) {
  return this.parseArrowExpression(this.startNodeAt(startPos, startLoc), exprList, false, forInit)
};

// New's precedence is slightly tricky. It must allow its argument to
// be a `[]` or dot subscript expression, but not a call — at least,
// not without wrapping it in parentheses. Thus, it uses the noCalls
// argument to parseSubscripts to prevent it from consuming the
// argument list.

var empty = [];

pp$5.parseNew = function() {
  if (this.containsEsc) { this.raiseRecoverable(this.start, "Escape sequence in keyword new"); }
  var node = this.startNode();
  this.next();
  if (this.options.ecmaVersion >= 6 && this.type === types$1.dot) {
    var meta = this.startNodeAt(node.start, node.loc && node.loc.start);
    meta.name = "new";
    node.meta = this.finishNode(meta, "Identifier");
    this.next();
    var containsEsc = this.containsEsc;
    node.property = this.parseIdent(true);
    if (node.property.name !== "target")
      { this.raiseRecoverable(node.property.start, "The only valid meta property for new is 'new.target'"); }
    if (containsEsc)
      { this.raiseRecoverable(node.start, "'new.target' must not contain escaped characters"); }
    if (!this.allowNewDotTarget)
      { this.raiseRecoverable(node.start, "'new.target' can only be used in functions and class static block"); }
    return this.finishNode(node, "MetaProperty")
  }
  var startPos = this.start, startLoc = this.startLoc;
  node.callee = this.parseSubscripts(this.parseExprAtom(null, false, true), startPos, startLoc, true, false);
  if (node.callee.type === "Super")
    { this.raiseRecoverable(startPos, "Invalid use of 'super'"); }
  if (this.eat(types$1.parenL)) { node.arguments = this.parseExprList(types$1.parenR, this.options.ecmaVersion >= 8, false); }
  else { node.arguments = empty; }
  return this.finishNode(node, "NewExpression")
};

// Parse template expression.

pp$5.parseTemplateElement = function(ref) {
  var isTagged = ref.isTagged;

  var elem = this.startNode();
  if (this.type === types$1.invalidTemplate) {
    if (!isTagged) {
      this.raiseRecoverable(this.start, "Bad escape sequence in untagged template literal");
    }
    elem.value = {
      raw: this.value.replace(/\r\n?/g, "\n"),
      cooked: null
    };
  } else {
    elem.value = {
      raw: this.input.slice(this.start, this.end).replace(/\r\n?/g, "\n"),
      cooked: this.value
    };
  }
  this.next();
  elem.tail = this.type === types$1.backQuote;
  return this.finishNode(elem, "TemplateElement")
};

pp$5.parseTemplate = function(ref) {
  if ( ref === void 0 ) ref = {};
  var isTagged = ref.isTagged; if ( isTagged === void 0 ) isTagged = false;

  var node = this.startNode();
  this.next();
  node.expressions = [];
  var curElt = this.parseTemplateElement({isTagged: isTagged});
  node.quasis = [curElt];
  while (!curElt.tail) {
    if (this.type === types$1.eof) { this.raise(this.pos, "Unterminated template literal"); }
    this.expect(types$1.dollarBraceL);
    node.expressions.push(this.parseExpression());
    this.expect(types$1.braceR);
    node.quasis.push(curElt = this.parseTemplateElement({isTagged: isTagged}));
  }
  this.next();
  return this.finishNode(node, "TemplateLiteral")
};

pp$5.isAsyncProp = function(prop) {
  return !prop.computed && prop.key.type === "Identifier" && prop.key.name === "async" &&
    (this.type === types$1.name || this.type === types$1.num || this.type === types$1.string || this.type === types$1.bracketL || this.type.keyword || (this.options.ecmaVersion >= 9 && this.type === types$1.star)) &&
    !lineBreak.test(this.input.slice(this.lastTokEnd, this.start))
};

// Parse an object literal or binding pattern.

pp$5.parseObj = function(isPattern, refDestructuringErrors) {
  var node = this.startNode(), first = true, propHash = {};
  node.properties = [];
  this.next();
  while (!this.eat(types$1.braceR)) {
    if (!first) {
      this.expect(types$1.comma);
      if (this.options.ecmaVersion >= 5 && this.afterTrailingComma(types$1.braceR)) { break }
    } else { first = false; }

    var prop = this.parseProperty(isPattern, refDestructuringErrors);
    if (!isPattern) { this.checkPropClash(prop, propHash, refDestructuringErrors); }
    node.properties.push(prop);
  }
  return this.finishNode(node, isPattern ? "ObjectPattern" : "ObjectExpression")
};

pp$5.parseProperty = function(isPattern, refDestructuringErrors) {
  var prop = this.startNode(), isGenerator, isAsync, startPos, startLoc;
  if (this.options.ecmaVersion >= 9 && this.eat(types$1.ellipsis)) {
    if (isPattern) {
      prop.argument = this.parseIdent(false);
      if (this.type === types$1.comma) {
        this.raiseRecoverable(this.start, "Comma is not permitted after the rest element");
      }
      return this.finishNode(prop, "RestElement")
    }
    // Parse argument.
    prop.argument = this.parseMaybeAssign(false, refDestructuringErrors);
    // To disallow trailing comma via `this.toAssignable()`.
    if (this.type === types$1.comma && refDestructuringErrors && refDestructuringErrors.trailingComma < 0) {
      refDestructuringErrors.trailingComma = this.start;
    }
    // Finish
    return this.finishNode(prop, "SpreadElement")
  }
  if (this.options.ecmaVersion >= 6) {
    prop.method = false;
    prop.shorthand = false;
    if (isPattern || refDestructuringErrors) {
      startPos = this.start;
      startLoc = this.startLoc;
    }
    if (!isPattern)
      { isGenerator = this.eat(types$1.star); }
  }
  var containsEsc = this.containsEsc;
  this.parsePropertyName(prop);
  if (!isPattern && !containsEsc && this.options.ecmaVersion >= 8 && !isGenerator && this.isAsyncProp(prop)) {
    isAsync = true;
    isGenerator = this.options.ecmaVersion >= 9 && this.eat(types$1.star);
    this.parsePropertyName(prop);
  } else {
    isAsync = false;
  }
  this.parsePropertyValue(prop, isPattern, isGenerator, isAsync, startPos, startLoc, refDestructuringErrors, containsEsc);
  return this.finishNode(prop, "Property")
};

pp$5.parseGetterSetter = function(prop) {
  var kind = prop.key.name;
  this.parsePropertyName(prop);
  prop.value = this.parseMethod(false);
  prop.kind = kind;
  var paramCount = prop.kind === "get" ? 0 : 1;
  if (prop.value.params.length !== paramCount) {
    var start = prop.value.start;
    if (prop.kind === "get")
      { this.raiseRecoverable(start, "getter should have no params"); }
    else
      { this.raiseRecoverable(start, "setter should have exactly one param"); }
  } else {
    if (prop.kind === "set" && prop.value.params[0].type === "RestElement")
      { this.raiseRecoverable(prop.value.params[0].start, "Setter cannot use rest params"); }
  }
};

pp$5.parsePropertyValue = function(prop, isPattern, isGenerator, isAsync, startPos, startLoc, refDestructuringErrors, containsEsc) {
  if ((isGenerator || isAsync) && this.type === types$1.colon)
    { this.unexpected(); }

  if (this.eat(types$1.colon)) {
    prop.value = isPattern ? this.parseMaybeDefault(this.start, this.startLoc) : this.parseMaybeAssign(false, refDestructuringErrors);
    prop.kind = "init";
  } else if (this.options.ecmaVersion >= 6 && this.type === types$1.parenL) {
    if (isPattern) { this.unexpected(); }
    prop.method = true;
    prop.value = this.parseMethod(isGenerator, isAsync);
    prop.kind = "init";
  } else if (!isPattern && !containsEsc &&
             this.options.ecmaVersion >= 5 && !prop.computed && prop.key.type === "Identifier" &&
             (prop.key.name === "get" || prop.key.name === "set") &&
             (this.type !== types$1.comma && this.type !== types$1.braceR && this.type !== types$1.eq)) {
    if (isGenerator || isAsync) { this.unexpected(); }
    this.parseGetterSetter(prop);
  } else if (this.options.ecmaVersion >= 6 && !prop.computed && prop.key.type === "Identifier") {
    if (isGenerator || isAsync) { this.unexpected(); }
    this.checkUnreserved(prop.key);
    if (prop.key.name === "await" && !this.awaitIdentPos)
      { this.awaitIdentPos = startPos; }
    if (isPattern) {
      prop.value = this.parseMaybeDefault(startPos, startLoc, this.copyNode(prop.key));
    } else if (this.type === types$1.eq && refDestructuringErrors) {
      if (refDestructuringErrors.shorthandAssign < 0)
        { refDestructuringErrors.shorthandAssign = this.start; }
      prop.value = this.parseMaybeDefault(startPos, startLoc, this.copyNode(prop.key));
    } else {
      prop.value = this.copyNode(prop.key);
    }
    prop.kind = "init";
    prop.shorthand = true;
  } else { this.unexpected(); }
};

pp$5.parsePropertyName = function(prop) {
  if (this.options.ecmaVersion >= 6) {
    if (this.eat(types$1.bracketL)) {
      prop.computed = true;
      prop.key = this.parseMaybeAssign();
      this.expect(types$1.bracketR);
      return prop.key
    } else {
      prop.computed = false;
    }
  }
  return prop.key = this.type === types$1.num || this.type === types$1.string ? this.parseExprAtom() : this.parseIdent(this.options.allowReserved !== "never")
};

// Initialize empty function node.

pp$5.initFunction = function(node) {
  node.id = null;
  if (this.options.ecmaVersion >= 6) { node.generator = node.expression = false; }
  if (this.options.ecmaVersion >= 8) { node.async = false; }
};

// Parse object or class method.

pp$5.parseMethod = function(isGenerator, isAsync, allowDirectSuper) {
  var node = this.startNode(), oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, oldAwaitIdentPos = this.awaitIdentPos;

  this.initFunction(node);
  if (this.options.ecmaVersion >= 6)
    { node.generator = isGenerator; }
  if (this.options.ecmaVersion >= 8)
    { node.async = !!isAsync; }

  this.yieldPos = 0;
  this.awaitPos = 0;
  this.awaitIdentPos = 0;
  this.enterScope(functionFlags(isAsync, node.generator) | SCOPE_SUPER | (allowDirectSuper ? SCOPE_DIRECT_SUPER : 0));

  this.expect(types$1.parenL);
  node.params = this.parseBindingList(types$1.parenR, false, this.options.ecmaVersion >= 8);
  this.checkYieldAwaitInDefaultParams();
  this.parseFunctionBody(node, false, true, false);

  this.yieldPos = oldYieldPos;
  this.awaitPos = oldAwaitPos;
  this.awaitIdentPos = oldAwaitIdentPos;
  return this.finishNode(node, "FunctionExpression")
};

// Parse arrow function expression with given parameters.

pp$5.parseArrowExpression = function(node, params, isAsync, forInit) {
  var oldYieldPos = this.yieldPos, oldAwaitPos = this.awaitPos, oldAwaitIdentPos = this.awaitIdentPos;

  this.enterScope(functionFlags(isAsync, false) | SCOPE_ARROW);
  this.initFunction(node);
  if (this.options.ecmaVersion >= 8) { node.async = !!isAsync; }

  this.yieldPos = 0;
  this.awaitPos = 0;
  this.awaitIdentPos = 0;

  node.params = this.toAssignableList(params, true);
  this.parseFunctionBody(node, true, false, forInit);

  this.yieldPos = oldYieldPos;
  this.awaitPos = oldAwaitPos;
  this.awaitIdentPos = oldAwaitIdentPos;
  return this.finishNode(node, "ArrowFunctionExpression")
};

// Parse function body and check parameters.

pp$5.parseFunctionBody = function(node, isArrowFunction, isMethod, forInit) {
  var isExpression = isArrowFunction && this.type !== types$1.braceL;
  var oldStrict = this.strict, useStrict = false;

  if (isExpression) {
    node.body = this.parseMaybeAssign(forInit);
    node.expression = true;
    this.checkParams(node, false);
  } else {
    var nonSimple = this.options.ecmaVersion >= 7 && !this.isSimpleParamList(node.params);
    if (!oldStrict || nonSimple) {
      useStrict = this.strictDirective(this.end);
      // If this is a strict mode function, verify that argument names
      // are not repeated, and it does not try to bind the words `eval`
      // or `arguments`.
      if (useStrict && nonSimple)
        { this.raiseRecoverable(node.start, "Illegal 'use strict' directive in function with non-simple parameter list"); }
    }
    // Start a new scope with regard to labels and the `inFunction`
    // flag (restore them to their old value afterwards).
    var oldLabels = this.labels;
    this.labels = [];
    if (useStrict) { this.strict = true; }

    // Add the params to varDeclaredNames to ensure that an error is thrown
    // if a let/const declaration in the function clashes with one of the params.
    this.checkParams(node, !oldStrict && !useStrict && !isArrowFunction && !isMethod && this.isSimpleParamList(node.params));
    // Ensure the function name isn't a forbidden identifier in strict mode, e.g. 'eval'
    if (this.strict && node.id) { this.checkLValSimple(node.id, BIND_OUTSIDE); }
    node.body = this.parseBlock(false, undefined, useStrict && !oldStrict);
    node.expression = false;
    this.adaptDirectivePrologue(node.body.body);
    this.labels = oldLabels;
  }
  this.exitScope();
};

pp$5.isSimpleParamList = function(params) {
  for (var i = 0, list = params; i < list.length; i += 1)
    {
    var param = list[i];

    if (param.type !== "Identifier") { return false
  } }
  return true
};

// Checks function params for various disallowed patterns such as using "eval"
// or "arguments" and duplicate parameters.

pp$5.checkParams = function(node, allowDuplicates) {
  var nameHash = Object.create(null);
  for (var i = 0, list = node.params; i < list.length; i += 1)
    {
    var param = list[i];

    this.checkLValInnerPattern(param, BIND_VAR, allowDuplicates ? null : nameHash);
  }
};

// Parses a comma-separated list of expressions, and returns them as
// an array. `close` is the token type that ends the list, and
// `allowEmpty` can be turned on to allow subsequent commas with
// nothing in between them to be parsed as `null` (which is needed
// for array literals).

pp$5.parseExprList = function(close, allowTrailingComma, allowEmpty, refDestructuringErrors) {
  var elts = [], first = true;
  while (!this.eat(close)) {
    if (!first) {
      this.expect(types$1.comma);
      if (allowTrailingComma && this.afterTrailingComma(close)) { break }
    } else { first = false; }

    var elt = (void 0);
    if (allowEmpty && this.type === types$1.comma)
      { elt = null; }
    else if (this.type === types$1.ellipsis) {
      elt = this.parseSpread(refDestructuringErrors);
      if (refDestructuringErrors && this.type === types$1.comma && refDestructuringErrors.trailingComma < 0)
        { refDestructuringErrors.trailingComma = this.start; }
    } else {
      elt = this.parseMaybeAssign(false, refDestructuringErrors);
    }
    elts.push(elt);
  }
  return elts
};

pp$5.checkUnreserved = function(ref) {
  var start = ref.start;
  var end = ref.end;
  var name = ref.name;

  if (this.inGenerator && name === "yield")
    { this.raiseRecoverable(start, "Cannot use 'yield' as identifier inside a generator"); }
  if (this.inAsync && name === "await")
    { this.raiseRecoverable(start, "Cannot use 'await' as identifier inside an async function"); }
  if (!(this.currentThisScope().flags & SCOPE_VAR) && name === "arguments")
    { this.raiseRecoverable(start, "Cannot use 'arguments' in class field initializer"); }
  if (this.inClassStaticBlock && (name === "arguments" || name === "await"))
    { this.raise(start, ("Cannot use " + name + " in class static initialization block")); }
  if (this.keywords.test(name))
    { this.raise(start, ("Unexpected keyword '" + name + "'")); }
  if (this.options.ecmaVersion < 6 &&
    this.input.slice(start, end).indexOf("\\") !== -1) { return }
  var re = this.strict ? this.reservedWordsStrict : this.reservedWords;
  if (re.test(name)) {
    if (!this.inAsync && name === "await")
      { this.raiseRecoverable(start, "Cannot use keyword 'await' outside an async function"); }
    this.raiseRecoverable(start, ("The keyword '" + name + "' is reserved"));
  }
};

// Parse the next token as an identifier. If `liberal` is true (used
// when parsing properties), it will also convert keywords into
// identifiers.

pp$5.parseIdent = function(liberal) {
  var node = this.parseIdentNode();
  this.next(!!liberal);
  this.finishNode(node, "Identifier");
  if (!liberal) {
    this.checkUnreserved(node);
    if (node.name === "await" && !this.awaitIdentPos)
      { this.awaitIdentPos = node.start; }
  }
  return node
};

pp$5.parseIdentNode = function() {
  var node = this.startNode();
  if (this.type === types$1.name) {
    node.name = this.value;
  } else if (this.type.keyword) {
    node.name = this.type.keyword;

    // To fix https://github.com/acornjs/acorn/issues/575
    // `class` and `function` keywords push new context into this.context.
    // But there is no chance to pop the context if the keyword is consumed as an identifier such as a property name.
    // If the previous token is a dot, this does not apply because the context-managing code already ignored the keyword
    if ((node.name === "class" || node.name === "function") &&
      (this.lastTokEnd !== this.lastTokStart + 1 || this.input.charCodeAt(this.lastTokStart) !== 46)) {
      this.context.pop();
    }
    this.type = types$1.name;
  } else {
    this.unexpected();
  }
  return node
};

pp$5.parsePrivateIdent = function() {
  var node = this.startNode();
  if (this.type === types$1.privateId) {
    node.name = this.value;
  } else {
    this.unexpected();
  }
  this.next();
  this.finishNode(node, "PrivateIdentifier");

  // For validating existence
  if (this.options.checkPrivateFields) {
    if (this.privateNameStack.length === 0) {
      this.raise(node.start, ("Private field '#" + (node.name) + "' must be declared in an enclosing class"));
    } else {
      this.privateNameStack[this.privateNameStack.length - 1].used.push(node);
    }
  }

  return node
};

// Parses yield expression inside generator.

pp$5.parseYield = function(forInit) {
  if (!this.yieldPos) { this.yieldPos = this.start; }

  var node = this.startNode();
  this.next();
  if (this.type === types$1.semi || this.canInsertSemicolon() || (this.type !== types$1.star && !this.type.startsExpr)) {
    node.delegate = false;
    node.argument = null;
  } else {
    node.delegate = this.eat(types$1.star);
    node.argument = this.parseMaybeAssign(forInit);
  }
  return this.finishNode(node, "YieldExpression")
};

pp$5.parseAwait = function(forInit) {
  if (!this.awaitPos) { this.awaitPos = this.start; }

  var node = this.startNode();
  this.next();
  node.argument = this.parseMaybeUnary(null, true, false, forInit);
  return this.finishNode(node, "AwaitExpression")
};

var pp$4 = Parser.prototype;

// This function is used to raise exceptions on parse errors. It
// takes an offset integer (into the current `input`) to indicate
// the location of the error, attaches the position to the end
// of the error message, and then raises a `SyntaxError` with that
// message.

pp$4.raise = function(pos, message) {
  var loc = getLineInfo(this.input, pos);
  message += " (" + loc.line + ":" + loc.column + ")";
  if (this.sourceFile) {
    message += " in " + this.sourceFile;
  }
  var err = new SyntaxError(message);
  err.pos = pos; err.loc = loc; err.raisedAt = this.pos;
  throw err
};

pp$4.raiseRecoverable = pp$4.raise;

pp$4.curPosition = function() {
  if (this.options.locations) {
    return new Position(this.curLine, this.pos - this.lineStart)
  }
};

var pp$3 = Parser.prototype;

var Scope = function Scope(flags) {
  this.flags = flags;
  // A list of var-declared names in the current lexical scope
  this.var = [];
  // A list of lexically-declared names in the current lexical scope
  this.lexical = [];
  // A list of lexically-declared FunctionDeclaration names in the current lexical scope
  this.functions = [];
};

// The functions in this module keep track of declared variables in the current scope in order to detect duplicate variable names.

pp$3.enterScope = function(flags) {
  this.scopeStack.push(new Scope(flags));
};

pp$3.exitScope = function() {
  this.scopeStack.pop();
};

// The spec says:
// > At the top level of a function, or script, function declarations are
// > treated like var declarations rather than like lexical declarations.
pp$3.treatFunctionsAsVarInScope = function(scope) {
  return (scope.flags & SCOPE_FUNCTION) || !this.inModule && (scope.flags & SCOPE_TOP)
};

pp$3.declareName = function(name, bindingType, pos) {
  var redeclared = false;
  if (bindingType === BIND_LEXICAL) {
    var scope = this.currentScope();
    redeclared = scope.lexical.indexOf(name) > -1 || scope.functions.indexOf(name) > -1 || scope.var.indexOf(name) > -1;
    scope.lexical.push(name);
    if (this.inModule && (scope.flags & SCOPE_TOP))
      { delete this.undefinedExports[name]; }
  } else if (bindingType === BIND_SIMPLE_CATCH) {
    var scope$1 = this.currentScope();
    scope$1.lexical.push(name);
  } else if (bindingType === BIND_FUNCTION) {
    var scope$2 = this.currentScope();
    if (this.treatFunctionsAsVar)
      { redeclared = scope$2.lexical.indexOf(name) > -1; }
    else
      { redeclared = scope$2.lexical.indexOf(name) > -1 || scope$2.var.indexOf(name) > -1; }
    scope$2.functions.push(name);
  } else {
    for (var i = this.scopeStack.length - 1; i >= 0; --i) {
      var scope$3 = this.scopeStack[i];
      if (scope$3.lexical.indexOf(name) > -1 && !((scope$3.flags & SCOPE_SIMPLE_CATCH) && scope$3.lexical[0] === name) ||
          !this.treatFunctionsAsVarInScope(scope$3) && scope$3.functions.indexOf(name) > -1) {
        redeclared = true;
        break
      }
      scope$3.var.push(name);
      if (this.inModule && (scope$3.flags & SCOPE_TOP))
        { delete this.undefinedExports[name]; }
      if (scope$3.flags & SCOPE_VAR) { break }
    }
  }
  if (redeclared) { this.raiseRecoverable(pos, ("Identifier '" + name + "' has already been declared")); }
};

pp$3.checkLocalExport = function(id) {
  // scope.functions must be empty as Module code is always strict.
  if (this.scopeStack[0].lexical.indexOf(id.name) === -1 &&
      this.scopeStack[0].var.indexOf(id.name) === -1) {
    this.undefinedExports[id.name] = id;
  }
};

pp$3.currentScope = function() {
  return this.scopeStack[this.scopeStack.length - 1]
};

pp$3.currentVarScope = function() {
  for (var i = this.scopeStack.length - 1;; i--) {
    var scope = this.scopeStack[i];
    if (scope.flags & (SCOPE_VAR | SCOPE_CLASS_FIELD_INIT | SCOPE_CLASS_STATIC_BLOCK)) { return scope }
  }
};

// Could be useful for `this`, `new.target`, `super()`, `super.property`, and `super[property]`.
pp$3.currentThisScope = function() {
  for (var i = this.scopeStack.length - 1;; i--) {
    var scope = this.scopeStack[i];
    if (scope.flags & (SCOPE_VAR | SCOPE_CLASS_FIELD_INIT | SCOPE_CLASS_STATIC_BLOCK) &&
        !(scope.flags & SCOPE_ARROW)) { return scope }
  }
};

var Node = function Node(parser, pos, loc) {
  this.type = "";
  this.start = pos;
  this.end = 0;
  if (parser.options.locations)
    { this.loc = new SourceLocation(parser, loc); }
  if (parser.options.directSourceFile)
    { this.sourceFile = parser.options.directSourceFile; }
  if (parser.options.ranges)
    { this.range = [pos, 0]; }
};

// Start an AST node, attaching a start offset.

var pp$2 = Parser.prototype;

pp$2.startNode = function() {
  return new Node(this, this.start, this.startLoc)
};

pp$2.startNodeAt = function(pos, loc) {
  return new Node(this, pos, loc)
};

// Finish an AST node, adding `type` and `end` properties.

function finishNodeAt(node, type, pos, loc) {
  node.type = type;
  node.end = pos;
  if (this.options.locations)
    { node.loc.end = loc; }
  if (this.options.ranges)
    { node.range[1] = pos; }
  return node
}

pp$2.finishNode = function(node, type) {
  return finishNodeAt.call(this, node, type, this.lastTokEnd, this.lastTokEndLoc)
};

// Finish node at given position

pp$2.finishNodeAt = function(node, type, pos, loc) {
  return finishNodeAt.call(this, node, type, pos, loc)
};

pp$2.copyNode = function(node) {
  var newNode = new Node(this, node.start, this.startLoc);
  for (var prop in node) { newNode[prop] = node[prop]; }
  return newNode
};

// This file was generated by "bin/generate-unicode-script-values.js". Do not modify manually!
var scriptValuesAddedInUnicode = "Berf Beria_Erfe Gara Garay Gukh Gurung_Khema Hrkt Katakana_Or_Hiragana Kawi Kirat_Rai Krai Nag_Mundari Nagm Ol_Onal Onao Sidetic Sidt Sunu Sunuwar Tai_Yo Tayo Todhri Todr Tolong_Siki Tols Tulu_Tigalari Tutg Unknown Zzzz";

// This file contains Unicode properties extracted from the ECMAScript specification.
// The lists are extracted like so:
// $$('#table-binary-unicode-properties > figure > table > tbody > tr > td:nth-child(1) code').map(el => el.innerText)

// #table-binary-unicode-properties
var ecma9BinaryProperties = "ASCII ASCII_Hex_Digit AHex Alphabetic Alpha Any Assigned Bidi_Control Bidi_C Bidi_Mirrored Bidi_M Case_Ignorable CI Cased Changes_When_Casefolded CWCF Changes_When_Casemapped CWCM Changes_When_Lowercased CWL Changes_When_NFKC_Casefolded CWKCF Changes_When_Titlecased CWT Changes_When_Uppercased CWU Dash Default_Ignorable_Code_Point DI Deprecated Dep Diacritic Dia Emoji Emoji_Component Emoji_Modifier Emoji_Modifier_Base Emoji_Presentation Extender Ext Grapheme_Base Gr_Base Grapheme_Extend Gr_Ext Hex_Digit Hex IDS_Binary_Operator IDSB IDS_Trinary_Operator IDST ID_Continue IDC ID_Start IDS Ideographic Ideo Join_Control Join_C Logical_Order_Exception LOE Lowercase Lower Math Noncharacter_Code_Point NChar Pattern_Syntax Pat_Syn Pattern_White_Space Pat_WS Quotation_Mark QMark Radical Regional_Indicator RI Sentence_Terminal STerm Soft_Dotted SD Terminal_Punctuation Term Unified_Ideograph UIdeo Uppercase Upper Variation_Selector VS White_Space space XID_Continue XIDC XID_Start XIDS";
var ecma10BinaryProperties = ecma9BinaryProperties + " Extended_Pictographic";
var ecma11BinaryProperties = ecma10BinaryProperties;
var ecma12BinaryProperties = ecma11BinaryProperties + " EBase EComp EMod EPres ExtPict";
var ecma13BinaryProperties = ecma12BinaryProperties;
var ecma14BinaryProperties = ecma13BinaryProperties;

var unicodeBinaryProperties = {
  9: ecma9BinaryProperties,
  10: ecma10BinaryProperties,
  11: ecma11BinaryProperties,
  12: ecma12BinaryProperties,
  13: ecma13BinaryProperties,
  14: ecma14BinaryProperties
};

// #table-binary-unicode-properties-of-strings
var ecma14BinaryPropertiesOfStrings = "Basic_Emoji Emoji_Keycap_Sequence RGI_Emoji_Modifier_Sequence RGI_Emoji_Flag_Sequence RGI_Emoji_Tag_Sequence RGI_Emoji_ZWJ_Sequence RGI_Emoji";

var unicodeBinaryPropertiesOfStrings = {
  9: "",
  10: "",
  11: "",
  12: "",
  13: "",
  14: ecma14BinaryPropertiesOfStrings
};

// #table-unicode-general-category-values
var unicodeGeneralCategoryValues = "Cased_Letter LC Close_Punctuation Pe Connector_Punctuation Pc Control Cc cntrl Currency_Symbol Sc Dash_Punctuation Pd Decimal_Number Nd digit Enclosing_Mark Me Final_Punctuation Pf Format Cf Initial_Punctuation Pi Letter L Letter_Number Nl Line_Separator Zl Lowercase_Letter Ll Mark M Combining_Mark Math_Symbol Sm Modifier_Letter Lm Modifier_Symbol Sk Nonspacing_Mark Mn Number N Open_Punctuation Ps Other C Other_Letter Lo Other_Number No Other_Punctuation Po Other_Symbol So Paragraph_Separator Zp Private_Use Co Punctuation P punct Separator Z Space_Separator Zs Spacing_Mark Mc Surrogate Cs Symbol S Titlecase_Letter Lt Unassigned Cn Uppercase_Letter Lu";

// #table-unicode-script-values
var ecma9ScriptValues = "Adlam Adlm Ahom Anatolian_Hieroglyphs Hluw Arabic Arab Armenian Armn Avestan Avst Balinese Bali Bamum Bamu Bassa_Vah Bass Batak Batk Bengali Beng Bhaiksuki Bhks Bopomofo Bopo Brahmi Brah Braille Brai Buginese Bugi Buhid Buhd Canadian_Aboriginal Cans Carian Cari Caucasian_Albanian Aghb Chakma Cakm Cham Cham Cherokee Cher Common Zyyy Coptic Copt Qaac Cuneiform Xsux Cypriot Cprt Cyrillic Cyrl Deseret Dsrt Devanagari Deva Duployan Dupl Egyptian_Hieroglyphs Egyp Elbasan Elba Ethiopic Ethi Georgian Geor Glagolitic Glag Gothic Goth Grantha Gran Greek Grek Gujarati Gujr Gurmukhi Guru Han Hani Hangul Hang Hanunoo Hano Hatran Hatr Hebrew Hebr Hiragana Hira Imperial_Aramaic Armi Inherited Zinh Qaai Inscriptional_Pahlavi Phli Inscriptional_Parthian Prti Javanese Java Kaithi Kthi Kannada Knda Katakana Kana Kayah_Li Kali Kharoshthi Khar Khmer Khmr Khojki Khoj Khudawadi Sind Lao Laoo Latin Latn Lepcha Lepc Limbu Limb Linear_A Lina Linear_B Linb Lisu Lisu Lycian Lyci Lydian Lydi Mahajani Mahj Malayalam Mlym Mandaic Mand Manichaean Mani Marchen Marc Masaram_Gondi Gonm Meetei_Mayek Mtei Mende_Kikakui Mend Meroitic_Cursive Merc Meroitic_Hieroglyphs Mero Miao Plrd Modi Mongolian Mong Mro Mroo Multani Mult Myanmar Mymr Nabataean Nbat New_Tai_Lue Talu Newa Newa Nko Nkoo Nushu Nshu Ogham Ogam Ol_Chiki Olck Old_Hungarian Hung Old_Italic Ital Old_North_Arabian Narb Old_Permic Perm Old_Persian Xpeo Old_South_Arabian Sarb Old_Turkic Orkh Oriya Orya Osage Osge Osmanya Osma Pahawh_Hmong Hmng Palmyrene Palm Pau_Cin_Hau Pauc Phags_Pa Phag Phoenician Phnx Psalter_Pahlavi Phlp Rejang Rjng Runic Runr Samaritan Samr Saurashtra Saur Sharada Shrd Shavian Shaw Siddham Sidd SignWriting Sgnw Sinhala Sinh Sora_Sompeng Sora Soyombo Soyo Sundanese Sund Syloti_Nagri Sylo Syriac Syrc Tagalog Tglg Tagbanwa Tagb Tai_Le Tale Tai_Tham Lana Tai_Viet Tavt Takri Takr Tamil Taml Tangut Tang Telugu Telu Thaana Thaa Thai Thai Tibetan Tibt Tifinagh Tfng Tirhuta Tirh Ugaritic Ugar Vai Vaii Warang_Citi Wara Yi Yiii Zanabazar_Square Zanb";
var ecma10ScriptValues = ecma9ScriptValues + " Dogra Dogr Gunjala_Gondi Gong Hanifi_Rohingya Rohg Makasar Maka Medefaidrin Medf Old_Sogdian Sogo Sogdian Sogd";
var ecma11ScriptValues = ecma10ScriptValues + " Elymaic Elym Nandinagari Nand Nyiakeng_Puachue_Hmong Hmnp Wancho Wcho";
var ecma12ScriptValues = ecma11ScriptValues + " Chorasmian Chrs Diak Dives_Akuru Khitan_Small_Script Kits Yezi Yezidi";
var ecma13ScriptValues = ecma12ScriptValues + " Cypro_Minoan Cpmn Old_Uyghur Ougr Tangsa Tnsa Toto Vithkuqi Vith";
var ecma14ScriptValues = ecma13ScriptValues + " " + scriptValuesAddedInUnicode;

var unicodeScriptValues = {
  9: ecma9ScriptValues,
  10: ecma10ScriptValues,
  11: ecma11ScriptValues,
  12: ecma12ScriptValues,
  13: ecma13ScriptValues,
  14: ecma14ScriptValues
};

var data = {};
function buildUnicodeData(ecmaVersion) {
  var d = data[ecmaVersion] = {
    binary: wordsRegexp(unicodeBinaryProperties[ecmaVersion] + " " + unicodeGeneralCategoryValues),
    binaryOfStrings: wordsRegexp(unicodeBinaryPropertiesOfStrings[ecmaVersion]),
    nonBinary: {
      General_Category: wordsRegexp(unicodeGeneralCategoryValues),
      Script: wordsRegexp(unicodeScriptValues[ecmaVersion])
    }
  };
  d.nonBinary.Script_Extensions = d.nonBinary.Script;

  d.nonBinary.gc = d.nonBinary.General_Category;
  d.nonBinary.sc = d.nonBinary.Script;
  d.nonBinary.scx = d.nonBinary.Script_Extensions;
}

for (var i = 0, list = [9, 10, 11, 12, 13, 14]; i < list.length; i += 1) {
  var ecmaVersion = list[i];

  buildUnicodeData(ecmaVersion);
}

var pp$1 = Parser.prototype;

// Track disjunction structure to determine whether a duplicate
// capture group name is allowed because it is in a separate branch.
var BranchID = function BranchID(parent, base) {
  // Parent disjunction branch
  this.parent = parent;
  // Identifies this set of sibling branches
  this.base = base || this;
};

BranchID.prototype.separatedFrom = function separatedFrom (alt) {
  // A branch is separate from another branch if they or any of
  // their parents are siblings in a given disjunction
  for (var self = this; self; self = self.parent) {
    for (var other = alt; other; other = other.parent) {
      if (self.base === other.base && self !== other) { return true }
    }
  }
  return false
};

BranchID.prototype.sibling = function sibling () {
  return new BranchID(this.parent, this.base)
};

var RegExpValidationState = function RegExpValidationState(parser) {
  this.parser = parser;
  this.validFlags = "gim" + (parser.options.ecmaVersion >= 6 ? "uy" : "") + (parser.options.ecmaVersion >= 9 ? "s" : "") + (parser.options.ecmaVersion >= 13 ? "d" : "") + (parser.options.ecmaVersion >= 15 ? "v" : "");
  this.unicodeProperties = data[parser.options.ecmaVersion >= 14 ? 14 : parser.options.ecmaVersion];
  this.source = "";
  this.flags = "";
  this.start = 0;
  this.switchU = false;
  this.switchV = false;
  this.switchN = false;
  this.pos = 0;
  this.lastIntValue = 0;
  this.lastStringValue = "";
  this.lastAssertionIsQuantifiable = false;
  this.numCapturingParens = 0;
  this.maxBackReference = 0;
  this.groupNames = Object.create(null);
  this.backReferenceNames = [];
  this.branchID = null;
};

RegExpValidationState.prototype.reset = function reset (start, pattern, flags) {
  var unicodeSets = flags.indexOf("v") !== -1;
  var unicode = flags.indexOf("u") !== -1;
  this.start = start | 0;
  this.source = pattern + "";
  this.flags = flags;
  if (unicodeSets && this.parser.options.ecmaVersion >= 15) {
    this.switchU = true;
    this.switchV = true;
    this.switchN = true;
  } else {
    this.switchU = unicode && this.parser.options.ecmaVersion >= 6;
    this.switchV = false;
    this.switchN = unicode && this.parser.options.ecmaVersion >= 9;
  }
};

RegExpValidationState.prototype.raise = function raise (message) {
  this.parser.raiseRecoverable(this.start, ("Invalid regular expression: /" + (this.source) + "/: " + message));
};

// If u flag is given, this returns the code point at the index (it combines a surrogate pair).
// Otherwise, this returns the code unit of the index (can be a part of a surrogate pair).
RegExpValidationState.prototype.at = function at (i, forceU) {
    if ( forceU === void 0 ) forceU = false;

  var s = this.source;
  var l = s.length;
  if (i >= l) {
    return -1
  }
  var c = s.charCodeAt(i);
  if (!(forceU || this.switchU) || c <= 0xD7FF || c >= 0xE000 || i + 1 >= l) {
    return c
  }
  var next = s.charCodeAt(i + 1);
  return next >= 0xDC00 && next <= 0xDFFF ? (c << 10) + next - 0x35FDC00 : c
};

RegExpValidationState.prototype.nextIndex = function nextIndex (i, forceU) {
    if ( forceU === void 0 ) forceU = false;

  var s = this.source;
  var l = s.length;
  if (i >= l) {
    return l
  }
  var c = s.charCodeAt(i), next;
  if (!(forceU || this.switchU) || c <= 0xD7FF || c >= 0xE000 || i + 1 >= l ||
      (next = s.charCodeAt(i + 1)) < 0xDC00 || next > 0xDFFF) {
    return i + 1
  }
  return i + 2
};

RegExpValidationState.prototype.current = function current (forceU) {
    if ( forceU === void 0 ) forceU = false;

  return this.at(this.pos, forceU)
};

RegExpValidationState.prototype.lookahead = function lookahead (forceU) {
    if ( forceU === void 0 ) forceU = false;

  return this.at(this.nextIndex(this.pos, forceU), forceU)
};

RegExpValidationState.prototype.advance = function advance (forceU) {
    if ( forceU === void 0 ) forceU = false;

  this.pos = this.nextIndex(this.pos, forceU);
};

RegExpValidationState.prototype.eat = function eat (ch, forceU) {
    if ( forceU === void 0 ) forceU = false;

  if (this.current(forceU) === ch) {
    this.advance(forceU);
    return true
  }
  return false
};

RegExpValidationState.prototype.eatChars = function eatChars (chs, forceU) {
    if ( forceU === void 0 ) forceU = false;

  var pos = this.pos;
  for (var i = 0, list = chs; i < list.length; i += 1) {
    var ch = list[i];

      var current = this.at(pos, forceU);
    if (current === -1 || current !== ch) {
      return false
    }
    pos = this.nextIndex(pos, forceU);
  }
  this.pos = pos;
  return true
};

/**
 * Validate the flags part of a given RegExpLiteral.
 *
 * @param {RegExpValidationState} state The state to validate RegExp.
 * @returns {void}
 */
pp$1.validateRegExpFlags = function(state) {
  var validFlags = state.validFlags;
  var flags = state.flags;

  var u = false;
  var v = false;

  for (var i = 0; i < flags.length; i++) {
    var flag = flags.charAt(i);
    if (validFlags.indexOf(flag) === -1) {
      this.raise(state.start, "Invalid regular expression flag");
    }
    if (flags.indexOf(flag, i + 1) > -1) {
      this.raise(state.start, "Duplicate regular expression flag");
    }
    if (flag === "u") { u = true; }
    if (flag === "v") { v = true; }
  }
  if (this.options.ecmaVersion >= 15 && u && v) {
    this.raise(state.start, "Invalid regular expression flag");
  }
};

function hasProp(obj) {
  for (var _ in obj) { return true }
  return false
}

/**
 * Validate the pattern part of a given RegExpLiteral.
 *
 * @param {RegExpValidationState} state The state to validate RegExp.
 * @returns {void}
 */
pp$1.validateRegExpPattern = function(state) {
  this.regexp_pattern(state);

  // The goal symbol for the parse is |Pattern[~U, ~N]|. If the result of
  // parsing contains a |GroupName|, reparse with the goal symbol
  // |Pattern[~U, +N]| and use this result instead. Throw a *SyntaxError*
  // exception if _P_ did not conform to the grammar, if any elements of _P_
  // were not matched by the parse, or if any Early Error conditions exist.
  if (!state.switchN && this.options.ecmaVersion >= 9 && hasProp(state.groupNames)) {
    state.switchN = true;
    this.regexp_pattern(state);
  }
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-Pattern
pp$1.regexp_pattern = function(state) {
  state.pos = 0;
  state.lastIntValue = 0;
  state.lastStringValue = "";
  state.lastAssertionIsQuantifiable = false;
  state.numCapturingParens = 0;
  state.maxBackReference = 0;
  state.groupNames = Object.create(null);
  state.backReferenceNames.length = 0;
  state.branchID = null;

  this.regexp_disjunction(state);

  if (state.pos !== state.source.length) {
    // Make the same messages as V8.
    if (state.eat(0x29 /* ) */)) {
      state.raise("Unmatched ')'");
    }
    if (state.eat(0x5D /* ] */) || state.eat(0x7D /* } */)) {
      state.raise("Lone quantifier brackets");
    }
  }
  if (state.maxBackReference > state.numCapturingParens) {
    state.raise("Invalid escape");
  }
  for (var i = 0, list = state.backReferenceNames; i < list.length; i += 1) {
    var name = list[i];

    if (!state.groupNames[name]) {
      state.raise("Invalid named capture referenced");
    }
  }
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-Disjunction
pp$1.regexp_disjunction = function(state) {
  var trackDisjunction = this.options.ecmaVersion >= 16;
  if (trackDisjunction) { state.branchID = new BranchID(state.branchID, null); }
  this.regexp_alternative(state);
  while (state.eat(0x7C /* | */)) {
    if (trackDisjunction) { state.branchID = state.branchID.sibling(); }
    this.regexp_alternative(state);
  }
  if (trackDisjunction) { state.branchID = state.branchID.parent; }

  // Make the same message as V8.
  if (this.regexp_eatQuantifier(state, true)) {
    state.raise("Nothing to repeat");
  }
  if (state.eat(0x7B /* { */)) {
    state.raise("Lone quantifier brackets");
  }
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-Alternative
pp$1.regexp_alternative = function(state) {
  while (state.pos < state.source.length && this.regexp_eatTerm(state)) {}
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-Term
pp$1.regexp_eatTerm = function(state) {
  if (this.regexp_eatAssertion(state)) {
    // Handle `QuantifiableAssertion Quantifier` alternative.
    // `state.lastAssertionIsQuantifiable` is true if the last eaten Assertion
    // is a QuantifiableAssertion.
    if (state.lastAssertionIsQuantifiable && this.regexp_eatQuantifier(state)) {
      // Make the same message as V8.
      if (state.switchU) {
        state.raise("Invalid quantifier");
      }
    }
    return true
  }

  if (state.switchU ? this.regexp_eatAtom(state) : this.regexp_eatExtendedAtom(state)) {
    this.regexp_eatQuantifier(state);
    return true
  }

  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-Assertion
pp$1.regexp_eatAssertion = function(state) {
  var start = state.pos;
  state.lastAssertionIsQuantifiable = false;

  // ^, $
  if (state.eat(0x5E /* ^ */) || state.eat(0x24 /* $ */)) {
    return true
  }

  // \b \B
  if (state.eat(0x5C /* \ */)) {
    if (state.eat(0x42 /* B */) || state.eat(0x62 /* b */)) {
      return true
    }
    state.pos = start;
  }

  // Lookahead / Lookbehind
  if (state.eat(0x28 /* ( */) && state.eat(0x3F /* ? */)) {
    var lookbehind = false;
    if (this.options.ecmaVersion >= 9) {
      lookbehind = state.eat(0x3C /* < */);
    }
    if (state.eat(0x3D /* = */) || state.eat(0x21 /* ! */)) {
      this.regexp_disjunction(state);
      if (!state.eat(0x29 /* ) */)) {
        state.raise("Unterminated group");
      }
      state.lastAssertionIsQuantifiable = !lookbehind;
      return true
    }
  }

  state.pos = start;
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-Quantifier
pp$1.regexp_eatQuantifier = function(state, noError) {
  if ( noError === void 0 ) noError = false;

  if (this.regexp_eatQuantifierPrefix(state, noError)) {
    state.eat(0x3F /* ? */);
    return true
  }
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-QuantifierPrefix
pp$1.regexp_eatQuantifierPrefix = function(state, noError) {
  return (
    state.eat(0x2A /* * */) ||
    state.eat(0x2B /* + */) ||
    state.eat(0x3F /* ? */) ||
    this.regexp_eatBracedQuantifier(state, noError)
  )
};
pp$1.regexp_eatBracedQuantifier = function(state, noError) {
  var start = state.pos;
  if (state.eat(0x7B /* { */)) {
    var min = 0, max = -1;
    if (this.regexp_eatDecimalDigits(state)) {
      min = state.lastIntValue;
      if (state.eat(0x2C /* , */) && this.regexp_eatDecimalDigits(state)) {
        max = state.lastIntValue;
      }
      if (state.eat(0x7D /* } */)) {
        // SyntaxError in https://www.ecma-international.org/ecma-262/8.0/#sec-term
        if (max !== -1 && max < min && !noError) {
          state.raise("numbers out of order in {} quantifier");
        }
        return true
      }
    }
    if (state.switchU && !noError) {
      state.raise("Incomplete quantifier");
    }
    state.pos = start;
  }
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-Atom
pp$1.regexp_eatAtom = function(state) {
  return (
    this.regexp_eatPatternCharacters(state) ||
    state.eat(0x2E /* . */) ||
    this.regexp_eatReverseSolidusAtomEscape(state) ||
    this.regexp_eatCharacterClass(state) ||
    this.regexp_eatUncapturingGroup(state) ||
    this.regexp_eatCapturingGroup(state)
  )
};
pp$1.regexp_eatReverseSolidusAtomEscape = function(state) {
  var start = state.pos;
  if (state.eat(0x5C /* \ */)) {
    if (this.regexp_eatAtomEscape(state)) {
      return true
    }
    state.pos = start;
  }
  return false
};
pp$1.regexp_eatUncapturingGroup = function(state) {
  var start = state.pos;
  if (state.eat(0x28 /* ( */)) {
    if (state.eat(0x3F /* ? */)) {
      if (this.options.ecmaVersion >= 16) {
        var addModifiers = this.regexp_eatModifiers(state);
        var hasHyphen = state.eat(0x2D /* - */);
        if (addModifiers || hasHyphen) {
          for (var i = 0; i < addModifiers.length; i++) {
            var modifier = addModifiers.charAt(i);
            if (addModifiers.indexOf(modifier, i + 1) > -1) {
              state.raise("Duplicate regular expression modifiers");
            }
          }
          if (hasHyphen) {
            var removeModifiers = this.regexp_eatModifiers(state);
            if (!addModifiers && !removeModifiers && state.current() === 0x3A /* : */) {
              state.raise("Invalid regular expression modifiers");
            }
            for (var i$1 = 0; i$1 < removeModifiers.length; i$1++) {
              var modifier$1 = removeModifiers.charAt(i$1);
              if (
                removeModifiers.indexOf(modifier$1, i$1 + 1) > -1 ||
                addModifiers.indexOf(modifier$1) > -1
              ) {
                state.raise("Duplicate regular expression modifiers");
              }
            }
          }
        }
      }
      if (state.eat(0x3A /* : */)) {
        this.regexp_disjunction(state);
        if (state.eat(0x29 /* ) */)) {
          return true
        }
        state.raise("Unterminated group");
      }
    }
    state.pos = start;
  }
  return false
};
pp$1.regexp_eatCapturingGroup = function(state) {
  if (state.eat(0x28 /* ( */)) {
    if (this.options.ecmaVersion >= 9) {
      this.regexp_groupSpecifier(state);
    } else if (state.current() === 0x3F /* ? */) {
      state.raise("Invalid group");
    }
    this.regexp_disjunction(state);
    if (state.eat(0x29 /* ) */)) {
      state.numCapturingParens += 1;
      return true
    }
    state.raise("Unterminated group");
  }
  return false
};
// RegularExpressionModifiers ::
//   [empty]
//   RegularExpressionModifiers RegularExpressionModifier
pp$1.regexp_eatModifiers = function(state) {
  var modifiers = "";
  var ch = 0;
  while ((ch = state.current()) !== -1 && isRegularExpressionModifier(ch)) {
    modifiers += codePointToString(ch);
    state.advance();
  }
  return modifiers
};
// RegularExpressionModifier :: one of
//   `i` `m` `s`
function isRegularExpressionModifier(ch) {
  return ch === 0x69 /* i */ || ch === 0x6d /* m */ || ch === 0x73 /* s */
}

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-ExtendedAtom
pp$1.regexp_eatExtendedAtom = function(state) {
  return (
    state.eat(0x2E /* . */) ||
    this.regexp_eatReverseSolidusAtomEscape(state) ||
    this.regexp_eatCharacterClass(state) ||
    this.regexp_eatUncapturingGroup(state) ||
    this.regexp_eatCapturingGroup(state) ||
    this.regexp_eatInvalidBracedQuantifier(state) ||
    this.regexp_eatExtendedPatternCharacter(state)
  )
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-InvalidBracedQuantifier
pp$1.regexp_eatInvalidBracedQuantifier = function(state) {
  if (this.regexp_eatBracedQuantifier(state, true)) {
    state.raise("Nothing to repeat");
  }
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-SyntaxCharacter
pp$1.regexp_eatSyntaxCharacter = function(state) {
  var ch = state.current();
  if (isSyntaxCharacter(ch)) {
    state.lastIntValue = ch;
    state.advance();
    return true
  }
  return false
};
function isSyntaxCharacter(ch) {
  return (
    ch === 0x24 /* $ */ ||
    ch >= 0x28 /* ( */ && ch <= 0x2B /* + */ ||
    ch === 0x2E /* . */ ||
    ch === 0x3F /* ? */ ||
    ch >= 0x5B /* [ */ && ch <= 0x5E /* ^ */ ||
    ch >= 0x7B /* { */ && ch <= 0x7D /* } */
  )
}

// https://www.ecma-international.org/ecma-262/8.0/#prod-PatternCharacter
// But eat eager.
pp$1.regexp_eatPatternCharacters = function(state) {
  var start = state.pos;
  var ch = 0;
  while ((ch = state.current()) !== -1 && !isSyntaxCharacter(ch)) {
    state.advance();
  }
  return state.pos !== start
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-ExtendedPatternCharacter
pp$1.regexp_eatExtendedPatternCharacter = function(state) {
  var ch = state.current();
  if (
    ch !== -1 &&
    ch !== 0x24 /* $ */ &&
    !(ch >= 0x28 /* ( */ && ch <= 0x2B /* + */) &&
    ch !== 0x2E /* . */ &&
    ch !== 0x3F /* ? */ &&
    ch !== 0x5B /* [ */ &&
    ch !== 0x5E /* ^ */ &&
    ch !== 0x7C /* | */
  ) {
    state.advance();
    return true
  }
  return false
};

// GroupSpecifier ::
//   [empty]
//   `?` GroupName
pp$1.regexp_groupSpecifier = function(state) {
  if (state.eat(0x3F /* ? */)) {
    if (!this.regexp_eatGroupName(state)) { state.raise("Invalid group"); }
    var trackDisjunction = this.options.ecmaVersion >= 16;
    var known = state.groupNames[state.lastStringValue];
    if (known) {
      if (trackDisjunction) {
        for (var i = 0, list = known; i < list.length; i += 1) {
          var altID = list[i];

          if (!altID.separatedFrom(state.branchID))
            { state.raise("Duplicate capture group name"); }
        }
      } else {
        state.raise("Duplicate capture group name");
      }
    }
    if (trackDisjunction) {
      (known || (state.groupNames[state.lastStringValue] = [])).push(state.branchID);
    } else {
      state.groupNames[state.lastStringValue] = true;
    }
  }
};

// GroupName ::
//   `<` RegExpIdentifierName `>`
// Note: this updates `state.lastStringValue` property with the eaten name.
pp$1.regexp_eatGroupName = function(state) {
  state.lastStringValue = "";
  if (state.eat(0x3C /* < */)) {
    if (this.regexp_eatRegExpIdentifierName(state) && state.eat(0x3E /* > */)) {
      return true
    }
    state.raise("Invalid capture group name");
  }
  return false
};

// RegExpIdentifierName ::
//   RegExpIdentifierStart
//   RegExpIdentifierName RegExpIdentifierPart
// Note: this updates `state.lastStringValue` property with the eaten name.
pp$1.regexp_eatRegExpIdentifierName = function(state) {
  state.lastStringValue = "";
  if (this.regexp_eatRegExpIdentifierStart(state)) {
    state.lastStringValue += codePointToString(state.lastIntValue);
    while (this.regexp_eatRegExpIdentifierPart(state)) {
      state.lastStringValue += codePointToString(state.lastIntValue);
    }
    return true
  }
  return false
};

// RegExpIdentifierStart ::
//   UnicodeIDStart
//   `$`
//   `_`
//   `\` RegExpUnicodeEscapeSequence[+U]
pp$1.regexp_eatRegExpIdentifierStart = function(state) {
  var start = state.pos;
  var forceU = this.options.ecmaVersion >= 11;
  var ch = state.current(forceU);
  state.advance(forceU);

  if (ch === 0x5C /* \ */ && this.regexp_eatRegExpUnicodeEscapeSequence(state, forceU)) {
    ch = state.lastIntValue;
  }
  if (isRegExpIdentifierStart(ch)) {
    state.lastIntValue = ch;
    return true
  }

  state.pos = start;
  return false
};
function isRegExpIdentifierStart(ch) {
  return isIdentifierStart(ch, true) || ch === 0x24 /* $ */ || ch === 0x5F /* _ */
}

// RegExpIdentifierPart ::
//   UnicodeIDContinue
//   `$`
//   `_`
//   `\` RegExpUnicodeEscapeSequence[+U]
//   <ZWNJ>
//   <ZWJ>
pp$1.regexp_eatRegExpIdentifierPart = function(state) {
  var start = state.pos;
  var forceU = this.options.ecmaVersion >= 11;
  var ch = state.current(forceU);
  state.advance(forceU);

  if (ch === 0x5C /* \ */ && this.regexp_eatRegExpUnicodeEscapeSequence(state, forceU)) {
    ch = state.lastIntValue;
  }
  if (isRegExpIdentifierPart(ch)) {
    state.lastIntValue = ch;
    return true
  }

  state.pos = start;
  return false
};
function isRegExpIdentifierPart(ch) {
  return isIdentifierChar(ch, true) || ch === 0x24 /* $ */ || ch === 0x5F /* _ */ || ch === 0x200C /* <ZWNJ> */ || ch === 0x200D /* <ZWJ> */
}

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-AtomEscape
pp$1.regexp_eatAtomEscape = function(state) {
  if (
    this.regexp_eatBackReference(state) ||
    this.regexp_eatCharacterClassEscape(state) ||
    this.regexp_eatCharacterEscape(state) ||
    (state.switchN && this.regexp_eatKGroupName(state))
  ) {
    return true
  }
  if (state.switchU) {
    // Make the same message as V8.
    if (state.current() === 0x63 /* c */) {
      state.raise("Invalid unicode escape");
    }
    state.raise("Invalid escape");
  }
  return false
};
pp$1.regexp_eatBackReference = function(state) {
  var start = state.pos;
  if (this.regexp_eatDecimalEscape(state)) {
    var n = state.lastIntValue;
    if (state.switchU) {
      // For SyntaxError in https://www.ecma-international.org/ecma-262/8.0/#sec-atomescape
      if (n > state.maxBackReference) {
        state.maxBackReference = n;
      }
      return true
    }
    if (n <= state.numCapturingParens) {
      return true
    }
    state.pos = start;
  }
  return false
};
pp$1.regexp_eatKGroupName = function(state) {
  if (state.eat(0x6B /* k */)) {
    if (this.regexp_eatGroupName(state)) {
      state.backReferenceNames.push(state.lastStringValue);
      return true
    }
    state.raise("Invalid named reference");
  }
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-CharacterEscape
pp$1.regexp_eatCharacterEscape = function(state) {
  return (
    this.regexp_eatControlEscape(state) ||
    this.regexp_eatCControlLetter(state) ||
    this.regexp_eatZero(state) ||
    this.regexp_eatHexEscapeSequence(state) ||
    this.regexp_eatRegExpUnicodeEscapeSequence(state, false) ||
    (!state.switchU && this.regexp_eatLegacyOctalEscapeSequence(state)) ||
    this.regexp_eatIdentityEscape(state)
  )
};
pp$1.regexp_eatCControlLetter = function(state) {
  var start = state.pos;
  if (state.eat(0x63 /* c */)) {
    if (this.regexp_eatControlLetter(state)) {
      return true
    }
    state.pos = start;
  }
  return false
};
pp$1.regexp_eatZero = function(state) {
  if (state.current() === 0x30 /* 0 */ && !isDecimalDigit(state.lookahead())) {
    state.lastIntValue = 0;
    state.advance();
    return true
  }
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-ControlEscape
pp$1.regexp_eatControlEscape = function(state) {
  var ch = state.current();
  if (ch === 0x74 /* t */) {
    state.lastIntValue = 0x09; /* \t */
    state.advance();
    return true
  }
  if (ch === 0x6E /* n */) {
    state.lastIntValue = 0x0A; /* \n */
    state.advance();
    return true
  }
  if (ch === 0x76 /* v */) {
    state.lastIntValue = 0x0B; /* \v */
    state.advance();
    return true
  }
  if (ch === 0x66 /* f */) {
    state.lastIntValue = 0x0C; /* \f */
    state.advance();
    return true
  }
  if (ch === 0x72 /* r */) {
    state.lastIntValue = 0x0D; /* \r */
    state.advance();
    return true
  }
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-ControlLetter
pp$1.regexp_eatControlLetter = function(state) {
  var ch = state.current();
  if (isControlLetter(ch)) {
    state.lastIntValue = ch % 0x20;
    state.advance();
    return true
  }
  return false
};
function isControlLetter(ch) {
  return (
    (ch >= 0x41 /* A */ && ch <= 0x5A /* Z */) ||
    (ch >= 0x61 /* a */ && ch <= 0x7A /* z */)
  )
}

// https://www.ecma-international.org/ecma-262/8.0/#prod-RegExpUnicodeEscapeSequence
pp$1.regexp_eatRegExpUnicodeEscapeSequence = function(state, forceU) {
  if ( forceU === void 0 ) forceU = false;

  var start = state.pos;
  var switchU = forceU || state.switchU;

  if (state.eat(0x75 /* u */)) {
    if (this.regexp_eatFixedHexDigits(state, 4)) {
      var lead = state.lastIntValue;
      if (switchU && lead >= 0xD800 && lead <= 0xDBFF) {
        var leadSurrogateEnd = state.pos;
        if (state.eat(0x5C /* \ */) && state.eat(0x75 /* u */) && this.regexp_eatFixedHexDigits(state, 4)) {
          var trail = state.lastIntValue;
          if (trail >= 0xDC00 && trail <= 0xDFFF) {
            state.lastIntValue = (lead - 0xD800) * 0x400 + (trail - 0xDC00) + 0x10000;
            return true
          }
        }
        state.pos = leadSurrogateEnd;
        state.lastIntValue = lead;
      }
      return true
    }
    if (
      switchU &&
      state.eat(0x7B /* { */) &&
      this.regexp_eatHexDigits(state) &&
      state.eat(0x7D /* } */) &&
      isValidUnicode(state.lastIntValue)
    ) {
      return true
    }
    if (switchU) {
      state.raise("Invalid unicode escape");
    }
    state.pos = start;
  }

  return false
};
function isValidUnicode(ch) {
  return ch >= 0 && ch <= 0x10FFFF
}

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-IdentityEscape
pp$1.regexp_eatIdentityEscape = function(state) {
  if (state.switchU) {
    if (this.regexp_eatSyntaxCharacter(state)) {
      return true
    }
    if (state.eat(0x2F /* / */)) {
      state.lastIntValue = 0x2F; /* / */
      return true
    }
    return false
  }

  var ch = state.current();
  if (ch !== 0x63 /* c */ && (!state.switchN || ch !== 0x6B /* k */)) {
    state.lastIntValue = ch;
    state.advance();
    return true
  }

  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-DecimalEscape
pp$1.regexp_eatDecimalEscape = function(state) {
  state.lastIntValue = 0;
  var ch = state.current();
  if (ch >= 0x31 /* 1 */ && ch <= 0x39 /* 9 */) {
    do {
      state.lastIntValue = 10 * state.lastIntValue + (ch - 0x30 /* 0 */);
      state.advance();
    } while ((ch = state.current()) >= 0x30 /* 0 */ && ch <= 0x39 /* 9 */)
    return true
  }
  return false
};

// Return values used by character set parsing methods, needed to
// forbid negation of sets that can match strings.
var CharSetNone = 0; // Nothing parsed
var CharSetOk = 1; // Construct parsed, cannot contain strings
var CharSetString = 2; // Construct parsed, can contain strings

// https://www.ecma-international.org/ecma-262/8.0/#prod-CharacterClassEscape
pp$1.regexp_eatCharacterClassEscape = function(state) {
  var ch = state.current();

  if (isCharacterClassEscape(ch)) {
    state.lastIntValue = -1;
    state.advance();
    return CharSetOk
  }

  var negate = false;
  if (
    state.switchU &&
    this.options.ecmaVersion >= 9 &&
    ((negate = ch === 0x50 /* P */) || ch === 0x70 /* p */)
  ) {
    state.lastIntValue = -1;
    state.advance();
    var result;
    if (
      state.eat(0x7B /* { */) &&
      (result = this.regexp_eatUnicodePropertyValueExpression(state)) &&
      state.eat(0x7D /* } */)
    ) {
      if (negate && result === CharSetString) { state.raise("Invalid property name"); }
      return result
    }
    state.raise("Invalid property name");
  }

  return CharSetNone
};

function isCharacterClassEscape(ch) {
  return (
    ch === 0x64 /* d */ ||
    ch === 0x44 /* D */ ||
    ch === 0x73 /* s */ ||
    ch === 0x53 /* S */ ||
    ch === 0x77 /* w */ ||
    ch === 0x57 /* W */
  )
}

// UnicodePropertyValueExpression ::
//   UnicodePropertyName `=` UnicodePropertyValue
//   LoneUnicodePropertyNameOrValue
pp$1.regexp_eatUnicodePropertyValueExpression = function(state) {
  var start = state.pos;

  // UnicodePropertyName `=` UnicodePropertyValue
  if (this.regexp_eatUnicodePropertyName(state) && state.eat(0x3D /* = */)) {
    var name = state.lastStringValue;
    if (this.regexp_eatUnicodePropertyValue(state)) {
      var value = state.lastStringValue;
      this.regexp_validateUnicodePropertyNameAndValue(state, name, value);
      return CharSetOk
    }
  }
  state.pos = start;

  // LoneUnicodePropertyNameOrValue
  if (this.regexp_eatLoneUnicodePropertyNameOrValue(state)) {
    var nameOrValue = state.lastStringValue;
    return this.regexp_validateUnicodePropertyNameOrValue(state, nameOrValue)
  }
  return CharSetNone
};

pp$1.regexp_validateUnicodePropertyNameAndValue = function(state, name, value) {
  if (!hasOwn(state.unicodeProperties.nonBinary, name))
    { state.raise("Invalid property name"); }
  if (!state.unicodeProperties.nonBinary[name].test(value))
    { state.raise("Invalid property value"); }
};

pp$1.regexp_validateUnicodePropertyNameOrValue = function(state, nameOrValue) {
  if (state.unicodeProperties.binary.test(nameOrValue)) { return CharSetOk }
  if (state.switchV && state.unicodeProperties.binaryOfStrings.test(nameOrValue)) { return CharSetString }
  state.raise("Invalid property name");
};

// UnicodePropertyName ::
//   UnicodePropertyNameCharacters
pp$1.regexp_eatUnicodePropertyName = function(state) {
  var ch = 0;
  state.lastStringValue = "";
  while (isUnicodePropertyNameCharacter(ch = state.current())) {
    state.lastStringValue += codePointToString(ch);
    state.advance();
  }
  return state.lastStringValue !== ""
};

function isUnicodePropertyNameCharacter(ch) {
  return isControlLetter(ch) || ch === 0x5F /* _ */
}

// UnicodePropertyValue ::
//   UnicodePropertyValueCharacters
pp$1.regexp_eatUnicodePropertyValue = function(state) {
  var ch = 0;
  state.lastStringValue = "";
  while (isUnicodePropertyValueCharacter(ch = state.current())) {
    state.lastStringValue += codePointToString(ch);
    state.advance();
  }
  return state.lastStringValue !== ""
};
function isUnicodePropertyValueCharacter(ch) {
  return isUnicodePropertyNameCharacter(ch) || isDecimalDigit(ch)
}

// LoneUnicodePropertyNameOrValue ::
//   UnicodePropertyValueCharacters
pp$1.regexp_eatLoneUnicodePropertyNameOrValue = function(state) {
  return this.regexp_eatUnicodePropertyValue(state)
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-CharacterClass
pp$1.regexp_eatCharacterClass = function(state) {
  if (state.eat(0x5B /* [ */)) {
    var negate = state.eat(0x5E /* ^ */);
    var result = this.regexp_classContents(state);
    if (!state.eat(0x5D /* ] */))
      { state.raise("Unterminated character class"); }
    if (negate && result === CharSetString)
      { state.raise("Negated character class may contain strings"); }
    return true
  }
  return false
};

// https://tc39.es/ecma262/#prod-ClassContents
// https://www.ecma-international.org/ecma-262/8.0/#prod-ClassRanges
pp$1.regexp_classContents = function(state) {
  if (state.current() === 0x5D /* ] */) { return CharSetOk }
  if (state.switchV) { return this.regexp_classSetExpression(state) }
  this.regexp_nonEmptyClassRanges(state);
  return CharSetOk
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-NonemptyClassRanges
// https://www.ecma-international.org/ecma-262/8.0/#prod-NonemptyClassRangesNoDash
pp$1.regexp_nonEmptyClassRanges = function(state) {
  while (this.regexp_eatClassAtom(state)) {
    var left = state.lastIntValue;
    if (state.eat(0x2D /* - */) && this.regexp_eatClassAtom(state)) {
      var right = state.lastIntValue;
      if (state.switchU && (left === -1 || right === -1)) {
        state.raise("Invalid character class");
      }
      if (left !== -1 && right !== -1 && left > right) {
        state.raise("Range out of order in character class");
      }
    }
  }
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-ClassAtom
// https://www.ecma-international.org/ecma-262/8.0/#prod-ClassAtomNoDash
pp$1.regexp_eatClassAtom = function(state) {
  var start = state.pos;

  if (state.eat(0x5C /* \ */)) {
    if (this.regexp_eatClassEscape(state)) {
      return true
    }
    if (state.switchU) {
      // Make the same message as V8.
      var ch$1 = state.current();
      if (ch$1 === 0x63 /* c */ || isOctalDigit(ch$1)) {
        state.raise("Invalid class escape");
      }
      state.raise("Invalid escape");
    }
    state.pos = start;
  }

  var ch = state.current();
  if (ch !== 0x5D /* ] */) {
    state.lastIntValue = ch;
    state.advance();
    return true
  }

  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-ClassEscape
pp$1.regexp_eatClassEscape = function(state) {
  var start = state.pos;

  if (state.eat(0x62 /* b */)) {
    state.lastIntValue = 0x08; /* <BS> */
    return true
  }

  if (state.switchU && state.eat(0x2D /* - */)) {
    state.lastIntValue = 0x2D; /* - */
    return true
  }

  if (!state.switchU && state.eat(0x63 /* c */)) {
    if (this.regexp_eatClassControlLetter(state)) {
      return true
    }
    state.pos = start;
  }

  return (
    this.regexp_eatCharacterClassEscape(state) ||
    this.regexp_eatCharacterEscape(state)
  )
};

// https://tc39.es/ecma262/#prod-ClassSetExpression
// https://tc39.es/ecma262/#prod-ClassUnion
// https://tc39.es/ecma262/#prod-ClassIntersection
// https://tc39.es/ecma262/#prod-ClassSubtraction
pp$1.regexp_classSetExpression = function(state) {
  var result = CharSetOk, subResult;
  if (this.regexp_eatClassSetRange(state)) ; else if (subResult = this.regexp_eatClassSetOperand(state)) {
    if (subResult === CharSetString) { result = CharSetString; }
    // https://tc39.es/ecma262/#prod-ClassIntersection
    var start = state.pos;
    while (state.eatChars([0x26, 0x26] /* && */)) {
      if (
        state.current() !== 0x26 /* & */ &&
        (subResult = this.regexp_eatClassSetOperand(state))
      ) {
        if (subResult !== CharSetString) { result = CharSetOk; }
        continue
      }
      state.raise("Invalid character in character class");
    }
    if (start !== state.pos) { return result }
    // https://tc39.es/ecma262/#prod-ClassSubtraction
    while (state.eatChars([0x2D, 0x2D] /* -- */)) {
      if (this.regexp_eatClassSetOperand(state)) { continue }
      state.raise("Invalid character in character class");
    }
    if (start !== state.pos) { return result }
  } else {
    state.raise("Invalid character in character class");
  }
  // https://tc39.es/ecma262/#prod-ClassUnion
  for (;;) {
    if (this.regexp_eatClassSetRange(state)) { continue }
    subResult = this.regexp_eatClassSetOperand(state);
    if (!subResult) { return result }
    if (subResult === CharSetString) { result = CharSetString; }
  }
};

// https://tc39.es/ecma262/#prod-ClassSetRange
pp$1.regexp_eatClassSetRange = function(state) {
  var start = state.pos;
  if (this.regexp_eatClassSetCharacter(state)) {
    var left = state.lastIntValue;
    if (state.eat(0x2D /* - */) && this.regexp_eatClassSetCharacter(state)) {
      var right = state.lastIntValue;
      if (left !== -1 && right !== -1 && left > right) {
        state.raise("Range out of order in character class");
      }
      return true
    }
    state.pos = start;
  }
  return false
};

// https://tc39.es/ecma262/#prod-ClassSetOperand
pp$1.regexp_eatClassSetOperand = function(state) {
  if (this.regexp_eatClassSetCharacter(state)) { return CharSetOk }
  return this.regexp_eatClassStringDisjunction(state) || this.regexp_eatNestedClass(state)
};

// https://tc39.es/ecma262/#prod-NestedClass
pp$1.regexp_eatNestedClass = function(state) {
  var start = state.pos;
  if (state.eat(0x5B /* [ */)) {
    var negate = state.eat(0x5E /* ^ */);
    var result = this.regexp_classContents(state);
    if (state.eat(0x5D /* ] */)) {
      if (negate && result === CharSetString) {
        state.raise("Negated character class may contain strings");
      }
      return result
    }
    state.pos = start;
  }
  if (state.eat(0x5C /* \ */)) {
    var result$1 = this.regexp_eatCharacterClassEscape(state);
    if (result$1) {
      return result$1
    }
    state.pos = start;
  }
  return null
};

// https://tc39.es/ecma262/#prod-ClassStringDisjunction
pp$1.regexp_eatClassStringDisjunction = function(state) {
  var start = state.pos;
  if (state.eatChars([0x5C, 0x71] /* \q */)) {
    if (state.eat(0x7B /* { */)) {
      var result = this.regexp_classStringDisjunctionContents(state);
      if (state.eat(0x7D /* } */)) {
        return result
      }
    } else {
      // Make the same message as V8.
      state.raise("Invalid escape");
    }
    state.pos = start;
  }
  return null
};

// https://tc39.es/ecma262/#prod-ClassStringDisjunctionContents
pp$1.regexp_classStringDisjunctionContents = function(state) {
  var result = this.regexp_classString(state);
  while (state.eat(0x7C /* | */)) {
    if (this.regexp_classString(state) === CharSetString) { result = CharSetString; }
  }
  return result
};

// https://tc39.es/ecma262/#prod-ClassString
// https://tc39.es/ecma262/#prod-NonEmptyClassString
pp$1.regexp_classString = function(state) {
  var count = 0;
  while (this.regexp_eatClassSetCharacter(state)) { count++; }
  return count === 1 ? CharSetOk : CharSetString
};

// https://tc39.es/ecma262/#prod-ClassSetCharacter
pp$1.regexp_eatClassSetCharacter = function(state) {
  var start = state.pos;
  if (state.eat(0x5C /* \ */)) {
    if (
      this.regexp_eatCharacterEscape(state) ||
      this.regexp_eatClassSetReservedPunctuator(state)
    ) {
      return true
    }
    if (state.eat(0x62 /* b */)) {
      state.lastIntValue = 0x08; /* <BS> */
      return true
    }
    state.pos = start;
    return false
  }
  var ch = state.current();
  if (ch < 0 || ch === state.lookahead() && isClassSetReservedDoublePunctuatorCharacter(ch)) { return false }
  if (isClassSetSyntaxCharacter(ch)) { return false }
  state.advance();
  state.lastIntValue = ch;
  return true
};

// https://tc39.es/ecma262/#prod-ClassSetReservedDoublePunctuator
function isClassSetReservedDoublePunctuatorCharacter(ch) {
  return (
    ch === 0x21 /* ! */ ||
    ch >= 0x23 /* # */ && ch <= 0x26 /* & */ ||
    ch >= 0x2A /* * */ && ch <= 0x2C /* , */ ||
    ch === 0x2E /* . */ ||
    ch >= 0x3A /* : */ && ch <= 0x40 /* @ */ ||
    ch === 0x5E /* ^ */ ||
    ch === 0x60 /* ` */ ||
    ch === 0x7E /* ~ */
  )
}

// https://tc39.es/ecma262/#prod-ClassSetSyntaxCharacter
function isClassSetSyntaxCharacter(ch) {
  return (
    ch === 0x28 /* ( */ ||
    ch === 0x29 /* ) */ ||
    ch === 0x2D /* - */ ||
    ch === 0x2F /* / */ ||
    ch >= 0x5B /* [ */ && ch <= 0x5D /* ] */ ||
    ch >= 0x7B /* { */ && ch <= 0x7D /* } */
  )
}

// https://tc39.es/ecma262/#prod-ClassSetReservedPunctuator
pp$1.regexp_eatClassSetReservedPunctuator = function(state) {
  var ch = state.current();
  if (isClassSetReservedPunctuator(ch)) {
    state.lastIntValue = ch;
    state.advance();
    return true
  }
  return false
};

// https://tc39.es/ecma262/#prod-ClassSetReservedPunctuator
function isClassSetReservedPunctuator(ch) {
  return (
    ch === 0x21 /* ! */ ||
    ch === 0x23 /* # */ ||
    ch === 0x25 /* % */ ||
    ch === 0x26 /* & */ ||
    ch === 0x2C /* , */ ||
    ch === 0x2D /* - */ ||
    ch >= 0x3A /* : */ && ch <= 0x3E /* > */ ||
    ch === 0x40 /* @ */ ||
    ch === 0x60 /* ` */ ||
    ch === 0x7E /* ~ */
  )
}

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-ClassControlLetter
pp$1.regexp_eatClassControlLetter = function(state) {
  var ch = state.current();
  if (isDecimalDigit(ch) || ch === 0x5F /* _ */) {
    state.lastIntValue = ch % 0x20;
    state.advance();
    return true
  }
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-HexEscapeSequence
pp$1.regexp_eatHexEscapeSequence = function(state) {
  var start = state.pos;
  if (state.eat(0x78 /* x */)) {
    if (this.regexp_eatFixedHexDigits(state, 2)) {
      return true
    }
    if (state.switchU) {
      state.raise("Invalid escape");
    }
    state.pos = start;
  }
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-DecimalDigits
pp$1.regexp_eatDecimalDigits = function(state) {
  var start = state.pos;
  var ch = 0;
  state.lastIntValue = 0;
  while (isDecimalDigit(ch = state.current())) {
    state.lastIntValue = 10 * state.lastIntValue + (ch - 0x30 /* 0 */);
    state.advance();
  }
  return state.pos !== start
};
function isDecimalDigit(ch) {
  return ch >= 0x30 /* 0 */ && ch <= 0x39 /* 9 */
}

// https://www.ecma-international.org/ecma-262/8.0/#prod-HexDigits
pp$1.regexp_eatHexDigits = function(state) {
  var start = state.pos;
  var ch = 0;
  state.lastIntValue = 0;
  while (isHexDigit(ch = state.current())) {
    state.lastIntValue = 16 * state.lastIntValue + hexToInt(ch);
    state.advance();
  }
  return state.pos !== start
};
function isHexDigit(ch) {
  return (
    (ch >= 0x30 /* 0 */ && ch <= 0x39 /* 9 */) ||
    (ch >= 0x41 /* A */ && ch <= 0x46 /* F */) ||
    (ch >= 0x61 /* a */ && ch <= 0x66 /* f */)
  )
}
function hexToInt(ch) {
  if (ch >= 0x41 /* A */ && ch <= 0x46 /* F */) {
    return 10 + (ch - 0x41 /* A */)
  }
  if (ch >= 0x61 /* a */ && ch <= 0x66 /* f */) {
    return 10 + (ch - 0x61 /* a */)
  }
  return ch - 0x30 /* 0 */
}

// https://www.ecma-international.org/ecma-262/8.0/#prod-annexB-LegacyOctalEscapeSequence
// Allows only 0-377(octal) i.e. 0-255(decimal).
pp$1.regexp_eatLegacyOctalEscapeSequence = function(state) {
  if (this.regexp_eatOctalDigit(state)) {
    var n1 = state.lastIntValue;
    if (this.regexp_eatOctalDigit(state)) {
      var n2 = state.lastIntValue;
      if (n1 <= 3 && this.regexp_eatOctalDigit(state)) {
        state.lastIntValue = n1 * 64 + n2 * 8 + state.lastIntValue;
      } else {
        state.lastIntValue = n1 * 8 + n2;
      }
    } else {
      state.lastIntValue = n1;
    }
    return true
  }
  return false
};

// https://www.ecma-international.org/ecma-262/8.0/#prod-OctalDigit
pp$1.regexp_eatOctalDigit = function(state) {
  var ch = state.current();
  if (isOctalDigit(ch)) {
    state.lastIntValue = ch - 0x30; /* 0 */
    state.advance();
    return true
  }
  state.lastIntValue = 0;
  return false
};
function isOctalDigit(ch) {
  return ch >= 0x30 /* 0 */ && ch <= 0x37 /* 7 */
}

// https://www.ecma-international.org/ecma-262/8.0/#prod-Hex4Digits
// https://www.ecma-international.org/ecma-262/8.0/#prod-HexDigit
// And HexDigit HexDigit in https://www.ecma-international.org/ecma-262/8.0/#prod-HexEscapeSequence
pp$1.regexp_eatFixedHexDigits = function(state, length) {
  var start = state.pos;
  state.lastIntValue = 0;
  for (var i = 0; i < length; ++i) {
    var ch = state.current();
    if (!isHexDigit(ch)) {
      state.pos = start;
      return false
    }
    state.lastIntValue = 16 * state.lastIntValue + hexToInt(ch);
    state.advance();
  }
  return true
};

// Object type used to represent tokens. Note that normally, tokens
// simply exist as properties on the parser object. This is only
// used for the onToken callback and the external tokenizer.

var Token = function Token(p) {
  this.type = p.type;
  this.value = p.value;
  this.start = p.start;
  this.end = p.end;
  if (p.options.locations)
    { this.loc = new SourceLocation(p, p.startLoc, p.endLoc); }
  if (p.options.ranges)
    { this.range = [p.start, p.end]; }
};

// ## Tokenizer

var pp = Parser.prototype;

// Move to the next token

pp.next = function(ignoreEscapeSequenceInKeyword) {
  if (!ignoreEscapeSequenceInKeyword && this.type.keyword && this.containsEsc)
    { this.raiseRecoverable(this.start, "Escape sequence in keyword " + this.type.keyword); }
  if (this.options.onToken)
    { this.options.onToken(new Token(this)); }

  this.lastTokEnd = this.end;
  this.lastTokStart = this.start;
  this.lastTokEndLoc = this.endLoc;
  this.lastTokStartLoc = this.startLoc;
  this.nextToken();
};

pp.getToken = function() {
  this.next();
  return new Token(this)
};

// If we're in an ES6 environment, make parsers iterable
if (typeof Symbol !== "undefined")
  { pp[Symbol.iterator] = function() {
    var this$1$1 = this;

    return {
      next: function () {
        var token = this$1$1.getToken();
        return {
          done: token.type === types$1.eof,
          value: token
        }
      }
    }
  }; }

// Toggle strict mode. Re-reads the next number or string to please
// pedantic tests (`"use strict"; 010;` should fail).

// Read a single token, updating the parser object's token-related
// properties.

pp.nextToken = function() {
  var curContext = this.curContext();
  if (!curContext || !curContext.preserveSpace) { this.skipSpace(); }

  this.start = this.pos;
  if (this.options.locations) { this.startLoc = this.curPosition(); }
  if (this.pos >= this.input.length) { return this.finishToken(types$1.eof) }

  if (curContext.override) { return curContext.override(this) }
  else { this.readToken(this.fullCharCodeAtPos()); }
};

pp.readToken = function(code) {
  // Identifier or keyword. '\uXXXX' sequences are allowed in
  // identifiers, so '\' also dispatches to that.
  if (isIdentifierStart(code, this.options.ecmaVersion >= 6) || code === 92 /* '\' */)
    { return this.readWord() }

  return this.getTokenFromCode(code)
};

pp.fullCharCodeAt = function(pos) {
  var code = this.input.charCodeAt(pos);
  if (code <= 0xd7ff || code >= 0xdc00) { return code }
  var next = this.input.charCodeAt(pos + 1);
  return next <= 0xdbff || next >= 0xe000 ? code : (code << 10) + next - 0x35fdc00
};

pp.fullCharCodeAtPos = function() {
  return this.fullCharCodeAt(this.pos)
};

pp.skipBlockComment = function() {
  var startLoc = this.options.onComment && this.curPosition();
  var start = this.pos, end = this.input.indexOf("*/", this.pos += 2);
  if (end === -1) { this.raise(this.pos - 2, "Unterminated comment"); }
  this.pos = end + 2;
  if (this.options.locations) {
    for (var nextBreak = (void 0), pos = start; (nextBreak = nextLineBreak(this.input, pos, this.pos)) > -1;) {
      ++this.curLine;
      pos = this.lineStart = nextBreak;
    }
  }
  if (this.options.onComment)
    { this.options.onComment(true, this.input.slice(start + 2, end), start, this.pos,
                           startLoc, this.curPosition()); }
};

pp.skipLineComment = function(startSkip) {
  var start = this.pos;
  var startLoc = this.options.onComment && this.curPosition();
  var ch = this.input.charCodeAt(this.pos += startSkip);
  while (this.pos < this.input.length && !isNewLine(ch)) {
    ch = this.input.charCodeAt(++this.pos);
  }
  if (this.options.onComment)
    { this.options.onComment(false, this.input.slice(start + startSkip, this.pos), start, this.pos,
                           startLoc, this.curPosition()); }
};

// Called at the start of the parse and after every token. Skips
// whitespace and comments, and.

pp.skipSpace = function() {
  loop: while (this.pos < this.input.length) {
    var ch = this.input.charCodeAt(this.pos);
    switch (ch) {
    case 32: case 160: // ' '
      ++this.pos;
      break
    case 13:
      if (this.input.charCodeAt(this.pos + 1) === 10) {
        ++this.pos;
      }
    case 10: case 8232: case 8233:
      ++this.pos;
      if (this.options.locations) {
        ++this.curLine;
        this.lineStart = this.pos;
      }
      break
    case 47: // '/'
      switch (this.input.charCodeAt(this.pos + 1)) {
      case 42: // '*'
        this.skipBlockComment();
        break
      case 47:
        this.skipLineComment(2);
        break
      default:
        break loop
      }
      break
    default:
      if (ch > 8 && ch < 14 || ch >= 5760 && nonASCIIwhitespace.test(String.fromCharCode(ch))) {
        ++this.pos;
      } else {
        break loop
      }
    }
  }
};

// Called at the end of every token. Sets `end`, `val`, and
// maintains `context` and `exprAllowed`, and skips the space after
// the token, so that the next one's `start` will point at the
// right position.

pp.finishToken = function(type, val) {
  this.end = this.pos;
  if (this.options.locations) { this.endLoc = this.curPosition(); }
  var prevType = this.type;
  this.type = type;
  this.value = val;

  this.updateContext(prevType);
};

// ### Token reading

// This is the function that is called to fetch the next token. It
// is somewhat obscure, because it works in character codes rather
// than characters, and because operator parsing has been inlined
// into it.
//
// All in the name of speed.
//
pp.readToken_dot = function() {
  var next = this.input.charCodeAt(this.pos + 1);
  if (next >= 48 && next <= 57) { return this.readNumber(true) }
  var next2 = this.input.charCodeAt(this.pos + 2);
  if (this.options.ecmaVersion >= 6 && next === 46 && next2 === 46) { // 46 = dot '.'
    this.pos += 3;
    return this.finishToken(types$1.ellipsis)
  } else {
    ++this.pos;
    return this.finishToken(types$1.dot)
  }
};

pp.readToken_slash = function() { // '/'
  var next = this.input.charCodeAt(this.pos + 1);
  if (this.exprAllowed) { ++this.pos; return this.readRegexp() }
  if (next === 61) { return this.finishOp(types$1.assign, 2) }
  return this.finishOp(types$1.slash, 1)
};

pp.readToken_mult_modulo_exp = function(code) { // '%*'
  var next = this.input.charCodeAt(this.pos + 1);
  var size = 1;
  var tokentype = code === 42 ? types$1.star : types$1.modulo;

  // exponentiation operator ** and **=
  if (this.options.ecmaVersion >= 7 && code === 42 && next === 42) {
    ++size;
    tokentype = types$1.starstar;
    next = this.input.charCodeAt(this.pos + 2);
  }

  if (next === 61) { return this.finishOp(types$1.assign, size + 1) }
  return this.finishOp(tokentype, size)
};

pp.readToken_pipe_amp = function(code) { // '|&'
  var next = this.input.charCodeAt(this.pos + 1);
  if (next === code) {
    if (this.options.ecmaVersion >= 12) {
      var next2 = this.input.charCodeAt(this.pos + 2);
      if (next2 === 61) { return this.finishOp(types$1.assign, 3) }
    }
    return this.finishOp(code === 124 ? types$1.logicalOR : types$1.logicalAND, 2)
  }
  if (next === 61) { return this.finishOp(types$1.assign, 2) }
  return this.finishOp(code === 124 ? types$1.bitwiseOR : types$1.bitwiseAND, 1)
};

pp.readToken_caret = function() { // '^'
  var next = this.input.charCodeAt(this.pos + 1);
  if (next === 61) { return this.finishOp(types$1.assign, 2) }
  return this.finishOp(types$1.bitwiseXOR, 1)
};

pp.readToken_plus_min = function(code) { // '+-'
  var next = this.input.charCodeAt(this.pos + 1);
  if (next === code) {
    if (next === 45 && !this.inModule && this.input.charCodeAt(this.pos + 2) === 62 &&
        (this.lastTokEnd === 0 || lineBreak.test(this.input.slice(this.lastTokEnd, this.pos)))) {
      // A `-->` line comment
      this.skipLineComment(3);
      this.skipSpace();
      return this.nextToken()
    }
    return this.finishOp(types$1.incDec, 2)
  }
  if (next === 61) { return this.finishOp(types$1.assign, 2) }
  return this.finishOp(types$1.plusMin, 1)
};

pp.readToken_lt_gt = function(code) { // '<>'
  var next = this.input.charCodeAt(this.pos + 1);
  var size = 1;
  if (next === code) {
    size = code === 62 && this.input.charCodeAt(this.pos + 2) === 62 ? 3 : 2;
    if (this.input.charCodeAt(this.pos + size) === 61) { return this.finishOp(types$1.assign, size + 1) }
    return this.finishOp(types$1.bitShift, size)
  }
  if (next === 33 && code === 60 && !this.inModule && this.input.charCodeAt(this.pos + 2) === 45 &&
      this.input.charCodeAt(this.pos + 3) === 45) {
    // `<!--`, an XML-style comment that should be interpreted as a line comment
    this.skipLineComment(4);
    this.skipSpace();
    return this.nextToken()
  }
  if (next === 61) { size = 2; }
  return this.finishOp(types$1.relational, size)
};

pp.readToken_eq_excl = function(code) { // '=!'
  var next = this.input.charCodeAt(this.pos + 1);
  if (next === 61) { return this.finishOp(types$1.equality, this.input.charCodeAt(this.pos + 2) === 61 ? 3 : 2) }
  if (code === 61 && next === 62 && this.options.ecmaVersion >= 6) { // '=>'
    this.pos += 2;
    return this.finishToken(types$1.arrow)
  }
  return this.finishOp(code === 61 ? types$1.eq : types$1.prefix, 1)
};

pp.readToken_question = function() { // '?'
  var ecmaVersion = this.options.ecmaVersion;
  if (ecmaVersion >= 11) {
    var next = this.input.charCodeAt(this.pos + 1);
    if (next === 46) {
      var next2 = this.input.charCodeAt(this.pos + 2);
      if (next2 < 48 || next2 > 57) { return this.finishOp(types$1.questionDot, 2) }
    }
    if (next === 63) {
      if (ecmaVersion >= 12) {
        var next2$1 = this.input.charCodeAt(this.pos + 2);
        if (next2$1 === 61) { return this.finishOp(types$1.assign, 3) }
      }
      return this.finishOp(types$1.coalesce, 2)
    }
  }
  return this.finishOp(types$1.question, 1)
};

pp.readToken_numberSign = function() { // '#'
  var ecmaVersion = this.options.ecmaVersion;
  var code = 35; // '#'
  if (ecmaVersion >= 13) {
    ++this.pos;
    code = this.fullCharCodeAtPos();
    if (isIdentifierStart(code, true) || code === 92 /* '\' */) {
      return this.finishToken(types$1.privateId, this.readWord1())
    }
  }

  this.raise(this.pos, "Unexpected character '" + codePointToString(code) + "'");
};

pp.getTokenFromCode = function(code) {
  switch (code) {
  // The interpretation of a dot depends on whether it is followed
  // by a digit or another two dots.
  case 46: // '.'
    return this.readToken_dot()

  // Punctuation tokens.
  case 40: ++this.pos; return this.finishToken(types$1.parenL)
  case 41: ++this.pos; return this.finishToken(types$1.parenR)
  case 59: ++this.pos; return this.finishToken(types$1.semi)
  case 44: ++this.pos; return this.finishToken(types$1.comma)
  case 91: ++this.pos; return this.finishToken(types$1.bracketL)
  case 93: ++this.pos; return this.finishToken(types$1.bracketR)
  case 123: ++this.pos; return this.finishToken(types$1.braceL)
  case 125: ++this.pos; return this.finishToken(types$1.braceR)
  case 58: ++this.pos; return this.finishToken(types$1.colon)

  case 96: // '`'
    if (this.options.ecmaVersion < 6) { break }
    ++this.pos;
    return this.finishToken(types$1.backQuote)

  case 48: // '0'
    var next = this.input.charCodeAt(this.pos + 1);
    if (next === 120 || next === 88) { return this.readRadixNumber(16) } // '0x', '0X' - hex number
    if (this.options.ecmaVersion >= 6) {
      if (next === 111 || next === 79) { return this.readRadixNumber(8) } // '0o', '0O' - octal number
      if (next === 98 || next === 66) { return this.readRadixNumber(2) } // '0b', '0B' - binary number
    }

  // Anything else beginning with a digit is an integer, octal
  // number, or float.
  case 49: case 50: case 51: case 52: case 53: case 54: case 55: case 56: case 57: // 1-9
    return this.readNumber(false)

  // Quotes produce strings.
  case 34: case 39: // '"', "'"
    return this.readString(code)

  // Operators are parsed inline in tiny state machines. '=' (61) is
  // often referred to. `finishOp` simply skips the amount of
  // characters it is given as second argument, and returns a token
  // of the type given by its first argument.
  case 47: // '/'
    return this.readToken_slash()

  case 37: case 42: // '%*'
    return this.readToken_mult_modulo_exp(code)

  case 124: case 38: // '|&'
    return this.readToken_pipe_amp(code)

  case 94: // '^'
    return this.readToken_caret()

  case 43: case 45: // '+-'
    return this.readToken_plus_min(code)

  case 60: case 62: // '<>'
    return this.readToken_lt_gt(code)

  case 61: case 33: // '=!'
    return this.readToken_eq_excl(code)

  case 63: // '?'
    return this.readToken_question()

  case 126: // '~'
    return this.finishOp(types$1.prefix, 1)

  case 35: // '#'
    return this.readToken_numberSign()
  }

  this.raise(this.pos, "Unexpected character '" + codePointToString(code) + "'");
};

pp.finishOp = function(type, size) {
  var str = this.input.slice(this.pos, this.pos + size);
  this.pos += size;
  return this.finishToken(type, str)
};

pp.readRegexp = function() {
  var escaped, inClass, start = this.pos;
  for (;;) {
    if (this.pos >= this.input.length) { this.raise(start, "Unterminated regular expression"); }
    var ch = this.input.charAt(this.pos);
    if (lineBreak.test(ch)) { this.raise(start, "Unterminated regular expression"); }
    if (!escaped) {
      if (ch === "[") { inClass = true; }
      else if (ch === "]" && inClass) { inClass = false; }
      else if (ch === "/" && !inClass) { break }
      escaped = ch === "\\";
    } else { escaped = false; }
    ++this.pos;
  }
  var pattern = this.input.slice(start, this.pos);
  ++this.pos;
  var flagsStart = this.pos;
  var flags = this.readWord1();
  if (this.containsEsc) { this.unexpected(flagsStart); }

  // Validate pattern
  var state = this.regexpState || (this.regexpState = new RegExpValidationState(this));
  state.reset(start, pattern, flags);
  this.validateRegExpFlags(state);
  this.validateRegExpPattern(state);

  // Create Literal#value property value.
  var value = null;
  try {
    value = new RegExp(pattern, flags);
  } catch (e) {
    // ESTree requires null if it failed to instantiate RegExp object.
    // https://github.com/estree/estree/blob/a27003adf4fd7bfad44de9cef372a2eacd527b1c/es5.md#regexpliteral
  }

  return this.finishToken(types$1.regexp, {pattern: pattern, flags: flags, value: value})
};

// Read an integer in the given radix. Return null if zero digits
// were read, the integer value otherwise. When `len` is given, this
// will return `null` unless the integer has exactly `len` digits.

pp.readInt = function(radix, len, maybeLegacyOctalNumericLiteral) {
  // `len` is used for character escape sequences. In that case, disallow separators.
  var allowSeparators = this.options.ecmaVersion >= 12 && len === undefined;

  // `maybeLegacyOctalNumericLiteral` is true if it doesn't have prefix (0x,0o,0b)
  // and isn't fraction part nor exponent part. In that case, if the first digit
  // is zero then disallow separators.
  var isLegacyOctalNumericLiteral = maybeLegacyOctalNumericLiteral && this.input.charCodeAt(this.pos) === 48;

  var start = this.pos, total = 0, lastCode = 0;
  for (var i = 0, e = len == null ? Infinity : len; i < e; ++i, ++this.pos) {
    var code = this.input.charCodeAt(this.pos), val = (void 0);

    if (allowSeparators && code === 95) {
      if (isLegacyOctalNumericLiteral) { this.raiseRecoverable(this.pos, "Numeric separator is not allowed in legacy octal numeric literals"); }
      if (lastCode === 95) { this.raiseRecoverable(this.pos, "Numeric separator must be exactly one underscore"); }
      if (i === 0) { this.raiseRecoverable(this.pos, "Numeric separator is not allowed at the first of digits"); }
      lastCode = code;
      continue
    }

    if (code >= 97) { val = code - 97 + 10; } // a
    else if (code >= 65) { val = code - 65 + 10; } // A
    else if (code >= 48 && code <= 57) { val = code - 48; } // 0-9
    else { val = Infinity; }
    if (val >= radix) { break }
    lastCode = code;
    total = total * radix + val;
  }

  if (allowSeparators && lastCode === 95) { this.raiseRecoverable(this.pos - 1, "Numeric separator is not allowed at the last of digits"); }
  if (this.pos === start || len != null && this.pos - start !== len) { return null }

  return total
};

function stringToNumber(str, isLegacyOctalNumericLiteral) {
  if (isLegacyOctalNumericLiteral) {
    return parseInt(str, 8)
  }

  // `parseFloat(value)` stops parsing at the first numeric separator then returns a wrong value.
  return parseFloat(str.replace(/_/g, ""))
}

function stringToBigInt(str) {
  if (typeof BigInt !== "function") {
    return null
  }

  // `BigInt(value)` throws syntax error if the string contains numeric separators.
  return BigInt(str.replace(/_/g, ""))
}

pp.readRadixNumber = function(radix) {
  var start = this.pos;
  this.pos += 2; // 0x
  var val = this.readInt(radix);
  if (val == null) { this.raise(this.start + 2, "Expected number in radix " + radix); }
  if (this.options.ecmaVersion >= 11 && this.input.charCodeAt(this.pos) === 110) {
    val = stringToBigInt(this.input.slice(start, this.pos));
    ++this.pos;
  } else if (isIdentifierStart(this.fullCharCodeAtPos())) { this.raise(this.pos, "Identifier directly after number"); }
  return this.finishToken(types$1.num, val)
};

// Read an integer, octal integer, or floating-point number.

pp.readNumber = function(startsWithDot) {
  var start = this.pos;
  if (!startsWithDot && this.readInt(10, undefined, true) === null) { this.raise(start, "Invalid number"); }
  var octal = this.pos - start >= 2 && this.input.charCodeAt(start) === 48;
  if (octal && this.strict) { this.raise(start, "Invalid number"); }
  var next = this.input.charCodeAt(this.pos);
  if (!octal && !startsWithDot && this.options.ecmaVersion >= 11 && next === 110) {
    var val$1 = stringToBigInt(this.input.slice(start, this.pos));
    ++this.pos;
    if (isIdentifierStart(this.fullCharCodeAtPos())) { this.raise(this.pos, "Identifier directly after number"); }
    return this.finishToken(types$1.num, val$1)
  }
  if (octal && /[89]/.test(this.input.slice(start, this.pos))) { octal = false; }
  if (next === 46 && !octal) { // '.'
    ++this.pos;
    this.readInt(10);
    next = this.input.charCodeAt(this.pos);
  }
  if ((next === 69 || next === 101) && !octal) { // 'eE'
    next = this.input.charCodeAt(++this.pos);
    if (next === 43 || next === 45) { ++this.pos; } // '+-'
    if (this.readInt(10) === null) { this.raise(start, "Invalid number"); }
  }
  if (isIdentifierStart(this.fullCharCodeAtPos())) { this.raise(this.pos, "Identifier directly after number"); }

  var val = stringToNumber(this.input.slice(start, this.pos), octal);
  return this.finishToken(types$1.num, val)
};

// Read a string value, interpreting backslash-escapes.

pp.readCodePoint = function() {
  var ch = this.input.charCodeAt(this.pos), code;

  if (ch === 123) { // '{'
    if (this.options.ecmaVersion < 6) { this.unexpected(); }
    var codePos = ++this.pos;
    code = this.readHexChar(this.input.indexOf("}", this.pos) - this.pos);
    ++this.pos;
    if (code > 0x10FFFF) { this.invalidStringToken(codePos, "Code point out of bounds"); }
  } else {
    code = this.readHexChar(4);
  }
  return code
};

pp.readString = function(quote) {
  var out = "", chunkStart = ++this.pos;
  for (;;) {
    if (this.pos >= this.input.length) { this.raise(this.start, "Unterminated string constant"); }
    var ch = this.input.charCodeAt(this.pos);
    if (ch === quote) { break }
    if (ch === 92) { // '\'
      out += this.input.slice(chunkStart, this.pos);
      out += this.readEscapedChar(false);
      chunkStart = this.pos;
    } else if (ch === 0x2028 || ch === 0x2029) {
      if (this.options.ecmaVersion < 10) { this.raise(this.start, "Unterminated string constant"); }
      ++this.pos;
      if (this.options.locations) {
        this.curLine++;
        this.lineStart = this.pos;
      }
    } else {
      if (isNewLine(ch)) { this.raise(this.start, "Unterminated string constant"); }
      ++this.pos;
    }
  }
  out += this.input.slice(chunkStart, this.pos++);
  return this.finishToken(types$1.string, out)
};

// Reads template string tokens.

var INVALID_TEMPLATE_ESCAPE_ERROR = {};

pp.tryReadTemplateToken = function() {
  this.inTemplateElement = true;
  try {
    this.readTmplToken();
  } catch (err) {
    if (err === INVALID_TEMPLATE_ESCAPE_ERROR) {
      this.readInvalidTemplateToken();
    } else {
      throw err
    }
  }

  this.inTemplateElement = false;
};

pp.invalidStringToken = function(position, message) {
  if (this.inTemplateElement && this.options.ecmaVersion >= 9) {
    throw INVALID_TEMPLATE_ESCAPE_ERROR
  } else {
    this.raise(position, message);
  }
};

pp.readTmplToken = function() {
  var out = "", chunkStart = this.pos;
  for (;;) {
    if (this.pos >= this.input.length) { this.raise(this.start, "Unterminated template"); }
    var ch = this.input.charCodeAt(this.pos);
    if (ch === 96 || ch === 36 && this.input.charCodeAt(this.pos + 1) === 123) { // '`', '${'
      if (this.pos === this.start && (this.type === types$1.template || this.type === types$1.invalidTemplate)) {
        if (ch === 36) {
          this.pos += 2;
          return this.finishToken(types$1.dollarBraceL)
        } else {
          ++this.pos;
          return this.finishToken(types$1.backQuote)
        }
      }
      out += this.input.slice(chunkStart, this.pos);
      return this.finishToken(types$1.template, out)
    }
    if (ch === 92) { // '\'
      out += this.input.slice(chunkStart, this.pos);
      out += this.readEscapedChar(true);
      chunkStart = this.pos;
    } else if (isNewLine(ch)) {
      out += this.input.slice(chunkStart, this.pos);
      ++this.pos;
      switch (ch) {
      case 13:
        if (this.input.charCodeAt(this.pos) === 10) { ++this.pos; }
      case 10:
        out += "\n";
        break
      default:
        out += String.fromCharCode(ch);
        break
      }
      if (this.options.locations) {
        ++this.curLine;
        this.lineStart = this.pos;
      }
      chunkStart = this.pos;
    } else {
      ++this.pos;
    }
  }
};

// Reads a template token to search for the end, without validating any escape sequences
pp.readInvalidTemplateToken = function() {
  for (; this.pos < this.input.length; this.pos++) {
    switch (this.input[this.pos]) {
    case "\\":
      ++this.pos;
      break

    case "$":
      if (this.input[this.pos + 1] !== "{") { break }
      // fall through
    case "`":
      return this.finishToken(types$1.invalidTemplate, this.input.slice(this.start, this.pos))

    case "\r":
      if (this.input[this.pos + 1] === "\n") { ++this.pos; }
      // fall through
    case "\n": case "\u2028": case "\u2029":
      ++this.curLine;
      this.lineStart = this.pos + 1;
      break
    }
  }
  this.raise(this.start, "Unterminated template");
};

// Used to read escaped characters

pp.readEscapedChar = function(inTemplate) {
  var ch = this.input.charCodeAt(++this.pos);
  ++this.pos;
  switch (ch) {
  case 110: return "\n" // 'n' -> '\n'
  case 114: return "\r" // 'r' -> '\r'
  case 120: return String.fromCharCode(this.readHexChar(2)) // 'x'
  case 117: return codePointToString(this.readCodePoint()) // 'u'
  case 116: return "\t" // 't' -> '\t'
  case 98: return "\b" // 'b' -> '\b'
  case 118: return "\u000b" // 'v' -> '\u000b'
  case 102: return "\f" // 'f' -> '\f'
  case 13: if (this.input.charCodeAt(this.pos) === 10) { ++this.pos; } // '\r\n'
  case 10: // ' \n'
    if (this.options.locations) { this.lineStart = this.pos; ++this.curLine; }
    return ""
  case 56:
  case 57:
    if (this.strict) {
      this.invalidStringToken(
        this.pos - 1,
        "Invalid escape sequence"
      );
    }
    if (inTemplate) {
      var codePos = this.pos - 1;

      this.invalidStringToken(
        codePos,
        "Invalid escape sequence in template string"
      );
    }
  default:
    if (ch >= 48 && ch <= 55) {
      var octalStr = this.input.substr(this.pos - 1, 3).match(/^[0-7]+/)[0];
      var octal = parseInt(octalStr, 8);
      if (octal > 255) {
        octalStr = octalStr.slice(0, -1);
        octal = parseInt(octalStr, 8);
      }
      this.pos += octalStr.length - 1;
      ch = this.input.charCodeAt(this.pos);
      if ((octalStr !== "0" || ch === 56 || ch === 57) && (this.strict || inTemplate)) {
        this.invalidStringToken(
          this.pos - 1 - octalStr.length,
          inTemplate
            ? "Octal literal in template string"
            : "Octal literal in strict mode"
        );
      }
      return String.fromCharCode(octal)
    }
    if (isNewLine(ch)) {
      // Unicode new line characters after \ get removed from output in both
      // template literals and strings
      if (this.options.locations) { this.lineStart = this.pos; ++this.curLine; }
      return ""
    }
    return String.fromCharCode(ch)
  }
};

// Used to read character escape sequences ('\x', '\u', '\U').

pp.readHexChar = function(len) {
  var codePos = this.pos;
  var n = this.readInt(16, len);
  if (n === null) { this.invalidStringToken(codePos, "Bad character escape sequence"); }
  return n
};

// Read an identifier, and return it as a string. Sets `this.containsEsc`
// to whether the word contained a '\u' escape.
//
// Incrementally adds only escaped chars, adding other chunks as-is
// as a micro-optimization.

pp.readWord1 = function() {
  this.containsEsc = false;
  var word = "", first = true, chunkStart = this.pos;
  var astral = this.options.ecmaVersion >= 6;
  while (this.pos < this.input.length) {
    var ch = this.fullCharCodeAtPos();
    if (isIdentifierChar(ch, astral)) {
      this.pos += ch <= 0xffff ? 1 : 2;
    } else if (ch === 92) { // "\"
      this.containsEsc = true;
      word += this.input.slice(chunkStart, this.pos);
      var escStart = this.pos;
      if (this.input.charCodeAt(++this.pos) !== 117) // "u"
        { this.invalidStringToken(this.pos, "Expecting Unicode escape sequence \\uXXXX"); }
      ++this.pos;
      var esc = this.readCodePoint();
      if (!(first ? isIdentifierStart : isIdentifierChar)(esc, astral))
        { this.invalidStringToken(escStart, "Invalid Unicode escape"); }
      word += codePointToString(esc);
      chunkStart = this.pos;
    } else {
      break
    }
    first = false;
  }
  return word + this.input.slice(chunkStart, this.pos)
};

// Read an identifier or keyword token. Will check for reserved
// words when necessary.

pp.readWord = function() {
  var word = this.readWord1();
  var type = types$1.name;
  if (this.keywords.test(word)) {
    type = keywords[word];
  }
  return this.finishToken(type, word)
};

// Acorn is a tiny, fast JavaScript parser written in JavaScript.
//
// Acorn was written by Marijn Haverbeke, Ingvar Stepanyan, and
// various contributors and released under an MIT license.
//
// Git repositories for Acorn are available at
//
//     http://marijnhaverbeke.nl/git/acorn
//     https://github.com/acornjs/acorn.git
//
// Please use the [github bug tracker][ghbt] to report issues.
//
// [ghbt]: https://github.com/acornjs/acorn/issues


var version = "8.18.0";

Parser.acorn = {
  Parser: Parser,
  version: version,
  defaultOptions: defaultOptions,
  Position: Position,
  SourceLocation: SourceLocation,
  getLineInfo: getLineInfo,
  Node: Node,
  TokenType: TokenType,
  tokTypes: types$1,
  keywordTypes: keywords,
  TokContext: TokContext,
  tokContexts: types,
  isIdentifierChar: isIdentifierChar,
  isIdentifierStart: isIdentifierStart,
  Token: Token,
  isNewLine: isNewLine,
  lineBreak: lineBreak,
  lineBreakG: lineBreakG,
  nonASCIIwhitespace: nonASCIIwhitespace
};

// The main exported interface (under `self.acorn` when in the
// browser) is a `parse` function that takes a code string and returns
// an abstract syntax tree as specified by the [ESTree spec][estree].
//
// [estree]: https://github.com/estree/estree

function parse(input, options) {
  return Parser.parse(input, options)
}

// This function tries to parse a single expression at a given
// offset in a string. Useful for parsing mixed-language formats
// that embed JavaScript expressions.

function parseExpressionAt(input, pos, options) {
  return Parser.parseExpressionAt(input, pos, options)
}

// Acorn is organized as a tokenizer and a recursive-descent parser.
// The `tokenizer` export provides an interface to the tokenizer.

function tokenizer(input, options) {
  return Parser.tokenizer(input, options)
}

return parse;
})();
// END VENDORED_ACORN_DIST_ACORN_MJS_8_18_0

const allNfc = (value) =>
  typeof value === "string"
    ? value === value.normalize("NFC")
    : Array.isArray(value)
    ? value.every(allNfc)
    : value && typeof value === "object"
    ? Object.keys(value).every((key) => allNfc(key) && allNfc(value[key]))
    : true;
const canonicalJson = (value) =>
  Array.isArray(value)
    ? `[${value.map(canonicalJson).join(",")}]`
    : value && typeof value === "object"
    ? `{${
      Object.keys(value).sort().map((key) =>
        `${JSON.stringify(key)}:${canonicalJson(value[key])}`
      ).join(",")
    }}`
    : JSON.stringify(value);
const digestRecord = (domain, value) => {
  check(allNfc(domain) && allNfc(value), "NON_NFC");
  return {
    algorithm: "sha256",
    canonicalization:
      "recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1",
    domain,
    frame: "utf8(domain)||0x00||canonical-json-utf8||0x0a",
    value: sha256(
      Buffer.concat([
        Buffer.from(domain),
        Buffer.from([0]),
        Buffer.from(`${canonicalJson(value)}\n`),
      ]),
    ),
  };
};
const deriveAuthorizationNonceDigest = (authorizationId, inputHex) => {
  check(
    typeof authorizationId === "string" &&
      /^[A-Za-z0-9:._-]+$/u.test(authorizationId),
    "B0_AUTH_SCHEMA",
    "nonce-authorization-id",
  );
  check(
    typeof inputHex === "string" && /^[0-9a-f]{64}$/u.test(inputHex),
    "B0_AUTH_SCHEMA",
    "nonce-private-bytes",
  );
  const privateBytes = Buffer.from(inputHex, "hex");
  check(
    privateBytes.length === 32 && privateBytes.toString("hex") === inputHex,
    "B0_AUTH_SCHEMA",
    "nonce-private-bytes",
  );
  const domain =
    `${PREFIX}/future/b0-execution-authorization/nonce/${authorizationId}`;
  return sha256(
    Buffer.concat([Buffer.from(domain), Buffer.from([0]), privateBytes]),
  );
};
const fileDigestRecord = (locator, bytes) => {
  const domain = `${PREFIX}/file/${locator}`;
  return {
    algorithm: "sha256",
    canonicalization: "raw-file-bytes-v1",
    domain,
    frame: "utf8(domain)||0x00||raw-file-bytes",
    value: sha256(
      Buffer.concat([Buffer.from(domain), Buffer.from([0]), bytes]),
    ),
  };
};
const duplicateKeys = (text) => {
  let index = 0;
  const ws = () => {
    while (/[\x20\x09\x0a\x0d]/.test(text[index] ?? "")) index++;
  };
  const str = () => {
    const start = index++;
    while (index < text.length) {
      if (text[index] === "\\") {
        index += 2;
        continue;
      }
      if (text[index++] === '"') return JSON.parse(text.slice(start, index));
    }
    throw new Error("string");
  };
  const value = () => {
    ws();
    if (text[index] === '"') {
      str();
      return;
    }
    if (text[index] === "{") {
      index++;
      ws();
      const seen = new Set();
      if (text[index] === "}") {
        index++;
        return;
      }
      for (;;) {
        ws();
        const key = str();
        if (seen.has(key)) throw new Error("duplicate");
        seen.add(key);
        ws();
        if (text[index++] !== ":") throw new Error("colon");
        value();
        ws();
        if (text[index] === "}") {
          index++;
          return;
        }
        if (text[index++] !== ",") throw new Error("comma");
      }
    }
    if (text[index] === "[") {
      index++;
      ws();
      if (text[index] === "]") {
        index++;
        return;
      }
      for (;;) {
        value();
        ws();
        if (text[index] === "]") {
          index++;
          return;
        }
        if (text[index++] !== ",") throw new Error("comma");
      }
    }
    const match = text.slice(index).match(
      /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/,
    );
    if (!match) throw new Error("value");
    index += match[0].length;
  };
  value();
  ws();
  if (index !== text.length) throw new Error("trailing");
};
const strictParse = (bytes, { canonical = false, allowNfd = false } = {}) => {
  const text = bytes.toString("utf8");
  check(Buffer.from(text).equals(bytes), "UTF8");
  try {
    duplicateKeys(text);
  } catch {
    fail("DUPLICATE_KEY");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail("UTF8");
  }
  check(allowNfd || allNfc(value), "NON_NFC");
  if (canonical) {
    check(text === `${canonicalJson(value)}\n`, "UTF8", "noncanonical");
  }
  return value;
};
const parseSourceJson = (bytes) => {
  const text = bytes.toString("utf8");
  check(Buffer.from(text).equals(bytes), "SSA_SOURCE_SEMANTIC", "utf8");
  try {
    duplicateKeys(text);
    return JSON.parse(text);
  } catch {
    fail("SSA_SOURCE_SEMANTIC", "parse");
  }
};
const safeLocator = (locator) => {
  check(
    typeof locator === "string" && allNfc(locator) && locator &&
      !isAbsolute(locator) && !locator.includes("\\") &&
      !locator.includes("\0") &&
      locator.split("/").every((part) => part && part !== "." && part !== ".."),
    "PATH",
  );
  return locator;
};
const safeRead = (root, locator) => {
  safeLocator(locator);
  check(isAbsolute(root), "PATH");
  let rootStat;
  try {
    rootStat = lstatSync(root);
  } catch {
    fail("PATH", "root");
  }
  check(rootStat.isDirectory() && !rootStat.isSymbolicLink(), "LINK", "root");
  const absolute = resolve(root, locator), rel = relative(root, absolute);
  check(
    rel && !rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel),
    "PATH",
  );
  let cursor = root;
  for (const part of locator.split("/")) {
    cursor = resolve(cursor, part);
    let stat;
    try {
      stat = lstatSync(cursor);
    } catch {
      fail("PATH", locator);
    }
    check(!stat.isSymbolicLink(), "LINK", locator);
  }
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    fail("PATH", locator);
  }
  check(stat.isFile(), "SPECIAL_FILE", locator);
  check(stat.nlink === 1, "LINK", locator);
  check((stat.mode & 0o777) === 0o644, "FILE_MODE", locator);
  try {
    return readFileSync(absolute);
  } catch {
    fail("PATH", locator);
  }
};
const walk = (root) => {
  const rows = [];
  const visit = (absolute, logical) => {
    let names;
    try {
      names = readdirSync(absolute).sort();
    } catch {
      fail("PACKAGE_CLOSURE", logical || ".");
    }
    for (const name of names) {
      const child = resolve(absolute, name),
        locator = logical ? `${logical}/${name}` : name;
      let stat;
      try {
        stat = lstatSync(child);
      } catch {
        fail("PACKAGE_CLOSURE", locator);
      }
      rows.push({ locator, stat });
      if (stat.isDirectory() && !stat.isSymbolicLink()) visit(child, locator);
    }
  };
  visit(root, "");
  return rows;
};
const checkClosure = (root, mode) => {
  let packageStat;
  try {
    packageStat = lstatSync(root);
  } catch {
    fail("PACKAGE_CLOSURE", "root");
  }
  check(
    packageStat.isDirectory() && !packageStat.isSymbolicLink(),
    "PACKAGE_CLOSURE",
  );
  const rows = walk(root),
    files = rows.filter((row) => row.stat.isFile()).map((row) => row.locator)
      .sort(),
    dirs = [
      ".",
      ...rows.filter((row) => row.stat.isDirectory()).map((row) => row.locator),
    ].sort(),
    expected =
      (mode === "sealed"
        ? [...AUTHORED_FILES, "MANIFEST.json", "SHA256SUMS"]
        : AUTHORED_FILES).slice().sort();
  check(rows.every((row) => !row.stat.isSymbolicLink()), "LINK");
  check(
    rows.every((row) => row.stat.isFile() || row.stat.isDirectory()),
    "SPECIAL_FILE",
  );
  check(same(files, expected), "PACKAGE_CLOSURE");
  check(same(dirs, [".", "schemas", "test"]), "PACKAGE_CLOSURE");
  for (const dir of dirs) {
    const stat = lstatSync(resolve(root, dir));
    check(stat.isDirectory() && !stat.isSymbolicLink(), "LINK", dir);
    check((stat.mode & 0o777) === 0o755, "DIR_MODE", dir);
  }
  for (const file of files) {
    const stat = lstatSync(resolve(root, file));
    check(stat.nlink === 1, "LINK", file);
    check((stat.mode & 0o777) === 0o644, "FILE_MODE", file);
  }
  return { files: files.length, directories: dirs.length };
};
const deriveSealEnvelope = (packageRoot = here) => {
  const entries = AUTHORED_FILES.map((locator) => {
    const bytes = safeRead(packageRoot, locator);
    return {
      bytes: bytes.length,
      fileDigest: fileDigestRecord(locator, bytes),
      locator,
      rawSha256: sha256(bytes),
    };
  });
  const rosterDigest = digestRecord(`${PREFIX}/manifest-roster`, entries),
    manifest = {
      schema: `${SCHEMA_PREFIX}manifest.v1.schema.json`,
      format: "shieldkit-static-manifest-v1",
      packageId: PACKAGE_ID,
      entryCount: 27,
      entries,
      rosterDigest,
    },
    manifestBytes = Buffer.from(`${canonicalJson(manifest)}\n`),
    sumsBytes = Buffer.from(
      `${
        [...entries, {
          locator: "MANIFEST.json",
          rawSha256: sha256(manifestBytes),
        }].map((row) => `${row.rawSha256}  ${row.locator}`).join("\n")
      }\n`,
    );
  return { entries, rosterDigest, manifest, manifestBytes, sumsBytes };
};
export const parseValidationCliArgs = (argv) => {
  check(
    Array.isArray(argv) && argv.every((value) => typeof value === "string"),
    "CLI_ARGS",
  );
  const unsealed = ["--mode", "unsealed"];
  if (same(argv, unsealed)) return { mode: "unsealed" };
  const flags = [
    "--mode",
    "sealed",
    "--anchor-root",
    null,
    "--anchor-locator",
    null,
    "--anchor-bytes",
    null,
    "--anchor-raw-sha256",
    null,
  ];
  check(
    argv.length === 10 &&
      flags.every((value, index) => value === null || argv[index] === value),
    "CLI_ARGS",
  );
  const anchorRoot = argv[3],
    anchorLocator = argv[5],
    bytes = argv[7],
    anchorRawSha256 = argv[9];
  check(isAbsolute(anchorRoot), "ANCHOR_LOCATION");
  safeLocator(anchorLocator);
  check(
    /^[1-9][0-9]*$/.test(bytes) && Number.isSafeInteger(Number(bytes)),
    "ANCHOR_PIN",
  );
  check(/^[0-9a-f]{64}$/.test(anchorRawSha256), "ANCHOR_PIN");
  return {
    mode: "sealed",
    anchorRoot,
    anchorLocator,
    anchorBytes: Number(bytes),
    anchorRawSha256,
  };
};
const readAnchor = (
  { anchorRoot, anchorLocator, anchorBytes, anchorRawSha256 },
  packageRoot,
) => {
  check(
    isAbsolute(anchorRoot) && typeof anchorLocator === "string",
    "ANCHOR_REQUIRED",
  );
  let bytes;
  try {
    bytes = safeRead(anchorRoot, anchorLocator);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("CPSB_PATH")) {
      fail("ANCHOR_LOCATION", anchorLocator);
    }
    throw error;
  }
  check(
    bytes.length === anchorBytes && sha256(bytes) === anchorRawSha256,
    "ANCHOR_RAW",
  );
  const absolute = resolve(anchorRoot, anchorLocator);
  let pkg, actualAnchor;
  try {
    pkg = realpathSync(packageRoot);
    actualAnchor = realpathSync(absolute);
  } catch {
    fail("ANCHOR_LOCATION", anchorLocator);
  }
  check(!actualAnchor.startsWith(`${pkg}${sep}`), "ANCHOR_LOCATION");
  const anchor = strictParse(bytes, { canonical: true });
  const keys = [
    "schema",
    "artifactId",
    "packageId",
    "status",
    "package",
    "rootRawSha256",
    "rootContentDigest",
    "validatorRawSha256",
    "entryCount",
    "rosterDigest",
    "manifestRawSha256",
    "sha256SumsRawSha256",
    "schemaBindingTableDigest",
    "schemaBindings",
    "componentDigests",
    "directDependencyBinding",
    "eappV1DispositionDigest",
    "nonAuthorityBoundary",
    "orderedClosure",
  ];
  check(same(Object.keys(anchor), keys.slice().sort()), "ANCHOR_SCHEMA");
  check(
    anchor.schema === `${PREFIX}/external-review-anchor/v1` &&
      anchor.artifactId ===
        "artifact:gate-b:gate-b0-external-authority-control-plane-schema-bridge-review-anchor-v1" &&
      anchor.packageId === PACKAGE_ID &&
      anchor.status ===
        "sealed-static-control-plane-schema-bridge-review-anchor-no-principals-no-decisions-no-contracts-no-bindings-no-authorizations-no-instances-no-admission-no-execution-unqualified" &&
      anchor.package ===
        "research-lanes/bch-shielded-pool-design/p2/gate-b/gate-b0-external-authority-control-plane-schema-bridge-v1" &&
      anchor.entryCount === 27,
    "ANCHOR_SCHEMA",
  );
  return anchor;
};
const CPSB_AST_LOCATORS = Object.freeze([
  "test/future-schema.test.mjs",
  "test/mutation.test.mjs",
  "test/package-boundary.test.mjs",
  "test/static.test.mjs",
  "validate-static.mjs",
]);
const CPSB_AST_FINGERPRINTS = Object.freeze([
  ["test/future-schema.test.mjs", "8a52542047f2393f367b0bdb59e8ff0ac0f69fb2c42adb0d58b370ea29438f9a"],
  ["test/mutation.test.mjs", "57860849c5e6ea45f17292ce62b8df803a57266f863810f9e6af05be7e4a155b"],
  ["test/package-boundary.test.mjs", "aa22b6ade0e7015dee2cad51389f7612f7ccd3b8e9bc7a0e00e12775ae6a318d"],
  ["test/static.test.mjs", "5ad4ad8da4f71e5f8c6cbdc796e2ed3505d01f674c2834031fa6f3dc3073eba1"],
  ["validate-static.mjs", "ec0bb0ca178e9ece663934d28bc17c1d7658c03c85943ca80ae4fc9402d20dcd"],
]);
const CPSB_IMPORT_ROSTERS = Object.freeze({
  "test/future-schema.test.mjs": [
    ["node:test", ["default:test"]],
    ["node:assert/strict", ["default:assert"]],
    ["node:crypto", ["named:createHash:createHash"]],
    ["ajv/dist/2020.js", ["default:Ajv2020"]],
    ["node:fs", ["named:readFileSync:readFileSync", "named:readdirSync:readdirSync"]],
    ["node:path", ["named:dirname:dirname", "named:join:join"]],
    ["node:url", ["named:fileURLToPath:fileURLToPath"]],
    ["../validate-static.mjs", ["named:auditSyntheticFutureGraph:auditSyntheticFutureGraph"]],
  ],
  "test/mutation.test.mjs": [
    ["node:test", ["default:test"]],
    ["node:assert/strict", ["default:assert"]],
    ["ajv/dist/2020.js", ["default:Ajv2020"]],
    ["node:crypto", ["named:createHash:createHash"]],
    ["node:fs", [
      "named:chmodSync:chmodSync", "named:cpSync:cpSync",
      "named:lstatSync:lstatSync", "named:mkdirSync:mkdirSync",
      "named:mkdtempSync:mkdtempSync", "named:readFileSync:readFileSync",
      "named:readdirSync:readdirSync", "named:rmSync:rmSync",
      "named:writeFileSync:writeFileSync",
    ]],
    ["node:path", ["named:dirname:dirname", "named:resolve:resolve"]],
    ["node:url", ["named:fileURLToPath:fileURLToPath"]],
    ["../validate-static.mjs", ["named:validateStatic:validateStatic"]],
  ],
  "test/package-boundary.test.mjs": [
    ["node:test", ["default:test"]],
    ["node:assert/strict", ["default:assert"]],
    ["node:crypto", ["named:createHash:createHash"]],
    ["node:net", ["named:createServer:createServer"]],
    ["node:os", ["named:tmpdir:tmpdir"]],
    ["node:fs", [
      "named:chmodSync:chmodSync", "named:copyFileSync:copyFileSync",
      "named:linkSync:linkSync", "named:mkdirSync:mkdirSync",
      "named:mkdtempSync:mkdtempSync", "named:readFileSync:readFileSync",
      "named:rmSync:rmSync", "named:symlinkSync:symlinkSync",
      "named:unlinkSync:unlinkSync", "named:writeFileSync:writeFileSync",
    ]],
    ["node:path", ["named:dirname:dirname", "named:resolve:resolve"]],
    ["../validate-static.mjs", ["named:validateStatic:validateStatic"]],
  ],
  "test/static.test.mjs": [
    ["node:test", ["default:test"]],
    ["node:assert/strict", ["default:assert"]],
    ["node:fs", [
      "named:chmodSync:chmodSync", "named:copyFileSync:copyFileSync",
      "named:mkdirSync:mkdirSync", "named:mkdtempSync:mkdtempSync",
      "named:readFileSync:readFileSync", "named:rmSync:rmSync",
      "named:writeFileSync:writeFileSync",
    ]],
    ["node:path", ["named:dirname:dirname", "named:resolve:resolve"]],
    ["node:url", ["named:fileURLToPath:fileURLToPath"]],
    ["../validate-static.mjs", [
      "named:parseValidationCliArgs:parseValidationCliArgs",
      "named:validateStatic:validateStatic",
    ]],
  ],
  "validate-static.mjs": [
    ["ajv/dist/2020.js", ["default:Ajv2020"]],
    ["node:crypto", ["named:createHash:createHash"]],
    ["node:fs", [
      "named:lstatSync:lstatSync", "named:readdirSync:readdirSync",
      "named:readFileSync:readFileSync", "named:realpathSync:realpathSync",
    ]],
    ["node:path", [
      "named:basename:basename", "named:dirname:dirname",
      "named:isAbsolute:isAbsolute", "named:relative:relative",
      "named:resolve:resolve", "named:sep:sep",
    ]],
    ["node:url", ["named:fileURLToPath:fileURLToPath"]],
  ],
});
const CPSB_EXPORT_ROSTERS = Object.freeze({
  "test/future-schema.test.mjs": [],
  "test/mutation.test.mjs": [],
  "test/package-boundary.test.mjs": [],
  "test/static.test.mjs": [],
  "validate-static.mjs": [
    "named-const:parseValidationCliArgs",
    "named-const:auditSyntheticFutureGraph",
    "named-const:validateStatic",
  ],
});
const CPSB_AST_PARSE_OPTIONS = Object.freeze({
  ecmaVersion: 2026,
  sourceType: "module",
  allowHashBang: false,
});
const CPSB_AST_NODE_FIELDS = Object.freeze({
  ArrayExpression: ["elements"],
  ArrayPattern: ["elements"],
  ArrowFunctionExpression: ["id", "expression", "generator", "async", "params", "body"],
  AssignmentExpression: ["operator", "left", "right"],
  AssignmentPattern: ["left", "right"],
  AwaitExpression: ["argument"],
  BinaryExpression: ["left", "operator", "right"],
  BlockStatement: ["body"],
  BreakStatement: ["label"],
  CallExpression: ["callee", "arguments", "optional"],
  CatchClause: ["param", "body"],
  ChainExpression: ["expression"],
  ClassBody: ["body"],
  ClassDeclaration: ["id", "superClass", "body"],
  ClassExpression: ["id", "superClass", "body"],
  ConditionalExpression: ["test", "consequent", "alternate"],
  ContinueStatement: ["label"],
  DebuggerStatement: [],
  DoWhileStatement: ["body", "test"],
  EmptyStatement: [],
  ExportAllDeclaration: ["exported", "source", "attributes"],
  ExportDefaultDeclaration: ["declaration"],
  ExportNamedDeclaration: ["declaration", "specifiers", "source", "attributes"],
  ExportSpecifier: ["local", "exported"],
  ExpressionStatement: ["expression", "directive"],
  ForInStatement: ["left", "right", "body"],
  ForOfStatement: ["await", "left", "right", "body"],
  ForStatement: ["init", "test", "update", "body"],
  FunctionDeclaration: ["id", "expression", "generator", "async", "params", "body"],
  FunctionExpression: ["id", "expression", "generator", "async", "params", "body"],
  Identifier: ["name"],
  IfStatement: ["test", "consequent", "alternate"],
  ImportAttribute: ["key", "value"],
  ImportDeclaration: ["specifiers", "source", "attributes"],
  ImportDefaultSpecifier: ["local"],
  ImportExpression: ["source", "options"],
  ImportNamespaceSpecifier: ["local"],
  ImportSpecifier: ["imported", "local"],
  LabeledStatement: ["label", "body"],
  LogicalExpression: ["left", "operator", "right"],
  MemberExpression: ["object", "property", "computed", "optional"],
  MetaProperty: ["meta", "property"],
  MethodDefinition: ["computed", "key", "value", "kind", "static"],
  NewExpression: ["callee", "arguments"],
  ObjectExpression: ["properties"],
  ObjectPattern: ["properties"],
  ParenthesizedExpression: ["expression"],
  PrivateIdentifier: ["name"],
  Program: ["body", "sourceType"],
  Property: ["method", "shorthand", "computed", "key", "value", "kind"],
  PropertyDefinition: ["computed", "key", "value", "static"],
  RestElement: ["argument"],
  ReturnStatement: ["argument"],
  SequenceExpression: ["expressions"],
  SpreadElement: ["argument"],
  StaticBlock: ["body"],
  Super: [],
  SwitchCase: ["test", "consequent"],
  SwitchStatement: ["discriminant", "cases"],
  TaggedTemplateExpression: ["tag", "quasi"],
  TemplateLiteral: ["expressions", "quasis"],
  ThisExpression: [],
  ThrowStatement: ["argument"],
  TryStatement: ["block", "handler", "finalizer"],
  UnaryExpression: ["operator", "prefix", "argument"],
  UpdateExpression: ["operator", "prefix", "argument"],
  VariableDeclaration: ["declarations", "kind"],
  VariableDeclarator: ["id", "init"],
  WhileStatement: ["test", "body"],
  WithStatement: ["object", "body"],
  YieldExpression: ["delegate", "argument"],
  CPSBVerifiedAcornRegion: ["sha256"],
  CPSBVerifiedFingerprintTable: ["locators"],
  CPSBVerifiedMutationValidatorPins: ["names", "literalTypes", "declarationShape"],
});
const CPSB_AST_OMITTED_FIELDS = new Set([
  "start", "end", "loc", "comments", "leadingComments", "trailingComments",
  "innerComments",
]);
const astCheck = (condition, token, locator) => {
  if (!condition) fail(token, locator);
};
const exactAstKeys = (node, fields, token, locator) => {
  const allowed = new Set(["type", ...fields, "start", "end", "loc"]);
  astCheck(
    Object.keys(node).every((key) => allowed.has(key)) &&
      fields.every((key) => Object.hasOwn(node, key)),
    token,
    locator,
  );
};
const projectLiteral = (node, token, locator) => {
  const allowed = new Set([
    "type", "value", "raw", "regex", "bigint", ...CPSB_AST_OMITTED_FIELDS,
  ]);
  astCheck(Object.keys(node).every((key) => allowed.has(key)), token, locator);
  if (Object.hasOwn(node, "regex")) {
    astCheck(
      node.regex && typeof node.regex.pattern === "string" &&
        typeof node.regex.flags === "string" &&
        same(Object.keys(node.regex).sort(), ["flags", "pattern"]),
      token,
      locator,
    );
    return {
      type: "Literal",
      literalType: "regexp",
      pattern: node.regex.pattern,
      flags: node.regex.flags,
    };
  }
  if (Object.hasOwn(node, "bigint")) {
    astCheck(
      typeof node.bigint === "string" && typeof node.value === "bigint",
      token,
      locator,
    );
    return { type: "Literal", literalType: "bigint", value: node.bigint };
  }
  const literalType = node.value === null ? "null" : typeof node.value;
  astCheck(
    ["null", "string", "boolean", "number"].includes(literalType),
    token,
    locator,
  );
  return { type: "Literal", literalType, value: node.value };
};
const projectTemplateElement = (node, token, locator) => {
  const allowed = new Set([
    "type", "value", "tail", ...CPSB_AST_OMITTED_FIELDS,
  ]);
  astCheck(
    Object.keys(node).every((key) => allowed.has(key)) &&
      node.value && same(Object.keys(node.value).sort(), ["cooked", "raw"]) &&
      typeof node.value.raw === "string" &&
      (node.value.cooked === null || typeof node.value.cooked === "string") &&
      typeof node.tail === "boolean",
    token,
    locator,
  );
  return {
    type: "TemplateElement",
    value: { raw: node.value.raw, cooked: node.value.cooked },
    tail: node.tail,
  };
};
const projectAstValue = (value, token, locator) => {
  if (value === null || ["string", "boolean", "number"].includes(typeof value)) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => projectAstValue(entry, token, locator));
  }
  astCheck(value && typeof value === "object" && typeof value.type === "string", token, locator);
  if (value.type === "Literal") return projectLiteral(value, token, locator);
  if (value.type === "TemplateElement") return projectTemplateElement(value, token, locator);
  const fields = CPSB_AST_NODE_FIELDS[value.type];
  astCheck(Array.isArray(fields), token, locator);
  const allowed = new Set(["type", ...fields, ...CPSB_AST_OMITTED_FIELDS]);
  astCheck(Object.keys(value).every((key) => allowed.has(key)), token, locator);
  const projected = { type: value.type };
  for (const field of fields) {
    if (Object.hasOwn(value, field)) {
      projected[field] = projectAstValue(value[field], token, locator);
    }
  }
  return projected;
};
const astFingerprint = (program, locator) => sha256(Buffer.from(
  `cpsb-reviewed-executable-ast-v1\0${
    canonicalJson(projectAstValue(program, "ACTIVATION_BOUNDARY", locator))
  }\n`,
));
const astContains = (value, nodeType) => {
  if (!value || typeof value !== "object") return false;
  if (value.type === nodeType) return true;
  return Object.values(value).some((entry) =>
    Array.isArray(entry)
      ? entry.some((item) => astContains(item, nodeType))
      : astContains(entry, nodeType)
  );
};
const identifierName = (node, token, locator) => {
  exactAstKeys(node, ["name"], token, locator);
  astCheck(node.type === "Identifier" && typeof node.name === "string", token, locator);
  return node.name;
};
const importAstRoster = (program, locator) => program.body
  .filter((node) => node.type === "ImportDeclaration")
  .map((node) => {
    exactAstKeys(node, ["specifiers", "source", "attributes"], "IMPORT_BOUNDARY", locator);
    astCheck(
      node.source.type === "Literal" && typeof node.source.value === "string" &&
        Array.isArray(node.attributes) && node.attributes.length === 0,
      "IMPORT_BOUNDARY",
      locator,
    );
    const specifiers = node.specifiers.map((specifier) => {
      if (specifier.type === "ImportDefaultSpecifier") {
        exactAstKeys(specifier, ["local"], "IMPORT_BOUNDARY", locator);
        return `default:${identifierName(specifier.local, "IMPORT_BOUNDARY", locator)}`;
      }
      if (specifier.type === "ImportNamespaceSpecifier") {
        exactAstKeys(specifier, ["local"], "IMPORT_BOUNDARY", locator);
        return `namespace:${identifierName(specifier.local, "IMPORT_BOUNDARY", locator)}`;
      }
      astCheck(specifier.type === "ImportSpecifier", "IMPORT_BOUNDARY", locator);
      exactAstKeys(specifier, ["imported", "local"], "IMPORT_BOUNDARY", locator);
      return `named:${identifierName(specifier.imported, "IMPORT_BOUNDARY", locator)}:${
        identifierName(specifier.local, "IMPORT_BOUNDARY", locator)
      }`;
    });
    return [node.source.value, specifiers];
  });
const exportAstRoster = (program, locator) => program.body
  .filter((node) => node.type.startsWith("Export"))
  .map((node) => {
    astCheck(node.type === "ExportNamedDeclaration", "EXPORT_BOUNDARY", locator);
    exactAstKeys(
      node,
      ["declaration", "specifiers", "source", "attributes"],
      "EXPORT_BOUNDARY",
      locator,
    );
    astCheck(
      node.source === null && node.specifiers.length === 0 &&
        node.attributes.length === 0 &&
        node.declaration?.type === "VariableDeclaration" &&
        node.declaration.kind === "const" &&
        node.declaration.declarations.length === 1 &&
        node.declaration.declarations[0].id?.type === "Identifier",
      "EXPORT_BOUNDARY",
      locator,
    );
    return `named-const:${node.declaration.declarations[0].id.name}`;
  });
const verifyAcornRegion = (bytes, source, program, locator) => {
  const beginLine = Buffer.from(`${ACORN_REGION_BEGIN}\n`),
    endLine = Buffer.from(`${ACORN_REGION_END}\n`),
    begin = bytes.indexOf(beginLine),
    end = bytes.indexOf(endLine);
  astCheck(
    begin >= 0 && end > begin && bytes.lastIndexOf(beginLine) === begin &&
      bytes.lastIndexOf(endLine) === end,
    "ACTIVATION_BOUNDARY",
    locator,
  );
  const regionStart = begin + beginLine.length,
    region = bytes.subarray(regionStart, end);
  astCheck(
    region.length === ACORN_REGION_BYTES && sha256(region) === ACORN_REGION_SHA256,
    "ACTIVATION_BOUNDARY",
    locator,
  );
  const declarations = program.body.filter((node) =>
    node.type === "VariableDeclaration" &&
    node.declarations.some((declaration) => declaration.id?.name === "acornParse")
  );
  astCheck(declarations.length === 1, "ACTIVATION_BOUNDARY", locator);
  const declaration = declarations[0], declarator = declaration.declarations[0],
    call = declarator?.init, arrow = call?.callee;
  astCheck(
    declaration.kind === "const" && declaration.declarations.length === 1 &&
      declarator.id?.type === "Identifier" && declarator.id.name === "acornParse" &&
      call?.type === "CallExpression" && call.optional === false &&
      call.arguments.length === 0 && arrow?.type === "ArrowFunctionExpression" &&
      arrow.async === false && arrow.generator === false && arrow.expression === false &&
      arrow.params.length === 0 && arrow.body?.type === "BlockStatement" &&
      Buffer.byteLength(source.slice(0, declaration.start)) === regionStart &&
      Buffer.byteLength(source.slice(0, declaration.end)) === end - 1,
    "ACTIVATION_BOUNDARY",
    locator,
  );
  return declaration;
};
const parsedFingerprintTable = (program, locator) => {
  const declarations = program.body.filter((node) =>
    node.type === "VariableDeclaration" &&
    node.declarations.some((declaration) =>
      declaration.id?.name === "CPSB_AST_FINGERPRINTS"
    )
  );
  astCheck(declarations.length === 1, "ACTIVATION_BOUNDARY", locator);
  const declaration = declarations[0], declarator = declaration.declarations[0],
    call = declarator?.init, callee = call?.callee, argument = call?.arguments?.[0];
  astCheck(
    declaration.kind === "const" && declaration.declarations.length === 1 &&
      declarator.id?.type === "Identifier" &&
      declarator.id.name === "CPSB_AST_FINGERPRINTS" &&
      call?.type === "CallExpression" && call.optional === false &&
      call.arguments.length === 1 && callee?.type === "MemberExpression" &&
      callee.computed === false && callee.optional === false &&
      callee.object?.type === "Identifier" && callee.object.name === "Object" &&
      callee.property?.type === "Identifier" && callee.property.name === "freeze" &&
      argument?.type === "ArrayExpression" && argument.elements.length === 5,
    "ACTIVATION_BOUNDARY",
    locator,
  );
  const rows = argument.elements.map((entry) => {
    astCheck(
      entry?.type === "ArrayExpression" && entry.elements.length === 2 &&
        entry.elements.every((item) =>
          item?.type === "Literal" && typeof item.value === "string"
        ),
      "ACTIVATION_BOUNDARY",
      locator,
    );
    return entry.elements.map((item) => item.value);
  });
  astCheck(
    same(rows.map(([rowLocator]) => rowLocator), CPSB_AST_LOCATORS) &&
      rows.every(([, fingerprint]) => /^[0-9a-f]{64}$/u.test(fingerprint)) &&
      same(rows, CPSB_AST_FINGERPRINTS),
    "ACTIVATION_BOUNDARY",
    locator,
  );
  return { declaration, rows };
};
const normalizedValidatorProgram = (bytes, source, program, locator) => {
  const acornDeclaration = verifyAcornRegion(bytes, source, program, locator),
    table = parsedFingerprintTable(program, locator);
  return {
    ...program,
    body: program.body.map((node) =>
      node === acornDeclaration
        ? { type: "CPSBVerifiedAcornRegion", sha256: ACORN_REGION_SHA256 }
        : node === table.declaration
        ? { type: "CPSBVerifiedFingerprintTable", locators: CPSB_AST_LOCATORS }
        : node
    ),
  };
};
const MUTATION_VALIDATOR_PIN_NAMES = Object.freeze([
  "H0_VALIDATOR_BYTES",
  "H0_VALIDATOR_RAW_SHA256",
]);
const parsedMutationValidatorPins = (program, locator) => {
  const matches = program.body.flatMap((node, index) =>
    node.type === "VariableDeclaration"
      ? node.declarations
        .filter((declarator) =>
          declarator.id?.type === "Identifier" &&
          MUTATION_VALIDATOR_PIN_NAMES.includes(declarator.id.name)
        )
        .map((declarator) => ({ declarator, index, name: declarator.id.name, node }))
      : []
  );
  astCheck(
    matches.length === 2 &&
      same(matches.map(({ name }) => name), MUTATION_VALIDATOR_PIN_NAMES) &&
      matches[1].index === matches[0].index + 1,
    "ACTIVATION_BOUNDARY",
    locator,
  );
  const literalValue = (match, literalType) => {
    exactAstKeys(match.node, ["declarations", "kind"], "ACTIVATION_BOUNDARY", locator);
    astCheck(
      match.node.kind === "const" && match.node.declarations.length === 1 &&
        match.node.declarations[0] === match.declarator &&
        match.declarator.id?.type === "Identifier" &&
        match.declarator.init?.type === "Literal",
      "ACTIVATION_BOUNDARY",
      locator,
    );
    exactAstKeys(match.declarator, ["id", "init"], "ACTIVATION_BOUNDARY", locator);
    exactAstKeys(match.declarator.id, ["name"], "ACTIVATION_BOUNDARY", locator);
    exactAstKeys(match.declarator.init, ["value", "raw"], "ACTIVATION_BOUNDARY", locator);
    astCheck(
      match.declarator.id.name === match.name &&
        typeof match.declarator.init.value === literalType,
      "ACTIVATION_BOUNDARY",
      locator,
    );
    return match.declarator.init.value;
  };
  const bytes = literalValue(matches[0], "number"),
    rawSha256 = literalValue(matches[1], "string");
  astCheck(
    Number.isSafeInteger(bytes) && bytes > 0 && /^[0-9a-f]{64}$/u.test(rawSha256),
    "ACTIVATION_BOUNDARY",
    locator,
  );
  return {
    bytes,
    firstIndex: matches[0].index,
    lastIndex: matches[1].index,
    rawSha256,
  };
};
const normalizedMutationProgram = (program, validatorBytes, locator) => {
  const pins = parsedMutationValidatorPins(program, locator);
  astCheck(
    pins.bytes === validatorBytes.length && pins.rawSha256 === sha256(validatorBytes),
    "ACTIVATION_BOUNDARY",
    locator,
  );
  return {
    ...program,
    body: [
      ...program.body.slice(0, pins.firstIndex),
      {
        type: "CPSBVerifiedMutationValidatorPins",
        names: MUTATION_VALIDATOR_PIN_NAMES,
        literalTypes: ["number", "string"],
        declarationShape: "adjacent-const-single-variable-declarator-identifier-literal",
      },
      ...program.body.slice(pins.lastIndex + 1),
    ],
  };
};
const isStaticPositiveDeclaration = (node, name, initializer) =>
  node?.type === "VariableDeclaration" && node.kind === "const" &&
  node.declarations.length === 1 && node.declarations[0].id?.type === "Identifier" &&
  node.declarations[0].id.name === name && initializer(node.declarations[0].init);
const normalizedStaticProgram = (program) => {
  const first = program.body.at(-2), second = program.body.at(-1),
    exactSuffix = isStaticPositiveDeclaration(
      first,
      "from",
      (init) => init?.type === "Literal" && init.value === 1,
    ) && isStaticPositiveDeclaration(
      second,
      "to",
      (init) => init?.type === "Identifier" && init.name === "from",
    );
  return exactSuffix ? { ...program, body: program.body.slice(0, -2) } : program;
};
const parseReviewedProgram = (source, locator) => {
  let program;
  try {
    program = acornParse(source, CPSB_AST_PARSE_OPTIONS);
  } catch {
    fail("ACTIVATION_BOUNDARY", locator);
  }
  astCheck(
    program?.type === "Program" && program.sourceType === "module",
    "ACTIVATION_BOUNDARY",
    locator,
  );
  astCheck(!astContains(program, "ImportExpression"), "IMPORT_BOUNDARY", locator);
  astCheck(
    same(importAstRoster(program, locator), CPSB_IMPORT_ROSTERS[locator]),
    "IMPORT_BOUNDARY",
    locator,
  );
  astCheck(
    same(exportAstRoster(program, locator), CPSB_EXPORT_ROSTERS[locator]),
    "EXPORT_BOUNDARY",
    locator,
  );
  return program;
};
const scanSources = (packageRoot) => {
  astCheck(
    same(AUTHORED_FILES.filter((file) => file.endsWith(".mjs")), CPSB_AST_LOCATORS),
    "ACTIVATION_BOUNDARY",
    "roster",
  );
  const validatorBytes = safeRead(packageRoot, "validate-static.mjs");
  for (const locator of CPSB_AST_LOCATORS) {
    const bytes = locator === "validate-static.mjs"
        ? validatorBytes
        : safeRead(packageRoot, locator),
      source = bytes.toString("utf8"),
      program = parseReviewedProgram(source, locator),
      normalized = locator === "validate-static.mjs"
        ? normalizedValidatorProgram(bytes, source, program, locator)
        : locator === "test/mutation.test.mjs"
        ? normalizedMutationProgram(program, validatorBytes, locator)
        : locator === "test/static.test.mjs"
        ? normalizedStaticProgram(program)
        : program,
      expected = CPSB_AST_FINGERPRINTS.find(([name]) => name === locator)?.[1];
    astCheck(
      typeof expected === "string" && astFingerprint(normalized, locator) === expected,
      "ACTIVATION_BOUNDARY",
      locator,
    );
  }
};
const checkDocs = (packageRoot) => {
  const read = (name) => safeRead(packageRoot, name).toString("utf8"),
    readme = read("README.md"),
    command = read("COMMAND.txt");
  const readmeSentences = [
      "This package is a static, nonauthorizing, zero-record additive control-plane schema bridge. It may exist only as the exact source-unsealed 27-file closure or the exact anchored-sealed 29-file closure; it creates, authenticates, issues, selects, binds, authorizes, instantiates, admits, executes, measures, qualifies, ranks, or promotes nothing.",
      "The bridge repairs only future record grammar and content-hash ordering: selectedDag remains null, authorizedTransitions remains empty, every record count remains zero, and no principal, issuer decision, authority contract, provider contract, G0 authorization, provider binding, reviewed catalog, G1 authorization, B0 execution authorization, instance, admission, or execution exists or is permitted by this package.",
      "The sealed gate-b0-external-authority-prerequisite-policy-v1 package remains the governing static prerequisite policy; only its future record-instantiation templates are superseded by this additive v2 future-record language.",
      "Raw-artifact-map authority and independent-result-validator authority remain external-authority-contract payload variants, not packages, implementations, provider instances, artifact-map instances, validator evaluations, or results created here.",
      "Source-unsealed validation is nonauthoritative review, and anchored-sealed validation is also nonauthorizing closure verification.",
      "Before importing or evaluating validate-static.mjs or any test, a caller-controlled launcher must independently raw-pin every authored byte; in sealed mode it must additionally pin and verify the outside-package review anchor before trusting package-local bytes.",
      "Before starting Node, that launcher must also authenticate the absolute Node executable, repository package.json and package-lock.json, and every regular file in the resolved Ajv 8.20.0 runtime dependency closure from an externally held ordered byte-and-hash table; it must reject links, specials, and extra closure entries, clear loader and preload injection inputs, and invoke only an authenticated read-only snapshot.",
      "The dynamic loader, libc, kernel, host shell and hashing implementation, and hardware remain explicit external host TCB inputs unless the caller separately authenticates them; this package does not authenticate or authorize those inputs.",
      "The parent EAPP root, validator, envelope, outside anchor, the sealed SSA source-language authority, and EAC, B0R, UOPC, and SPM roots are pinned constraint inputs only and grant this bridge no transitive authority.",
      "The validator contains an exact MIT-licensed Acorn 8.18.0 build-time parser region whose transformed bytes are internally pinned; external raw authentication of the complete validator remains the only authority for executing that parser.",
      "Source activation review is an exact reviewed-AST allowlist: any executable AST drift requires independent review, new authorized fingerprints, a new validator raw pin, and resealing, even when the edit appears benign.",
      "Reviewed-AST identity normalizes only the raw-verified Acorn declaration, the exact five-row fingerprint-table declaration, the two exact mutation-test validator-pin declarations whose values are separately checked against the target validator bytes, and the exact terminal `const from=1; const to=from;` static-test positive fixture; every other executable AST change requires a new fingerprint.",
    ],
    commandSentences = [
      "Direct package-local Node invocations are nonauthorizing diagnostic self-checks only and cannot authenticate the bytes they import or execute.",
      "Before either form is invoked, a caller-controlled outside-package launcher must independently verify an externally held exact locator, byte-count, and raw-SHA-256 table for all 27 authored files, including validate-static.mjs and every test.",
      "For sealed validation that launcher must first independently raw-pin and parse the outside review anchor and verify its exact identity, ordered closure, root, validator, schemas, MANIFEST.json, and SHA256SUMS bindings.",
      "Before starting Node, the launcher must also verify externally held exact byte-and-hash rows for the absolute Node executable, repository package.json and package-lock.json, and the full installed Ajv 8.20.0 runtime dependency closure; it must reject links, specials, and extra closure entries, copy all authenticated inputs into a private read-only snapshot, and clear NODE_OPTIONS, NODE_PATH, preload, import, and custom-loader injection.",
      "The dynamic loader, libc, kernel, host shell and hashing implementation, and hardware remain explicit external host TCB inputs unless separately authenticated by the caller.",
      "In those forms, node denotes the already authenticated absolute executable operating only on the authenticated snapshot.",
      "The shell variables are caller-owned literal pins; validate-static.mjs has no environment fallback or sealed default.",
    ];
  for (const sentence of readmeSentences) {
    check(readme.split(sentence).length === 2, "DOCUMENTATION");
  }
  for (const sentence of commandSentences) {
    check(command.split(sentence).length === 2, "DOCUMENTATION");
  }
  check(
    command.includes("node validate-static.mjs --mode unsealed") &&
      command.includes(
        'node validate-static.mjs --mode sealed --anchor-root "$CPSB_ANCHOR_ROOT" --anchor-locator "$CPSB_ANCHOR_LOCATOR" --anchor-bytes "$CPSB_ANCHOR_BYTES" --anchor-raw-sha256 "$CPSB_ANCHOR_RAW_SHA256"',
      ),
    "DOCUMENTATION",
  );
};
const localRefs = (value) => {
  const refs = [];
  const visit = (node) => {
    if (!node || typeof node !== "object") return;
    if (typeof node.$ref === "string") refs.push(node.$ref);
    for (const child of Object.values(node)) visit(child);
  };
  visit(value);
  return refs;
};
const checkSchemas = (packageRoot) => {
  const schemas = new Map(),
    banned = new Set([
      "$dynamicRef",
      "$recursiveRef",
      "$anchor",
      "$dynamicAnchor",
      "patternProperties",
      "unevaluatedProperties",
      "default",
    ]);
  for (const locator of SCHEMAS) {
    const bytes = safeRead(packageRoot, locator),
      schema = strictParse(bytes, { canonical: true });
    check(
      schema.$id === `${SCHEMA_PREFIX}${basename(locator)}`,
      "SCHEMA_ID",
      locator,
    );
    const inspect = (node) => {
      if (!node || typeof node !== "object") return;
      for (const entry of Object.entries(node)) {
        check(!banned.has(entry[0]), "SCHEMA_REF", entry[0]);
        inspect(entry[1]);
      }
    };
    inspect(schema);
    schemas.set(schema.$id, schema);
  }
  const rootSeed = `${SCHEMA_PREFIX}root.v1.schema.json#/$defs/root`,
    manifestSeed = `${SCHEMA_PREFIX}manifest.v1.schema.json#/$defs/manifest`,
    rootValue = parseRoot(packageRoot),
    seeds = [
      rootSeed,
      manifestSeed,
      ...rootValue.futureRecordContracts.entries.map((row) =>
        `${row.schemaId}${row.definitionPointer}`
      ),
    ],
    seen = new Set(),
    queue = [...seeds];
  while (queue.length) {
    const ref = queue.shift();
    if (seen.has(ref)) continue;
    const hash = ref.indexOf("#"),
      id = hash < 0 ? ref : ref.slice(0, hash),
      fragment = hash < 0 ? "" : ref.slice(hash + 1),
      schema = schemas.get(id);
    check(schema, "SCHEMA_REF", ref);
    let node = schema;
    if (fragment) {
      const name = fragment.replace(/^\/\$defs\//, "");
      check(name && schema.$defs?.[name], "SCHEMA_REF", ref);
      node = schema.$defs[name];
    }
    seen.add(ref);
    for (const nested of localRefs(node)) {
      queue.push(nested.startsWith("#") ? `${id}${nested}` : nested);
    }
  }
  for (const schema of schemas.values()) {
    for (const ref of localRefs(schema)) {
      const hash = ref.indexOf("#"),
        id = ref.startsWith("#")
          ? schema.$id
          : hash < 0
          ? ref
          : ref.slice(0, hash),
        fragment = ref.startsWith("#")
          ? ref.slice(1)
          : hash < 0
          ? ""
          : ref.slice(hash + 1);
      check(id.startsWith(SCHEMA_PREFIX) && schemas.has(id), "SCHEMA_REF", ref);
      if (fragment) {
        const name = fragment.replace(/^\/\$defs\//, "");
        check(name && schemas.get(id).$defs?.[name], "SCHEMA_REF", ref);
      }
    }
  }
  check(
    SCHEMAS.every((locator) =>
      [...seen].some((ref) =>
        ref.startsWith(`${SCHEMA_PREFIX}${basename(locator)}`)
      )
    ) && [...schemas.values()].every((schema) =>
      Object.keys(schema.$defs ?? {}).every((name) =>
        seen.has(`${schema.$id}#/$defs/${name}`)
      )
    ),
    "SCHEMA_REACHABILITY",
  );
  check(
    same(SCHEMA_SEMANTIC_FINGERPRINTS.map(([locator]) => locator), SCHEMAS),
    "SCHEMA_COMPILE",
    "semantic-fingerprint-roster",
  );
  for (const [locator, expected] of SCHEMA_SEMANTIC_FINGERPRINTS) {
    const schema = schemas.get(`${SCHEMA_PREFIX}${basename(locator)}`);
    check(
      schema && sha256(Buffer.from(canonicalJson(schema))) === expected,
      "SCHEMA_COMPILE",
      `semantic-fingerprint:${locator}`,
    );
  }
  const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    validateFormats: false,
  });
  for (const schema of schemas.values()) ajv.addSchema(schema);
  try {
    for (const schema of schemas.values()) {
      ajv.getSchema(schema.$id) ?? ajv.compile(schema);
    }
  } catch {
    fail("SCHEMA_COMPILE");
  }
  return { schemas, ajv };
};
const parseRoot = (packageRoot) =>
  strictParse(safeRead(packageRoot, ROOT_FILE), { canonical: true });
const assertSealedRootPin = (packageRoot, anchor) => {
  if (!anchor) return;
  const bytes = safeRead(packageRoot, ROOT_FILE);
  check(sha256(bytes) === anchor.rootRawSha256, "ANCHOR_RAW", "root");
};
const RFC3339_UTC =
  /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.(\d+))?Z$/;
const isLeapYear = (year) =>
  year % 4n === 0n && (year % 100n !== 0n || year % 400n === 0n);
const daysInMonth = (year, month) => [
  31n,
  isLeapYear(year) ? 29n : 28n,
  31n,
  30n,
  31n,
  30n,
  31n,
  31n,
  30n,
  31n,
  30n,
  31n,
][Number(month - 1n)];
const floorDiv = (dividend, divisor) => {
  const quotient = dividend / divisor, remainder = dividend % divisor;
  return remainder !== 0n && (remainder > 0n) !== (divisor > 0n)
    ? quotient - 1n
    : quotient;
};
const daysSinceUnixEpoch = (year, month, day) => {
  const adjustedYear = year - (month <= 2n ? 1n : 0n),
    era = floorDiv(adjustedYear, 400n),
    yearOfEra = adjustedYear - era * 400n,
    adjustedMonth = month + (month > 2n ? -3n : 9n),
    dayOfYear = floorDiv(153n * adjustedMonth + 2n, 5n) + day - 1n,
    dayOfEra = yearOfEra * 365n + floorDiv(yearOfEra, 4n) -
      floorDiv(yearOfEra, 100n) + dayOfYear;
  return era * 146097n + dayOfEra - 719468n;
};
/* Exact tuple: seconds are integral; trailing-zero-normalized fraction is lexical. */
const strictUtcTime = (value) => {
  if (typeof value !== "string") return null;
  const match = value.match(RFC3339_UTC);
  if (!match) return null;
  const yearText = match[1], monthText = match[2], dayText = match[3],
    hourText = match[4], minuteText = match[5], secondText = match[6],
    fraction = match[7] ?? "";
  const year = BigInt(yearText), month = BigInt(monthText), day = BigInt(dayText);
  if (day > daysInMonth(year, month)) return null;
  return Object.freeze({
    seconds: daysSinceUnixEpoch(year, month, day) * 86400n +
      BigInt(hourText) * 3600n + BigInt(minuteText) * 60n + BigInt(secondText),
    fraction: fraction.replace(/0+$/u, ""),
  });
};
const compareUtcTime = (left, right) => {
  if (left.seconds !== right.seconds) return left.seconds < right.seconds ? -1 : 1;
  const width = Math.max(left.fraction.length, right.fraction.length);
  for (let index = 0; index < width; index++) {
    const leftDigit = left.fraction.charCodeAt(index) || 48,
      rightDigit = right.fraction.charCodeAt(index) || 48;
    if (leftDigit !== rightDigit) return leftDigit < rightDigit ? -1 : 1;
  }
  return 0;
};
const utcTimeEqual = (left, right) => compareUtcTime(left, right) === 0;
const utcTimeBefore = (left, right) => compareUtcTime(left, right) === -1;
const utcTimeAtOrBefore = (left, right) => compareUtcTime(left, right) !== 1;
const validTimeOrder = (start, end) => {
  const a = strictUtcTime(start), b = strictUtcTime(end);
  return a !== null && b !== null && utcTimeBefore(a, b);
};
const checkTemporalSchemaContracts = (schemas) => {
  const principal =
      schemas.get(`${SCHEMA_PREFIX}principal-identity-ref.v1.schema.json`).$defs
        .principalIdentityRef,
    issuer = schemas.get(`${SCHEMA_PREFIX}issuer-decision.v1.schema.json`).$defs
      .issuerDecision;
  check(
    principal.required.includes("validFrom") &&
      principal.required.includes("expiresAt") &&
      issuer.required.includes("issuedAt") &&
      issuer.required.includes("expiresAt"),
    "IDENTITY_SCHEMA",
    "time-roster",
  );
  check(
    validTimeOrder("2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z") &&
      !validTimeOrder("2026-01-01T00:00:01Z", "2026-01-01T00:00:00Z"),
    "ISSUER_DECISION_SCHEMA",
    "time-order",
  );
};
const EAPP_PREFIX =
    "shieldkit-labs/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1",
  SSA_PREFIX = "shieldkit-labs/p2/gate-b/gate-b0-static-source-authority/v1";
const EAPP_AUTHORED = [
  "COMMAND.txt",
  "README.md",
  "external-authority-prerequisite-policy-root.v1.json",
  "schemas/authority-policy.v1.schema.json",
  "schemas/causal-dag.v1.schema.json",
  "schemas/creation-transition-policy.v1.schema.json",
  "schemas/dependency-binding.v1.schema.json",
  "schemas/digest.v1.schema.json",
  "schemas/future-external-authority-contract.v1.schema.json",
  "schemas/future-governance-authorization.v1.schema.json",
  "schemas/manifest.v1.schema.json",
  "schemas/non-authority-boundary.v1.schema.json",
  "schemas/provider-binding-policy.v1.schema.json",
  "schemas/requirement-authority-map.v1.schema.json",
  "schemas/root.v1.schema.json",
  "test/digest.kat.json",
  "test/mutation.test.mjs",
  "test/package-boundary.test.mjs",
  "test/source-collision.test.mjs",
  "test/static.test.mjs",
  "validate-static.mjs",
];
const SSA_AUTHORED = [
  "COMMAND.txt",
  "README.md",
  "schemas/dependency-pin.v1.schema.json",
  "schemas/digest.v1.schema.json",
  "schemas/governance.v1.schema.json",
  "schemas/manifest.v1.schema.json",
  "schemas/non-authority-boundary.v1.schema.json",
  "schemas/owner-contract-source-catalog.v1.schema.json",
  "schemas/private-capture-source-catalog.v1.schema.json",
  "schemas/raw-artifact-map-source-contract.v1.schema.json",
  "schemas/requirement-resolution.v1.schema.json",
  "schemas/result-validator-source-contract.v1.schema.json",
  "schemas/retry-lineage-source-catalog.v1.schema.json",
  "schemas/root.v1.schema.json",
  "schemas/source-contract.v1.schema.json",
  "schemas/state-fact-source-catalog.v1.schema.json",
  "schemas/workload-projection-source-catalog.v1.schema.json",
  "static-source-authority-root.v1.json",
  "test/digest.kat.json",
  "test/mutation.test.mjs",
  "test/package-boundary.test.mjs",
  "test/source-resolution.test.mjs",
  "test/static.test.mjs",
  "validate-static.mjs",
];
const EAPP_COMPONENTS = Object.freeze([
  ["dependencyBinding", "dependency-binding"],
  ["governanceBoundary", "governance-boundary"],
  ["authorityPolicyGroups", "authority-policy-groups"],
  ["supplementalPolicies", "supplemental-policies"],
  ["requirementAuthorityMap", "requirement-authority-map"],
  ["sourceCollisions", "source-collisions"],
  ["creationTransitionPolicy", "creation-transition-policy"],
  ["providerBindingPolicy", "provider-binding-policy"],
  [
    "futureGovernanceAuthorizationSchema",
    "future-governance-authorization-schema",
  ],
  [
    "futureExternalAuthorityContractSchema",
    "future-external-authority-contract-schema",
  ],
  ["independenceConstraints", "independence-constraints"],
  ["causalDag", "causal-dag"],
  ["nonAuthorityBoundary", "nonauthority-boundary"],
  ["runtimeBoundary", "runtime-boundary"],
  ["schemaBindings", "schema-bindings"],
]);
const SSA_COMPONENTS = Object.freeze([
  ["governance", "governance"],
  ["dependencyPins", "dependencies"],
  ["transitiveSourcePins", "transitive-source-pins"],
  ["ownerContractSourceCatalog", "owner-contract-source-catalog"],
  ["retryLineageSourceCatalog", "retry-lineage-source-catalog"],
  ["privateCaptureSourceCatalog", "private-capture-source-catalog"],
  ["workloadProjectionSourceCatalog", "workload-projection-source-catalog"],
  ["stateFactSourceCatalog", "state-fact-source-catalog"],
  ["supplementalContracts", "supplemental-contracts"],
  ["requirementResolutions", "requirement-resolutions"],
  ["preauthorizationSemantics", "preauthorization-semantics"],
  ["nonAuthorityBoundary", "nonauthority-boundary"],
  ["runtimeBoundary", "runtime-boundary"],
  ["schemaBindings", "schema-bindings"],
]);
const EAC_COMPONENTS = Object.freeze([
  ["externalRequirements", "external-requirements"],
  ["futureArtifactMapContract", "future-artifact-map-contract"],
  ["futureResultAdmissionContract", "future-result-admission-contract"],
  ["futureStateGrammar", "future-state-grammar"],
  ["historicalDisposition", "historical-disposition"],
  ["nonAuthorityBoundary", "nonauthority-boundary"],
  ["sourcePins", "source-pins"],
]);
const EAPP_REQUIREMENT_STATIC_KINDS = Object.freeze([
  "ENDPOINT_BYTE_AUTHORITY_SOURCE_SCHEMA",
  "LIVE_F_PRIVATE_CAPTURE_SOURCE_SCHEMA",
  "ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA",
  "OWNER_BOUND_A_FACT_SOURCE_SCHEMA",
  "OWNER_BOUND_B_FACT_SOURCE_SCHEMA",
  "OWNER_BOUND_C_FACT_SOURCE_SCHEMA",
  "OWNER_BOUND_D_FACT_SOURCE_SCHEMA",
  "OWNER_BOUND_LIVE_F_FACT_SOURCE_SCHEMA",
  "OWNER_BOUND_Q_FACT_SOURCE_SCHEMA",
  "PRIVATE_DISPATCH_PLAN_SOURCE_SCHEMA",
  "RETRY_TARGET_SOURCE_SCHEMA",
  "RETRY_TERMINAL_PREDECESSOR_SOURCE_SCHEMA",
  "UPSTREAM_OWNER_CONTRACT_SCHEMA",
  "WORKER_ROWS_OWNER_BINDING_SOURCE_SCHEMA",
  "WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE",
  "WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE",
  "WORKLOAD_ROOT_SOURCE_SCHEMA",
]);
const EAPP_REQUIREMENT_SUPPLEMENTAL_KINDS = Object.freeze([
  "RAW_ARTIFACT_MAP_AUTHORITY_SOURCE_CONTRACT",
]);
const EAPP_REQUIREMENT_SPM_REFS = Object.freeze([
  [0], [0], [0], [0], [0], [0], [0], [1, 2], [3], [4, 5], [4, 5],
  [4, 5], [4, 5], [6], [1, 2], [3], [6, 7], [9], [1, 2, 9], [9],
  [10], [10], [10], [3, 11], [12], [11, 12], [13], [14], [8],
  [6, 7, 8, 15],
]);
const EAPP_REQUIREMENT_CONTEXTUAL_KINDS = Object.freeze({
  FROZEN_SURFACE_ORDER_PROVIDER: Object.freeze([
    "ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA",
    "WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE",
    "WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE",
  ]),
  ENDPOINT_CONTROL_ORDER_PROVIDER: Object.freeze([
    "ORDERED_WORKLOAD_ROOTS_SOURCE_SCHEMA",
    "WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE",
    "WORKLOAD_ROOT_PROJECTION_ENCODING_SOURCE",
  ]),
  WORKLOAD_ROOT_ORDER_PROVIDER: Object.freeze([
    "WORKLOAD_ROOT_SOURCE_SCHEMA",
  ]),
  WORKLOAD_PROJECTION_PROVIDER: Object.freeze([
    "WORKLOAD_ROOT_DIGEST_DOMAIN_SOURCE",
  ]),
});
const EAPP_ANCHOR_KEYS = Object.freeze([
  "artifactId",
  "componentDigests",
  "directDependencyBinding",
  "entryCount",
  "manifestRawSha256",
  "nonAuthorityBoundary",
  "orderedClosure",
  "package",
  "packageId",
  "rootContentDigest",
  "rootRawSha256",
  "rosterDigest",
  "schema",
  "schemaBindingTableDigest",
  "schemaBindings",
  "sha256SumsRawSha256",
  "sourceCollisionDigest",
  "status",
  "validatorRawSha256",
]);
const SSA_ANCHOR_KEYS = Object.freeze([
  "artifactId",
  "componentDigests",
  "directDependencyBinding",
  "entryCount",
  "manifestRawSha256",
  "nonAuthorityBoundary",
  "orderedClosure",
  "package",
  "packageId",
  "rootContentDigest",
  "rootRawSha256",
  "rosterDigest",
  "schema",
  "schemaBindingTableDigest",
  "schemaBindings",
  "sha256SumsRawSha256",
  "status",
  "transitiveSourcePinTableDigest",
  "validatorRawSha256",
]);
const SOURCE_PIN_IDS = [
  "pin:parent:b0r-root",
  "pin:parent:b0r-manifest",
  "pin:parent:b0r-sums",
  "pin:parent:b0r-validator",
  "pin:parent:b0r-anchor",
  "pin:foundation:p-root",
  "pin:foundation:p-manifest",
  "pin:foundation:p-sums",
  "pin:foundation:r-root",
  "pin:foundation:r-manifest",
  "pin:foundation:r-sums",
  "pin:foundation:k-root",
  "pin:foundation:k-manifest",
  "pin:foundation:k-sums",
  "pin:foundation:f-root",
  "pin:foundation:f-manifest",
  "pin:foundation:f-sums",
  "pin:origin:live-root",
  "pin:origin:live-manifest",
  "pin:origin:live-sums",
  "pin:origin:cabm-root",
  "pin:origin:cabm-manifest",
  "pin:origin:cabm-sums",
  "pin:origin:ecoc-root",
  "pin:origin:ecoc-manifest",
  "pin:origin:ecoc-sums",
  "pin:origin:uopc-root",
  "pin:origin:uopc-manifest",
  "pin:origin:uopc-sums",
  "pin:origin:source-map-root",
  "pin:origin:source-map-manifest",
  "pin:origin:source-map-sums",
  "pin:history:attempt000-auth",
  "pin:history:attempt000-schema",
  "pin:history:accounting-root",
  "pin:history:abort-receipt",
  "pin:history:accounting-manifest",
  "pin:history:accounting-sums",
  "pin:history:retry-wrapper",
  "pin:history:retry-manifest",
  "pin:history:retry-sums",
  "pin:history:v3-contract",
  "pin:history:v3-manifest",
  "pin:history:v3-sums",
  "pin:history:v3-freeze",
  "pin:history:v3-schema",
  "pin:frozen:campaign",
  "pin:frozen:corpus",
  "pin:frozen:fixtures",
  "pin:frozen:work-items",
  "pin:frozen:epoch",
  "pin:frozen:manifest",
  "pin:frozen:sums",
  "pin:frozen:construction",
  "pin:frozen:schedule",
  "pin:frozen:descriptor-m31d5",
  "pin:frozen:descriptor-m31d6",
  "pin:frozen:descriptor-m61d3",
  "pin:frozen:descriptor-m89d2",
  "pin:frozen:engine-native",
  "pin:frozen:engine-libauth",
  "pin:frozen:engine-bchn",
  "pin:frozen:engine-leanbch",
  "pin:frozen:engine-schema",
];
const DIRECT_SOURCE_RULES = [[
  "EAC",
  "shieldkit-labs/p2/gate-b/gate-b0-execution-admission-contract/v1/root",
  "utf8(domain)||0x00||canonical-json-utf8||0x0a",
], [
  "B0R",
  "shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/root",
  "utf8(domain)||0x00||canonical-json-utf8||0x0a",
], [
  "UOPC",
  "shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/model-root",
  "utf8(domain)||0x00||canonical-json-utf8-lf-v1",
], [
  "SPM",
  "shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root",
  "utf8(domain)||0x00||canonical-json-utf8-lf-v1",
]];
const sourceDigest = (
  domain,
  value,
  frame = "utf8(domain)||0x00||canonical-json-utf8||0x0a",
) => ({
  algorithm: "sha256",
  canonicalization:
    "recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1",
  domain,
  frame,
  value: sha256(
    Buffer.concat([
      Buffer.from(domain),
      Buffer.from([0]),
      Buffer.from(`${canonicalJson(value)}\n`),
    ]),
  ),
});
const sourceFileDigest = (prefix, locator, bytes) => {
  const domain = `${prefix}/file/${locator}`;
  return {
    algorithm: "sha256",
    canonicalization: "raw-file-bytes-v1",
    domain,
    frame: "utf8(domain)||0x00||raw-file-bytes",
    value: sha256(
      Buffer.concat([Buffer.from(domain), Buffer.from([0]), bytes]),
    ),
  };
};
const sourceHash = (domain, value, pretty = false, noLf = false) => {
  const encoded = noLf
    ? canonicalJson(value)
    : pretty
    ? `${JSON.stringify(JSON.parse(canonicalJson(value)), null, 2)}\n`
    : `${canonicalJson(value)}\n`;
  return sha256(
    Buffer.concat([
      Buffer.from(domain),
      Buffer.from([0]),
      Buffer.from(encoded),
    ]),
  );
};
const RAW_SEMANTIC_PIN_IDS = Object.freeze([
  "pin:parent:b0r-sums",
  "pin:parent:b0r-validator",
  "pin:parent:b0r-anchor",
  "pin:foundation:p-sums",
  "pin:foundation:r-sums",
  "pin:foundation:k-root",
  "pin:foundation:k-sums",
  "pin:foundation:f-sums",
  "pin:origin:live-sums",
  "pin:origin:cabm-sums",
  "pin:origin:ecoc-sums",
  "pin:origin:uopc-sums",
  "pin:origin:source-map-sums",
  "pin:history:attempt000-schema",
  "pin:history:accounting-sums",
  "pin:history:retry-sums",
  "pin:history:v3-sums",
  "pin:history:v3-schema",
  "pin:frozen:manifest",
  "pin:frozen:sums",
  "pin:frozen:engine-schema",
]);
const semanticRule = (type, domain = null, bindingKinds = []) =>
  Object.freeze({ type, domain, bindingKinds: Object.freeze(bindingKinds) });
const SEMANTIC_RULES = Object.freeze(
  Object.assign(
    Object.fromEntries(
      RAW_SEMANTIC_PIN_IDS.map((id) => [id, semanticRule("RAW")]),
    ),
    {
      "pin:parent:b0r-root": semanticRule(
        "COMPACT",
        "shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:parent:b0r-manifest": semanticRule(
        "ENTRIES",
        "shieldkit-labs/p2/gate-b/gate-b0-evidence-plan/v1/manifest-roster",
        ["MANIFEST_ROSTER_DIGEST"],
      ),
      "pin:foundation:p-root": semanticRule(
        "COMPACT",
        "shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:foundation:p-manifest": semanticRule(
        "FILES",
        "shieldkit-labs/p2/gate-b/cohort-policy-authority/v1/manifest-roster",
        ["MANIFEST_ROSTER_DIGEST"],
      ),
      "pin:foundation:r-root": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/cohort-runtime-binding/v1/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:foundation:r-manifest": semanticRule(
        "PRETTY_MANIFEST",
        "shieldkit-labs/p2/gate-b/cohort-runtime-binding/v1/file-content",
        ["MANIFEST_CONTENT_DIGEST"],
      ),
      "pin:foundation:k-manifest": semanticRule("K", null, [
        "K_MANIFEST_PACKAGE_ROOT",
        "K_MANIFEST_ROOT",
        "K_ENTRIES_ROOT",
      ]),
      "pin:foundation:f-root": semanticRule(
        "COMPACT",
        "shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:foundation:f-manifest": semanticRule(
        "F_MANIFEST",
        "shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/manifest",
        ["MANIFEST_CONTENT_DIGEST", "MANIFEST_ROSTER_DIGEST"],
      ),
      "pin:origin:live-root": semanticRule(
        "COMPACT",
        "shieldkit-labs/p2/gate-b/cohort-live-executor/v2/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:origin:live-manifest": semanticRule(
        "PACKAGE_ENTRIES",
        "shieldkit-labs/p2/gate-b/cohort-live-executor/v2/manifest-roster",
        ["MANIFEST_ROSTER_DIGEST"],
      ),
      "pin:origin:cabm-root": semanticRule(
        "COMPACT",
        "shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:origin:cabm-manifest": semanticRule(
        "PACKAGE_ENTRIES",
        "shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/manifest-roster",
        ["MANIFEST_ROSTER_DIGEST"],
      ),
      "pin:origin:ecoc-root": semanticRule(
        "COMPACT",
        "shieldkit-labs/p2/gate-b/cohort-external-origin-contract/v1/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:origin:ecoc-manifest": semanticRule(
        "PACKAGE_ENTRIES",
        "shieldkit-labs/p2/gate-b/cohort-external-origin-contract/v1/manifest-roster",
        ["MANIFEST_ROSTER_DIGEST"],
      ),
      "pin:origin:uopc-root": semanticRule(
        "COMPACT",
        "shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/model-root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:origin:uopc-manifest": semanticRule(
        "AUTHORED",
        "shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/manifest-roster",
        ["MANIFEST_ROSTER_DIGEST"],
      ),
      "pin:origin:source-map-root": semanticRule(
        "COMPACT",
        "shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/model-root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:origin:source-map-manifest": semanticRule(
        "AUTHORED",
        "shieldkit-labs/p2/gate-b/cohort-upstream-provider-source-map/v1/manifest-roster",
        ["MANIFEST_ROSTER_DIGEST"],
      ),
      "pin:history:attempt000-auth": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/cohort-executor-v2/authorization/v2/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:history:accounting-root": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/cohort-attempt-accounting/v1/root/attempt-000",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:history:abort-receipt": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/cohort-attempt-accounting/v1/receipt/attempt-000",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:history:accounting-manifest": semanticRule(
        "PRETTY_MANIFEST",
        "shieldkit-labs/p2/gate-b/cohort-attempt-accounting-v1/package-manifest/root",
        ["MANIFEST_CONTENT_DIGEST"],
      ),
      "pin:history:retry-wrapper": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/cohort-retry/v1/attempt-001",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:history:retry-manifest": semanticRule(
        "PRETTY_MANIFEST",
        "shieldkit-labs/p2/gate-b/cohort-retry/v1/package-manifest/root",
        ["MANIFEST_CONTENT_DIGEST"],
      ),
      "pin:history:v3-contract": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/execution-contract/v3/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:history:v3-manifest": semanticRule(
        "PRETTY_MANIFEST",
        "shieldkit-labs/p2/gate-b/cohort-execution-v3/package-manifest/root",
        ["MANIFEST_CONTENT_DIGEST"],
      ),
      "pin:history:v3-freeze": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/cohort-v3-freeze/v1/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:frozen:campaign": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/campaign/v2/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:frozen:corpus": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/canonical-corpus/v2/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:frozen:fixtures": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture-roster",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:frozen:work-items": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/execution-epoch/v2/work-item-roster",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:frozen:epoch": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/execution-epoch/v2/root",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:frozen:construction": semanticRule("UNFRAMED", null, [
        "CONTENT_DIGEST_STRING",
      ]),
      "pin:frozen:schedule": semanticRule("UNFRAMED", null, [
        "CONTENT_DIGEST_RECORD_VALUE",
      ]),
      "pin:frozen:descriptor-m31d5": semanticRule("UNFRAMED", null, [
        "CONTENT_DIGEST_RECORD_VALUE",
      ]),
      "pin:frozen:descriptor-m31d6": semanticRule("UNFRAMED", null, [
        "CONTENT_DIGEST_RECORD_VALUE",
      ]),
      "pin:frozen:descriptor-m61d3": semanticRule("UNFRAMED", null, [
        "CONTENT_DIGEST_RECORD_VALUE",
      ]),
      "pin:frozen:descriptor-m89d2": semanticRule("UNFRAMED", null, [
        "CONTENT_DIGEST_RECORD_VALUE",
      ]),
      "pin:frozen:engine-native": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/engine:native",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:frozen:engine-libauth": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/engine:libauth",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:frozen:engine-bchn": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/engine:bchn",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
      "pin:frozen:engine-leanbch": semanticRule(
        "PRETTY",
        "shieldkit-labs/p2/gate-b/execution-epoch/v2/engine/engine:leanbch",
        ["CONTENT_DIGEST_RECORD_VALUE"],
      ),
    },
  ),
);
const UOPC_AUTHORED_LOCATORS = Object.freeze([
  "COMMAND.txt",
  "README.md",
  "schemas/dependency-catalog.v1.schema.json",
  "schemas/digest.v1.schema.json",
  "schemas/external-origin-provider-catalog.v1.schema.json",
  "schemas/fact-provider-catalog.v1.schema.json",
  "schemas/manifest.v1.schema.json",
  "schemas/model-root.v1.schema.json",
  "schemas/order-provider-catalog.v1.schema.json",
  "schemas/owner-provider-catalog.v1.schema.json",
  "schemas/projection-provider-catalog.v1.schema.json",
  "schemas/provider-dag.v1.schema.json",
  "schemas/root-provider-catalog.v1.schema.json",
  "test/digest.kat.json",
  "test/mutation.test.mjs",
  "test/package-boundary.test.mjs",
  "test/static.test.mjs",
  "upstream-origin-provider-contract-root.v1.json",
  "validate-static.mjs",
]);
const SOURCE_MAP_AUTHORED_LOCATORS = Object.freeze([
  "COMMAND.txt",
  "README.md",
  "upstream-provider-source-map-root.v1.json",
  "schemas/b1-reentry-boundary.v1.schema.json",
  "schemas/dependency-catalog.v1.schema.json",
  "schemas/digest.v1.schema.json",
  "schemas/interface-source-map.v1.schema.json",
  "schemas/manifest.v1.schema.json",
  "schemas/mapping-dag.v1.schema.json",
  "schemas/model-root.v1.schema.json",
  "schemas/non-authority-boundary.v1.schema.json",
  "schemas/source-reference-catalog.v1.schema.json",
  "schemas/uopc-contract-prefix.v1.schema.json",
  "validate-static.mjs",
  "test/digest.kat.json",
  "test/mutation.test.mjs",
  "test/package-boundary.test.mjs",
  "test/static.test.mjs",
]);
const sourceDomainHash = (domain, value) => {
  check(allNfc(domain) && allNfc(value), "SSA_SOURCE_SEMANTIC", "nfc");
  return sha256(
    Buffer.concat([
      Buffer.from(domain),
      Buffer.from([0]),
      Buffer.from(`${canonicalJson(value)}\n`),
    ]),
  );
};
const prettyDomainHash = (domain, value) =>
  sha256(
    Buffer.concat([
      Buffer.from(domain),
      Buffer.from([0]),
      Buffer.from(
        `${JSON.stringify(JSON.parse(canonicalJson(value)), null, 2)}\n`,
      ),
    ]),
  );
const noLfDomainHash = (domain, value) =>
  sha256(
    Buffer.concat([
      Buffer.from(domain),
      Buffer.from([0]),
      Buffer.from(canonicalJson(value)),
    ]),
  );
const withoutDigest = (value) => {
  const copy = { ...value };
  delete copy.contentDigest;
  return copy;
};
const sourceProfile = (row, value) => {
  try {
    const rule = SEMANTIC_RULES[row.pinId];
    if (
      !rule ||
      !same(row.semanticBindings.map((item) => item.kind), rule.bindingKinds)
    ) return false;
    if (rule.type === "RAW") return row.semanticBindings.length === 0;
    const binding = (kind, boundValue) =>
      row.semanticBindings.some((item) =>
        item.kind === kind && item.value === boundValue
      );
    if (rule.type === "COMPACT" || rule.type === "PRETTY") {
      const derived = rule.type === "COMPACT"
          ? sourceDomainHash(rule.domain, withoutDigest(value))
          : prettyDomainHash(rule.domain, withoutDigest(value)),
        record = value.contentDigest;
      return record && record.value === derived &&
        record.domain === rule.domain &&
        binding("CONTENT_DIGEST_RECORD_VALUE", derived);
    }
    if (rule.type === "UNFRAMED") {
      const derived = sha256(Buffer.from(canonicalJson(withoutDigest(value)))),
        record = value.contentDigest;
      if (row.pinId === "pin:frozen:construction") {
        return record === derived && binding("CONTENT_DIGEST_STRING", derived);
      }
      return record?.algorithm === "sha256-jcs-omit-contentDigest" &&
        record.value === derived &&
        binding("CONTENT_DIGEST_RECORD_VALUE", derived);
    }
    if (rule.type === "ENTRIES") {
      const derived = sourceDomainHash(rule.domain, value.entries);
      return value.rosterDigest?.value === derived &&
        value.rosterDigest.domain === rule.domain &&
        binding("MANIFEST_ROSTER_DIGEST", derived);
    }
    if (rule.type === "FILES") {
      const derived = sourceDomainHash(rule.domain, value.files);
      return value.manifestRosterDigest?.value === derived &&
        value.manifestRosterDigest.domain === rule.domain &&
        binding("MANIFEST_ROSTER_DIGEST", derived);
    }
    if (rule.type === "PRETTY_MANIFEST") {
      const derived = prettyDomainHash(rule.domain, withoutDigest(value)),
        record = typeof value.contentDigest === "string"
          ? value.contentDigest
          : value.contentDigest?.value;
      return record === derived && binding("MANIFEST_CONTENT_DIGEST", derived);
    }
    if (rule.type === "F_MANIFEST") {
      const content = sourceDomainHash(rule.domain, withoutDigest(value)),
        roster = sourceDomainHash(
          "shieldkit-labs/p2/gate-b/cohort-frozen-inputs/v1/manifest-roster",
          value.files,
        );
      return value.contentDigest?.value === content &&
        value.manifestRosterDigest?.value === roster &&
        binding("MANIFEST_CONTENT_DIGEST", content) &&
        binding("MANIFEST_ROSTER_DIGEST", roster);
    }
    if (rule.type === "PACKAGE_ENTRIES") {
      const packages = {
          "pin:origin:live-manifest": "cohort-live-executor-v2",
          "pin:origin:cabm-manifest": "cohort-authority-binding-model-v1",
          "pin:origin:ecoc-manifest": "cohort-external-origin-contract-v1",
        },
        pkg = packages[row.pinId],
        derived = sourceDomainHash(rule.domain, {
          package: pkg,
          entries: value.entries,
        });
      return value.package === pkg && value.rosterDigest === derived &&
        binding("MANIFEST_ROSTER_DIGEST", derived);
    }
    if (rule.type === "AUTHORED") {
      const expected = row.pinId === "pin:origin:uopc-manifest"
          ? UOPC_AUTHORED_LOCATORS
          : SOURCE_MAP_AUTHORED_LOCATORS,
        locators = value.entries.map((item) => item.locator),
        derived = sourceDomainHash(rule.domain, expected);
      return same(locators, expected) && value.rosterDigest === derived &&
        binding("MANIFEST_ROSTER_DIGEST", derived);
    }
    if (rule.type === "K") {
      const entriesRoot = noLfDomainHash("K/ENTRIES", value.entries),
        body = { ...value };
      delete body.manifestRoot;
      delete body.packageRoot;
      const manifestRoot = noLfDomainHash("K/MANIFEST", body),
        packageRoot = noLfDomainHash("K/PACKAGE", {
          manifestRoot,
          entriesRoot,
          executionAllowed: false,
        });
      return value.entriesRoot === entriesRoot &&
        value.manifestRoot === manifestRoot &&
        value.packageRoot === packageRoot &&
        same(row.semanticBindings, [
          { kind: "K_MANIFEST_PACKAGE_ROOT", value: packageRoot },
          { kind: "K_MANIFEST_ROOT", value: manifestRoot },
          { kind: "K_ENTRIES_ROOT", value: entriesRoot },
        ]);
    }
    return false;
  } catch {
    return false;
  }
};
const exactDependency = (root, packageRoot) => {
  const expected =
    strictParse(
      safeRead(packageRoot, "schemas/dependency-binding.v1.schema.json"),
      { canonical: true },
    ).$defs.dependencyBinding.properties;
  check(
    root.dependencyBinding.status === expected.status.const &&
      same(root.dependencyBinding.directParent, expected.directParent.const) &&
      same(
        root.dependencyBinding.sourceLanguageAuthority,
        expected.sourceLanguageAuthority.const,
      ) && same(root.dependencyBinding.sourceRoots, expected.sourceRoots.const),
    "DEPENDENCY_SEMANTIC",
  );
};
const checkPinned = (root, locator, pin, token, detail) => {
  const bytes = safeRead(root, locator);
  check(
    bytes.length === pin.bytes && sha256(bytes) === pin.rawSha256,
    token,
    detail,
  );
  return bytes;
};
const checkDependencyTree = (packageRoot, authored, token) => {
  let rootStat;
  try {
    rootStat = lstatSync(packageRoot);
  } catch {
    fail(token, "package-root");
  }
  check(
    rootStat.isDirectory() && !rootStat.isSymbolicLink() &&
      (rootStat.mode & 0o777) === 0o755,
    token,
    "package-root",
  );
  const rows = walk(packageRoot),
    files = rows.filter((row) => row.stat.isFile()).map((row) => row.locator)
      .sort(),
    dirs = [
      ".",
      ...rows.filter((row) => row.stat.isDirectory()).map((row) => row.locator),
    ].sort();
  check(
    rows.every((row) => row.stat.isFile() || row.stat.isDirectory()) &&
      same(files, [...authored, "MANIFEST.json", "SHA256SUMS"].sort()) &&
      same(dirs, [".", "schemas", "test"]),
    token,
    "closure",
  );
  for (const row of rows) {
    check(
      !row.stat.isSymbolicLink() &&
        (row.stat.isDirectory()
          ? (row.stat.mode & 0o777) === 0o755
          : row.stat.nlink === 1 && (row.stat.mode & 0o777) === 0o644),
      token,
      row.locator,
    );
  }
};
const checkEappDependency = (dependency, repositoryRoot) => {
  const packageRoot = resolve(repositoryRoot, dependency.packagePath),
    rootBytes = checkPinned(
      packageRoot,
      dependency.root.path,
      dependency.root,
      "EAPP_CLOSURE",
      "root",
    ),
    validator = checkPinned(
      packageRoot,
      dependency.validator.path,
      dependency.validator,
      "EAPP_CLOSURE",
      "validator",
    ),
    manifestBytes = checkPinned(
      packageRoot,
      dependency.manifest.path,
      dependency.manifest,
      "EAPP_CLOSURE",
      "manifest",
    ),
    sumsBytes = checkPinned(
      packageRoot,
      dependency.checksums.path,
      dependency.checksums,
      "EAPP_CLOSURE",
      "sums",
    ),
    anchorBytes = checkPinned(
      repositoryRoot,
      dependency.reviewAnchor.path,
      dependency.reviewAnchor,
      "EAPP_CLOSURE",
      "anchor",
    );
  checkDependencyTree(packageRoot, EAPP_AUTHORED, "EAPP_CLOSURE");
  const eapp = strictParse(rootBytes, { canonical: true }),
    manifest = strictParse(manifestBytes, { canonical: true }),
    anchor = strictParse(anchorBytes, { canonical: true }),
    body = withoutDigest(eapp),
    entries = EAPP_AUTHORED.map((locator) => {
      const bytes = safeRead(packageRoot, locator);
      return {
        bytes: bytes.length,
        fileDigest: sourceFileDigest(EAPP_PREFIX, locator, bytes),
        locator,
        rawSha256: sha256(bytes),
      };
    }),
    expectedSums = `${
      [...entries, {
        locator: "MANIFEST.json",
        rawSha256: sha256(manifestBytes),
      }].map((row) => `${row.rawSha256}  ${row.locator}`).join("\n")
    }\n`;
  check(
    validator.length === dependency.validator.bytes &&
      same(
        Object.keys(manifest).sort(),
        [
          "entries",
          "entryCount",
          "format",
          "packageId",
          "rosterDigest",
          "schema",
        ].sort(),
      ) &&
      manifest.schema ===
        "https://shieldkit-labs.local/p2/gate-b/gate-b0-external-authority-prerequisite-policy/v1/manifest.v1.schema.json" &&
      manifest.format === "shieldkit-static-manifest-v1" &&
      manifest.packageId ===
        "gate-b0-external-authority-prerequisite-policy-v1" &&
      manifest.entryCount === 21 && same(manifest.entries, entries) &&
      same(
        manifest.rosterDigest,
        sourceDigest(`${EAPP_PREFIX}/manifest-roster`, entries),
      ) && sumsBytes.toString("utf8") === expectedSums,
    "EAPP_CLOSURE",
    "manifest",
  );
  check(
    eapp.schema === EAPP_PREFIX &&
      eapp.artifactId ===
        "artifact:gate-b:gate-b0-external-authority-prerequisite-policy-v1" &&
      eapp.packageId === "gate-b0-external-authority-prerequisite-policy-v1" &&
      same(eapp.contentDigest, sourceDigest(`${EAPP_PREFIX}/root`, body)) &&
      eapp.contentDigest.value === dependency.root.contentDigest,
    "EAPP_COMPONENT",
    "root",
  );
  const schemaLocators = EAPP_AUTHORED.filter((locator) =>
      locator.startsWith("schemas/")
    ),
    expectedComponents = EAPP_COMPONENTS.map(([component, suffix]) => ({
      component,
      digest: sourceDigest(`${EAPP_PREFIX}/${suffix}`, eapp[component]),
    }));
  check(
    same(eapp.componentDigests, expectedComponents) &&
      eapp.schemaBindings.length === 12 && same(
        eapp.schemaBindings.map((row) => row.locator),
        schemaLocators,
      ) &&
      eapp.schemaBindings.every((row) =>
        sha256(safeRead(packageRoot, row.locator)) === row.rawSha256 &&
        strictParse(safeRead(packageRoot, row.locator), { canonical: true })
            .$id === row.schemaId
      ) && eapp.futureExternalAuthorityContractSchema?.recordCount === 0 &&
      eapp.futureGovernanceAuthorizationSchema?.recordCount === 0 &&
      eapp.providerBindingPolicy?.bindingCount === 0 &&
      eapp.sourceCollisions?.collisionCount === 1 &&
      eapp.sourceCollisions?.entries?.length === 1 &&
      eapp.sourceCollisions.entries[0].selectedDag === null &&
      eapp.creationTransitionPolicy?.authorizedTransitions?.length === 0 &&
      eapp.creationTransitionPolicy?.currentState ===
        "AUTHORITY_POLICY_FROZEN_NO_AUTHORITY",
    "EAPP_COMPONENT",
    "joins",
  );
  check(
    same(Object.keys(anchor), EAPP_ANCHOR_KEYS) &&
      anchor.schema === `${EAPP_PREFIX}/external-review-anchor/v1` &&
      anchor.artifactId ===
        "artifact:gate-b:gate-b0-external-authority-prerequisite-policy-review-anchor-v1" &&
      anchor.packageId ===
        "gate-b0-external-authority-prerequisite-policy-v1" &&
      anchor.status ===
        "sealed-static-external-authority-prerequisite-policy-review-anchor-no-governance-authorization-no-authority-bindings-no-instances-no-admission-no-execution-unqualified" &&
      anchor.entryCount === 21 && anchor.package === dependency.packagePath &&
      anchor.rootRawSha256 === dependency.root.rawSha256 &&
      anchor.validatorRawSha256 === dependency.validator.rawSha256 &&
      anchor.manifestRawSha256 === dependency.manifest.rawSha256 &&
      anchor.sha256SumsRawSha256 === dependency.checksums.rawSha256 &&
      same(anchor.orderedClosure, entries) &&
      same(anchor.rosterDigest, manifest.rosterDigest) &&
      same(anchor.componentDigests, eapp.componentDigests) &&
      same(anchor.schemaBindings, eapp.schemaBindings) &&
      same(anchor.rootContentDigest, eapp.contentDigest) &&
      same(anchor.directDependencyBinding, eapp.dependencyBinding) &&
      same(
        anchor.schemaBindingTableDigest,
        sourceDigest(
          `${EAPP_PREFIX}/schema-binding-table`,
          eapp.schemaBindings,
        ),
      ) &&
      same(
        anchor.sourceCollisionDigest,
        eapp.componentDigests.find((row) =>
          row.component === "sourceCollisions"
        ).digest,
      ) && same(anchor.nonAuthorityBoundary, eapp.nonAuthorityBoundary),
    "EAPP_CLOSURE",
    "anchor",
  );
  return eapp;
};
const checkSsaDependency = (dependency, repositoryRoot) => {
  const packageRoot = resolve(repositoryRoot, dependency.packagePath),
    rootBytes = checkPinned(
      packageRoot,
      dependency.root.path,
      dependency.root,
      "SSA_CLOSURE",
      "root",
    ),
    validator = checkPinned(
      packageRoot,
      dependency.validator.path,
      dependency.validator,
      "SSA_CLOSURE",
      "validator",
    ),
    manifestBytes = checkPinned(
      packageRoot,
      dependency.manifest.path,
      dependency.manifest,
      "SSA_CLOSURE",
      "manifest",
    ),
    sumsBytes = checkPinned(
      packageRoot,
      dependency.checksums.path,
      dependency.checksums,
      "SSA_CLOSURE",
      "sums",
    ),
    anchorBytes = checkPinned(
      repositoryRoot,
      dependency.reviewAnchor.path,
      dependency.reviewAnchor,
      "SSA_CLOSURE",
      "anchor",
    );
  checkDependencyTree(packageRoot, SSA_AUTHORED, "SSA_CLOSURE");
  const ssa = strictParse(rootBytes, { canonical: true }),
    manifest = strictParse(manifestBytes, { canonical: true }),
    anchor = strictParse(anchorBytes, { canonical: true }),
    entries = SSA_AUTHORED.map((locator) => {
      const bytes = safeRead(packageRoot, locator);
      return {
        bytes: bytes.length,
        fileDigest: sourceFileDigest(SSA_PREFIX, locator, bytes),
        locator,
        rawSha256: sha256(bytes),
      };
    }),
    expectedSums = `${
      [...entries, {
        locator: "MANIFEST.json",
        rawSha256: sha256(manifestBytes),
      }].map((row) => `${row.rawSha256}  ${row.locator}`).join("\n")
    }\n`,
    body = withoutDigest(ssa);
  check(
    validator.length === dependency.validator.bytes &&
      same(
        Object.keys(manifest).sort(),
        [
          "entries",
          "entryCount",
          "format",
          "packageId",
          "rosterDigest",
          "schema",
        ].sort(),
      ) &&
      manifest.schema ===
        "https://shieldkit-labs.local/p2/gate-b/gate-b0-static-source-authority/v1/manifest.v1.schema.json" &&
      manifest.format === "shieldkit-static-manifest-v1" &&
      manifest.packageId === "gate-b0-static-source-authority-v1" &&
      manifest.entryCount === 24 && same(manifest.entries, entries) &&
      same(
        manifest.rosterDigest,
        sourceDigest(`${SSA_PREFIX}/manifest-roster`, entries),
      ) && sumsBytes.toString("utf8") === expectedSums,
    "SSA_CLOSURE",
    "manifest",
  );
  check(
    ssa.schema ===
        "https://shieldkit-labs.local/p2/gate-b/gate-b0-static-source-authority/v1/root.v1.schema.json" &&
      ssa.artifactId === "artifact:gate-b:gate-b0-static-source-authority-v1" &&
      ssa.packageId === "gate-b0-static-source-authority-v1" &&
      same(ssa.contentDigest, sourceDigest(`${SSA_PREFIX}/root`, body)) &&
      ssa.contentDigest.value === dependency.root.contentDigest,
    "SSA_CLOSURE",
    "root",
  );
  check(
    ssa.schemaBindings.length === 15 && same(
      ssa.schemaBindings.map((row) => row.locator),
      SSA_AUTHORED.filter((locator) => locator.startsWith("schemas/")),
    ) && ssa.schemaBindings.every((row) => {
      const entry = entries.find((item) => item.locator === row.locator);
      return entry && entry.rawSha256 === row.rawSha256 &&
        strictParse(safeRead(packageRoot, row.locator), { canonical: true })
            .$id === row.schemaId;
    }),
    "SSA_CLOSURE",
    "schema-bindings",
  );
  check(
    Array.isArray(ssa.transitiveSourcePins) &&
      same(ssa.transitiveSourcePins.map((row) => row.pinId), SOURCE_PIN_IDS) &&
      new Set(ssa.transitiveSourcePins.map((row) => row.pinId)).size === 64 &&
      new Set(ssa.transitiveSourcePins.map((row) => row.locator)).size === 64 &&
      Object.keys(SEMANTIC_RULES).length === 64 &&
      same(Object.keys(SEMANTIC_RULES).sort(), [...SOURCE_PIN_IDS].sort()),
    "SSA_CLOSURE",
    "source-pin-roster",
  );
  for (const pin of ssa.transitiveSourcePins) {
    const bytes = checkPinned(
      repositoryRoot,
      pin.locator,
      pin,
      "SSA_SOURCE_RAW",
      pin.pinId,
    );
    let value = null;
    if (pin.locator.endsWith(".json")) {
      try {
        value = parseSourceJson(bytes);
      } catch {
        fail("SSA_SOURCE_SEMANTIC", pin.pinId);
      }
    }
    check(sourceProfile(pin, value), "SSA_SOURCE_SEMANTIC", pin.pinId);
  }
  const expectedComponents = SSA_COMPONENTS.map(([component, suffix]) => ({
    component,
    digest: sourceDigest(`${SSA_PREFIX}/${suffix}`, ssa[component]),
  }));
  check(
    same(ssa.componentDigests, expectedComponents),
    "SSA_CLOSURE",
    "components",
  );
  check(
    same(Object.keys(anchor), SSA_ANCHOR_KEYS) &&
      anchor.schema === `${SSA_PREFIX}/external-review-anchor/v1` &&
      anchor.artifactId ===
        "artifact:gate-b:gate-b0-static-source-authority-review-anchor-v1" &&
      anchor.packageId === "gate-b0-static-source-authority-v1" &&
      anchor.status ===
        "sealed-static-source-contract-authority-review-anchor-no-provider-or-state-instances-no-io-no-execution-no-admission-unqualified" &&
      anchor.entryCount === 24 && anchor.package === dependency.packagePath &&
      anchor.rootRawSha256 === dependency.root.rawSha256 &&
      anchor.validatorRawSha256 === dependency.validator.rawSha256 &&
      anchor.manifestRawSha256 === dependency.manifest.rawSha256 &&
      anchor.sha256SumsRawSha256 === dependency.checksums.rawSha256 &&
      same(anchor.orderedClosure, entries) &&
      same(anchor.rosterDigest, manifest.rosterDigest) &&
      same(anchor.componentDigests, ssa.componentDigests) &&
      same(anchor.schemaBindings, ssa.schemaBindings) &&
      same(anchor.rootContentDigest, ssa.contentDigest) &&
      same(anchor.directDependencyBinding, ssa.dependencyPins[0]) &&
      same(
        anchor.schemaBindingTableDigest,
        sourceDigest(`${SSA_PREFIX}/schema-bindings`, ssa.schemaBindings),
      ) &&
      same(
        anchor.transitiveSourcePinTableDigest,
        sourceDigest(
          `${SSA_PREFIX}/transitive-source-pins`,
          ssa.transitiveSourcePins,
        ),
      ) && same(anchor.nonAuthorityBoundary, ssa.nonAuthorityBoundary),
    "SSA_CLOSURE",
    "anchor",
  );
  return ssa;
};
const checkDirectSources = (root, repositoryRoot) => {
  check(
    same(
      root.dependencyBinding.sourceRoots.map((row) => row.authorityId),
      DIRECT_SOURCE_RULES.map((row) => row[0]),
    ),
    "DIRECT_SOURCE_SEMANTIC",
    "roster",
  );
  const values = new Map();
  for (const [authorityId, domain, frame] of DIRECT_SOURCE_RULES) {
    const pin = root.dependencyBinding.sourceRoots.find((row) =>
        row.authorityId === authorityId
      ),
      bytes = checkPinned(
        repositoryRoot,
        pin.locator,
        pin,
        "DIRECT_SOURCE_RAW",
        authorityId,
      );
    let value;
    try {
      value = strictParse(bytes, { canonical: true });
    } catch {
      fail("DIRECT_SOURCE_SEMANTIC", `${authorityId}:parse`);
    }
    check(
      same(
        value.contentDigest,
        sourceDigest(domain, withoutDigest(value), frame),
      ) && value.contentDigest.value === pin.contentDigest,
      "DIRECT_SOURCE_SEMANTIC",
      authorityId,
    );
    values.set(authorityId, value);
  }
  return values;
};
const edgeKey = (edge) => typeof edge === "string"
  ? edge
  : `${edge.from}→${edge.to}`;
const resolveSourcePointer = (source, pointer, detail) => {
  check(typeof pointer === "string" && pointer.startsWith("#/"), "EAPP_COMPONENT", detail);
  let value = source;
  for (const encoded of pointer.slice(2).split("/")) {
    const key = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    check(value !== null && value !== undefined && Object.hasOwn(value, key), "EAPP_COMPONENT", detail);
    value = value[key];
  }
  return value;
};
const checkEappCollisionAndRequirements = (eapp, ssa, sources) => {
  const eac = sources.get("EAC"), uopc = sources.get("UOPC"),
    spm = sources.get("SPM"), collisions = eapp.sourceCollisions,
    collision = collisions.entries?.[0];
  check(
    collisions.status === "UNRESOLVED_EXTERNAL_PRECEDENCE" &&
      collisions.collisionCount === 1 && collisions.entries.length === 1 &&
      collision?.collisionId === "UOPC_EAC_FUTURE_PROVIDER_DAG_DIVERGENCE" &&
      collision.status === "UNRESOLVED_EXTERNAL_PRECEDENCE" &&
      collision.selectedDag === null && collision.selectedAPath === null &&
      collision.creationAuthorizationAllowed === false &&
      collision.admissionAllowed === false &&
      same(collision.affectedRequirementIds, [
        "Q_INITIAL_PROVIDER", "Q_RETRY_PROVIDER", "Q_ABORT_PROVIDER",
        "A_INITIAL_PROVIDER", "A_RETRY_PROVIDER", "A_ABORT_PROVIDER",
        "B_SUBJECT_ROOT_TYPE", "B_PROVIDER",
      ]),
    "EAPP_COMPONENT",
    "collision-roster",
  );
  check(
    same(collision.uopcSource, {
      authorityId: "UOPC",
      edgeCount: 40,
      jsonPointerRefs: [
        "#/factProviderCatalog/entries/1/modelDispositionByVariant/retry",
        "#/factProviderCatalog/entries/1/futureValidationRules",
        "#/providerCausalDag/edges",
      ],
      retryDispositionLiteral: "DENY_PREREQUISITE",
      retryValidationRuleLiteral:
        "retry-A-is-DENY_PREREQUISITE-while-retry-Q-is-BLOCKED_EXTERNAL",
      rootPinRef: "/dependencyBinding/sourceAuthorities/2",
    }) && same(collision.eacSource, {
      authorityId: "EAC",
      edgeCount: 37,
      futureAActivationAllowed: false,
      jsonPointerRefs: ["#/futureStateGrammar/futureA", "#/futureStateGrammar/edges"],
      rootPinRef: "/dependencyBinding/sourceAuthorities/1",
    }) && same(collision.ssaSource, {
      authorityId: "SSA",
      edgeAuthorityClaimed: false,
      jsonPointerRefs: [
        "#/requirementResolutions/18",
        "#/requirementResolutions/21",
        "#/requirementResolutions/24",
      ],
      rootPinRef: "/dependencyBinding",
      sourceContractResolutionLiteral: "RESOLVED_STATIC_SOURCE_CONTRACT",
    }) && same(collision.reconciliationPrerequisite, {
      authorityOriginClass: "EXTERNAL_ROOT_SOL_GOVERNANCE",
      decisionSchemaId: null,
      decisionVocabularyStatus: "NOT_DEFINED_BY_THIS_PACKAGE",
      governanceDecisionId: null,
      governanceDecisionRawSha256: null,
      governanceDecisionRoot: null,
      packageMayInfer: false,
      packageMaySelectSource: false,
      required: true,
      resolutionAllowed: false,
    }),
    "EAPP_COMPONENT",
    "collision-sources",
  );
  const uopcEdges = uopc.providerCausalDag.edges.map(edgeKey),
    eacEdges = eac.futureStateGrammar.edges.map(edgeKey),
    uopcSet = new Set(uopcEdges), eacSet = new Set(eacEdges),
    shared = uopcEdges.filter((edge) => eacSet.has(edge)),
    uopcOnly = uopcEdges.filter((edge) => !eacSet.has(edge)),
    eacOnly = eacEdges.filter((edge) => !uopcSet.has(edge));
  check(
    uopcEdges.length === 40 && eacEdges.length === 37 &&
      new Set(uopcEdges).size === 40 && new Set(eacEdges).size === 37 &&
      shared.length === 33 && uopcOnly.length === 7 && eacOnly.length === 4 &&
      same(collision.sharedEdges, shared) &&
      same(collision.uopcOnlyEdges, uopcOnly) &&
      same(collision.eacOnlyEdges, eacOnly),
    "EAPP_COMPONENT",
    "collision-edges",
  );
  const rows = eapp.requirementAuthorityMap,
    parentRows = ssa.requirementResolutions,
    globalKinds = [...new Set(
      spm.interfaceSourceMap.entries.flatMap((entry) => entry.missingSourceKinds),
    )].sort();
  check(
    rows.length === 30 && parentRows.length === 30 &&
      eac.externalRequirements.length === 30 &&
      uopc.providerCausalDag.nodes.length === 30 &&
      same(globalKinds, EAPP_REQUIREMENT_STATIC_KINDS),
    "EAPP_COMPONENT",
    "requirement-roster",
  );
  for (const [index, row] of rows.entries()) {
    const parent = parentRows[index], eacRow = eac.externalRequirements[index];
    check(
      row.ordinal === index && row.requirementId === parent.requirementId &&
        row.requirementId === eacRow.requirementId &&
        row.requirementId === uopc.providerCausalDag.nodes[index] &&
        row.classification === parent.classification &&
        row.instanceDisposition === parent.instanceDisposition &&
        row.sourceContractResolution === parent.sourceContractResolution &&
        row.currentInstanceRequired === false && row.instanceCount === 0 &&
        row.creationAuthorizationGranted === false && row.admissionGranted === false &&
        row.authorityContractRoot === null && row.authorityBindingRoot === null &&
        row.providerInstanceRoot === null && parent.authorityGranted === false &&
        parent.admissionGranted === false && parent.instanceCount === 0 &&
        eacRow.authorityGranted === false && eacRow.admissionGranted === false &&
        eacRow.instanceCount === 0 && same(row.sourceContractRefs, parent.sourceContractRefs) &&
        same(row.constraintRefs, parent.constraintRefs),
      "EAPP_COMPONENT",
      `requirement:${row.requirementId}`,
    );
    const sourceMapIndices = EAPP_REQUIREMENT_SPM_REFS[index],
      expectedSpmPointers = sourceMapIndices.map((sourceIndex) =>
        `SPM#/interfaceSourceMap/entries/${sourceIndex}`
      ),
      localSpmPointers = row.constraintRefs.filter((ref) => ref.startsWith("SPM#/"));
    check(same(localSpmPointers, expectedSpmPointers), "EAPP_COMPONENT", `spm-refs:${row.requirementId}`);
    for (const ref of row.constraintRefs) {
      const match = ref.match(/^(EAC|UOPC|SPM)#(\/.*)$/u);
      check(match, "EAPP_COMPONENT", `constraint:${row.requirementId}`);
      resolveSourcePointer(sources.get(match[1]), `#${match[2]}`, ref);
    }
    const staticKinds = row.sourceContractRefs.filter((kind) =>
        EAPP_REQUIREMENT_STATIC_KINDS.includes(kind)
      ),
      supplementalKinds = row.sourceContractRefs.filter((kind) =>
        !EAPP_REQUIREMENT_STATIC_KINDS.includes(kind)
      );
    check(
      supplementalKinds.every((kind) => EAPP_REQUIREMENT_SUPPLEMENTAL_KINDS.includes(kind)),
      "EAPP_COMPONENT",
      `source-kind:${row.requirementId}`,
    );
    const spmRows = sourceMapIndices.map((sourceIndex) => spm.interfaceSourceMap.entries[sourceIndex]);
    if (row.requirementId === "J_ROOT_TYPE") {
      check(
        spmRows.length === 1 && spmRows[0].id === "J_MAP" &&
          spmRows[0].resolution === "EXACT_DERIVED_TYPE_MAPPING_NO_PROVIDER_NO_INSTANCE" &&
          same(spmRows[0].missingSourceKinds, []) && same(spmRows[0].interfaceIds, ["J"]) &&
          same(staticKinds, ["OWNER_BOUND_B_FACT_SOURCE_SCHEMA", "OWNER_BOUND_C_FACT_SOURCE_SCHEMA"]) &&
          same(row.predecessorNodeIds, ["B_PROVIDER", "C_PROVIDER"]) &&
          same(spm.mappingDag.edges.filter((edge) => edge.endsWith("→J_MAP")), ["B_MAP→J_MAP", "C_MAP→J_MAP"]) &&
          same(spm.mappingDag.edges.filter((edge) => edge.startsWith("J_MAP→")), ["J_MAP→D_MAP"]),
        "EAPP_COMPONENT",
        "requirement:J_ROOT_TYPE:normalization",
      );
    } else {
      const directKinds = [...new Set(
          spmRows.flatMap((sourceRow) => sourceRow.missingSourceKinds),
        )].sort(),
        contextual = EAPP_REQUIREMENT_CONTEXTUAL_KINDS[row.requirementId] ?? [],
        expectedKinds = [...new Set([...staticKinds, ...contextual])].sort();
      check(same(directKinds, expectedKinds), "EAPP_COMPONENT", `spm-union:${row.requirementId}`);
    }
    if (row.requirementId === "B_SUBJECT_ROOT_TYPE") {
      check(
        same(parent.predecessorNodeIds, ["A_RETRY_PROVIDER", "P", "R", "K"]) &&
          same(row.predecessorNodeIds, []) && collision.selectedDag === null,
        "EAPP_COMPONENT",
        "requirement:B_SUBJECT_ROOT_TYPE:predecessors",
      );
    } else {
      check(same(row.predecessorNodeIds, parent.predecessorNodeIds), "EAPP_COMPONENT", `predecessors:${row.requirementId}`);
    }
  }
};
const checkDependencyBytes = (root, repositoryRoot) => {
  const eapp = checkEappDependency(
      root.dependencyBinding.directParent,
      repositoryRoot,
    ),
    ssa = checkSsaDependency(
      root.dependencyBinding.sourceLanguageAuthority,
      repositoryRoot,
    );
  check(
    eapp.dependencyBinding?.root?.rawSha256 ===
        root.dependencyBinding.sourceLanguageAuthority.root.rawSha256 &&
      eapp.dependencyBinding?.root?.contentDigest === ssa.contentDigest.value,
    "EAPP_COMPONENT",
    "ssa-join",
  );
  const sources = checkDirectSources(root, repositoryRoot),
    eac = sources.get("EAC");
  for (const [component, suffix] of EAC_COMPONENTS) {
    const expected = eapp.dependencyBinding.eacSemanticComponents[component],
      row = eac.componentDigests.find((item) => item.component === component);
    check(
      row?.digest?.value === expected &&
        same(
          row.digest,
          sourceDigest(
            `shieldkit-labs/p2/gate-b/gate-b0-execution-admission-contract/v1/${suffix}`,
            eac[component],
          ),
        ),
      "EAPP_COMPONENT",
      `eac:${component}`,
    );
  }
  check(
    same(
      eapp.dependencyBinding.sourceAuthorities.map((row) => row.authorityId),
      ["B0R", "EAC", "UOPC", "SPM"],
    ) && eapp.requirementAuthorityMap.length === 30 &&
      ssa.requirementResolutions.length === 30 &&
      eac.externalRequirements.length === 30 &&
      sources.get("UOPC").providerCausalDag.nodes.length === 30,
    "EAPP_COMPONENT",
    "source-joins",
  );
  checkEappCollisionAndRequirements(eapp, ssa, sources);
};
/*
 * This deliberately accepts data, rather than a package root.  The synthetic
 * records are an in-memory conformance probe: keeping the graph builder local
 * prevents it becoming an alternate artifact format or a public construction
 * API.  Callers receive a frozen list of the checks which actually ran.
 */
export const auditSyntheticFutureGraph = (graph) => {
  const rows = (value) => Array.isArray(value) ? value : [],
    record = (value) => value?.record ?? value,
    body = (value) => {
      const copy = { ...value };
      delete copy.contentDigest;
      return copy;
    },
    records = (value) => rows(value).map(record),
    token = (condition, name, detail) => check(condition, name, detail),
    finalDigest = (kind, id, value) => digestRecord(
      `${PREFIX}/future/${kind}/record/${id}`,
      body(value),
    ),
    coreDigest = (kind, id, value) => digestRecord(
      `${PREFIX}/future/${kind}/core/${id}`,
      value,
    ),
    referenceBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`, "utf8"),
    hasReference = (ref, value, idKey, id) => {
      const bytes = referenceBytes(value);
      return ref && ref[idKey] === id && ref.bytes === bytes.length &&
        ref.rawSha256 === sha256(bytes) && same(ref.contentDigest, value.contentDigest);
    },
    closedRevocationPolicyReference = (ref) => same(ref, {
      policyId: "policy:synthetic",
      locator: "synthetic/policy:synthetic.json",
      bytes: 1,
      rawSha256: "0".repeat(64),
      contentDigest: digestRecord(
        `${PREFIX}/future/revocation/policy:synthetic`,
        { id: "policy:synthetic" },
      ),
    }),
    time = (value, classToken, detail) => {
      const parsed = strictUtcTime(value);
      token(parsed !== null, classToken, `time:${detail}`);
      return parsed;
    },
    strictlyBefore = (left, right, classToken, detail) =>
      utcTimeBefore(
        time(left, classToken, `${detail}:left`),
        time(right, classToken, `${detail}:right`),
      ),
    atOrBefore = (left, right, classToken, detail) =>
      utcTimeAtOrBefore(
        time(left, classToken, `${detail}:left`),
        time(right, classToken, `${detail}:right`),
      ),
    identities = records(graph?.identities),
    decisions = records(graph?.decisions),
    authorityContracts = records(graph?.authorityContracts),
    providerContracts = records(graph?.providerContracts),
    collisions = records(graph?.collisions),
    bindings = records(graph?.bindings),
    proofs = records(graph?.proofs),
    authoritySet = record(graph?.authoritySet),
    bindingSet = record(graph?.bindingSet),
    g0 = record(graph?.g0),
    catalog = record(graph?.catalog),
    g1 = record(graph?.g1),
    b0 = record(graph?.b0),
    event = record(graph?.event),
    createdInstanceCores = records(graph?.createdInstanceCores),
    expectedFoundationRefs = graph?.expectedFoundationRefs,
    identityById = new Map(identities.map((item) => [item.principalRefId, item])),
    decisionById = new Map(decisions.map((item) => [item.decisionId, item])),
    authorityById = new Map(authorityContracts.map((item) => [item.contractCore?.authorityContractId, item])),
    providerById = new Map(providerContracts.map((item) => [item.contractCore?.providerContractId, item])),
    bindingById = new Map(bindings.map((item) => [item.bindingCore?.bindingId, item])),
    proofById = new Map(proofs.map((item) => [item.proofId, item])),
    decisionKinds = new Map([
      ["external-authority-contract", ["EXTERNAL_AUTHORITY_CONTRACT_V2", "EXTERNAL_AUTHORITY_CONTRACT_ISSUANCE", "AUTHORITY_CONTRACT_ISSUER"]],
      ["provider-contract", ["PROVIDER_CONTRACT", "PROVIDER_CONTRACT_ISSUANCE", "PROVIDER_CONTRACT_ISSUER"]],
      ["source-collision-decision", ["SOURCE_COLLISION_DECISION_V2", "SOURCE_COLLISION_SELECTION", "ROOT_SOL_GOVERNANCE_ISSUER"]],
      ["binding-creation-authorization-g0", ["BINDING_CREATION_AUTHORIZATION_G0", "BINDING_CREATION_AUTHORIZATION_G0", "ROOT_SOL_GOVERNANCE_ISSUER"]],
      ["provider-binding-catalog", ["PROVIDER_BINDING_CATALOG", "PROVIDER_BINDING_CATALOG_REVIEW", "PROVIDER_CATALOG_REVIEWER"]],
      ["governance-authorization-g1", ["GOVERNANCE_AUTHORIZATION_G1", "GOVERNANCE_AUTHORIZATION_G1", "ROOT_SOL_GOVERNANCE_ISSUER"]],
      ["b0-execution-authorization", ["B0_EXECUTION_AUTHORIZATION", "B0_EXECUTION_AUTHORIZATION", "B0_AUTHORIZATION_ISSUER"]],
      ["instance-creation-event", ["INSTANCE_CREATION_EVENT", "INSTANCE_CREATION", "INSTANCE_CREATOR"]],
    ]),
    expectedPolicySlotIds = [
      "RECOVERY_CHAIN_OWNER_PROVIDER", "REQUEST_OWNER_PROVIDER",
      "ACTIVATION_OWNER_PROVIDER", "PRIVATE_CAPTURE_OWNER_PROVIDER",
      "PRIVATE_DESCRIPTOR_OWNER_PROVIDER", "EXCLUSIVE_C_OWNER_PROVIDER",
      "PRIVATE_DISPATCH_OWNER_PROVIDER", "WORKLOAD_ROOT_ORDER_PROVIDER",
      "RAW_ARTIFACT_MAP_AUTHORITY", "INDEPENDENT_RESULT_VALIDATOR_AUTHORITY",
    ],
    classTokens = [];
  token(graph && typeof graph === "object", "ROOT_SCHEMA", "future-graph");
  token(
    same(Object.keys(graph).sort(), [
      "identities", "decisions", "authorityContracts", "providerContracts",
      "collisions", "authoritySet", "proofs", "bindings", "bindingSet",
      "g0", "catalog", "g1", "b0", "event", "createdInstanceCores",
      "expectedFoundationRefs", "nonceInputHex",
    ].sort()),
    "ROOT_SCHEMA",
    "future-graph-keys",
  );
  token(
    [
      [graph.identities, 26], [graph.decisions, 27],
      [graph.authorityContracts, 10], [graph.providerContracts, 10],
      [graph.collisions, 2], [graph.proofs, 10], [graph.bindings, 10],
      [graph.createdInstanceCores, 1],
    ].every(([value, count]) => Array.isArray(value) && value.length === count),
    "ROOT_SCHEMA",
    "future-populations",
  );
  token(identities.length === 26, "IDENTITY_SCHEMA", "future-identities");
  for (const identity of identities) {
    const ref = identity.revocationPolicyRef;
    token(
      same(identity.contentDigest, digestRecord(
        `${PREFIX}/future/principal-identity-ref/${identity.principalRefId}`,
        body(identity),
      )) && strictlyBefore(
        identity.validFrom,
        identity.expiresAt,
        "IDENTITY_SCHEMA",
        `identity:${identity.principalRefId}`,
      ) && same(ref, expectedFoundationRefs?.revocationPolicyRef),
      "IDENTITY_SCHEMA",
      `identity:${identity.principalRefId}`,
    );
  }
  const identityRoles = identities.map((item) => item.principalRole);
  token(
    identityRoles.filter((role) => role === "AUTHORITY_PRINCIPAL").length === 10 &&
      identityRoles.filter((role) => role === "PROVIDER_PRINCIPAL").length === 10 &&
      ["ROOT_SOL_GOVERNANCE_ISSUER", "AUTHORITY_CONTRACT_ISSUER", "PROVIDER_CONTRACT_ISSUER", "PROVIDER_CATALOG_REVIEWER", "B0_AUTHORIZATION_ISSUER", "INSTANCE_CREATOR"].every((role) => identityRoles.filter((value) => value === role).length === 1),
    "IDENTITY_SCHEMA",
    "future-roles",
  );
  const hasUnique = (items, select) =>
    new Set(items.map(select)).size === items.length;
  token(
    decisions.length === 27 &&
      hasUnique(identities, (item) => item.principalRefId) &&
      hasUnique(decisions, (item) => item.decisionId) &&
      hasUnique(authorityContracts, (item) => item.contractCore?.authorityContractId) &&
      hasUnique(providerContracts, (item) => item.contractCore?.providerContractId) &&
      hasUnique(collisions, (item) => item.decisionCore?.collisionDecisionId) &&
      hasUnique(proofs, (item) => item.proofId) &&
      hasUnique(proofs, (item) => item.bindingId) &&
      hasUnique(bindings, (item) => item.bindingCore?.bindingId),
    "ISSUER_DECISION_SCHEMA",
    "unique-ids",
  );
  const schemaBearingPrimaries = [
    ...identities, ...decisions, ...authorityContracts, ...providerContracts,
    ...collisions, authoritySet, ...bindings, bindingSet, g0, catalog, g1, b0,
    event,
  ];
  token(
    schemaBearingPrimaries.length === 92 &&
      schemaBearingPrimaries.every((item) =>
        item && typeof item.schema === "string" && typeof item.artifactId === "string"
      ) &&
      hasUnique(schemaBearingPrimaries, (item) => item.artifactId),
    "ROOT_SCHEMA",
    "future-schema-bearing-primaries",
  );
  const auditRecord = (kind, idKey, coreKey, digestKey, item, classToken) => {
    const coreValue = item?.[coreKey], id = coreValue?.[idKey];
    token(
      item && same(item[digestKey], coreDigest(kind, id, coreValue)) &&
        same(item.contentDigest, finalDigest(kind, id, item)),
      classToken,
      `digest:${id ?? "missing"}`,
    );
    const issuer = coreValue.issuerPrincipalRef ?? coreValue.creatorPrincipalRef ?? coreValue.reviewerPrincipalRef,
      localDecisionRef = item.issuerDecisionRef ?? item.reviewDecisionRef,
      decision = decisionById.get(localDecisionRef?.decisionId),
      issuerIdentity = identityById.get(issuer?.principalRefId);
    token(decision && hasReference(localDecisionRef, decision, "decisionId", decision.decisionId), classToken, `decision-ref:${id}`);
    token(
      issuerIdentity && hasReference(
        issuer,
        issuerIdentity,
        "principalRefId",
        issuerIdentity.principalRefId,
      ) && decision.issuerPrincipalRef.principalRefId === issuer.principalRefId,
      classToken,
      `issuer:${id}`,
    );
    const [expectedKind, expectedDecision, expectedRole] = decisionKinds.get(kind),
      commitments = decision.subjectCoreCommitments,
      decisionIssuerIdentity = identityById.get(decision.issuerPrincipalRef.principalRefId);
    token(
      Array.isArray(commitments) && commitments.length === 1 &&
        commitments[0].recordId === id && commitments[0].recordKind === expectedKind &&
        same(commitments[0].coreDigest, item[digestKey]) &&
        decision.decisionKind === expectedDecision &&
        decisionIssuerIdentity?.principalRole === expectedRole,
      "ISSUER_DECISION_SCHEMA",
      `commitment:${id}`,
    );
    classTokens.push(`${kind}:${id}`);
  };
  for (const decision of decisions) {
    const issuer = identityById.get(decision.issuerPrincipalRef?.principalRefId);
    token(
      same(decision.contentDigest, digestRecord(
        `${PREFIX}/future/issuer-decision/${decision.decisionId}`,
        body(decision),
      )) && issuer && hasReference(
        decision.issuerPrincipalRef,
        issuer,
        "principalRefId",
        issuer.principalRefId,
      ) && decision.subjectCoreCommitments?.length === 1 &&
        strictlyBefore(
          decision.issuedAt,
          decision.expiresAt,
          "ISSUER_DECISION_SCHEMA",
          `decision:${decision.decisionId}`,
        ) &&
        atOrBefore(
          issuer.validFrom,
          decision.issuedAt,
          "ISSUER_DECISION_SCHEMA",
          `identity:${decision.decisionId}:valid-from`,
      ) && strictlyBefore(
        decision.issuedAt,
        issuer.expiresAt,
        "ISSUER_DECISION_SCHEMA",
        `identity:${decision.decisionId}:expiry`,
        ) && same(
          decision.revocationPolicyRef,
          expectedFoundationRefs?.revocationPolicyRef,
        ),
      "ISSUER_DECISION_SCHEMA",
      `decision:${decision.decisionId}`,
    );
  }
  token(authorityContracts.length === 10 && providerContracts.length === 10, "ROOT_SCHEMA", "future-contract-counts");
  for (const item of authorityContracts) auditRecord("external-authority-contract", "authorityContractId", "contractCore", "contractCoreDigest", item, "AUTHORITY_CONTRACT_SCHEMA");
  for (const item of providerContracts) auditRecord("provider-contract", "providerContractId", "contractCore", "contractCoreDigest", item, "PROVIDER_CONTRACT_SCHEMA");
  const authorityPrincipalIds = identities
      .filter((item) => item.principalRole === "AUTHORITY_PRINCIPAL")
      .map((item) => item.principalRefId),
    providerPrincipalIds = identities
      .filter((item) => item.principalRole === "PROVIDER_PRINCIPAL")
      .map((item) => item.principalRefId),
    hasExactPrincipalMembership = (contracts, refKey, role, principalIds) => {
      const refs = contracts.map((item) => item.contractCore?.[refKey]);
      return hasUnique(refs, (ref) => ref?.principalRefId) &&
        same(
          refs.map((ref) => ref?.principalRefId).sort(),
          [...principalIds].sort(),
        ) && refs.every((ref) => {
          const identity = identityById.get(ref?.principalRefId);
          return identity?.principalRole === role && hasReference(
            ref,
            identity,
            "principalRefId",
            identity.principalRefId,
          );
        });
    };
  token(
    authorityPrincipalIds.length === 10 && hasExactPrincipalMembership(
      authorityContracts,
      "authorityPrincipalRef",
      "AUTHORITY_PRINCIPAL",
      authorityPrincipalIds,
    ),
    "AUTHORITY_CONTRACT_SCHEMA",
    "authority-principal-bijection",
  );
  token(
    providerPrincipalIds.length === 10 && hasExactPrincipalMembership(
      providerContracts,
      "providerPrincipalRef",
      "PROVIDER_PRINCIPAL",
      providerPrincipalIds,
    ),
    "PROVIDER_CONTRACT_SCHEMA",
    "provider-principal-bijection",
  );
  token(collisions.length === 2, "COLLISION_DECISION_SCHEMA", "collision-branches");
  for (const item of collisions) auditRecord("source-collision-decision", "collisionDecisionId", "decisionCore", "decisionCoreDigest", item, "COLLISION_DECISION_SCHEMA");
  token(
    same(collisions.map((item) => item.decisionCore.selectedDag).sort(), ["EAC", "UOPC"]),
    "COLLISION_DECISION_SCHEMA",
    "collision-selected-dags",
  );
  const collisionBranches = new Map([
    ["UOPC", ["8c80d46922c05700f3d9bbd999e5a780201a09d42da1604dbc22f7a15bda585d", 40, "UOPC_INITIAL_RETRY_ABORT_WITH_A_INITIAL_TO_B_SUBJECT", "A_RETRY_DENY_PREREQUISITE_WHILE_Q_RETRY_BLOCKED_EXTERNAL"]],
    ["EAC", ["72edbc5ea6b08b018bed9a6794b518bab2fee5703e104fb36928f463dead4707", 37, "EAC_RETRY_TO_B_SUBJECT_WITH_INITIAL_ABORT_ACTIVATION_UNAVAILABLE", "A_RETRY_BLOCKED_EXTERNAL_REQUIRES_Q_RETRY_AND_ACTIVATION_OWNER"]],
  ]);
  for (const item of collisions) {
    const expected = collisionBranches.get(item.decisionCore.selectedDag);
    token(
      expected && same([
        item.decisionCore.selectedDagComponentDigest,
        item.decisionCore.selectedDagEdgeCount,
        item.decisionCore.selectedAPath,
        item.decisionCore.selectedRetryDisposition,
      ], expected) && item.decisionCore.uopcSourceRef.locator !== item.decisionCore.eacSourceRef.locator,
      "COLLISION_DECISION_SCHEMA",
      `collision-branch:${item.decisionCore.selectedDag}`,
    );
  }
  const sourceReference = (ref) => {
      const id = ref?.artifactId;
      return typeof id === "string" && same(ref, {
        artifactId: id,
        locator: `synthetic/${id}.json`,
        bytes: 1,
        rawSha256: "0".repeat(64),
        contentDigest: digestRecord(`${PREFIX}/future/source/${id}`, { id }),
      });
    },
    expectedFoundationRefKeys = [
      "authorityPolicyRef", "controlPlaneBridgeRef", "uopcSourceRef",
      "eacSourceRef", "eacRef", "b0rRef", "ssaRef", "eappRef",
      "revocationPolicyRef",
    ];
  token(
    expectedFoundationRefs &&
      same(Object.keys(expectedFoundationRefs).sort(), expectedFoundationRefKeys.sort()) &&
      expectedFoundationRefKeys.filter((key) => key !== "revocationPolicyRef").every((key) =>
        sourceReference(expectedFoundationRefs[key])
      ) && closedRevocationPolicyReference(expectedFoundationRefs.revocationPolicyRef) &&
      same(expectedFoundationRefs.eacSourceRef, expectedFoundationRefs.eacRef),
    "ROOT_SCHEMA",
    "future-foundation-refs",
  );
  for (const item of collisions) {
    token(
      same(item.decisionCore.uopcSourceRef, expectedFoundationRefs.uopcSourceRef) &&
        same(item.decisionCore.eacSourceRef, expectedFoundationRefs.eacSourceRef),
      "COLLISION_DECISION_SCHEMA",
      `foundation:${item.decisionCore.collisionDecisionId}`,
    );
  }
  for (const item of authorityContracts) {
    token(
      same(
        item.contractCore.revocationPolicyRef,
        expectedFoundationRefs.revocationPolicyRef,
      ) && same(
        item.contractCore.sourceAuthorityRef,
        expectedFoundationRefs.authorityPolicyRef,
      ),
      "AUTHORITY_CONTRACT_SCHEMA",
      `foundation:${item.contractCore.authorityContractId}`,
    );
  }
  for (const item of providerContracts) {
    token(
      same(
        item.contractCore.revocationPolicyRef,
        expectedFoundationRefs.revocationPolicyRef,
      ),
      "PROVIDER_CONTRACT_SCHEMA",
      `foundation:${item.contractCore.providerContractId}`,
    );
  }
  for (const item of collisions) {
    token(
      same(
        item.decisionCore.revocationPolicyRef,
        expectedFoundationRefs.revocationPolicyRef,
      ),
      "COLLISION_DECISION_SCHEMA",
      `revocation:${item.decisionCore.collisionDecisionId}`,
    );
  }
  auditRecord("binding-creation-authorization-g0", "authorizationId", "authorizationCore", "authorizationCoreDigest", g0, "G0_SCHEMA");
  token(
    same(g0.authorizationCore.authorizedPolicySlotIds, expectedPolicySlotIds) &&
      same(authoritySet.entries.map((entry) => entry.policySlotId), expectedPolicySlotIds) &&
      g0.authorizationCore.principalCoincidencePolicy.status === "ALL_RELEVANT_PRINCIPALS_MUST_BE_DISTINCT" &&
      same(g0.authorizationCore.principalCoincidencePolicy.allowedPairs, []),
    "G0_SCHEMA",
    "g0-slots",
  );
  const uopcCollision = collisions.find((item) => item.decisionCore.selectedDag === "UOPC"),
    bindingCollisionRef = (ref, id) => token(
      hasReference(ref, uopcCollision, "decisionId", uopcCollision?.decisionCore?.collisionDecisionId) &&
        same(ref, g0.authorizationCore.sourceCollisionDecisionRef),
      "PROVIDER_BINDING_SCHEMA",
      `binding-collision:${id}`,
    );
  token(bindings.length === 10 && proofs.length === 10, "PROVIDER_BINDING_SCHEMA", "binding-counts");
  for (const item of bindings) {
    const coreValue = item.bindingCore, id = coreValue?.bindingId;
    token(
      same(item.bindingCoreDigest, coreDigest("provider-binding", id, coreValue)) &&
        same(item.contentDigest, finalDigest("provider-binding", id, item)) &&
        hasReference(item.g0AuthorizationRef, g0, "authorizationId", g0.authorizationCore.authorizationId),
      "PROVIDER_BINDING_SCHEMA",
      `binding:${id}`,
    );
    bindingCollisionRef(coreValue.sourceCollisionDecisionRef, id);
    const principals = [coreValue.authorityPrincipalRef, coreValue.providerPrincipalRef, coreValue.catalogReviewerPrincipalRef]
      .map((ref) => ref.principalRefId);
    const authorityRecord = authorityById.get(coreValue.authorityContractRef.authorityContractId),
      providerRecord = providerById.get(coreValue.providerContractRef.providerContractId),
      proof = proofById.get(coreValue.principalIndependenceProofRef.proofId);
    token(
      new Set(principals).size === principals.length &&
        authorityRecord && hasReference(coreValue.authorityContractRef, authorityRecord, "authorityContractId", authorityRecord.contractCore.authorityContractId) &&
        providerRecord && hasReference(coreValue.providerContractRef, providerRecord, "providerContractId", providerRecord.contractCore.providerContractId) &&
        proof && hasReference(coreValue.principalIndependenceProofRef, proof, "proofId", proof.proofId) &&
        coreValue.policySlotId === authorityRecord.contractCore.policySlotId &&
        coreValue.policySlotId === providerRecord.contractCore.policySlotId &&
        coreValue.authorityPrincipalRef.principalRefId === authorityRecord.contractCore.authorityPrincipalRef.principalRefId &&
        coreValue.providerPrincipalRef.principalRefId === providerRecord.contractCore.providerPrincipalRef.principalRefId &&
        coreValue.catalogReviewerPrincipalRef.principalRefId === catalog.catalogCore.reviewerPrincipalRef.principalRefId,
      "PROVIDER_BINDING_SCHEMA",
      `principal-independence:${id}`,
    );
  }
  for (const proof of proofs) {
    const proofBody = body(proof), projected = proofBody.principalProjection,
      binding = bindingById.get(proofBody.bindingId),
      bindingCore = binding?.bindingCore,
      authorityRecord = authorityById.get(bindingCore?.authorityContractRef?.authorityContractId),
      providerRecord = providerById.get(bindingCore?.providerContractRef?.providerContractId),
      actualRefs = [
        g0.authorizationCore.issuerPrincipalRef,
        authorityRecord?.contractCore?.issuerPrincipalRef,
        bindingCore?.authorityPrincipalRef,
        providerRecord?.contractCore?.issuerPrincipalRef,
        bindingCore?.providerPrincipalRef,
        bindingCore?.catalogReviewerPrincipalRef,
      ],
      actualIdentities = actualRefs.map((ref) => identityById.get(ref?.principalRefId));
    const relations = ["ROOT_GOVERNANCE", "AUTHORITY_CONTRACT_ISSUER", "AUTHORITY_PRINCIPAL", "PROVIDER_CONTRACT_ISSUER", "PROVIDER_PRINCIPAL", "CATALOG_REVIEWER"],
      roles = ["ROOT_SOL_GOVERNANCE_ISSUER", "AUTHORITY_CONTRACT_ISSUER", "AUTHORITY_PRINCIPAL", "PROVIDER_CONTRACT_ISSUER", "PROVIDER_PRINCIPAL", "PROVIDER_CATALOG_REVIEWER"];
    token(
      same(proof.contentDigest, digestRecord(
        `${PREFIX}/future/provider-binding/principal-independence-proof/${proof.proofId}`,
        proofBody,
      )) && Array.isArray(projected) && projected.length === 6 &&
        new Set(projected.map((row) => row.principalRefId)).size === 6 &&
        proofBody.proofType === "SYNTHETIC_PRINCIPAL_INDEPENDENCE_PROJECTION_V1" &&
        proofBody.projectedPrincipalCount === 6 &&
        proofBody.distinctPrincipalRefIdCount === 6 &&
        proofBody.allProjectedPrincipalRefIdsDistinct === true &&
        same(proofBody.principalCoincidencePolicy, { status: "ALL_RELEVANT_PRINCIPALS_MUST_BE_DISTINCT", allowedPairs: [] }) &&
        same(projected.map((row) => row.relation), relations) &&
        same(projected.map((row) => row.requiredPrincipalRole), roles) &&
        projected.every((row) => same(Object.keys(row).sort(), [
          "relation", "requiredPrincipalRole", "principalRefId", "principalIdentityContentDigest",
        ].sort())) &&
        projected.every((row) => {
          const identity = identityById.get(row.principalRefId);
          return identity?.principalRole === row.requiredPrincipalRole &&
            same(row.principalIdentityContentDigest, identity.contentDigest);
        }) && binding && proofBody.policySlotId === bindingCore.policySlotId &&
        hasReference(bindingCore.principalIndependenceProofRef, proof, "proofId", proof.proofId) &&
        authorityRecord && providerRecord &&
        actualRefs.every((ref, index) => hasReference(
          ref,
          actualIdentities[index],
          "principalRefId",
          ref?.principalRefId,
        )) &&
        actualRefs[2].principalRefId === authorityRecord.contractCore.authorityPrincipalRef.principalRefId &&
        actualRefs[4].principalRefId === providerRecord.contractCore.providerPrincipalRef.principalRefId &&
        actualRefs[5].principalRefId === catalog.catalogCore.reviewerPrincipalRef.principalRefId &&
        same(
          projected.map((row) => [row.principalRefId, row.principalIdentityContentDigest]),
          actualIdentities.map((identity) => [identity?.principalRefId, identity?.contentDigest]),
        ),
      "PROVIDER_BINDING_SCHEMA",
      `proof:${proof.proofId}`,
    );
  }
  const auditSet = (kind, set, entries, classToken) => {
    const idKey = kind === "provider-binding" ? "bindingId" : "authorityContractId",
      coreKey = kind === "provider-binding" ? "bindingCore" : "contractCore",
      targetById = new Map(entries.map((item) => [item?.[coreKey]?.[idKey], item]));
    token(set?.entryCount === 10 && Array.isArray(set.entries) && set.entries.length === 10 &&
      same(set.rosterDigest, digestRecord(`${PREFIX}/future/${kind}/set-roster/${set.artifactId}`, set.entries)) &&
      same(set.contentDigest, finalDigest(kind, set.artifactId, set)), classToken, `set:${set?.artifactId}`);
    token(
      targetById.size === 10 && hasUnique(set.entries, (entry) => entry[idKey]) &&
        hasUnique(set.entries, (entry) => canonicalJson(entry)) &&
        same(set.entries.map((entry) => entry.policySlotId), expectedPolicySlotIds) &&
        set.entries.every((entry) => {
          const target = targetById.get(entry[idKey]);
          return target && hasReference(entry, target, idKey, entry[idKey]) &&
            entry.policySlotId === target[coreKey].policySlotId;
        }) &&
        same(
          [...new Set(set.entries.map((entry) => entry[idKey]))].sort(),
          [...targetById.keys()].sort(),
        ),
      classToken,
      `set-membership:${set?.artifactId}`,
    );
  };
  auditSet("external-authority-contract", authoritySet, authorityContracts, "AUTHORITY_CONTRACT_SCHEMA");
  auditSet("provider-binding", bindingSet, bindings, "PROVIDER_BINDING_SCHEMA");
  const authorityMembers = authoritySet.entries.map((entry) => authorityById.get(entry.authorityContractId)),
    bindingMembers = bindingSet.entries.map((entry) => bindingById.get(entry.bindingId)),
    providerMembers = bindingMembers.map((item) =>
      providerById.get(item.bindingCore.providerContractRef.providerContractId)
    );
  token(
    hasUnique(providerMembers, (item) => item.contractCore.providerContractId) &&
      same(
        providerMembers.map((item) => item.contractCore.providerContractId).sort(),
        providerContracts.map((item) => item.contractCore.providerContractId).sort(),
      ),
    "PROVIDER_BINDING_SCHEMA",
    "binding-provider-closure",
  );
  auditRecord("provider-binding-catalog", "catalogId", "catalogCore", "catalogCoreDigest", catalog, "CATALOG_SCHEMA");
  auditRecord("governance-authorization-g1", "authorizationId", "authorizationCore", "authorizationCoreDigest", g1, "G1_SCHEMA");
  auditRecord("b0-execution-authorization", "authorizationId", "authorizationCore", "authorizationCoreDigest", b0, "B0_AUTH_SCHEMA");
  auditRecord("instance-creation-event", "eventId", "eventCore", "eventCoreDigest", event, "INSTANCE_EVENT_SCHEMA");
  const collisionRef = (ref, classToken, detail) => token(
      hasReference(ref, uopcCollision, "decisionId", uopcCollision?.decisionCore?.collisionDecisionId),
      classToken,
      detail,
    );
  collisionRef(g0.authorizationCore.sourceCollisionDecisionRef, "G0_SCHEMA", "g0-collision");
  collisionRef(catalog.catalogCore.sourceCollisionDecisionRef, "CATALOG_SCHEMA", "catalog-collision");
  collisionRef(g1.authorizationCore.sourceCollisionDecisionRef, "G1_SCHEMA", "g1-collision");
  collisionRef(b0.authorizationCore.sourceCollisionDecisionRef, "B0_AUTH_SCHEMA", "b0-collision");
  for (const [item, classToken, detail, hasRevocationPolicy] of [
    [g0.authorizationCore, "G0_SCHEMA", "g0", true],
    [catalog.catalogCore, "CATALOG_SCHEMA", "catalog", false],
    [g1.authorizationCore, "G1_SCHEMA", "g1", true],
  ]) {
    token(
      same(item.authorityPolicyRef, expectedFoundationRefs.authorityPolicyRef) &&
        same(item.controlPlaneBridgeRef, expectedFoundationRefs.controlPlaneBridgeRef) &&
        (!hasRevocationPolicy || same(
          item.revocationPolicyRef,
          expectedFoundationRefs.revocationPolicyRef,
        )),
      classToken,
      `foundation:${detail}`,
    );
  }
  token(
    same(b0.authorizationCore.controlPlaneBridgeRef, expectedFoundationRefs.controlPlaneBridgeRef) &&
      same(b0.authorizationCore.revocationPolicyRef, expectedFoundationRefs.revocationPolicyRef) &&
      ["eacRef", "b0rRef", "ssaRef", "eappRef"].every((key) =>
        same(b0.authorizationCore[key], expectedFoundationRefs[key])
      ),
    "B0_AUTH_SCHEMA",
    "foundation:b0",
  );
  for (const [coreValue, classToken, detail] of [
    [catalog.catalogCore, "CATALOG_SCHEMA", "catalog"],
    [event.eventCore, "INSTANCE_EVENT_SCHEMA", "event"],
  ]) {
    token(
      !Object.hasOwn(coreValue, "revocationPolicyRef") || same(
        coreValue.revocationPolicyRef,
        expectedFoundationRefs.revocationPolicyRef,
      ),
      classToken,
      `revocation:${detail}`,
    );
  }
  const g0Ref = (ref, classToken, detail) => token(
    hasReference(ref, g0, "authorizationId", g0?.authorizationCore?.authorizationId),
    classToken,
    detail,
  );
  for (const item of bindings) g0Ref(item.g0AuthorizationRef, "PROVIDER_BINDING_SCHEMA", `binding-g0:${item.bindingCore.bindingId}`);
  g0Ref(catalog.catalogCore.g0AuthorizationRef, "CATALOG_SCHEMA", "catalog-g0");
  const authoritySetRef = (ref, classToken, detail) => token(
      hasReference(ref, authoritySet, "artifactId", authoritySet?.artifactId) &&
        ref.schemaId === authoritySet.schema && ref.entryCount === 10 &&
        same(ref.rosterDigest, authoritySet.rosterDigest),
      classToken,
      detail,
    ),
    bindingSetRef = (ref, classToken, detail) => token(
      hasReference(ref, bindingSet, "artifactId", bindingSet?.artifactId) &&
        ref.schemaId === bindingSet.schema && ref.entryCount === 10 &&
        same(ref.rosterDigest, bindingSet.rosterDigest),
      classToken,
      detail,
    ),
    catalogRef = (ref, classToken, detail) => token(
      hasReference(ref, catalog, "artifactId", catalog?.artifactId),
      classToken,
      detail,
    );
  authoritySetRef(g0.authorizationCore.externalAuthorityContractSetRef, "G0_SCHEMA", "g0-authority-set");
  authoritySetRef(catalog.catalogCore.externalAuthorityContractSetRef, "CATALOG_SCHEMA", "catalog-authority-set");
  authoritySetRef(g1.authorizationCore.externalAuthorityContractSetRef, "G1_SCHEMA", "g1-authority-set");
  authoritySetRef(b0.authorizationCore.externalAuthorityContractSetRef, "B0_AUTH_SCHEMA", "b0-authority-set");
  bindingSetRef(catalog.catalogCore.providerBindingSetRef, "CATALOG_SCHEMA", "catalog-binding-set");
  token(
    same(catalog.catalogCore.bindingRefs, bindingSet.entries) &&
      catalog.catalogCore.bindingCount === 10,
    "CATALOG_SCHEMA",
    "catalog-binding-roster",
  );
  catalogRef(g1.authorizationCore.providerBindingCatalogRef, "G1_SCHEMA", "g1-catalog");
  catalogRef(b0.authorizationCore.providerBindingCatalogRef, "B0_AUTH_SCHEMA", "b0-catalog");
  token(
    hasReference(b0.g1AuthorizationRef, g1, "authorizationId", g1.authorizationCore.authorizationId),
    "B0_AUTH_SCHEMA",
    "b0-g1",
  );
  token(
    hasReference(event.b0ExecutionAuthorizationRef, b0, "authorizationId", b0.authorizationCore.authorizationId),
    "INSTANCE_EVENT_SCHEMA",
    "event-b0",
  );
  const nonce = b0.authorizationCore.authorizationNonceDigest;
  token(
    nonce === deriveAuthorizationNonceDigest(b0.authorizationCore.authorizationId, graph.nonceInputHex) &&
      event.eventCore.authorizationNonceDigest === nonce &&
      event.eventCore.createdInstanceCoreCommitment.instanceClass === b0.authorizationCore.authorizedInstanceClass,
    "B0_AUTH_SCHEMA",
    "nonce-join",
  );
  const createdCoreById = new Map(createdInstanceCores.map((item) => [item?.instanceId, item])),
    commitment = event.eventCore.createdInstanceCoreCommitment,
    retry = b0.authorizationCore.authorizedInstanceClass === "Q_RETRY";
  token(
    createdCoreById.size === 1 &&
      createdInstanceCores.every((item) =>
        item && same(Object.keys(item).sort(), ["instanceClass", "instanceId"]) &&
          ["Q_INITIAL", "Q_RETRY", "Q_ABORT"].includes(item.instanceClass) &&
          typeof item.instanceId === "string"
      ) &&
      commitment && createdCoreById.get(commitment.instanceId)?.instanceClass === commitment.instanceClass &&
      same(
        commitment.coreDigest,
        digestRecord(
          `${PREFIX}/future/instance-creation-event/instance-core/${commitment.instanceId}`,
          createdCoreById.get(commitment.instanceId),
        ),
      ),
    "INSTANCE_EVENT_SCHEMA",
    "created-instance-core",
  );
  token(
    retry
      ? sourceReference(b0.authorizationCore.retryPredecessorRef) &&
        sourceReference(event.eventCore.predecessorInstanceRef) &&
        same(b0.authorizationCore.retryPredecessorRef, event.eventCore.predecessorInstanceRef)
      : b0.authorizationCore.retryPredecessorRef === null &&
        event.eventCore.predecessorInstanceRef === null,
    "B0_AUTH_SCHEMA",
    "retry-predecessor",
  );
  const stage = (id, classToken, decision, coreAt, expiresAt, identities) => ({
      id,
      classToken,
      decision,
      coreAt,
      expiresAt,
      identities,
    }),
    stages = [
      ...authorityContracts.map((item) => stage(
        `authority:${item.contractCore.authorityContractId}`,
        "AUTHORITY_CONTRACT_SCHEMA",
        decisionById.get(item.issuerDecisionRef.decisionId),
        null,
        [item.contractCore.expiresAt],
        [
          item.contractCore.issuerPrincipalRef.principalRefId,
          item.contractCore.authorityPrincipalRef.principalRefId,
        ],
      )),
      ...providerContracts.map((item) => stage(
        `provider:${item.contractCore.providerContractId}`,
        "PROVIDER_CONTRACT_SCHEMA",
        decisionById.get(item.issuerDecisionRef.decisionId),
        null,
        [item.contractCore.expiresAt],
        [
          item.contractCore.issuerPrincipalRef.principalRefId,
          item.contractCore.providerPrincipalRef.principalRefId,
        ],
      )),
      ...collisions.map((item) => stage(
        `collision:${item.decisionCore.collisionDecisionId}`,
        "COLLISION_DECISION_SCHEMA",
        decisionById.get(item.issuerDecisionRef.decisionId),
        null,
        [item.decisionCore.expiresAt],
        [item.decisionCore.issuerPrincipalRef.principalRefId],
      )),
      stage(
        "g0",
        "G0_SCHEMA",
        decisionById.get(g0.issuerDecisionRef.decisionId),
        g0.authorizationCore.issuedAt,
        [g0.authorizationCore.expiresAt],
        [g0.authorizationCore.issuerPrincipalRef.principalRefId],
      ),
      stage(
        "catalog",
        "CATALOG_SCHEMA",
        decisionById.get(catalog.reviewDecisionRef.decisionId),
        null,
        [],
        [catalog.catalogCore.reviewerPrincipalRef.principalRefId],
      ),
      stage(
        "g1",
        "G1_SCHEMA",
        decisionById.get(g1.issuerDecisionRef.decisionId),
        g1.authorizationCore.issuedAt,
        [g1.authorizationCore.expiresAt],
        [g1.authorizationCore.issuerPrincipalRef.principalRefId],
      ),
      stage(
        "b0",
        "B0_AUTH_SCHEMA",
        decisionById.get(b0.issuerDecisionRef.decisionId),
        b0.authorizationCore.issuedAt,
        [b0.authorizationCore.expiresAt],
        [b0.authorizationCore.issuerPrincipalRef.principalRefId],
      ),
      stage(
        "event",
        "INSTANCE_EVENT_SCHEMA",
        decisionById.get(event.issuerDecisionRef.decisionId),
        event.eventCore.createdAt,
        [],
        [event.eventCore.creatorPrincipalRef.principalRefId],
      ),
    ],
    stageById = new Map(stages.map((item) => [item.id, item])),
    requireStage = (id, classToken, detail) => {
      const value = stageById.get(id);
      token(value, classToken, `time-stage:${detail}`);
      return value;
    },
    validateStage = (item) => {
      const decisionAt = time(
          item.decision?.issuedAt,
          item.classToken,
          `${item.id}:decision`,
        ),
        decisionExpires = time(
          item.decision?.expiresAt,
          item.classToken,
          `${item.id}:decision-expiry`,
        ),
        coreAt = item.coreAt === null
          ? decisionAt
          : time(item.coreAt, item.classToken, `${item.id}:core`),
        signedTimes = item.coreAt === null ? [decisionAt] : [decisionAt, coreAt];
      const coreTimeJoined = item.coreAt === null ||
        (item.id === "event"
          ? utcTimeAtOrBefore(decisionAt, coreAt)
          : utcTimeEqual(decisionAt, coreAt));
      token(
        utcTimeBefore(decisionAt, decisionExpires) &&
          coreTimeJoined &&
          utcTimeBefore(coreAt, decisionExpires) &&
          item.expiresAt.every((value) => utcTimeBefore(coreAt, time(
            value,
            item.classToken,
            `${item.id}:core-expiry`,
          ))),
        item.classToken,
        `time-stage:${item.id}`,
      );
      for (const identityId of item.identities) {
        const identity = identityById.get(identityId),
          validFrom = time(
            identity?.validFrom,
            item.classToken,
            `${item.id}:identity:${identityId}:valid-from`,
          ),
          expiresAt = time(
            identity?.expiresAt,
            item.classToken,
            `${item.id}:identity:${identityId}:expiry`,
          );
        token(
          signedTimes.every((signedAt) =>
            utcTimeAtOrBefore(validFrom, signedAt) &&
              utcTimeBefore(signedAt, expiresAt)
          ),
          item.classToken,
          `identity:${item.id}:${identityId}`,
        );
      }
      return { issuedAt: decisionAt, expiryTimes: [decisionExpires, ...item.expiresAt.map(
        (value) => time(value, item.classToken, `${item.id}:prerequisite-expiry`),
      )] };
    },
    stageTimes = new Map(stages.map((item) => [item.id, validateStage(item)])),
    authorityStageIds = authorityContracts.map((item) =>
      `authority:${item.contractCore.authorityContractId}`
    ),
    providerStageIds = providerContracts.map((item) =>
      `provider:${item.contractCore.providerContractId}`
    ),
    temporalEdges = [
      ["g0", [...authorityStageIds, "collision:collision:uopc"]],
      ["catalog", ["g0", ...authorityStageIds, ...providerStageIds, "collision:collision:uopc"]],
      ["g1", ["catalog", "g0", ...authorityStageIds, ...providerStageIds, "collision:collision:uopc"]],
      ["b0", ["g1", "catalog", "g0", ...authorityStageIds, ...providerStageIds, "collision:collision:uopc"]],
      ["event", ["b0"]],
    ];
  for (const [consumerId, prerequisiteIds] of temporalEdges) {
      const consumer = requireStage(consumerId, "ROOT_SCHEMA", consumerId),
      consumerTimes = consumer.coreAt === null
        ? [time(consumer.decision.issuedAt, consumer.classToken, `${consumerId}:consumer`)]
        : [
          time(consumer.decision.issuedAt, consumer.classToken, `${consumerId}:decision-consumer`),
          time(consumer.coreAt, consumer.classToken, `${consumerId}:core-consumer`),
        ];
    for (const prerequisiteId of prerequisiteIds) {
      const prerequisite = requireStage(
          prerequisiteId,
          consumer.classToken,
          `${consumerId}:${prerequisiteId}`,
        ),
        prerequisiteTimes = stageTimes.get(prerequisite.id);
      token(
        consumerTimes.every((time) =>
          utcTimeBefore(prerequisiteTimes.issuedAt, time) &&
            prerequisiteTimes.expiryTimes.every((expiresAt) => utcTimeBefore(time, expiresAt))
        ),
        consumer.classToken,
        `time-edge:${consumerId}:${prerequisiteId}`,
      );
    }
  }
  /*
   * Independently prove that the synthetic support closure is acyclic.  Edges
   * point from a prerequisite to the core/final which consumes it; the joins
   * above authenticate every referenced endpoint before this topology check.
   */
  const closureNodes = new Set(), closureEdges = [],
    addNode = (name) => (closureNodes.add(name), name),
    addEdge = (from, to) => {
      closureNodes.add(from);
      closureNodes.add(to);
      closureEdges.push([from, to]);
    },
    identityNode = (id) => `identity:${id}`,
    coreNode = (kind, id) => `core:${kind}:${id}`,
    decisionNode = (id) => `decision:${id}`,
    finalNode = (kind, id) => `final:${kind}:${id}`,
    addIssuedRecord = (kind, id, issuerId, decisionId) => {
      const coreName = addNode(coreNode(kind, id)),
        decisionName = addNode(decisionNode(decisionId)),
        finalName = addNode(finalNode(kind, id));
      addEdge(identityNode(issuerId), coreName);
      addEdge(identityNode(issuerId), decisionName);
      addEdge(coreName, decisionName);
      addEdge(coreName, finalName);
      addEdge(decisionName, finalName);
      return { coreName, finalName };
    },
    instanceCoreNode = (id) => `instance-core:${id}`;
  for (const identity of identities) addNode(identityNode(identity.principalRefId));
  for (const item of authorityMembers) {
    const id = item.contractCore.authorityContractId,
      nodes = addIssuedRecord(
        "external-authority-contract",
        id,
        item.contractCore.issuerPrincipalRef.principalRefId,
        item.issuerDecisionRef.decisionId,
      );
    addEdge(identityNode(item.contractCore.authorityPrincipalRef.principalRefId), nodes.coreName);
  }
  for (const item of providerMembers) {
    const id = item.contractCore.providerContractId,
      nodes = addIssuedRecord(
        "provider-contract",
        id,
        item.contractCore.issuerPrincipalRef.principalRefId,
        item.issuerDecisionRef.decisionId,
      );
    addEdge(identityNode(item.contractCore.providerPrincipalRef.principalRefId), nodes.coreName);
  }
  for (const item of collisions) {
    addIssuedRecord(
      "source-collision-decision",
      item.decisionCore.collisionDecisionId,
      item.decisionCore.issuerPrincipalRef.principalRefId,
      item.issuerDecisionRef.decisionId,
    );
  }
  const authoritySetNode = addNode(`set:external-authority-contract:${authoritySet.artifactId}`);
  for (const item of authorityMembers) addEdge(finalNode("external-authority-contract", item.contractCore.authorityContractId), authoritySetNode);
  const g0Nodes = addIssuedRecord(
    "binding-creation-authorization-g0",
    g0.authorizationCore.authorizationId,
    g0.authorizationCore.issuerPrincipalRef.principalRefId,
    g0.issuerDecisionRef.decisionId,
  );
  addEdge(authoritySetNode, g0Nodes.coreName);
  addEdge(finalNode("source-collision-decision", uopcCollision.decisionCore.collisionDecisionId), g0Nodes.coreName);
  for (const item of bindingMembers) {
    const proof = proofById.get(item.bindingCore.principalIndependenceProofRef.proofId),
      proofNode = addNode(`proof:${proof.proofId}`);
    for (const row of proof.principalProjection) addEdge(identityNode(row.principalRefId), proofNode);
  }
  for (const item of bindingMembers) {
    const id = item.bindingCore.bindingId,
      coreName = addNode(coreNode("provider-binding", id)),
      finalName = addNode(finalNode("provider-binding", id));
    addEdge(finalNode("external-authority-contract", item.bindingCore.authorityContractRef.authorityContractId), coreName);
    addEdge(finalNode("provider-contract", item.bindingCore.providerContractRef.providerContractId), coreName);
    addEdge(finalNode("source-collision-decision", uopcCollision.decisionCore.collisionDecisionId), coreName);
    addEdge(`proof:${item.bindingCore.principalIndependenceProofRef.proofId}`, coreName);
    addEdge(g0Nodes.finalName, coreName);
    addEdge(coreName, finalName);
  }
  const bindingSetNode = addNode(`set:provider-binding:${bindingSet.artifactId}`);
  for (const item of bindingMembers) addEdge(finalNode("provider-binding", item.bindingCore.bindingId), bindingSetNode);
  const catalogNodes = addIssuedRecord(
    "provider-binding-catalog",
    catalog.catalogCore.catalogId,
    catalog.catalogCore.reviewerPrincipalRef.principalRefId,
    catalog.reviewDecisionRef.decisionId,
  );
  for (const dependency of [authoritySetNode, bindingSetNode, g0Nodes.finalName, finalNode("source-collision-decision", uopcCollision.decisionCore.collisionDecisionId)]) addEdge(dependency, catalogNodes.coreName);
  const g1Nodes = addIssuedRecord(
    "governance-authorization-g1",
    g1.authorizationCore.authorizationId,
    g1.authorizationCore.issuerPrincipalRef.principalRefId,
    g1.issuerDecisionRef.decisionId,
  );
  for (const dependency of [authoritySetNode, catalogNodes.finalName, finalNode("source-collision-decision", uopcCollision.decisionCore.collisionDecisionId)]) addEdge(dependency, g1Nodes.coreName);
  const b0Nodes = addIssuedRecord(
    "b0-execution-authorization",
    b0.authorizationCore.authorizationId,
    b0.authorizationCore.issuerPrincipalRef.principalRefId,
    b0.issuerDecisionRef.decisionId,
  );
  for (const dependency of [authoritySetNode, catalogNodes.finalName, g1Nodes.finalName, finalNode("source-collision-decision", uopcCollision.decisionCore.collisionDecisionId)]) addEdge(dependency, b0Nodes.coreName);
  const eventNodes = addIssuedRecord(
    "instance-creation-event",
    event.eventCore.eventId,
    event.eventCore.creatorPrincipalRef.principalRefId,
    event.issuerDecisionRef.decisionId,
  );
  addEdge(b0Nodes.finalName, eventNodes.coreName);
  const createdInstanceCoreNode = addNode(instanceCoreNode(commitment.instanceId));
  addEdge(createdInstanceCoreNode, eventNodes.coreName);
  const indegree = new Map([...closureNodes].map((name) => [name, 0])), adjacency = new Map();
  for (const [from, to] of closureEdges) {
    if (!adjacency.has(from)) adjacency.set(from, []);
    adjacency.get(from).push(to);
    indegree.set(to, indegree.get(to) + 1);
  }
  const ready = [...closureNodes].filter((name) => indegree.get(name) === 0).sort();
  let visited = 0;
  while (ready.length) {
    const current = ready.shift();
    visited++;
    for (const next of adjacency.get(current) ?? []) {
      indegree.set(next, indegree.get(next) - 1);
      if (indegree.get(next) === 0) {
        ready.push(next);
        ready.sort();
      }
    }
  }
  const derivedClosureNodeCount = closureNodes.size;
  token(
    visited === derivedClosureNodeCount,
    "ROOT_SCHEMA",
    "future-cycle",
  );
  return Object.freeze(classTokens);
};
const assertSyntheticFutureCoherence = (schemaState) => {
  const schema = (file, definition) =>
      `${SCHEMA_PREFIX}${file}#/$defs/${definition}`,
    copy = (value) => JSON.parse(JSON.stringify(value)),
    hash = "0".repeat(64),
    from = "2030-01-02T03:04:00Z",
    issued = "2030-01-02T03:04:01Z",
    g0Issued = "2030-01-02T03:04:02Z",
    catalogIssued = "2030-01-02T03:04:03Z",
    g1Issued = "2030-01-02T03:04:04Z",
    b0Issued = "2030-01-02T03:04:05Z",
    instanceIssued = "2030-01-02T03:04:06Z",
    created = "2030-01-02T03:04:07Z",
    expires = "2030-01-02T03:04:30Z",
    slots = [
      "RECOVERY_CHAIN_OWNER_PROVIDER",
      "REQUEST_OWNER_PROVIDER",
      "ACTIVATION_OWNER_PROVIDER",
      "PRIVATE_CAPTURE_OWNER_PROVIDER",
      "PRIVATE_DESCRIPTOR_OWNER_PROVIDER",
      "EXCLUSIVE_C_OWNER_PROVIDER",
      "PRIVATE_DISPATCH_OWNER_PROVIDER",
      "WORKLOAD_ROOT_ORDER_PROVIDER",
      "RAW_ARTIFACT_MAP_AUTHORITY",
      "INDEPENDENT_RESULT_VALIDATOR_AUTHORITY",
    ],
    digest = (domain, value) => digestRecord(domain, value),
    ref = (key, id, contentDigest) => ({
      [key]: id,
      locator: `synthetic/${id}.json`,
      bytes: 1,
      rawSha256: hash,
      contentDigest,
    }),
    source = (id) => ref("artifactId", id, digest(`${PREFIX}/future/source/${id}`, { id })),
    revoke = ref("policyId", "policy:synthetic", digest(`${PREFIX}/future/revocation/policy:synthetic`, { id: "policy:synthetic" })),
    eacSource = source("artifact:eac"),
    b0rSource = source("artifact:b0r"),
    ssaSource = source("artifact:ssa"),
    eappSource = source("artifact:eapp"),
    bridgeSource = source("artifact:bridge"),
    policySource = source("artifact:policy"),
    expectedFoundationRefs = {
      authorityPolicyRef: policySource,
      controlPlaneBridgeRef: bridgeSource,
      uopcSourceRef: source("artifact:uopc"),
      eacSourceRef: eacSource,
      eacRef: eacSource,
      b0rRef: b0rSource,
      ssaRef: ssaSource,
      eappRef: eappSource,
      revocationPolicyRef: revoke,
    },
    coreDomain = (kind, id) => `${PREFIX}/future/${kind}/core/${id}`,
    finalDomain = (kind, id) => `${PREFIX}/future/${kind}/record/${id}`,
    final = (kind, id, body) => ({
      ...body,
      contentDigest: digest(
        kind === "principal-identity-ref" || kind === "issuer-decision"
          ? `${PREFIX}/future/${kind}/${id}`
          : finalDomain(kind, id),
        body,
      ),
    }),
    core = (kind, id, value) => digest(coreDomain(kind, id), value),
    authoritySetId = "artifact:authority-set",
    bindingSetId = "artifact:binding-set";
  const providerCore = {
      providerContractId: "provider:synthetic",
      policySlotId: slots[0],
      issuerPrincipalRef: null,
      providerPrincipalRef: null,
      providerScope: "synthetic-scope",
      providerInterfaceSchemaId: "synthetic-provider-schema",
      providerMaterial: {
        materialClass: "EXTERNAL_CONTENT_ADDRESSED_PROVIDER_CONTRACT_BYTES",
        contractArtifactLocator: "synthetic/provider.bin",
        contractArtifactBytes: 1,
        contractArtifactRawSha256: hash,
        contractArtifactSchemaId: "synthetic-material-schema",
        importEvaluationAllowed: false,
      },
      instanceCreationAllowed: false,
      executionAllowed: false,
      admissionAllowed: false,
      revocationPolicyRef: revoke,
      expiresAt: expires,
    },
    authorityCore = {
      authorityContractId: "authority:synthetic",
      policySlotId: slots[0],
      issuerPrincipalRef: null,
      authorityPrincipalRef: null,
      authorityScope: "synthetic-scope",
      sourceAuthorityRef: policySource,
      authorityPayload: {
        payloadType: "OWNER_AUTHORITY_PAYLOAD",
        ownerScopeId: slots[0],
        ownerContractSchemaId: "synthetic-owner-schema",
        ownerBindingDomain: "synthetic-owner-domain",
      },
      providerBindingCreationCapability: "REQUIRES_SEPARATE_G0_AUTHORIZATION",
      instanceCreationAllowed: false,
      executionAllowed: false,
      admissionAllowed: false,
      revocationPolicyRef: revoke,
      expiresAt: expires,
    },
    collisionCore = {
      collisionDecisionId: "collision:synthetic",
      collisionId: "UOPC_EAC_FUTURE_PROVIDER_DAG_DIVERGENCE",
      issuerPrincipalRef: null,
      uopcSourceRef: source("artifact:uopc"),
      eacSourceRef: eacSource,
      eappCollisionComponentDigest: "c69be9027fa2cfef09f82d706a099a756dc4a563d2febb2fc1eb1ab8eacaffc9",
      selectedDag: "UOPC",
      selectedDagComponentDigest: "8c80d46922c05700f3d9bbd999e5a780201a09d42da1604dbc22f7a15bda585d",
      selectedDagEdgeCount: 40,
      selectedAPath: "UOPC_INITIAL_RETRY_ABORT_WITH_A_INITIAL_TO_B_SUBJECT",
      selectedRetryDisposition: "A_RETRY_DENY_PREREQUISITE_WHILE_Q_RETRY_BLOCKED_EXTERNAL",
      affectedRequirementIds: ["Q_INITIAL_PROVIDER", "Q_RETRY_PROVIDER", "Q_ABORT_PROVIDER", "A_INITIAL_PROVIDER", "A_RETRY_PROVIDER", "A_ABORT_PROVIDER", "B_SUBJECT_ROOT_TYPE", "B_PROVIDER"],
      decisionScope: "synthetic-scope",
      instanceCreationAllowed: false,
      executionAllowed: false,
      admissionAllowed: false,
      revocationPolicyRef: revoke,
      expiresAt: expires,
    },
    g0Core = {
      authorizationId: "authorization:g0",
      issuerPrincipalRef: null,
      authorityPolicyRef: policySource,
      controlPlaneBridgeRef: bridgeSource,
      externalAuthorityContractSetRef: null,
      sourceCollisionDecisionRef: null,
      authorizedOperation: "CREATE_AND_REVIEW_PROVIDER_BINDING_CATALOG_ONLY",
      authorizedPolicySlotIds: slots,
      principalCoincidencePolicy: { status: "ALL_RELEVANT_PRINCIPALS_MUST_BE_DISTINCT", allowedPairs: [] },
      issuedAt: issued,
      expiresAt: expires,
      revocationPolicyRef: revoke,
      providerBindingCreationAllowed: true,
      instanceCreationAllowed: false,
      executionAllowed: false,
      admissionAllowed: false,
    },
    catalogCore = { catalogId: "catalog:synthetic", status: "EXTERNALLY_REVIEWED_BINDINGS_NO_INSTANCES", authorityPolicyRef: policySource, controlPlaneBridgeRef: bridgeSource, externalAuthorityContractSetRef: null, g0AuthorizationRef: null, sourceCollisionDecisionRef: null, providerBindingSetRef: null, bindingCount: 10, bindingRefs: [], reviewerPrincipalRef: null, allAuthorityRootsExternallyPinned: true, selfAttestationAllowed: false, principalCoincidenceAllowed: false, instanceCreationAllowed: false, executionAllowed: false, admissionAllowed: false },
    g1Core = { authorizationId: "authorization:g1", issuerPrincipalRef: null, authorityPolicyRef: policySource, controlPlaneBridgeRef: bridgeSource, externalAuthorityContractSetRef: null, providerBindingCatalogRef: null, sourceCollisionDecisionRef: null, authorizedOperation: "CREATE_B0_EXECUTION_AUTHORIZATION_RECORD_ONLY", authorizedTransition: { from: "PROVIDER_BINDINGS_REVIEWED_NO_INSTANCES", to: "B0_EXECUTION_AUTHORIZATION_CREATION_AUTHORIZED_NO_INSTANCES" }, authorizedPolicySlotIds: slots, issuedAt: g1Issued, expiresAt: expires, revocationPolicyRef: revoke, b0ExecutionAuthorizationCreationAllowed: true, instanceCreationAllowed: false, executionAllowed: false, admissionAllowed: false },
    nonceInputHex =
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    nonce = deriveAuthorizationNonceDigest("authorization:b0", nonceInputHex),
    b0Core = { authorizationId: "authorization:b0", issuerPrincipalRef: null, eacRef: eacSource, b0rRef: b0rSource, ssaRef: ssaSource, eappRef: eappSource, controlPlaneBridgeRef: bridgeSource, externalAuthorityContractSetRef: null, providerBindingCatalogRef: null, sourceCollisionDecisionRef: null, authorizedOperation: "AUTHORIZE_ONE_FUTURE_B0_INSTANCE_CREATION_EVENT_ONLY", authorizationScope: { campaignClass: "B0_EVIDENCE_CAMPAIGN", candidateSelectionAllowed: false, parameterAssignmentAllowed: false, providerSelectionAllowed: false }, authorizationNonceDigest: nonce, authorizedInstanceClass: "Q_INITIAL", retryPredecessorRef: null, maxInstanceCreationEvents: 1, consumedInstanceCreationEventCount: 0, instanceCreationEventRequired: true, executionAuthorizationPresent: true, executionStartAllowed: false, admissionAllowed: false, evidenceAdmissionAllowed: false, qualificationAllowed: false, issuedAt: b0Issued, expiresAt: expires, revocationPolicyRef: revoke },
    eventCore = { eventId: "event:synthetic", creatorPrincipalRef: null, createdInstanceCoreCommitment: { instanceClass: "Q_INITIAL", instanceId: "instance:synthetic", coreDigest: digest(`${PREFIX}/future/instance-creation-event/instance-core/instance:synthetic`, { id: "instance:synthetic" }) }, authorizationNonceDigest: nonce, predecessorInstanceRef: null, createdAt: created, executionStartAllowed: false, admissionAllowed: false, evidenceAdmissionAllowed: false };
  check(
    nonce === "d8e7782053e651d06382cb1fb187e26be18c97361ab9dba49744e099ec345b0b",
    "B0_AUTH_SCHEMA",
    "nonce-vector",
  );
  for (const invalid of [nonceInputHex.slice(2), nonceInputHex.toUpperCase(), `${nonceInputHex}00`]) {
    let rejected = false;
    try {
      deriveAuthorizationNonceDigest("authorization:b0", invalid);
    } catch (error) {
      rejected = error instanceof Error &&
        error.message === "CPSB_B0_AUTH_SCHEMA:nonce-private-bytes";
    }
    check(rejected, "B0_AUTH_SCHEMA", "nonce-representation");
  }
  const nonceDomain =
      `${PREFIX}/future/b0-execution-authorization/nonce/authorization:b0`,
    nonceBytes = Buffer.from(nonceInputHex, "hex");
  check(
    deriveAuthorizationNonceDigest("authorization:b1", nonceInputHex) !== nonce &&
      sha256(Buffer.concat([
        Buffer.from(nonceDomain), Buffer.from([0]), Buffer.from(nonceInputHex),
      ])) !== nonce &&
      sha256(Buffer.concat([
        Buffer.from(nonceDomain), Buffer.from([0]), nonceBytes, Buffer.from([10]),
      ])) !== nonce,
    "B0_AUTH_SCHEMA",
    "nonce-framing",
  );
  /* The following is intentionally an ephemeral acyclic graph.  It exercises
   * the join auditor without writing a second representation to disk. */
  const futureRef = (key, id, value) => ({
      [key]: id,
      locator: `synthetic/future-${id}.json`,
      bytes: Buffer.byteLength(`${canonicalJson(value)}\n`, "utf8"),
      rawSha256: sha256(Buffer.from(`${canonicalJson(value)}\n`, "utf8")),
      contentDigest: value.contentDigest,
    }),
    proofRecord = (proofId, value) => ({
      ...value,
      contentDigest: digest(`${PREFIX}/future/provider-binding/principal-independence-proof/${proofId}`, value),
    }),
    identity = (principalRefId, principalRole) => final("principal-identity-ref", principalRefId, {
      schema: schema("principal-identity-ref.v1.schema.json", "principalIdentityRef"), artifactId: `artifact:${principalRefId}`,
      principalRefId, principalRole, identityArtifactLocator: `synthetic/${principalRefId}.identity`, identityArtifactBytes: 1,
      identityArtifactRawSha256: hash, identityArtifactSchemaId: "synthetic-identity-schema", externalTrustRootId: "trust:synthetic",
      validFrom: from, expiresAt: expires, revocationPolicyRef: revoke,
    }),
    principals = [
      identity("principal:root-governance", "ROOT_SOL_GOVERNANCE_ISSUER"), identity("principal:authority-issuer", "AUTHORITY_CONTRACT_ISSUER"),
      identity("principal:provider-issuer", "PROVIDER_CONTRACT_ISSUER"), identity("principal:catalog-reviewer", "PROVIDER_CATALOG_REVIEWER"),
      identity("principal:b0-issuer", "B0_AUTHORIZATION_ISSUER"), identity("principal:instance-creator", "INSTANCE_CREATOR"),
      ...slots.map((_, index) => identity(`principal:authority-${index}`, "AUTHORITY_PRINCIPAL")),
      ...slots.map((_, index) => identity(`principal:provider-${index}`, "PROVIDER_PRINCIPAL")),
    ],
    principalById = new Map(principals.map((item) => [item.principalRefId, item])),
    principalRecordRef = (id) => futureRef("principalRefId", id, principalById.get(id)),
    futureDecision = (decisionId, decisionKind, issuerId, recordKind, recordId, digestValue, decisionIssued = issued) => final("issuer-decision", decisionId, {
      schema: schema("issuer-decision.v1.schema.json", "issuerDecision"), artifactId: `artifact:${decisionId}`, decisionId, decisionKind,
      issuerPrincipalRef: principalRecordRef(issuerId), subjectCoreCommitments: [{ recordKind, recordId, coreDigest: digestValue }],
      decisionScope: "synthetic-scope", decisionStatus: "ISSUED_EXTERNAL_DECISION", issuedAt: decisionIssued, expiresAt: expires, revocationPolicyRef: revoke,
    }),
    authorityCores = slots.map((policySlotId, index) => ({
      ...copy(authorityCore), authorityContractId: `authority:${index}`, policySlotId,
      issuerPrincipalRef: principalRecordRef("principal:authority-issuer"), authorityPrincipalRef: principalRecordRef(`principal:authority-${index}`),
      authorityPayload: index < 7
        ? { payloadType: "OWNER_AUTHORITY_PAYLOAD", ownerScopeId: policySlotId, ownerContractSchemaId: "synthetic-owner-schema", ownerBindingDomain: "synthetic-owner-domain" }
        : index === 7
        ? { payloadType: "WORKLOAD_MATERIAL_AUTHORITY_PAYLOAD", workloadRootOrderSchemaId: "synthetic-workload-schema", projectionEncodingSchemaId: "synthetic-projection-schema", workloadBindingDomain: "synthetic-workload-domain" }
        : index === 8
        ? { payloadType: "RAW_ARTIFACT_MAP_AUTHORITY_PAYLOAD", artifactMapSchemaId: "synthetic-map-schema", exclusiveWriterPolicySchemaId: "synthetic-writer-schema", artifactMapBindingDomain: "synthetic-map-domain", artifactProducerSeparationRequired: true }
        : { payloadType: "INDEPENDENT_RESULT_VALIDATOR_AUTHORITY_PAYLOAD", resultSchemaId: "synthetic-result-schema", validatorInterfaceSchemaId: "synthetic-validator-schema", independencePolicyId: "synthetic-independence", resultProducerSeparationRequired: true, executionProducerSeparationRequired: true },
    })),
    authorityDigests = authorityCores.map((value) => core("external-authority-contract", value.authorityContractId, value)),
    authorityDecisions = authorityCores.map((value, index) => futureDecision(`decision:authority-${index}`, "EXTERNAL_AUTHORITY_CONTRACT_ISSUANCE", "principal:authority-issuer", "EXTERNAL_AUTHORITY_CONTRACT_V2", value.authorityContractId, authorityDigests[index])),
    authorityRecords = authorityCores.map((value, index) => final("external-authority-contract", value.authorityContractId, {
      schema: schema("external-authority-contract.v2.schema.json", "externalAuthorityContractV2"), artifactId: `artifact:authority-${index}`,
      contractCore: value, contractCoreDigest: authorityDigests[index], issuerDecisionRef: futureRef("decisionId", authorityDecisions[index].decisionId, authorityDecisions[index]),
    })),
    providerCores = slots.map((policySlotId, index) => ({
      ...copy(providerCore), providerContractId: `provider:${index}`, policySlotId,
      issuerPrincipalRef: principalRecordRef("principal:provider-issuer"), providerPrincipalRef: principalRecordRef(`principal:provider-${index}`),
    })),
    providerDigests = providerCores.map((value) => core("provider-contract", value.providerContractId, value)),
    providerDecisions = providerCores.map((value, index) => futureDecision(`decision:provider-${index}`, "PROVIDER_CONTRACT_ISSUANCE", "principal:provider-issuer", "PROVIDER_CONTRACT", value.providerContractId, providerDigests[index])),
    providerRecords = providerCores.map((value, index) => final("provider-contract", value.providerContractId, {
      schema: schema("provider-contract.v1.schema.json", "providerContract"), artifactId: `artifact:provider-${index}`,
      contractCore: value, contractCoreDigest: providerDigests[index], issuerDecisionRef: futureRef("decisionId", providerDecisions[index].decisionId, providerDecisions[index]),
    })),
    collisionCores = ["UOPC", "EAC"].map((selectedDag) => ({
      ...copy(collisionCore), collisionDecisionId: `collision:${selectedDag.toLowerCase()}`, issuerPrincipalRef: principalRecordRef("principal:root-governance"), selectedDag,
      selectedDagComponentDigest: selectedDag === "UOPC" ? "8c80d46922c05700f3d9bbd999e5a780201a09d42da1604dbc22f7a15bda585d" : "72edbc5ea6b08b018bed9a6794b518bab2fee5703e104fb36928f463dead4707",
      selectedDagEdgeCount: selectedDag === "UOPC" ? 40 : 37,
      selectedAPath: selectedDag === "UOPC" ? "UOPC_INITIAL_RETRY_ABORT_WITH_A_INITIAL_TO_B_SUBJECT" : "EAC_RETRY_TO_B_SUBJECT_WITH_INITIAL_ABORT_ACTIVATION_UNAVAILABLE",
      selectedRetryDisposition: selectedDag === "UOPC" ? "A_RETRY_DENY_PREREQUISITE_WHILE_Q_RETRY_BLOCKED_EXTERNAL" : "A_RETRY_BLOCKED_EXTERNAL_REQUIRES_Q_RETRY_AND_ACTIVATION_OWNER",
    })),
    collisionDigests = collisionCores.map((value) => core("source-collision-decision", value.collisionDecisionId, value)),
    collisionDecisions = collisionCores.map((value, index) => futureDecision(`decision:collision-${index}`, "SOURCE_COLLISION_SELECTION", "principal:root-governance", "SOURCE_COLLISION_DECISION_V2", value.collisionDecisionId, collisionDigests[index])),
    collisionRecords = collisionCores.map((value, index) => final("source-collision-decision", value.collisionDecisionId, {
      schema: schema("source-collision-decision.v2.schema.json", "sourceCollisionDecisionV2"), artifactId: `artifact:collision-${index}`,
      decisionCore: value, decisionCoreDigest: collisionDigests[index], issuerDecisionRef: futureRef("decisionId", collisionDecisions[index].decisionId, collisionDecisions[index]),
    })),
    authorityEntries = authorityRecords.map((value, index) => ({ authorityContractId: value.contractCore.authorityContractId, policySlotId: slots[index], ...futureRef("authorityContractId", value.contractCore.authorityContractId, value) })),
    futureAuthoritySet = final("external-authority-contract", authoritySetId, {
      schema: schema("external-authority-contract.v2.schema.json", "externalAuthorityContractSet"), artifactId: authoritySetId,
      status: "EXTERNALLY_ISSUED_AUTHORITY_CONTRACT_SET_NO_INSTANCES", entryCount: 10, entries: authorityEntries,
      rosterDigest: digest(`${PREFIX}/future/external-authority-contract/set-roster/${authoritySetId}`, authorityEntries),
    }),
    futureAuthoritySetRef = { schemaId: schema("external-authority-contract.v2.schema.json", "externalAuthorityContractSet"), entryCount: 10, rosterDigest: futureAuthoritySet.rosterDigest, ...futureRef("artifactId", authoritySetId, futureAuthoritySet) },
    uopcFinal = collisionRecords[0],
    futureG0Core = { ...copy(g0Core), issuerPrincipalRef: principalRecordRef("principal:root-governance"), externalAuthorityContractSetRef: futureAuthoritySetRef, sourceCollisionDecisionRef: futureRef("decisionId", uopcFinal.decisionCore.collisionDecisionId, uopcFinal), issuedAt: g0Issued },
    futureG0Digest = core("binding-creation-authorization-g0", futureG0Core.authorizationId, futureG0Core),
    futureG0Decision = futureDecision("decision:g0", "BINDING_CREATION_AUTHORIZATION_G0", "principal:root-governance", "BINDING_CREATION_AUTHORIZATION_G0", futureG0Core.authorizationId, futureG0Digest, g0Issued),
    futureG0 = final("binding-creation-authorization-g0", futureG0Core.authorizationId, { schema: schema("binding-creation-authorization-g0.v1.schema.json", "bindingCreationAuthorizationG0"), artifactId: "artifact:future-g0", authorizationCore: futureG0Core, authorizationCoreDigest: futureG0Digest, issuerDecisionRef: futureRef("decisionId", futureG0Decision.decisionId, futureG0Decision) }),
    futureProofs = slots.map((policySlotId, index) => proofRecord(`proof:${index}`, { proofId: `proof:${index}`, proofType: "SYNTHETIC_PRINCIPAL_INDEPENDENCE_PROJECTION_V1", bindingId: `binding:${index}`, policySlotId, principalCoincidencePolicy: { status: "ALL_RELEVANT_PRINCIPALS_MUST_BE_DISTINCT", allowedPairs: [] }, principalProjection: ["principal:root-governance", "principal:authority-issuer", `principal:authority-${index}`, "principal:provider-issuer", `principal:provider-${index}`, "principal:catalog-reviewer"].map((principalRefId, row) => ({ relation: ["ROOT_GOVERNANCE", "AUTHORITY_CONTRACT_ISSUER", "AUTHORITY_PRINCIPAL", "PROVIDER_CONTRACT_ISSUER", "PROVIDER_PRINCIPAL", "CATALOG_REVIEWER"][row], requiredPrincipalRole: ["ROOT_SOL_GOVERNANCE_ISSUER", "AUTHORITY_CONTRACT_ISSUER", "AUTHORITY_PRINCIPAL", "PROVIDER_CONTRACT_ISSUER", "PROVIDER_PRINCIPAL", "PROVIDER_CATALOG_REVIEWER"][row], principalRefId, principalIdentityContentDigest: principalById.get(principalRefId).contentDigest })), projectedPrincipalCount: 6, distinctPrincipalRefIdCount: 6, allProjectedPrincipalRefIdsDistinct: true })),
    futureBindings = slots.map((policySlotId, index) => {
      const bindingCoreValue = { bindingId: `binding:${index}`, policySlotId, authorityContractRef: authorityEntries[index], authorityPrincipalRef: principalRecordRef(`principal:authority-${index}`), providerContractRef: { providerContractId: providerRecords[index].contractCore.providerContractId, policySlotId, ...futureRef("providerContractId", providerRecords[index].contractCore.providerContractId, providerRecords[index]) }, providerPrincipalRef: principalRecordRef(`principal:provider-${index}`), catalogReviewerPrincipalRef: principalRecordRef("principal:catalog-reviewer"), sourceCollisionDecisionRef: futureRef("decisionId", uopcFinal.decisionCore.collisionDecisionId, uopcFinal), principalIndependenceProofRef: futureRef("proofId", futureProofs[index].proofId, futureProofs[index]), instanceCreationAllowed: false, executionAllowed: false, admissionAllowed: false }, bindingDigestValue = core("provider-binding", `binding:${index}`, bindingCoreValue);
      return final("provider-binding", `binding:${index}`, { schema: schema("provider-binding.v2.schema.json", "providerBindingV2"), artifactId: `artifact:binding-${index}`, bindingCore: bindingCoreValue, bindingCoreDigest: bindingDigestValue, g0AuthorizationRef: futureRef("authorizationId", futureG0Core.authorizationId, futureG0) });
    }),
    bindingEntries = futureBindings.map((value, index) => ({ bindingId: value.bindingCore.bindingId, policySlotId: slots[index], ...futureRef("bindingId", value.bindingCore.bindingId, value) })),
    futureBindingSet = final("provider-binding", bindingSetId, { schema: schema("provider-binding.v2.schema.json", "providerBindingSet"), artifactId: bindingSetId, status: "G0_AUTHORIZED_PROVIDER_BINDING_SET_NO_INSTANCES", entryCount: 10, entries: bindingEntries, rosterDigest: digest(`${PREFIX}/future/provider-binding/set-roster/${bindingSetId}`, bindingEntries) }),
    futureBindingSetRef = { schemaId: schema("provider-binding.v2.schema.json", "providerBindingSet"), entryCount: 10, rosterDigest: futureBindingSet.rosterDigest, ...futureRef("artifactId", bindingSetId, futureBindingSet) };
  /* Remaining records are formed after both immutable sets exist. */
  const futureCatalogCore = { ...copy(catalogCore), externalAuthorityContractSetRef: futureAuthoritySetRef, g0AuthorizationRef: futureRef("authorizationId", futureG0Core.authorizationId, futureG0), sourceCollisionDecisionRef: futureRef("decisionId", uopcFinal.decisionCore.collisionDecisionId, uopcFinal), providerBindingSetRef: futureBindingSetRef, bindingRefs: bindingEntries, reviewerPrincipalRef: principalRecordRef("principal:catalog-reviewer") },
    futureCatalogDigest = core("provider-binding-catalog", futureCatalogCore.catalogId, futureCatalogCore),
    futureCatalogDecision = futureDecision("decision:catalog", "PROVIDER_BINDING_CATALOG_REVIEW", "principal:catalog-reviewer", "PROVIDER_BINDING_CATALOG", futureCatalogCore.catalogId, futureCatalogDigest, catalogIssued),
    futureCatalog = final("provider-binding-catalog", futureCatalogCore.catalogId, { schema: schema("provider-binding-catalog.v1.schema.json", "providerBindingCatalog"), artifactId: "artifact:future-catalog", catalogCore: futureCatalogCore, catalogCoreDigest: futureCatalogDigest, reviewDecisionRef: futureRef("decisionId", futureCatalogDecision.decisionId, futureCatalogDecision) }),
    futureCatalogRef = futureRef("artifactId", futureCatalog.artifactId, futureCatalog),
    futureG1Core = { ...copy(g1Core), issuerPrincipalRef: principalRecordRef("principal:root-governance"), externalAuthorityContractSetRef: futureAuthoritySetRef, providerBindingCatalogRef: futureCatalogRef, sourceCollisionDecisionRef: futureRef("decisionId", uopcFinal.decisionCore.collisionDecisionId, uopcFinal), issuedAt: g1Issued },
    futureG1Digest = core("governance-authorization-g1", futureG1Core.authorizationId, futureG1Core), futureG1Decision = futureDecision("decision:g1", "GOVERNANCE_AUTHORIZATION_G1", "principal:root-governance", "GOVERNANCE_AUTHORIZATION_G1", futureG1Core.authorizationId, futureG1Digest, g1Issued), futureG1 = final("governance-authorization-g1", futureG1Core.authorizationId, { schema: schema("governance-authorization-g1.v1.schema.json", "governanceAuthorizationG1"), artifactId: "artifact:future-g1", authorizationCore: futureG1Core, authorizationCoreDigest: futureG1Digest, issuerDecisionRef: futureRef("decisionId", futureG1Decision.decisionId, futureG1Decision) }),
    futureB0Core = { ...copy(b0Core), issuerPrincipalRef: principalRecordRef("principal:b0-issuer"), externalAuthorityContractSetRef: futureAuthoritySetRef, providerBindingCatalogRef: futureCatalogRef, sourceCollisionDecisionRef: futureRef("decisionId", uopcFinal.decisionCore.collisionDecisionId, uopcFinal), issuedAt: b0Issued }, futureB0Digest = core("b0-execution-authorization", futureB0Core.authorizationId, futureB0Core), futureB0Decision = futureDecision("decision:b0", "B0_EXECUTION_AUTHORIZATION", "principal:b0-issuer", "B0_EXECUTION_AUTHORIZATION", futureB0Core.authorizationId, futureB0Digest, b0Issued), futureB0 = final("b0-execution-authorization", futureB0Core.authorizationId, { schema: schema("b0-execution-authorization.v1.schema.json", "b0ExecutionAuthorization"), artifactId: "artifact:future-b0", authorizationCore: futureB0Core, authorizationCoreDigest: futureB0Digest, issuerDecisionRef: futureRef("decisionId", futureB0Decision.decisionId, futureB0Decision), g1AuthorizationRef: futureRef("authorizationId", futureG1Core.authorizationId, futureG1) }),
    createdInstanceCore = { instanceClass: "Q_INITIAL", instanceId: "instance:synthetic" },
    futureEventCore = { ...copy(eventCore), creatorPrincipalRef: principalRecordRef("principal:instance-creator"), createdInstanceCoreCommitment: { instanceClass: createdInstanceCore.instanceClass, instanceId: createdInstanceCore.instanceId, coreDigest: digest(`${PREFIX}/future/instance-creation-event/instance-core/${createdInstanceCore.instanceId}`, createdInstanceCore) }, authorizationNonceDigest: futureB0Core.authorizationNonceDigest }, futureEventDigest = core("instance-creation-event", futureEventCore.eventId, futureEventCore), futureEventDecision = futureDecision("decision:event", "INSTANCE_CREATION", "principal:instance-creator", "INSTANCE_CREATION_EVENT", futureEventCore.eventId, futureEventDigest, instanceIssued), futureEvent = final("instance-creation-event", futureEventCore.eventId, { schema: schema("instance-creation-event.v1.schema.json", "instanceCreationEvent"), artifactId: "artifact:future-event", eventCore: futureEventCore, eventCoreDigest: futureEventDigest, issuerDecisionRef: futureRef("decisionId", futureEventDecision.decisionId, futureEventDecision), b0ExecutionAuthorizationRef: futureRef("authorizationId", futureB0Core.authorizationId, futureB0) });
  const graph = { identities: principals, decisions: [...authorityDecisions, ...providerDecisions, ...collisionDecisions, futureG0Decision, futureCatalogDecision, futureG1Decision, futureB0Decision, futureEventDecision], authorityContracts: authorityRecords, providerContracts: providerRecords, collisions: collisionRecords, authoritySet: futureAuthoritySet, proofs: futureProofs, bindings: futureBindings, bindingSet: futureBindingSet, g0: futureG0, catalog: futureCatalog, g1: futureG1, b0: futureB0, event: futureEvent, createdInstanceCores: [createdInstanceCore], expectedFoundationRefs, nonceInputHex },
    primarySpecs = [
      ["principal-identity-ref.v1.schema.json", "principalIdentityRef", "IDENTITY_SCHEMA"],
      ["issuer-decision.v1.schema.json", "issuerDecision", "ISSUER_DECISION_SCHEMA"],
      ["external-authority-contract.v2.schema.json", "externalAuthorityContractV2", "AUTHORITY_CONTRACT_SCHEMA"],
      ["provider-contract.v1.schema.json", "providerContract", "PROVIDER_CONTRACT_SCHEMA"],
      ["source-collision-decision.v2.schema.json", "sourceCollisionDecisionV2", "COLLISION_DECISION_SCHEMA"],
      ["binding-creation-authorization-g0.v1.schema.json", "bindingCreationAuthorizationG0", "G0_SCHEMA"],
      ["provider-binding.v2.schema.json", "providerBindingV2", "PROVIDER_BINDING_SCHEMA"],
      ["provider-binding-catalog.v1.schema.json", "providerBindingCatalog", "CATALOG_SCHEMA"],
      ["governance-authorization-g1.v1.schema.json", "governanceAuthorizationG1", "G1_SCHEMA"],
      ["b0-execution-authorization.v1.schema.json", "b0ExecutionAuthorization", "B0_AUTH_SCHEMA"],
      ["instance-creation-event.v1.schema.json", "instanceCreationEvent", "INSTANCE_EVENT_SCHEMA"],
    ];
  const futureValidators = Object.fromEntries(primarySpecs.map(([file, definition, token]) => {
      const validate = schemaState.ajv.getSchema(schema(file, definition));
      check(validate, token, "synthetic-validator");
      return [definition, [validate, token]];
    })),
    validateAll = (validatorPair, values) => {
      for (const value of values) {
        check(validatorPair[0](value), validatorPair[1], "synthetic-positive");
      }
    },
    validateAuthoritySet = schemaState.ajv.getSchema(schema("external-authority-contract.v2.schema.json", "externalAuthorityContractSet")),
    validateBindingSet = schemaState.ajv.getSchema(schema("provider-binding.v2.schema.json", "providerBindingSet"));
  validateAll(futureValidators.principalIdentityRef, principals);
  validateAll(futureValidators.issuerDecision, graph.decisions);
  validateAll(futureValidators.externalAuthorityContractV2, authorityRecords);
  validateAll(futureValidators.providerContract, providerRecords);
  validateAll(futureValidators.sourceCollisionDecisionV2, collisionRecords);
  validateAll(futureValidators.bindingCreationAuthorizationG0, [futureG0]);
  validateAll(futureValidators.providerBindingV2, futureBindings);
  validateAll(futureValidators.providerBindingCatalog, [futureCatalog]);
  validateAll(futureValidators.governanceAuthorizationG1, [futureG1]);
  validateAll(futureValidators.b0ExecutionAuthorization, [futureB0]);
  validateAll(futureValidators.instanceCreationEvent, [futureEvent]);
  check(validateAuthoritySet && validateAuthoritySet(futureAuthoritySet), "AUTHORITY_CONTRACT_SCHEMA", "synthetic-set");
  check(validateBindingSet && validateBindingSet(futureBindingSet), "PROVIDER_BINDING_SCHEMA", "synthetic-set");
  auditSyntheticFutureGraph(graph);
  const expectSemanticFailure = (mutate, expected) => {
    const altered = copy(graph);
    mutate(altered);
    let actual = null;
    try {
      auditSyntheticFutureGraph(altered);
    } catch (error) {
      actual = error instanceof Error ? error.message : null;
    }
    check(actual === expected, "ROOT_SCHEMA", `future-negative:${expected}`);
  };
  expectSemanticFailure(
    value => {
      value.identities[0].expiresAt = value.identities[0].validFrom;
      const identityBody = withoutDigest(value.identities[0]);
      value.identities[0].contentDigest = digestRecord(
        `${PREFIX}/future/principal-identity-ref/${value.identities[0].principalRefId}`,
        identityBody,
      );
    },
    "CPSB_IDENTITY_SCHEMA:identity:principal:root-governance",
  );
  expectSemanticFailure(
    value => {
      value.b0.authorizationCore.authorizationNonceDigest = "1".repeat(64);
      value.b0.authorizationCoreDigest = digestRecord(
        `${PREFIX}/future/b0-execution-authorization/core/${value.b0.authorizationCore.authorizationId}`,
        value.b0.authorizationCore,
      );
      const b0Decision = value.decisions.find(item =>
        item.decisionId === value.b0.issuerDecisionRef.decisionId
      );
      b0Decision.subjectCoreCommitments[0].coreDigest = value.b0.authorizationCoreDigest;
      const b0DecisionBody = withoutDigest(b0Decision);
      b0Decision.contentDigest = digestRecord(
        `${PREFIX}/future/issuer-decision/${b0Decision.decisionId}`,
        b0DecisionBody,
      );
      value.b0.issuerDecisionRef = futureRef(
        "decisionId",
        b0Decision.decisionId,
        b0Decision,
      );
      const b0Body = withoutDigest(value.b0);
      value.b0.contentDigest = digestRecord(
        `${PREFIX}/future/b0-execution-authorization/record/${value.b0.authorizationCore.authorizationId}`,
        b0Body,
      );
      value.event.eventCore.authorizationNonceDigest = "1".repeat(64);
      value.event.b0ExecutionAuthorizationRef = futureRef(
        "authorizationId",
        value.b0.authorizationCore.authorizationId,
        value.b0,
      );
      value.event.eventCoreDigest = digestRecord(
        `${PREFIX}/future/instance-creation-event/core/${value.event.eventCore.eventId}`,
        value.event.eventCore,
      );
      const eventDecision = value.decisions.find(item =>
        item.decisionId === value.event.issuerDecisionRef.decisionId
      );
      eventDecision.subjectCoreCommitments[0].coreDigest = value.event.eventCoreDigest;
      const eventDecisionBody = withoutDigest(eventDecision);
      eventDecision.contentDigest = digestRecord(
        `${PREFIX}/future/issuer-decision/${eventDecision.decisionId}`,
        eventDecisionBody,
      );
      value.event.issuerDecisionRef = futureRef(
        "decisionId",
        eventDecision.decisionId,
        eventDecision,
      );
      const eventBody = withoutDigest(value.event);
      value.event.contentDigest = digestRecord(
        `${PREFIX}/future/instance-creation-event/record/${value.event.eventCore.eventId}`,
        eventBody,
      );
    },
    "CPSB_B0_AUTH_SCHEMA:nonce-join",
  );
  const nestedNonce = copy(futureB0);
  nestedNonce.authorizationCore.authorizationNonceDigest = digest(
    `${PREFIX}/future/b0-execution-authorization/nonce/${futureB0Core.authorizationId}`,
    { value: nonce },
  );
  check(
    !futureValidators.b0ExecutionAuthorization[0](nestedNonce),
    "B0_AUTH_SCHEMA",
    "nonce-digest-record",
  );
};
const checkExactSemanticTables = (root) => {
  const identity = {
      schema: root.schema,
      artifactId: root.artifactId,
      packageId: root.packageId,
      status: root.status,
      purpose: root.purpose,
      executionAllowed: root.executionAllowed,
      measurementAdmissionAllowed: root.measurementAdmissionAllowed,
    },
    future = COMPONENT_VALUE(root.futureRecordContracts),
    bindings = root.schemaBindings.map((row) => {
      const copy = { ...row };
      delete copy.rawSha256;
      return copy;
    });
  future.entries = future.entries.map(COMPONENT_VALUE);
  const rows = [
    ["identity", identity, "ROOT_ID"],
    [
      "dependencyBinding",
      COMPONENT_VALUE(root.dependencyBinding),
      "DEPENDENCY_SEMANTIC",
    ],
    [
      "eappV1Disposition",
      COMPONENT_VALUE(root.eappV1Disposition),
      "EAPP_V1_DISPOSITION",
    ],
    ["futureRecordContracts", future, "FUTURE_RECORD_ROSTER"],
    [
      "controlPlaneTransition",
      COMPONENT_VALUE(root.controlPlaneTransition),
      "TRANSITION",
    ],
    [
      "artifactDependencyDag",
      COMPONENT_VALUE(root.artifactDependencyDag),
      "DAG",
    ],
    [
      "nonAuthorityBoundary",
      COMPONENT_VALUE(root.nonAuthorityBoundary),
      "NONAUTHORITY",
    ],
    [
      "runtimeBoundary",
      COMPONENT_VALUE(root.runtimeBoundary),
      "RUNTIME_BOUNDARY",
    ],
    ["schemaBindings", bindings, "SCHEMA_RAW"],
  ];
  for (const row of rows) {
    check(
      semanticFingerprint(row[1]) === SEMANTIC_FINGERPRINTS[row[0]],
      row[2],
      `${row[0]}:literal-table`,
    );
  }
  check(
    root.schemaBindings.length === SCHEMA_BINDING_POINTERS.length &&
      root.schemaBindings.every((row, index) =>
        same(row.rootJsonPointers, SCHEMA_BINDING_POINTERS[index]) &&
        row.rootJsonPointers.every((pointer) => {
          pointerValue(root, pointer);
          return true;
        })
      ),
    "SCHEMA_RAW",
    "root-pointers",
  );
};
const checkSemantics = (root, packageRoot) => {
  check(same(Object.keys(root), ROOT_KEYS.slice().sort()), "ROOT_KEYS");
  check(root.schema === PREFIX && root.packageId === PACKAGE_ID, "ROOT_ID");
  check(
    root.status ===
      "static-control-plane-schema-bridge-no-principals-no-decisions-no-authority-contracts-no-provider-contracts-no-provider-bindings-no-governance-authorization-no-b0-execution-authorization-no-instances-no-admission-no-execution-unqualified",
    "STATUS",
  );
  exactDependency(root, packageRoot);
  checkExactSemanticTables(root);
  check(
    root.eappV1Disposition.selectedDag === null &&
      root.eappV1Disposition.recordInstantiationAllowed === false,
    "EAPP_V1_DISPOSITION",
  );
  check(
    root.futureRecordContracts.recordKindCount === 11 &&
      root.futureRecordContracts.totalRecordCount === 0 &&
      root.futureRecordContracts.creationAllowed === false &&
      root.futureRecordContracts.entries.length === 11 &&
      root.futureRecordContracts.entries.every((row) =>
        row.recordCount === 0 && row.creationAllowed === false &&
        row.packageMayEmbedRecord === false
      ),
    "FUTURE_RECORD_ROSTER",
  );
  for (const row of root.futureRecordContracts.entries) {
    const schema = strictParse(
        safeRead(
          packageRoot,
          root.schemaBindings.find((binding) =>
            binding.schemaId === row.schemaId
          )?.locator,
        ),
        { canonical: true },
      ),
      definition = schema.$defs
        ?.[row.definitionPointer.replace(/^#\/\$defs\//, "")];
    check(
      definition && same(definition.required, row.requiredKeys),
      "FUTURE_RECORD_SCHEMA",
      row.recordKind,
    );
  }
  check(
    root.controlPlaneTransition.currentState ===
        "AUTHORITY_POLICY_FROZEN_NO_AUTHORITY" &&
      root.controlPlaneTransition.authorizedTransitions.length === 0 &&
      root.controlPlaneTransition.selectedDag === null &&
      root.controlPlaneTransition.edges.length === 7,
    "TRANSITION",
  );
  const nodeIds = root.artifactDependencyDag.nodes.map((row) => row.nodeId),
    edges = root.artifactDependencyDag.edges;
  check(
    root.artifactDependencyDag.nodeCount === 28 &&
      root.artifactDependencyDag.edgeCount === 75 &&
      root.artifactDependencyDag.acyclic === true &&
      new Set(nodeIds).size === 28 &&
      edges.every((row) =>
        nodeIds.includes(row.from) && nodeIds.includes(row.to) &&
        row.edgeClass === "CONTENT_OR_SCHEMA_PREREQUISITE_NO_AUTHORITY"
      ) &&
      root.artifactDependencyDag.nodes.every((row) =>
        row.nodeId === row.artifactClass && row.recordCount === 0 &&
        row.creationAllowed === false
      ),
    "DAG",
  );
  const incoming = new Map(nodeIds.map((id) => [id, 0]));
  for (const edge of edges) incoming.set(edge.to, incoming.get(edge.to) + 1);
  const queue = nodeIds.filter((id) => incoming.get(id) === 0);
  let visited = 0;
  while (queue.length) {
    const id = queue.shift();
    visited++;
    for (const edge of edges.filter((row) => row.from === id)) {
      incoming.set(edge.to, incoming.get(edge.to) - 1);
      if (incoming.get(edge.to) === 0) queue.push(edge.to);
    }
  }
  check(visited === 28, "DAG", "cycle");
  check(
    Object.entries(root.nonAuthorityBoundary).every(([key, value]) =>
      key === "status" || key === "contentDigest" || value === 0 ||
      value === false
    ),
    "NONAUTHORITY",
  );
  check(
    root.runtimeBoundary.runtimeEntrypoint === null &&
      root.runtimeBoundary.runtimeModules.length === 0 &&
      root.runtimeBoundary.runtimeExports.length === 0 &&
      root.runtimeBoundary.importEvaluationAllowed === false,
    "RUNTIME_BOUNDARY",
  );
  check(
    root.schemaBindings.length === 18 && same(
      root.schemaBindings.map((row) => row.locator),
      SCHEMAS,
    ) &&
      root.schemaBindings.every((row) =>
        sha256(safeRead(packageRoot, row.locator)) === row.rawSha256 &&
        strictParse(safeRead(packageRoot, row.locator), { canonical: true })
            .$id === row.schemaId
      ),
    "SCHEMA_RAW",
  );
  for (const row of root.futureRecordContracts.entries) {
    const copy = { ...row };
    delete copy.contentDigest;
    check(
      same(
        row.contentDigest,
        digestRecord(
          `${PREFIX}/future-record-contract/${row.recordKind}`,
          copy,
        ),
      ),
      "DIGEST",
      row.recordKind,
    );
  }
  for (const [component, suffix] of COMPONENTS) {
    if (!Array.isArray(root[component])) {
      check(
        same(
          root[component].contentDigest,
          digestRecord(`${PREFIX}/${suffix}`, COMPONENT_VALUE(root[component])),
        ),
        "DIGEST",
        component,
      );
    }
  }
  check(
    same(
      root.componentDigests,
      COMPONENTS.map(([component, suffix]) => ({
        component,
        digest: digestRecord(
          `${PREFIX}/${suffix}`,
          COMPONENT_VALUE(root[component]),
        ),
      })),
    ),
    "DIGEST",
    "components",
  );
  const copy = { ...root };
  delete copy.contentDigest;
  check(
    same(root.contentDigest, digestRecord(`${PREFIX}/root`, copy)),
    "CONTENT_DIGEST",
  );
};
const checkKats = (packageRoot) => {
  const kat = strictParse(safeRead(packageRoot, "test/digest.kat.json"), {
      canonical: true,
      allowNfd: true,
    }),
    acceptedIds = [
      "semantic-empty-object",
      "semantic-key-sort",
      "semantic-nested-object",
      "semantic-array-order",
      "semantic-nfc",
      "raw-empty-file",
      "raw-lf-file",
      "raw-binary-file",
      "authority-contract-core",
      "g0-authorization-core",
      "b0-authorization-core",
      "b0-authorization-nonce",
      "manifest-roster",
    ],
    rejectedIds = [
      "semantic-nfd-reject",
      "duplicate-key-reject",
      "non-utf8-reject",
      "noncanonical-path-reject",
    ];
  check(
    same(Object.keys(kat), [
      "accepted",
      "artifactId",
      "rejected",
      "schema",
      "status",
    ]) && kat.schema === `${PREFIX}/digest-kat/v1` &&
      kat.artifactId ===
        "artifact:gate-b:gate-b0-external-authority-control-plane-schema-bridge-digest-kat-v1" &&
      kat.status === "static-build-time-zero-authority-kat" &&
      same(kat.accepted.map((row) => row.katId), acceptedIds) &&
      same(kat.rejected.map((row) => row.katId), rejectedIds),
    "DIGEST",
    "kat-roster",
  );
  for (const row of kat.accepted) {
    check(
      same(Object.keys(row), [
        "disposition",
        "domain",
        "inputHex",
        "katId",
        "preimageHex",
        "sha256",
      ]) && row.disposition === "ACCEPT" &&
        /^(?:[0-9a-f]{2})*$/u.test(row.inputHex) &&
        /^(?:[0-9a-f]{2})+$/u.test(row.preimageHex) &&
        /^[0-9a-f]{64}$/u.test(row.sha256),
      "DIGEST",
      row.katId,
    );
    const input = Buffer.from(row.inputHex, "hex"),
      semantic = row.katId.startsWith("semantic-") ||
        row.katId.endsWith("-core") || row.katId === "manifest-roster",
      preimage = row.katId === "b0-authorization-nonce"
        ? Buffer.concat([Buffer.from(row.domain), Buffer.from([0]), input])
        : Buffer.concat([
          Buffer.from(row.domain),
          Buffer.from([0]),
          semantic
            ? Buffer.from(`${canonicalJson(strictParse(input))}\n`)
            : input,
        ]);
    check(
      preimage.toString("hex") === row.preimageHex &&
        sha256(preimage) === row.sha256,
      "DIGEST",
      row.katId,
    );
    if (row.katId === "b0-authorization-nonce") {
      check(
        row.domain ===
          `${PREFIX}/future/b0-execution-authorization/nonce/authorization:b0` &&
          row.inputHex ===
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" &&
          deriveAuthorizationNonceDigest("authorization:b0", row.inputHex) ===
            row.sha256,
        "DIGEST",
        "b0-authorization-nonce",
      );
    }
  }
  const expectedErrors = [
    "CPSB_NON_NFC",
    "CPSB_DUPLICATE_KEY",
    "CPSB_UTF8",
    "CPSB_PATH",
  ];
  for (const [index, row] of kat.rejected.entries()) {
    check(
      same(Object.keys(row), [
        "disposition",
        "errorToken",
        "inputHex",
        "katId",
      ]) && row.disposition === "REJECT" &&
        row.errorToken === expectedErrors[index] &&
        /^(?:[0-9a-f]{2})+$/u.test(row.inputHex),
      "DIGEST",
      row.katId,
    );
    let rejected = false;
    try {
      const input = Buffer.from(row.inputHex, "hex");
      if (index < 3) strictParse(input);
      else safeLocator(input.toString("utf8"));
    } catch (error) {
      rejected = error instanceof Error && error.message === row.errorToken;
    }
    check(rejected, "DIGEST", row.katId);
  }
};
const checkEnvelope = (packageRoot, anchor) => {
  const envelope = deriveSealEnvelope(packageRoot),
    manifestBytes = safeRead(packageRoot, "MANIFEST.json"),
    sumsBytes = safeRead(packageRoot, "SHA256SUMS");
  check(manifestBytes.equals(envelope.manifestBytes), "MANIFEST");
  check(sumsBytes.equals(envelope.sumsBytes), "SUMS");
  check(
    same(anchor.orderedClosure, envelope.entries) &&
      same(anchor.rosterDigest, envelope.rosterDigest) &&
      anchor.manifestRawSha256 === sha256(manifestBytes) &&
      anchor.sha256SumsRawSha256 === sha256(sumsBytes),
    "ANCHOR_CLOSURE",
  );
  return envelope;
};
export const validateStatic = (
  {
    packageRoot = here,
    mode,
    anchorRoot = null,
    anchorLocator = null,
    anchorBytes = null,
    anchorRawSha256 = null,
  } = {},
) => {
  check(mode === "unsealed" || mode === "sealed", "PACKAGE_MODE");
  const pin = { anchorRoot, anchorLocator, anchorBytes, anchorRawSha256 };
  const anchor = mode === "sealed"
    ? readAnchor(pin, packageRoot)
    : (check(Object.values(pin).every((value) => value === null), "CLI_ARGS"),
      null);
  const closure = checkClosure(packageRoot, mode);
  if (anchor) checkEnvelope(packageRoot, anchor);
  scanSources(packageRoot);
  checkDocs(packageRoot);
  assertSealedRootPin(packageRoot, anchor);
  const root = parseRoot(packageRoot);
  check(
    root.schemaBindings.length === 18 && same(
      root.schemaBindings.map((row) => row.locator),
      SCHEMAS,
    ) &&
      root.schemaBindings.every((row) =>
        sha256(safeRead(packageRoot, row.locator)) === row.rawSha256
      ),
    "SCHEMA_RAW",
  );
  const schemaState = checkSchemas(packageRoot),
    rootValidator = schemaState.ajv.getSchema(
      `${SCHEMA_PREFIX}root.v1.schema.json#/$defs/root`,
    );
  check(rootValidator && rootValidator(root), "ROOT_SCHEMA");
  checkTemporalSchemaContracts(schemaState.schemas);
  checkSemantics(root, packageRoot);
  checkDependencyBytes(root, resolve(packageRoot, "../../../../.."));
  assertSyntheticFutureCoherence(schemaState);
  checkKats(packageRoot);
  if (anchor) {
    const schemaBindingTableDigest = digestRecord(
        `${PREFIX}/schema-bindings`,
        root.schemaBindings,
      ),
      eappDigest = root.componentDigests.find((row) =>
        row.component === "eappV1Disposition"
      )?.digest;
    check(
      anchor.rootRawSha256 === sha256(safeRead(packageRoot, ROOT_FILE)) &&
        same(anchor.rootContentDigest, root.contentDigest) &&
        anchor.validatorRawSha256 ===
          sha256(safeRead(packageRoot, "validate-static.mjs")),
      "ANCHOR_RAW",
    );
    check(
      same(anchor.schemaBindings, root.schemaBindings) &&
        same(anchor.schemaBindingTableDigest, schemaBindingTableDigest) &&
        same(anchor.componentDigests, root.componentDigests) &&
        same(anchor.directDependencyBinding, root.dependencyBinding) &&
        same(anchor.eappV1DispositionDigest, eappDigest) &&
        same(anchor.nonAuthorityBoundary, root.nonAuthorityBoundary),
      "ANCHOR_CLOSURE",
    );
  }
  return {
    ...closure,
    schemaCount: 18,
    futureRecordSchemaCount: 11,
    totalRecordCount: 0,
    rootContentDigest: root.contentDigest.value,
    unsealed: mode === "unsealed",
  };
};
if (
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const args = parseValidationCliArgs(process.argv.slice(2));
  console.log(JSON.stringify(validateStatic(args)));
}
