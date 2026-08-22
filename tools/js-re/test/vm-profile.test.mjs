import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalJson, semanticFingerprint, sha256Hex } from "../src/vm-profile/canonicalize.mjs";
import { extractVmProfile } from "../src/vm-profile/extract.mjs";
import { finalizeProfile, validateProfile } from "../src/vm-profile/schema.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "../../..");
const leftover1 = path.join(
  repo,
  "artifacts/re-out/chrome-oracle-leftover1/executed-fetch-15.js",
);
const leftover4 = path.join(
  repo,
  "artifacts/re-out/chrome-oracle-leftover4/executed-fetch-15.js",
);

function handler(profile, opcode) {
  return profile.handlers.find((candidate) => candidate.opcode === opcode);
}

test("canonical JSON and fingerprint are independent of object insertion order", () => {
  const a = { z: 1, a: { y: 2, b: [3, { q: 4, c: 5 }] } };
  const b = { a: { b: [3, { c: 5, q: 4 }], y: 2 }, z: 1 };
  assert.equal(canonicalJson(a), canonicalJson(b));
  assert.equal(sha256Hex(canonicalJson(a)), sha256Hex(canonicalJson(b)));
});

test("schema rejects unknown fields and semantic mutations", () => {
  const profile = finalizeProfile({
    schemaVersion: 1,
    sourceSha256: sha256Hex("source"),
    semanticFingerprint: "0".repeat(64),
    fetch: {
      initPc: 0,
      initKey: 62,
      byteBias: 1,
      keyMul: 40954,
      keyAdd: 30072,
      keyQuadB: 0,
    },
    switchOpcodes: [181],
    handlers: [
      {
        opcode: 181,
        handlerLabel: "rotatingName",
        handlerFingerprint: sha256Hex("handler"),
        spec: { kind: "unknown", reason: "synthetic" },
      },
    ],
  });
  assert.equal(validateProfile(profile), profile);
  assert.throws(() => validateProfile({ ...profile, surprise: true }), /keys/);
  const mutated = structuredClone(profile);
  mutated.handlers[0].spec = { kind: "jump_stop", reason: "changed" };
  assert.notEqual(semanticFingerprint(mutated), profile.semanticFingerprint);
  assert.throws(() => validateProfile(mutated), /semanticFingerprint mismatch/);
});

test("leftover rotations produce equivalent exact 181 and 167 specs", { timeout: 20_000 }, (t) => {
  if (!fs.existsSync(leftover1) || !fs.existsSync(leftover4)) {
    t.skip("gitignored headed-Chrome captures are absent");
    return;
  }
  const source1 = fs.readFileSync(leftover1, "utf8");
  const source4 = fs.readFileSync(leftover4, "utf8");
  const one = extractVmProfile(source1, { sourceName: leftover1 });
  const four = extractVmProfile(source4, { sourceName: leftover4 });

  assert.equal(one.summary.switchCaseCount, 69);
  assert.equal(four.summary.switchCaseCount, 69);
  assert.equal(one.summary.equivalentDispatches, 2);
  assert.equal(four.summary.equivalentDispatches, 2);
  assert.notEqual(one.profile.sourceSha256, four.profile.sourceSha256);
  assert.deepEqual(one.profile.switchOpcodes, four.profile.switchOpcodes);

  for (const opcode of [167, 181]) {
    assert.deepEqual(handler(one.profile, opcode).spec, handler(four.profile, opcode).spec);
    assert.equal(
      handler(one.profile, opcode).handlerFingerprint,
      handler(four.profile, opcode).handlerFingerprint,
    );
  }
  assert.deepEqual(handler(four.profile, 167).spec, {
    kind: "leb_table",
    count_byte_xor: 0,
    index_byte_xor: 0,
    max_count: 1_048_576,
  });
  const tagged = handler(four.profile, 181).spec;
  assert.equal(tagged.kind, "tagged_load");
  assert.equal(tagged.operand_order, "tag_then_dst");
  assert.equal(tagged.tag_xor, 217);
  assert.equal(tagged.dst_xor, 210);
  assert.deepEqual(
    tagged.tags.map((tag) => tag.tag),
    [7, 20, 27, 32, 37, 39, 80, 88, 120, 182, 195, 220, 251],
  );
  assert.deepEqual(tagged.tags.find((tag) => tag.tag === 32).payload, {
    kind: "string",
    length_byte_xor: 0,
    char_xor: 225,
  });
});

test("identifier rotation survives while semantic changes invalidate", { timeout: 30_000 }, (t) => {
  if (!fs.existsSync(leftover4)) {
    t.skip("gitignored headed-Chrome capture is absent");
    return;
  }
  const source = fs.readFileSync(leftover4, "utf8");
  const original = extractVmProfile(source).profile;

  const renamed = source
    .replace("function bg(", "function zz(")
    .replaceAll("case 181:bg[", "case 181:zz[");
  assert.notEqual(renamed, source);
  const renamedProfile = extractVmProfile(renamed).profile;
  assert.notEqual(renamedProfile.sourceSha256, original.sourceSha256);
  assert.equal(renamedProfile.semanticFingerprint, original.semanticFingerprint);
  assert.deepEqual(handler(renamedProfile, 181).spec, handler(original, 181).spec);

  const xorChanged = source.replace("217.96", "218.01");
  assert.notEqual(xorChanged, source);
  const xorProfile = extractVmProfile(xorChanged).profile;
  assert.equal(handler(xorProfile, 181).spec.tag_xor, 218);
  assert.notEqual(xorProfile.semanticFingerprint, original.semanticFingerprint);

  const calleeChanged = source.replaceAll("case 181:bg[", "case 181:bH[");
  const calleeProfile = extractVmProfile(calleeChanged).profile;
  assert.equal(handler(calleeProfile, 181).spec.kind, "unknown");
  assert.notEqual(calleeProfile.semanticFingerprint, original.semanticFingerprint);

  const caseChanged = source.replaceAll("case 134:bd[", "case 133:bd[");
  const caseProfile = extractVmProfile(caseChanged).profile;
  assert(caseProfile.switchOpcodes.includes(133));
  assert(!caseProfile.switchOpcodes.includes(134));
  assert.notEqual(caseProfile.semanticFingerprint, original.semanticFingerprint);
});
