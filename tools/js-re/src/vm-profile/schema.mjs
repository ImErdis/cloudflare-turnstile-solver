import { semanticFingerprint } from "./canonicalize.mjs";

export const VM_SKIP_PROFILE_SCHEMA_VERSION = 1;
export const MAX_FIXED_READS = 256;
export const MAX_TABLE_COUNT = 1_048_576;

const HEX_256 = /^[0-9a-f]{64}$/;
const SPEC_KINDS = new Set([
  "fixed_reads",
  "leb",
  "leb_table",
  "tagged_load",
  "string_load",
  "jump_stop",
  "unknown",
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertByte(value, field) {
  assert(Number.isInteger(value) && value >= 0 && value <= 255, `${field} must be a byte`);
}

function assertByteArray(values, field) {
  assert(Array.isArray(values) && values.length <= MAX_FIXED_READS, `${field} must be a bounded array`);
  values.forEach((value, index) => assertByte(value, `${field}[${index}]`));
}

function assertExactKeys(value, expected, field) {
  const got = Object.keys(value).sort();
  const want = [...expected].sort();
  assert(JSON.stringify(got) === JSON.stringify(want), `${field} keys ${got} != ${want}`);
}

function validatePayload(payload, field) {
  assert(payload && typeof payload === "object", `${field} must be an object`);
  switch (payload.kind) {
    case "none":
      assertExactKeys(payload, ["kind"], field);
      break;
    case "fixed_reads":
      assertExactKeys(payload, ["kind", "extra_xors"], field);
      assertByteArray(payload.extra_xors, `${field}.extra_xors`);
      break;
    case "leb":
      assertExactKeys(payload, ["kind", "byte_xor"], field);
      assertByte(payload.byte_xor, `${field}.byte_xor`);
      break;
    case "string":
    case "bytes":
      assertExactKeys(payload, ["kind", "length_byte_xor", "char_xor"], field);
      assertByte(payload.length_byte_xor, `${field}.length_byte_xor`);
      assertByte(payload.char_xor, `${field}.char_xor`);
      break;
    case "regexp":
      assertExactKeys(
        payload,
        ["kind", "pattern_length_byte_xor", "pattern_char_xor", "flags_length_xor", "flags_char_xor"],
        field,
      );
      assertByte(payload.pattern_length_byte_xor, `${field}.pattern_length_byte_xor`);
      assertByte(payload.pattern_char_xor, `${field}.pattern_char_xor`);
      assertByte(payload.flags_length_xor, `${field}.flags_length_xor`);
      assertByte(payload.flags_char_xor, `${field}.flags_char_xor`);
      break;
    default:
      throw new Error(`${field}.kind ${payload.kind} is unsupported`);
  }
}

function validateSpec(spec, field) {
  assert(spec && typeof spec === "object" && SPEC_KINDS.has(spec.kind), `${field}.kind is unsupported`);
  switch (spec.kind) {
    case "fixed_reads":
      assertExactKeys(spec, ["kind", "extra_xors"], field);
      assertByteArray(spec.extra_xors, `${field}.extra_xors`);
      break;
    case "leb":
      assertExactKeys(spec, ["kind", "byte_xor"], field);
      assertByte(spec.byte_xor, `${field}.byte_xor`);
      break;
    case "leb_table":
      assertExactKeys(spec, ["kind", "count_byte_xor", "index_byte_xor", "max_count"], field);
      assertByte(spec.count_byte_xor, `${field}.count_byte_xor`);
      assertByte(spec.index_byte_xor, `${field}.index_byte_xor`);
      assert(
        Number.isInteger(spec.max_count) && spec.max_count > 0 && spec.max_count <= MAX_TABLE_COUNT,
        `${field}.max_count is out of bounds`,
      );
      break;
    case "tagged_load": {
      assertExactKeys(spec, ["kind", "operand_order", "tag_xor", "dst_xor", "tags"], field);
      assert(["tag_then_dst", "dst_then_tag"].includes(spec.operand_order), `${field}.operand_order is invalid`);
      assertByte(spec.tag_xor, `${field}.tag_xor`);
      assertByte(spec.dst_xor, `${field}.dst_xor`);
      assert(Array.isArray(spec.tags) && spec.tags.length > 0, `${field}.tags must be non-empty`);
      const tags = spec.tags.map((tag, index) => {
        assertExactKeys(tag, ["tag", "payload"], `${field}.tags[${index}]`);
        assertByte(tag.tag, `${field}.tags[${index}].tag`);
        validatePayload(tag.payload, `${field}.tags[${index}].payload`);
        return tag.tag;
      });
      assert(tags.every((tag, index) => index === 0 || tags[index - 1] < tag), `${field}.tags must be sorted/unique`);
      break;
    }
    case "string_load":
      assertExactKeys(spec, ["kind", "prefix_xors", "length_byte_xor", "char_xor"], field);
      assertByteArray(spec.prefix_xors, `${field}.prefix_xors`);
      assertByte(spec.length_byte_xor, `${field}.length_byte_xor`);
      assertByte(spec.char_xor, `${field}.char_xor`);
      break;
    case "jump_stop":
    case "unknown":
      assertExactKeys(spec, ["kind", "reason"], field);
      assert(typeof spec.reason === "string" && spec.reason.length > 0 && spec.reason.length <= 512, `${field}.reason is invalid`);
      break;
  }
}

export function validateProfile(profile, { requireFingerprint = true } = {}) {
  assert(profile && typeof profile === "object", "profile must be an object");
  assertExactKeys(
    profile,
    ["schemaVersion", "sourceSha256", "semanticFingerprint", "fetch", "switchOpcodes", "handlers"],
    "profile",
  );
  assert(profile.schemaVersion === VM_SKIP_PROFILE_SCHEMA_VERSION, "unsupported schemaVersion");
  assert(HEX_256.test(profile.sourceSha256), "sourceSha256 must be lowercase SHA-256");
  assertExactKeys(
    profile.fetch,
    ["initPc", "initKey", "byteBias", "keyMul", "keyAdd", "keyQuadB"],
    "profile.fetch",
  );
  assert(Number.isInteger(profile.fetch.initPc) && profile.fetch.initPc >= 0, "fetch.initPc is invalid");
  assertByte(profile.fetch.initKey, "fetch.initKey");
  assertByte(profile.fetch.byteBias, "fetch.byteBias");
  for (const key of ["keyMul", "keyAdd", "keyQuadB"]) {
    assert(Number.isInteger(profile.fetch[key]) && profile.fetch[key] >= 0, `fetch.${key} is invalid`);
  }
  assert(Array.isArray(profile.switchOpcodes) && profile.switchOpcodes.length > 0, "switchOpcodes must be non-empty");
  profile.switchOpcodes.forEach((opcode, index) => assertByte(opcode, `switchOpcodes[${index}]`));
  assert(
    profile.switchOpcodes.every((opcode, index) => index === 0 || profile.switchOpcodes[index - 1] < opcode),
    "switchOpcodes must be sorted/unique",
  );
  assert(Array.isArray(profile.handlers), "handlers must be an array");
  assert(profile.handlers.length === profile.switchOpcodes.length, "handlers must cover every switch opcode");
  profile.handlers.forEach((handler, index) => {
    assertExactKeys(handler, ["opcode", "handlerLabel", "handlerFingerprint", "spec"], `handlers[${index}]`);
    assert(handler.opcode === profile.switchOpcodes[index], "handlers must be opcode-sorted and complete");
    assert(typeof handler.handlerLabel === "string" && handler.handlerLabel.length > 0, "handlerLabel is invalid");
    assert(HEX_256.test(handler.handlerFingerprint), "handlerFingerprint must be lowercase SHA-256");
    validateSpec(handler.spec, `handlers[${index}].spec`);
  });
  if (requireFingerprint) {
    assert(HEX_256.test(profile.semanticFingerprint), "semanticFingerprint must be lowercase SHA-256");
    assert(profile.semanticFingerprint === semanticFingerprint(profile), "semanticFingerprint mismatch");
  }
  return profile;
}

export function finalizeProfile(profile) {
  profile.semanticFingerprint = semanticFingerprint(profile);
  return validateProfile(profile);
}
