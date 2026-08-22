import { createHash } from "node:crypto";

export function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError(`cannot canonicalize ${typeof value}`);
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function semanticPayload(profile) {
  return {
    schemaVersion: profile.schemaVersion,
    fetch: profile.fetch,
    switchOpcodes: profile.switchOpcodes,
    handlers: profile.handlers.map(({ opcode, handlerFingerprint, spec }) => ({
      opcode,
      handlerFingerprint,
      spec,
    })),
  };
}

export function semanticFingerprint(profile) {
  return sha256Hex(canonicalJson(semanticPayload(profile)));
}
