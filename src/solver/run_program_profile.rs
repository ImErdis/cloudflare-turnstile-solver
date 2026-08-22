//! Schema and validation for statically extracted `runProgram` skip profiles.
//!
//! A profile is bound to both the captured executed-JS SHA-256 and the exact
//! fetch parameters supplied by the caller.  It is never selected from the
//! multiplier/addend alone.  Profiles describe encoded operand reads only;
//! they cannot ask the skipper to execute handlers or follow control flow.

use crate::solver::run_program_vm::FetchParams;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

pub const VM_SKIP_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const VM_PROFILE_MAX_FIXED_READS: usize = 256;
pub const VM_PROFILE_MAX_TABLE_COUNT: u32 = 1_048_576;
pub const VM_PROFILE_MAX_REASON_LEN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmSkipProfile {
    pub schema_version: u32,
    pub source_sha256: String,
    pub semantic_fingerprint: String,
    pub fetch: VmProfileFetch,
    pub switch_opcodes: Vec<u8>,
    pub handlers: Vec<VmHandlerProfile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmProfileFetch {
    pub init_pc: u32,
    pub init_key: u8,
    pub byte_bias: u8,
    pub key_mul: u32,
    pub key_add: u32,
    pub key_quad_b: u32,
}

impl VmProfileFetch {
    pub const fn from_params(params: FetchParams) -> Self {
        Self {
            init_pc: params.init_pc,
            init_key: params.init_key,
            byte_bias: params.byte_bias,
            key_mul: params.key_mul,
            key_add: params.key_add,
            key_quad_b: params.key_quad_b,
        }
    }

    pub const fn matches(self, params: FetchParams) -> bool {
        self.init_pc == params.init_pc
            && self.init_key == params.init_key
            && self.byte_bias == params.byte_bias
            && self.key_mul == params.key_mul
            && self.key_add == params.key_add
            && self.key_quad_b == params.key_quad_b
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmHandlerProfile {
    pub opcode: u8,
    /// Current-capture name for diagnostics only.  Excluded from semantic identity.
    pub handler_label: String,
    /// Normalized structural hash emitted by the static analyzer.
    pub handler_fingerprint: String,
    pub spec: VmSkipSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VmSkipSpec {
    FixedReads {
        extra_xors: Vec<u8>,
    },
    Leb {
        byte_xor: u8,
    },
    LebTable {
        count_byte_xor: u8,
        index_byte_xor: u8,
        max_count: u32,
    },
    TaggedLoad {
        operand_order: VmTaggedOperandOrder,
        tag_xor: u8,
        dst_xor: u8,
        tags: Vec<VmTagProfile>,
    },
    StringLoad {
        prefix_xors: Vec<u8>,
        length_byte_xor: u8,
        char_xor: u8,
    },
    JumpStop {
        reason: String,
    },
    Unknown {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmTaggedOperandOrder {
    TagThenDst,
    DstThenTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmTagProfile {
    pub tag: u8,
    pub payload: VmTagPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VmTagPayload {
    None,
    FixedReads {
        extra_xors: Vec<u8>,
    },
    Leb {
        byte_xor: u8,
    },
    String {
        length_byte_xor: u8,
        char_xor: u8,
    },
    Bytes {
        length_byte_xor: u8,
        char_xor: u8,
    },
    Regexp {
        pattern_length_byte_xor: u8,
        pattern_char_xor: u8,
        flags_length_xor: u8,
        flags_char_xor: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmProfileValidationError {
    pub reason: String,
}

impl VmProfileValidationError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl Display for VmProfileValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for VmProfileValidationError {}

impl VmSkipProfile {
    pub fn from_json_str(raw: &str) -> Result<Self, VmProfileValidationError> {
        serde_json::from_str(raw)
            .map_err(|e| VmProfileValidationError::new(format!("invalid profile JSON: {e}")))
    }

    /// Validate a profile against the exact current script hash and fetch state.
    pub fn validate_for(
        &self,
        params: FetchParams,
        observed_source_sha256: &str,
    ) -> Result<(), VmProfileValidationError> {
        if self.schema_version != VM_SKIP_PROFILE_SCHEMA_VERSION {
            return Err(VmProfileValidationError::new(format!(
                "schema version {} != {}",
                self.schema_version, VM_SKIP_PROFILE_SCHEMA_VERSION
            )));
        }
        validate_sha256("sourceSha256", &self.source_sha256)?;
        validate_sha256("observed source SHA-256", observed_source_sha256)?;
        if self.source_sha256 != observed_source_sha256 {
            return Err(VmProfileValidationError::new(
                "captured source SHA-256 does not match profile",
            ));
        }
        if !self.fetch.matches(params) {
            return Err(VmProfileValidationError::new(
                "fetch parameters do not match profile",
            ));
        }
        validate_strictly_sorted_unique("switch opcodes", &self.switch_opcodes)?;
        if self.switch_opcodes.is_empty() {
            return Err(VmProfileValidationError::new("switch opcode set is empty"));
        }
        if self.handlers.len() != self.switch_opcodes.len() {
            return Err(VmProfileValidationError::new(format!(
                "handler count {} != switch opcode count {}",
                self.handlers.len(),
                self.switch_opcodes.len()
            )));
        }
        let mut last_opcode = None;
        for handler in &self.handlers {
            if let Some(last) = last_opcode
                && handler.opcode <= last
            {
                return Err(VmProfileValidationError::new(
                    "handlers must be strictly opcode-sorted and unique",
                ));
            }
            last_opcode = Some(handler.opcode);
            if self.switch_opcodes.binary_search(&handler.opcode).is_err() {
                return Err(VmProfileValidationError::new(format!(
                    "handler opcode {} is absent from switch",
                    handler.opcode
                )));
            }
            if handler.handler_label.is_empty() || handler.handler_label.len() > 256 {
                return Err(VmProfileValidationError::new(format!(
                    "opcode {} has invalid diagnostic handler label",
                    handler.opcode
                )));
            }
            validate_sha256("handler fingerprint", &handler.handler_fingerprint)?;
            validate_spec(handler.opcode, &handler.spec)?;
        }
        validate_sha256("semanticFingerprint", &self.semantic_fingerprint)?;
        let computed = self.computed_semantic_fingerprint()?;
        if computed != self.semantic_fingerprint {
            return Err(VmProfileValidationError::new(format!(
                "semantic fingerprint mismatch: profile {}, computed {computed}",
                self.semantic_fingerprint
            )));
        }
        Ok(())
    }

    pub fn handler(&self, opcode: u8) -> Option<&VmHandlerProfile> {
        self.handlers
            .binary_search_by_key(&opcode, |h| h.opcode)
            .ok()
            .map(|i| &self.handlers[i])
    }

    pub fn computed_semantic_fingerprint(&self) -> Result<String, VmProfileValidationError> {
        let handlers: Vec<Value> = self
            .handlers
            .iter()
            .map(|handler| {
                json!({
                    "opcode": handler.opcode,
                    "handlerFingerprint": handler.handler_fingerprint,
                    "spec": handler.spec,
                })
            })
            .collect();
        let value = json!({
            "schemaVersion": self.schema_version,
            "fetch": self.fetch,
            "switchOpcodes": self.switch_opcodes,
            "handlers": handlers,
        });
        let canonical = canonical_json(&value)?;
        Ok(sha256_hex(canonical.as_bytes()))
    }
}

pub fn source_sha256_hex(source: &[u8]) -> String {
    sha256_hex(source)
}

pub fn canonical_json(value: &Value) -> Result<String, VmProfileValidationError> {
    fn write(value: &Value, out: &mut String) -> Result<(), VmProfileValidationError> {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Value::Number(v) => out.push_str(&v.to_string()),
            Value::String(v) => out.push_str(
                &serde_json::to_string(v)
                    .map_err(|e| VmProfileValidationError::new(e.to_string()))?,
            ),
            Value::Array(values) => {
                out.push('[');
                for (i, value) in values.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    write(value, out)?;
                }
                out.push(']');
            }
            Value::Object(values) => {
                out.push('{');
                let mut sorted = Map::new();
                let mut keys: Vec<&String> = values.keys().collect();
                keys.sort();
                for key in keys {
                    sorted.insert(key.clone(), values[key].clone());
                }
                for (i, (key, value)) in sorted.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    out.push_str(
                        &serde_json::to_string(key)
                            .map_err(|e| VmProfileValidationError::new(e.to_string()))?,
                    );
                    out.push(':');
                    write(value, out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }

    let mut out = String::new();
    write(value, &mut out)?;
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn validate_sha256(field: &str, value: &str) -> Result<(), VmProfileValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(VmProfileValidationError::new(format!(
            "{field} must be 64 lowercase hex characters"
        )));
    }
    Ok(())
}

fn validate_strictly_sorted_unique(
    field: &str,
    values: &[u8],
) -> Result<(), VmProfileValidationError> {
    if values.windows(2).any(|w| w[0] >= w[1]) {
        return Err(VmProfileValidationError::new(format!(
            "{field} must be strictly sorted and unique"
        )));
    }
    Ok(())
}

fn validate_spec(opcode: u8, spec: &VmSkipSpec) -> Result<(), VmProfileValidationError> {
    match spec {
        VmSkipSpec::FixedReads { extra_xors } => validate_reads(opcode, extra_xors),
        VmSkipSpec::Leb { .. } => Ok(()),
        VmSkipSpec::LebTable { max_count, .. } => {
            if *max_count == 0 || *max_count > VM_PROFILE_MAX_TABLE_COUNT {
                return Err(VmProfileValidationError::new(format!(
                    "opcode {opcode} LEB table max_count {max_count} is out of bounds"
                )));
            }
            Ok(())
        }
        VmSkipSpec::TaggedLoad { tags, .. } => {
            if tags.is_empty() {
                return Err(VmProfileValidationError::new(format!(
                    "opcode {opcode} tagged load has no tags"
                )));
            }
            let mut seen = BTreeSet::new();
            for tag in tags {
                if !seen.insert(tag.tag) {
                    return Err(VmProfileValidationError::new(format!(
                        "opcode {opcode} has duplicate tag {}",
                        tag.tag
                    )));
                }
                if let VmTagPayload::FixedReads { extra_xors } = &tag.payload {
                    validate_reads(opcode, extra_xors)?;
                }
            }
            Ok(())
        }
        VmSkipSpec::StringLoad { prefix_xors, .. } => validate_reads(opcode, prefix_xors),
        VmSkipSpec::JumpStop { reason } | VmSkipSpec::Unknown { reason } => {
            validate_reason(opcode, reason)
        }
    }
}

fn validate_reads(opcode: u8, reads: &[u8]) -> Result<(), VmProfileValidationError> {
    if reads.len() > VM_PROFILE_MAX_FIXED_READS {
        return Err(VmProfileValidationError::new(format!(
            "opcode {opcode} has too many fixed reads: {}",
            reads.len()
        )));
    }
    Ok(())
}

fn validate_reason(opcode: u8, reason: &str) -> Result<(), VmProfileValidationError> {
    if reason.is_empty() || reason.len() > VM_PROFILE_MAX_REASON_LEN {
        return Err(VmProfileValidationError::new(format!(
            "opcode {opcode} has an invalid reason"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::run_program_vm::FETCH_HTML_40954_UNVERIFIED;

    fn unknown_profile() -> VmSkipProfile {
        let source = source_sha256_hex(b"synthetic executed JS");
        let handler_fingerprint = source_sha256_hex(b"normalized handler");
        let mut profile = VmSkipProfile {
            schema_version: VM_SKIP_PROFILE_SCHEMA_VERSION,
            source_sha256: source,
            semantic_fingerprint: "0".repeat(64),
            fetch: VmProfileFetch::from_params(FETCH_HTML_40954_UNVERIFIED),
            switch_opcodes: vec![181],
            handlers: vec![VmHandlerProfile {
                opcode: 181,
                handler_label: "rotating_name".into(),
                handler_fingerprint,
                spec: VmSkipSpec::Unknown {
                    reason: "recognizer not implemented".into(),
                },
            }],
        };
        profile.semantic_fingerprint = profile.computed_semantic_fingerprint().unwrap();
        profile
    }

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        let value = json!({"z": 1, "a": {"y": 2, "b": [3, {"q": 4, "c": 5}]}});
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":{"b":[3,{"c":5,"q":4}],"y":2},"z":1}"#
        );
    }

    #[test]
    fn profile_binds_source_fetch_and_semantics() {
        let profile = unknown_profile();
        assert!(
            profile
                .validate_for(FETCH_HTML_40954_UNVERIFIED, &profile.source_sha256)
                .is_ok()
        );

        let mut wrong_source = profile.clone();
        wrong_source.source_sha256 = source_sha256_hex(b"rotated source");
        assert!(
            wrong_source
                .validate_for(FETCH_HTML_40954_UNVERIFIED, &profile.source_sha256)
                .unwrap_err()
                .reason
                .contains("captured source")
        );

        let mut wrong_fetch = FETCH_HTML_40954_UNVERIFIED;
        wrong_fetch.init_key ^= 1;
        assert!(
            profile
                .validate_for(wrong_fetch, &profile.source_sha256)
                .unwrap_err()
                .reason
                .contains("fetch parameters")
        );

        let mut wrong_semantics = profile.clone();
        wrong_semantics.handlers[0].spec = VmSkipSpec::JumpStop {
            reason: "semantic mutation".into(),
        };
        assert!(
            wrong_semantics
                .validate_for(FETCH_HTML_40954_UNVERIFIED, &wrong_semantics.source_sha256)
                .unwrap_err()
                .reason
                .contains("semantic fingerprint")
        );
    }

    #[test]
    fn profile_requires_complete_sorted_dispatch() {
        let mut profile = unknown_profile();
        profile.switch_opcodes = vec![181, 7];
        assert!(
            profile
                .validate_for(FETCH_HTML_40954_UNVERIFIED, &profile.source_sha256)
                .unwrap_err()
                .reason
                .contains("strictly sorted")
        );

        let mut profile = unknown_profile();
        profile.switch_opcodes.push(247);
        profile.semantic_fingerprint = profile.computed_semantic_fingerprint().unwrap();
        assert!(
            profile
                .validate_for(FETCH_HTML_40954_UNVERIFIED, &profile.source_sha256)
                .unwrap_err()
                .reason
                .contains("handler count")
        );
    }
}
