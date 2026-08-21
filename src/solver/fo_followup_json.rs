//! Second `/fo/` POST **plaintext field set** (the JSON `f4` compresses).
//!
//! Live iframe: `runProgram(packed, helper)` return, if a function, is invoked
//! as `fn(initObj, sendHelper)`. That path mutates the init object in place,
//! then the send helper does `send(f4(obj))` again (same `N` / URL / `cf-chl-ra: 0`).
//!
//! Key **names** (not values) come from headed Chrome Debugger on `f4`/`wZ` or
//! the `setTimeout(send, 100, url, obj)` helper (`scripts/chrome_oracle.mjs`).
//! A `JSON.stringify` hook is backup; `CSSStyleDeclaration` dumps (1000+ keys,
//! `alignContent`, numeric `0..n`) are rejected. Extra ident **names** still
//! need a successful iframe harvest.
//! Classification against [`INIT_JSON_KEYS_B`](crate::solver::fo_init_json::INIT_JSON_KEYS_B):
//!
//! * **copied** — ident keys that already appeared on the init object
//! * **computed numeric** — `"1".."N"` slots the VM writes (the orchestrate-era
//!   `TurnstileTask::build_second_payload` inserted `parsed_vm.entries` under
//!   those keys; live does the same *kind* of write, not that Rust path)
//! * **extra ident** — named keys the VM adds that were not in the init literal
//!
//! This module does **not** fill values, reconstruct `f4`/`wZ` as a live POST,
//! or execute handlers as a solver.

use crate::solver::fo_init_json::INIT_JSON_KEY_COUNT;
use serde::Serialize;

/// Remaining live gap after the follow-up **field-set kind** is mapped.
/// Extra ident **names** still need a headed Chrome `f4` harvest; until that
/// snapshot is filled, stay on this gap rather than claiming handler semantics.
pub const NEXT_AFTER_FOLLOWUP_JSON: &str = "fo_followup_json";

/// Historical crate inserted VM entries under `"1".."N"` (1-based).
pub const NUMERIC_KEYS_ARE_ONE_BASED: bool = true;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FoPlaintextKind {
    Init,
    FollowUp,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoFollowUpJsonShape {
    pub copied_from_init: bool,
    pub numeric_vm_entries: bool,
    pub extra_ident_from_vm: bool,
    pub init_ident_count: usize,
    pub note: &'static str,
}

pub const LIVE_FO_FOLLOWUP_JSON: FoFollowUpJsonShape = FoFollowUpJsonShape {
    copied_from_init: true,
    numeric_vm_entries: true,
    extra_ident_from_vm: true,
    init_ident_count: INIT_JSON_KEY_COUNT,
    note: "follow-up is the mutated init object plus numeric VM entries plus extra ident keys. Names only — do not fill or POST.",
};

pub fn looks_like_numeric_key(k: &str) -> bool {
    !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit())
}

pub fn copied_init_keys<'a>(ident: &'a [String], init: &[&str]) -> Vec<&'a str> {
    ident
        .iter()
        .filter(|k| init.iter().any(|i| i == k))
        .map(|k| k.as_str())
        .collect()
}

pub fn extra_ident_keys<'a>(ident: &'a [String], init: &[&str]) -> Vec<&'a str> {
    ident
        .iter()
        .filter(|k| !init.iter().any(|i| i == k))
        .map(|k| k.as_str())
        .collect()
}

pub fn classify_fo_plaintext(
    ident: &[String],
    numeric_count: usize,
    init: &[&str],
) -> FoPlaintextKind {
    let copied = copied_init_keys(ident, init).len();
    let extra = extra_ident_keys(ident, init).len();
    if numeric_count > 0 {
        FoPlaintextKind::FollowUp
    } else if copied >= 40 && extra == 0 {
        FoPlaintextKind::Init
    } else if copied >= 40 {
        FoPlaintextKind::FollowUp
    } else if ident.len() >= 40 && extra == 0 && init.is_empty() {
        FoPlaintextKind::Init
    } else {
        FoPlaintextKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::fo_init_json::INIT_JSON_KEYS_B;

    #[test]
    fn shape_says_copied_plus_numeric_plus_extra() {
        assert_eq!(LIVE_FO_FOLLOWUP_JSON.init_ident_count, INIT_JSON_KEY_COUNT);
        assert_eq!(NEXT_AFTER_FOLLOWUP_JSON, "fo_followup_json");
        let s = serde_json::to_value(LIVE_FO_FOLLOWUP_JSON).unwrap();
        assert_eq!(s["copied_from_init"], true);
        assert_eq!(s["numeric_vm_entries"], true);
        assert_eq!(s["extra_ident_from_vm"], true);
    }

    #[test]
    fn classify_init_vs_followup_against_branch_b() {
        let init: Vec<String> = INIT_JSON_KEYS_B.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(
            classify_fo_plaintext(&init, 0, INIT_JSON_KEYS_B),
            FoPlaintextKind::Init
        );
        let mut follow = init.clone();
        follow.push("extraVmKey".into());
        assert_eq!(
            classify_fo_plaintext(&follow, 12, INIT_JSON_KEYS_B),
            FoPlaintextKind::FollowUp
        );
        assert_eq!(copied_init_keys(&follow, INIT_JSON_KEYS_B).len(), 47);
        assert_eq!(extra_ident_keys(&follow, INIT_JSON_KEYS_B), vec!["extraVmKey"]);
        assert!(looks_like_numeric_key("1"));
        assert!(looks_like_numeric_key("12"));
        assert!(!looks_like_numeric_key("ThPv3"));
        assert!(!looks_like_numeric_key(""));
    }

    #[test]
    fn chrome_oracle_fixture_followup_json_if_harvested() {
        let path = std::path::Path::new("scripts/fixtures/headed_chrome_oracle.json");
        if !path.is_file() {
            return;
        }
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let row = v
            .pointer("/laterSameDay/foFollowUpJson")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if row.is_null() {
            return;
        }
        assert_eq!(row["copiedFromInit"], true);
        assert_eq!(row["numericVmEntries"], true);
        if let Some(n) = row["copiedCount"].as_u64() {
            assert_eq!(n, INIT_JSON_KEY_COUNT as u64);
        }
        if let Some(keys) = row["extraIdent"].as_array() {
            for k in keys {
                let s = k.as_str().unwrap_or("");
                assert!(!INIT_JSON_KEYS_B.contains(&s), "extra ident {s} is an init key");
                assert!(!looks_like_numeric_key(s), "extra ident {s} looks numeric");
            }
        }
        if let Some(ident) = row["identKeys"].as_array() {
            let names: Vec<String> = ident
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            let numeric = row["numericKeyCount"].as_u64().unwrap_or(0) as usize;
            if names.len() >= 40 {
                assert_eq!(
                    classify_fo_plaintext(&names, numeric, INIT_JSON_KEYS_B),
                    FoPlaintextKind::FollowUp
                );
            }
        }
    }
}
