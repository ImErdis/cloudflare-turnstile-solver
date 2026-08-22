//! Second `/fo/` POST **plaintext field set** (the JSON `f4` compresses).
//!
//! Live iframe: `runProgram(packed, E)` return, if a function, is invoked
//! as `fn(initObj, fj)` on the 56907 HTML (`fz` is a debug logger). That path
//! mutates the init object in place, then `fj` POSTs again (same `N` / URL /
//! `cf-chl-ra: 0`). The visible custom-b64 encoder on that path is `f3`.
//!
//! Key **names** (not values) come from headed Chrome Debugger on `f4`/`wZ` or
//! the `setTimeout(send, 100, url, obj)` helper (`scripts/chrome_oracle.mjs`).
//! A `JSON.stringify` hook is backup; `CSSStyleDeclaration` dumps (1000+ keys,
//! `alignContent`, numeric `0..n`) are rejected.
//!
//! Headed Chrome (SolveGate invisible, branch `b`, 2026-08-21) saw an early
//! `f4` of init + one extra ident (`xBCsP4`, no numeric slots) and a later
//! `f4` of the mutated object: 46 of 47 init keys (`MaOkK2` dropped), 14 extra
//! ident names, and numeric `"1"`..`"39"`. The oracle picker prefers the numeric
//! shape. `rpReturn` extra `AmbKQ5` is an intermediate, not this snapshot.
//! JSON.stringify would omit extra keys whose live kinds were `function` or
//! `undefined`; Object.keys still listed them.
//!
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

/// Remaining live gap after the follow-up **field-set names** are snapshotted.
/// Do not run handlers as a solver.
pub const NEXT_AFTER_FOLLOWUP_JSON: &str = "handler_semantics";

/// Historical crate inserted VM entries under `"1".."N"` (1-based).
pub const NUMERIC_KEYS_ARE_ONE_BASED: bool = true;

/// Init ident keys still present on the later `f4` follow-up object (branch `b`).
pub const FOLLOWUP_COPIED_COUNT_B: usize = 46;

/// Init ident dropped before the numeric follow-up `f4` (branch `b`).
pub const FOLLOWUP_DROPPED_INIT_B: &[&str] = &["MaOkK2"];

/// Extra ident **names** on the later `f4` follow-up object (branch `b`).
/// Same-day iframe build as [`crate::solver::fo_init_json::INIT_JSON_KEYS_B`].
pub const FOLLOWUP_EXTRA_IDENT_B: &[&str] = &[
    "SMrTl9", "OQbM0", "xBCsP4", "UjLjP6", "YfDjo7", "Iqrc9", "OZgbm6", "pFyv1", "SfUI1",
    "sqKXG6", "HUDi4", "DTBF3", "mQiic7", "gNcr3",
];

/// Extra ident whose live kinds were `function` or `undefined` (JSON.stringify omits).
pub const FOLLOWUP_EXTRA_IDENT_OMITTED_BY_JSON_B: &[&str] =
    &["OQbM0", "UjLjP6", "YfDjo7", "Iqrc9", "OZgbm6"];

/// Last numeric `f4` snapshot (`"1"`..`"39"`). An earlier `f4` stopped at 38.
pub const FOLLOWUP_NUMERIC_KEY_MIN_B: u32 = 1;
pub const FOLLOWUP_NUMERIC_KEY_MAX_B: u32 = 39;

/// Quoted `"1":` / `'1':` style keys are **not** in the 56907 iframe HTML.
/// Numeric follow-up slots come from runtime writes, not an object literal.
pub const FOLLOWUP_NUMERIC_KEYS_IN_HTML: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExtraIdentHtmlSource {
    pub name: &'static str,
    /// `chl_opt` / `other_object` / `string_table` / `absent`.
    pub html: &'static str,
    pub note: &'static str,
}

/// Where each extra ident string appears in the 56907 iframe HTML (not values).
/// `_cf_chl_opt` keys are not the init JSON literal. Absent names are runtime.
pub const FOLLOWUP_EXTRA_IDENT_HTML_B: &[ExtraIdentHtmlSource] = &[
    ExtraIdentHtmlSource { name: "SMrTl9", html: "chl_opt", note: "_cf_chl_opt ray (16-hex); also string table" },
    ExtraIdentHtmlSource { name: "OQbM0", html: "absent", note: "not in 56907 iframe HTML" },
    ExtraIdentHtmlSource { name: "xBCsP4", html: "chl_opt", note: "_cf_chl_opt: []; also string table" },
    ExtraIdentHtmlSource { name: "UjLjP6", html: "absent", note: "not in 56907 iframe HTML" },
    ExtraIdentHtmlSource { name: "YfDjo7", html: "absent", note: "not in 56907 iframe HTML" },
    ExtraIdentHtmlSource { name: "Iqrc9", html: "absent", note: "not in 56907 iframe HTML" },
    ExtraIdentHtmlSource { name: "OZgbm6", html: "absent", note: "not in 56907 iframe HTML" },
    ExtraIdentHtmlSource { name: "pFyv1", html: "absent", note: "not in 56907 iframe HTML" },
    ExtraIdentHtmlSource { name: "SfUI1", html: "absent", note: "not in 56907 iframe HTML" },
    ExtraIdentHtmlSource { name: "sqKXG6", html: "other_object", note: "worker-like object literal, not init JSON" },
    ExtraIdentHtmlSource { name: "HUDi4", html: "absent", note: "not in 56907 iframe HTML" },
    ExtraIdentHtmlSource { name: "DTBF3", html: "absent", note: "not in 56907 iframe HTML" },
    ExtraIdentHtmlSource { name: "mQiic7", html: "string_table", note: "string-table token only" },
    ExtraIdentHtmlSource { name: "gNcr3", html: "absent", note: "not in 56907 iframe HTML" },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FollowUpFieldWrite {
    pub name: &'static str,
    /// `chl_opt` / `other_object` / `string_table` / `absent` / `init_obj` / `numeric_family`.
    pub source: &'static str,
    /// `host_copy` / `bytecode_string` / `glue` / `host_xi` / `vm_entry_index` / `unseen_in_dumps`.
    pub write_path: &'static str,
    pub opcode: Option<u8>,
    pub evidence: &'static str,
}

const fn w(
    name: &'static str,
    source: &'static str,
    write_path: &'static str,
    opcode: Option<u8>,
    evidence: &'static str,
) -> FollowUpFieldWrite {
    FollowUpFieldWrite {
        name,
        source,
        write_path,
        opcode,
        evidence,
    }
}

/// How each follow-up field is written (56907 dumps). Names were already known.
/// The 822k live `/fo/` packed body was not saved; skip-harvest of the HTML-embedded
/// 5k `runProgram(\`71GxwDch…\`)` stub does not contain the 14 extra ident names.
/// Do not fill values or POST.
pub const FOLLOWUP_FIELD_WRITE_B: &[FollowUpFieldWrite] = &[
    w("SMrTl9", "chl_opt", "host_copy", None,
        "_cf_chl_opt SMrTl9 is the 16-hex ray; follow-up kind string. Not on the init JSON literal. Assignment onto initObj is not in HTML."),
    w("OQbM0", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind undefined (stringify omits)"),
    w("xBCsP4", "chl_opt", "host_copy", None,
        "_cf_chl_opt xBCsP4: []; follow-up kind array. Early f4 is init plus this key (no numeric slots) before the later mutated f4."),
    w("UjLjP6", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind function (stringify omits)"),
    w("YfDjo7", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind undefined"),
    w("Iqrc9", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind undefined"),
    w("OZgbm6", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind function (stringify omits)"),
    w("pFyv1", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind number"),
    w("SfUI1", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind array"),
    w("sqKXG6", "other_object", "unseen_in_dumps", None,
        "HTML has Xu={\"sqKXG6\":W?W:undefined,...} on an /eb/ error beacon (stack file string), not the /fo/ init literal. Follow-up kind string. Copy onto initObj not in HTML; stub harvest miss."),
    w("HUDi4", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind string"),
    w("DTBF3", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind string"),
    w("mQiic7", "string_table", "unseen_in_dumps", None,
        "semicolon string-table token only; follow-up kind number. Stub harvest miss."),
    w("gNcr3", "absent", "unseen_in_dumps", None,
        "not in 56907 HTML or the HTML-embedded packed stub; Chrome kind number"),
    w("MaOkK2", "init_obj", "glue", None,
        "on the init object literal (\"MaOkK2\": host call). Absent from later f4 identKeys. delete/drop not in HTML."),
    w("1..39", "numeric_family", "vm_entry_index", None,
        "consecutive 1-based keys, count 39, no quoted \"1\": in HTML. Same kind as orchestrate-era parsed_vm.entries under \"1\"..\"N\". ge/169 can write an integer key imm; the HTML-embedded stub harvested none in 1..=39. Kinds for numeric slots were not saved."),
];

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
    pub copied_count: usize,
    pub extra_ident_count: usize,
    pub numeric_key_min: u32,
    pub numeric_key_max: u32,
    pub note: &'static str,
}

pub const LIVE_FO_FOLLOWUP_JSON: FoFollowUpJsonShape = FoFollowUpJsonShape {
    copied_from_init: true,
    numeric_vm_entries: true,
    extra_ident_from_vm: true,
    init_ident_count: INIT_JSON_KEY_COUNT,
    copied_count: FOLLOWUP_COPIED_COUNT_B,
    extra_ident_count: FOLLOWUP_EXTRA_IDENT_B.len(),
    numeric_key_min: FOLLOWUP_NUMERIC_KEY_MIN_B,
    numeric_key_max: FOLLOWUP_NUMERIC_KEY_MAX_B,
    note: "follow-up is 46 of 47 init keys (MaOkK2 dropped) plus numeric 1..39 plus 14 extra ident names. Names only — do not fill or POST.",
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

pub fn dropped_init_keys<'a>(ident: &[String], init: &'a [&str]) -> Vec<&'a str> {
    init.iter()
        .copied()
        .filter(|i| !ident.iter().any(|k| k == i))
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
    use std::collections::BTreeSet;

    #[test]
    fn shape_says_copied_plus_numeric_plus_extra() {
        assert_eq!(LIVE_FO_FOLLOWUP_JSON.init_ident_count, INIT_JSON_KEY_COUNT);
        assert_eq!(LIVE_FO_FOLLOWUP_JSON.copied_count, FOLLOWUP_COPIED_COUNT_B);
        assert_eq!(LIVE_FO_FOLLOWUP_JSON.extra_ident_count, 14);
        assert_eq!(NEXT_AFTER_FOLLOWUP_JSON, "handler_semantics");
        let s = serde_json::to_value(LIVE_FO_FOLLOWUP_JSON).unwrap();
        assert_eq!(s["copied_from_init"], true);
        assert_eq!(s["numeric_vm_entries"], true);
        assert_eq!(s["extra_ident_from_vm"], true);
        assert_eq!(s["numeric_key_max"], 39);
    }

    #[test]
    fn branch_b_extra_ident_is_not_init_or_numeric() {
        assert_eq!(FOLLOWUP_EXTRA_IDENT_B.len(), 14);
        assert_eq!(FOLLOWUP_DROPPED_INIT_B, &["MaOkK2"]);
        assert_eq!(
            FOLLOWUP_COPIED_COUNT_B,
            INIT_JSON_KEY_COUNT - FOLLOWUP_DROPPED_INIT_B.len()
        );
        let init: BTreeSet<_> = INIT_JSON_KEYS_B.iter().copied().collect();
        for k in FOLLOWUP_EXTRA_IDENT_B {
            assert!(!init.contains(k), "extra ident {k} is an init key");
            assert!(!looks_like_numeric_key(k), "extra ident {k} looks numeric");
        }
        for k in FOLLOWUP_DROPPED_INIT_B {
            assert!(init.contains(k), "dropped {k} is not an init key");
        }
        let omitted: BTreeSet<_> = FOLLOWUP_EXTRA_IDENT_OMITTED_BY_JSON_B.iter().copied().collect();
        for k in FOLLOWUP_EXTRA_IDENT_OMITTED_BY_JSON_B {
            assert!(
                FOLLOWUP_EXTRA_IDENT_B.contains(k),
                "json-omitted {k} missing from extra ident"
            );
        }
        assert_eq!(omitted.len(), FOLLOWUP_EXTRA_IDENT_OMITTED_BY_JSON_B.len());
        assert_eq!(FOLLOWUP_NUMERIC_KEY_MIN_B, 1);
        assert_eq!(FOLLOWUP_NUMERIC_KEY_MAX_B, 39);
        assert_eq!(FOLLOWUP_EXTRA_IDENT_HTML_B.len(), FOLLOWUP_EXTRA_IDENT_B.len());
        for (src, name) in FOLLOWUP_EXTRA_IDENT_HTML_B.iter().zip(FOLLOWUP_EXTRA_IDENT_B) {
            assert_eq!(src.name, *name);
        }
        assert_eq!(FOLLOWUP_FIELD_WRITE_B.len(), FOLLOWUP_EXTRA_IDENT_B.len() + 2);
        for (row, name) in FOLLOWUP_FIELD_WRITE_B.iter().zip(FOLLOWUP_EXTRA_IDENT_B) {
            assert_eq!(row.name, *name);
            assert_eq!(row.opcode, None);
        }
        assert_eq!(FOLLOWUP_FIELD_WRITE_B[0].write_path, "host_copy");
        assert_eq!(FOLLOWUP_FIELD_WRITE_B[2].write_path, "host_copy");
        assert_eq!(FOLLOWUP_FIELD_WRITE_B[2].name, "xBCsP4");
        assert_eq!(FOLLOWUP_FIELD_WRITE_B[9].name, "sqKXG6");
        assert_eq!(FOLLOWUP_FIELD_WRITE_B[9].source, "other_object");
        assert_eq!(FOLLOWUP_FIELD_WRITE_B[9].write_path, "unseen_in_dumps");
        let dropped = FOLLOWUP_FIELD_WRITE_B.iter().find(|r| r.name == "MaOkK2").unwrap();
        assert_eq!(dropped.write_path, "glue");
        assert_eq!(dropped.source, "init_obj");
        let numeric = FOLLOWUP_FIELD_WRITE_B.iter().find(|r| r.name == "1..39").unwrap();
        assert_eq!(numeric.write_path, "vm_entry_index");
        assert_eq!(NEXT_AFTER_FOLLOWUP_JSON, "handler_semantics");
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if path.is_file() {
            let html = std::fs::read_to_string(path).unwrap();
            assert!(html.contains("SMrTl9: '"));
            assert!(html.contains("xBCsP4: []"));
            assert!(html.contains("\"sqKXG6\":"));
            assert!(html.contains(";mQiic7;"));
            for src in FOLLOWUP_EXTRA_IDENT_HTML_B {
                if src.html == "absent" {
                    assert!(
                        !html.contains(src.name),
                        "extra ident {} should be absent from HTML",
                        src.name
                    );
                } else {
                    assert!(html.contains(src.name), "extra ident {} missing from HTML", src.name);
                }
            }
            assert!(!html.contains("\"1\":"));
            assert!(!html.contains("'1':"));
            assert!(html.contains("SMrTl9: '"));
            assert!(html.contains("xBCsP4: []"));
            assert!(html.contains("\"sqKXG6\":"));
            assert!(html.contains("\"MaOkK2\":"));
            assert!(html.contains("XK=A[rH(JY.aj)](runProgram,XS,E)"));
            assert!(html.contains("A[rH(JY.aH)](XK,n,fj)"));
        }
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
            assert_eq!(n, FOLLOWUP_COPIED_COUNT_B as u64);
        }
        if let Some(keys) = row["extraIdent"].as_array() {
            let got: Vec<&str> = keys.iter().filter_map(|k| k.as_str()).collect();
            assert_eq!(got, FOLLOWUP_EXTRA_IDENT_B);
            for s in &got {
                assert!(!INIT_JSON_KEYS_B.contains(s), "extra ident {s} is an init key");
                assert!(!looks_like_numeric_key(s), "extra ident {s} looks numeric");
            }
        }
        if let Some(dropped) = row["droppedInit"].as_array() {
            let got: Vec<&str> = dropped.iter().filter_map(|k| k.as_str()).collect();
            assert_eq!(got, FOLLOWUP_DROPPED_INIT_B);
        }
        if let Some(n) = row["numericKeyCount"].as_u64() {
            assert_eq!(n, FOLLOWUP_NUMERIC_KEY_MAX_B as u64);
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
                assert_eq!(
                    copied_init_keys(&names, INIT_JSON_KEYS_B).len(),
                    FOLLOWUP_COPIED_COUNT_B
                );
                assert_eq!(
                    dropped_init_keys(&names, INIT_JSON_KEYS_B),
                    FOLLOWUP_DROPPED_INIT_B.to_vec()
                );
                assert_eq!(
                    extra_ident_keys(&names, INIT_JSON_KEYS_B),
                    FOLLOWUP_EXTRA_IDENT_B.to_vec()
                );
            }
        }
    }
}
