//! First `/fo/` POST **plaintext shape** (the JSON `f4` compresses).
//!
//! Live iframe (branch `b`, 2026-08-21) builds an object literal, optionally
//! copies extraParams, then `setTimeout(sendFn, 100, url, obj)`. The XHR helper
//! overwrites **one** numeric field with `Date.now() - start` immediately before
//! `send(f4(obj))`.
//!
//! Key **names** rotate with the iframe JS build (not each page load). Same-day
//! `b` captures kept the same 47 keys even after fetch went quadratic (`56907`).
//! Branch `g` has a different 47-name set. Several identifiers are **shared**
//! with `window._cf_chl_opt` (parse those by value, as `CloudflareChallengeOptions`
//! already does).
//!
//! The orchestrate-era [`PayloadKeyExtractor`](crate::parser::payload::PayloadKeyExtractor)
//! looks for `setTimeout(fn, 100, …, { object literal })`. Live HTML assigns the
//! literal to a temp (`Xm` / `xL` / `Xt`) and passes the **identifier**, so that
//! visitor does not see the keys.
//!
//! Follow-up envelope after `runProgram` is [`crate::solver::fo_followup`].
//! This module does **not** fill values, serialize a live body, or POST.

use serde::Serialize;
use std::collections::BTreeSet;

/// Remaining after init-JSON **shape** (follow-up envelope is mapped separately).
pub const NEXT_AFTER_SHAPE: &str = crate::solver::fo_followup::NEXT_AFTER_FOLLOWUP_SHAPE;

pub const INIT_JSON_KEY_COUNT: usize = 47;
pub const SET_TIMEOUT_DELAY_MS: u32 = 100;
/// Orchestrate-era [`crate::solver::keys::InitPayloadKeys`] slot count.
pub const CRATE_ORCHESTRATE_SLOT_COUNT: usize = 40;

/// Branch-`b` init keys (SolveGate invisible, 2026-08-21; stable across that day's `b` iframes).
pub const INIT_JSON_KEYS_B: &[&str] = &[
    "ThPv3", "zlGF5", "OpPY6", "IlxW5", "XxyI8", "HmVl5", "Hvdx8", "SpRN6", "uHTPv5", "xOSD5",
    "Eugge3", "MaOkK2", "sYTa8", "ANNwt4", "XNzg0", "Qkvw6", "wSEe6", "XNAR2", "jPUKG9", "BfDsa5",
    "NLBQh4", "gZuvw0", "DmMyh8", "UqfC6", "SsIhw3", "UvCHC0", "QNwGo0", "bxwC4", "mPCxG3", "rrYRv3",
    "ZVrB5", "oEyAb1", "SdHeo9", "uzri0", "WIuS3", "RjLr7", "FWhj7", "wwGxq8", "samm5", "SiHjy8",
    "XsrRO3", "Qppo3", "jzZH4", "axZzC3", "ElYCL0", "gzpfB4", "yZZpI0",
];

/// Branch-`g` init keys (captured solvegate `g` iframe). Same count, different names.
pub const INIT_JSON_KEYS_G: &[&str] = &[
    "cpza4", "kwYu6", "Cplz9", "zcNj0", "bACR4", "gAMzq7", "NWUB3", "WpIu5", "yRMqb7", "jRwR8",
    "yTXuH8", "NGYVs4", "yCCo2", "ucBTZ7", "InHf7", "riWe2", "YIjU8", "qOeu1", "PnHD6", "IfWx3",
    "RGOD3", "QnRk5", "CORKS6", "ZSOv1", "SGOjP8", "NCyW3", "KImJo0", "ccSxK3", "MJLB4", "HsMRH3",
    "sJcj4", "CGKBH1", "qYXIZ1", "OxVd3", "kytBC0", "WAiB1", "ZJFpx3", "ViXgZ4", "DSKBL2", "pRJpX8",
    "XNan0", "xRRo8", "VrJt8", "DoKk0", "yJEso5", "BRqvJ4", "FELcX1",
];

/// Identifiers that appear on both `_cf_chl_opt` and the init object (branch `b` snapshot).
pub const SHARED_WITH_CHL_OPT_B: &[&str] = &[
    "DmMyh8", "Eugge3", "SdHeo9", "UqfC6", "bxwC4", "uzri0", "xOSD5", "zlGF5",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoInitJsonShape {
    pub key_count: usize,
    pub set_timeout_delay_ms: u32,
    pub crate_orchestrate_slots: usize,
    pub keys_rotate_with_iframe_build: bool,
    pub json_stringify_field: bool,
    pub empty_string_field: bool,
    pub send_overwrites_timing: bool,
    pub optional_extra_params: bool,
    pub note: &'static str,
}

pub const LIVE_FO_INIT_JSON: FoInitJsonShape = FoInitJsonShape {
    key_count: INIT_JSON_KEY_COUNT,
    set_timeout_delay_ms: SET_TIMEOUT_DELAY_MS,
    crate_orchestrate_slots: CRATE_ORCHESTRATE_SLOT_COUNT,
    keys_rotate_with_iframe_build: true,
    json_stringify_field: true,
    empty_string_field: true,
    send_overwrites_timing: true,
    optional_extra_params: true,
    note: "47-key object then setTimeout(send, 100, url, obj); one field overwritten with Date.now()-start before f4. Do not fill or POST this object.",
};

/// Quoted object keys from the iframe init literal (`"ThPv3":…`).
pub fn quoted_object_keys(object_js: &str) -> Vec<String> {
    let bytes = object_js.as_bytes();
    let mut keys = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'"' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            if j < bytes.len() && bytes.get(j + 1) == Some(&b':') {
                if let Ok(k) = std::str::from_utf8(&bytes[i + 1..j])
                    && looks_like_init_key(k)
                {
                    keys.push(k.to_string());
                }
                i = j + 2;
                continue;
            }
        }
        i += 1;
    }
    keys
}

fn looks_like_init_key(k: &str) -> bool {
    let n = k.len();
    (2..=12).contains(&n)
        && k.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && k.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Brace-match a `{…}` starting at `start`, skipping quoted / template strings.
pub fn brace_end(js: &str, start: usize) -> Option<usize> {
    let b = js.as_bytes();
    if b.get(start) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_str: Option<u8> = None;
    let mut i = start;
    while i < b.len() {
        let c = b[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else if c == b'"' || c == b'\'' || c == b'`' {
            in_str = Some(c);
        } else if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i + 1);
            }
        }
        i += 1;
    }
    None
}

/// Init-JSON object literal from iframe HTML (`:JSON[` plus ≥40 quoted keys, `setTimeout` nearby).
pub fn extract_init_json_object(html: &str) -> Option<&str> {
    let mut search = 0usize;
    while let Some(rel) = html[search..].find(":JSON[") {
        let at = search + rel;
        let window_start = at.saturating_sub(8000);
        let prefix = &html[window_start..at];
        if let Some(obj_rel) = prefix.rfind("={") {
            let obj_start = window_start + obj_rel + 1;
            if let Some(obj_end) = brace_end(html, obj_start) {
                let obj = &html[obj_start..obj_end];
                let keys = quoted_object_keys(obj);
                let after = html.get(obj_end..obj_end.saturating_add(800).min(html.len())).unwrap_or("");
                if keys.len() >= 40 && after.contains("setTimeout") {
                    return Some(obj);
                }
            }
        }
        search = at + 6;
    }
    None
}

pub fn extract_init_json_keys(html: &str) -> Option<Vec<String>> {
    extract_init_json_object(html).map(quoted_object_keys)
}

pub fn keys_match_snapshot(keys: &[String], snapshot: &[&str]) -> bool {
    keys.len() == snapshot.len() && keys.iter().zip(snapshot.iter()).all(|(a, b)| a == b)
}

pub fn shared_with_opt<'a>(init_keys: &'a [String], opt_js: &str) -> Vec<&'a str> {
    let opt: BTreeSet<&str> = opt_js
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| looks_like_init_key(s))
        .collect();
    init_keys
        .iter()
        .filter(|k| opt.contains(k.as_str()))
        .map(|k| k.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::keys::InitPayloadKeys;
    use std::path::Path;

    #[test]
    fn snapshots_are_47_and_disjoint() {
        assert_eq!(INIT_JSON_KEYS_B.len(), INIT_JSON_KEY_COUNT);
        assert_eq!(INIT_JSON_KEYS_G.len(), INIT_JSON_KEY_COUNT);
        assert_eq!(LIVE_FO_INIT_JSON.key_count, INIT_JSON_KEY_COUNT);
        assert_eq!(LIVE_FO_INIT_JSON.set_timeout_delay_ms, 100);
        let b: BTreeSet<_> = INIT_JSON_KEYS_B.iter().copied().collect();
        let g: BTreeSet<_> = INIT_JSON_KEYS_G.iter().copied().collect();
        assert_eq!(b.len(), INIT_JSON_KEY_COUNT);
        assert_eq!(g.len(), INIT_JSON_KEY_COUNT);
        assert!(b.is_disjoint(&g));
        for k in SHARED_WITH_CHL_OPT_B {
            assert!(INIT_JSON_KEYS_B.contains(k), "{k}");
        }
    }

    #[test]
    fn crate_orchestrate_slots_are_40() {
        let v = serde_json::to_value(InitPayloadKeys::default()).unwrap();
        assert_eq!(v.as_object().unwrap().len(), CRATE_ORCHESTRATE_SLOT_COUNT);
        assert_eq!(INIT_JSON_KEY_COUNT.saturating_sub(CRATE_ORCHESTRATE_SLOT_COUNT), 7);
    }

    #[test]
    fn extract_from_tiny_html() {
        let mut keys = String::new();
        for (i, k) in INIT_JSON_KEYS_B.iter().enumerate() {
            if i > 0 {
                keys.push(',');
            }
            if *k == "XNAR2" {
                keys.push_str(&format!("\"{k}\":JSON[n](x)"));
            } else if *k == "wSEe6" {
                keys.push_str(&format!("\"{k}\":``"));
            } else if i == 2 || i == 3 || i == 19 {
                keys.push_str(&format!("\"{k}\":0"));
            } else if i == 8 {
                keys.push_str(&format!("\"{k}\":1"));
            } else {
                keys.push_str(&format!("\"{k}\":V[0]"));
            }
        }
        let html = format!("Xm={{{keys}}};setTimeout(fz,100,d,Xm)");
        let got = extract_init_json_keys(&html).expect("extract");
        assert!(keys_match_snapshot(&got, INIT_JSON_KEYS_B));
        assert!(html.contains("setTimeout"));
    }

    #[test]
    fn captured_b_iframe_matches_snapshot_if_present() {
        let path = Path::new("artifacts/re-out/chrome-oracle-norm/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        let keys = extract_init_json_keys(&html).expect("init json in live iframe");
        assert!(
            keys_match_snapshot(&keys, INIT_JSON_KEYS_B),
            "got {keys:?}"
        );
        let obj = extract_init_json_object(&html).unwrap();
        assert!(obj.contains(":JSON["));
        assert!(obj.contains(":``") || obj.contains(":\"\""));
        assert!(obj.contains(":0,"));
        assert!(obj.contains(":1,") || obj.contains(":1}"));
        for k in SHARED_WITH_CHL_OPT_B {
            assert!(html.contains(&format!("{k}:")), "opt missing {k}");
        }
    }

    #[test]
    fn captured_g_iframe_matches_g_snapshot_if_present() {
        let path = Path::new("artifacts/re-out/solvegate-invisible/iframe-inline.js");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        let keys = extract_init_json_keys(&html).expect("init json in g iframe");
        assert!(keys_match_snapshot(&keys, INIT_JSON_KEYS_G), "got {keys:?}");
        assert!(!keys_match_snapshot(&keys, INIT_JSON_KEYS_B));
    }
}
