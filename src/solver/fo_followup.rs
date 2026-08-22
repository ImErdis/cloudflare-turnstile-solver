//! Second `/fo/` POST **envelope** after `runProgram` (headed Chrome oracle).
//!
//! Same compressor wrapper as the init POST (`f4`, historical `wZ`). `N` is
//! once per iframe, so the pair shares the encoded RSA prefix (observed:
//! identical 24 chars). On the 56907 iframe the XHR helper is **`fj`**
//! (`setTimeout(fj, 100, url, obj)`). **`fz` is a debug logger**, not send.
//! After onload setup, the visible custom-b64 body encoder is **`f3`**.
//!
//! Sequence on the 56907 / branch-`b` iframe:
//!
//! 1. Object literal → `setTimeout(fj, 100, url, obj)` → init POST ~3.7–4.2k.
//! 2. Init **response** ~822–846k standard base64 → packed `runProgram`.
//! 3. `runProgram(packed, E)` return value, if a function, is invoked as
//!    `fn(initObj, fj)`. JS responses use `new Function(f5(decoded))(initObj, fj)`.
//! 4. That path POSTs again to the **same** URL: follow-up ~86–88k custom-b64,
//!    `cf-chl-ra: 0`, same prefix.
//! 5. Follow-up **response** ~2.4k — not another packed program.
//!
//! Plaintext **kind** (cannot decrypt custom-b64 without the RSA private key):
//! a large compressed blob (~65k LZ/XTEA after stripping the 129-byte RSA/pad
//! header), consistent with a JSON fingerprint object. It is **not** a second
//! packed `runProgram` string (those are standard base64 on the *response*).
//!
//! This module does **not** fill fields, reconstruct `f4`/`wZ`/`f3` as a live
//! POST, or execute handlers as a solver.

use crate::solver::fo_body::{
    COMPRESSOR_HISTORICAL_NAME, COMPRESSOR_LIVE_NAME, RSA_BLOB_LEN,
};
use serde::Serialize;

/// Remaining live gap after the follow-up **envelope**: handler semantics
/// (follow-up JSON names are snapshotted). See [`crate::solver::fo_followup_json`].
pub const NEXT_AFTER_FOLLOWUP_SHAPE: &str = crate::solver::fo_followup_json::NEXT_AFTER_FOLLOWUP_JSON;

/// XHR send + response handler on the 56907 iframe (`setTimeout(fj, 100, …)`).
/// Minified name rotates (`fj` / historical `fz`).
pub const SEND_HELPER_LIVE_NAME: &str = "fj";

/// Tiny debug logger on the 56907 iframe. Not the send helper.
pub const DEBUG_LOGGER_LIVE_NAME: &str = "fz";

/// Visible custom-b64 body encoder called after the timing overwrite (`f3(obj)`).
/// Optional host wrap remains [`COMPRESSOR_LIVE_NAME`] (`f4`).
pub const BODY_ENCODER_LIVE_NAME: &str = "f3";

/// First 24 chars of paired POSTs are the RSA blob (same `N`).
pub const SHARED_PREFIX_CHARS: usize = 24;

/// RSA blob plus the 1-byte LZ pad length that precedes XTEA.
pub const RSA_AND_PAD_OVERHEAD: usize = RSA_BLOB_LEN + 1;

/// Observed follow-up **response** lengths (headed Chrome xhr `responseText`).
pub const CHROME_FO_FOLLOW_UP_RESP_LENS: &[usize] = &[2400];

/// Observed init **response** lengths (packed `runProgram`, standard base64).
pub const CHROME_FO_INIT_RESP_LENS: &[usize] = &[822_840, 822_956, 845_928, 846_392];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FoFollowUpPlaintextKind {
    /// Large LZ/XTEA blob after `runProgram`; not a packed program.
    CompressedBlobAfterRunProgram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FoResponseLenBand {
    /// ~822–846k standard base64 of a packed `runProgram`.
    PackedRunProgram,
    /// ~2.4k follow-up ack; not another VM blob.
    FollowUpAck,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoFollowUpShape {
    pub compressor_live_name: &'static str,
    pub compressor_historical_name: &'static str,
    pub send_helper: &'static str,
    pub same_n_wrapper: bool,
    pub same_url: bool,
    pub shared_prefix_chars: usize,
    pub cf_chl_ra: &'static str,
    pub sent_after_run_program: bool,
    pub plaintext_kind: FoFollowUpPlaintextKind,
    pub not_packed_program: bool,
    pub note: &'static str,
}

pub const LIVE_FO_FOLLOWUP: FoFollowUpShape = FoFollowUpShape {
    compressor_live_name: COMPRESSOR_LIVE_NAME,
    compressor_historical_name: COMPRESSOR_HISTORICAL_NAME,
    send_helper: SEND_HELPER_LIVE_NAME,
    same_n_wrapper: true,
    same_url: true,
    shared_prefix_chars: SHARED_PREFIX_CHARS,
    cf_chl_ra: "0",
    sent_after_run_program: true,
    plaintext_kind: FoFollowUpPlaintextKind::CompressedBlobAfterRunProgram,
    not_packed_program: true,
    note: "same f4/N wrapper as init (shared 24-char prefix); plaintext is a large compressed blob after runProgram, not a packed program. Do not reconstruct or POST.",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RunProgramReturnBridge {
    pub send_helper: &'static str,
    pub debug_logger: &'static str,
    pub body_encoder: &'static str,
    pub compressor_wrap: &'static str,
    pub init_schedule: &'static str,
    pub packed_call: &'static str,
    pub invoke_if_fn: &'static str,
    pub js_alt: &'static str,
    pub note: &'static str,
}

/// How the 56907 iframe turns a packed init **response** into the follow-up POST.
/// Glue only — do not execute `runProgram` or POST.
pub const LIVE_RUN_PROGRAM_RETURN: RunProgramReturnBridge = RunProgramReturnBridge {
    send_helper: SEND_HELPER_LIVE_NAME,
    debug_logger: DEBUG_LOGGER_LIVE_NAME,
    body_encoder: BODY_ENCODER_LIVE_NAME,
    compressor_wrap: COMPRESSOR_LIVE_NAME,
    init_schedule: "setTimeout(fj, 100, url, obj)",
    packed_call: "runProgram(packed, E)",
    invoke_if_fn: "fn(initObj, fj)",
    js_alt: "new Function(f5(decoded))(initObj, fj)",
    note: "typeof-function gate then the same fj helper; JS eval is an alt response shape, not a second protocol. Do not execute or POST.",
};

/// Custom-b64 (6 bits/char) length → decoded byte count.
pub fn custom_b64_decoded_len(chars: usize) -> usize {
    chars.saturating_mul(6) / 8
}

/// Bytes after RSA blob + pad that XTEA/LZ occupy (approx).
pub fn approx_lz_xtea_len(custom_b64_chars: usize) -> usize {
    custom_b64_decoded_len(custom_b64_chars).saturating_sub(RSA_AND_PAD_OVERHEAD)
}

pub fn classify_fo_response_len(len: usize) -> FoResponseLenBand {
    match len {
        700_000..=950_000 => FoResponseLenBand::PackedRunProgram,
        1_500..=4_000 => FoResponseLenBand::FollowUpAck,
        _ => FoResponseLenBand::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::fo_body::{
        CHROME_FO_FOLLOW_UP_LENS, CHROME_FO_INIT_LENS, CHROME_FO_PREFIXES_B, FoBodyLenBand,
        classify_fo_body_len, same_prefix,
    };
    use std::path::Path;

    #[test]
    fn followup_shape_is_same_wrapper_not_a_packed_program() {
        assert_eq!(LIVE_FO_FOLLOWUP.compressor_live_name, "f4");
        assert_eq!(LIVE_FO_FOLLOWUP.send_helper, "fj");
        assert_eq!(LIVE_RUN_PROGRAM_RETURN.send_helper, "fj");
        assert_eq!(LIVE_RUN_PROGRAM_RETURN.debug_logger, "fz");
        assert_eq!(LIVE_RUN_PROGRAM_RETURN.body_encoder, "f3");
        assert_eq!(LIVE_RUN_PROGRAM_RETURN.compressor_wrap, "f4");
        assert_ne!(
            LIVE_RUN_PROGRAM_RETURN.send_helper,
            LIVE_RUN_PROGRAM_RETURN.debug_logger
        );
        assert_eq!(LIVE_FO_FOLLOWUP.same_n_wrapper, LIVE_FO_FOLLOWUP.same_url);
        assert_eq!(
            LIVE_FO_FOLLOWUP.not_packed_program,
            LIVE_FO_FOLLOWUP.sent_after_run_program
        );
        assert_eq!(
            LIVE_FO_FOLLOWUP.plaintext_kind,
            FoFollowUpPlaintextKind::CompressedBlobAfterRunProgram
        );
        assert_eq!(NEXT_AFTER_FOLLOWUP_SHAPE, "handler_semantics");
        for &len in CHROME_FO_FOLLOW_UP_LENS {
            assert_eq!(classify_fo_body_len(len), FoBodyLenBand::FollowUp, "{len}");
            let blob = approx_lz_xtea_len(len);
            assert!(
                blob > 50_000 && blob < 80_000,
                "follow-up LZ/XTEA {blob} from {len} chars"
            );
        }
        for &len in CHROME_FO_INIT_LENS {
            assert_eq!(classify_fo_body_len(len), FoBodyLenBand::Init, "{len}");
            assert!(approx_lz_xtea_len(len) < 10_000, "{len}");
        }
        for &len in CHROME_FO_FOLLOW_UP_RESP_LENS {
            assert_eq!(
                classify_fo_response_len(len),
                FoResponseLenBand::FollowUpAck,
                "{len}"
            );
        }
        for &len in CHROME_FO_INIT_RESP_LENS {
            assert_eq!(
                classify_fo_response_len(len),
                FoResponseLenBand::PackedRunProgram,
                "{len}"
            );
        }
        assert!(same_prefix(
            CHROME_FO_PREFIXES_B[0],
            CHROME_FO_PREFIXES_B[0],
            SHARED_PREFIX_CHARS
        ));
    }

    #[test]
    fn chrome_pairs_share_prefix_and_url_if_oracle_present() {
        let path = Path::new("artifacts/re-out/chrome-oracle/oracle.json");
        if !path.is_file() {
            return;
        }
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mul = v
            .pointer("/fetch/key_mul")
            .or_else(|| v.pointer("/fetchSchedule/keyMul"))
            .and_then(|x| x.as_u64());
        if mul != Some(56_907) && v.get("laterSameDay").is_none() {
            return;
        }
        let pairs = v
            .get("foPostPairs")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(
            !pairs.is_empty(),
            "headed Chrome should have init+follow-up pairs"
        );
        for p in &pairs {
            assert_eq!(p["sameUrl"], true);
            assert_eq!(p["samePrefix"], true);
            let posts = p["posts"].as_array().unwrap();
            assert_eq!(posts.len(), 2);
            let a = posts[0]["bodyLen"].as_u64().unwrap() as usize;
            let b = posts[1]["bodyLen"].as_u64().unwrap() as usize;
            assert_eq!(classify_fo_body_len(a), FoBodyLenBand::Init);
            assert_eq!(classify_fo_body_len(b), FoBodyLenBand::FollowUp);
            assert_eq!(posts[0]["cfChlRa"].as_str(), Some("0"));
            assert_eq!(posts[1]["cfChlRa"].as_str(), Some("0"));
            assert_eq!(
                posts[0]["bodyPrefix"].as_str(),
                posts[1]["bodyPrefix"].as_str()
            );
        }
        let xhr = v
            .get("xhrHook")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let mut saw_ack = false;
        let mut saw_packed = false;
        for row in &xhr {
            let req = row["bodyLen"].as_u64().unwrap_or(0) as usize;
            let resp = row["respLen"].as_u64().unwrap_or(0) as usize;
            if classify_fo_body_len(req) == FoBodyLenBand::FollowUp {
                assert_eq!(classify_fo_response_len(resp), FoResponseLenBand::FollowUpAck);
                saw_ack = true;
            }
            if classify_fo_body_len(req) == FoBodyLenBand::Init && resp > 0 {
                assert_eq!(
                    classify_fo_response_len(resp),
                    FoResponseLenBand::PackedRunProgram
                );
                saw_packed = true;
            }
        }
        assert!(saw_ack && saw_packed, "xhr hook should see both response bands");
    }

    #[test]
    fn live_iframe_sends_followup_via_same_f4_after_runprogram_if_present() {
        for candidate in [
            "artifacts/re-out/chrome-oracle/iframe-1.html",
            "artifacts/re-out/chrome-oracle-bp/iframe-1.html",
            "artifacts/re-out/chrome-oracle-norm/iframe-1.html",
        ] {
            let path = Path::new(candidate);
            if !path.is_file() {
                continue;
            }
            let html = std::fs::read_to_string(path).unwrap();
            if !html.contains("56907") {
                continue;
            }
            if candidate.ends_with("chrome-oracle/iframe-1.html")
                && !html.contains("setTimeout(fj,100,h,Xm)")
            {
                continue;
            }
            assert!(
                html.contains("function f4") || html.contains("f4=function"),
                "{candidate} missing f4"
            );
            assert!(html.contains("runProgram("), "{candidate} missing runProgram");
            assert!(html.contains("f4("), "{candidate} missing f4(");
            if candidate.ends_with("chrome-oracle/iframe-1.html") {
                for snip in [
                    "setTimeout(fj,100,h,Xm)",
                    "XK=A[rH(JY.aj)](runProgram,XS,E)",
                    "A[rH(JY.aH)](XK,n,fj)",
                    "new E[rH(JY.aI)](f5(XS))(n,fj)",
                    "f3=function",
                    "function fz(",
                    "function fj(",
                ] {
                    assert!(html.contains(snip), "{candidate} missing {snip}");
                }
                assert!(!html.contains("setTimeout(fz,100"));
            }
            return;
        }
    }
}
