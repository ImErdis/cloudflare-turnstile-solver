//! First `/fo/` POST **wrapper** (live compressor `f4`, historical name `wZ`).
//!
//! Headed Chrome (2026-08-21, branch `b`) plus the iframe HTML:
//!
//! ```text
//! N = crypto.getRandomValues(Uint8Array(128))
//! N[0] = 2                    // before RSA
//! derived = N ** 65537 % PUBKEY   // 128 bytes, left-padded
//! N[0] = 0                    // after RSA, XTEA key material
//! pad = (8 - lz_len % 8) % 8
//! key = N[pad*9+40 .. pad*9+56]
//! bytes = derived || pad_byte || XTEA(LZ(plaintext), key)
//! body  = custom_b64(bytes)   // charset[0..64], no '=' padding
//! ```
//!
//! `N` is **once per iframe load**, so both XHR POSTs to the same `/fo/` URL
//! share a long encoded prefix (the RSA blob). Observed: init ~3.7–4.2k chars
//! then follow-up ~86–88k, identical 24-char prefix, `cf-chl-ra: 0`.
//!
//! The compressor identifier rotates (`f4` on the 56907 iframe; older `g`
//! captures spelled `wZ`). Charset **order** rotates; the **set** is stable:
//! `A–Za–z0–9` plus `+$ -` (65 unique chars). No `/` or `=`.
//!
//! XHR (`fj` on the 56907 build; historical comments said `fz`, which is a
//! debug logger on that HTML) does `open("POST", url)`, sets `cf-chl` /
//! `cf-chl-ra`. After timing overwrite the visible encoder is `f3(obj)`.
//! First-POST plaintext is a JSON object with **randomized keys** (same style
//! as `_cf_chl_opt`).
//!
//! This module does **not** build that JSON, encrypt it, or POST it. The crate's
//! orchestrate-era `Compressor` / `encrypt_payload` still zeros `N[0]` *before*
//! RSA — leave that path alone.

use crate::reverse::{PUBLIC_KEY_HEX, RSA_PUBLIC_EXPONENT};
use serde::Serialize;
use std::collections::BTreeSet;

/// Live iframe compressor name on the 56907 / branch-`b` capture.
pub const COMPRESSOR_LIVE_NAME: &str = "f4";
/// Historical / branch-`g` compressor name in older captures.
pub const COMPRESSOR_HISTORICAL_NAME: &str = "wZ";

/// Remaining live gap after this wrapper map: first-POST JSON field set.
pub const NEXT_AFTER_WRAPPER: &str = "fo_init_json";

/// Branch-`b` iframe charset (2026-08-21). 65 unique chars; encoder uses `[0..64]`.
pub const CHARSET_BRANCH_B: &str =
    "eoUfnCPsq3FtDYIAyr5hGd18az9ju+HbL-m$KJ0S24BpMQZVlvTkx6gXciW7REONw";

/// Branch-`g` iframe charset (captured orchestrate-era / solvegate `g` HTML).
pub const CHARSET_BRANCH_G: &str =
    "Mcsmg7IDf234BVHpJTx6itCbauPOyW8ZEr$LS9j0-+G1hklXN5nvYRUqFKdzeoAwQ";

/// Chrome `/fo/` body prefixes (first 24 chars). Same RSA blob on each pair.
pub const CHROME_FO_PREFIXES_B: &[&str] = &[
    "GIgYSecMoIjsYqQYUIzNB6Eh",
    "PaPO87+Ak$+AA4D6x2U0syqB",
    "Fy6Ao6iukOi0Cib7ldoSMI04",
    "PfBqPj7oouhzs5qq1S6kP41u",
    "urVvAlNgLoSrQL7rs5MJRmo4",
    "+6O6m5UJ8$PH0eF1Vh+4QucV",
];

/// Observed first-POST lengths (headed Chrome, same day).
pub const CHROME_FO_INIT_LENS: &[usize] = &[3724, 4172, 4183, 3735];
/// Observed second-POST lengths.
pub const CHROME_FO_FOLLOW_UP_LENS: &[usize] = &[86882, 86636, 88108];

/// Live iframe sets this **before** the RSA modpow.
pub const LIVE_N0_BEFORE_RSA: u8 = 2;
/// Live iframe then zeros this for XTEA key bytes (crate `encrypt_payload` zeros first).
pub const LIVE_N0_AFTER_RSA: u8 = 0;
pub const RSA_BLOB_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FoBodyLenBand {
    Init,
    FollowUp,
    Other,
}

/// Static wrapper facts (not a POST builder).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoBodyWrapper {
    pub compressor_live_name: &'static str,
    pub compressor_historical_name: &'static str,
    pub n0_before_rsa: u8,
    pub n0_after_rsa: u8,
    pub rsa_blob_len: usize,
    pub rsa_exponent: u32,
    pub xtea_key_formula: &'static str,
    pub custom_b64_padding: bool,
    pub n_once_per_iframe: bool,
    pub pubkey_hex: &'static str,
    pub note: &'static str,
}

pub const LIVE_FO_WRAPPER: FoBodyWrapper = FoBodyWrapper {
    compressor_live_name: COMPRESSOR_LIVE_NAME,
    compressor_historical_name: COMPRESSOR_HISTORICAL_NAME,
    n0_before_rsa: LIVE_N0_BEFORE_RSA,
    n0_after_rsa: LIVE_N0_AFTER_RSA,
    rsa_blob_len: RSA_BLOB_LEN,
    rsa_exponent: RSA_PUBLIC_EXPONENT,
    xtea_key_formula: "pad*9+40",
    custom_b64_padding: false,
    n_once_per_iframe: true,
    pubkey_hex: PUBLIC_KEY_HEX,
    note: "wrapper mapped from iframe HTML + Chrome prefixes; crate encrypt_payload still zeros N[0] before RSA (orchestrate path). Do not emit a live POST body from this module.",
};

/// XTEA key start index in the 128-byte `N` buffer (`pad` is 0..=7).
pub fn xtea_key_index(pad: usize) -> usize {
    pad * 9 + 40
}

pub fn classify_fo_body_len(len: usize) -> FoBodyLenBand {
    match len {
        3_000..=5_000 => FoBodyLenBand::Init,
        70_000..=100_000 => FoBodyLenBand::FollowUp,
        _ => FoBodyLenBand::Other,
    }
}

/// Every character of `body` occurs in `charset` (order-insensitive membership).
pub fn body_chars_in_charset(body: &str, charset: &str) -> bool {
    !body.is_empty() && body.chars().all(|c| charset.contains(c))
}

pub fn unique_alphabet(s: &str) -> String {
    s.chars().collect::<BTreeSet<_>>().into_iter().collect()
}

/// 65 unique chars, includes `+$ -`, no `/` or `=`.
pub fn charset_is_well_formed(charset: &str) -> bool {
    charset.len() == 65
        && charset.chars().count() == 65
        && unique_alphabet(charset).chars().count() == 65
        && charset.contains('$')
        && charset.contains('+')
        && charset.contains('-')
        && !charset.contains('/')
        && !charset.contains('=')
}

/// Custom Turnstile alphabet (not standard base64): subset of the 65-char set, no padding.
pub fn looks_like_custom_b64(s: &str) -> bool {
    body_chars_in_charset(s, CHARSET_BRANCH_B) && !s.contains('/') && !s.contains('=')
}

/// First backtick/quote 65-char alphabet in iframe HTML (`i=\`eoUfn…\``).
pub fn extract_compressor_charset(html: &str) -> Option<&str> {
    let bytes = html.as_bytes();
    let mut i = 0;
    while i + 67 <= bytes.len() {
        let open = bytes[i];
        if matches!(open, b'`' | b'\'' | b'"')
            && let Some(slice) = html.get(i + 1..i + 66)
            && bytes.get(i + 66) == Some(&open)
            && charset_is_well_formed(slice)
        {
            return Some(slice);
        }
        i += 1;
    }
    None
}

pub fn same_prefix(a: &str, b: &str, n: usize) -> bool {
    a.chars().take(n).eq(b.chars().take(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reverse::compress::Compressor;
    use std::path::Path;

    #[test]
    fn charsets_are_permutations_of_the_same_set() {
        assert!(charset_is_well_formed(CHARSET_BRANCH_B));
        assert!(charset_is_well_formed(CHARSET_BRANCH_G));
        assert_ne!(CHARSET_BRANCH_B, CHARSET_BRANCH_G);
        assert_eq!(
            unique_alphabet(CHARSET_BRANCH_B),
            unique_alphabet(CHARSET_BRANCH_G)
        );
        assert_eq!(CHARSET_BRANCH_B.len(), 65);
        assert_eq!(CHARSET_BRANCH_B.as_bytes()[64], b'w');
        assert_eq!(CHARSET_BRANCH_G.as_bytes()[64], b'Q');
        assert_eq!(LIVE_FO_WRAPPER.rsa_exponent, 65537);
        assert_eq!(LIVE_FO_WRAPPER.pubkey_hex, PUBLIC_KEY_HEX);
        assert_eq!(PUBLIC_KEY_HEX.len(), 258);
    }

    #[test]
    fn chrome_prefixes_are_custom_b64_not_standard() {
        let mut saw_dollar = false;
        for prefix in CHROME_FO_PREFIXES_B {
            assert!(
                looks_like_custom_b64(prefix),
                "prefix {prefix} not in live charset"
            );
            assert!(body_chars_in_charset(prefix, CHARSET_BRANCH_G));
            if prefix.contains('$') {
                saw_dollar = true;
            }
        }
        assert!(saw_dollar, "at least one Chrome prefix uses $ (not standard b64)");
        assert!(!looks_like_custom_b64("cSTZrlWxKogI4i6I===="));
        assert!(!body_chars_in_charset("abc/def", CHARSET_BRANCH_B));
    }

    #[test]
    fn length_bands_match_headed_chrome() {
        for &len in CHROME_FO_INIT_LENS {
            assert_eq!(classify_fo_body_len(len), FoBodyLenBand::Init, "{len}");
        }
        for &len in CHROME_FO_FOLLOW_UP_LENS {
            assert_eq!(
                classify_fo_body_len(len),
                FoBodyLenBand::FollowUp,
                "{len}"
            );
        }
        assert_eq!(classify_fo_body_len(12), FoBodyLenBand::Other);
        assert!(same_prefix(
            "GIgYSecMoIjsYqQYUIzNB6EhAAAA",
            "GIgYSecMoIjsYqQYUIzNB6EhBBBB",
            24
        ));
    }

    #[test]
    fn xtea_key_index_fits_n_buffer() {
        for pad in 0..8 {
            let i = xtea_key_index(pad);
            assert_eq!(i, pad * 9 + 40);
            assert!(i + 16 <= RSA_BLOB_LEN, "pad {pad} key {i}");
        }
        assert_eq!(xtea_key_index(0), 40);
        assert_eq!(xtea_key_index(7), 103);
    }

    #[test]
    fn crate_compressor_emits_custom_alphabet_not_a_live_body() {
        let c = Compressor::new(CHARSET_BRANCH_B.to_string());
        let out = c.compress("{}");
        assert!(looks_like_custom_b64(&out), "out prefix {:?}", &out[..out.len().min(24)]);
        assert!(!out.contains('='));
        assert!(!out.contains('/'));
    }

    #[test]
    fn extract_charset_from_tiny_html() {
        let html = format!("i=`{CHARSET_BRANCH_B}`,D=BigInt(`0x{PUBLIC_KEY_HEX}`)");
        assert_eq!(extract_compressor_charset(&html), Some(CHARSET_BRANCH_B));
        assert!(html.contains(PUBLIC_KEY_HEX));
    }

    #[test]
    fn captured_live_iframe_charset_matches_if_present() {
        let path = Path::new("artifacts/re-out/chrome-oracle-norm/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        assert!(html.contains(CHARSET_BRANCH_B));
        assert!(html.contains(PUBLIC_KEY_HEX));
        assert!(html.contains("BigInt(65537)"));
        assert_eq!(extract_compressor_charset(&html), Some(CHARSET_BRANCH_B));
    }

    #[test]
    fn captured_g_iframe_uses_g_charset_if_present() {
        let path = Path::new("artifacts/re-out/solvegate-invisible/iframe-inline.js");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        assert!(html.contains(CHARSET_BRANCH_G));
        assert!(html.contains(PUBLIC_KEY_HEX));
        assert_eq!(extract_compressor_charset(&html), Some(CHARSET_BRANCH_G));
    }
}
