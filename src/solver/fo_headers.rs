//! `/fo/` request shape: iframe XHR (headed Chrome oracle) vs this crate.
//!
//! The iframe does `xhr.open("POST", url)`, `setRequestHeader("cf-chl", ch)`,
//! `setRequestHeader("cf-chl-ra", retryCounter)`, `send(wZ(init))`. It does
//! **not** set Content-Type; Chrome's XHR default for a string body is
//! `text/plain;charset=UTF-8`. `cf-chl-ra` is the retry counter (`0` on the
//! first attempt).
//!
//! Chrome (2026-08-21) POSTs **twice** to the same `/fo/{session}/{ray}/{ch}`
//! URL (small init ~4k → packed program; larger follow-up ~90k). `priority` is
//! `u=1, i`; this crate's empty `probe_fo_blob` uses `u=2`. Custom header
//! **names/values** otherwise match. The remaining live gap is the **body**
//! (`wZ(...)`), not a missing `cf-chl` header.

use serde::Serialize;
use std::collections::BTreeMap;

/// First-attempt `/fo/` XHR as observed from headed Chrome + the iframe source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoPostShape {
    pub method: &'static str,
    pub content_type: &'static str,
    pub cf_chl_header: &'static str,
    pub cf_chl_ra_header: &'static str,
    pub cf_chl_ra_first: &'static str,
    pub accept: &'static str,
    pub origin_host: &'static str,
    pub sec_fetch_site: &'static str,
    pub sec_fetch_mode: &'static str,
    pub sec_fetch_dest: &'static str,
    pub referer_is_iframe: bool,
    /// Iframe sets these via `setRequestHeader`. Content-Type is the XHR default.
    pub xhr_set_header_names: &'static [&'static str],
}

pub const CHROME_FO_POST: FoPostShape = FoPostShape {
    method: "POST",
    content_type: "text/plain;charset=UTF-8",
    cf_chl_header: "cf-chl",
    cf_chl_ra_header: "cf-chl-ra",
    cf_chl_ra_first: "0",
    accept: "*/*",
    origin_host: "challenges.cloudflare.com",
    sec_fetch_site: "same-origin",
    sec_fetch_mode: "cors",
    sec_fetch_dest: "empty",
    referer_is_iframe: true,
    xhr_set_header_names: &["cf-chl", "cf-chl-ra"],
};

/// What `TaskClient::fo_request` / `post_init_payload` send today.
pub const CRATE_FO_POST: FoPostShape = FoPostShape {
    method: "POST",
    content_type: "text/plain;charset=UTF-8",
    cf_chl_header: "cf-chl",
    cf_chl_ra_header: "cf-chl-ra",
    cf_chl_ra_first: "0",
    accept: "*/*",
    origin_host: "challenges.cloudflare.com",
    sec_fetch_site: "same-origin",
    sec_fetch_mode: "cors",
    sec_fetch_dest: "empty",
    referer_is_iframe: true,
    xhr_set_header_names: &["cf-chl", "cf-chl-ra"],
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HeaderFieldDiff {
    pub field: &'static str,
    pub chrome: String,
    pub crate_value: String,
    pub same: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FoHeaderCompare {
    pub all_match: bool,
    pub fields: Vec<HeaderFieldDiff>,
    pub note: &'static str,
}

pub fn compare_chrome_and_crate_fo_post() -> FoHeaderCompare {
    let c = CHROME_FO_POST;
    let k = CRATE_FO_POST;
    let pairs: [(&'static str, &str, &str); 9] = [
        ("method", c.method, k.method),
        ("content_type", c.content_type, k.content_type),
        ("cf_chl", c.cf_chl_header, k.cf_chl_header),
        ("cf_chl_ra", c.cf_chl_ra_header, k.cf_chl_ra_header),
        ("cf_chl_ra_first", c.cf_chl_ra_first, k.cf_chl_ra_first),
        ("accept", c.accept, k.accept),
        ("origin_host", c.origin_host, k.origin_host),
        ("sec_fetch_site", c.sec_fetch_site, k.sec_fetch_site),
        ("sec_fetch_mode", c.sec_fetch_mode, k.sec_fetch_mode),
    ];
    let mut fields: Vec<HeaderFieldDiff> = pairs
        .into_iter()
        .map(|(field, chrome, crate_value)| HeaderFieldDiff {
            field,
            chrome: chrome.to_string(),
            crate_value: crate_value.to_string(),
            same: chrome == crate_value,
        })
        .collect();
    fields.push(HeaderFieldDiff {
        field: "sec_fetch_dest",
        chrome: c.sec_fetch_dest.to_string(),
        crate_value: k.sec_fetch_dest.to_string(),
        same: c.sec_fetch_dest == k.sec_fetch_dest,
    });
    let all_match = fields.iter().all(|f| f.same);
    FoHeaderCompare {
        all_match,
        fields,
        note: "crate matches Chrome XHR header names; Chrome POSTs twice to the same /fo/ URL with priority u=1, i (probe uses u=2); live 400s without the wZ body",
    }
}

/// Lowercased header map from a Chrome CDP `Network.requestWillBeSentExtraInfo`.
pub fn chrome_extra_headers_match_shape(
    headers: &BTreeMap<String, String>,
) -> Vec<(&'static str, bool)> {
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    vec![
        (
            "content-type",
            get("content-type")
                .is_some_and(|v| v.eq_ignore_ascii_case(CHROME_FO_POST.content_type)),
        ),
        ("cf-chl", get("cf-chl").is_some_and(|v| !v.is_empty())),
        (
            "cf-chl-ra",
            get("cf-chl-ra").is_some_and(|v| v == CHROME_FO_POST.cf_chl_ra_first),
        ),
        (
            "sec-fetch-site",
            get("sec-fetch-site").is_some_and(|v| v == CHROME_FO_POST.sec_fetch_site),
        ),
        (
            "sec-fetch-mode",
            get("sec-fetch-mode").is_some_and(|v| v == CHROME_FO_POST.sec_fetch_mode),
        ),
        (
            "sec-fetch-dest",
            get("sec-fetch-dest").is_some_and(|v| v == CHROME_FO_POST.sec_fetch_dest),
        ),
        (
            "origin",
            get("origin").is_some_and(|v| v.contains(CHROME_FO_POST.origin_host)),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_already_matches_chrome_fo_shape() {
        let cmp = compare_chrome_and_crate_fo_post();
        assert!(
            cmp.all_match,
            "header mismatch: {}",
            serde_json::to_string_pretty(&cmp).unwrap()
        );
    }

    #[test]
    fn extra_info_map_checks_first_post() {
        let mut h = BTreeMap::new();
        h.insert("Content-Type".into(), "text/plain;charset=UTF-8".into());
        h.insert("cf-chl".into(), "abc".into());
        h.insert("cf-chl-ra".into(), "0".into());
        h.insert("sec-fetch-site".into(), "same-origin".into());
        h.insert("sec-fetch-mode".into(), "cors".into());
        h.insert("sec-fetch-dest".into(), "empty".into());
        h.insert("origin".into(), "https://challenges.cloudflare.com".into());
        let rows = chrome_extra_headers_match_shape(&h);
        assert!(rows.iter().all(|(_, ok)| *ok), "{rows:?}");
    }
}
