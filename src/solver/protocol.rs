use crate::solver::VersionInfo;
use anyhow::{anyhow, bail};
use rand::Rng;
use regex::Regex;

pub const PUBLIC_API_JS: &str = "https://challenges.cloudflare.com/turnstile/v0/api.js";
pub const DEMO_SITE_KEY: &str = "0x4AAAAAAER49t0sMxTcief0";
pub const DEMO_HREF: &str = "https://solvegate.io/demo/invisible";

const ENABLE_FEEDBACK: bool = true;
const THEME: &str = "auto";
const LANGUAGE: &str = "auto";

/// Current Turnstile widget iframe (branch `g`, path `turnstile/f/av0/rch`).
///
/// Language is a query parameter. The previous crate URL
/// (`turnstile/if/ov2/av0/rcv/.../{lang}/` on branch `b`) 404s.
pub fn turnstile_iframe_url(branch: &str, site_key: &str, widget_id: &str) -> String {
    let feedback_param = if ENABLE_FEEDBACK { "fbE" } else { "fbD" };
    format!(
        "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/{}/turnstile/f/av0/rch/{}/{}/{}/{}/new/normal?lang={}",
        branch, widget_id, site_key, THEME, feedback_param, LANGUAGE,
    )
}

pub fn generate_widget_id() -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut rng = rand::rng();
    let mut r = String::new();
    for _ in 0..5 {
        let idx = rng.random_range(0..chars.len());
        r.push(chars[idx]);
    }
    r
}

/// Parse the redirected public `api.js` URL:
/// `https://challenges.cloudflare.com/turnstile/v0/{branch}/{version}/api.js`
pub fn parse_turnstile_api_js_url(url: &str) -> Result<VersionInfo, anyhow::Error> {
    let needle = "/turnstile/v0/";
    let idx = url
        .find(needle)
        .ok_or_else(|| anyhow!("turnstile api.js url missing /turnstile/v0/: {url}"))?;
    let rest = &url[idx + needle.len()..];
    let mut parts = rest.split('/');
    let branch = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("turnstile api.js url missing branch: {url}"))?;
    let version_part = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("turnstile api.js url missing version: {url}"))?;
    let version = version_part.split('?').next().unwrap_or(version_part);
    let file = parts.next().unwrap_or("");
    let file_name = file.split('?').next().unwrap_or(file);
    if file_name != "api.js" {
        bail!("unexpected turnstile api.js url: {url}");
    }
    if branch == "api.js" || version == "api.js" {
        bail!("turnstile api.js url has no branch/version (not redirected?): {url}");
    }
    Ok(VersionInfo {
        branch: branch.to_string(),
        version: version.to_string(),
    })
}

pub fn extract_fo_session(html: &str) -> Option<String> {
    let re = Regex::new(r"/fo/([0-9]+:[0-9]+:[A-Za-z0-9_.-]+)").ok()?;
    re.captures(html)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

pub fn fo_blob_url(zone: &str, branch: &str, session: &str, c_ray: &str, ch: &str) -> String {
    format!(
        "https://{}/cdn-cgi/challenge-platform/h/{}/fo/{}/{}/{}",
        zone, branch, session, c_ray, ch
    )
}

pub fn looks_like_javascript(body: &str) -> bool {
    let t = body.trim_start();
    if t.is_empty() || t.starts_with('<') {
        return false;
    }
    t.contains("function") || t.contains("=>") || t.contains("window.")
}

pub fn orchestrate_url(zone: &str, branch: &str, c_ray: &str) -> String {
    format!(
        "https://{}/cdn-cgi/challenge-platform/h/{}/orchestrate/chl_api/v1?ray={}&lang=auto",
        zone, branch, c_ray
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_current_public_api_js_url() {
        let info = parse_turnstile_api_js_url(
            "https://challenges.cloudflare.com/turnstile/v0/g/aae2b9a1c261/api.js",
        )
        .unwrap();
        assert_eq!(info.branch, "g");
        assert_eq!(info.version, "aae2b9a1c261");
    }

    #[test]
    fn parse_api_js_url_rejects_unversioned() {
        assert!(
            parse_turnstile_api_js_url("https://challenges.cloudflare.com/turnstile/v0/api.js")
                .is_err()
        );
    }

    #[test]
    fn iframe_url_uses_rch_query_lang() {
        let url = turnstile_iframe_url("g", "0x4AAAAAAER49t0sMxTcief0", "abc12");
        assert!(url.contains("/h/g/turnstile/f/av0/rch/abc12/"));
        assert!(url.contains("?lang=auto"));
        assert!(!url.contains("/if/ov2/"));
        assert!(!url.contains("/rcv/"));
        assert!(!url.ends_with("/auto/"));
    }

    #[test]
    fn fo_session_from_inline_script() {
        let html =
            r#"x="/fo/3582283294:1787313908:APFDW9U4h3BzonFjglK0KtrPIGcFM_zQT0e9v8HCAcs/"+ray"#;
        assert_eq!(
            extract_fo_session(html).as_deref(),
            Some("3582283294:1787313908:APFDW9U4h3BzonFjglK0KtrPIGcFM_zQT0e9v8HCAcs")
        );
    }

    #[test]
    fn html_is_not_javascript() {
        assert!(!looks_like_javascript("<!DOCTYPE html><html>"));
        assert!(looks_like_javascript("function hello(){}"));
    }
}
