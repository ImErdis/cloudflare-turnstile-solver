use crate::solver::protocol::extract_fo_session;
use anyhow::anyhow;
use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CloudflareChallengeOptions {
    pub c_type: String,
    pub cv_id: String,
    pub c_arg: String,
    pub zone: String,
    pub api_v_id: String,
    pub widget_id: String,
    pub site_key: String,
    pub api_mode: String,
    pub api_size: String,
    pub api_rcv: String,
    pub reset_src: String,
    pub c_ray: String,
    pub ch: String,
    pub md: String,
    pub time: String,
    pub iss_ua: String,
    pub ip: String,
    pub turnstile_u: String,
    /// Platform branch letter from `_cf_chl_opt` (`g`, `b`, …).
    pub branch: String,
    /// Session id from the inline `/fo/{session}/` path, if present.
    pub fo_session: String,
}

impl CloudflareChallengeOptions {
    pub fn from_html(html: &str) -> Result<Self, anyhow::Error> {
        let data = extract_chl_opt_object(html)
            .ok_or_else(|| anyhow!("Failed to find window._cf_chl_opt object"))?;

        let mut opt = if looks_like_legacy_named_keys(data) {
            parse_legacy(data, html)
        } else {
            parse_randomized(data)
        };

        if opt.fo_session.is_empty() {
            opt.fo_session = extract_fo_session(html).unwrap_or_default();
        }

        if opt.zone.is_empty() || opt.c_ray.is_empty() {
            anyhow::bail!(
                "parsed _cf_chl_opt but missing zone/c_ray (zone={:?} ray={:?})",
                opt.zone,
                opt.c_ray
            );
        }

        Ok(opt)
    }

    pub fn missing_orchestrate_hint(&self) -> String {
        if self.fo_session.is_empty() {
            format!(
                "orchestrate/chl_api is not the VM this crate disassembles (type {}, ray {}, branch {})",
                self.c_type, self.c_ray, self.branch
            )
        } else {
            format!(
                "orchestrate/chl_api is not the VM; iframe XHR POSTs /fo/{}/{{ray}}/{{ch}} with cf-chl and a compressed init body, then runProgram()s the ray-decrypted response (ray {}, branch {}, type {})",
                self.fo_session, self.c_ray, self.branch, self.c_type
            )
        }
    }
}

fn looks_like_legacy_named_keys(data: &str) -> bool {
    data.contains("cType:") && data.contains("cRay:")
}

fn parse_legacy(data: &str, html: &str) -> CloudflareChallengeOptions {
    fn extract_field(data: &str, key: &str) -> String {
        let pat = format!(r#"{}\s*:\s*['"]([^'"]*)['"]"#, key);
        Regex::new(&pat)
            .ok()
            .and_then(|re| re.captures(data))
            .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
            .unwrap_or_default()
    }

    fn get_turnstile_u(html: &str) -> String {
        html.split("chlTimeoutMs:")
            .nth(1)
            .and_then(|s| s.split(',').nth(1))
            .and_then(|raw| raw.split(['\'', '"']).nth(1))
            .map(str::to_string)
            .unwrap_or_default()
    }

    CloudflareChallengeOptions {
        c_type: extract_field(data, "cType"),
        cv_id: extract_field(data, "cvId"),
        c_arg: extract_field(data, "cFPWv"),
        zone: extract_field(data, "cZone"),
        api_v_id: extract_field(data, "chlApivId"),
        widget_id: extract_field(data, "chlApiWidgetId"),
        site_key: extract_field(data, "chlApiSitekey"),
        api_mode: extract_field(data, "chlApiMode"),
        api_size: extract_field(data, "chlApiSize"),
        api_rcv: extract_field(data, "chlApiRcV"),
        c_ray: extract_field(data, "cRay"),
        ch: extract_field(data, "cH"),
        md: extract_field(data, "md"),
        time: extract_field(data, "cITimeS"),
        iss_ua: extract_field(data, "chlIssUA"),
        ip: extract_field(data, "chlIp"),
        reset_src: extract_field(data, "chlApiResetSrc"),
        turnstile_u: get_turnstile_u(html),
        branch: String::new(),
        fo_session: String::new(),
    }
}

fn parse_randomized(data: &str) -> CloudflareChallengeOptions {
    let values = collect_quoted_strings(data);
    let widget_id = named_string(data, "widgetId").unwrap_or_default();
    let api_rcv = named_string(data, "nextRcV").unwrap_or_default();

    let mut site_key = String::new();
    let mut zone = String::new();
    let mut api_mode = String::new();
    let mut api_size = String::new();
    let mut c_type = String::new();
    let mut c_ray = String::new();
    let mut time = String::new();
    let mut branch = String::new();
    let mut cv_id = String::new();
    let mut widget_from_len = String::new();

    for v in &values {
        if site_key.is_empty() && v.starts_with("0x") && v.len() >= 16 {
            site_key = v.clone();
            continue;
        }
        if zone.is_empty() && v.contains('.') && !v.contains(' ') && looks_like_hostname(v) {
            zone = v.clone();
            continue;
        }
        if c_type.is_empty() && v.starts_with("chl_api") {
            c_type = v.clone();
            continue;
        }
        if api_mode.is_empty() && matches!(v.as_str(), "managed" | "non-interactive" | "invisible")
        {
            api_mode = v.clone();
            continue;
        }
        if api_size.is_empty() && matches!(v.as_str(), "normal" | "compact" | "flexible") {
            api_size = v.clone();
            continue;
        }
        if c_ray.is_empty() && is_ray(v) {
            c_ray = v.clone();
            continue;
        }
        if time.is_empty() && is_unix_seconds(v) {
            time = v.clone();
            continue;
        }
        if widget_from_len.is_empty() && is_widget_id(v) {
            widget_from_len = v.clone();
            continue;
        }
        if cv_id.is_empty() && is_cv_id(v) {
            cv_id = v.clone();
            continue;
        }
        if branch.is_empty() && is_platform_branch(v) {
            branch = v.clone();
            continue;
        }
    }

    let tokens: Vec<String> = values
        .into_iter()
        .filter(|v| is_cf_versioned_token(v))
        .collect();
    let mut remaining: Vec<String> = tokens.into_iter().filter(|t| *t != api_rcv).collect();
    remaining.sort_by_key(|s| s.len());

    let ch = remaining.first().cloned().unwrap_or_default();
    let md = if remaining.len() > 1 {
        remaining.last().cloned().unwrap_or_default()
    } else {
        String::new()
    };
    let reset_src = remaining
        .iter()
        .find(|t| *t != &ch && *t != &md && t.contains("-1.3."))
        .cloned()
        .or_else(|| remaining.iter().find(|t| *t != &ch && *t != &md).cloned())
        .unwrap_or_default();

    CloudflareChallengeOptions {
        c_type,
        cv_id,
        c_arg: String::new(),
        zone,
        api_v_id: String::new(),
        widget_id: if widget_id.is_empty() {
            widget_from_len
        } else {
            widget_id
        },
        site_key,
        api_mode,
        api_size,
        api_rcv,
        reset_src,
        c_ray,
        ch,
        md,
        time,
        iss_ua: String::new(),
        ip: String::new(),
        turnstile_u: String::new(),
        branch,
        fo_session: String::new(),
    }
}

fn extract_chl_opt_object(html: &str) -> Option<&str> {
    let marker = "window._cf_chl_opt";
    let idx = html.find(marker)?;
    let after_name = &html[idx + marker.len()..];
    let eq = after_name.find('=')?;
    let after_eq = after_name[eq + 1..].trim_start();
    if !after_eq.starts_with('{') {
        return None;
    }
    let open = html.len() - after_eq.len();
    extract_balanced_object(html, open)
}

fn extract_balanced_object(src: &str, open: usize) -> Option<&str> {
    let bytes = src.as_bytes();
    if open >= bytes.len() || bytes[open] != b'{' {
        return None;
    }
    let mut depth = 0i32;
    let mut i = open;
    let mut in_str: Option<u8> = None;
    let mut escape = false;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if escape {
                escape = false;
            } else if c == b'\\' {
                escape = true;
            } else if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'\'' | b'"' => in_str = Some(c),
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[open..=i]);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

fn collect_quoted_strings(data: &str) -> Vec<String> {
    let bytes = data.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\'' || c == b'"' {
            let q = c;
            i += 1;
            let start = i;
            let mut escape = false;
            while i < bytes.len() {
                let b = bytes[i];
                if escape {
                    escape = false;
                } else if b == b'\\' {
                    escape = true;
                } else if b == q {
                    if let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                        out.push(s.to_string());
                    }
                    break;
                }
                i += 1;
            }
        }
        i += 1;
    }
    out
}

fn named_string(data: &str, key: &str) -> Option<String> {
    let pat = format!(r#"{}\s*:\s*['"]([^'"]*)['"]"#, regex::escape(key));
    Regex::new(&pat)
        .ok()
        .and_then(|re| re.captures(data))
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn looks_like_hostname(v: &str) -> bool {
    v.len() <= 64
        && !is_cf_versioned_token(v)
        && v.contains('.')
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn is_ray(v: &str) -> bool {
    v.len() == 16 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_unix_seconds(v: &str) -> bool {
    v.len() == 10 && v.bytes().all(|b| b.is_ascii_digit())
}

fn is_widget_id(v: &str) -> bool {
    v.len() == 5
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn is_cv_id(v: &str) -> bool {
    (1..=2).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit()) && v != "0"
}

fn is_platform_branch(v: &str) -> bool {
    matches!(v, "b" | "c" | "g")
}

fn is_cf_versioned_token(v: &str) -> bool {
    if v.len() < 40 {
        return false;
    }
    let Some(ver) = v.find("-1.") else {
        return false;
    };
    let ts = v[..ver].rsplit('-').next().unwrap_or("");
    ts.len() == 10 && ts.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const RANDOMIZED_HTML: &str = r#"<!DOCTYPE html><html><script>
window._cf_chl_opt = {kwYu6: '3',iHMNd4: 'challenges.cloudflare.com',aaPs0: 5,CORKS6: '0',yLYdq1: 'nsp06',ZSOv1: '0x4AAAAAAER49t0sMxTcief0',GqmCB8: 'invisible',FDwx0: 'normal',jBgT4: 'dark',qYXIZ1: 'duzwS3R88HaptZDmjTF5Hl447ssndpAjc01iavMlLco-1787317736-1.3.1.1-QrWkMgdMFgFhNnZ5co9VtX84SDS4Xy1Am.cD1jxrF7I',OxVd3: 'new',GHjg0: 'tjBwNx1WMngaeo7avrkB_fOgBmxgjfCZC9h7JANlyYI-1787317736-1.3.1.1-SJ8szLTlv2gC6LJby6jzYz77IbBj_6PKNDwbuqSzjJjgOvMOiH0dhOMDLEiU_IyfZtGCr.et30XM9lTBavcZaQ',MEjdb0: 'chl_api_inv',wxfI5: 'a2e9de8f39a58015',FIHY8: 'FLEwnStyjx6jLxco0wJo48QfCzWSPV80NlZ0WRO3K_k-1787317736-1.2.1.1-FRszUAzRwVWa83pGUFa6gFsbVPifKuvz3UNw8rb98DxM4GER2C.VRl904dIaujIa',STupN6: 'g',QSsJ3: 'n',yTXuH8: 'lQ23MdZ.PCVk6_kC1W9gcEOML4eZbayrcPuh5A08bOU-1787317736-1.2.1.1-verylongmdpayloadxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',cVRzu3: 'fMro04NZ7QrZH41Nr1G8ceARyx8otwx4XACJ.twJI1s-1787317736-1.2.1.1-5G6BWHIufy91cjzaLJDoIgVspSI1sSiA4eEAhrHkJE_llHuZ58Euz7MgmcKF_Yl6HIULXsStTuXh10v1YqAVkBr2thX',jRwR8: '1787317736',STeH5: 'qkf0qnfc',RgbV8: function(refreshTrigger){window.parent.postMessage({trigger: refreshTrigger,source: 'cloudflare-challenge',widgetId: 'nsp06',nextRcV: 'duzwS3R88HaptZDmjTF5Hl447ssndpAjc01iavMlLco-1787317736-1.3.1.1-QrWkMgdMFgFhNnZ5co9VtX84SDS4Xy1Am.cD1jxrF7I',event: 'reloadRequest',}, '*');}};
"/fo/3582283294:1787313908:APFDW9U4h3BzonFjglK0KtrPIGcFM_zQT0e9v8HCAcs/"
</script></html>"#;

    const LEGACY_HTML: &str = r#"<html><script>window._cf_chl_opt={cType:'chl_api',cvId:'3',cFPWv:'b',cZone:'challenges.cloudflare.com',chlApivId:'v0',chlApiWidgetId:'abc12',chlApiSitekey:'0x4AAAAAABdbdHypG5Crbw0P',chlApiMode:'managed',chlApiSize:'normal',chlApiRcV:'rcv-token',cRay:'0123456789abcdef',cH:'ch-token',md:'md-token',cITimeS:'1700000000',chlIssUA:'Mozilla',chlIp:'1.2.3.4',chlApiResetSrc:'reset'};chlTimeoutMs:10000,'turnstile-u',</script></html>"#;

    #[test]
    fn parse_legacy_named_keys() {
        let opt = CloudflareChallengeOptions::from_html(LEGACY_HTML).unwrap();
        assert_eq!(opt.c_type, "chl_api");
        assert_eq!(opt.c_ray, "0123456789abcdef");
        assert_eq!(opt.site_key, "0x4AAAAAABdbdHypG5Crbw0P");
        assert_eq!(opt.zone, "challenges.cloudflare.com");
        assert_eq!(opt.widget_id, "abc12");
        assert_eq!(opt.api_mode, "managed");
        assert_eq!(opt.turnstile_u, "turnstile-u");
    }

    #[test]
    fn parse_randomized_keys_and_trailing_function() {
        let opt = CloudflareChallengeOptions::from_html(RANDOMIZED_HTML).unwrap();
        assert_eq!(opt.site_key, "0x4AAAAAAER49t0sMxTcief0");
        assert_eq!(opt.zone, "challenges.cloudflare.com");
        assert_eq!(opt.widget_id, "nsp06");
        assert_eq!(opt.api_mode, "invisible");
        assert_eq!(opt.api_size, "normal");
        assert_eq!(opt.c_type, "chl_api_inv");
        assert_eq!(opt.c_ray, "a2e9de8f39a58015");
        assert_eq!(opt.branch, "g");
        assert_eq!(opt.cv_id, "3");
        assert_eq!(opt.time, "1787317736");
        assert_eq!(
            opt.api_rcv,
            "duzwS3R88HaptZDmjTF5Hl447ssndpAjc01iavMlLco-1787317736-1.3.1.1-QrWkMgdMFgFhNnZ5co9VtX84SDS4Xy1Am.cD1jxrF7I"
        );
        assert!(opt.ch.contains("-1.2.1.1-"), "ch={}", opt.ch);
        assert!(opt.md.len() > opt.ch.len(), "md should be the long token");
        assert_eq!(
            opt.fo_session,
            "3582283294:1787313908:APFDW9U4h3BzonFjglK0KtrPIGcFM_zQT0e9v8HCAcs"
        );
        assert!(
            !opt.missing_orchestrate_hint()
                .contains("orchestrate/chl_api/v1")
        );
        assert!(opt.missing_orchestrate_hint().contains("/fo/"));
    }

    #[test]
    fn rejects_html_without_chl_opt() {
        assert!(CloudflareChallengeOptions::from_html("<html>nope</html>").is_err());
    }

    #[test]
    fn parse_live_capture_if_present() {
        let dir = Path::new("artifacts/re-out/solvegate-invisible/html");
        if !dir.is_dir() {
            return;
        }
        let mut parsed = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) != Some("html") {
                continue;
            }
            let html = std::fs::read_to_string(&path).unwrap();
            if !html.contains("window._cf_chl_opt") {
                continue;
            }
            let opt = CloudflareChallengeOptions::from_html(&html)
                .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
            assert_eq!(opt.zone, "challenges.cloudflare.com");
            assert_eq!(opt.c_ray.len(), 16);
            assert!(opt.site_key.starts_with("0x"));
            assert!(
                opt.c_type.starts_with("chl_api"),
                "c_type={} in {}",
                opt.c_type,
                path.display()
            );
            assert!(
                !opt.fo_session.is_empty(),
                "missing /fo/ in {}",
                path.display()
            );
            parsed += 1;
        }
        assert!(
            parsed > 0,
            "expected at least one iframe html with _cf_chl_opt"
        );
    }
}
