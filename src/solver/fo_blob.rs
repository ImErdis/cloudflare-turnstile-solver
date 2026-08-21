use crate::reverse::encryption::decrypt_cloudflare_response;
use crate::solver::protocol::looks_like_javascript;
use anyhow::Context;
use serde::Serialize;

/// Prefix shared by the iframe's inline `runProgram(...)` argument and a
/// `decrypt_cloudflare_response(ray, /fo/ body)` of the captured blob.
pub const PACKED_RUN_PROGRAM_PREFIX: &str = "ryrCJzUnLCItNTiVeJ";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FoBlobAnalysis {
    pub input_bytes: usize,
    pub looks_like_json_error: bool,
    pub looks_like_b64: bool,
    pub decrypt_ok: bool,
    pub decrypt_bytes: usize,
    pub decrypt_prefix: String,
    pub looks_like_javascript: bool,
    pub looks_like_packed_run_program: bool,
    pub json_error_d_len: Option<usize>,
}

impl FoBlobAnalysis {
    pub fn summary(&self) -> String {
        if self.looks_like_packed_run_program {
            format!(
                "/fo/ body decrypts with c_ray to a packed runProgram blob ({} bytes, prefix {:?}); not the orchestrate VM this crate disassembles",
                self.decrypt_bytes, self.decrypt_prefix
            )
        } else if self.looks_like_json_error {
            format!(
                "/fo/ returned JSON error (d_len={:?}); iframe POSTs a compressed init payload with cf-chl, GET without that body 400s",
                self.json_error_d_len
            )
        } else if self.decrypt_ok {
            format!(
                "/fo/ decrypted {} bytes (prefix {:?}) but is not packed runProgram / JS",
                self.decrypt_bytes, self.decrypt_prefix
            )
        } else {
            format!(
                "/fo/ body {} bytes, b64={}, json_error={}",
                self.input_bytes, self.looks_like_b64, self.looks_like_json_error
            )
        }
    }
}

pub fn analyze_fo_body(c_ray: &str, body: &str) -> FoBlobAnalysis {
    let trimmed = body.trim();
    let looks_like_json_error = trimmed.starts_with('{') && trimmed.contains("\"d\"");
    let json_error_d_len = if looks_like_json_error {
        serde_json::from_str::<serde_json::Value>(trimmed)
            .ok()
            .and_then(|v| v.get("d").and_then(|d| d.as_str()).map(|s| s.len()))
    } else {
        None
    };

    let candidate = if looks_like_json_error {
        serde_json::from_str::<serde_json::Value>(trimmed)
            .ok()
            .and_then(|v| v.get("d").and_then(|d| d.as_str()).map(str::to_string))
            .unwrap_or_else(|| trimmed.to_string())
    } else {
        trimmed.to_string()
    };

    let looks_like_b64 = is_standard_b64(&candidate);
    let decrypted = if looks_like_b64 {
        decrypt_padded(c_ray, &candidate).ok()
    } else {
        None
    };

    let decrypt_ok = decrypted.is_some();
    let decrypt_bytes = decrypted.as_ref().map(|s| s.len()).unwrap_or(0);
    let decrypt_prefix = decrypted
        .as_ref()
        .map(|s| s.chars().take(24).collect())
        .unwrap_or_default();
    let looks_js = decrypted
        .as_ref()
        .map(|s| looks_like_javascript(s))
        .unwrap_or(false);
    // A 400 JSON `{"d":...}` body is not the worker program even if `d` is b64.
    let looks_like_packed_run_program = !looks_like_json_error
        && decrypted
            .as_ref()
            .map(|s| is_packed_run_program(s))
            .unwrap_or(false);

    FoBlobAnalysis {
        input_bytes: body.len(),
        looks_like_json_error,
        looks_like_b64,
        decrypt_ok,
        decrypt_bytes,
        decrypt_prefix,
        looks_like_javascript: looks_js,
        looks_like_packed_run_program,
        json_error_d_len,
    }
}

pub fn is_packed_run_program(plain: &str) -> bool {
    if looks_like_javascript(plain) {
        return false;
    }
    if plain.starts_with(PACKED_RUN_PROGRAM_PREFIX) {
        return true;
    }
    // Packed iframe programs are printable ASCII in '+'..='z', no spaces.
    plain.len() > 256
        && plain.is_ascii()
        && !plain.contains(' ')
        && !plain.contains('\n')
        && plain.bytes().all(|b| (b'+'..=b'z').contains(&b))
}

fn is_standard_b64(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n' | b'\r'))
}

fn decrypt_padded(ray: &str, data: &str) -> Result<String, anyhow::Error> {
    let compact: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = match compact.len() % 4 {
        0 => compact,
        2 => format!("{compact}=="),
        3 => format!("{compact}="),
        _ => compact,
    };
    decrypt_cloudflare_response(ray, &padded)
        .with_context(|| format!("decrypt /fo/ body with ray {ray}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reverse::encryption::decrypt_cloudflare_response;
    use base64::Engine;
    use std::path::Path;

    fn encrypt_cloudflare_response(ray: &str, plain: &str) -> String {
        let key = format!("{ray}_0");
        let mut h: u8 = 32;
        for byte in key.bytes() {
            h ^= byte;
        }
        let raw: Vec<u8> = plain
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                let val = (b as i32 + h as i32 + (i % 65535) as i32).rem_euclid(255);
                val as u8
            })
            .collect();
        base64::prelude::BASE64_STANDARD.encode(raw)
    }

    #[test]
    fn ray_decrypt_roundtrip() {
        let ray = "a2e9de8f39a58015";
        let plain = format!("{PACKED_RUN_PROGRAM_PREFIX}fixture-not-js");
        let enc = encrypt_cloudflare_response(ray, &plain);
        assert_eq!(decrypt_cloudflare_response(ray, &enc).unwrap(), plain);
        let report = analyze_fo_body(ray, &enc);
        assert!(report.decrypt_ok);
        assert!(report.looks_like_packed_run_program);
        assert!(!report.looks_like_javascript);
    }

    #[test]
    fn json_error_is_not_packed_program() {
        let report = analyze_fo_body("a2e9de8f39a58015", r#"{"d":"cSTZrlWxKogI4i6I"}"#);
        assert!(report.looks_like_json_error);
        assert!(!report.looks_like_packed_run_program);
    }

    fn rays_from_html_captures() -> Vec<String> {
        let dir = Path::new("artifacts/re-out/solvegate-invisible/html");
        let mut rays = Vec::new();
        if !dir.is_dir() {
            return rays;
        }
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) != Some("html") {
                continue;
            }
            let html = std::fs::read_to_string(&path).unwrap_or_default();
            if let Ok(opt) = crate::solver::challenge::CloudflareChallengeOptions::from_html(&html)
            {
                if opt.c_ray.len() == 16 && !rays.contains(&opt.c_ray) {
                    rays.push(opt.c_ray);
                }
            }
        }
        rays
    }

    #[test]
    fn captured_fo_blob_decrypts_to_packed_program_if_present() {
        let dir = Path::new("artifacts/re-out/solvegate-invisible/js");
        if !dir.is_dir() {
            return;
        }
        let mut rays = rays_from_html_captures();
        if rays.is_empty() {
            rays.push("a2e9de8f39a58015".to_string());
        }
        let mut found = false;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !name.contains("_fo_") {
                continue;
            }
            let body = std::fs::read_to_string(&path).unwrap();
            if body.len() < 10_000 {
                continue;
            }
            for ray in &rays {
                let report = analyze_fo_body(ray, &body);
                if report.looks_like_packed_run_program
                    && report.decrypt_prefix.starts_with(PACKED_RUN_PROGRAM_PREFIX)
                {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        assert!(
            found,
            "expected a captured /fo/ blob under artifacts/ to decrypt with a captured c_ray"
        );
    }
}
