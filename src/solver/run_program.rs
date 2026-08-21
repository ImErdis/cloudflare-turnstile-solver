use crate::solver::protocol::looks_like_javascript;
use anyhow::{Context, bail};
use base64::Engine;
use serde::Serialize;

/// Base64 prefix of packed `runProgram(...)` on the captured branch-`g` iframe.
/// The first 16 characters encode [`RUN_PROGRAM_MAGIC_BYTES`][0..12]; the 17th–18th
/// encode byte 13 (`0x78`) plus the high nibble of byte 14 (captures use `0x9x` → `J`).
pub const PACKED_RUN_PROGRAM_PREFIX: &str = "ryrCJzUnLCItNTiVeJ";

/// Headed Chrome (2026-08-21, platform branch `b`) packed prefix (first 16
/// chars = 12 magic bytes). The 17th–18th chars vary with byte 14 (`Y`/`Z`).
pub const PACKED_RUN_PROGRAM_PREFIX_B: &str = "TX5omy48NT82Lp1u";

/// Later same-day Chrome rotation (`71GxwDchICYfNxikQT…`).
pub const PACKED_RUN_PROGRAM_PREFIX_B_LATE: &str = "71GxwDchICYfNxik";

/// First 13 decoded bytes of branch-`g` packed programs.
///
/// The iframe copies `atob(packed)` into a byte array (`function C`) and runs a
/// rolling-XOR interpreter (`runProgram`). Unpack lives here; the opcode fetch
/// / switch table is [`crate::solver::run_program_vm`].
pub const RUN_PROGRAM_MAGIC_BYTES: [u8; 13] = [
    0xaf, 0x2a, 0xc2, 0x27, 0x35, 0x27, 0x2c, 0x22, 0x2d, 0x35, 0x38, 0x95, 0x78,
];

/// First 13 decoded bytes of live branch-`b` packed programs (`TX5omy48NT82Lp1ueY`).
pub const RUN_PROGRAM_MAGIC_BYTES_B: [u8; 13] = [
    0x4d, 0x7e, 0x68, 0x9b, 0x2e, 0x3c, 0x35, 0x3f, 0x36, 0x2e, 0x9d, 0x6e, 0x79,
];

/// First 13 decoded bytes of the later same-day `b` rotation (`71GxwDchICYfNxikQT`).
pub const RUN_PROGRAM_MAGIC_BYTES_B_LATE: [u8; 13] = [
    0xef, 0x51, 0xb1, 0xc0, 0x37, 0x21, 0x20, 0x26, 0x1f, 0x37, 0x18, 0xa4, 0x41,
];

/// Stable header size in decoded bytecode (the magic). Two `/fo/` captures from
/// the same session shared more than this (138 bytes); that extra overlap is
/// session-specific and is not treated as a format field.
pub const RUN_PROGRAM_MAGIC_LEN: usize = RUN_PROGRAM_MAGIC_BYTES.len();

#[derive(Debug, Clone, Serialize)]
pub struct RunProgramAnalysis {
    pub packed_chars: usize,
    pub standard_b64: bool,
    pub decode_ok: bool,
    pub bytecode_len: usize,
    pub magic_ok: bool,
    pub magic_hex: String,
    pub header_latin1: String,
    pub header_entropy_bits: f64,
    pub body_entropy_bits: f64,
    pub looks_like_javascript: bool,
    pub looks_like_zlib: bool,
    pub unique_body_bytes: usize,
    pub next_gap: &'static str,
}

impl RunProgramAnalysis {
    pub fn summary(&self) -> String {
        if !self.decode_ok {
            return format!(
                "packed runProgram ({} chars) is not standard base64 after the magic prefix",
                self.packed_chars
            );
        }
        format!(
            "packed runProgram: {} chars -> {} bytecode bytes, magic_ok={}, body_entropy={:.2} bits; {}",
            self.packed_chars,
            self.bytecode_len,
            self.magic_ok,
            self.body_entropy_bits,
            self.next_gap
        )
    }
}

/// Standard-base64 decode of a packed `runProgram` string. Does not interpret opcodes.
pub fn unpack_packed_run_program(packed: &str) -> Result<Vec<u8>, anyhow::Error> {
    let compact: String = packed.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < PACKED_RUN_PROGRAM_PREFIX.len() {
        bail!("packed runProgram too short ({} chars)", compact.len());
    }
    if !is_standard_b64(&compact) {
        bail!("packed runProgram is not standard base64");
    }
    decode_std_b64(&compact).with_context(|| "standard-base64 decode of packed runProgram")
}

pub fn analyze_packed_run_program(packed: &str) -> RunProgramAnalysis {
    let compact: String = packed.chars().filter(|c| !c.is_whitespace()).collect();
    let standard_b64 = is_standard_b64(&compact);
    let decoded = if standard_b64 {
        decode_std_b64(&compact).ok()
    } else {
        None
    };
    let decode_ok = decoded.is_some();
    let bytecode = decoded.unwrap_or_default();
    let magic_ok = bytecode.starts_with(&RUN_PROGRAM_MAGIC_BYTES)
        || bytecode.starts_with(&RUN_PROGRAM_MAGIC_BYTES_B)
        || bytecode.starts_with(&RUN_PROGRAM_MAGIC_BYTES_B_LATE);
    let magic_hex = bytecode
        .get(..RUN_PROGRAM_MAGIC_LEN.min(bytecode.len()))
        .unwrap_or(&[])
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("");
    let header = bytecode
        .get(..RUN_PROGRAM_MAGIC_LEN.min(bytecode.len()))
        .unwrap_or(&[]);
    let body = bytecode.get(RUN_PROGRAM_MAGIC_LEN..).unwrap_or(&[]);
    let looks_js = looks_like_javascript(packed)
        || bytecode
            .get(..32)
            .map(|h| looks_like_javascript(&String::from_utf8_lossy(h)))
            .unwrap_or(false);
    let looks_like_zlib = body.starts_with(&[0x78, 0x9c])
        || body.starts_with(&[0x78, 0xda])
        || bytecode.starts_with(&[0x1f, 0x8b]);

    let next_gap = if !decode_ok {
        "packed_string_not_standard_b64"
    } else if looks_js {
        "runProgram_argument_is_javascript"
    } else if looks_like_zlib {
        "bytecode_looks_like_zlib"
    } else if !magic_ok {
        "bytecode_magic_mismatch"
    } else {
        // Fetch + operand layout are mapped; live /fo/ still needs the wZ body.
        crate::solver::run_program_vm::NEXT_GAP
    };

    RunProgramAnalysis {
        packed_chars: compact.len(),
        standard_b64,
        decode_ok,
        bytecode_len: bytecode.len(),
        magic_ok,
        magic_hex,
        header_latin1: header
            .iter()
            .map(|&b| {
                if (32..127).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect(),
        header_entropy_bits: round3(shannon_entropy(header)),
        body_entropy_bits: round3(shannon_entropy(body)),
        looks_like_javascript: looks_js,
        looks_like_zlib,
        unique_body_bytes: unique_byte_count(body),
        next_gap,
    }
}

fn is_standard_b64(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n' | b'\r'))
}

fn decode_std_b64(s: &str) -> Result<Vec<u8>, anyhow::Error> {
    let padded = match s.len() % 4 {
        0 => s.to_string(),
        2 => format!("{s}=="),
        3 => format!("{s}="),
        _ => s.to_string(),
    };
    Ok(base64::prelude::BASE64_STANDARD.decode(padded.as_bytes())?)
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn unique_byte_count(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut n = 0;
    for &b in bytes {
        if !seen[b as usize] {
            seen[b as usize] = true;
            n += 1;
        }
    }
    n
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reverse::encryption::decrypt_cloudflare_response;
    use crate::solver::challenge::CloudflareChallengeOptions;
    use std::path::Path;

    #[test]
    fn magic_bytes_encode_to_known_prefix() {
        // 18 prefix chars encode 13 bytes plus the high nibble of byte 14.
        // Captures use 0x9x there (`J`); zero padding would yield `A`.
        let mut raw = RUN_PROGRAM_MAGIC_BYTES.to_vec();
        raw.push(0x90);
        let encoded = base64::prelude::BASE64_STANDARD.encode(&raw);
        assert!(
            encoded.starts_with(PACKED_RUN_PROGRAM_PREFIX),
            "encoded {encoded} prefix {PACKED_RUN_PROGRAM_PREFIX}"
        );
        let twelve = base64::prelude::BASE64_STANDARD.encode(&RUN_PROGRAM_MAGIC_BYTES[..12]);
        assert_eq!(
            &PACKED_RUN_PROGRAM_PREFIX[..16],
            twelve.trim_end_matches('=')
        );
        let twelve_b = base64::prelude::BASE64_STANDARD.encode(&RUN_PROGRAM_MAGIC_BYTES_B[..12]);
        assert_eq!(PACKED_RUN_PROGRAM_PREFIX_B, twelve_b.trim_end_matches('='));
        let mut raw_b = RUN_PROGRAM_MAGIC_BYTES_B.to_vec();
        raw_b.push(0x80);
        let encoded_b = base64::prelude::BASE64_STANDARD.encode(&raw_b);
        assert!(
            encoded_b.starts_with(PACKED_RUN_PROGRAM_PREFIX_B),
            "encoded {encoded_b} prefix {PACKED_RUN_PROGRAM_PREFIX_B}"
        );
        let twelve_late =
            base64::prelude::BASE64_STANDARD.encode(&RUN_PROGRAM_MAGIC_BYTES_B_LATE[..12]);
        assert_eq!(
            PACKED_RUN_PROGRAM_PREFIX_B_LATE,
            twelve_late.trim_end_matches('=')
        );
    }

    #[test]
    fn unpacks_synthetic_magic_payload() {
        let mut raw = RUN_PROGRAM_MAGIC_BYTES.to_vec();
        raw.push(0x90);
        raw.extend_from_slice(&[0u8; 64]);
        let packed = base64::prelude::BASE64_STANDARD.encode(&raw);
        assert!(packed.starts_with(PACKED_RUN_PROGRAM_PREFIX));
        let unpacked = unpack_packed_run_program(&packed).unwrap();
        assert_eq!(&unpacked[..13], &RUN_PROGRAM_MAGIC_BYTES);
        let report = analyze_packed_run_program(&packed);
        assert!(report.decode_ok);
        assert!(report.magic_ok);
        assert!(!report.looks_like_javascript);
        assert!(!report.looks_like_zlib);
        assert_eq!(report.next_gap, crate::solver::run_program_vm::NEXT_GAP);
    }

    #[test]
    fn rejects_javascript() {
        let report = analyze_packed_run_program("function hello(){ return 1; }");
        assert!(!report.decode_ok || report.looks_like_javascript);
    }

    fn captured_packed_programs() -> Vec<(String, String)> {
        let mut out = Vec::new();
        let js_dir = Path::new("artifacts/re-out/solvegate-invisible/js");
        let html_dir = Path::new("artifacts/re-out/solvegate-invisible/html");
        let mut rays = Vec::new();
        if html_dir.is_dir() {
            for entry in std::fs::read_dir(html_dir).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().and_then(|s| s.to_str()) != Some("html") {
                    continue;
                }
                let html = std::fs::read_to_string(&path).unwrap_or_default();
                if let Ok(opt) = CloudflareChallengeOptions::from_html(&html)
                    && opt.c_ray.len() == 16
                    && !rays.contains(&opt.c_ray)
                {
                    rays.push(opt.c_ray);
                }
                if let Some(inline) = extract_inline_packed(&html) {
                    out.push((format!("{}#inline", path.display()), inline));
                }
            }
        }
        if rays.is_empty() {
            rays.push("a2e9de8f39a58015".to_string());
        }
        if js_dir.is_dir() {
            for entry in std::fs::read_dir(js_dir).unwrap() {
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
                    if let Ok(plain) = decrypt_padded(ray, &body)
                        && plain.starts_with(PACKED_RUN_PROGRAM_PREFIX)
                    {
                        out.push((path.display().to_string(), plain));
                        break;
                    }
                }
            }
        }
        out
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
    }

    fn extract_inline_packed(html: &str) -> Option<String> {
        let needle = format!("runProgram(`{PACKED_RUN_PROGRAM_PREFIX}");
        let start = html.find(&needle)? + "runProgram(`".len();
        let rest = &html[start..];
        let end = rest.find('`')?;
        Some(rest[..end].to_string())
    }

    #[test]
    fn captured_programs_share_magic_and_unpack_if_present() {
        let programs = captured_packed_programs();
        if programs.is_empty() {
            return;
        }
        let mut bytecodes = Vec::new();
        for (label, packed) in &programs {
            let report = analyze_packed_run_program(packed);
            assert!(report.magic_ok && report.decode_ok, "{label}: {report:?}");
            assert!(!report.looks_like_javascript, "{label} decoded as JS");
            assert!(!report.looks_like_zlib, "{label} looked like zlib");
            assert_eq!(report.next_gap, crate::solver::run_program_vm::NEXT_GAP);
            assert!(
                report.body_entropy_bits > 6.5,
                "{label} body entropy {}",
                report.body_entropy_bits
            );
            bytecodes.push(unpack_packed_run_program(packed).unwrap());
        }
        for bc in &bytecodes {
            assert!(
                crate::solver::run_program_vm::params_for_magic(bc).is_some(),
                "unknown magic {:02x?}",
                &bc[..RUN_PROGRAM_MAGIC_LEN.min(bc.len())]
            );
            let (params, table) = crate::solver::run_program_vm::params_for_magic(bc)
                .expect("captured bytecode magic");
            let stream =
                crate::solver::run_program_vm::naive_one_byte_fetches(bc, params, table, 8);
            assert!(
                stream.fetches[0].mapped,
                "magic + documented init must land on a switch opcode, got {}",
                stream.fetches[0].opcode
            );
        }
    }
}
