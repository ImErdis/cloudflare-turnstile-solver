//! Static unpack of a packed `runProgram` blob.
//!
//! This does **not** interpret opcodes or talk to Cloudflare. Pass either a
//! ray-decrypted packed string, or a captured `/fo/` body plus `--ray`.
//!
//! ```text
//! cargo run --locked --bin analyze_run_program -- --ray <c_ray> path/to/fo_body.js
//! cargo run --locked --bin analyze_run_program -- packed.txt
//! ```

use anyhow::{Context, Result, bail};
use cf::reverse::encryption::decrypt_cloudflare_response;
use cf::{analyze_fo_body, analyze_packed_run_program};
use serde_json::json;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let code = match run() {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            0
        }
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<serde_json::Value> {
    let mut ray = None;
    let mut files = Vec::<PathBuf>::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--ray" {
            ray = Some(args.next().context("--ray needs a 16-hex c_ray")?);
        } else if arg.starts_with('-') {
            bail!("unknown flag {arg}");
        } else {
            files.push(PathBuf::from(arg));
        }
    }
    if files.is_empty() {
        bail!("usage: analyze_run_program [--ray <c_ray>] <file>...");
    }

    let mut reports = Vec::new();
    for path in files {
        let raw = fs::read_to_string(&path).with_context(|| path.display().to_string())?;
        let packed = if let Some(ray) = ray.as_deref() {
            let fo = analyze_fo_body(ray, &raw);
            if !fo.looks_like_packed_run_program {
                reports.push(json!({
                    "path": path.display().to_string(),
                    "kind": "not_packed_fo",
                    "fo": fo,
                }));
                continue;
            }
            decrypt_fo(ray, &raw)?
        } else {
            raw.trim().to_string()
        };
        let analysis = analyze_packed_run_program(&packed);
        reports.push(json!({
            "path": path.display().to_string(),
            "kind": if ray.is_some() { "fo_decrypted" } else { "packed_plaintext" },
            "analysis": analysis,
            "summary": analysis.summary(),
        }));
    }
    Ok(json!({ "ok": true, "reports": reports }))
}

fn decrypt_fo(ray: &str, data: &str) -> Result<String> {
    let compact: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = match compact.len() % 4 {
        0 => compact,
        2 => format!("{compact}=="),
        3 => format!("{compact}="),
        _ => compact,
    };
    decrypt_cloudflare_response(ray, &padded)
}
