use anyhow::{Context, Result};
use cf::deobfuscator::deobfuscate;
use cf::disassembler::disassemble::parse_script_interpreter;
use oxc_allocator::Allocator;
use oxc_codegen::Codegen;
use serde_json::{json, Value};
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

fn run() -> Result<Value> {
    let path = PathBuf::from(
        env::args()
            .nth(1)
            .context("usage: analyze_js <file.js> [--write-deobfuscated <out.js>]")?,
    );
    let write_out = env::args()
        .position(|a| a == "--write-deobfuscated")
        .and_then(|i| env::args().nth(i + 1));

    let source = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let mut report = json!({
        "path": path.display().to_string(),
        "bytes": source.len(),
        "markers": {
            "cf_chl_opt": source.contains("_cf_chl_opt"),
            "window_cf_chl_opt": source.contains("window._cf_chl_opt"),
            "orchestrate": source.contains("orchestrate"),
            "turnstile": source.to_ascii_lowercase().contains("turnstile"),
            "challenge_platform": source.contains("challenge-platform"),
        }
    });

    let allocator = Allocator::new();
    let program = deobfuscate(&source, &allocator, true);
    let generated = Codegen::new().build(program).code;
    report["deobfuscated_bytes"] = json!(generated.len());

    if let Some(out) = write_out {
        fs::write(&out, &generated).with_context(|| format!("write {out}"))?;
        report["wrote"] = json!(out);
    }

    match parse_script_interpreter(program, &allocator) {
        Ok((_, vm, keys, create_ident, opcode_fn, opcode_map)) => {
            report["interpreter"] = json!({
                "ok": true,
                "create_function_ident": create_ident,
                "function_with_opcodes": opcode_fn,
                "opcode_count": opcode_map.len(),
                "opcode_names": opcode_map.values().cloned().collect::<Vec<_>>(),
                "has_initial_vm": vm.initial_vm.is_some(),
                "initial_vm_b64_prefix": vm.initial_vm.as_ref().map(|s| s.chars().take(48).collect::<String>()),
                "browser_keys_key": keys.browser_keys_key,
                "initial_keys_count": keys.initial_keys.len(),
                "initial_obj_keys_count": keys.initial_obj_keys.len(),
            });
        }
        Err(e) => {
            report["interpreter"] = json!({
                "ok": false,
                "error": e.to_string(),
            });
        }
    }

    Ok(report)
}
