//! Static unpack / opcode-fetch of a packed `runProgram` blob.
//!
//! This does **not** run handlers, reconstruct `wZ`, or talk to Cloudflare
//! unless you pass a captured file. Pass a ray-decrypted packed string, a
//! captured `/fo/` body plus `--ray`, and optionally `--decode N` for the
//! 1-byte naive walk (diverges at the first mapped handler).
//!
//! ```text
//! cargo run --locked --bin analyze_run_program -- --ray <c_ray> path/to/fo_body.js
//! cargo run --locked --bin analyze_run_program -- --decode 16 packed.txt
//! cargo run --locked --bin analyze_run_program -- --oracle scripts/fixtures/headed_chrome_oracle.json
//! ```

use anyhow::{Context, Result, bail};
use cf::reverse::encryption::decrypt_cloudflare_response;
use cf::solver::run_program::{RUN_PROGRAM_MAGIC_BYTES_B, unpack_packed_run_program};
use cf::solver::run_program_ops::{
    DN_OPCODE, DN_TAG_STRING, classify_pc_delta, first_dn_tag_b, operand_from_byte,
};
use cf::solver::run_program_vm::{
    FETCH_BRANCH_B, FETCH_BRANCH_G, FETCH_LIVE, OPCODE_TABLE_B, OPCODE_TABLE_G,
    naive_one_byte_fetches, opcode_def_in, verify_oracle_tuple,
};
use cf::{analyze_fo_body, analyze_packed_run_program, compare_chrome_and_crate_fo_post};
use serde_json::{Value, json};
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
    let mut ray = None;
    let mut decode_n: usize = 0;
    let mut oracle: Option<PathBuf> = None;
    let mut files = Vec::<PathBuf>::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--ray" {
            ray = Some(args.next().context("--ray needs a 16-hex c_ray")?);
        } else if arg == "--decode" {
            let n = args.next().unwrap_or_else(|| "16".to_string());
            decode_n = n.parse().context("--decode needs a count")?;
        } else if arg == "--oracle" {
            oracle = Some(PathBuf::from(
                args.next().context("--oracle needs a json path")?,
            ));
        } else if arg.starts_with('-') {
            bail!("unknown flag {arg}");
        } else {
            files.push(PathBuf::from(arg));
        }
    }

    if let Some(path) = oracle {
        return verify_oracle_file(&path);
    }

    if files.is_empty() {
        bail!("usage: analyze_run_program [--ray <c_ray>] [--decode N] [--oracle json] <file>...");
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
        let mut row = json!({
            "path": path.display().to_string(),
            "kind": if ray.is_some() { "fo_decrypted" } else { "packed_plaintext" },
            "analysis": analysis,
            "summary": analysis.summary(),
        });
        if decode_n > 0 && analysis.decode_ok {
            let bytecode = unpack_packed_run_program(&packed)?;
            let (params, table) = if bytecode.starts_with(&RUN_PROGRAM_MAGIC_BYTES_B) {
                (FETCH_BRANCH_B, OPCODE_TABLE_B)
            } else {
                (FETCH_BRANCH_G, OPCODE_TABLE_G)
            };
            let stream = naive_one_byte_fetches(&bytecode, params, table, decode_n);
            let fetches: Vec<Value> = stream
                .fetches
                .iter()
                .map(|f| {
                    json!({
                        "pc": f.pc,
                        "key": f.key,
                        "byte": f.byte,
                        "opcode": f.opcode,
                        "next_key": f.next_key,
                        "mapped": f.mapped,
                        "handler": opcode_def_in(table, f.opcode).map(|d| d.handler),
                    })
                })
                .collect();
            row["naive_fetches"] = json!({
                "note": "1-byte walk; diverges at the first mapped handler that reads immediates",
                "init_pc": stream.init_pc,
                "init_key": stream.init_key,
                "stopped": stream.stopped,
                "first_mapped": stream.first_mapped,
                "fetches": fetches,
            });
        }
        reports.push(row);
    }
    Ok(json!({
        "ok": true,
        "header_compare": compare_chrome_and_crate_fo_post(),
        "reports": reports,
    }))
}

fn verify_oracle_file(path: &PathBuf) -> Result<Value> {
    let raw = fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let v: Value = serde_json::from_str(&raw)?;
    let mut errors = Vec::new();
    let fetches = v
        .get("opcodeFetches")
        .or_else(|| v.get("fetches"))
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    for (i, f) in fetches.iter().enumerate() {
        let pc = f.get("pc").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
        let key = f.get("key").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
        let byte = f
            .get("byte")
            .or_else(|| f.get("b"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u8;
        let op = f
            .get("op")
            .or_else(|| f.get("opcode"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u8;
        if let Err(e) = verify_oracle_tuple(FETCH_LIVE, pc, key, byte, op) {
            errors.push(format!("fetch {i}: {e}"));
        }
        if byte != 0 || key != 0 {
            // Operand path: post-fetch key is `next_key`, not the fetch key.
            let _ = operand_from_byte(FETCH_LIVE, key, byte, 0);
        }
    }
    let deltas = v
        .get("pcDeltas")
        .or_else(|| v.get("pc_deltas"))
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let mut width_rows = Vec::new();
    for d in &deltas {
        let op = d
            .get("op")
            .or_else(|| d.get("opcode"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u8;
        let width = d.get("width").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
        width_rows.push(classify_pc_delta(op, width));
    }
    let first_tag = v
        .get("firstDnTag")
        .or_else(|| v.get("first_dn_tag"))
        .and_then(|x| x.as_u64())
        .map(|n| n as u8);
    if let Some(tag) = first_tag {
        if tag != DN_TAG_STRING {
            errors.push(format!(
                "first dN tag {tag}, expected string tag {DN_TAG_STRING} for TX5omy48 magic"
            ));
        }
    }
    let first_op = fetches
        .first()
        .and_then(|f| f.get("op").or_else(|| f.get("opcode")))
        .and_then(|x| x.as_u64())
        .map(|n| n as u8);
    if first_op == Some(DN_OPCODE) || first_tag.is_some() {
        let _ = first_dn_tag_b(&[0x4d, 0x7e]);
    }
    Ok(json!({
        "ok": errors.is_empty(),
        "path": path.display().to_string(),
        "fetch_count": fetches.len(),
        "pc_delta_count": deltas.len(),
        "widths": width_rows,
        "first_dn_tag": first_tag,
        "errors": errors,
        "header_compare": compare_chrome_and_crate_fo_post(),
        "first": fetches.first(),
    }))
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
