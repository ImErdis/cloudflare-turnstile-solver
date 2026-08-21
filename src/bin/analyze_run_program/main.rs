//! Static unpack / opcode-fetch of a packed `runProgram` blob.
//!
//! This does **not** run handlers, reconstruct a live `/fo/` body, or talk to Cloudflare
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
use cf::solver::run_program::unpack_packed_run_program;
use cf::solver::run_program_ops::{
    DN_OPCODE, DN_TAG_STRING, XF_TAG_STRING, classify_pc_delta, first_dn_tag_b, first_xf_tag_late,
    operand_from_byte,
};
use cf::solver::run_program_vm::{
    FETCH_BRANCH_B, FETCH_LIVE, naive_one_byte_fetches, opcode_def_in, params_for_magic,
    params_from_oracle_fetch, verify_oracle_tuple,
};
use cf::solver::fo_body::{
    CHARSET_BRANCH_B, body_chars_in_charset, charset_is_well_formed, classify_fo_body_len,
};
use cf::{
    analyze_fo_body, analyze_packed_run_program, compare_chrome_and_crate_fo_post, LIVE_FO_WRAPPER,
};
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
            let (params, table) = params_for_magic(&bytecode).unwrap_or((FETCH_LIVE, cf::solver::run_program_vm::OPCODE_TABLE));
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
    let fetch = v.get("fetch").cloned().unwrap_or(v.clone());
    let params = params_from_oracle_fetch(
        fetch.get("init_key").and_then(|x| x.as_u64()).unwrap_or(0) as u8,
        fetch.get("byte_bias").and_then(|x| x.as_u64()).unwrap_or(0) as u8,
        fetch.get("key_mul").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
    )
    .unwrap_or(FETCH_BRANCH_B);
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
        if let Err(e) = verify_oracle_tuple(params, pc, key, byte, op) {
            errors.push(format!("fetch {i}: {e}"));
        }
        if byte != 0 || key != 0 {
            // Operand path: post-fetch key is `next_key`, not the fetch key.
            let _ = operand_from_byte(params, key, byte, 0);
        }
    }
    if let Some(late) = v.get("laterSameDay") {
        let late_fetch = late.get("fetch").cloned().unwrap_or(late.clone());
        if let Some(lp) = params_from_oracle_fetch(
            late_fetch.get("init_key").and_then(|x| x.as_u64()).unwrap_or(0) as u8,
            late_fetch
                .get("byte_bias")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u8,
            late_fetch.get("key_mul").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        ) {
            let lf = late
                .get("fetches")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            for (i, f) in lf.iter().enumerate() {
                let pc = f.get("pc").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let key = f.get("key").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
                let byte = f.get("byte").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
                let op = f
                    .get("op")
                    .or_else(|| f.get("opcode"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0) as u8;
                if let Err(e) = verify_oracle_tuple(lp, pc, key, byte, op) {
                    errors.push(format!("laterSameDay fetch {i}: {e}"));
                }
            }
            if late.get("firstXfTag").and_then(|x| x.as_u64()) != Some(u64::from(XF_TAG_STRING)) {
                errors.push("laterSameDay firstXfTag should be 199 (string)".into());
            }
            let _ = first_xf_tag_late(&[0xef, 0x51]);
        } else {
            errors.push("laterSameDay fetch constants did not match FETCH_BRANCH_B_LATE".into());
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
    if let Some(tag) = first_tag
        && tag != DN_TAG_STRING
    {
        errors.push(format!(
            "first dN tag {tag}, expected string tag {DN_TAG_STRING} for TX5omy48 magic"
        ));
    }
    let first_op = fetches
        .first()
        .and_then(|f| f.get("op").or_else(|| f.get("opcode")))
        .and_then(|x| x.as_u64())
        .map(|n| n as u8);
    if first_op == Some(DN_OPCODE) || first_tag.is_some() {
        let _ = first_dn_tag_b(&[0x4d, 0x7e]);
    }
    let fo_body = v
        .pointer("/laterSameDay/foBody")
        .or_else(|| v.get("foBody"))
        .cloned();
    let mut fo_prefix_ok = 0usize;
    if let Some(fo) = &fo_body {
        let charset = fo
            .get("charset")
            .and_then(|x| x.as_str())
            .unwrap_or(CHARSET_BRANCH_B);
        if !charset_is_well_formed(charset) {
            errors.push("foBody.charset is not a 65-char custom alphabet".into());
        }
        if fo.get("compressorLiveName").and_then(|x| x.as_str()) != Some("f4") {
            errors.push("foBody.compressorLiveName should be f4".into());
        }
        if let Some(prefs) = fo.get("prefixes").and_then(|x| x.as_array()) {
            for (i, p) in prefs.iter().enumerate() {
                let s = p.as_str().unwrap_or("");
                if body_chars_in_charset(s, charset) {
                    fo_prefix_ok += 1;
                } else {
                    errors.push(format!("foBody prefix {i} not in charset"));
                }
            }
        }
        if let Some(lens) = fo.get("initLens").and_then(|x| x.as_array()) {
            for (i, n) in lens.iter().enumerate() {
                let len = n.as_u64().unwrap_or(0) as usize;
                if classify_fo_body_len(len) != cf::solver::fo_body::FoBodyLenBand::Init {
                    errors.push(format!("foBody initLens[{i}]={len} not in init band"));
                }
            }
        }
        if let Some(lens) = fo.get("followUpLens").and_then(|x| x.as_array()) {
            for (i, n) in lens.iter().enumerate() {
                let len = n.as_u64().unwrap_or(0) as usize;
                if classify_fo_body_len(len) != cf::solver::fo_body::FoBodyLenBand::FollowUp {
                    errors.push(format!(
                        "foBody followUpLens[{i}]={len} not in follow-up band"
                    ));
                }
            }
        }
    }
    Ok(json!({
        "ok": errors.is_empty(),
        "path": path.display().to_string(),
        "params_label": params.label,
        "fetch_count": fetches.len(),
        "pc_delta_count": deltas.len(),
        "widths": width_rows,
        "first_dn_tag": first_tag,
        "errors": errors,
        "header_compare": compare_chrome_and_crate_fo_post(),
        "fo_wrapper": LIVE_FO_WRAPPER,
        "fo_prefix_ok": fo_prefix_ok,
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
