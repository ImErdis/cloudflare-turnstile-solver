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
//! cargo run --locked --bin analyze_run_program -- --skip-harvest packed.txt
//! cargo run --locked --bin analyze_run_program -- --oracle scripts/fixtures/headed_chrome_oracle.json
//! cargo run --locked --bin analyze_run_program -- --verify-case-tuples artifacts/re-out/chrome-oracle-tuples6/oracle.json
//! ```

use anyhow::{Context, Result, bail};
use cf::reverse::encryption::decrypt_cloudflare_response;
use cf::solver::run_program::unpack_packed_run_program;
use cf::solver::run_program_skip::skip_harvest_live;
use cf::solver::run_program_ops::{
    CALL_IMM_ROLES_B_LATE, DN_OPCODE, DN_TAG_STRING, HANDLER_LAYOUT_B_LATE, JUMP_IMM_ROLES_B_LATE,
    LATE_DIRECT_HANDLER_COUNT, LEB_OBJECT_ROLES_B_LATE, PROPERTY_IMM_ROLES_B_LATE, S1_CASES_B_LATE,
    S1_HTML_HANDLER, S2_CASES_B_LATE, S2_HTML_HANDLER, XD_MIX_SEED, XD_SLOT_XOR, XF_TAG_CASES,
    XF_TAG_STRING, XI_TYPE_CASES, XP_TAG_CASES, classify_pc_delta, classify_pc_delta_late,
    first_dn_tag_b, first_xf_tag_late, operand_from_byte,
};
use cf::solver::run_program_vm::{
    FETCH_BRANCH_B, FETCH_LIVE, FetchParams, naive_one_byte_fetches, opcode_def_in,
    next_key, params_for_magic, params_from_oracle_fetch, verify_oracle_tuple,
    verify_oracle_tuple_next_key,
};
use cf::solver::fo_body::{
    CHARSET_BRANCH_B, body_chars_in_charset, charset_is_well_formed, classify_fo_body_len,
};
use cf::solver::fo_followup::{
    BODY_ENCODER_LIVE_NAME, DEBUG_LOGGER_LIVE_NAME, LIVE_FO_FOLLOWUP, LIVE_RUN_PROGRAM_RETURN,
    SEND_HELPER_LIVE_NAME, classify_fo_response_len, FoResponseLenBand,
};
use cf::solver::fo_init_json::{
    INIT_JSON_KEY_COUNT, INIT_JSON_KEYS_B, LIVE_FO_INIT_JSON, keys_match_snapshot,
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
    let mut case_tuples: Option<PathBuf> = None;
    let mut skip_harvest = false;
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
        } else if arg == "--verify-case-tuples" {
            case_tuples = Some(PathBuf::from(
                args.next().context("--verify-case-tuples needs an oracle.json path")?,
            ));
        } else if arg == "--skip-harvest" {
            skip_harvest = true;
        } else if arg.starts_with('-') {
            bail!("unknown flag {arg}");
        } else {
            files.push(PathBuf::from(arg));
        }
    }

    if let Some(path) = oracle {
        return verify_oracle_file(&path);
    }
    if let Some(path) = case_tuples {
        return verify_case_tuples_file(&path);
    }

        if files.is_empty() {
        bail!("usage: analyze_run_program [--ray <c_ray>] [--decode N] [--skip-harvest] [--oracle json] [--verify-case-tuples oracle.json] <file>...");
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
        if skip_harvest && analysis.decode_ok {
            let bytecode = unpack_packed_run_program(&packed)?;
            let h = skip_harvest_live(&bytecode);
            let extra: Vec<&str> = cf::FOLLOWUP_EXTRA_IDENT_B
                .iter()
                .copied()
                .filter(|n| h.contains_ident(n))
                .collect();
            let unseen: Vec<&str> = cf::FOLLOWUP_UNSEEN_EXTRA_IDENT_B
                .iter()
                .copied()
                .filter(|n| h.contains_ident(n))
                .collect();
            row["skipHarvest"] = json!({
                "note": "width-aware skip of immediates; does not execute handlers",
                "paramsLabel": h.params_label,
                "instructions": h.instructions,
                "lastPc": h.last_pc,
                "lastOpcode": h.last_opcode,
                "stopped": h.stopped,
                "stringCount": h.strings.len(),
                "geKeyImm1to39": h.ge_key_imms.iter().any(|k| (1..=39).contains(k)),
                "extraIdentHits": extra,
                "unseenIdentHits": unseen,
            });
        }
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

/// HTML spelling seen on the 2026-08-22 SolveGate iframe (`23196*(mix*mix)+mix*32619+19372`).
/// Candidate only — not `FETCH_LIVE`. Used to test case-label harvest rows.
const HTML_CANDIDATE_23196: FetchParams = FetchParams {
    label: "html-candidate-23196",
    init_pc: 0,
    init_key: 63,
    byte_bias: 217,
    key_mul: 23_196,
    key_add: 19_372,
    key_quad_b: 32_619,
};

fn row_has_op_byte(f: &Value) -> bool {
    let op = f.get("op").or_else(|| f.get("caseOp")).and_then(|x| x.as_u64());
    let byte = f.get("byte").and_then(|x| x.as_u64());
    op.is_some() && byte.is_some()
}

fn row_has_fetch_key(f: &Value) -> bool {
    f.get("key").and_then(|x| x.as_u64()).is_some()
}

fn row_has_next_key(f: &Value) -> bool {
    f.get("nextKey")
        .or_else(|| f.get("next_key"))
        .and_then(|x| x.as_u64())
        .is_some()
}

/// Prefer inject `{pc,op,key,byte}` over case-label `{pc,op,byte,nextKey}`.
/// Empty `fetchLoopTuples` must not hide `opcodeFetches`.
fn harvest_tuple_rows(v: &Value) -> Vec<Value> {
    let loop_rows = v
        .get("fetchLoopTuples")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let op_rows = v
        .get("opcodeFetches")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let complete: Vec<Value> = op_rows
        .iter()
        .chain(loop_rows.iter())
        .filter(|f| row_has_op_byte(f) && row_has_fetch_key(f))
        .cloned()
        .collect();
    if !complete.is_empty() {
        return complete;
    }
    loop_rows
        .iter()
        .chain(op_rows.iter())
        .filter(|f| row_has_op_byte(f) && row_has_next_key(f))
        .cloned()
        .collect()
}

fn html_candidate_from_oracle(v: &Value) -> Option<FetchParams> {
    let fs = v.get("fetchSchedule")?;
    let mul = fs.get("keyMul")?.as_u64()? as u32;
    let add = fs.get("keyAdd")?.as_u64()? as u32;
    let bias = fs.get("byteBias")?.as_u64()? as u8;
    let init = fs.get("initKeyCandidate")?.as_u64()? as u8;
    let quad = fs.get("keyQuadB").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    if mul == 0 {
        return None;
    }
    Some(FetchParams {
        label: "html-candidate",
        init_pc: 0,
        init_key: init,
        byte_bias: bias,
        key_mul: mul,
        key_add: add,
        key_quad_b: quad,
    })
}

fn verify_case_tuples_file(path: &PathBuf) -> Result<Value> {
    let raw = fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let v: Value = serde_json::from_str(&raw)?;
    let rows = harvest_tuple_rows(&v);
    let marker = v
        .get("events")
        .and_then(|e| e.as_array())
        .into_iter()
        .flatten()
        .find(|e| e.get("kind").and_then(|k| k.as_str()) == Some("scriptFetchConst"))
        .and_then(|e| e.get("marker").and_then(|m| m.as_str()))
        .unwrap_or("");
    let mut candidates = vec![FETCH_LIVE];
    if let Some(html) = html_candidate_from_oracle(&v) {
        if html.key_mul != FETCH_LIVE.key_mul {
            candidates.push(html);
        }
    } else if marker == "23196" {
        candidates.push(HTML_CANDIDATE_23196);
    }
    let mut reports = Vec::new();
    for params in candidates {
        let mut ok = 0u32;
        let mut fail = Vec::new();
        let mut recovered = Vec::new();
        for (i, f) in rows.iter().enumerate() {
            let pc = f.get("pc").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let byte = f.get("byte").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
            let op = f
                .get("op")
                .or_else(|| f.get("caseOp"))
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u8;
            let fetch_key = f.get("key").and_then(|x| x.as_u64()).map(|n| n as u8);
            let next_k = f
                .get("nextKey")
                .or_else(|| f.get("next_key"))
                .and_then(|x| x.as_u64())
                .map(|n| n as u8);
            let result = if let Some(key) = fetch_key {
                verify_oracle_tuple(params, pc, key, byte, op).map(|()| key)
            } else if let Some(nk) = next_k {
                verify_oracle_tuple_next_key(params, pc, op, byte, nk)
            } else {
                Err("missing key and nextKey".to_string())
            };
            match result {
                Ok(key) => {
                    ok += 1;
                    recovered.push(json!({
                        "i": i,
                        "pc": pc,
                        "op": op,
                        "byte": byte,
                        "nextKey": next_k,
                        "fetchKey": key,
                    }));
                }
                Err(e) => fail.push(json!({
                    "i": i,
                    "pc": pc,
                    "op": op,
                    "byte": byte,
                    "nextKey": next_k,
                    "key": fetch_key,
                    "error": e,
                })),
            }
        }
        let mut chain_fail = Vec::new();
        if rows.iter().all(row_has_fetch_key) && rows.len() >= 2 {
            for w in rows.windows(2) {
                let k0 = w[0].get("key").and_then(|x| x.as_u64()).unwrap() as u8;
                let op0 = w[0]
                    .get("op")
                    .or_else(|| w[0].get("caseOp"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0) as u8;
                let k1 = w[1].get("key").and_then(|x| x.as_u64()).unwrap() as u8;
                let got = next_key(params, k0, op0);
                if got != k1 {
                    chain_fail.push(json!({
                        "pc": w[0].get("pc"),
                        "op": op0,
                        "key": k0,
                        "nextRowKey": k1,
                        "expectedNextKey": got,
                    }));
                }
            }
        }
        reports.push(json!({
            "label": params.label,
            "keyMul": params.key_mul,
            "ok": ok,
            "fail": fail.len(),
            "recovered": recovered,
            "errors": fail,
            "keyChainFail": chain_fail,
            "allOk": fail.is_empty() && ok > 0 && chain_fail.is_empty(),
        }));
    }
    Ok(json!({
        "path": path.display().to_string(),
        "rowCount": rows.len(),
        "marker": marker,
        "note": "HTML candidate is a test only. Do not assign FETCH_LIVE. Quote mismatches.",
        "candidates": reports,
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
            if let Some(widths) = late.get("chromeStableWidths") {
                let checks = [
                    ("gq_246", 246u8, 3i32),
                    ("gG_227", 227, 4),
                    ("X3_104", 104, 2),
                    ("gY_72", 72, 5),
                    ("X4_12", 12, 2),
                    ("Xz_52", 52, 3),
                    ("Xg_130", 130, 3),
                    ("ge_169", 169, 5),
                ];
                for (key, op, width) in checks {
                    if widths.get(key).and_then(|x| x.as_i64()) != Some(i64::from(width)) {
                        errors.push(format!("laterSameDay.chromeStableWidths.{key} should be {width}"));
                    }
                    let row = classify_pc_delta_late(op, width);
                    if row.matches_fixed != Some(true) {
                        errors.push(format!("late opcode {op} width {width} does not match layout"));
                    }
                }
            }
            if let Some(extras) = late.get("operandExtras") {
                for h in HANDLER_LAYOUT_B_LATE {
                    let row = extras.get(h.handler);
                    let got = row
                        .and_then(|r| r.get("extras"))
                        .and_then(|x| x.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_u64().map(|n| n as u8))
                                .collect::<Vec<_>>()
                        });
                    if got.as_deref() != Some(h.extra_xors) {
                        errors.push(format!(
                            "laterSameDay.operandExtras.{} extras mismatch",
                            h.handler
                        ));
                    }
                    if let Some(fam) = row.and_then(|r| r.get("family")).and_then(|x| x.as_str())
                        && fam != h.family
                    {
                        errors.push(format!(
                            "laterSameDay.operandExtras.{} family mismatch",
                            h.handler
                        ));
                    }
                }
                if late.get("directHandlerCount").and_then(|x| x.as_u64())
                    != Some(LATE_DIRECT_HANDLER_COUNT as u64)
                {
                    errors.push(format!(
                        "laterSameDay.directHandlerCount should be {LATE_DIRECT_HANDLER_COUNT}"
                    ));
                }
            }
            if let Some(xf) = late.get("xfTagCases") {
                let cases = xf.get("cases").and_then(|x| x.as_array());
                if cases.map(|c| c.len()) != Some(XF_TAG_CASES.len()) {
                    errors.push("laterSameDay.xfTagCases.cases length mismatch".into());
                } else if let Some(cases) = cases {
                    for (c, row) in XF_TAG_CASES.iter().zip(cases) {
                        if row.get("tag").and_then(|x| x.as_u64()) != Some(u64::from(c.tag))
                            || row.get("kind").and_then(|x| x.as_str()) != Some(c.kind)
                        {
                            errors.push(format!("xfTagCases mismatch at {}", c.kind));
                        }
                    }
                }
                if xf.get("defaultKind").and_then(|x| x.as_str()) != Some("true") {
                    errors.push("xfTagCases.defaultKind should be true".into());
                }
            }
            if let Some(props) = late.get("propertyImmRoles").and_then(|x| x.as_array()) {
                if props.len() != PROPERTY_IMM_ROLES_B_LATE.len() {
                    errors.push("laterSameDay.propertyImmRoles length mismatch".into());
                }
                for (p, row) in PROPERTY_IMM_ROLES_B_LATE.iter().zip(props) {
                    if row.get("assign").and_then(|x| x.as_str()) != Some(p.assign) {
                        errors.push(format!("propertyImmRoles.{} assign mismatch", p.handler));
                    }
                }
            }
            if let Some(leb) = late.get("lebObjectRoles").and_then(|x| x.as_array()) {
                if leb.len() != LEB_OBJECT_ROLES_B_LATE.len() {
                    errors.push("laterSameDay.lebObjectRoles length mismatch".into());
                }
                for (r, row) in LEB_OBJECT_ROLES_B_LATE.iter().zip(leb) {
                    if row.get("role").and_then(|x| x.as_str()) != Some(r.role)
                        || row.get("assign").and_then(|x| x.as_str()) != Some(r.assign)
                    {
                        errors.push(format!("lebObjectRoles.{} mismatch", r.handler));
                    }
                }
            }
            if let Some(xp) = late.get("xpTagCases") {
                let cases = xp.get("cases").and_then(|x| x.as_array());
                if cases.map(|c| c.len()) != Some(XP_TAG_CASES.len()) {
                    errors.push("laterSameDay.xpTagCases.cases length mismatch".into());
                } else if let Some(cases) = cases {
                    for (c, row) in XP_TAG_CASES.iter().zip(cases) {
                        if row.get("tag").and_then(|x| x.as_u64()) != Some(u64::from(c.tag))
                            || row.get("kind").and_then(|x| x.as_str()) != Some(c.kind)
                        {
                            errors.push(format!("xpTagCases mismatch at {}", c.kind));
                        }
                    }
                }
            }
            if let Some(calls) = late.get("callImmRoles").and_then(|x| x.as_array()) {
                if calls.len() != CALL_IMM_ROLES_B_LATE.len() {
                    errors.push("laterSameDay.callImmRoles length mismatch".into());
                }
                for (c, row) in CALL_IMM_ROLES_B_LATE.iter().zip(calls) {
                    if row.get("callee").and_then(|x| x.as_str()) != Some(c.callee)
                        || row.get("arity").and_then(|x| x.as_str()) != Some(c.arity)
                    {
                        errors.push(format!("callImmRoles.{} mismatch", c.handler));
                    }
                }
            }
            if let Some(jumps) = late.get("jumpImmRoles").and_then(|x| x.as_array()) {
                if jumps.len() != JUMP_IMM_ROLES_B_LATE.len() {
                    errors.push("laterSameDay.jumpImmRoles length mismatch".into());
                }
                for (j, row) in JUMP_IMM_ROLES_B_LATE.iter().zip(jumps) {
                    if row.get("condition").and_then(|x| x.as_str()) != Some(j.condition)
                        || row.get("paths").and_then(|x| x.as_str()) != Some(j.paths)
                    {
                        errors.push(format!("jumpImmRoles.{} mismatch", j.handler));
                    }
                }
            }
            if let Some(xi) = late.get("xiTypeCases") {
                let cases = xi.get("cases").and_then(|x| x.as_array());
                if cases.map(|c| c.len()) != Some(XI_TYPE_CASES.len()) {
                    errors.push("laterSameDay.xiTypeCases.cases length mismatch".into());
                } else if let Some(cases) = cases {
                    for (c, row) in XI_TYPE_CASES.iter().zip(cases) {
                        if row.get("kind").and_then(|x| x.as_str()) != Some(c.kind) {
                            errors.push(format!("xiTypeCases mismatch at {}", c.kind));
                        }
                    }
                }
            }
            if let Some(xd) = late.get("xdMix")
                && (xd.get("seed").and_then(|x| x.as_u64()) != Some(u64::from(XD_MIX_SEED))
                    || xd.get("slotXor").and_then(|x| x.as_u64()) != Some(u64::from(XD_SLOT_XOR)))
            {
                errors.push("laterSameDay.xdMix mismatch".into());
            }
            if let Some(s1) = late.get("s1Cases").and_then(|x| x.as_array()) {
                if s1.len() != S1_CASES_B_LATE.len() {
                    errors.push("laterSameDay.s1Cases length mismatch".into());
                }
                for (c, row) in S1_CASES_B_LATE.iter().zip(s1) {
                    if row.get("imm").and_then(|x| x.as_u64()) != Some(u64::from(c.imm))
                        || row.get("kind").and_then(|x| x.as_str()) != Some(c.kind)
                    {
                        errors.push(format!("s1Cases opcode {} mismatch", c.opcode));
                    }
                }
            }
            if let Some(s2) = late.get("s2Cases").and_then(|x| x.as_array()) {
                if s2.len() != S2_CASES_B_LATE.len() {
                    errors.push("laterSameDay.s2Cases length mismatch".into());
                }
                for (c, row) in S2_CASES_B_LATE.iter().zip(s2) {
                    if row.get("imm").and_then(|x| x.as_u64()) != Some(u64::from(c.imm))
                        || row.get("kind").and_then(|x| x.as_str()) != Some(c.kind)
                    {
                        errors.push(format!("s2Cases opcode {} mismatch", c.opcode));
                    }
                }
            }
            if late.get("s1HtmlHandler").and_then(|x| x.as_str()) != Some(S1_HTML_HANDLER) {
                errors.push("laterSameDay.s1HtmlHandler should be gS".into());
            }
            if late.get("s2HtmlHandler").and_then(|x| x.as_str()) != Some(S2_HTML_HANDLER) {
                errors.push("laterSameDay.s2HtmlHandler should be gK".into());
            }
            if let Some(fu) = late.get("foFollowUp") {
                if fu.get("plaintextKind").and_then(|x| x.as_str())
                    != Some("compressed_blob_after_runProgram")
                {
                    errors.push("foFollowUp.plaintextKind should be compressed_blob_after_runProgram".into());
                }
                if fu.get("notPackedProgram") != Some(&Value::Bool(true)) {
                    errors.push("foFollowUp.notPackedProgram should be true".into());
                }
                if fu.get("sameNWrapper") != Some(&Value::Bool(true)) {
                    errors.push("foFollowUp.sameNWrapper should be true".into());
                }
                if fu.get("sendHelper").and_then(|x| x.as_str()) != Some(SEND_HELPER_LIVE_NAME) {
                    errors.push("foFollowUp.sendHelper should be fj".into());
                }
                if fu.get("debugLogger").and_then(|x| x.as_str()) != Some(DEBUG_LOGGER_LIVE_NAME) {
                    errors.push("foFollowUp.debugLogger should be fz".into());
                }
                if fu.get("bodyEncoder").and_then(|x| x.as_str()) != Some(BODY_ENCODER_LIVE_NAME) {
                    errors.push("foFollowUp.bodyEncoder should be f3".into());
                }
                if fu.get("invokeIfFn").and_then(|x| x.as_str())
                    != Some(LIVE_RUN_PROGRAM_RETURN.invoke_if_fn)
                {
                    errors.push("foFollowUp.invokeIfFn mismatch".into());
                }
                if LIVE_FO_FOLLOWUP.send_helper != SEND_HELPER_LIVE_NAME {
                    errors.push("LIVE_FO_FOLLOWUP.send_helper should match SEND_HELPER_LIVE_NAME".into());
                }
                if let Some(lens) = fu.get("chromeLens").and_then(|x| x.as_array()) {
                    for (i, n) in lens.iter().enumerate() {
                        let len = n.as_u64().unwrap_or(0) as usize;
                        if classify_fo_body_len(len) != cf::solver::fo_body::FoBodyLenBand::FollowUp {
                            errors.push(format!("foFollowUp.chromeLens[{i}]={len} not follow-up band"));
                        }
                    }
                }
                if let Some(lens) = fu.get("chromeRespLens").and_then(|x| x.as_array()) {
                    for (i, n) in lens.iter().enumerate() {
                        let len = n.as_u64().unwrap_or(0) as usize;
                        if classify_fo_response_len(len) != FoResponseLenBand::FollowUpAck {
                            errors.push(format!("foFollowUp.chromeRespLens[{i}]={len} not ack band"));
                        }
                    }
                }
            }
            if let Some(fj) = late.get("foFollowUpJson") {
                if fj.get("copiedFromInit") != Some(&Value::Bool(true)) {
                    errors.push("foFollowUpJson.copiedFromInit should be true".into());
                }
                if fj.get("numericVmEntries") != Some(&Value::Bool(true)) {
                    errors.push("foFollowUpJson.numericVmEntries should be true".into());
                }
                if let Some(n) = fj.get("copiedCount").and_then(|x| x.as_u64())
                    && n != cf::FOLLOWUP_COPIED_COUNT_B as u64
                {
                    errors.push(format!(
                        "foFollowUpJson.copiedCount={n} expected {}",
                        cf::FOLLOWUP_COPIED_COUNT_B
                    ));
                }
                if let Some(extra) = fj.get("extraIdent").and_then(|x| x.as_array()) {
                    let got: Vec<&str> = extra.iter().filter_map(|k| k.as_str()).collect();
                    if got != cf::FOLLOWUP_EXTRA_IDENT_B {
                        errors.push(format!(
                            "foFollowUpJson.extraIdent={got:?} expected {:?}",
                            cf::FOLLOWUP_EXTRA_IDENT_B
                        ));
                    }
                }
                if let Some(dropped) = fj.get("droppedInit").and_then(|x| x.as_array()) {
                    let got: Vec<&str> = dropped.iter().filter_map(|k| k.as_str()).collect();
                    if got != cf::FOLLOWUP_DROPPED_INIT_B {
                        errors.push(format!(
                            "foFollowUpJson.droppedInit={got:?} expected {:?}",
                            cf::FOLLOWUP_DROPPED_INIT_B
                        ));
                    }
                }
                if let Some(srcs) = fj.get("extraIdentHtml").and_then(|x| x.as_array()) {
                    if srcs.len() != cf::solver::fo_followup_json::FOLLOWUP_EXTRA_IDENT_HTML_B.len()
                    {
                        errors.push("foFollowUpJson.extraIdentHtml length mismatch".into());
                    }
                    for (src, row) in cf::solver::fo_followup_json::FOLLOWUP_EXTRA_IDENT_HTML_B
                        .iter()
                        .zip(srcs)
                    {
                        if row.get("name").and_then(|x| x.as_str()) != Some(src.name)
                            || row.get("html").and_then(|x| x.as_str()) != Some(src.html)
                        {
                            errors.push(format!("foFollowUpJson.extraIdentHtml.{} mismatch", src.name));
                        }
                    }
                }
                if fj.get("numericKeysInHtml") == Some(&Value::Bool(true)) {
                    errors.push("foFollowUpJson.numericKeysInHtml should be false".into());
                }
                if let Some(writes) = fj.get("writes").and_then(|x| x.as_array()) {
                    if writes.len() != cf::FOLLOWUP_FIELD_WRITE_B.len() {
                        errors.push("foFollowUpJson.writes length mismatch".into());
                    }
                    for (row, got) in cf::FOLLOWUP_FIELD_WRITE_B.iter().zip(writes) {
                        if got.get("name").and_then(|x| x.as_str()) != Some(row.name)
                            || got.get("source").and_then(|x| x.as_str()) != Some(row.source)
                            || got.get("writePath").and_then(|x| x.as_str()) != Some(row.write_path)
                        {
                            errors.push(format!("foFollowUpJson.writes.{} mismatch", row.name));
                        }
                    }
                }
                if let Some(hv) = fj.get("inlinePackedHarvest") {
                    if hv.get("extraIdentInStub") != Some(&Value::Bool(false)) {
                        errors.push("inlinePackedHarvest.extraIdentInStub should be false".into());
                    }
                    if hv.get("stopped").and_then(|x| x.as_str()) == Some("unparsed_op_177_XU") {
                        errors.push(
                            "inlinePackedHarvest.stopped should not be unparsed_op_177_XU (XU immediates are skipped without apply)".into(),
                        );
                    }
                }
                if fj.get("numericSlotKind").and_then(|x| x.as_str()) == Some("object") {
                    if fj.get("numericSlotKeyCountMin").and_then(|x| x.as_u64())
                        != Some(u64::from(cf::solver::fo_followup_json::FOLLOWUP_NUMERIC_SLOT_KEYCOUNT_MIN_B))
                    {
                        errors.push("foFollowUpJson.numericSlotKeyCountMin mismatch".into());
                    }
                }
                if let Some(lp) = fj.get("leftoverProbe") {
                    if lp.get("opcodeRecovered") == Some(&Value::Bool(true)) {
                        errors.push("leftoverProbe.opcodeRecovered should be false".into());
                    }
                    if let Some(names) = lp.get("unseenNames").and_then(|x| x.as_array()) {
                        let got: Vec<&str> = names.iter().filter_map(|k| k.as_str()).collect();
                        if got != cf::FOLLOWUP_UNSEEN_EXTRA_IDENT_B {
                            errors.push("leftoverProbe.unseenNames mismatch".into());
                        }
                    }
                }
                if let Some(ph) = fj.get("packedHarvest") {
                    if ph.get("recaptured") != Some(&Value::Bool(true)) {
                        errors.push("packedHarvest.recaptured should be true".into());
                    }
                    if ph.get("fetchLiveUnchanged") != Some(&Value::Bool(true)) {
                        errors.push("packedHarvest.fetchLiveUnchanged should be true".into());
                    }
                    if ph.get("packedPrefix").and_then(|x| x.as_str())
                        != Some(cf::solver::fo_followup_json::FOLLOWUP_LIVE_PACKED_PREFIX)
                    {
                        errors.push("packedHarvest.packedPrefix mismatch".into());
                    }
                    if ph.get("unseenIdentHits").and_then(|x| x.as_array()).map(|a| a.len())
                        != Some(0)
                    {
                        errors.push("packedHarvest.unseenIdentHits should be empty".into());
                    }
                }
                if let Some(ident) = fj.get("identKeys").and_then(|x| x.as_array()) {
                    let names: Vec<String> = ident
                        .iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect();
                    let numeric = fj.get("numericKeyCount").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                    if names.len() >= 40
                        && cf::solver::fo_followup_json::classify_fo_plaintext(
                            &names,
                            numeric,
                            INIT_JSON_KEYS_B,
                        ) != cf::solver::fo_followup_json::FoPlaintextKind::FollowUp
                    {
                        errors.push("foFollowUpJson.identKeys did not classify as follow-up".into());
                    }
                }
            }
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
    let fo_init = v
        .pointer("/laterSameDay/foInitJson")
        .or_else(|| v.get("foInitJson"))
        .cloned();
    let mut fo_init_keys_ok = false;
    if let Some(init) = &fo_init {
        if init.get("keyCount").and_then(|x| x.as_u64()) != Some(INIT_JSON_KEY_COUNT as u64) {
            errors.push("foInitJson.keyCount should be 47".into());
        }
        if init.get("setTimeoutDelayMs").and_then(|x| x.as_u64()) != Some(100) {
            errors.push("foInitJson.setTimeoutDelayMs should be 100".into());
        }
        if let Some(prefs) = init.get("keys").and_then(|x| x.as_array()) {
            let keys: Vec<String> = prefs
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            if keys_match_snapshot(&keys, INIT_JSON_KEYS_B) {
                fo_init_keys_ok = true;
            } else {
                errors.push("foInitJson.keys do not match branch-b snapshot".into());
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
        "fo_init_json": LIVE_FO_INIT_JSON,
        "fo_followup": LIVE_FO_FOLLOWUP,
        "fo_followup_json": cf::solver::fo_followup_json::LIVE_FO_FOLLOWUP_JSON,
        "fo_prefix_ok": fo_prefix_ok,
        "fo_init_keys_ok": fo_init_keys_ok,
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
