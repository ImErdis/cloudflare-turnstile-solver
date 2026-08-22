//! Width-aware **skip** of mapped `runProgram` immediates (late-`b` `56907`).
//!
//! Harvests string immediates (`Xf` tag 199/161, `gC`/`gl` LEB, `ge` 4th imm)
//! without executing handlers, calling host JS, or taking jumps. Linear walk
//! skips `XU`/177 immediates (no `XI.apply`) and stops at the first jump or
//! other Variable family this module does not skip. That is a disassembler of
//! immediates, not a VM.
//!
//! `go[i] = String.fromCharCode(i)` on the 56907 iframe, so charset extras
//! (`136`, `1`, `43`) index latin1 directly.

use crate::solver::run_program_ops::{
    GE_OPCODE, InstrWidth, XF_DST_XOR, XF_INT_XOR, XF_OPCODE,
    XF_STRING_CHARSET_XOR, XF_TAG_BYTES, XF_TAG_FALSE, XF_TAG_INT, XF_TAG_LEB, XF_TAG_NULL,
    XF_TAG_NUMBER_A, XF_TAG_NUMBER_B, XF_TAG_REGEXP, XF_TAG_STRING, XF_TAG_UNDEF, XF_TAG_XOR,
    jump_roles_for_late, layout_for_late, operand_from_byte,
};
use crate::solver::run_program_vm::{FETCH_LIVE, FetchParams, step_fetch};
use serde::Serialize;

pub const GC_OPCODE: u8 = 226;
pub const GL_OPCODE: u8 = 140;
pub const XU_OPCODE: u8 = 177;
pub const GC_STRING_CHARSET_XOR: u8 = 1;
pub const GL_STRING_CHARSET_XOR: u8 = 43;
pub const GE_KEY_IMM_XOR: u8 = 19;
pub const XU_DST_XOR: u8 = 96;
pub const XU_KEY_XOR: u8 = 207;
pub const XU_FLAGS_XOR: u8 = 68;
pub const XU_ARITY_XOR: u8 = 83;
pub const XU_ARG_XOR: u8 = 37;
/// Linear skip cap. Live `/fo/` packed bodies are ~600k+ bytecode bytes.
pub const SKIP_HARVEST_INSTR_LIMIT: usize = 1_048_576;
pub const XF_REGEXP_CHARSET_A: u8 = 195;
pub const XF_REGEXP_CHARSET_B: u8 = 229;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HarvestedString {
    pub opcode: u8,
    pub handler: &'static str,
    pub pc: u32,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkipHarvest {
    pub params_label: &'static str,
    pub instructions: usize,
    pub last_pc: u32,
    pub last_opcode: Option<u8>,
    pub stopped: &'static str,
    pub strings: Vec<HarvestedString>,
    pub ge_key_imms: Vec<u8>,
}

impl SkipHarvest {
    pub fn contains_ident(&self, name: &str) -> bool {
        self.strings.iter().any(|s| s.text == name || s.text.contains(name))
    }
}

struct Cursor<'a> {
    bytecode: &'a [u8],
    params: FetchParams,
    pc: usize,
    key: u8,
}

impl<'a> Cursor<'a> {
    fn at_end(&self) -> bool {
        self.pc >= self.bytecode.len()
    }

    fn fetch_opcode(&mut self) -> Result<u8, &'static str> {
        if self.at_end() {
            return Err("end_of_bytecode");
        }
        let byte = self.bytecode[self.pc];
        let (op, next) = step_fetch(self.params, self.key, byte);
        self.pc += 1;
        self.key = next;
        Ok(op)
    }

    fn imm(&mut self, extra: u8) -> Result<u8, &'static str> {
        if self.at_end() {
            return Err("eof_imm");
        }
        let v = operand_from_byte(self.params, self.key, self.bytecode[self.pc], extra);
        self.pc += 1;
        Ok(v)
    }

    fn leb(&mut self) -> Result<u32, &'static str> {
        let mut x = self.imm(0)?;
        let mut n = u32::from(x & 127);
        let mut shift = 7;
        while x & 128 != 0 {
            if shift >= 21 {
                return Err("leb_too_long");
            }
            x = self.imm(0)?;
            n |= u32::from(x & 127) << shift;
            shift += 7;
        }
        Ok(n)
    }

    fn charset_string(&mut self, extra: u8) -> Result<String, &'static str> {
        let len = self.leb()? as usize;
        if len > 32_768 {
            return Err("string_too_long");
        }
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            out.push(char::from(self.imm(extra)?));
        }
        Ok(out)
    }

    fn skip_fixed(&mut self, width: u8) -> Result<(), &'static str> {
        let rest = usize::from(width.saturating_sub(1));
        if self.pc + rest > self.bytecode.len() {
            return Err("eof_fixed");
        }
        self.pc += rest;
        Ok(())
    }
}

fn push_str(
    out: &mut Vec<HarvestedString>,
    opcode: u8,
    handler: &'static str,
    pc: u32,
    text: String,
) {
    out.push(HarvestedString {
        opcode,
        handler,
        pc,
        text,
    });
}

fn skip_xf(cur: &mut Cursor<'_>, start_pc: u32, strings: &mut Vec<HarvestedString>) -> Result<(), &'static str> {
    let tag = cur.imm(XF_TAG_XOR)?;
    let _dst = cur.imm(XF_DST_XOR)?;
    match tag {
        XF_TAG_STRING => {
            let text = cur.charset_string(XF_STRING_CHARSET_XOR)?;
            push_str(strings, XF_OPCODE, "Xf", start_pc, text);
            Ok(())
        }
        XF_TAG_BYTES => {
            let text = cur.charset_string(XF_STRING_CHARSET_XOR)?;
            push_str(strings, XF_OPCODE, "Xf", start_pc, text);
            Ok(())
        }
        XF_TAG_INT => {
            let _ = cur.imm(XF_INT_XOR)?;
            Ok(())
        }
        XF_TAG_UNDEF | XF_TAG_NULL | XF_TAG_FALSE | XF_TAG_NUMBER_A | XF_TAG_NUMBER_B => Ok(()),
        XF_TAG_LEB => {
            let _ = cur.leb()?;
            Ok(())
        }
        XF_TAG_REGEXP => {
            let a = cur.charset_string(XF_REGEXP_CHARSET_A)?;
            let b = cur.charset_string(XF_REGEXP_CHARSET_B)?;
            push_str(strings, XF_OPCODE, "Xf", start_pc, a);
            push_str(strings, XF_OPCODE, "Xf", start_pc, b);
            Ok(())
        }
        _ => Err("xf_unskipped_tag"),
    }
}

fn skip_gc(cur: &mut Cursor<'_>, start_pc: u32, strings: &mut Vec<HarvestedString>) -> Result<(), &'static str> {
    let _ = cur.imm(42)?;
    let _ = cur.imm(182)?;
    let text = cur.charset_string(GC_STRING_CHARSET_XOR)?;
    push_str(strings, GC_OPCODE, "gC", start_pc, text);
    Ok(())
}

fn skip_gl(cur: &mut Cursor<'_>, start_pc: u32, strings: &mut Vec<HarvestedString>) -> Result<(), &'static str> {
    let text = cur.charset_string(GL_STRING_CHARSET_XOR)?;
    let _ = cur.imm(69)?;
    let _ = cur.imm(118)?;
    push_str(strings, GL_OPCODE, "gl", start_pc, text);
    Ok(())
}

fn skip_ge(cur: &mut Cursor<'_>, imms: &mut Vec<u8>) -> Result<(), &'static str> {
    let _ = cur.imm(41)?;
    let _ = cur.imm(221)?;
    let _ = cur.imm(180)?;
    imms.push(cur.imm(GE_KEY_IMM_XOR)?);
    Ok(())
}

/// Skip `XU`/177 immediates without `XI.apply`.
///
/// 56907 HTML: dst^96, u24 (three extra-0 bytes), key^207, flags^68, arity^83,
/// then `arity` args^37. Does not call host JS.
fn skip_xu(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let _dst = cur.imm(XU_DST_XOR)?;
    let _u24_hi = cur.imm(0)?;
    let _u24_mid = cur.imm(0)?;
    let _u24_lo = cur.imm(0)?;
    let _key = cur.imm(XU_KEY_XOR)?;
    let _flags = cur.imm(XU_FLAGS_XOR)?;
    let arity = cur.imm(XU_ARITY_XOR)?;
    for _ in 0..arity {
        let _ = cur.imm(XU_ARG_XOR)?;
    }
    Ok(())
}

/// Linear skip-harvest from `params.init_pc` / `init_key`. Skips `XU`/177
/// immediates without apply. Does not take jumps or invoke callees. Stops at
/// the first unskipped jump / Variable handler.
pub fn skip_harvest_strings(bytecode: &[u8], params: FetchParams) -> SkipHarvest {
    let mut cur = Cursor {
        bytecode,
        params,
        pc: params.init_pc as usize,
        key: params.init_key,
    };
    let mut strings = Vec::new();
    let mut ge_key_imms = Vec::new();
    let mut instructions = 0usize;
    let mut last_pc = params.init_pc;
    let mut last_opcode = None;
    let mut stopped = "limit";

    let limit = bytecode.len().max(4_096).min(SKIP_HARVEST_INSTR_LIMIT);
    for _ in 0..limit {
        if cur.at_end() {
            stopped = "end_of_bytecode";
            break;
        }
        last_pc = cur.pc as u32;
        let op = match cur.fetch_opcode() {
            Ok(op) => op,
            Err(e) => {
                stopped = e;
                break;
            }
        };
        last_opcode = Some(op);
        instructions += 1;
        let result = if op == XF_OPCODE {
            skip_xf(&mut cur, last_pc, &mut strings)
        } else if op == GC_OPCODE {
            skip_gc(&mut cur, last_pc, &mut strings)
        } else if op == GL_OPCODE {
            skip_gl(&mut cur, last_pc, &mut strings)
        } else if op == GE_OPCODE {
            skip_ge(&mut cur, &mut ge_key_imms)
        } else if op == XU_OPCODE {
            skip_xu(&mut cur)
        } else if jump_roles_for_late(op).is_some() {
            Err("unparsed_jump")
        } else if let Some(layout) = layout_for_late(op) {
            match layout.width {
                InstrWidth::Fixed(w) => cur.skip_fixed(w),
                InstrWidth::Variable => Err("unparsed_variable"),
            }
        } else {
            Err("unmapped_opcode")
        };
        if let Err(reason) = result {
            stopped = match (reason, op) {
                ("unparsed_jump", _) => "unparsed_jump",
                ("unparsed_variable", _) => "unparsed_variable",
                ("xf_unskipped_tag", _) => "xf_unskipped_tag",
                other => other.0,
            };
            break;
        }
    }

    SkipHarvest {
        params_label: params.label,
        instructions,
        last_pc,
        last_opcode,
        stopped,
        strings,
        ge_key_imms,
    }
}

pub fn skip_harvest_live(bytecode: &[u8]) -> SkipHarvest {
    skip_harvest_strings(bytecode, FETCH_LIVE)
}

pub fn extract_inline_run_program_packed(html: &str) -> Option<String> {
    let start = html.find("runProgram(`")? + "runProgram(`".len();
    let rest = html.get(start..)?;
    let end = rest.find('`')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::fo_followup_json::{FOLLOWUP_EXTRA_IDENT_B, FOLLOWUP_UNSEEN_EXTRA_IDENT_B};
    use crate::solver::run_program::unpack_packed_run_program;
    use crate::solver::run_program_ops::XF_TAG_XOR;
    use crate::solver::run_program_vm::{FETCH_BRANCH_B_LATE, FetchParams, encode_byte, next_key};

    fn push_op(buf: &mut Vec<u8>, key: &mut u8, opcode: u8) {
        buf.push(encode_byte(FETCH_BRANCH_B_LATE, *key, opcode));
        *key = next_key(FETCH_BRANCH_B_LATE, *key, opcode);
    }

    fn push_imm(buf: &mut Vec<u8>, key: u8, extra: u8, value: u8) {
        buf.push(encode_byte(FETCH_BRANCH_B_LATE, key, value ^ extra));
    }

    fn push_str_payload(buf: &mut Vec<u8>, key: u8, extra: u8, text: &str) {
        assert!(text.len() < 127);
        buf.push(encode_byte(FETCH_BRANCH_B_LATE, key, text.len() as u8));
        for b in text.bytes() {
            push_imm(buf, key, extra, b);
        }
    }

    #[test]
    fn skip_harvests_synthetic_xf_string() {
        let mut buf = Vec::new();
        let mut key = FETCH_BRANCH_B_LATE.init_key;
        push_op(&mut buf, &mut key, XF_OPCODE);
        push_imm(&mut buf, key, XF_TAG_XOR, XF_TAG_STRING);
        push_imm(&mut buf, key, XF_DST_XOR, 0);
        push_str_payload(&mut buf, key, XF_STRING_CHARSET_XOR, "window");
        let h = skip_harvest_strings(&buf, FETCH_BRANCH_B_LATE);
        assert_eq!(h.strings.len(), 1);
        assert_eq!(h.strings[0].text, "window");
        assert_eq!(h.strings[0].opcode, XF_OPCODE);
        assert_eq!(h.stopped, "end_of_bytecode");
        assert!(!h.contains_ident("SMrTl9"));
    }

    #[test]
    fn skip_harvests_ge_integer_key_imm() {
        let mut buf = Vec::new();
        let mut key = FETCH_BRANCH_B_LATE.init_key;
        push_op(&mut buf, &mut key, GE_OPCODE);
        push_imm(&mut buf, key, 41, 0);
        push_imm(&mut buf, key, 221, 1);
        push_imm(&mut buf, key, 180, 2);
        push_imm(&mut buf, key, GE_KEY_IMM_XOR, 7);
        let h = skip_harvest_strings(&buf, FETCH_BRANCH_B_LATE);
        assert_eq!(h.ge_key_imms, vec![7]);
        assert_eq!(h.stopped, "end_of_bytecode");
    }

    #[test]
    fn skip_harvests_xu_immediates_without_apply() {
        let mut buf = Vec::new();
        let mut key = FETCH_BRANCH_B_LATE.init_key;
        push_op(&mut buf, &mut key, XU_OPCODE);
        push_imm(&mut buf, key, XU_DST_XOR, 0);
        push_imm(&mut buf, key, 0, 0);
        push_imm(&mut buf, key, 0, 1);
        push_imm(&mut buf, key, 0, 2);
        push_imm(&mut buf, key, XU_KEY_XOR, 0);
        push_imm(&mut buf, key, XU_FLAGS_XOR, 0);
        push_imm(&mut buf, key, XU_ARITY_XOR, 2);
        push_imm(&mut buf, key, XU_ARG_XOR, 3);
        push_imm(&mut buf, key, XU_ARG_XOR, 4);
        let h = skip_harvest_strings(&buf, FETCH_BRANCH_B_LATE);
        assert_eq!(h.last_opcode, Some(XU_OPCODE));
        assert_eq!(h.stopped, "end_of_bytecode");
        assert_eq!(h.instructions, 1);
        assert!(h.strings.is_empty());
    }

    #[test]
    fn inline_56907_stub_has_host_strings_not_followup_idents() {
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        assert!(html.contains("go=[],gR=0;gR<256;go[gR]=String["));
        assert!(html.contains("Xw+=go[Xt^3+XM[Xm++]&255^136]"));
        let packed = extract_inline_run_program_packed(&html).expect("inline runProgram packed");
        assert!(packed.starts_with("71GxwDch"));
        let bc = unpack_packed_run_program(&packed).unwrap();
        let h = skip_harvest_live(&bc);
        assert!(h.instructions >= 10, "instructions {}", h.instructions);
        assert_eq!(h.stopped, "unparsed_jump");
        assert_eq!(h.last_opcode, Some(187));
        let texts: Vec<&str> = h.strings.iter().map(|s| s.text.as_str()).collect();
        assert!(texts.contains(&"window"), "{texts:?}");
        assert!(texts.contains(&"querySelectorAll"), "{texts:?}");
        assert!(texts.contains(&"NLBQh4"), "{texts:?}");
        for name in FOLLOWUP_EXTRA_IDENT_B {
            assert!(
                !h.contains_ident(name),
                "HTML-embedded 5k stub should not contain extra ident {name}"
            );
        }
        assert!(
            h.ge_key_imms.iter().all(|k| !(1..=39).contains(k)),
            "stub ge key imms {:?}",
            h.ge_key_imms
        );
    }

    #[test]
    fn live_fo_packed_leftover_idents_unseen_if_dump_present() {
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle-packed2/fo-init-response.txt");
        let ray_path = std::path::Path::new("artifacts/re-out/chrome-oracle-packed2/fo-init-ray.txt");
        if !path.is_file() || !ray_path.is_file() {
            return;
        }
        let ray = std::fs::read_to_string(ray_path).unwrap();
        let ray = ray.trim();
        let body = std::fs::read_to_string(path).unwrap();
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let padded = match compact.len() % 4 {
            2 => format!("{compact}=="),
            3 => format!("{compact}="),
            _ => compact,
        };
        let packed = crate::reverse::encryption::decrypt_cloudflare_response(ray, &padded).unwrap();
        assert!(packed.starts_with("1oUjjpq4"), "prefix {}", &packed[..20.min(packed.len())]);
        for name in FOLLOWUP_UNSEEN_EXTRA_IDENT_B {
            assert!(
                !packed.contains(name),
                "leftover {name} in decrypted packed plaintext"
            );
        }
        let bc = unpack_packed_run_program(&packed).unwrap();
        let live_fetch = skip_harvest_live(&bc);
        assert_eq!(live_fetch.params_label, FETCH_LIVE.label);
        for name in FOLLOWUP_UNSEEN_EXTRA_IDENT_B {
            assert!(
                !live_fetch.contains_ident(name),
                "FETCH_LIVE harvest hit {name} stopped={} op={:?}",
                live_fetch.stopped,
                live_fetch.last_opcode
            );
        }
        // HTML formula on this iframe (not FETCH_LIVE): mix²*23196 + mix*32619 + 19372.
        let html_fetch = FetchParams {
            label: "chrome-oracle-2026-08-22-b-23196",
            init_pc: 0,
            init_key: 63,
            byte_bias: 217,
            key_mul: 23_196,
            key_add: 19_372,
            key_quad_b: 32_619,
        };
        let h = skip_harvest_strings(&bc, html_fetch);
        for name in FOLLOWUP_UNSEEN_EXTRA_IDENT_B {
            assert!(
                !h.contains_ident(name),
                "html-fetch harvest hit {name} stopped={} op={:?} strings={}",
                h.stopped,
                h.last_opcode,
                h.strings.len()
            );
        }
    }
}
