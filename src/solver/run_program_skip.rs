//! Width-aware **skip** of mapped `runProgram` immediates.
//!
//! 56907: harvests `Xf` tag 199/161, `gC`/`gl` LEB, `ge` 4th imm. Skips `XU`/177
//! (no `XI.apply`). `go[i] = String.fromCharCode(i)`, so charset extras
//! (`136`, `1`, `43`) index latin1 directly.
//!
//! 5886 (`FETCH_CHROME_2026_08_22_B_5886`, tuples27 executed JS): skips `Hg`/5
//! (no apply), `HW`/156 tagged load, `qR`/`Hx`/`HV`/`qC` charset names, and
//! fixed-width ALU/unary handlers. Does not take jumps or invoke callees.
//! That is a disassembler of immediates, not a VM.
//!
//! 40954 (`FETCH_HTML_40954_UNVERIFIED`, leftover1/leftover4 executed JS):
//! separate table. Linear `*40954+30072`, method-call switch
//! `fn[call](this)`. Opcode **181** `bg` is the tagged load (tag then dst).
//! Do not reuse 56907 or 5886 extra-xors or opcode numbers. Does not take
//! jumps (`bW`/247) or invoke callees.

use crate::solver::run_program_ops::{
    GE_OPCODE, InstrWidth, XF_DST_XOR, XF_INT_XOR, XF_OPCODE, XF_STRING_CHARSET_XOR, XF_TAG_BYTES,
    XF_TAG_FALSE, XF_TAG_INT, XF_TAG_LEB, XF_TAG_NULL, XF_TAG_NUMBER_A, XF_TAG_NUMBER_B,
    XF_TAG_REGEXP, XF_TAG_STRING, XF_TAG_UNDEF, XF_TAG_XOR, jump_roles_for_late, layout_for_late,
    operand_from_byte,
};
use crate::solver::run_program_profile::{
    VmHandlerProfile, VmSkipProfile, VmSkipSpec, VmTagPayload, VmTaggedOperandOrder,
};
use crate::solver::run_program_vm::{
    FETCH_CHROME_2026_08_22_B_5886, FETCH_HTML_40954_UNVERIFIED, FETCH_LIVE, FetchParams,
    step_fetch,
};
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

/// tuples27 executed `Hg` (`case 5:`): call/apply header extras then arity×arg.
/// Floats `75.87` / `210.17` / `111.28` → ToInt32. Do not invoke the callee.
pub const HG_5886_OPCODE: u8 = 5;
pub const HG_5886_CALLEE_XOR: u8 = 55;
pub const HG_5886_THIS_XOR: u8 = 75;
pub const HG_5886_DST_XOR: u8 = 210;
pub const HG_5886_ARITY_XOR: u8 = 36;
pub const HG_5886_ARG_XOR: u8 = 111;

/// tuples27 executed `qR` (`case 51:`): LEB latin1 name then property get.
pub const QR_5886_OPCODE: u8 = 51;
pub const QR_5886_DST_XOR: u8 = 158;
pub const QR_5886_BASE_XOR: u8 = 33;
pub const QR_5886_CHARSET_XOR: u8 = 233;

/// tuples27 `HW` (`case 156:`): tagged load (Xf analogue). Dst then tag.
/// Split order `2|1|4|0|3|5` is LEB then charset 130. Not a jump (`<<16` is tag 213).
pub const HW_5886_OPCODE: u8 = 156;
pub const HW_5886_DST_XOR: u8 = 231;
pub const HW_5886_TAG_XOR: u8 = 4;
pub const HW_5886_INT_XOR: u8 = 18;
pub const HW_5886_STRING_CHARSET_XOR: u8 = 130;
pub const HW_5886_PACKED_KEY_XOR: u8 = 82;
pub const HW_5886_BYTES_CHARSET_XOR: u8 = 74;
pub const HW_5886_REGEXP_CHARSET_A: u8 = 108;
pub const HW_5886_REGEXP_CHARSET_B: u8 = 180;
pub const HW_5886_REGEXP_FLAGS_LEN_XOR: u8 = 1;
pub const HW_5886_TAG_INT: u8 = 128;
pub const HW_5886_TAG_UNDEF: u8 = 59;
pub const HW_5886_TAG_STRING: u8 = 241;
pub const HW_5886_TAG_LEB: u8 = 102;
pub const HW_5886_TAG_FLOAT: u8 = 236;
pub const HW_5886_TAG_NULL: u8 = 250;
pub const HW_5886_TAG_NUMBER_A: u8 = 110;
pub const HW_5886_TAG_NUMBER_B: u8 = 67;
pub const HW_5886_TAG_TRUE: u8 = 234;
pub const HW_5886_TAG_FALSE: u8 = 173;
pub const HW_5886_TAG_PACKED: u8 = 213;
pub const HW_5886_TAG_BYTES: u8 = 8;
pub const HW_5886_TAG_REGEXP: u8 = 38;

/// tuples27 `Hx` (`case 168:`): LEB object + charset name then call/apply. No invoke.
pub const HX_5886_OPCODE: u8 = 168;
pub const HX_5886_DST_XOR: u8 = 193;
pub const HX_5886_CHARSET_XOR: u8 = 0;
pub const HX_5886_FLAGS_XOR: u8 = 63;
pub const HX_5886_ARG_XOR: u8 = 228;

/// tuples27 `HV` (`case 230:`): dst/base + charset name then call/apply. No invoke.
pub const HV_5886_OPCODE: u8 = 230;
pub const HV_5886_DST_XOR: u8 = 31;
pub const HV_5886_BASE_XOR: u8 = 89;
pub const HV_5886_CHARSET_XOR: u8 = 126;
pub const HV_5886_FLAGS_XOR: u8 = 187;
pub const HV_5886_ARG_XOR: u8 = 20;

/// tuples27 `qC` (`case 224:`): split `1|2|5|3|4|7|0|6` = dst, LEB name, extra 252.
pub const QC_5886_OPCODE: u8 = 224;
pub const QC_5886_DST_XOR: u8 = 33;
pub const QC_5886_CHARSET_XOR: u8 = 146;
pub const QC_5886_KEY_XOR: u8 = 252;

/// tuples27 `Hk` (`case 70:`): LEB extra 0, then extras 17 and 88. Not `HK`/39.
pub const HK_LEB_5886_OPCODE: u8 = 70;
pub const HK_LEB_5886_DST_XOR: u8 = 17;
pub const HK_LEB_5886_KEY_XOR: u8 = 88;

/// tuples27 `HG` (`case 227:`): outer LEB count, then that many inner LEBs. No alloc.
pub const HG_TABLE_5886_OPCODE: u8 = 227;

/// tuples27 `HF`/`Hi`: LEB slot then extra 240.
pub const HF_5886_OPCODE: u8 = 212;
pub const HI_5886_OPCODE: u8 = 221;
pub const HF_HI_5886_XOR: u8 = 240;

/// tuples27 `HX` (`case 67:`): dst^17, this^46, arity^75, args^161. No invoke.
pub const HX_CALL_5886_OPCODE: u8 = 67;
pub const HX_CALL_5886_DST_XOR: u8 = 17;
pub const HX_CALL_5886_THIS_XOR: u8 = 46;
pub const HX_CALL_5886_ARITY_XOR: u8 = 75;
pub const HX_CALL_5886_ARG_XOR: u8 = 161;

/// tuples27 `HO` (`case 33:`): dst^56, LEB obj, flags^178, args^62. No invoke.
pub const HO_5886_OPCODE: u8 = 33;
pub const HO_5886_DST_XOR: u8 = 56;
pub const HO_5886_FLAGS_XOR: u8 = 178;
pub const HO_5886_ARG_XOR: u8 = 62;

/// tuples27 `Ht` (`case 219:`): dst^176, ctor^90, arity^216, args^132. No `new`.
pub const HT_NEW_5886_OPCODE: u8 = 219;
pub const HT_NEW_5886_DST_XOR: u8 = 176;
pub const HT_NEW_5886_CTOR_XOR: u8 = 90;
pub const HT_NEW_5886_ARITY_XOR: u8 = 216;
pub const HT_NEW_5886_ARG_XOR: u8 = 132;

/// tuples27 `HE` (`case 119:`): XU analogue. dst^229, u24, key^82, flags^240, arity^37, args^33. No apply.
pub const HE_5886_OPCODE: u8 = 119;
pub const HE_5886_DST_XOR: u8 = 229;
pub const HE_5886_KEY_XOR: u8 = 82;
pub const HE_5886_FLAGS_XOR: u8 = 240;
pub const HE_5886_ARITY_XOR: u8 = 37;
pub const HE_5886_ARG_XOR: u8 = 33;

/// tuples27 `Hb` (`case 249:`): tag^117, LEB, then extra 240 or N inner LEBs.
pub const HB_5886_OPCODE: u8 = 249;
pub const HB_5886_TAG_XOR: u8 = 117;
pub const HB_5886_XOR: u8 = 240;
pub const HB_5886_TAG_STORE: u8 = 95;
pub const HB_5886_TAG_LOAD: u8 = 120;
pub const HB_5886_TAG_ALLOC: u8 = 35;

/// Shared `qZ` ALU (`case N:qZ.call(this, variant)`): always 3 imms.
pub const QZ_5886_OPCODES: &[u8] = &[
    4, 24, 30, 80, 86, 96, 104, 108, 116, 127, 137, 149, 151, 155, 163, 197, 203, 234,
];

/// Shared `qu` unary (`case N:qu.call(this, variant)`): always 2 imms.
pub const QU_5886_OPCODES: &[u8] = &[27, 84, 142, 229, 240];

/// Unique `case N:` arms on the tuples27 fetch switch (69 handlers). Opcodes
/// **not** in this list have no case; the fetch loop already consumed that byte.
pub const SWITCH_OPCODES_5886: &[u8] = &[
    4, 5, 7, 13, 24, 27, 30, 33, 39, 41, 51, 52, 59, 67, 70, 76, 80, 81, 84, 86, 87, 89, 90, 91,
    95, 96, 101, 104, 108, 112, 113, 116, 119, 127, 129, 135, 137, 142, 148, 149, 151, 154, 155,
    156, 162, 163, 168, 176, 184, 190, 191, 197, 203, 212, 213, 215, 217, 219, 221, 224, 227, 229,
    230, 234, 239, 240, 249, 250, 251,
];

/// tuples27 unique handlers that assign `this.j` from a u24 as control transfer.
/// Skip-harvest does not take these. `HW`/156 and `qw`/112 are not jumps.
pub const JUMP_OPCODES_5886: &[u8] = &[7, 13, 52, 89, 129, 135, 176, 213];

/// leftover1/leftover4 fetch switch (`*40954+30072`). Same 69 `case N:` arms
/// on leftover1-15 and leftover4-15. Not 56907, not 5886.
pub const SWITCH_OPCODES_40954: &[u8] = &[
    7, 14, 20, 23, 24, 26, 28, 31, 35, 36, 40, 45, 46, 48, 55, 56, 58, 59, 64, 65, 70, 76, 78, 85,
    89, 95, 96, 98, 101, 103, 105, 107, 114, 118, 119, 120, 122, 125, 127, 134, 143, 145, 150, 154,
    156, 157, 160, 162, 163, 167, 171, 179, 180, 181, 185, 193, 197, 202, 216, 221, 226, 230, 239,
    246, 247, 249, 250, 251, 254,
];

/// leftover4 `bW` (`case 247:`): three extra-0 bytes assemble a u24, extra
/// `252` updates the key, then `k[Y]=MU` with `Y=this.j`. Skip-harvest does
/// not take this. Opcode 181 is **not** a jump.
pub const JUMP_OPCODES_40954: &[u8] = &[247];

/// leftover4 `bg` (`case 181:`): tagged load. Tag^217.96 then dst^210.
/// String charset^225.23, bytes^211.24, regexp pattern^51 / flags-len^25.72
/// / flags^85. Int extra 8. Packed key^252. Not 56907 `Xh`/181.
pub const BG_40954_OPCODE: u8 = 181;
pub const BG_40954_TAG_XOR: u8 = 217;
pub const BG_40954_DST_XOR: u8 = 210;
pub const BG_40954_INT_XOR: u8 = 8;
pub const BG_40954_STRING_CHARSET_XOR: u8 = 225;
pub const BG_40954_BYTES_CHARSET_XOR: u8 = 211;
pub const BG_40954_PACKED_KEY_XOR: u8 = 252;
pub const BG_40954_REGEXP_CHARSET_A: u8 = 51;
pub const BG_40954_REGEXP_FLAGS_LEN_XOR: u8 = 25;
pub const BG_40954_REGEXP_CHARSET_B: u8 = 85;
pub const BG_40954_TAG_INT: u8 = 37;
pub const BG_40954_TAG_UNDEF: u8 = 27;
pub const BG_40954_TAG_STRING: u8 = 32;
pub const BG_40954_TAG_LEB: u8 = 88;
pub const BG_40954_TAG_FLOAT: u8 = 7;
pub const BG_40954_TAG_NULL: u8 = 195;
pub const BG_40954_TAG_NUMBER_A: u8 = 120;
pub const BG_40954_TAG_NUMBER_B: u8 = 182;
pub const BG_40954_TAG_TRUE: u8 = 80;
pub const BG_40954_TAG_FALSE: u8 = 251;
pub const BG_40954_TAG_PACKED: u8 = 220;
pub const BG_40954_TAG_BYTES: u8 = 39;
pub const BG_40954_TAG_REGEXP: u8 = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HarvestedString {
    pub opcode: u8,
    pub handler: String,
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
    /// Fetched `(pc, opcode)` in walk order, including the instruction that stopped.
    #[serde(skip)]
    pub ops: Vec<(u32, u8)>,
    /// `HW`/156 tag bytes in walk order (5886 only).
    #[serde(skip)]
    pub hw_tags: Vec<(u32, u8)>,
    /// Tagged-load tag bytes emitted by an explicit dynamic profile.
    #[serde(skip)]
    pub profile_tags: Vec<(u32, u8)>,
    /// Validation detail when `stopped == "profile_mismatch"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_error: Option<String>,
}

impl SkipHarvest {
    pub fn contains_ident(&self, name: &str) -> bool {
        self.strings
            .iter()
            .any(|s| s.text == name || s.text.contains(name))
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
        self.leb_with_extra(0)
    }

    fn leb_with_extra(&mut self, extra: u8) -> Result<u32, &'static str> {
        let mut x = self.imm(extra)?;
        let mut n = u32::from(x & 127);
        let mut shift = 7;
        while x & 128 != 0 {
            if shift >= 21 {
                return Err("leb_too_long");
            }
            x = self.imm(extra)?;
            n |= u32::from(x & 127) << shift;
            shift += 7;
        }
        Ok(n)
    }

    fn charset_string(&mut self, extra: u8) -> Result<String, &'static str> {
        self.charset_string_with(0, extra)
    }

    fn charset_string_with(
        &mut self,
        length_extra: u8,
        char_extra: u8,
    ) -> Result<String, &'static str> {
        let len = self.leb_with_extra(length_extra)? as usize;
        self.charset_n(len, char_extra)
    }

    fn charset_n(&mut self, len: usize, extra: u8) -> Result<String, &'static str> {
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
    handler: impl Into<String>,
    pc: u32,
    text: String,
) {
    out.push(HarvestedString {
        opcode,
        handler: handler.into(),
        pc,
        text,
    });
}

fn skip_xf(
    cur: &mut Cursor<'_>,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
) -> Result<(), &'static str> {
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

fn skip_gc(
    cur: &mut Cursor<'_>,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
) -> Result<(), &'static str> {
    let _ = cur.imm(42)?;
    let _ = cur.imm(182)?;
    let text = cur.charset_string(GC_STRING_CHARSET_XOR)?;
    push_str(strings, GC_OPCODE, "gC", start_pc, text);
    Ok(())
}

fn skip_gl(
    cur: &mut Cursor<'_>,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
) -> Result<(), &'static str> {
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

/// tuples27 `Hg`/5: four header imms, then `arity` register args. No call.
fn skip_hg_5886(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let _callee = cur.imm(HG_5886_CALLEE_XOR)?;
    let _this = cur.imm(HG_5886_THIS_XOR)?;
    let _dst = cur.imm(HG_5886_DST_XOR)?;
    let arity = cur.imm(HG_5886_ARITY_XOR)?;
    for _ in 0..arity {
        let _ = cur.imm(HG_5886_ARG_XOR)?;
    }
    Ok(())
}

/// tuples27 `qR`/51: dst^158, base^33, LEB length, charset^233 name. Property get
/// is not executed; the name is harvested.
fn skip_qr_5886(
    cur: &mut Cursor<'_>,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
) -> Result<(), &'static str> {
    let _dst = cur.imm(QR_5886_DST_XOR)?;
    let _base = cur.imm(QR_5886_BASE_XOR)?;
    let text = cur.charset_string(QR_5886_CHARSET_XOR)?;
    push_str(strings, QR_5886_OPCODE, "qR", start_pc, text);
    Ok(())
}

/// tuples27 `HW`/156: dst^231, tag^4, then tag payload. No host store.
fn skip_hw_5886(
    cur: &mut Cursor<'_>,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
    hw_tags: &mut Vec<(u32, u8)>,
) -> Result<(), &'static str> {
    let _dst = cur.imm(HW_5886_DST_XOR)?;
    let tag = cur.imm(HW_5886_TAG_XOR)?;
    hw_tags.push((start_pc, tag));
    match tag {
        HW_5886_TAG_STRING => {
            let text = cur.charset_string(HW_5886_STRING_CHARSET_XOR)?;
            push_str(strings, HW_5886_OPCODE, "HW", start_pc, text);
            Ok(())
        }
        HW_5886_TAG_BYTES => {
            let text = cur.charset_string(HW_5886_BYTES_CHARSET_XOR)?;
            push_str(strings, HW_5886_OPCODE, "HW", start_pc, text);
            Ok(())
        }
        HW_5886_TAG_INT => {
            let _ = cur.imm(HW_5886_INT_XOR)?;
            Ok(())
        }
        HW_5886_TAG_UNDEF | HW_5886_TAG_NULL | HW_5886_TAG_TRUE | HW_5886_TAG_FALSE
        | HW_5886_TAG_NUMBER_A | HW_5886_TAG_NUMBER_B => Ok(()),
        HW_5886_TAG_LEB => {
            let _ = cur.leb()?;
            Ok(())
        }
        HW_5886_TAG_FLOAT => {
            for _ in 0..8 {
                let _ = cur.imm(0)?;
            }
            Ok(())
        }
        HW_5886_TAG_PACKED => {
            let _ = cur.imm(0)?;
            let _ = cur.imm(0)?;
            let _ = cur.imm(0)?;
            let _ = cur.imm(HW_5886_PACKED_KEY_XOR)?;
            Ok(())
        }
        HW_5886_TAG_REGEXP => {
            let a = cur.charset_string(HW_5886_REGEXP_CHARSET_A)?;
            let flen = usize::from(cur.imm(HW_5886_REGEXP_FLAGS_LEN_XOR)?);
            let b = cur.charset_n(flen, HW_5886_REGEXP_CHARSET_B)?;
            push_str(strings, HW_5886_OPCODE, "HW", start_pc, a);
            push_str(strings, HW_5886_OPCODE, "HW", start_pc, b);
            Ok(())
        }
        _ => Err("xf_unskipped_tag"),
    }
}

/// tuples27 `Hx`/168: dst^193, LEB obj, charset^0 name, flags^63, arity×^228. No call.
fn skip_hx_5886(
    cur: &mut Cursor<'_>,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
) -> Result<(), &'static str> {
    let _dst = cur.imm(HX_5886_DST_XOR)?;
    let _obj = cur.leb()?;
    let text = cur.charset_string(HX_5886_CHARSET_XOR)?;
    let flags = cur.imm(HX_5886_FLAGS_XOR)?;
    for _ in 0..flags {
        let _ = cur.imm(HX_5886_ARG_XOR)?;
    }
    push_str(strings, HX_5886_OPCODE, "Hx", start_pc, text);
    Ok(())
}

/// tuples27 `HV`/230: dst^31, base^89, charset^126 name, flags^187, arity×^20. No call.
fn skip_hv_5886(
    cur: &mut Cursor<'_>,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
) -> Result<(), &'static str> {
    let _dst = cur.imm(HV_5886_DST_XOR)?;
    let _base = cur.imm(HV_5886_BASE_XOR)?;
    let text = cur.charset_string(HV_5886_CHARSET_XOR)?;
    let flags = cur.imm(HV_5886_FLAGS_XOR)?;
    for _ in 0..flags {
        let _ = cur.imm(HV_5886_ARG_XOR)?;
    }
    push_str(strings, HV_5886_OPCODE, "HV", start_pc, text);
    Ok(())
}

/// tuples27 `qC`/224: dst^33, LEB charset^146 name, extra^252. Property set is not executed.
fn skip_qc_5886(
    cur: &mut Cursor<'_>,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
) -> Result<(), &'static str> {
    let _dst = cur.imm(QC_5886_DST_XOR)?;
    let text = cur.charset_string(QC_5886_CHARSET_XOR)?;
    let _ = cur.imm(QC_5886_KEY_XOR)?;
    push_str(strings, QC_5886_OPCODE, "qC", start_pc, text);
    Ok(())
}

/// tuples27 `Hk`/70: LEB extra 0, dst^17, extra^88.
fn skip_hk_5886(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let _ = cur.leb()?;
    let _ = cur.imm(HK_LEB_5886_DST_XOR)?;
    let _ = cur.imm(HK_LEB_5886_KEY_XOR)?;
    Ok(())
}

fn skip_hg_table_5886(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let n = cur.leb()? as usize;
    if n > 1_048_576 {
        return Err("string_too_long");
    }
    for _ in 0..n {
        let _ = cur.leb()?;
    }
    Ok(())
}

fn skip_hf_hi_5886(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let _ = cur.leb()?;
    let _ = cur.imm(HF_HI_5886_XOR)?;
    Ok(())
}

fn skip_hx_call_5886(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let _ = cur.imm(HX_CALL_5886_DST_XOR)?;
    let _ = cur.imm(HX_CALL_5886_THIS_XOR)?;
    let arity = cur.imm(HX_CALL_5886_ARITY_XOR)?;
    for _ in 0..arity {
        let _ = cur.imm(HX_CALL_5886_ARG_XOR)?;
    }
    Ok(())
}

fn skip_ho_5886(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let _ = cur.imm(HO_5886_DST_XOR)?;
    let _ = cur.leb()?;
    let flags = cur.imm(HO_5886_FLAGS_XOR)?;
    for _ in 0..flags {
        let _ = cur.imm(HO_5886_ARG_XOR)?;
    }
    Ok(())
}

fn skip_ht_new_5886(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let _ = cur.imm(HT_NEW_5886_DST_XOR)?;
    let _ = cur.imm(HT_NEW_5886_CTOR_XOR)?;
    let arity = cur.imm(HT_NEW_5886_ARITY_XOR)?;
    for _ in 0..arity {
        let _ = cur.imm(HT_NEW_5886_ARG_XOR)?;
    }
    Ok(())
}

fn skip_he_5886(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let _ = cur.imm(HE_5886_DST_XOR)?;
    let _ = cur.imm(0)?;
    let _ = cur.imm(0)?;
    let _ = cur.imm(0)?;
    let _ = cur.imm(HE_5886_KEY_XOR)?;
    let _ = cur.imm(HE_5886_FLAGS_XOR)?;
    let arity = cur.imm(HE_5886_ARITY_XOR)?;
    for _ in 0..arity {
        let _ = cur.imm(HE_5886_ARG_XOR)?;
    }
    Ok(())
}

fn skip_hb_5886(cur: &mut Cursor<'_>) -> Result<(), &'static str> {
    let tag = cur.imm(HB_5886_TAG_XOR)?;
    let n = cur.leb()?;
    match tag {
        HB_5886_TAG_STORE | HB_5886_TAG_LOAD => {
            let _ = cur.imm(HB_5886_XOR)?;
            Ok(())
        }
        HB_5886_TAG_ALLOC => {
            if n as usize > 1_048_576 {
                return Err("string_too_long");
            }
            for _ in 0..n {
                let _ = cur.leb()?;
            }
            Ok(())
        }
        _ => Err("xf_unskipped_tag"),
    }
}

fn uses_5886_skip(params: FetchParams) -> bool {
    params.key_mul == FETCH_CHROME_2026_08_22_B_5886.key_mul
        && params.key_quad_b == FETCH_CHROME_2026_08_22_B_5886.key_quad_b
        && params.byte_bias == FETCH_CHROME_2026_08_22_B_5886.byte_bias
        && params.key_add == FETCH_CHROME_2026_08_22_B_5886.key_add
}

fn is_40954_fetch(params: FetchParams) -> bool {
    params.key_mul == FETCH_HTML_40954_UNVERIFIED.key_mul
        && params.key_quad_b == FETCH_HTML_40954_UNVERIFIED.key_quad_b
        && params.byte_bias == FETCH_HTML_40954_UNVERIFIED.byte_bias
        && params.key_add == FETCH_HTML_40954_UNVERIFIED.key_add
}

fn skip_profile_handler(
    cur: &mut Cursor<'_>,
    handler: &VmHandlerProfile,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
    profile_tags: &mut Vec<(u32, u8)>,
) -> Result<(), &'static str> {
    let opcode = handler.opcode;
    match &handler.spec {
        VmSkipSpec::FixedReads { extra_xors } => {
            for extra in extra_xors {
                let _ = cur.imm(*extra)?;
            }
            Ok(())
        }
        VmSkipSpec::Leb { byte_xor } => {
            let _ = cur.leb_with_extra(*byte_xor)?;
            Ok(())
        }
        VmSkipSpec::LebTable {
            count_byte_xor,
            index_byte_xor,
            max_count,
        } => {
            let count = cur.leb_with_extra(*count_byte_xor)?;
            if count > *max_count {
                return Err("profile_count_too_large");
            }
            for _ in 0..count {
                let _ = cur.leb_with_extra(*index_byte_xor)?;
            }
            Ok(())
        }
        VmSkipSpec::TaggedLoad {
            operand_order,
            tag_xor,
            dst_xor,
            tags,
        } => {
            let tag = match operand_order {
                VmTaggedOperandOrder::TagThenDst => {
                    let tag = cur.imm(*tag_xor)?;
                    let _dst = cur.imm(*dst_xor)?;
                    tag
                }
                VmTaggedOperandOrder::DstThenTag => {
                    let _dst = cur.imm(*dst_xor)?;
                    cur.imm(*tag_xor)?
                }
            };
            profile_tags.push((start_pc, tag));
            let Some(tag_profile) = tags.iter().find(|candidate| candidate.tag == tag) else {
                return Err("profile_tag_unknown");
            };
            match &tag_profile.payload {
                VmTagPayload::None => Ok(()),
                VmTagPayload::FixedReads { extra_xors } => {
                    for extra in extra_xors {
                        let _ = cur.imm(*extra)?;
                    }
                    Ok(())
                }
                VmTagPayload::Leb { byte_xor } => {
                    let _ = cur.leb_with_extra(*byte_xor)?;
                    Ok(())
                }
                VmTagPayload::String {
                    length_byte_xor,
                    char_xor,
                }
                | VmTagPayload::Bytes {
                    length_byte_xor,
                    char_xor,
                } => {
                    let text = cur.charset_string_with(*length_byte_xor, *char_xor)?;
                    push_str(
                        strings,
                        opcode,
                        handler.handler_label.clone(),
                        start_pc,
                        text,
                    );
                    Ok(())
                }
                VmTagPayload::Regexp {
                    pattern_length_byte_xor,
                    pattern_char_xor,
                    flags_length_xor,
                    flags_char_xor,
                } => {
                    let pattern =
                        cur.charset_string_with(*pattern_length_byte_xor, *pattern_char_xor)?;
                    let flags_len = usize::from(cur.imm(*flags_length_xor)?);
                    let flags = cur.charset_n(flags_len, *flags_char_xor)?;
                    push_str(
                        strings,
                        opcode,
                        handler.handler_label.clone(),
                        start_pc,
                        pattern,
                    );
                    push_str(
                        strings,
                        opcode,
                        handler.handler_label.clone(),
                        start_pc,
                        flags,
                    );
                    Ok(())
                }
            }
        }
        VmSkipSpec::StringLoad {
            prefix_xors,
            length_byte_xor,
            char_xor,
        } => {
            for extra in prefix_xors {
                let _ = cur.imm(*extra)?;
            }
            let text = cur.charset_string_with(*length_byte_xor, *char_xor)?;
            push_str(
                strings,
                opcode,
                handler.handler_label.clone(),
                start_pc,
                text,
            );
            Ok(())
        }
        VmSkipSpec::JumpStop { .. } => Err("jump_stop"),
        VmSkipSpec::Unknown { .. } => Err("unknown_handler"),
    }
}

fn fixed_width_5886(op: u8) -> Option<u8> {
    if QZ_5886_OPCODES.contains(&op) {
        return Some(4);
    }
    if QU_5886_OPCODES.contains(&op) {
        return Some(3);
    }
    match op {
        41 | 215 | 250 | 76 => Some(2),
        87 | 91 | 217 | 81 | 101 => Some(3),
        162 | 154 => Some(4),
        113 | 251 | 59 => Some(5),
        112 | 191 => Some(6),
        _ => None,
    }
}

fn skip_mapped_5886(
    cur: &mut Cursor<'_>,
    op: u8,
    start_pc: u32,
    strings: &mut Vec<HarvestedString>,
    hw_tags: &mut Vec<(u32, u8)>,
) -> Result<(), &'static str> {
    if JUMP_OPCODES_5886.contains(&op) {
        return Err("unparsed_jump");
    }
    match op {
        HG_5886_OPCODE => skip_hg_5886(cur),
        QR_5886_OPCODE => skip_qr_5886(cur, start_pc, strings),
        HW_5886_OPCODE => skip_hw_5886(cur, start_pc, strings, hw_tags),
        HX_5886_OPCODE => skip_hx_5886(cur, start_pc, strings),
        HV_5886_OPCODE => skip_hv_5886(cur, start_pc, strings),
        QC_5886_OPCODE => skip_qc_5886(cur, start_pc, strings),
        HK_LEB_5886_OPCODE => skip_hk_5886(cur),
        HG_TABLE_5886_OPCODE => skip_hg_table_5886(cur),
        HF_5886_OPCODE | HI_5886_OPCODE => skip_hf_hi_5886(cur),
        HX_CALL_5886_OPCODE => skip_hx_call_5886(cur),
        HO_5886_OPCODE => skip_ho_5886(cur),
        HT_NEW_5886_OPCODE => skip_ht_new_5886(cur),
        HE_5886_OPCODE => skip_he_5886(cur),
        HB_5886_OPCODE => skip_hb_5886(cur),
        _ => match fixed_width_5886(op) {
            Some(w) => cur.skip_fixed(w),
            None => Err("unmapped_opcode"),
        },
    }
}

fn empty_harvest(
    params: FetchParams,
    stopped: &'static str,
    profile_error: Option<String>,
) -> SkipHarvest {
    SkipHarvest {
        params_label: params.label,
        instructions: 0,
        last_pc: params.init_pc,
        last_opcode: None,
        stopped,
        strings: Vec::new(),
        ge_key_imms: Vec::new(),
        ops: Vec::new(),
        hw_tags: Vec::new(),
        profile_tags: Vec::new(),
        profile_error,
    }
}

/// Linear skip-harvest using an explicitly bound, statically extracted profile.
///
/// Validation occurs before the first opcode byte is consumed. A profile cannot
/// be selected by fetch constants alone: callers must supply the SHA-256 of the
/// current executed script separately from the profile JSON.
pub fn skip_harvest_with_profile(
    bytecode: &[u8],
    params: FetchParams,
    profile: &VmSkipProfile,
    observed_source_sha256: &str,
) -> SkipHarvest {
    if let Err(error) = profile.validate_for(params, observed_source_sha256) {
        return empty_harvest(params, "profile_mismatch", Some(error.reason));
    }
    skip_harvest_impl(bytecode, params, Some(profile))
}

/// Linear skip-harvest from `params.init_pc` / `init_key` using historical
/// built-in snapshots. Skips immediates without apply and never takes jumps.
///
/// The 40954 HTML candidate deliberately has no implicit built-in selection;
/// it requires [`skip_harvest_with_profile`].
pub fn skip_harvest_strings(bytecode: &[u8], params: FetchParams) -> SkipHarvest {
    if is_40954_fetch(params) {
        return empty_harvest(
            params,
            "profile_required",
            Some("40954 semantics require an explicit source-bound profile".into()),
        );
    }
    skip_harvest_impl(bytecode, params, None)
}

fn skip_harvest_impl(
    bytecode: &[u8],
    params: FetchParams,
    profile: Option<&VmSkipProfile>,
) -> SkipHarvest {
    let mut cur = Cursor {
        bytecode,
        params,
        pc: params.init_pc as usize,
        key: params.init_key,
    };
    let mut strings = Vec::new();
    let mut ge_key_imms = Vec::new();
    let mut ops = Vec::new();
    let mut hw_tags = Vec::new();
    let mut profile_tags = Vec::new();
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
        ops.push((last_pc, op));
        instructions += 1;
        let result = if let Some(profile) = profile {
            match profile.handler(op) {
                Some(handler) => skip_profile_handler(
                    &mut cur,
                    handler,
                    last_pc,
                    &mut strings,
                    &mut profile_tags,
                ),
                None => Err("unknown_handler"),
            }
        } else if uses_5886_skip(params) {
            skip_mapped_5886(&mut cur, op, last_pc, &mut strings, &mut hw_tags)
        } else if op == XF_OPCODE {
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
        ops,
        hw_tags,
        profile_tags,
        profile_error: None,
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
    use crate::solver::run_program_profile::{
        VM_SKIP_PROFILE_SCHEMA_VERSION, VmHandlerProfile, VmProfileFetch, VmSkipProfile,
        VmSkipSpec, VmTagPayload, VmTagProfile, VmTaggedOperandOrder, source_sha256_hex,
    };
    use crate::solver::run_program_vm::{
        FETCH_BRANCH_B_LATE, FETCH_CHROME_2026_08_22_B_5886, FETCH_HTML_40954_UNVERIFIED,
        FETCH_LIVE, FetchParams, encode_byte, next_key, verify_oracle_tuple,
    };

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

    fn bg_40954_tagged_spec() -> VmSkipSpec {
        let none = |tag| VmTagProfile {
            tag,
            payload: VmTagPayload::None,
        };
        VmSkipSpec::TaggedLoad {
            operand_order: VmTaggedOperandOrder::TagThenDst,
            tag_xor: BG_40954_TAG_XOR,
            dst_xor: BG_40954_DST_XOR,
            tags: vec![
                VmTagProfile {
                    tag: BG_40954_TAG_FLOAT,
                    payload: VmTagPayload::FixedReads {
                        extra_xors: vec![0; 8],
                    },
                },
                VmTagProfile {
                    tag: BG_40954_TAG_REGEXP,
                    payload: VmTagPayload::Regexp {
                        pattern_length_byte_xor: 0,
                        pattern_char_xor: BG_40954_REGEXP_CHARSET_A,
                        flags_length_xor: BG_40954_REGEXP_FLAGS_LEN_XOR,
                        flags_char_xor: BG_40954_REGEXP_CHARSET_B,
                    },
                },
                none(BG_40954_TAG_UNDEF),
                VmTagProfile {
                    tag: BG_40954_TAG_STRING,
                    payload: VmTagPayload::String {
                        length_byte_xor: 0,
                        char_xor: BG_40954_STRING_CHARSET_XOR,
                    },
                },
                VmTagProfile {
                    tag: BG_40954_TAG_INT,
                    payload: VmTagPayload::FixedReads {
                        extra_xors: vec![BG_40954_INT_XOR],
                    },
                },
                VmTagProfile {
                    tag: BG_40954_TAG_BYTES,
                    payload: VmTagPayload::Bytes {
                        length_byte_xor: 0,
                        char_xor: BG_40954_BYTES_CHARSET_XOR,
                    },
                },
                none(BG_40954_TAG_TRUE),
                VmTagProfile {
                    tag: BG_40954_TAG_LEB,
                    payload: VmTagPayload::Leb { byte_xor: 0 },
                },
                none(BG_40954_TAG_NUMBER_A),
                none(BG_40954_TAG_NUMBER_B),
                none(BG_40954_TAG_NULL),
                VmTagProfile {
                    tag: BG_40954_TAG_PACKED,
                    payload: VmTagPayload::FixedReads {
                        extra_xors: vec![0, 0, 0, BG_40954_PACKED_KEY_XOR],
                    },
                },
                none(BG_40954_TAG_FALSE),
            ],
        }
    }

    fn test_40954_profile(source: &[u8], include_leb_table: bool) -> VmSkipProfile {
        let source_sha256 = source_sha256_hex(source);
        let handlers = SWITCH_OPCODES_40954
            .iter()
            .copied()
            .map(|opcode| {
                let spec = if opcode == BG_40954_OPCODE {
                    bg_40954_tagged_spec()
                } else if opcode == 167 && include_leb_table {
                    VmSkipSpec::LebTable {
                        count_byte_xor: 0,
                        index_byte_xor: 0,
                        max_count: 1_048_576,
                    }
                } else if JUMP_OPCODES_40954.contains(&opcode) {
                    VmSkipSpec::JumpStop {
                        reason: "current handler writes the program counter".into(),
                    }
                } else {
                    VmSkipSpec::Unknown {
                        reason: "test profile has no proven recognizer".into(),
                    }
                };
                VmHandlerProfile {
                    opcode,
                    handler_label: format!("handler_{opcode}"),
                    handler_fingerprint: source_sha256_hex(
                        format!("normalized-handler-{opcode}-{spec:?}").as_bytes(),
                    ),
                    spec,
                }
            })
            .collect();
        let mut profile = VmSkipProfile {
            schema_version: VM_SKIP_PROFILE_SCHEMA_VERSION,
            source_sha256,
            semantic_fingerprint: "0".repeat(64),
            fetch: VmProfileFetch::from_params(FETCH_HTML_40954_UNVERIFIED),
            switch_opcodes: SWITCH_OPCODES_40954.to_vec(),
            handlers,
        };
        profile.semantic_fingerprint = profile.computed_semantic_fingerprint().unwrap();
        profile
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
    }

    #[test]
    fn skip_harvests_synthetic_hg_5886_call_without_apply() {
        let params = FetchParams {
            init_pc: 0,
            ..FETCH_CHROME_2026_08_22_B_5886
        };
        let mut buf = Vec::new();
        let mut key = params.init_key;
        buf.push(encode_byte(params, key, HG_5886_OPCODE));
        key = next_key(params, key, HG_5886_OPCODE);
        buf.push(encode_byte(params, key, 0 ^ HG_5886_CALLEE_XOR));
        buf.push(encode_byte(params, key, 0 ^ HG_5886_THIS_XOR));
        buf.push(encode_byte(params, key, 0 ^ HG_5886_DST_XOR));
        buf.push(encode_byte(params, key, 2 ^ HG_5886_ARITY_XOR));
        buf.push(encode_byte(params, key, 7 ^ HG_5886_ARG_XOR));
        buf.push(encode_byte(params, key, 8 ^ HG_5886_ARG_XOR));
        let h = skip_harvest_strings(&buf, params);
        assert_eq!(h.params_label, FETCH_CHROME_2026_08_22_B_5886.label);
        assert_eq!(h.last_opcode, Some(HG_5886_OPCODE));
        assert_eq!(h.instructions, 1);
        assert_eq!(h.stopped, "end_of_bytecode");
        assert!(h.strings.is_empty());
        assert_eq!(FETCH_LIVE.key_mul, 56_907);
    }

    #[test]
    fn skip_harvests_synthetic_qr_5886_property_name() {
        let params = FetchParams {
            init_pc: 0,
            ..FETCH_CHROME_2026_08_22_B_5886
        };
        let mut buf = Vec::new();
        let mut key = params.init_key;
        buf.push(encode_byte(params, key, QR_5886_OPCODE));
        key = next_key(params, key, QR_5886_OPCODE);
        buf.push(encode_byte(params, key, QR_5886_DST_XOR));
        buf.push(encode_byte(params, key, QR_5886_BASE_XOR));
        let text = "OQbM0";
        buf.push(encode_byte(params, key, text.len() as u8));
        for b in text.bytes() {
            buf.push(encode_byte(params, key, b ^ QR_5886_CHARSET_XOR));
        }
        let h = skip_harvest_strings(&buf, params);
        assert_eq!(h.last_opcode, Some(QR_5886_OPCODE));
        assert_eq!(h.strings.len(), 1);
        assert_eq!(h.strings[0].text, text);
        assert_eq!(h.stopped, "end_of_bytecode");
        assert!(h.contains_ident("OQbM0"));
        assert_eq!(FETCH_LIVE.key_mul, 56_907);
    }

    #[test]
    fn skip_harvests_synthetic_hw_5886_string() {
        let params = FetchParams {
            init_pc: 0,
            ..FETCH_CHROME_2026_08_22_B_5886
        };
        let mut buf = Vec::new();
        let mut key = params.init_key;
        buf.push(encode_byte(params, key, HW_5886_OPCODE));
        key = next_key(params, key, HW_5886_OPCODE);
        buf.push(encode_byte(params, key, 0 ^ HW_5886_DST_XOR));
        buf.push(encode_byte(
            params,
            key,
            HW_5886_TAG_STRING ^ HW_5886_TAG_XOR,
        ));
        let text = "sqKXG6";
        buf.push(encode_byte(params, key, text.len() as u8));
        for b in text.bytes() {
            buf.push(encode_byte(params, key, b ^ HW_5886_STRING_CHARSET_XOR));
        }
        let h = skip_harvest_strings(&buf, params);
        assert_eq!(h.last_opcode, Some(HW_5886_OPCODE));
        assert_eq!(h.strings.len(), 1);
        assert_eq!(h.strings[0].text, text);
        assert_eq!(h.stopped, "end_of_bytecode");
        assert_eq!(FETCH_LIVE.key_mul, 56_907);
    }

    #[test]
    fn skip_harvests_synthetic_bg_40954_string() {
        let params = FetchParams {
            init_pc: 0,
            ..FETCH_HTML_40954_UNVERIFIED
        };
        let source = b"synthetic 40954 executed JS";
        let profile = test_40954_profile(source, false);
        let mut buf = Vec::new();
        let mut key = params.init_key;
        buf.push(encode_byte(params, key, BG_40954_OPCODE));
        key = next_key(params, key, BG_40954_OPCODE);
        buf.push(encode_byte(
            params,
            key,
            BG_40954_TAG_STRING ^ BG_40954_TAG_XOR,
        ));
        buf.push(encode_byte(params, key, 0 ^ BG_40954_DST_XOR));
        let text = "window";
        buf.push(encode_byte(params, key, text.len() as u8));
        for b in text.bytes() {
            buf.push(encode_byte(params, key, b ^ BG_40954_STRING_CHARSET_XOR));
        }
        let implicit = skip_harvest_strings(&buf, params);
        assert_eq!(implicit.stopped, "profile_required");
        assert_eq!(implicit.instructions, 0);
        assert_eq!(implicit.last_opcode, None);

        let mismatched =
            skip_harvest_with_profile(&buf, params, &profile, &source_sha256_hex(b"other JS"));
        assert_eq!(mismatched.stopped, "profile_mismatch");
        assert_eq!(mismatched.instructions, 0);
        assert_eq!(mismatched.last_opcode, None);

        let h = skip_harvest_with_profile(&buf, params, &profile, &source_sha256_hex(source));
        assert_eq!(h.params_label, FETCH_HTML_40954_UNVERIFIED.label);
        assert_eq!(h.last_opcode, Some(BG_40954_OPCODE));
        assert_eq!(h.strings.len(), 1);
        assert_eq!(h.strings[0].text, text);
        assert_eq!(h.strings[0].handler, "handler_181");
        assert_eq!(h.profile_tags, vec![(0, BG_40954_TAG_STRING)]);
        assert_eq!(h.stopped, "end_of_bytecode");
        assert_eq!(FETCH_LIVE.key_mul, 56_907);
        assert_ne!(params.key_mul, FETCH_LIVE.key_mul);
        assert_ne!(params.key_mul, FETCH_CHROME_2026_08_22_B_5886.key_mul);
        assert_eq!(BG_40954_TAG_XOR, 217);
        assert_eq!(BG_40954_DST_XOR, 210);
        assert_eq!(BG_40954_STRING_CHARSET_XOR, 225);
        assert_eq!(SWITCH_OPCODES_40954.len(), 69);
        assert!(SWITCH_OPCODES_40954.contains(&BG_40954_OPCODE));
        assert!(JUMP_OPCODES_40954.contains(&247));
        assert!(!JUMP_OPCODES_40954.contains(&BG_40954_OPCODE));
    }

    #[test]
    fn skip_harvests_synthetic_qc_5886_property_name() {
        let params = FetchParams {
            init_pc: 0,
            ..FETCH_CHROME_2026_08_22_B_5886
        };
        let mut buf = Vec::new();
        let mut key = params.init_key;
        buf.push(encode_byte(params, key, QC_5886_OPCODE));
        key = next_key(params, key, QC_5886_OPCODE);
        buf.push(encode_byte(params, key, QC_5886_DST_XOR));
        let text = "mQiic7";
        buf.push(encode_byte(params, key, text.len() as u8));
        for b in text.bytes() {
            buf.push(encode_byte(params, key, b ^ QC_5886_CHARSET_XOR));
        }
        buf.push(encode_byte(params, key, QC_5886_KEY_XOR));
        let h = skip_harvest_strings(&buf, params);
        assert_eq!(h.last_opcode, Some(QC_5886_OPCODE));
        assert_eq!(h.strings.len(), 1);
        assert_eq!(h.strings[0].text, text);
        assert_eq!(h.stopped, "end_of_bytecode");
        assert_eq!(FETCH_LIVE.key_mul, 56_907);
    }

    #[test]
    fn inline_56907_stub_has_host_strings_not_followup_idents() {
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        if !html.contains("56907") || !html.contains("Xw+=go[Xt^3+XM[Xm++]&255^136]") {
            return;
        }
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
        let path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-packed2/fo-init-response.txt");
        let ray_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-packed2/fo-init-ray.txt");
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
        assert!(
            packed.starts_with("1oUjjpq4"),
            "prefix {}",
            &packed[..20.min(packed.len())]
        );
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

    #[test]
    fn tuples27_5886_bytes_match_and_skip_harvest_if_dump_present() {
        let oracle_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-tuples27/oracle.json");
        let resp_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-tuples27/fo-init-response.txt");
        let ray_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-tuples27/fo-init-ray.txt");
        if !oracle_path.is_file() || !resp_path.is_file() || !ray_path.is_file() {
            return;
        }
        assert_eq!(FETCH_LIVE.key_mul, 56_907);
        assert_eq!(
            crate::solver::run_program_ops::NEXT_GAP,
            "handler_semantics"
        );
        let oracle: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(oracle_path).unwrap()).unwrap();
        let rows = oracle
            .get("fetchLoopTuples")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(rows.len(), 9, "tuples27 harvest row count");
        for f in &rows {
            let pc = f.get("pc").and_then(|x| x.as_u64()).unwrap() as u32;
            let key = f.get("key").and_then(|x| x.as_u64()).unwrap() as u8;
            let byte = f.get("byte").and_then(|x| x.as_u64()).unwrap() as u8;
            let op = f.get("op").and_then(|x| x.as_u64()).unwrap() as u8;
            verify_oracle_tuple(FETCH_CHROME_2026_08_22_B_5886, pc, key, byte, op)
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(
                verify_oracle_tuple(FETCH_LIVE, pc, key, byte, op).is_err(),
                "FETCH_LIVE must not decode tuples27 pc={pc}"
            );
        }
        let ray = std::fs::read_to_string(ray_path).unwrap();
        let ray = ray.trim();
        let body = std::fs::read_to_string(resp_path).unwrap();
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let padded = match compact.len() % 4 {
            2 => format!("{compact}=="),
            3 => format!("{compact}="),
            _ => compact,
        };
        let packed = crate::reverse::encryption::decrypt_cloudflare_response(ray, &padded).unwrap();
        let bc = unpack_packed_run_program(&packed).unwrap();
        assert_eq!(
            bc.len(),
            476_051,
            "unpacked /fo/ bytecode len vs live harvest bcLen"
        );
        for f in &rows {
            let pc = f.get("pc").and_then(|x| x.as_u64()).unwrap() as usize;
            let byte = f.get("byte").and_then(|x| x.as_u64()).unwrap() as u8;
            assert!(
                pc < bc.len(),
                "harvest pc {pc} past unpacked len {}",
                bc.len()
            );
            assert_eq!(
                bc[pc], byte,
                "unpacked bytecode[pc={pc}] = {} harvest byte={byte}",
                bc[pc]
            );
        }
        let h = skip_harvest_strings(&bc, FETCH_CHROME_2026_08_22_B_5886);
        assert_eq!(h.params_label, FETCH_CHROME_2026_08_22_B_5886.label);
        let html_entry = FetchParams {
            label: "html-candidate-176-unverified",
            init_pc: 0,
            init_key: 176,
            byte_bias: FETCH_CHROME_2026_08_22_B_5886.byte_bias,
            key_mul: FETCH_CHROME_2026_08_22_B_5886.key_mul,
            key_add: FETCH_CHROME_2026_08_22_B_5886.key_add,
            key_quad_b: FETCH_CHROME_2026_08_22_B_5886.key_quad_b,
        };
        let from_zero = skip_harvest_strings(&bc, html_entry);
        assert_ne!(
            from_zero.params_label, FETCH_LIVE.label,
            "HTML 176 start must not be labeled FETCH_LIVE"
        );
        let mut union_strings: Vec<String> = h.strings.iter().map(|s| s.text.clone()).collect();
        union_strings.extend(from_zero.strings.iter().map(|s| s.text.clone()));
        for f in &rows {
            let pc = f.get("pc").and_then(|x| x.as_u64()).unwrap() as u32;
            let key = f.get("key").and_then(|x| x.as_u64()).unwrap() as u8;
            if pc == FETCH_CHROME_2026_08_22_B_5886.init_pc
                && key == FETCH_CHROME_2026_08_22_B_5886.init_key
            {
                continue;
            }
            let start = FetchParams {
                init_pc: pc,
                init_key: key,
                ..FETCH_CHROME_2026_08_22_B_5886
            };
            let block = skip_harvest_strings(&bc, start);
            union_strings.extend(block.strings.iter().map(|s| s.text.clone()));
        }
        let leftover_hits: Vec<&str> = FOLLOWUP_UNSEEN_EXTRA_IDENT_B
            .iter()
            .copied()
            .filter(|n| {
                h.contains_ident(n) || union_strings.iter().any(|s| s == n || s.contains(n))
            })
            .collect();
        let extra_hits: Vec<&str> = FOLLOWUP_EXTRA_IDENT_B
            .iter()
            .copied()
            .filter(|n| {
                h.contains_ident(n) || union_strings.iter().any(|s| s == n || s.contains(n))
            })
            .collect();
        let packed_leftover: Vec<&str> = FOLLOWUP_UNSEEN_EXTRA_IDENT_B
            .iter()
            .copied()
            .filter(|n| packed.contains(n))
            .collect();
        assert!(
            matches!(
                h.stopped,
                "unmapped_opcode"
                    | "unparsed_jump"
                    | "unparsed_variable"
                    | "end_of_bytecode"
                    | "xf_unskipped_tag"
                    | "eof_imm"
                    | "eof_fixed"
                    | "limit"
            ),
            "5886 skip-harvest stopped={} last_pc={} last_op={:?} instr={} strings={} leftover={leftover_hits:?} extra={extra_hits:?} packed_leftover={packed_leftover:?}",
            h.stopped,
            h.last_pc,
            h.last_opcode,
            h.instructions,
            h.strings.len()
        );
        assert_eq!(SWITCH_OPCODES_5886.len(), 69);
        let from_zero_leftover: Vec<&str> = FOLLOWUP_UNSEEN_EXTRA_IDENT_B
            .iter()
            .copied()
            .filter(|n| from_zero.contains_ident(n))
            .collect();
        let h_texts: Vec<&str> = h.strings.iter().map(|s| s.text.as_str()).collect();
        let z_texts: Vec<&str> = from_zero.strings.iter().map(|s| s.text.as_str()).collect();
        let mut union_unique = union_strings.clone();
        union_unique.sort();
        union_unique.dedup();
        let ops_head: Vec<(u32, u8)> = h.ops.iter().copied().take(32).collect();
        let z_ops_head: Vec<(u32, u8)> = from_zero.ops.iter().copied().take(32).collect();
        eprintln!(
            "tuples27 5886 skip-harvest stopped={} last_pc={} last_op={:?} instr={} leftover={leftover_hits:?} extra={extra_hits:?} packed_leftover={packed_leftover:?} ops={ops_head:?} hw_tags={:?} texts={h_texts:?} union_n={} union_unique={:?} html176 stopped={} last_pc={} last_op={:?} instr={} leftover={from_zero_leftover:?} ops={z_ops_head:?} hw_tags={:?} texts={z_texts:?}",
            h.stopped,
            h.last_pc,
            h.last_opcode,
            h.instructions,
            h.hw_tags,
            union_strings.len(),
            union_unique,
            from_zero.stopped,
            from_zero.last_pc,
            from_zero.last_opcode,
            from_zero.instructions,
            from_zero.hw_tags
        );
        assert!(
            z_texts.contains(&"window"),
            "html176 HW strings {z_texts:?}"
        );
        assert_eq!(from_zero.stopped, "unparsed_jump");
        assert_eq!(from_zero.last_opcode, Some(135));
        assert_eq!(h.stopped, "unmapped_opcode");
        assert_eq!(h.last_opcode, Some(54));
        assert!(
            !SWITCH_OPCODES_5886.contains(&54),
            "opcode 54 is absent from the tuples27 fetch switch"
        );
        assert!(
            !(h.last_pc == 181 && h.last_opcode == Some(HW_5886_OPCODE)),
            "HW/156 at pc=181 must be skipped (not a jump); stopped={}",
            h.stopped
        );
        assert!(
            !(from_zero.last_pc == 0 && from_zero.last_opcode == Some(HW_5886_OPCODE)),
            "html176 HW/156 at pc=0 must be skipped; stopped={} instr={}",
            from_zero.stopped,
            from_zero.instructions
        );
        assert_eq!(FETCH_LIVE.key_mul, 56_907);
        assert!(
            leftover_hits.is_empty(),
            "56907 leftover names on 5886 linear slices {leftover_hits:?}"
        );
        assert!(
            union_unique.iter().any(|s| s == "window"),
            "union HW/qR/Hx strings {union_unique:?}"
        );
        assert!(
            packed_leftover.is_empty(),
            "leftover names in tuples27 packed plaintext {packed_leftover:?}"
        );
    }

    #[test]
    fn leftover1_40954_html_fetch_skip_harvest_if_dump_present() {
        let resp_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-leftover1/fo-init-response.txt");
        let ray_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-leftover1/fo-init-ray.txt");
        let js_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-leftover1/executed-fetch-15.js");
        if !resp_path.is_file() || !ray_path.is_file() || !js_path.is_file() {
            return;
        }
        let js = std::fs::read_to_string(js_path).unwrap();
        assert!(js.contains("*40954,30072)&255"), "leftover1 HTML fetch");
        assert!(
            js.contains("255+MW[F],255"),
            "leftover1 (255+byte)&255 bias 1"
        );
        assert!(
            js.contains("case 181:bg["),
            "leftover1 opcode 181 is bg.call(this)"
        );
        assert!(
            js.contains("^217),MU=") || js.contains("^217.96") || js.contains(",217),"),
            "leftover1 bg tag extra 217"
        );
        assert!(
            !js.contains("function f4("),
            "compressor is not f4 on leftover1"
        );
        assert!(js.contains("Mt=function("), "body encoder Mt");
        assert_eq!(FETCH_LIVE.key_mul, 56_907);
        let html_fetch = FETCH_HTML_40954_UNVERIFIED;
        assert_ne!(html_fetch.key_mul, FETCH_LIVE.key_mul);
        assert_ne!(html_fetch.key_mul, FETCH_CHROME_2026_08_22_B_5886.key_mul);
        let profile = test_40954_profile(js.as_bytes(), false);
        let ray = std::fs::read_to_string(ray_path).unwrap();
        let ray = ray.trim();
        let body = std::fs::read_to_string(resp_path).unwrap();
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let padded = match compact.len() % 4 {
            2 => format!("{compact}=="),
            3 => format!("{compact}="),
            _ => compact,
        };
        let packed = crate::reverse::encryption::decrypt_cloudflare_response(ray, &padded).unwrap();
        let bc = unpack_packed_run_program(&packed).unwrap();
        assert!(
            bc.len() > 10_000,
            "unpacked leftover1 bytecode too small {}",
            bc.len()
        );
        let packed_leftover: Vec<&str> = FOLLOWUP_UNSEEN_EXTRA_IDENT_B
            .iter()
            .copied()
            .filter(|n| packed.contains(n))
            .collect();
        let implicit = skip_harvest_strings(&bc, html_fetch);
        assert_eq!(implicit.stopped, "profile_required");
        assert_eq!(implicit.instructions, 0);
        let h =
            skip_harvest_with_profile(&bc, html_fetch, &profile, &source_sha256_hex(js.as_bytes()));
        let texts: Vec<&str> = h.strings.iter().map(|s| s.text.as_str()).collect();
        let leftover_hits: Vec<&str> = FOLLOWUP_UNSEEN_EXTRA_IDENT_B
            .iter()
            .copied()
            .filter(|n| h.contains_ident(n))
            .collect();
        eprintln!(
            "leftover1 40954 skip-harvest stopped={} last_pc={} last_op={:?} instr={} strings={} leftover={leftover_hits:?} packed_leftover={packed_leftover:?} texts={texts:?} profile_tags={:?} bc_len={}",
            h.stopped,
            h.last_pc,
            h.last_opcode,
            h.instructions,
            h.strings.len(),
            h.profile_tags,
            bc.len()
        );
        assert_eq!(h.params_label, html_fetch.label);
        assert!(
            texts.contains(&"window"),
            "leftover1 bg/181 ident-like strings {texts:?}"
        );
        assert_eq!(h.stopped, "unknown_handler");
        assert_eq!(h.last_opcode, Some(167));
        assert!(
            leftover_hits.is_empty(),
            "56907 leftover names on 40954 skip-harvest {leftover_hits:?}"
        );
        assert!(
            packed_leftover.is_empty(),
            "56907 leftover names in leftover1 packed plaintext {packed_leftover:?}"
        );
        assert!(
            !(h.last_pc == 0
                && h.last_opcode == Some(BG_40954_OPCODE)
                && h.stopped != "end_of_bytecode"
                && h.instructions == 1
                && h.profile_tags.is_empty()),
            "bg/181 at pc=0 must be skipped; stopped={} instr={} tags={:?}",
            h.stopped,
            h.instructions,
            h.profile_tags
        );
        assert!(
            !h.profile_tags.is_empty() || h.instructions > 1,
            "leftover1 must skip bg/181; stopped={} last_op={:?} instr={}",
            h.stopped,
            h.last_opcode,
            h.instructions
        );
        assert_eq!(
            crate::solver::run_program_ops::NEXT_GAP,
            "handler_semantics"
        );
    }

    #[test]
    fn leftover4_extra_ident_now_skip_harvest_if_dump_present() {
        let oracle_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-leftover4/oracle.json");
        let resp_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-leftover4/fo-init-response.txt");
        let ray_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-leftover4/fo-init-ray.txt");
        let js_path =
            std::path::Path::new("artifacts/re-out/chrome-oracle-leftover4/executed-fetch-15.js");
        if !oracle_path.is_file()
            || !resp_path.is_file()
            || !ray_path.is_file()
            || !js_path.is_file()
        {
            return;
        }
        let oracle: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(oracle_path).unwrap()).unwrap();
        let extra: Vec<String> = oracle
            .pointer("/leftoverProbe/extraIdentNow")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let js = std::fs::read_to_string(js_path).unwrap();
        assert!(
            js.contains("case 181:bg["),
            "leftover4 opcode 181 is bg.call(this)"
        );
        assert!(
            js.contains("^217.96") || js.contains("^217)"),
            "leftover4 bg tag extra 217.96"
        );
        assert!(
            js.contains(",210)") || js.contains("^210"),
            "leftover4 bg dst extra 210"
        );
        assert!(
            js.contains("^225.23") || js.contains("^225]"),
            "leftover4 string charset 225"
        );
        assert!(
            extra.iter().any(|n| n == "AmbKQ5"),
            "leftover4 extraIdentNow {extra:?}"
        );
        assert!(
            extra.iter().any(|n| n == "xBCsP4"),
            "leftover4 extraIdentNow {extra:?}"
        );
        let mul = oracle
            .pointer("/fetchSchedule/keyMul")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        assert_eq!(mul, 40_954);
        assert_ne!(mul, FETCH_LIVE.key_mul as u64);
        let html_fetch = FETCH_HTML_40954_UNVERIFIED;
        let profile = test_40954_profile(js.as_bytes(), false);
        let ray = std::fs::read_to_string(ray_path).unwrap();
        let ray = ray.trim();
        let body = std::fs::read_to_string(resp_path).unwrap();
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let padded = match compact.len() % 4 {
            2 => format!("{compact}=="),
            3 => format!("{compact}="),
            _ => compact,
        };
        let packed = crate::reverse::encryption::decrypt_cloudflare_response(ray, &padded).unwrap();
        let bc = unpack_packed_run_program(&packed).unwrap();
        let implicit = skip_harvest_strings(&bc, html_fetch);
        assert_eq!(implicit.stopped, "profile_required");
        assert_eq!(implicit.instructions, 0);
        let h =
            skip_harvest_with_profile(&bc, html_fetch, &profile, &source_sha256_hex(js.as_bytes()));
        let leftover_hits: Vec<&str> = extra
            .iter()
            .map(String::as_str)
            .filter(|n| h.contains_ident(n))
            .collect();
        let packed_hits: Vec<&str> = extra
            .iter()
            .map(String::as_str)
            .filter(|n| packed.contains(*n))
            .collect();
        eprintln!(
            "leftover4 40954 skip-harvest stopped={} last_pc={} last_op={:?} instr={} extra={extra:?} leftover_hits={leftover_hits:?} packed_hits={packed_hits:?} texts={:?} profile_tags={:?} bc_len={}",
            h.stopped,
            h.last_pc,
            h.last_opcode,
            h.instructions,
            h.strings
                .iter()
                .map(|s| s.text.as_str())
                .collect::<Vec<_>>(),
            h.profile_tags,
            bc.len()
        );
        assert!(
            leftover_hits.is_empty(),
            "early extraIdentNow in 40954 skip-harvest {leftover_hits:?} stopped={}",
            h.stopped
        );
        assert!(
            packed_hits.is_empty(),
            "early extraIdentNow in leftover4 packed plaintext {packed_hits:?}"
        );
        assert!(
            h.contains_ident("window"),
            "leftover4 bg/181 ident-like strings {:?}",
            h.strings
                .iter()
                .map(|s| s.text.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(h.stopped, "unknown_handler");
        assert_eq!(h.last_opcode, Some(167));
        assert!(
            !h.profile_tags.is_empty(),
            "leftover4 bg/181 at pc=0 must be skipped; stopped={} last_op={:?} instr={}",
            h.stopped,
            h.last_opcode,
            h.instructions
        );
        assert_eq!(h.profile_tags[0], (0, h.profile_tags[0].1));
        assert!(
            !(h.last_pc == 0
                && h.last_opcode == Some(BG_40954_OPCODE)
                && h.instructions == 1
                && matches!(h.stopped, "unparsed_variable")),
            "bg/181 is no longer 56907 unparsed_variable; stopped={}",
            h.stopped
        );
        assert_eq!(
            crate::solver::run_program_ops::NEXT_GAP,
            "handler_semantics"
        );
        assert_eq!(FETCH_LIVE.key_mul, 56_907);
    }
}
