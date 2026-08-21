//! Operand encodings for mapped `runProgram` handlers.
//!
//! After the fetch loop consumes the opcode byte and updates `key` with mul/add,
//! handlers read immediates **with the post-fetch key** (`g[this.i]` at handler
//! entry) and **without** the mul/add schedule:
//!
//! ```text
//! imm = next_key ^ wrapping_sub(byte, bias) ^ extra_xor
//! ```
//!
//! `extra_xor` is JS `ToInt32` of an obfuscated float (`62.48` → `62`). Register
//! slots are then usually `imm ^ this.h`. Headed Chrome logs PC deltas: a stable
//! small delta is the instruction width; large or negative deltas are jumps.
//!
//! Late-`b` (`56907`) extra-xors for the Chrome-stable widths (`gq`/246,
//! `gG`/227, `X3`/104, `gY`/72, `X4`/12, `Xz`/52, `Xg`/130, `ge`/169) plus
//! already-mapped `Xf`/222 live in [`HANDLER_LAYOUT_B_LATE`]. Minified names
//! rotate on later same-day HTML (`gx`/`ge`/`X4`/`gZ`/`Xg` for the first five;
//! `X5`/`Xv`/`XX`/`gN` for the four added here); opcode numbers and `ToInt32`
//! extras did not.
//!
//! This module does **not** execute handlers or produce a token.

use crate::solver::run_program_vm::{
    FETCH_BRANCH_B, FETCH_BRANCH_B_LATE, FetchParams, OPCODE_TABLE_B, OPCODE_TABLE_B_LATE,
    OpcodeDef, decode_opcode, opcode_def_in, step_fetch,
};
use serde::Serialize;

/// Remaining live gap after fetch, operands, `f4`, init-JSON shape, follow-up
/// envelope, late-`b` extra-xors, and follow-up JSON key names: handler semantics.
pub const NEXT_GAP: &str = crate::solver::fo_followup_json::NEXT_AFTER_FOLLOWUP_JSON;

/// JS `x ^ 62.48` is `x ^ ToInt32(62.48)` = `x ^ 62`.
pub fn js_xor_imm(float_const: f64) -> u8 {
    (float_const as i32) as u8
}

/// Operand byte using the **post-fetch** key.
pub fn operand_from_byte(params: FetchParams, next_key: u8, byte: u8, extra_xor: u8) -> u8 {
    decode_opcode(params, next_key, byte) ^ extra_xor
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstrWidth {
    /// Total bytes including the opcode. Stable across Chrome PC deltas.
    Fixed(u8),
    /// Tagged load / unary family / control flow — width depends on the tag.
    Variable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HandlerLayout {
    pub opcode: u8,
    pub handler: &'static str,
    pub width: InstrWidth,
    pub extra_xors: &'static [u8],
    pub note: &'static str,
}

/// First mapped opcode on live branch `b` (`case 8: dN`).
///
/// Tagged constant load. Tag extra-xor is `154.33` → 154; dst extra-xor is 48.
/// Magic `TX5omy48…` decodes tag **179** (string).
pub const DN_OPCODE: u8 = 8;
pub const DN_TAG_XOR: u8 = 154;
pub const DN_DST_XOR: u8 = 48;
pub const DN_INT_XOR: u8 = 59;
pub const DN_TAG_INT: u8 = 49;
pub const DN_TAG_UNDEF: u8 = 230;
pub const DN_TAG_STRING: u8 = 179;
pub const DN_TAG_NULL: u8 = 42;
pub const DN_TAG_FALSE: u8 = 66;
pub const DN_TAG_FLOAT: u8 = 191;
pub const DN_TAG_BYTES: u8 = 206;

/// Later same-day tagged load (`case 222: Xf`). Same family as `dN`; extras rotated.
pub const XF_OPCODE: u8 = 222;
pub const XF_TAG_XOR: u8 = 86;
pub const XF_DST_XOR: u8 = 112;
pub const XF_INT_XOR: u8 = 19;
pub const XF_TAG_INT: u8 = 162;
pub const XF_TAG_UNDEF: u8 = 86;
pub const XF_TAG_STRING: u8 = 199;
pub const XF_TAG_LEB: u8 = 36;
pub const XF_TAG_FLOAT: u8 = 58;
pub const XF_TAG_NULL: u8 = 80;
pub const XF_TAG_FALSE: u8 = 202;
pub const XF_TAG_BYTES: u8 = 161;

/// Fixed-width handlers recovered from the headed-Chrome iframe (branch `b`).
/// Operand extras are `ToInt32` of the floats in the handler source.
pub const HANDLER_LAYOUT_B: &[HandlerLayout] = &[
    HandlerLayout {
        opcode: 8,
        handler: "dN",
        width: InstrWidth::Variable,
        extra_xors: &[DN_TAG_XOR, DN_DST_XOR],
        note: "tagged load: 49 int (+xor 59), 230 undef, 179 string, 191 float, 42 null, 66 false, 206 bytes",
    },
    HandlerLayout {
        opcode: 14,
        handler: "d6",
        width: InstrWidth::Fixed(2),
        extra_xors: &[62],
        note: "store {} at (imm^h)",
    },
    HandlerLayout {
        opcode: 176,
        handler: "d7",
        width: InstrWidth::Fixed(2),
        extra_xors: &[8],
        note: "store [] at (imm^h)",
    },
    HandlerLayout {
        opcode: 50,
        handler: "d4",
        width: InstrWidth::Fixed(2),
        extra_xors: &[29],
        note: "throw register",
    },
    HandlerLayout {
        opcode: 215,
        handler: "d5",
        width: InstrWidth::Fixed(2),
        extra_xors: &[154],
        note: "1-imm helper (stack/slot xor 36 and 53 are not bytecode)",
    },
    HandlerLayout {
        opcode: 49,
        handler: "dQ",
        width: InstrWidth::Fixed(3),
        extra_xors: &[48, 59],
        note: "2-imm store of a decoded byte",
    },
    HandlerLayout {
        opcode: 0,
        handler: "d1",
        width: InstrWidth::Fixed(3),
        extra_xors: &[123, 5],
        note: "array push",
    },
    HandlerLayout {
        opcode: 31,
        handler: "d3",
        width: InstrWidth::Fixed(3),
        extra_xors: &[205, 31],
        note: "2-imm call/result store",
    },
    HandlerLayout {
        opcode: 9,
        handler: "p",
        width: InstrWidth::Fixed(4),
        extra_xors: &[80, 243, 107],
        note: "property get: dst = obj[key]",
    },
    HandlerLayout {
        opcode: 112,
        handler: "F",
        width: InstrWidth::Fixed(4),
        extra_xors: &[84, 250, 33],
        note: "property set: obj[key] = src",
    },
    HandlerLayout {
        opcode: 185,
        handler: "x",
        width: InstrWidth::Variable,
        extra_xors: &[],
        note: "s1 family: switch immediate from the case (245,17,105,…) plus bytecode",
    },
    HandlerLayout {
        opcode: 69,
        handler: "g",
        width: InstrWidth::Variable,
        extra_xors: &[],
        note: "s2 family: unary typeof/- /+ /! /~ selected by switch immediate",
    },
    HandlerLayout {
        opcode: 222,
        handler: "Xf",
        width: InstrWidth::Variable,
        extra_xors: &[XF_TAG_XOR, XF_DST_XOR],
        note: "later-day tagged load (dN renamed): 162 int (+xor 19), 86 undef, 199 string, 36 LEB, 58 float, 80 null, 202 false, 161 bytes",
    },
];

/// Late-`b` (`56907`) handlers whose Chrome PC deltas are stable widths.
///
/// Operand extras are `ToInt32` of the floats next to bytecode bumps in the
/// headed-Chrome iframe (`chrome-oracle` / `chrome-oracle-bp` used these
/// names; `chrome-oracle-norm` renamed the functions).
pub const GQ_OPCODE: u8 = 246;
pub const GG_OPCODE: u8 = 227;
pub const X3_OPCODE: u8 = 104;
pub const GY_OPCODE: u8 = 72;
/// Late-`b` `store []` (`d7` analogue). Later HTML calls this `X5`; later HTML's `X4` is opcode 104.
pub const X4_OPCODE: u8 = 12;
pub const XZ_OPCODE: u8 = 52;
pub const XG_OPCODE: u8 = 130;
/// 4-imm property set. Later HTML calls this `gN`; later HTML's `ge` is opcode 227.
pub const GE_OPCODE: u8 = 169;

pub const HANDLER_LAYOUT_B_LATE: &[HandlerLayout] = &[
    HandlerLayout {
        opcode: XF_OPCODE,
        handler: "Xf",
        width: InstrWidth::Variable,
        extra_xors: &[XF_TAG_XOR, XF_DST_XOR],
        note: "tagged load: tag^86 dst^112, string tag 199. Later HTML calls this Xg.",
    },
    HandlerLayout {
        opcode: GQ_OPCODE,
        handler: "gq",
        width: InstrWidth::Fixed(3),
        extra_xors: &[123, 148],
        note: "2-imm (js 123.64/123.07, 148); dst slot then register load. Later HTML: gx.",
    },
    HandlerLayout {
        opcode: GG_OPCODE,
        handler: "gG",
        width: InstrWidth::Fixed(4),
        extra_xors: &[221, 41, 180],
        note: "3-imm (js 221, 41, 180.99); obj[key] = src. Later HTML: ge.",
    },
    HandlerLayout {
        opcode: X3_OPCODE,
        handler: "X3",
        width: InstrWidth::Fixed(2),
        extra_xors: &[1],
        note: "1-imm store {} at (imm^h); early-b d6 analogue. Later HTML: X4.",
    },
    HandlerLayout {
        opcode: GY_OPCODE,
        handler: "gY",
        width: InstrWidth::Fixed(5),
        extra_xors: &[117, 221, 231, 177],
        note: "4-imm nested property get dst = obj[k1][k2] (js 177.81). Later HTML: gZ.",
    },
    HandlerLayout {
        opcode: X4_OPCODE,
        handler: "X4",
        width: InstrWidth::Fixed(2),
        extra_xors: &[58],
        note: "1-imm store [] at (imm^h); early-b d7 analogue (js ^58). Later HTML: X5.",
    },
    HandlerLayout {
        opcode: XZ_OPCODE,
        handler: "Xz",
        width: InstrWidth::Fixed(3),
        extra_xors: &[132],
        note: "LEB then slot^132.63; Xm[XQ]['o']=reg. Chrome histogram was all width 3 (1-byte LEB). Later HTML: Xv.",
    },
    HandlerLayout {
        opcode: XG_OPCODE,
        handler: "Xg",
        width: InstrWidth::Fixed(3),
        extra_xors: &[112, 19],
        note: "2-imm store (js 112.87, 19). Later HTML: XX.",
    },
    HandlerLayout {
        opcode: GE_OPCODE,
        handler: "ge",
        width: InstrWidth::Fixed(5),
        extra_xors: &[41, 221, 180, 19],
        note: "4-imm property set dest[key]=src (js 41.43, 221, 180, 19). Later HTML: gN.",
    },
];

pub fn layout_for(opcode: u8) -> Option<&'static HandlerLayout> {
    HANDLER_LAYOUT_B.iter().find(|h| h.opcode == opcode)
}

pub fn layout_for_late(opcode: u8) -> Option<&'static HandlerLayout> {
    HANDLER_LAYOUT_B_LATE.iter().find(|h| h.opcode == opcode)
}

/// First `dN` tag in a branch-`b` packed program (opcode 8 at pc 0).
pub fn first_dn_tag(params: FetchParams, bytecode: &[u8]) -> Option<u8> {
    if bytecode.len() < 2 {
        return None;
    }
    let (op, next_key) = step_fetch(params, params.init_key, bytecode[0]);
    if op != DN_OPCODE {
        return None;
    }
    Some(operand_from_byte(params, next_key, bytecode[1], DN_TAG_XOR))
}

pub fn first_dn_tag_b(bytecode: &[u8]) -> Option<u8> {
    first_dn_tag(FETCH_BRANCH_B, bytecode)
}

/// First `Xf` tag on the later same-day `b` rotation (opcode 222 at pc 0).
pub fn first_xf_tag(params: FetchParams, bytecode: &[u8]) -> Option<u8> {
    if bytecode.len() < 2 {
        return None;
    }
    let (op, next_key) = step_fetch(params, params.init_key, bytecode[0]);
    if op != XF_OPCODE {
        return None;
    }
    Some(operand_from_byte(params, next_key, bytecode[1], XF_TAG_XOR))
}

pub fn first_xf_tag_late(bytecode: &[u8]) -> Option<u8> {
    first_xf_tag(FETCH_BRANCH_B_LATE, bytecode)
}

#[derive(Debug, Clone, Serialize)]
pub struct WidthObservation {
    pub opcode: u8,
    pub handler: Option<&'static str>,
    pub width: i32,
    pub matches_fixed: Option<bool>,
}

/// Compare Chrome PC deltas to statically recovered fixed widths.
/// Negative / huge deltas are jumps, not encoding widths.
pub fn classify_pc_delta_in(
    opcode: u8,
    width: i32,
    table: &[OpcodeDef],
    layouts: &[HandlerLayout],
) -> WidthObservation {
    let handler = opcode_def_in(table, opcode).map(|d| d.handler);
    let matches_fixed = layouts.iter().find(|h| h.opcode == opcode).and_then(|h| {
        match h.width {
            InstrWidth::Fixed(n) => Some(width == i32::from(n)),
            InstrWidth::Variable => None,
        }
    });
    WidthObservation {
        opcode,
        handler,
        width,
        matches_fixed,
    }
}

pub fn classify_pc_delta(opcode: u8, width: i32) -> WidthObservation {
    classify_pc_delta_in(opcode, width, OPCODE_TABLE_B, HANDLER_LAYOUT_B)
}

pub fn classify_pc_delta_late(opcode: u8, width: i32) -> WidthObservation {
    classify_pc_delta_in(opcode, width, OPCODE_TABLE_B_LATE, HANDLER_LAYOUT_B_LATE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::run_program::{RUN_PROGRAM_MAGIC_BYTES_B, RUN_PROGRAM_MAGIC_BYTES_B_LATE};
    use crate::solver::run_program_vm::{FETCH_BRANCH_B, FETCH_BRANCH_B_LATE, OPCODE_TABLE_B_LATE, next_key};

    #[test]
    fn js_float_xor_truncates_like_to_int32() {
        assert_eq!(js_xor_imm(62.48), 62);
        assert_eq!(js_xor_imm(154.33), 154);
        assert_eq!(js_xor_imm(29.71), 29);
        assert_eq!(js_xor_imm(107.76), 107);
        assert_eq!(js_xor_imm(14.31), 14);
        assert_eq!(js_xor_imm(123.64), 123);
        assert_eq!(js_xor_imm(123.07), 123);
        assert_eq!(js_xor_imm(180.99), 180);
        assert_eq!(js_xor_imm(177.81), 177);
        assert_eq!(js_xor_imm(112.68), 112);
        assert_eq!(js_xor_imm(182.31), 182);
        assert_eq!(js_xor_imm(112.87), 112);
        assert_eq!(js_xor_imm(41.43), 41);
        assert_eq!(js_xor_imm(132.63), 132);
    }

    #[test]
    fn post_fetch_key_then_dn_tag_is_string() {
        let params = FETCH_BRANCH_B;
        let byte0 = RUN_PROGRAM_MAGIC_BYTES_B[0];
        let (op, nk) = step_fetch(params, params.init_key, byte0);
        assert_eq!(op, DN_OPCODE);
        assert_eq!(nk, next_key(params, params.init_key, op));
        assert_eq!(nk, 112);
        assert_eq!(
            operand_from_byte(params, nk, RUN_PROGRAM_MAGIC_BYTES_B[1], DN_TAG_XOR),
            DN_TAG_STRING
        );
        assert_eq!(
            first_dn_tag_b(&RUN_PROGRAM_MAGIC_BYTES_B),
            Some(DN_TAG_STRING)
        );
    }

    #[test]
    fn post_fetch_key_then_xf_tag_is_string() {
        let params = FETCH_BRANCH_B_LATE;
        let byte0 = RUN_PROGRAM_MAGIC_BYTES_B_LATE[0];
        let (op, nk) = step_fetch(params, params.init_key, byte0);
        assert_eq!(op, XF_OPCODE);
        assert_eq!(nk, next_key(params, params.init_key, op));
        assert_eq!(nk, 197);
        assert_eq!(
            operand_from_byte(params, nk, RUN_PROGRAM_MAGIC_BYTES_B_LATE[1], XF_TAG_XOR),
            XF_TAG_STRING
        );
        assert_eq!(
            first_xf_tag_late(&RUN_PROGRAM_MAGIC_BYTES_B_LATE),
            Some(XF_TAG_STRING)
        );
    }

    #[test]
    fn wrapping_sub_operand_matches_plus_219() {
        let params = FETCH_BRANCH_B;
        for (key, byte, extra) in [(112u8, 0x7e, 154u8), (112, 0x68, 48), (0, 0, 0)] {
            let a = operand_from_byte(params, key, byte, extra);
            let plus = (256u16 - u16::from(params.byte_bias)) as u8;
            let b = key ^ byte.wrapping_add(plus) ^ extra;
            assert_eq!(a, b);
        }
    }

    #[test]
    fn layouts_point_at_real_switch_ids() {
        for h in HANDLER_LAYOUT_B {
            if matches!(h.handler, "x" | "g" | "Xf") {
                continue;
            }
            assert_eq!(
                opcode_def_in(OPCODE_TABLE_B, h.opcode).map(|d| d.handler),
                Some(h.handler),
                "opcode {} handler {}",
                h.opcode,
                h.handler
            );
        }
        assert_eq!(
            opcode_def_in(OPCODE_TABLE_B_LATE, XF_OPCODE).map(|d| d.handler),
            Some("Xf")
        );
        assert_eq!(layout_for(14).unwrap().width, InstrWidth::Fixed(2));
        assert_eq!(layout_for(9).unwrap().width, InstrWidth::Fixed(4));
        assert_eq!(layout_for(8).unwrap().width, InstrWidth::Variable);
        assert_eq!(layout_for(222).unwrap().width, InstrWidth::Variable);
    }

    #[test]
    fn late_b_layouts_match_chrome_stable_widths() {
        for h in HANDLER_LAYOUT_B_LATE {
            assert_eq!(
                opcode_def_in(OPCODE_TABLE_B_LATE, h.opcode).map(|d| d.handler),
                Some(h.handler),
                "opcode {} handler {}",
                h.opcode,
                h.handler
            );
        }
        let gq = layout_for_late(GQ_OPCODE).unwrap();
        assert_eq!(gq.width, InstrWidth::Fixed(3));
        assert_eq!(gq.extra_xors, &[123, 148]);
        let gg = layout_for_late(GG_OPCODE).unwrap();
        assert_eq!(gg.width, InstrWidth::Fixed(4));
        assert_eq!(gg.extra_xors, &[221, 41, 180]);
        let x3 = layout_for_late(X3_OPCODE).unwrap();
        assert_eq!(x3.width, InstrWidth::Fixed(2));
        assert_eq!(x3.extra_xors, &[1]);
        let gy = layout_for_late(GY_OPCODE).unwrap();
        assert_eq!(gy.width, InstrWidth::Fixed(5));
        assert_eq!(gy.extra_xors, &[117, 221, 231, 177]);
        let xf = layout_for_late(XF_OPCODE).unwrap();
        assert_eq!(xf.width, InstrWidth::Variable);
        assert_eq!(xf.extra_xors, &[XF_TAG_XOR, XF_DST_XOR]);
        let x4 = layout_for_late(X4_OPCODE).unwrap();
        assert_eq!(x4.width, InstrWidth::Fixed(2));
        assert_eq!(x4.extra_xors, &[58]);
        let xz = layout_for_late(XZ_OPCODE).unwrap();
        assert_eq!(xz.width, InstrWidth::Fixed(3));
        assert_eq!(xz.extra_xors, &[132]);
        let xg = layout_for_late(XG_OPCODE).unwrap();
        assert_eq!(xg.width, InstrWidth::Fixed(3));
        assert_eq!(xg.extra_xors, &[112, 19]);
        let ge = layout_for_late(GE_OPCODE).unwrap();
        assert_eq!(ge.width, InstrWidth::Fixed(5));
        assert_eq!(ge.extra_xors, &[41, 221, 180, 19]);

        let hit = classify_pc_delta_late(246, 3);
        assert_eq!(hit.handler, Some("gq"));
        assert_eq!(hit.matches_fixed, Some(true));
        let miss = classify_pc_delta_late(246, 9);
        assert_eq!(miss.matches_fixed, Some(false));
        let var = classify_pc_delta_late(222, 11);
        assert_eq!(var.handler, Some("Xf"));
        assert_eq!(var.matches_fixed, None);
        assert_eq!(classify_pc_delta_late(227, 4).matches_fixed, Some(true));
        assert_eq!(classify_pc_delta_late(104, 2).matches_fixed, Some(true));
        assert_eq!(classify_pc_delta_late(72, 5).matches_fixed, Some(true));
        assert_eq!(classify_pc_delta_late(12, 2).matches_fixed, Some(true));
        assert_eq!(classify_pc_delta_late(52, 3).matches_fixed, Some(true));
        assert_eq!(classify_pc_delta_late(130, 3).matches_fixed, Some(true));
        assert_eq!(classify_pc_delta_late(169, 5).matches_fixed, Some(true));
    }

    #[test]
    fn late_b_handler_snippets_carry_documented_floats() {
        // Headed Chrome iframe (chrome-oracle, names gq/gG/X3/gY/Xf).
        const GQ: &str = "^123.64,XM=h[XM^W[bY(zZ.W)](Xs[Xw++],253)+256&255^148^Xt]";
        const GG: &str = "221),XM),Xo=W[bR(zh.Xw)](W[bR(zh.Xu)](Xs,W[bR(zh.W)](W[bR(zh.XQ)](W[bR(zh.Xo)](Xm[Xu++],253),256),255)),41)^XM,XM^=W[bR(zh.XR)](Xs,W[bR(zh.W)](W[bR(zh.XM)](W[bR(zh.XS)](Xm[Xu++],253),256),255))^180.99";
        const X3: &str = "h[this.i]^3+h[this.l][Xs++]&255.51,1),h[XM]=Xs,h[W[bq(vV.A)](Xm,Xt)]={}";
        const GY: &str = "^117^XM,Xo=Xs^W[bu(jO.n)](W[bu(jO.h)](Xm[Xu++],253)+256,255)^221^XM,XR=W[bu(jO.A)](Xs,W[bu(jO.W)](3+Xm[Xu++],255))^231^XM,XM^=Xs^3+Xm[Xu++]&255^177";
        const XF: &str = "n[d2(T8.a)](Xt^n[d2(T8.n)](n[d2(T8.d)](XM[Xm++],253),256)&255,86),Xu=n[d2(T8.A)](Xt^n[d2(T8.W)](n[d2(T8.h)](XM[Xm++]-253,256),255),112),162===Xw";
        const X4: &str = "n[this.i]^3+n[this.l][h++]&255^58,n[W]=h,n[A^Xt]=[]";
        const XZ: &str = "^132.63,A[Xs]=Xw,Xm[XQ][`o`]=A[Xt^W]";
        const XG: &str = "^112.87,XM^=W[d3(Ta.d)](W[d3(Ta.W)](Xs[Xw++]-253,256),255)^19,h[Xm]=Xw,h[Xu^Xt]=XM";
        const GE: &str = "^41.43,XM),Xo=W[bS(zv.Xm)](Xs^W[bS(zv.Xw)](W[bS(zv.h)](W[bS(zv.Xu)](Xm[Xu++],253),256),255),221)^XM,XM^=W[bS(zv.Xt)](W[bS(zv.XQ)](Xs,W[bS(zv.n)](3+Xm[Xu++],255)),180),Xs^=W[bS(zv.Xo)](W[bS(zv.XR)](W[bS(zv.XS)](W[bS(zv.Xu)](Xm[Xu++],253),256),255),19)";
        assert_eq!(js_xor_imm(123.64), 123);
        assert!(GQ.contains("^148^"));
        assert!(GG.contains(",41)") && GG.contains("^180.99"));
        assert!(X3.contains(",1)") && X3.contains("={}") );
        assert!(GY.contains("^117^") && GY.contains("^221^") && GY.contains("^231^") && GY.contains("^177"));
        assert!(XF.contains(",86)") && XF.contains(",112)"));
        assert_eq!(js_xor_imm(58.0), 58);
        assert!(X4.contains("^58") && X4.contains("=[]"));
        assert_eq!(js_xor_imm(132.63), 132);
        assert!(XZ.contains("^132.63") && XZ.contains("[`o`]"));
        assert_eq!(js_xor_imm(112.87), 112);
        assert!(XG.contains("^112.87") && XG.contains("^19"));
        assert_eq!(js_xor_imm(41.43), 41);
        assert!(GE.contains("^41.43") && GE.contains(",221)") && GE.contains(",180)") && GE.contains(",19)"));
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if path.is_file() {
            let html = std::fs::read_to_string(path).unwrap();
            for snip in [GQ, GG, X3, GY, XF, X4, XZ, XG, GE] {
                assert!(html.contains(snip), "iframe missing snippet {snip}");
            }
        }
    }

    #[test]
    fn oracle_fixture_late_extras_match_layout() {
        let path = std::path::Path::new("scripts/fixtures/headed_chrome_oracle.json");
        if !path.is_file() {
            return;
        }
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let late = &v["laterSameDay"];
        let widths = &late["chromeStableWidths"];
        assert_eq!(widths["gq_246"].as_u64(), Some(3));
        assert_eq!(widths["gG_227"].as_u64(), Some(4));
        assert_eq!(widths["X3_104"].as_u64(), Some(2));
        assert_eq!(widths["gY_72"].as_u64(), Some(5));
        let extras = &late["operandExtras"];
        for h in HANDLER_LAYOUT_B_LATE {
            let row = extras.get(h.handler).unwrap_or_else(|| panic!("{}", h.handler));
            assert_eq!(row["opcode"].as_u64(), Some(u64::from(h.opcode)));
            if let InstrWidth::Fixed(w) = h.width {
                assert_eq!(row["width"].as_u64(), Some(u64::from(w)));
                let got = classify_pc_delta_late(h.opcode, i32::from(w));
                assert_eq!(got.matches_fixed, Some(true));
            }
            let arr = row["extras"].as_array().unwrap();
            let got: Vec<u8> = arr
                .iter()
                .map(|x| x.as_u64().unwrap() as u8)
                .collect();
            assert_eq!(got, h.extra_xors, "{}", h.handler);
        }
        assert_eq!(
            late["foFollowUp"]["plaintextKind"].as_str(),
            Some("compressed_blob_after_runProgram")
        );
        assert_eq!(late["foFollowUp"]["notPackedProgram"], true);
        assert_eq!(late["foFollowUp"]["sameNWrapper"], true);
    }

    #[test]
    fn classify_fixed_width_delta() {
        let hit = classify_pc_delta(14, 2);
        assert_eq!(hit.handler, Some("d6"));
        assert_eq!(hit.matches_fixed, Some(true));
        let miss = classify_pc_delta(14, 9);
        assert_eq!(miss.matches_fixed, Some(false));
        let var = classify_pc_delta(8, 11);
        assert_eq!(var.matches_fixed, None);
    }
}
