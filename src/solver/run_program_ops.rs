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
//! This module does **not** execute handlers or produce a token.

use crate::solver::run_program_vm::{
    FETCH_BRANCH_B, FetchParams, OPCODE_TABLE_B, decode_opcode, opcode_def_in, step_fetch,
};
use serde::Serialize;

/// Remaining live gap after fetch + operand layout: the compressed `/fo/` body.
pub const NEXT_GAP: &str = "wZ_init_body";

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
];

pub fn layout_for(opcode: u8) -> Option<&'static HandlerLayout> {
    HANDLER_LAYOUT_B.iter().find(|h| h.opcode == opcode)
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

#[derive(Debug, Clone, Serialize)]
pub struct WidthObservation {
    pub opcode: u8,
    pub handler: Option<&'static str>,
    pub width: i32,
    pub matches_fixed: Option<bool>,
}

/// Compare Chrome PC deltas to statically recovered fixed widths.
/// Negative / huge deltas are jumps, not encoding widths.
pub fn classify_pc_delta(opcode: u8, width: i32) -> WidthObservation {
    let handler = opcode_def_in(OPCODE_TABLE_B, opcode).map(|d| d.handler);
    let matches_fixed = layout_for(opcode).and_then(|h| match h.width {
        InstrWidth::Fixed(n) => Some(width == i32::from(n)),
        InstrWidth::Variable => None,
    });
    WidthObservation {
        opcode,
        handler,
        width,
        matches_fixed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::run_program::RUN_PROGRAM_MAGIC_BYTES_B;
    use crate::solver::run_program_vm::{FETCH_BRANCH_B, next_key};

    #[test]
    fn js_float_xor_truncates_like_to_int32() {
        assert_eq!(js_xor_imm(62.48), 62);
        assert_eq!(js_xor_imm(154.33), 154);
        assert_eq!(js_xor_imm(29.71), 29);
        assert_eq!(js_xor_imm(107.76), 107);
        assert_eq!(js_xor_imm(14.31), 14);
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
            if matches!(h.handler, "x" | "g") {
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
        assert_eq!(layout_for(14).unwrap().width, InstrWidth::Fixed(2));
        assert_eq!(layout_for(9).unwrap().width, InstrWidth::Fixed(4));
        assert_eq!(layout_for(8).unwrap().width, InstrWidth::Variable);
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
