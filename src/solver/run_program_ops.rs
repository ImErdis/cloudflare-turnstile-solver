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
//! Late-`b` (`56907`) Direct handlers are catalogued in [`HANDLER_LAYOUT_B_LATE`]
//! by **opcode number** (46 switch cases). Chrome-stable widths stay as
//! `Fixed`; jumps, LEB, `new`/`call` arity, and tagged load are `Variable`.
//! Minified names rotate; opcode numbers, `ToInt32` extras, and family tags
//! did not on the same-day HTML. s1/s2 (`gS`/`gK`) stay case-immediate families.
//!
//! This module does **not** execute handlers or produce a token.

use crate::solver::run_program_vm::{
    FETCH_BRANCH_B, FETCH_BRANCH_B_LATE, FetchParams, OPCODE_TABLE_B, OPCODE_TABLE_B_LATE,
    OpcodeDef, decode_opcode, opcode_def_in, step_fetch,
};
use serde::Serialize;

/// Remaining live gap after fetch, operands, `f4`, init-JSON shape, follow-up
/// envelope, late-`b` extra-xors, follow-up JSON key names, and HTML family
/// tags: handler semantics (do not run handlers as a solver).
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
    /// Shape tag from HTML (not a solver). Opcode-keyed; names rotate.
    pub family: &'static str,
    pub note: &'static str,
}

const fn h(
    opcode: u8,
    handler: &'static str,
    width: InstrWidth,
    extra_xors: &'static [u8],
    family: &'static str,
    note: &'static str,
) -> HandlerLayout {
    HandlerLayout {
        opcode,
        handler,
        width,
        extra_xors,
        family,
        note,
    }
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
/// Charset extra on tag-199 string and tag-161 bytes (`go[...^136]`).
pub const XF_STRING_CHARSET_XOR: u8 = 136;
/// Host `Number[...]` tags (obfuscated property names — not Infinity/NaN literals in source).
pub const XF_TAG_NUMBER_A: u8 = 165;
pub const XF_TAG_NUMBER_B: u8 = 174;
/// Packed 4-tuple / frame-like array (js `Xw===98`).
pub const XF_TAG_PACKED: u8 = 98;
/// Two LEB strings then `RegExp(pattern, flags)` (js `Xw,117`).
pub const XF_TAG_REGEXP: u8 = 117;
/// `109!==Xw` gate around false/packed/bytes/regexp/true. Not its own store kind.
pub const XF_TAG_GATE: u8 = 109;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct XfTagCase {
    pub tag: u8,
    pub kind: &'static str,
    pub note: &'static str,
}

/// `Xf`/222 tag `switch` from the 56907 iframe. Tag byte extra `86`, dst extra `112`.
/// Default after the `109!==` gate is `true` (`XQ=!0`) — not a tag number.
/// Do not execute.
pub const XF_TAG_CASES: &[XfTagCase] = &[
    XfTagCase { tag: XF_TAG_INT, kind: "int", note: "value ^= 19 then store to regs[dst]" },
    XfTagCase { tag: XF_TAG_UNDEF, kind: "undefined", note: "store void 0" },
    XfTagCase { tag: XF_TAG_STRING, kind: "string", note: "LEB length; charset extra 136" },
    XfTagCase { tag: XF_TAG_LEB, kind: "leb_int", note: "LEB integer payload" },
    XfTagCase { tag: XF_TAG_FLOAT, kind: "float", note: "IEEE-like Math.pow(2, exp) bit walk" },
    XfTagCase { tag: XF_TAG_NULL, kind: "null", note: "store null" },
    XfTagCase { tag: XF_TAG_NUMBER_A, kind: "number_host", note: "Number[obfuscated prop]; not a JSON key" },
    XfTagCase { tag: XF_TAG_NUMBER_B, kind: "number_host", note: "Number[other obfuscated prop]" },
    XfTagCase { tag: XF_TAG_FALSE, kind: "false", note: "store !1; inside 109!== gate" },
    XfTagCase { tag: XF_TAG_PACKED, kind: "packed_tuple", note: "u24-ish tuple plus extra 207.58 and this.m" },
    XfTagCase { tag: XF_TAG_BYTES, kind: "bytes", note: "LEB length; charset extra 136" },
    XfTagCase { tag: XF_TAG_REGEXP, kind: "regexp", note: "two LEB strings (charset 195, 229) then RegExp" },
];

pub fn xf_tag_kind(tag: u8) -> Option<&'static str> {
    XF_TAG_CASES.iter().find(|c| c.tag == tag).map(|c| c.kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PropertyImmRoles {
    pub opcode: u8,
    pub handler: &'static str,
    pub family: &'static str,
    pub roles: &'static [&'static str],
    pub assign: &'static str,
    pub note: &'static str,
}

/// Property get/set on the 56907 iframe. Immediates select **register slots**
/// (`imm ^ this.h`) or a bytecode LEB string. Follow-up JSON ident names are
/// not literals here — do not claim numeric `"1".."39"` writes.
pub const PROPERTY_IMM_ROLES_B_LATE: &[PropertyImmRoles] = &[
    PropertyImmRoles {
        opcode: 132,
        handler: "gy",
        family: "property_get",
        roles: &["obj", "dst", "key"],
        assign: "dst = obj[key]",
        note: "Xt[Xo]=Xt[XQ][Xt[XM]]; extras 99, 216, 38",
    },
    PropertyImmRoles {
        opcode: 227,
        handler: "gG",
        family: "property_set",
        roles: &["key", "obj", "src"],
        assign: "obj[key] = src",
        note: "Xt[Xo][Xt[XQ]]=Xt[XM]; extras 221, 41, 180",
    },
    PropertyImmRoles {
        opcode: 169,
        handler: "ge",
        family: "property_set",
        roles: &["obj", "key_slot", "src", "key_imm"],
        assign: "regs[key_slot]=key_imm; obj[key_imm]=src",
        note: "4th imm is the property name itself (decoded this.i), not a register; sibling of gN",
    },
    PropertyImmRoles {
        opcode: 138,
        handler: "gN",
        family: "property_set",
        roles: &["obj", "key", "dst", "src_imm"],
        assign: "regs[dst]=src_imm; obj[regs[key]]=src_imm",
        note: "4th imm is the value; key is a register. Sibling of ge (same extras 41,221,180,19)",
    },
    PropertyImmRoles {
        opcode: 72,
        handler: "gY",
        family: "nested_property_get",
        roles: &["k1", "k2", "dst", "obj"],
        assign: "dst = obj[k1][k2]",
        note: "Xt[XR]=Xt[XM][Xt[XQ]][Xt[Xo]]; extras 117, 221, 231, 177",
    },
    PropertyImmRoles {
        opcode: 183,
        handler: "gZ",
        family: "dual_property_get",
        roles: &["k_a", "dst_b", "obj", "k_b", "dst_a"],
        assign: "dst_a = obj[k_b]; dst_b = obj[k_a]",
        note: "two gets from the same object; extras 208, 108, 168, 12, 192",
    },
    PropertyImmRoles {
        opcode: 226,
        handler: "gC",
        family: "string_key_set",
        roles: &["obj", "src"],
        assign: "obj[leb_string] = src",
        note: "LEB string key charset extra 1; string is in packed bytecode, not this HTML",
    },
    PropertyImmRoles {
        opcode: 140,
        handler: "gl",
        family: "string_key_get",
        roles: &["obj", "dst"],
        assign: "dst = obj[leb_string]",
        note: "LEB string key charset extra 43 then extras 69, 118; string is in packed bytecode",
    },
];

pub fn property_roles_for_late(opcode: u8) -> Option<&'static PropertyImmRoles> {
    PROPERTY_IMM_ROLES_B_LATE.iter().find(|p| p.opcode == opcode)
}

/// Fixed-width handlers recovered from the headed-Chrome iframe (branch `b`).
/// Operand extras are `ToInt32` of the floats in the handler source.
pub const HANDLER_LAYOUT_B: &[HandlerLayout] = &[
    h(8, "dN", InstrWidth::Variable, &[DN_TAG_XOR, DN_DST_XOR], "tagged_load",
        "tagged load: 49 int (+xor 59), 230 undef, 179 string, 191 float, 42 null, 66 false, 206 bytes"),
    h(14, "d6", InstrWidth::Fixed(2), &[62], "store_empty_object", "store {} at (imm^h)"),
    h(176, "d7", InstrWidth::Fixed(2), &[8], "store_empty_array", "store [] at (imm^h)"),
    h(50, "d4", InstrWidth::Fixed(2), &[29], "throw_register", "throw register"),
    h(215, "d5", InstrWidth::Fixed(2), &[154], "helper_1imm",
        "1-imm helper (stack/slot xor 36 and 53 are not bytecode)"),
    h(49, "dQ", InstrWidth::Fixed(3), &[48, 59], "store_decoded_byte", "2-imm store of a decoded byte"),
    h(0, "d1", InstrWidth::Fixed(3), &[123, 5], "array_push", "array push"),
    h(31, "d3", InstrWidth::Fixed(3), &[205, 31], "call_result_store", "2-imm call/result store"),
    h(9, "p", InstrWidth::Fixed(4), &[80, 243, 107], "property_get", "property get: dst = obj[key]"),
    h(112, "F", InstrWidth::Fixed(4), &[84, 250, 33], "property_set", "property set: obj[key] = src"),
    h(185, "x", InstrWidth::Variable, &[], "s1",
        "s1 family: switch immediate from the case (245,17,105,…) plus bytecode"),
    h(69, "g", InstrWidth::Variable, &[], "s2",
        "s2 family: unary typeof/- /+ /! /~ selected by switch immediate"),
    h(222, "Xf", InstrWidth::Variable, &[XF_TAG_XOR, XF_DST_XOR], "tagged_load",
        "later-day tagged load (dN renamed): 162 int (+xor 19), 86 undef, 199 string, 36 LEB, 58 float, 80 null, 202 false, 161 bytes"),
];

/// Late-`b` (`56907`) Direct handlers from headed-Chrome iframe HTML.
///
/// Chrome-stable widths (`gq`/`gG`/`X3`/`gY`/`X4`/`Xz`/`Xg`/`ge`) keep `Fixed`.
/// Jumps, LEB, `new`/`call` arity, and tagged load are `Variable`. Operand extras
/// are `ToInt32` of the floats next to bytecode bumps. Do not execute.
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

/// One entry per Direct switch case on the 56907 iframe (not s1/s2).
pub const LATE_DIRECT_HANDLER_COUNT: usize = 46;

pub const HANDLER_LAYOUT_B_LATE: &[HandlerLayout] = &[
    h(187, "XX", InstrWidth::Variable, &[207], "jump_u24",
        "unconditional pc=u24; extra 207 on the key byte at post-increment pc. Chrome deltas are jumps."),
    h(153, "X5", InstrWidth::Variable, &[96, 207], "cond_jump",
        "if reg then pc=u24 and key^=207 else fall through (js ^96, ^207.34)"),
    h(38, "X6", InstrWidth::Variable, &[21, 200, 207], "cond_jump",
        "compare two regs (extras 21, 200); taken path pc=u24 key^207 (else also ^207)"),
    h(34, "X8", InstrWidth::Variable, &[21, 200, 207], "cond_jump",
        "compare two regs (js ,21 ^200.95 ^207); taken/else u24 like X6"),
    h(26, "X7", InstrWidth::Variable, &[112, 19, 21, 207], "cond_jump",
        "2-imm store-like (112.88, 19) then cond (21.07) then u24 key^207"),
    h(122, "X9", InstrWidth::Variable, &[120, 252, 54, 207], "cond_jump",
        "compare >= (js 120, 252, 54) then u24 key^207.37"),
    h(196, "X2", InstrWidth::Fixed(2), &[131], "number_helper",
        "1-imm (js 131.21); Number host helper, not bytecode arithmetic"),
    h(45, "X1", InstrWidth::Fixed(2), &[144], "throw_register",
        "1-imm throw register (js ^144); early-b d4 analogue"),
    h(X3_OPCODE, "X3", InstrWidth::Fixed(2), &[1], "store_empty_object",
        "1-imm store {} at (imm^h); early-b d6 analogue. Later HTML: X4."),
    h(X4_OPCODE, "X4", InstrWidth::Fixed(2), &[58], "store_empty_array",
        "1-imm store [] at (imm^h); early-b d7 analogue (js ^58). Later HTML: X5."),
    h(XF_OPCODE, "Xf", InstrWidth::Variable, &[XF_TAG_XOR, XF_DST_XOR], "tagged_load",
        "tagged load: tag^86 dst^112; 162 int^19, 86 undef, 199 string, 36 LEB, 58 float, 80 null, 165/174 Number host, 202 false, 98 packed, 161 bytes, 117 regexp, else true. Later HTML: Xg."),
    h(XG_OPCODE, "Xg", InstrWidth::Fixed(3), &[112, 19], "register_store",
        "2-imm store (js 112.87, 19). Later HTML: XX."),
    h(113, "XP", InstrWidth::Variable, &[52, 132], "leb_object_slot",
        "tag^52 then LEB; branch loads table[n].o or slot^132. Later HTML name rotates."),
    h(201, "Xj", InstrWidth::Variable, &[], "leb_alloc_objects",
        "LEB count then per-slot LEB; allocates {o: undefined} into this.m. No extra xor on the count."),
    h(XZ_OPCODE, "Xz", InstrWidth::Fixed(3), &[132], "leb_object_slot",
        "LEB then slot^132.63; Xm[XQ]['o']=reg. Chrome histogram was all width 3 (1-byte LEB). Later HTML: Xv."),
    h(230, "Xv", InstrWidth::Variable, &[132, 209, 199], "leb_object_slot",
        "LEB then extras 132, 209, 199; o-slot family like Xz with more immediates"),
    h(94, "XH", InstrWidth::Variable, &[132], "leb_object_slot",
        "LEB then slot^132; store table[n].o. Same extra as Xz, variable LEB width."),
    h(73, "Xk", InstrWidth::Variable, &[15, 223], "leb_object_slot",
        "LEB then ^15 ^223; bind Xm[n]['o'] and store the object"),
    h(27, "XB", InstrWidth::Variable, &[27, 223, 246, 77, 132, 213], "leb_object_state",
        "state machine over this.m[].o (js 27.67, 223.27, 246.32, 77.01, 132, 213). Do not execute."),
    h(55, "XT", InstrWidth::Variable, &[132, 112, 19, 207], "leb_cond_jump",
        "LEB slot^132 then 2-imm (112.89, 19) then u24 key^207"),
    h(177, "XU", InstrWidth::Variable, &[96, 207, 68, 83, 37], "apply_construct",
        "u24 + flags (js 96, 207, 68, 83, 37) then XI.apply-like call. Arity from bytecode."),
    h(135, "Xi", InstrWidth::Variable, &[85, 63, 207, 164], "typed_store",
        "switch on type tag (js 85.58, 63, 207, 164.29); Number/bytes store. Do not execute."),
    h(219, "XD", InstrWidth::Variable, &[77], "binary_arith",
        "1-imm (js 77.98) then packed u32 constants; host/binary arithmetic. Do not execute."),
    h(134, "gO", InstrWidth::Fixed(3), &[125, 131], "call_1arg",
        "2-imm (js 125, 131); callee(arg) with no result store"),
    h(127, "gc", InstrWidth::Variable, &[131, 207], "push_frame",
        "slot^131 then u24 key^207; method call with a 4-tuple frame. Chrome deltas are jumps."),
    h(103, "X0", InstrWidth::Fixed(3), &[209, 199], "call_noarg",
        "2-imm (js 209.39, 199); store callee() result"),
    h(30, "gx", InstrWidth::Fixed(3), &[20, 36], "register_swap",
        "2-imm (js 20.58, 36.26); swap two registers"),
    h(GQ_OPCODE, "gq", InstrWidth::Fixed(3), &[123, 148], "register_load",
        "2-imm (js 123.64/123.07, 148); dst slot then register load. Later HTML: gx."),
    h(11, "XJ", InstrWidth::Variable, &[16, 108, 206, 87], "new_construct",
        "dst^16.51 arity^108 ctor^206 then N args ^87.86; switch(N) new Ctor(...)"),
    h(208, "Xn", InstrWidth::Variable, &[77, 27, 246, 22, 217], "call_apply",
        "call/apply (js 77.5, 27, 246, 22, 217); arity from bytecode"),
    h(168, "Xb", InstrWidth::Variable, &[77, 27, 246, 217], "call_apply",
        "call/apply state machine (js 77.07, 27, 246.12, 217.37)"),
    h(161, "Xr", InstrWidth::Variable, &[77, 27, 246, 217], "call_apply",
        "call/apply state machine (js 77, 27, 246.93, 217.37); 2-arg apply path"),
    h(119, "Xd", InstrWidth::Variable, &[47, 191, 129, 194], "call_apply",
        "N-arg call (js 47.63, 191, 129, 194/194.71/194.33); switch on arity"),
    h(165, "XA", InstrWidth::Variable, &[90, 154, 36], "call_apply",
        "LEB index into this.m[].o then N-arg call (js 90, 154.7, 36.98/36.17)"),
    h(126, "XW", InstrWidth::Variable, &[176, 104], "call_apply",
        "LEB then this.m[].o call (js 176.88, 104.03)"),
    h(181, "Xh", InstrWidth::Variable, &[19, 30], "call_apply",
        "2-arg call (js 19, 30) via state machine"),
    h(176, "XE", InstrWidth::Variable, &[44, 10, 206, 25, 37], "named_call",
        "dst^44 name-idx^10 then LEB string (charset ^206.24) then arity ^25.01 args ^37"),
    h(98, "XV", InstrWidth::Variable, &[51, 17, 141, 56], "named_call",
        "like XE via this.m[].o (js 51, 17.26, 141, 56.48/56.04)"),
    h(GG_OPCODE, "gG", InstrWidth::Fixed(4), &[221, 41, 180], "property_set",
        "3-imm obj[key]=src (roles key, obj, src; js 221, 41, 180.99). Later HTML: ge."),
    h(GE_OPCODE, "ge", InstrWidth::Fixed(5), &[41, 221, 180, 19], "property_set",
        "4-imm: key is decoded imm; obj[key_imm]=src (roles obj, key_slot, src, key_imm). Later HTML: gN."),
    h(138, "gN", InstrWidth::Fixed(5), &[41, 221, 180, 19], "property_set",
        "4-imm: src is decoded imm; obj[regs[key]]=src_imm (roles obj, key, dst, src_imm); sibling of ge"),
    h(226, "gC", InstrWidth::Variable, &[42, 182, 1], "string_key_set",
        "2-imm (42, 182) then LEB string (charset ^1); obj[str]=src. String is in packed bytecode."),
    h(132, "gy", InstrWidth::Fixed(4), &[99, 216, 38], "property_get",
        "3-imm dst=obj[key] (roles obj, dst, key; js 99.04, 216.44, 38); early-b p analogue"),
    h(GY_OPCODE, "gY", InstrWidth::Fixed(5), &[117, 221, 231, 177], "nested_property_get",
        "4-imm dst=obj[k1][k2] (roles k1, k2, dst, obj; js 177.81). Later HTML: gZ."),
    h(183, "gZ", InstrWidth::Fixed(6), &[208, 108, 168, 12, 192], "dual_property_get",
        "5-imm two gets from the same object (roles k_a, dst_b, obj, k_b, dst_a)"),
    h(140, "gl", InstrWidth::Variable, &[43, 69, 118], "string_key_get",
        "LEB string (charset ^43) then extras 69, 118; dst=obj[str]. String is in packed bytecode."),
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
    use crate::solver::run_program_vm::{
        FETCH_BRANCH_B, FETCH_BRANCH_B_LATE, OPCODE_TABLE_B_LATE, OpcodeKind, next_key,
    };

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
        assert_eq!(layout_for_late(45).unwrap().family, "throw_register");
        assert_eq!(layout_for_late(132).unwrap().family, "property_get");
        assert_eq!(layout_for_late(30).unwrap().family, "register_swap");
        assert_eq!(layout_for_late(187).unwrap().family, "jump_u24");
        assert_eq!(classify_pc_delta_late(187, 4).matches_fixed, None);
        assert_eq!(classify_pc_delta_late(30, 3).matches_fixed, Some(true));
        assert_eq!(classify_pc_delta_late(132, 4).matches_fixed, Some(true));
        assert_eq!(classify_pc_delta_late(138, 5).matches_fixed, Some(true));
        assert_eq!(classify_pc_delta_late(183, 6).matches_fixed, Some(true));
    }

    #[test]
    fn late_direct_handlers_are_catalogued() {
        assert_eq!(HANDLER_LAYOUT_B_LATE.len(), LATE_DIRECT_HANDLER_COUNT);
        let mut seen = std::collections::BTreeSet::new();
        for def in OPCODE_TABLE_B_LATE {
            if def.kind != OpcodeKind::Direct {
                continue;
            }
            let h = layout_for_late(def.opcode).unwrap_or_else(|| panic!("{}", def.handler));
            assert_eq!(h.handler, def.handler, "opcode {}", def.opcode);
            assert!(!h.family.is_empty(), "{}", def.handler);
            assert!(seen.insert(def.opcode), "duplicate {}", def.opcode);
        }
        assert_eq!(seen.len(), LATE_DIRECT_HANDLER_COUNT);
    }

    #[test]
    fn xf_tag_cases_match_56907_html() {
        assert_eq!(xf_tag_kind(XF_TAG_STRING), Some("string"));
        assert_eq!(xf_tag_kind(XF_TAG_INT), Some("int"));
        assert_eq!(xf_tag_kind(XF_TAG_UNDEF), Some("undefined"));
        assert_eq!(xf_tag_kind(XF_TAG_REGEXP), Some("regexp"));
        assert_eq!(xf_tag_kind(XF_TAG_PACKED), Some("packed_tuple"));
        assert_eq!(xf_tag_kind(XF_TAG_GATE), None);
        assert_eq!(js_xor_imm(136.0), XF_STRING_CHARSET_XOR);
        let tags: Vec<u8> = XF_TAG_CASES.iter().map(|c| c.tag).collect();
        assert_eq!(tags.len(), 12);
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        for snip in [
            "162===Xw",
            "Xw===86",
            "199===Xw",
            "Xw===36",
            "(Xw,58)",
            "(Xw,80)",
            "(Xw,165)",
            "(Xw,174)",
            "109!==Xw",
            "(Xw,202)",
            "Xw===98",
            "(Xw,161)",
            "(Xw,117)",
            "RegExp,XQ,Xo",
            "XQ=!0",
            "^136]",
        ] {
            assert!(html.contains(snip), "Xf html missing {snip}");
        }
    }

    #[test]
    fn property_imm_roles_match_56907_html() {
        assert_eq!(PROPERTY_IMM_ROLES_B_LATE.len(), 8);
        let gy = property_roles_for_late(132).unwrap();
        assert_eq!(gy.roles, &["obj", "dst", "key"]);
        assert_eq!(gy.assign, "dst = obj[key]");
        let ge = property_roles_for_late(169).unwrap();
        assert_eq!(ge.roles, &["obj", "key_slot", "src", "key_imm"]);
        let gn = property_roles_for_late(138).unwrap();
        assert_eq!(gn.roles, &["obj", "key", "dst", "src_imm"]);
        assert_ne!(ge.assign, gn.assign);
        for p in PROPERTY_IMM_ROLES_B_LATE {
            let h = layout_for_late(p.opcode).unwrap();
            assert_eq!(h.handler, p.handler);
            assert_eq!(h.family, p.family);
        }
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        for snip in [
            "Xt[Xo]=Xt[XQ][Xt[XM]]}",
            "Xt[Xo][Xt[XQ]]=Xt[XM]}",
            "Xt[Xo]=Xs,Xt[XQ][Xs]=Xt[XM]}",
            "Xt[XM]=Xs,Xt[XQ][Xt[Xo]]=Xs}",
            "Xt[XR]=Xt[XM][Xt[XQ]][Xt[Xo]]}",
            "Xt[XM]=Xt[XR][Xt[XS]],Xt[Xo]=Xt[XR][Xt[XQ]]}",
            "A[Xu][Xw]=A[W]}",
            "A[W]=A[XQ][Xw]}",
        ] {
            assert!(html.contains(snip), "property html missing {snip}");
        }
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
        const X1: &str = "^144^Xt],h[XM]=Xs,Xt}";
        const X2: &str = "^131.21^Xt],h[XM]=Number";
        const GX: &str = "^36.26,h[Xm]=Xw,Xm=h[Xt],h[Xt]=h[Xu],h[Xu]=Xm";
        const GN: &str = "Xt[XQ][Xt[Xo]]=Xs}";
        const GY_GET: &str = "Xt[Xo]=Xt[XQ][Xt[XM]]}";
        const GZ: &str = "Xt[XM]=Xt[XR][Xt[XS]],Xt[Xo]=Xt[XR][Xt[XQ]]}";
        const X5: &str = "^207.34,XM?";
        const XJ: &str = "^16.51";
        const XJ_NEW: &str = "new Xt(";
        const GC: &str = ",42)^W";
        const GL: &str = "^118,A[Xs]=Xm,A[W]=A[XQ][Xw]}";
        const XJ_ALLOC: &str = "XY[`o`]=void 0";
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
            for snip in [
                GQ, GG, X3, GY, XF, X4, XZ, XG, GE, X1, X2, GX, GN, GY_GET, GZ, X5, XJ, XJ_NEW, GC,
                GL, XJ_ALLOC,
            ] {
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
            if let Some(fam) = row.get("family").and_then(|x| x.as_str()) {
                assert_eq!(fam, h.family, "{}", h.handler);
            }
        }
        assert_eq!(
            extras.as_object().map(|m| m.len() - usize::from(extras.get("note").is_some())),
            Some(LATE_DIRECT_HANDLER_COUNT)
        );
        assert_eq!(
            late["foFollowUp"]["plaintextKind"].as_str(),
            Some("compressed_blob_after_runProgram")
        );
        assert_eq!(late["foFollowUp"]["notPackedProgram"], true);
        assert_eq!(late["foFollowUp"]["sameNWrapper"], true);
        let tags = late["xfTagCases"]["cases"].as_array().expect("xfTagCases.cases");
        assert_eq!(tags.len(), XF_TAG_CASES.len());
        for (i, c) in XF_TAG_CASES.iter().enumerate() {
            let row = &tags[i];
            assert_eq!(row["tag"].as_u64(), Some(u64::from(c.tag)), "{}", c.kind);
            assert_eq!(row["kind"].as_str(), Some(c.kind));
        }
        assert_eq!(late["xfTagCases"]["tagXor"].as_u64(), Some(u64::from(XF_TAG_XOR)));
        assert_eq!(late["xfTagCases"]["dstXor"].as_u64(), Some(u64::from(XF_DST_XOR)));
        assert_eq!(late["xfTagCases"]["defaultKind"].as_str(), Some("true"));
        let props = late["propertyImmRoles"].as_array().expect("propertyImmRoles");
        assert_eq!(props.len(), PROPERTY_IMM_ROLES_B_LATE.len());
        for (p, row) in PROPERTY_IMM_ROLES_B_LATE.iter().zip(props) {
            assert_eq!(row["opcode"].as_u64(), Some(u64::from(p.opcode)));
            assert_eq!(row["assign"].as_str(), Some(p.assign));
            let roles: Vec<&str> = row["roles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap())
                .collect();
            assert_eq!(roles, p.roles);
        }
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
