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
//! Remaining Direct families (LEB/`this.m[].o`, call/`new`, jumps, typed store,
//! binary mix) are shape-snapshotted from the same 56907 HTML — still not a VM.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LebObjectRole {
    pub opcode: u8,
    pub handler: &'static str,
    pub role: &'static str,
    pub assign: &'static str,
    pub note: &'static str,
}

/// `this.m[].o` table on the 56907 iframe. Alloc writes `{o: undefined}`; bind
/// stores a register into `.o`; load reads `.o` back. Later calls use `.o` as a
/// callee — that is a different family ([`CALL_IMM_ROLES_B_LATE`]). `.o` is also
/// added as a number (`Xk`, `XB` case 9). Do not execute.
pub const LEB_OBJECT_ROLES_B_LATE: &[LebObjectRole] = &[
    LebObjectRole {
        opcode: 201,
        handler: "Xj",
        role: "alloc",
        assign: "for n in leb_count { this.m[leb] = {o: undefined} }",
        note: "LEB count has no extra xor; per-slot LEB index. XY[`o`]=void 0",
    },
    LebObjectRole {
        opcode: 52,
        handler: "Xz",
        role: "bind",
        assign: "this.m[leb].o = regs[slot^132]",
        note: "Chrome-stable width 3 (1-byte LEB). Xm[XQ][`o`]=A[Xt^W]",
    },
    LebObjectRole {
        opcode: 230,
        handler: "Xv",
        role: "bind_then_noarg",
        assign: "this.m[leb].o = src; dst = other[obf]()",
        note: "extras 132, 209, 199; 0-arg call is a register method, not .o",
    },
    LebObjectRole {
        opcode: 94,
        handler: "XH",
        role: "load",
        assign: "regs[slot^132] = this.m[leb].o",
        note: "same extra as Xz; variable LEB width",
    },
    LebObjectRole {
        opcode: 73,
        handler: "Xk",
        role: "bind_add",
        assign: "this.m[leb].o += imm^223; dst^15 = this.m[leb].o",
        note: "add helper shares string-table id 417 with byte-253+256 wrapping add",
    },
    LebObjectRole {
        opcode: 113,
        handler: "XP",
        role: "tagged_leb",
        assign: "tag^52 then LEB; bind / load / alloc",
        note: "tag 227 bind, 78 load, 1 alloc; see XP_TAG_CASES",
    },
    LebObjectRole {
        opcode: 27,
        handler: "XB",
        role: "state_machine",
        assign: "mixed bind/load/add/call on this.m[n].o",
        note: "20 CFF cases; bind `2`, load `14`, add `9`, apply `4`. Do not execute",
    },
    LebObjectRole {
        opcode: 55,
        handler: "XT",
        role: "load_then_cond_jump",
        assign: "dst = this.m[leb].o; if loaded===imm { pc=u24 key^=207 } else alt-or-fall",
        note: "also in JUMP_IMM_ROLES_B_LATE; extras 132, 112, 19, 207",
    },
];

pub fn leb_role_for_late(opcode: u8) -> Option<&'static LebObjectRole> {
    LEB_OBJECT_ROLES_B_LATE.iter().find(|r| r.opcode == opcode)
}

/// `XP`/113 first-imm tag after extra 52.
pub const XP_TAG_XOR: u8 = 52;
pub const XP_TAG_BIND: u8 = 227;
pub const XP_TAG_LOAD: u8 = 78;
pub const XP_TAG_ALLOC: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct XpTagCase {
    pub tag: u8,
    pub kind: &'static str,
    pub note: &'static str,
}

pub const XP_TAG_CASES: &[XpTagCase] = &[
    XpTagCase { tag: XP_TAG_BIND, kind: "bind", note: "XR===227: table[n].o = regs[slot^132]" },
    XpTagCase { tag: XP_TAG_LOAD, kind: "load", note: "XR===78: regs[slot^132] = table[n].o" },
    XpTagCase { tag: XP_TAG_ALLOC, kind: "alloc", note: "1===XR: loop {o:undefined} like Xj" },
];

pub fn xp_tag_kind(tag: u8) -> Option<&'static str> {
    XP_TAG_CASES.iter().find(|c| c.tag == tag).map(|c| c.kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CallImmRoles {
    pub opcode: u8,
    pub handler: &'static str,
    pub callee: &'static str,
    pub arity: &'static str,
    pub assign: &'static str,
    pub note: &'static str,
}

/// Call / `apply` / `new` / named-call on the 56907 iframe. Arity `switch(N)` is
/// layout, not “run N times in Rust”. Callee is a register, `this.m[n].o`, a
/// bytecode LEB string, or host `XI`. Do not execute.
pub const CALL_IMM_ROLES_B_LATE: &[CallImmRoles] = &[
    CallImmRoles {
        opcode: 165,
        handler: "XA",
        callee: "table_o",
        arity: "n_switch",
        assign: "dst^90 = this.m[leb].o(...args^36)",
        note: "arity^154.7; 0/1/2-arg specials then switch 3..7 else apply",
    },
    CallImmRoles {
        opcode: 126,
        handler: "XW",
        callee: "table_o",
        arity: "1",
        assign: "dst^176.88 = this.m[leb].o(arg^104.03)",
        note: "CFF; load .o then one register arg then call",
    },
    CallImmRoles {
        opcode: 181,
        handler: "Xh",
        callee: "table_o",
        arity: "2",
        assign: "dst^19 = this.m[leb].o(a^30, b^30)",
        note: "CFF 7 cases; XK(Xy,Xu)",
    },
    CallImmRoles {
        opcode: 119,
        handler: "Xd",
        callee: "register",
        arity: "n_switch",
        assign: "dst^47.63 = callee^191(...args^194)",
        note: "arity^129; same 0/1/2 + switch 3..7 pattern as XA",
    },
    CallImmRoles {
        opcode: 208,
        handler: "Xn",
        callee: "register_method",
        arity: "n_switch",
        assign: "dst^77.5 = thisArg===undefined ? fn(...args) : fn.apply(thisArg, args)",
        note: "obj^27 key^246 arity^22 args^217; void 0 thisArg uses call",
    },
    CallImmRoles {
        opcode: 168,
        handler: "Xb",
        callee: "register_method",
        arity: "1",
        assign: "dst^77.07 = thisArg===undefined ? fn(arg) : fn.call(thisArg, arg)",
        note: "CFF; extras 27, 246.12, 217.37",
    },
    CallImmRoles {
        opcode: 161,
        handler: "Xr",
        callee: "register_method",
        arity: "2",
        assign: "dst^77 = thisArg===undefined ? fn(a,b) : fn.call(thisArg, a, b)",
        note: "CFF; extras 27, 246.93, 217.37",
    },
    CallImmRoles {
        opcode: 103,
        handler: "X0",
        callee: "register",
        arity: "0",
        assign: "dst^199 = callee^209.39()",
        note: "store 0-arg result",
    },
    CallImmRoles {
        opcode: 134,
        handler: "gO",
        callee: "register",
        arity: "1",
        assign: "callee^125(arg^131)",
        note: "no result store; obfuscated property call",
    },
    CallImmRoles {
        opcode: 127,
        handler: "gc",
        callee: "register_frame",
        arity: "4tuple",
        assign: "callee^131([u24, key^207, this.m[obf](), regs[154^h][obf]])",
        note: "Chrome deltas are jumps; frame includes the object table",
    },
    CallImmRoles {
        opcode: 177,
        handler: "XU",
        callee: "host_xi",
        arity: "n_plus_flags",
        assign: "dst = XI.apply(null, this, [u24, key^207, this.m, args^37, flags])",
        note: "flags from imm^68: 15&x, bit7, bit6. Host apply — do not execute",
    },
    CallImmRoles {
        opcode: 11,
        handler: "XJ",
        callee: "register_ctor",
        arity: "n_switch",
        assign: "dst^16.51 = new ctor^206(...args^87.86)",
        note: "arity^108; switch 0..7 else Function.prototype.bind.apply",
    },
    CallImmRoles {
        opcode: 176,
        handler: "XE",
        callee: "named_string",
        arity: "n_switch",
        assign: "dst^44 = (obj^10===undefined ? name : obj[name])(...args^37)",
        note: "LEB string charset extra 206.24; arity^25.01",
    },
    CallImmRoles {
        opcode: 98,
        handler: "XV",
        callee: "table_o_named",
        arity: "n_switch",
        assign: "dst^51 = this.m[leb].o[leb_string](...args^56)",
        note: "string charset extra 17.26; arity^141; sibling of XE via .o",
    },
];

pub fn call_roles_for_late(opcode: u8) -> Option<&'static CallImmRoles> {
    CALL_IMM_ROLES_B_LATE.iter().find(|c| c.opcode == opcode)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct JumpImmRoles {
    pub opcode: u8,
    pub handler: &'static str,
    pub condition: &'static str,
    pub paths: &'static str,
    pub key_extra: u8,
    pub note: &'static str,
}

/// Control-flow on the 56907 iframe. `pc = u24` is not an encoding width.
/// Taken / else-jump paths xor the fetch **key** with extra 207. Fall-through
/// leaves the key as the post-fetch value. Do not execute.
pub const JUMP_KEY_XOR: u8 = 207;

pub const JUMP_IMM_ROLES_B_LATE: &[JumpImmRoles] = &[
    JumpImmRoles {
        opcode: 187,
        handler: "XX",
        condition: "always",
        paths: "jump",
        key_extra: JUMP_KEY_XOR,
        note: "unconditional pc=u24; key byte at destination ^207 (no ++ on that read)",
    },
    JumpImmRoles {
        opcode: 153,
        handler: "X5",
        condition: "reg_truthy",
        paths: "taken_or_fall",
        key_extra: JUMP_KEY_XOR,
        note: "slot^96; taken pc=u24 key^207.34, else pc=fall-through (key unchanged)",
    },
    JumpImmRoles {
        opcode: 38,
        handler: "X6",
        condition: "regs_eq",
        paths: "taken_alt_or_fall",
        key_extra: JUMP_KEY_XOR,
        note: "two-reg === (extras 21, 200); taken u24, else if flag alt u24, else fall",
    },
    JumpImmRoles {
        opcode: 34,
        handler: "X8",
        condition: "regs_eq",
        paths: "taken_or_else",
        key_extra: JUMP_KEY_XOR,
        note: "two-reg === (extras 21, 200.95); both paths pc=u24 key^207 — no fall-through",
    },
    JumpImmRoles {
        opcode: 26,
        handler: "X7",
        condition: "stored_eq_reg",
        paths: "taken_alt_or_fall",
        key_extra: JUMP_KEY_XOR,
        note: "store imm^19 to slot^112.88, then stored===regs[^21.07]; 3-way like X6",
    },
    JumpImmRoles {
        opcode: 122,
        handler: "X9",
        condition: "regs_ge",
        paths: "taken_alt_or_fall",
        key_extra: JUMP_KEY_XOR,
        note: "store (a>=b) to slot^120; a^252 b^54; jump if true; 3-way",
    },
    JumpImmRoles {
        opcode: 55,
        handler: "XT",
        condition: "loaded_eq_imm",
        paths: "taken_alt_or_fall",
        key_extra: JUMP_KEY_XOR,
        note: "load this.m[leb].o then compare to imm^19; also in LEB_OBJECT_ROLES_B_LATE",
    },
];

pub fn jump_roles_for_late(opcode: u8) -> Option<&'static JumpImmRoles> {
    JUMP_IMM_ROLES_B_LATE.iter().find(|j| j.opcode == opcode)
}

/// `Xi`/135 type-tag cases after extra 164.29 (store into regs[198^h] buffer).
/// Do not execute.
pub const XI_OPCODE: u8 = 135;
pub const XI_TYPE_XOR: u8 = 164;
pub const XI_BUFFER_SLOT_XOR: u8 = 198;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct XiTypeCase {
    pub tag: u8,
    pub kind: &'static str,
    pub note: &'static str,
}

pub const XI_TYPE_CASES: &[XiTypeCase] = &[
    XiTypeCase { tag: 0, kind: "u8", note: "push Number(val)&255" },
    XiTypeCase { tag: 1, kind: "u16", note: "low then (Number>>8)&255" },
    XiTypeCase { tag: 2, kind: "i32", note: "Xp(buf, Number(val)|0)" },
    XiTypeCase { tag: 3, kind: "i64", note: "8-byte BigInt walk or two 32-bit Xp" },
    XiTypeCase { tag: 4, kind: "i32_or", note: "Xp(buf, Number(val)|0) again" },
    XiTypeCase { tag: 5, kind: "f64", note: "DataView setFloat64 little-endian, 8 bytes" },
    XiTypeCase { tag: 6, kind: "bool", note: "push 1 or 0" },
    XiTypeCase { tag: 7, kind: "len_prefixed", note: "u16 length then bytes" },
    XiTypeCase { tag: 8, kind: "leb_prefixed", note: "LEB length then bytes" },
];

pub fn xi_type_kind(tag: u8) -> Option<&'static str> {
    XI_TYPE_CASES.iter().find(|c| c.tag == tag).map(|c| c.kind)
}

/// `XD`/219 mix constants from the 56907 HTML. Host/binary arithmetic — do not execute.
pub const XD_OPCODE: u8 = 219;
pub const XD_SLOT_XOR: u8 = 77;
pub const XD_MIX_SEED: u32 = 854_423_113;
pub const XD_MIX_A: u32 = 11_095;
pub const XD_MIX_B: u32 = 49_971;

/// Late-`b` s1 HTML handler (`gS`). Many opcodes, one function; kind is the case immediate.
pub const S1_HTML_HANDLER: &str = "gS";
/// Late-`b` s2 HTML handler (`gK`). Unary typeof/- /+ /! /~.
pub const S2_HTML_HANDLER: &str = "gK";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct S1Case {
    pub opcode: u8,
    pub imm: u8,
    pub kind: &'static str,
    pub note: &'static str,
}

/// `gS` switch immediates from [`OPCODE_TABLE_B_LATE`] plus the HTML operator.
/// Do not invent a Direct handler per case.
pub const S1_CASES_B_LATE: &[S1Case] = &[
    S1Case { opcode: 194, imm: 66, kind: "add", note: "Xm+A" },
    S1Case { opcode: 221, imm: 18, kind: "sub", note: "A-Xm (CFF)" },
    S1Case { opcode: 66, imm: 241, kind: "mul", note: "XS*A" },
    S1Case { opcode: 157, imm: 65, kind: "div", note: "Xm/XS (helper XK/Xy)" },
    S1Case { opcode: 203, imm: 3, kind: "mod", note: "Xm%A" },
    S1Case { opcode: 10, imm: 22, kind: "and", note: "XS&&A" },
    S1Case { opcode: 43, imm: 214, kind: "or", note: "XS||Xm" },
    S1Case { opcode: 15, imm: 88, kind: "bitand", note: "XS&Xm" },
    S1Case { opcode: 137, imm: 149, kind: "bitor", note: "Xm|A (helper Xy|XK)" },
    S1Case { opcode: 214, imm: 131, kind: "xor", note: "XS^Xm (helper Xy^XK)" },
    S1Case { opcode: 108, imm: 150, kind: "shl", note: "A<<XS" },
    S1Case { opcode: 0, imm: 55, kind: "shr", note: "XS>>A" },
    S1Case { opcode: 19, imm: 62, kind: "ushr", note: "XS>>>A" },
    S1Case { opcode: 90, imm: 249, kind: "eq", note: "A==Xm" },
    S1Case { opcode: 93, imm: 27, kind: "seq", note: "Xm===XS" },
    S1Case { opcode: 234, imm: 21, kind: "gt", note: "Xm>XS" },
    S1Case { opcode: 4, imm: 198, kind: "ge", note: "Xm>=A" },
    S1Case { opcode: 31, imm: 220, kind: "instanceof", note: "XS instanceof A" },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct S2Case {
    pub opcode: u8,
    pub imm: u8,
    pub kind: &'static str,
    pub note: &'static str,
}

pub const S2_CASES_B_LATE: &[S2Case] = &[
    S2Case { opcode: 97, imm: 139, kind: "typeof", note: "typeof A" },
    S2Case { opcode: 22, imm: 234, kind: "neg", note: "-Xs" },
    S2Case { opcode: 87, imm: 133, kind: "plus", note: "+Xs" },
    S2Case { opcode: 148, imm: 119, kind: "not", note: "!A" },
    S2Case { opcode: 241, imm: 144, kind: "bitnot", note: "~Xs" },
];

pub fn s1_kind_for_imm(imm: u8) -> Option<&'static str> {
    S1_CASES_B_LATE.iter().find(|c| c.imm == imm).map(|c| c.kind)
}

pub fn s2_kind_for_imm(imm: u8) -> Option<&'static str> {
    S2_CASES_B_LATE.iter().find(|c| c.imm == imm).map(|c| c.kind)
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
        "unconditional pc=u24; extra 207 on the key byte at destination. Chrome deltas are jumps."),
    h(153, "X5", InstrWidth::Variable, &[96, 207], "cond_jump",
        "if regs[slot^96] then pc=u24 key^207.34 else fall (key unchanged)"),
    h(38, "X6", InstrWidth::Variable, &[21, 200, 207], "cond_jump",
        "two-reg === (extras 21, 200); taken u24 key^207, else if flag alt u24, else fall"),
    h(34, "X8", InstrWidth::Variable, &[21, 200, 207], "cond_jump",
        "two-reg === (extras 21, 200.95); both paths pc=u24 key^207 (no fall-through)"),
    h(26, "X7", InstrWidth::Variable, &[112, 19, 21, 207], "cond_jump",
        "store imm^19 to slot^112.88 then stored===regs[^21]; 3-way jump like X6"),
    h(122, "X9", InstrWidth::Variable, &[120, 252, 54, 207], "cond_jump",
        "store (a>=b) to slot^120 (a^252 b^54); jump if true; 3-way"),
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
        "tag^52 then LEB: 227 bind, 78 load, 1 alloc. Later HTML name rotates."),
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
    fn leb_object_roles_match_56907_html() {
        assert_eq!(LEB_OBJECT_ROLES_B_LATE.len(), 8);
        assert_eq!(leb_role_for_late(201).unwrap().role, "alloc");
        assert_eq!(leb_role_for_late(52).unwrap().role, "bind");
        assert_eq!(leb_role_for_late(94).unwrap().role, "load");
        assert_eq!(leb_role_for_late(73).unwrap().role, "bind_add");
        assert_eq!(xp_tag_kind(XP_TAG_BIND), Some("bind"));
        assert_eq!(xp_tag_kind(XP_TAG_LOAD), Some("load"));
        assert_eq!(xp_tag_kind(XP_TAG_ALLOC), Some("alloc"));
        assert_eq!(xp_tag_kind(0), None);
        for r in LEB_OBJECT_ROLES_B_LATE {
            let h = layout_for_late(r.opcode).unwrap();
            assert_eq!(h.handler, r.handler);
        }
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        for snip in [
            "XY[`o`]=void 0,XR[XK]=XY",
            "Xm[XQ][`o`]=A[Xt^W]",
            "]=Xu[XR].o}",
            "Xm[XQ][`o`]=Xs,A[Xu^W]=Xs",
            "XM[Xs^Xm]=XQ[XK].o",
            "XQ[XK][`o`]=XM[",
            "XS[XY][`o`]=XZ",
            "XR=XS[XY].o",
            "Xo[XK].o",
            "XR!==227",
            "1===XR",
            "(XR,78)",
        ] {
            assert!(html.contains(snip), "leb html missing {snip}");
        }
    }

    #[test]
    fn call_imm_roles_match_56907_html() {
        assert_eq!(CALL_IMM_ROLES_B_LATE.len(), 14);
        assert_eq!(call_roles_for_late(165).unwrap().callee, "table_o");
        assert_eq!(call_roles_for_late(119).unwrap().callee, "register");
        assert_eq!(call_roles_for_late(11).unwrap().callee, "register_ctor");
        assert_eq!(call_roles_for_late(176).unwrap().callee, "named_string");
        assert_eq!(call_roles_for_late(98).unwrap().callee, "table_o_named");
        assert_eq!(call_roles_for_late(177).unwrap().callee, "host_xi");
        for c in CALL_IMM_ROLES_B_LATE {
            let h = layout_for_late(c.opcode).unwrap();
            assert_eq!(h.handler, c.handler);
        }
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        for snip in [
            "A[this.m][XQ].o",
            "XR=XM[this.m][XS].o",
            "W[this.m][Xo].o",
            "XK=Xm[this.m][Xy].o",
            "new Xt;",
            "new Xt(Xs[0])",
            "XK(Xy,Xu)",
        ] {
            assert!(html.contains(snip), "call html missing {snip}");
        }
    }

    #[test]
    fn jump_imm_roles_match_56907_html() {
        assert_eq!(JUMP_IMM_ROLES_B_LATE.len(), 7);
        assert_eq!(jump_roles_for_late(187).unwrap().paths, "jump");
        assert_eq!(jump_roles_for_late(153).unwrap().paths, "taken_or_fall");
        assert_eq!(jump_roles_for_late(34).unwrap().paths, "taken_or_else");
        assert_eq!(jump_roles_for_late(38).unwrap().condition, "regs_eq");
        assert_eq!(jump_roles_for_late(122).unwrap().condition, "regs_ge");
        for j in JUMP_IMM_ROLES_B_LATE {
            assert_eq!(j.key_extra, JUMP_KEY_XOR);
            let h = layout_for_late(j.opcode).unwrap();
            assert_eq!(h.handler, j.handler);
        }
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        for snip in [
            "^207.34,XM?",
            "Xm>=A",
            "XS=XS>=XK",
            "Xw^=W[d0(Hf.Xe)](Xu[XQ++]-253,256)&255^207,Xt[Xs]=Xo,Xt[Xm]=Xw)}",
        ] {
            assert!(html.contains(snip), "jump html missing {snip}");
        }
        // X5/X6 fall through by writing the post-instr pc; X8's else path jumps (snippet above).
        assert!(html.contains("XM?(Xt[Xs]=Xo,Xt[Xm]=Xw):Xt[Xs]=XQ}"));
    }

    #[test]
    fn typed_store_and_s1s2_match_56907_html() {
        assert_eq!(xi_type_kind(5), Some("f64"));
        assert_eq!(XI_TYPE_CASES.len(), 9);
        assert_eq!(js_xor_imm(164.29), XI_TYPE_XOR);
        assert_eq!(js_xor_imm(77.98), XD_SLOT_XOR);
        assert_eq!(S1_CASES_B_LATE.len(), 18);
        assert_eq!(S2_CASES_B_LATE.len(), 5);
        assert_eq!(s1_kind_for_imm(66), Some("add"));
        assert_eq!(s1_kind_for_imm(220), Some("instanceof"));
        assert_eq!(s2_kind_for_imm(139), Some("typeof"));
        assert_eq!(s2_kind_for_imm(144), Some("bitnot"));
        let mut s1_ops = std::collections::BTreeSet::new();
        let mut s2_ops = std::collections::BTreeSet::new();
        for def in OPCODE_TABLE_B_LATE {
            match def.kind {
                OpcodeKind::S1 => {
                    let c = S1_CASES_B_LATE
                        .iter()
                        .find(|c| c.opcode == def.opcode)
                        .unwrap_or_else(|| panic!("s1 opcode {}", def.opcode));
                    assert_eq!(Some(c.imm), def.imm, "s1 opcode {}", def.opcode);
                    assert!(s1_ops.insert(def.opcode));
                }
                OpcodeKind::S2 => {
                    let c = S2_CASES_B_LATE
                        .iter()
                        .find(|c| c.opcode == def.opcode)
                        .unwrap_or_else(|| panic!("s2 opcode {}", def.opcode));
                    assert_eq!(Some(c.imm), def.imm, "s2 opcode {}", def.opcode);
                    assert!(s2_ops.insert(def.opcode));
                }
                OpcodeKind::Direct => {}
            }
        }
        assert_eq!(s1_ops.len(), S1_CASES_B_LATE.len());
        assert_eq!(s2_ops.len(), S2_CASES_B_LATE.len());
        assert_eq!(
            crate::solver::run_program_vm::FETCH_LIVE.key_mul,
            FETCH_BRANCH_B_LATE.key_mul
        );
        assert_eq!(NEXT_GAP, "handler_semantics");
        let path = std::path::Path::new("artifacts/re-out/chrome-oracle/iframe-1.html");
        if !path.is_file() {
            return;
        }
        let html = std::fs::read_to_string(path).unwrap();
        for snip in [
            "new DataView(W)",
            "new ArrayBuffer(8)",
            "854423113",
            "Xt[XM^Xs]=typeof A",
            "Xt[XM^A]=~Xs",
            "Xt[XM^Xs]=!A",
            "XS instanceof A",
            "Xm>=A",
            "A==Xm",
            "Xm===XS",
            "A<<XS",
            "Xm%A",
            "XS>>>A",
            "XS||Xm",
            "XS*A",
            "Xm+A",
            "XS&Xm",
            "A-Xm",
        ] {
            assert!(html.contains(snip), "arith/s1s2 html missing {snip}");
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
        let leb = late["lebObjectRoles"].as_array().expect("lebObjectRoles");
        assert_eq!(leb.len(), LEB_OBJECT_ROLES_B_LATE.len());
        for (r, row) in LEB_OBJECT_ROLES_B_LATE.iter().zip(leb) {
            assert_eq!(row["opcode"].as_u64(), Some(u64::from(r.opcode)));
            assert_eq!(row["role"].as_str(), Some(r.role));
            assert_eq!(row["assign"].as_str(), Some(r.assign));
        }
        let xp = late["xpTagCases"]["cases"].as_array().expect("xpTagCases.cases");
        assert_eq!(xp.len(), XP_TAG_CASES.len());
        for (c, row) in XP_TAG_CASES.iter().zip(xp) {
            assert_eq!(row["tag"].as_u64(), Some(u64::from(c.tag)));
            assert_eq!(row["kind"].as_str(), Some(c.kind));
        }
        let calls = late["callImmRoles"].as_array().expect("callImmRoles");
        assert_eq!(calls.len(), CALL_IMM_ROLES_B_LATE.len());
        for (c, row) in CALL_IMM_ROLES_B_LATE.iter().zip(calls) {
            assert_eq!(row["opcode"].as_u64(), Some(u64::from(c.opcode)));
            assert_eq!(row["callee"].as_str(), Some(c.callee));
            assert_eq!(row["arity"].as_str(), Some(c.arity));
        }
        let jumps = late["jumpImmRoles"].as_array().expect("jumpImmRoles");
        assert_eq!(jumps.len(), JUMP_IMM_ROLES_B_LATE.len());
        for (j, row) in JUMP_IMM_ROLES_B_LATE.iter().zip(jumps) {
            assert_eq!(row["opcode"].as_u64(), Some(u64::from(j.opcode)));
            assert_eq!(row["condition"].as_str(), Some(j.condition));
            assert_eq!(row["paths"].as_str(), Some(j.paths));
            assert_eq!(row["keyExtra"].as_u64(), Some(u64::from(j.key_extra)));
        }
        let xi = late["xiTypeCases"]["cases"].as_array().expect("xiTypeCases.cases");
        assert_eq!(xi.len(), XI_TYPE_CASES.len());
        for (c, row) in XI_TYPE_CASES.iter().zip(xi) {
            assert_eq!(row["tag"].as_u64(), Some(u64::from(c.tag)));
            assert_eq!(row["kind"].as_str(), Some(c.kind));
        }
        assert_eq!(late["xdMix"]["seed"].as_u64(), Some(u64::from(XD_MIX_SEED)));
        assert_eq!(late["xdMix"]["slotXor"].as_u64(), Some(u64::from(XD_SLOT_XOR)));
        let s1 = late["s1Cases"].as_array().expect("s1Cases");
        assert_eq!(s1.len(), S1_CASES_B_LATE.len());
        for (c, row) in S1_CASES_B_LATE.iter().zip(s1) {
            assert_eq!(row["opcode"].as_u64(), Some(u64::from(c.opcode)));
            assert_eq!(row["imm"].as_u64(), Some(u64::from(c.imm)));
            assert_eq!(row["kind"].as_str(), Some(c.kind));
        }
        let s2 = late["s2Cases"].as_array().expect("s2Cases");
        assert_eq!(s2.len(), S2_CASES_B_LATE.len());
        for (c, row) in S2_CASES_B_LATE.iter().zip(s2) {
            assert_eq!(row["opcode"].as_u64(), Some(u64::from(c.opcode)));
            assert_eq!(row["imm"].as_u64(), Some(u64::from(c.imm)));
            assert_eq!(row["kind"].as_str(), Some(c.kind));
        }
        assert_eq!(late["s1HtmlHandler"].as_str(), Some(S1_HTML_HANDLER));
        assert_eq!(late["s2HtmlHandler"].as_str(), Some(S2_HTML_HANDLER));
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
