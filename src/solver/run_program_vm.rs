//! Static map of the iframe `runProgram` interpreter.
//!
//! Fetch constants and switch IDs **rotate with the iframe build**. Headed Chrome
//! is the oracle: dump the iframe HTML (`* 36163 + 38392` / `new dy(N)(0,32,[])`)
//! and `/fo/` extraInfo headers. This module does **not** execute handlers,
//! reconstruct `wZ(...)`, or produce a token.
//!
//! ```text
//! opcode = key ^ ((byte wrapping_sub bias) & 0xff)
//! key    = ((key + opcode) * mul + add) & 0xff
//! ```
//!
//! The try/catch copy uses `key ^ ((byte + (256-bias)) & 0xff)` — same wrapping
//! subtract. Mapped handlers then read immediates with **different** biases.

use serde::Serialize;

/// Honest remaining work: handler bodies / per-operand encodings (and re-running
/// the Chrome oracle when fetch constants rotate again).
pub const NEXT_GAP: &str = "runProgram_handlers";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FetchParams {
    pub label: &'static str,
    pub init_pc: u32,
    pub init_key: u8,
    pub byte_bias: u8,
    pub key_mul: u32,
    pub key_add: u32,
}

/// Captured branch-`g` iframe (`aae2b9a1c261` / prettier dump).
pub const FETCH_BRANCH_G: FetchParams = FetchParams {
    label: "iframe-g",
    init_pc: 0,
    init_key: 100,
    byte_bias: 62,
    key_mul: 19_663,
    key_add: 36_376,
};

/// Headed Chrome oracle, SolveGate, 2026-08-21, platform branch `b`.
pub const FETCH_BRANCH_B: FetchParams = FetchParams {
    label: "chrome-oracle-2026-08-21-b",
    init_pc: 0,
    init_key: 32,
    byte_bias: 37,
    key_mul: 36_163,
    key_add: 38_392,
};

pub const FETCH_LIVE: FetchParams = FETCH_BRANCH_B;

/// Live entry (Chrome). Historical g-branch used key 100.
pub const INIT_PC: u32 = FETCH_LIVE.init_pc;
pub const INIT_KEY: u8 = FETCH_LIVE.init_key;
pub const BYTE_BIAS: u8 = FETCH_LIVE.byte_bias;
pub const KEY_MUL: u32 = FETCH_LIVE.key_mul;
pub const KEY_ADD: u32 = FETCH_LIVE.key_add;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpcodeKind {
    Direct,
    S1,
    S2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OpcodeDef {
    pub opcode: u8,
    pub handler: &'static str,
    pub kind: OpcodeKind,
    pub imm: Option<u8>,
}

/// Switch from the branch-`g` capture (`sF` = 21, …).
pub const OPCODE_TABLE_G: &[OpcodeDef] = &[
    d(213, "sh"),
    d(246, "sZ"),
    d(239, "sz"),
    d(189, "si"),
    d(77, "sU"),
    d(40, "sa"),
    d(38, "sc"),
    d(30, "sJ"),
    d(17, "st"),
    d(25, "sO"),
    d(21, "sF"),
    d(13, "sk"),
    d(136, "sQ"),
    d(116, "sf"),
    d(111, "sd"),
    d(9, "sL"),
    d(229, "se"),
    d(209, "sA"),
    d(231, "sq"),
    d(137, "sT"),
    d(29, "sS"),
    d(68, "su"),
    d(253, "sm"),
    d(86, "sX"),
    d(47, "sI"),
    d(192, "sW"),
    d(108, "sx"),
    d(202, "sw"),
    d(188, "sE"),
    d(151, "sP"),
    d(207, "sM"),
    d(43, "sr"),
    d(250, "sK"),
    d(177, "sy"),
    d(206, "sp"),
    d(182, "sg"),
    d(71, "sj"),
    d(129, "sN"),
    d(224, "s7"),
    d(219, "s8"),
    d(61, "s9"),
    d(157, "ss"),
    d(212, "s3"),
    d(121, "s4"),
    d(20, "s5"),
    d(67, "s6"),
    s1(147, 164),
    s1(238, 147),
    s1(185, 177),
    s1(123, 183),
    s1(3, 222),
    s1(146, 14),
    s1(218, 65),
    s1(161, 230),
    s1(148, 154),
    s1(2, 159),
    s1(243, 122),
    s1(221, 127),
    s1(240, 76),
    s1(251, 100),
    s1(235, 75),
    s1(51, 175),
    s1(194, 249),
    s1(125, 129),
    s2(215, 84),
    s2(153, 215),
    s2(165, 220),
    s2(79, 28),
    s2(126, 203),
];

/// Switch from headed Chrome iframe HTML (branch `b`, 2026-08-21).
pub const OPCODE_TABLE_B: &[OpcodeDef] = &[
    d(247, "dA"),
    d(184, "d8"),
    d(230, "d9"),
    d(191, "dJ"),
    d(2, "dd"),
    d(103, "dh"),
    d(215, "d5"),
    d(50, "d4"),
    d(14, "d6"),
    d(176, "d7"),
    d(8, "dN"),
    d(49, "dQ"),
    d(165, "dO"),
    d(111, "dI"),
    d(63, "dc"),
    d(156, "dK"),
    d(188, "dn"),
    d(207, "dR"),
    d(225, "dU"),
    d(91, "dq"),
    d(41, "dl"),
    d(183, "dv"),
    d(51, "di"),
    d(0, "d1"),
    d(71, "d2"),
    d(31, "d3"),
    d(133, "d0"),
    d(252, "P"),
    d(113, "df"),
    d(87, "dV"),
    d(197, "dL"),
    d(38, "da"),
    d(52, "dG"),
    d(211, "dZ"),
    d(177, "dS"),
    d(56, "dk"),
    d(77, "dD"),
    d(160, "db"),
    d(112, "F"),
    d(144, "m"),
    d(48, "o"),
    d(81, "M"),
    d(9, "p"),
    d(85, "T"),
    d(16, "B"),
    d(243, "X"),
    s1(185, 245),
    s1(66, 17),
    s1(202, 105),
    s1(209, 198),
    s1(5, 154),
    s1(83, 33),
    s1(122, 236),
    s1(1, 214),
    s1(218, 204),
    s1(117, 192),
    s1(17, 243),
    s1(204, 115),
    s1(145, 200),
    s1(162, 146),
    s1(171, 162),
    s1(65, 10),
    s1(124, 153),
    s1(147, 158),
    s2(69, 42),
    s2(244, 100),
    s2(70, 7),
    s2(199, 128),
    s2(25, 81),
];

pub const OPCODE_TABLE: &[OpcodeDef] = OPCODE_TABLE_B;

const fn d(opcode: u8, handler: &'static str) -> OpcodeDef {
    OpcodeDef {
        opcode,
        handler,
        kind: OpcodeKind::Direct,
        imm: None,
    }
}

const fn s1(opcode: u8, imm: u8) -> OpcodeDef {
    OpcodeDef {
        opcode,
        handler: "s1",
        kind: OpcodeKind::S1,
        imm: Some(imm),
    }
}

const fn s2(opcode: u8, imm: u8) -> OpcodeDef {
    OpcodeDef {
        opcode,
        handler: "s2",
        kind: OpcodeKind::S2,
        imm: Some(imm),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OpcodeFetch {
    pub pc: u32,
    pub key: u8,
    pub byte: u8,
    pub opcode: u8,
    pub next_key: u8,
    pub mapped: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpcodeStream {
    pub params_label: &'static str,
    pub init_pc: u32,
    pub init_key: u8,
    pub fetches: Vec<OpcodeFetch>,
    pub stopped: &'static str,
    pub first_mapped: Option<u8>,
    pub pc_deltas: Vec<u32>,
}

pub fn decode_opcode(params: FetchParams, key: u8, byte: u8) -> u8 {
    key ^ byte.wrapping_sub(params.byte_bias)
}

pub fn encode_byte(params: FetchParams, key: u8, opcode: u8) -> u8 {
    (key ^ opcode).wrapping_add(params.byte_bias)
}

pub fn next_key(params: FetchParams, key: u8, opcode: u8) -> u8 {
    let mixed = (u32::from(key) + u32::from(opcode)) * params.key_mul + params.key_add;
    (mixed & 0xff) as u8
}

pub fn opcode_def_in(table: &[OpcodeDef], opcode: u8) -> Option<&OpcodeDef> {
    table.iter().find(|d| d.opcode == opcode)
}

pub fn opcode_def(opcode: u8) -> Option<&'static OpcodeDef> {
    opcode_def_in(OPCODE_TABLE, opcode)
}

pub fn is_mapped_in(table: &[OpcodeDef], opcode: u8) -> bool {
    opcode_def_in(table, opcode).is_some()
}

pub fn step_fetch(params: FetchParams, key: u8, byte: u8) -> (u8, u8) {
    let opcode = decode_opcode(params, key, byte);
    (opcode, next_key(params, key, opcode))
}

pub fn verify_oracle_tuple(
    params: FetchParams,
    pc: u32,
    key: u8,
    byte: u8,
    opcode: u8,
) -> Result<(), String> {
    let got = decode_opcode(params, key, byte);
    if got != opcode {
        return Err(format!(
            "pc {pc}: decode({} key={key} byte=0x{byte:02x}) = {got}, oracle {opcode}",
            params.label
        ));
    }
    Ok(())
}

/// 1-byte walk. Diverges at the first mapped handler that consumes immediates.
pub fn naive_one_byte_fetches(
    bytecode: &[u8],
    params: FetchParams,
    table: &[OpcodeDef],
    limit: usize,
) -> OpcodeStream {
    let mut pc = params.init_pc;
    let mut key = params.init_key;
    let mut fetches = Vec::new();
    let mut first_mapped = None;
    let mut stopped = "limit";

    while fetches.len() < limit {
        let idx = pc as usize;
        if idx >= bytecode.len() {
            stopped = "end_of_bytecode";
            break;
        }
        let byte = bytecode[idx];
        let (opcode, nk) = step_fetch(params, key, byte);
        let mapped = is_mapped_in(table, opcode);
        if mapped && first_mapped.is_none() {
            first_mapped = Some(opcode);
        }
        fetches.push(OpcodeFetch {
            pc,
            key,
            byte,
            opcode,
            next_key: nk,
            mapped,
        });
        pc += 1;
        key = nk;
    }

    let pc_deltas = fetches
        .windows(2)
        .map(|w| w[1].pc.saturating_sub(w[0].pc))
        .collect();

    OpcodeStream {
        params_label: params.label,
        init_pc: params.init_pc,
        init_key: params.init_key,
        fetches,
        stopped,
        first_mapped,
        pc_deltas,
    }
}

pub fn magic_header_naive_fetches(
    magic: &[u8],
    params: FetchParams,
    table: &[OpcodeDef],
) -> OpcodeStream {
    naive_one_byte_fetches(magic, params, table, magic.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::run_program::{RUN_PROGRAM_MAGIC_BYTES, RUN_PROGRAM_MAGIC_BYTES_B};

    #[test]
    fn tables_are_unique_69() {
        for table in [OPCODE_TABLE_G, OPCODE_TABLE_B] {
            let mut seen = [false; 256];
            for def in table {
                assert!(!seen[def.opcode as usize], "dup {}", def.opcode);
                seen[def.opcode as usize] = true;
            }
            assert_eq!(table.len(), 69);
        }
    }

    #[test]
    fn fetch_roundtrip_both_builds() {
        for params in [FETCH_BRANCH_G, FETCH_BRANCH_B] {
            for key in [0u8, 1, params.init_key, 255] {
                for opcode in [0u8, 1, 8, 21, 255] {
                    let byte = encode_byte(params, key, opcode);
                    assert_eq!(decode_opcode(params, key, byte), opcode);
                    let mixed =
                        (u32::from(key) + u32::from(opcode)) * params.key_mul + params.key_add;
                    assert_eq!(next_key(params, key, opcode), (mixed & 0xff) as u8);
                }
            }
        }
    }

    #[test]
    fn g_magic_at_init_is_mapped_sf() {
        assert_eq!(
            decode_opcode(
                FETCH_BRANCH_G,
                FETCH_BRANCH_G.init_key,
                RUN_PROGRAM_MAGIC_BYTES[0]
            ),
            21
        );
        assert_eq!(
            opcode_def_in(OPCODE_TABLE_G, 21).map(|d| d.handler),
            Some("sF")
        );
        let stream =
            magic_header_naive_fetches(&RUN_PROGRAM_MAGIC_BYTES, FETCH_BRANCH_G, OPCODE_TABLE_G);
        assert_eq!(stream.fetches[0].opcode, 21);
        assert!(stream.fetches[0].mapped);
    }

    #[test]
    fn b_magic_at_init_is_mapped_dn() {
        // Chrome live packed prefix TX5omy48NT82Lp1ueY → 4d7e68… ; key 32 ^ (0x4d-37) = 8.
        assert_eq!(
            decode_opcode(
                FETCH_BRANCH_B,
                FETCH_BRANCH_B.init_key,
                RUN_PROGRAM_MAGIC_BYTES_B[0]
            ),
            8
        );
        assert_eq!(
            opcode_def_in(OPCODE_TABLE_B, 8).map(|d| d.handler),
            Some("dN")
        );
        let stream =
            magic_header_naive_fetches(&RUN_PROGRAM_MAGIC_BYTES_B, FETCH_BRANCH_B, OPCODE_TABLE_B);
        assert_eq!(stream.fetches[0].pc, 0);
        assert_eq!(stream.fetches[0].key, 32);
        assert_eq!(stream.fetches[0].opcode, 8);
        assert!(stream.fetches[0].mapped);
    }

    #[test]
    fn wrapping_sub_37_equals_plus_219() {
        for byte in [0u8, 1, 37, 77, 0x4d, 255] {
            let a = byte.wrapping_sub(37);
            let b = byte.wrapping_add(219);
            assert_eq!(a, b, "byte {byte}");
        }
    }

    #[test]
    fn synthetic_mapped_stream_roundtrips() {
        let params = FETCH_BRANCH_B;
        let ops = [8u8, 247, 0];
        let mut key = params.init_key;
        let mut bytes = Vec::new();
        for op in ops {
            bytes.push(encode_byte(params, key, op));
            key = next_key(params, key, op);
        }
        let stream = naive_one_byte_fetches(&bytes, params, OPCODE_TABLE_B, 8);
        assert_eq!(
            stream.fetches.iter().map(|f| f.opcode).collect::<Vec<_>>(),
            ops
        );
    }

    #[test]
    fn oracle_tuple_helper_rejects_mismatch() {
        assert!(verify_oracle_tuple(FETCH_BRANCH_B, 0, 32, 0x4d, 8).is_ok());
        assert!(verify_oracle_tuple(FETCH_BRANCH_B, 0, 32, 0x4d, 0).is_err());
        assert!(verify_oracle_tuple(FETCH_BRANCH_G, 0, 100, 0xaf, 21).is_ok());
    }

    #[test]
    fn headed_chrome_oracle_fixture_matches_formula_if_present() {
        let path = std::path::Path::new("scripts/fixtures/headed_chrome_oracle.json");
        if !path.is_file() {
            return;
        }
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let fetch = v.get("fetch").cloned().unwrap_or(v.clone());
        let params = FETCH_BRANCH_B;
        if let Some(key) = fetch.get("init_key").and_then(|x| x.as_u64()) {
            assert_eq!(key as u8, params.init_key);
        }
        if let Some(bias) = fetch.get("byte_bias").and_then(|x| x.as_u64()) {
            assert_eq!(bias as u8, params.byte_bias);
        }
        if let Some(mul) = fetch.get("key_mul").and_then(|x| x.as_u64()) {
            assert_eq!(mul as u32, params.key_mul);
        }
        let fetches = v
            .get("opcodeFetches")
            .or_else(|| v.get("fetches"))
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        for (i, f) in fetches.iter().enumerate() {
            let pc = f["pc"].as_u64().unwrap_or(0) as u32;
            let key = f["key"].as_u64().unwrap_or(0) as u8;
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
            verify_oracle_tuple(params, pc, key, byte, op)
                .unwrap_or_else(|e| panic!("fetch {i}: {e}"));
        }
        if let Some(fo) = v.get("headerCompare").or_else(|| v.get("fo")) {
            if let Some(ct) = fo.get("contentType").or_else(|| fo.get("content_type")) {
                assert_eq!(
                    ct.as_str().unwrap_or("").to_ascii_lowercase(),
                    "text/plain;charset=utf-8"
                );
            }
            if let Some(ra) = fo.get("cfChlRa").or_else(|| fo.get("cf_chl_ra")) {
                assert_eq!(ra.as_str().unwrap_or(""), "0");
            }
        }
    }
}
