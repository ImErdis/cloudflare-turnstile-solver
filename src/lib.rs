pub mod decompiler;
pub mod deobfuscator;
pub mod disassembler;
pub mod parser;
pub mod reverse;
pub mod solver;

pub use solver::VersionInfo;
pub use solver::challenge::CloudflareChallengeOptions;
pub use solver::fo_blob::{FoBlobAnalysis, analyze_fo_body};
pub use solver::fo_body::{
    CHARSET_BRANCH_B, CHARSET_BRANCH_G, CHROME_FO_PREFIXES_B, LIVE_FO_WRAPPER, body_chars_in_charset,
    classify_fo_body_len, extract_compressor_charset, looks_like_custom_b64, xtea_key_index,
};
pub use solver::fo_headers::{CHROME_FO_POST, CRATE_FO_POST, compare_chrome_and_crate_fo_post};
pub use solver::fo_init_json::{
    INIT_JSON_KEY_COUNT, INIT_JSON_KEYS_B, LIVE_FO_INIT_JSON, extract_init_json_keys,
};
pub use solver::fo_followup::{
    LIVE_FO_FOLLOWUP, classify_fo_response_len, NEXT_AFTER_FOLLOWUP_SHAPE,
};
pub use solver::fo_followup_json::{
    FOLLOWUP_COPIED_COUNT_B, FOLLOWUP_DROPPED_INIT_B, FOLLOWUP_EXTRA_IDENT_B, FOLLOWUP_FIELD_WRITE_B,
    LIVE_FO_FOLLOWUP_JSON, classify_fo_plaintext, NEXT_AFTER_FOLLOWUP_JSON,
};
pub use solver::protocol::{
    DEMO_HREF, DEMO_SITE_KEY, PUBLIC_API_JS, extract_fo_session, parse_turnstile_api_js_url,
    turnstile_iframe_url,
};
pub use solver::run_program::{
    PACKED_RUN_PROGRAM_PREFIX, PACKED_RUN_PROGRAM_PREFIX_B, PACKED_RUN_PROGRAM_PREFIX_B_LATE,
    RUN_PROGRAM_MAGIC_BYTES, RUN_PROGRAM_MAGIC_BYTES_B, RUN_PROGRAM_MAGIC_BYTES_B_LATE,
    RunProgramAnalysis, analyze_packed_run_program, unpack_packed_run_program,
};
pub use solver::run_program_ops::{
    DN_TAG_STRING, HANDLER_LAYOUT_B, HANDLER_LAYOUT_B_LATE, PROPERTY_IMM_ROLES_B_LATE, XF_TAG_CASES,
    XF_TAG_STRING, classify_pc_delta, classify_pc_delta_late, first_dn_tag_b, first_xf_tag_late,
    operand_from_byte, xf_tag_kind,
};
pub use solver::run_program_vm::{
    FETCH_LIVE, INIT_KEY, INIT_PC, OPCODE_TABLE, decode_opcode, naive_one_byte_fetches, next_key,
    opcode_def, opcode_def_in, params_for_magic, verify_oracle_tuple,
};
