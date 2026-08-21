pub mod decompiler;
pub mod deobfuscator;
pub mod disassembler;
pub mod parser;
pub mod reverse;
pub mod solver;

pub use solver::VersionInfo;
pub use solver::challenge::CloudflareChallengeOptions;
pub use solver::fo_blob::{FoBlobAnalysis, analyze_fo_body};
pub use solver::fo_headers::{CHROME_FO_POST, CRATE_FO_POST, compare_chrome_and_crate_fo_post};
pub use solver::protocol::{
    DEMO_HREF, DEMO_SITE_KEY, PUBLIC_API_JS, extract_fo_session, parse_turnstile_api_js_url,
    turnstile_iframe_url,
};
pub use solver::run_program::{
    PACKED_RUN_PROGRAM_PREFIX, PACKED_RUN_PROGRAM_PREFIX_B, RUN_PROGRAM_MAGIC_BYTES,
    RUN_PROGRAM_MAGIC_BYTES_B, RunProgramAnalysis, analyze_packed_run_program,
    unpack_packed_run_program,
};
pub use solver::run_program_vm::{
    FETCH_LIVE, INIT_KEY, INIT_PC, OPCODE_TABLE, decode_opcode, naive_one_byte_fetches, next_key,
    opcode_def, opcode_def_in, verify_oracle_tuple,
};
