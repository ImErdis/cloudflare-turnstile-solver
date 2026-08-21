# AGENTS.md

## Cursor Cloud specific instructions

This is a single Rust crate (`cf`) — a request-based Cloudflare Turnstile solver/reverse-engineering
library plus a `solve_test` binary. See `README.md`; the author notes the project is out-of-date and
may not fully work end-to-end against live Cloudflare.

### Toolchain
- Uses `edition = "2024"`, which requires Rust >= 1.85. The environment's default toolchain is
  `stable` (installed via `rustup`); the pre-existing 1.83 toolchain is too old. Do not downgrade.

### Dependencies (important, non-obvious)
- `rquest` and `rquest-util` were renamed upstream to `wreq`/`wreq-util`, and **all** `rquest`
  versions on crates.io are **yanked**. A fresh dependency resolution therefore fails with
  `version X is yanked`. A committed `Cargo.lock` pins the yanked crates.io versions (with
  checksums), so the crate builds fine using the lock.
- Always build/test with the committed lock. Do NOT run `cargo update` (or delete `Cargo.lock` and
  re-resolve) for `rquest`/`rquest-util` — it will re-trigger the yanked-version error. Prefer
  `--locked`.

### System dependency
- `rquest` pulls in `boring2`/`boring-sys2` (BoringSSL), which compiles C/C++ via cmake and links
  with clang (`/usr/bin/cc` -> clang). Clang selects the gcc **14** toolchain, so `libstdc++-14-dev`
  must be installed or linking fails with `cannot find -lstdc++`. This is provided in the base image;
  if you hit that error, `sudo apt-get install -y libstdc++-14-dev`.

### Commands
- Build: `cargo build --locked`
- Lint: `cargo clippy --locked --all-targets`  (currently emits warnings only, no errors)
- Test: `cargo test --locked`
- Run the app: `cargo run --locked --bin solve_test`
- Analyze a captured JS file with the in-tree oxc pipeline:
  `cargo run --locked --bin analyze_js -- path/to/script.js --write-deobfuscated artifacts/re-out/deob.js`

### JS reverse-engineering toolkit

This crate *is* a JS reverse: oxc-based deobfuscation, VM disassembly, payload-key extraction.
A typical JS RE bench for obfuscated browser scripts (webcrack, prettier/js-beautify,
synchrony, Acorn AST dumps, Chrome CDP capture, mitmproxy) is in `tools/js-re`.

Setup (once per machine): `npm ci --prefix tools/js-re`

| Step | Command |
| --- | --- |
| Fetch public Turnstile `api.js` | `node tools/js-re/src/fetch-public-api.mjs` |
| Beautify + webcrack | `node tools/js-re/src/deobfuscate.mjs artifacts/re-out/api.js` |
| AST histogram | `node tools/js-re/src/dump-ast.mjs artifacts/re-out/api.js` |
| Capture JS from a page | `node tools/js-re/src/capture-scripts.mjs <url>` |
| In-tree VM/opcode probe | `cargo run --locked --bin analyze_js -- <file.js>` |
| HTTPS intercept | `mitmdump -p 8080` (installed in the Cloud Agent image) then point Chrome at the proxy |

Workflow that actually matches how this repo was built:

1. Capture the **orchestrate** script (not just public `api.js`) from a widget load via CDP or mitmproxy.
2. Run prettier/webcrack so you can read it.
3. Run `analyze_js` — it applies *this crate's* oxc transformers and then the opcode/VM visitors.
   If `interpreter.ok` is false, the live script no longer matches the reverse (that is the
   current situation: iframe path and VM layout changed).
4. Diff opcode names / payload keys against `src/parser` and `src/deobfuscator/transformers`.

Public `api.js` is the widget loader only. The VM this crate reverses lives on
`/cdn-cgi/challenge-platform/.../orchestrate/...` and is issued per challenge. `analyze_js` on
`api.js` is expected to report `vm code was not found`; that is a useful negative result.

Do not `cargo update` rquest. Do not check captured Cloudflare scripts into git (`artifacts/` is
gitignored).


### Running the `solve_test` binary
- `TurnstileSolver::new()` reads a private fingerprint dataset from `./workspace/cloudflare_test.json`
  (relative to the current dir). That file is gitignored (`/workspace` in `.gitignore`, i.e. the
  `workspace/` subdirectory) and is **not** included in the repo, so the binary panics with
  `NotFound` until that dataset is supplied. Building, linting, and testing do not need it.
