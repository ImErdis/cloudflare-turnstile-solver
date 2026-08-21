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

### Running the `solve_test` binary
- `TurnstileSolver::new()` reads a private fingerprint dataset from `./workspace/cloudflare_test.json`
  (relative to the current dir). That file is gitignored (`/workspace` in `.gitignore`, i.e. the
  `workspace/` subdirectory) and is **not** included in the repo, so the binary panics with
  `NotFound` until that dataset is supplied. Building, linting, and testing do not need it.
