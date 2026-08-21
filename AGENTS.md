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
- `TurnstileSolver::new()` reads `./workspace/cloudflare_test.json` (relative to the repo root).
  The original author's dump was never published. A collected fingerprint that matches the
  `Fingerprint` serde schema lives at that path. A collector is in
  `scripts/collect_fingerprint.mjs`.
- Regenerate it with Google Chrome + puppeteer-core:
  `cd scripts && npm install && node collect_fingerprint.mjs`
- The collector records real navigator/WebGL/Intl/audio surfaces from this VM's Chrome. It does
  **not** reproduce Cloudflare Turnstile's private VM hashes. The hashes are SHA-256 of local
  surfaces so the JSON deserializes; they will not match a live Turnstile script.
- `cargo run --locked --bin solve_test` loads that file, builds an HTTP client, and requests
  Cloudflare's widget iframe. As of 2026-08 the request returns **HTTP 404**: the hardcoded
  iframe path (`/cdn-cgi/challenge-platform/h/b/turnstile/if/ov2/av0/rcv/...`) is stale. Current
  `api.js` uses `turnstile/f/av0/rch` and version `g/aae2b9a1c261` instead of branch `b` /
  `8359bcf47b68`. The README already states the reverse is out of date. Updating the protocol
  is application reverse-engineering, not environment setup.
