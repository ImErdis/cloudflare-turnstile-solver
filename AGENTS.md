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
- Probe live iframe protocol (no fingerprint): `cargo run --locked --bin probe_iframe`
- Run the solver against the SolveGate demo: `cargo run --locked --bin solve_test`

### Live Turnstile protocol (as of 2026-08)

Public `api.js` redirects to `/turnstile/v0/{branch}/{version}/api.js` (currently `g` /
`aae2b9a1c261`). The widget iframe is:

```
https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/{branch}/turnstile/f/av0/rch/{widget}/{sitekey}/{theme}/{fbE|fbD}/new/normal?lang={lang}
```

The old crate URL (`/h/b/turnstile/if/ov2/av0/rcv/.../{lang}/`, version `8359bcf47b68`) 404s.

`window._cf_chl_opt` still exists, but keys are randomized per challenge and the object ends in a
`postMessage` function — parse by value (sitekey, 16-hex ray, `chl_api_*`, `widgetId` / `nextRcV`
inside the function), not by `cType` / `cRay` names, and brace-match instead of truncating on the
first `};`.

There is still an `/orchestrate/chl_api/v1` URL, but the body is bootstrap JS that writes
randomized `_cf_chl_opt` fields — not the VM this crate disassembles (no `"lang":"` payload).

The iframe bootstrap then **XHR POSTs** `/fo/{session}/{ray}/{ch}` with headers `cf-chl` /
`cf-chl-ra` and a compressed init body (`wZ(...)`). A GET or empty POST is expected to 400
with JSON `{"d":"..."}`. A successful POST body is standard base64; `decrypt_cloudflare_response(ray, body)`
yields a packed `runProgram` blob (prefix `ryrCJzUnLCItNTiVeJ...`), not JS. The Worker blob
`eval`s that under a trustedTypes policy (`GAPH2`).

`probe_iframe` / `solve_test` should get iframe HTTP 200 + parsed options, then an honest
failure: orchestrate is not the VM, live `/fo/` without the init body 400s, and a captured
successful `/fo/` decrypts to packed `runProgram`. `/cmg/1` 404s (images moved to
`/ci/{ray}/...`) and is skipped so the client reaches that break. Do **not** reconstruct the
init payload or implement `runProgram` as a working solver.

Default demo: `https://solvegate.io/demo/invisible` (sitekey `0x4AAAAAAER49t0sMxTcief0`).

### Running the `solve_test` binary
- `TurnstileSolver::new()` reads a private fingerprint dataset from `./workspace/cloudflare_test.json`
  (relative to the current dir). That file is gitignored (`/workspace` in `.gitignore`, i.e. the
  `workspace/` subdirectory) and is **not** included in the repo, so the binary panics until that
  dataset is supplied. Building, linting, `probe_iframe`, and unit tests do not need it.
