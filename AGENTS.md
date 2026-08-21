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
- Unpack a captured packed `runProgram` blob (no network): `cargo run --locked --bin analyze_run_program`
- Naive opcode-fetch walk: `cargo run --locked --bin analyze_run_program -- --decode 16 <packed>`
- Headed Chrome oracle: `cd scripts && npm install && DISPLAY=:1 node chrome_oracle.mjs`
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
`cf-chl-ra` (retry counter, `0` on the first attempt) and a compressed init body
(live compressor `f4`, historical name `wZ`). A GET or empty POST is expected to 400
with JSON `{"d":"..."}`. A successful POST body is
standard base64; `decrypt_cloudflare_response(ray, body)` yields a packed `runProgram` blob
(prefix `ryrCJzUnLCItNTiVeJ...`), not JS. That packed string is **standard base64** of
bytecode whose first 13 bytes are a stable magic (`af2ac22735272c222d35389578`). The iframe
unpacks it with `atob` + `charCodeAt` (`function C`) and interprets it in `runProgram`.

Opcode fetch (headed Chrome oracle; **constants rotate per iframe build**, including
mid-day):

Linear (`g` and early `b`):

```
opcode = key ^ ((byte - bias) & 0xff)
key    = ((key + opcode) * mul + add) & 0xff
```

Later same-day `b` (Chrome 2026-08-21, `56907` in the iframe):

```
opcode = key ^ ((3 + byte) & 0xff)          // bias 253
mix    = key + opcode
key    = (mix*mix*56907 + 7914*mix + 22357) & 0xff
```

Snapshots:

- Early `b`: `bias=37`, `mul=36163`, `add=38392`, entry `(0, 32, [])`,
  packed prefix `TX5omy48NT82Lp1u`, first opcode `dN` (8), string tag **179**.
- Later `b`: `bias=253`, quadratic `(56907, 7914, 22357)`, entry `(0, 44, [])`,
  packed prefix `71GxwDchICYfNxik`, first opcode `Xf` (222), string tag **199**.
- Evening `b` (same SolveGate day): HTML fetch **rotated twice**. First
  `mix²*8904 + 14792*mix + 11229` / byte `-232` / case **113**, then linear
  `((key+op)*31579+59205)&255` / byte bias **113** / case **104**. The oracle
  injects both the quadratic pair and any `*mul,add)&255` linear spelling.
  `init_key` is not filled until opcode tuples verify. **Not** `FETCH_LIVE`
  (that stays the `56907` table).
- Captured branch `g`: `bias=62`, `mul=19663`, `add=36376`, entry `(0, 100, [])`,
  prefix `ryrCJzUnLCItNTiVeJ`, first opcode `sF` (21).

All three have **69** switch cases with different IDs. `dN`/`Cf`/`Xf` is the
same tagged-load family; extra-xors rotate (`154/48` → `86/112`).

Operand immediates use the **post-fetch** key (no mul/add / no quadratic):

```
imm = next_key ^ ((byte - bias) & 0xff) ^ extra_xor
```

Fixed-width handlers on early `b` (d6/d7/d4 width 2, dQ/d1/d3 width 3, p/F
width 4) are in `src/solver/run_program_ops.rs`. Late-`b` (`56907`) Direct
handlers are all 46 switch cases in `HANDLER_LAYOUT_B_LATE`, keyed by opcode
number. Chrome-stable widths: `gq`/246 width 3 extras `123,148`; `gG`/227
width 4 extras `221,41,180`; `X3`/104 width 2 extra `1`; `gY`/72 width 5
extras `117,221,231,177`; `X4`/12 width 2 extra `58`; `Xz`/52 width 3 extra
`132`; `Xg`/130 width 3 extras `112,19`; `ge`/169 width 5 extras `41,221,180,19`;
`Xf`/222 variable tag `86` dst `112`. The rest are HTML family tags (jump,
cond jump, LEB/`this.m[].o`, call/apply, `new`, property get/set, string-key
get/set, register swap). Minified names rotate; opcode numbers, `ToInt32`
extras, and family tags did not. A 1-byte walk still diverges immediately.
Do **not** execute these handlers as a solver. Chrome PC-delta inject must
match the **current** key-update spelling (`36163)+38392&255` or
`mix*mix,56907`) and harvest `{pc,op}` **while the OOPIF lives** (iframes close
before end-of-run `frame.evaluate`).

Headed Chrome Debugger pause at `56907` sees opcode `222` and mix `266`
(`44+222`); the next mix is `419` (`197+222`). `Fetch.fulfillRequest` rewrite
is ignored by the OOPIF; the breakpoint on the executed script is the oracle.
Minified local names rotate; the oracle classifies the varying 0–255 local as
opcode. Pause is after `pc+=1`, so the first observed pc is 1; deltas are still
instruction widths (`Xf` variable, `gq`/246 width 3, `gG`/227 width 4,
`X3`/104 width 2, `gY`/72 width 5).

Headed Chrome oracle: `cd scripts && npm install && DISPLAY=:1 node chrome_oracle.mjs`.
Chrome POSTs twice to the same `/fo/` URL (init ~4k → packed program; follow-up
~90k); `Content-Type: text/plain;charset=UTF-8` is XHR's default; `cf-chl-ra`
is `0` on the first attempt; `priority: u=1, i`. That **header shape did not
rotate** with the 56907 fetch. Crate POST header names and probe priority
match.

The compressor wrapper (live name `f4`, historical `wZ`) is mapped in
`src/solver/fo_body.rs`:

```
N = crypto.getRandomValues(Uint8Array(128))
N[0] = 2                    // before RSA
derived = N ** 65537 % PUBKEY
N[0] = 0                    // after RSA, XTEA key material
pad = (8 - lz_len % 8) % 8
key = N[pad*9+40 : pad*9+56]
body = custom_b64(derived || pad_byte || XTEA(LZ(json), key))
```

`N` is once per iframe, so both POSTs share the encoded RSA prefix. Charset
**order** rotates; the **set** is `A–Za–z0–9` plus `+$ -` (no `/` or `=`).
The crate's orchestrate `encrypt_payload` still zeros `N[0]` *before* RSA —
leave that.

First-POST plaintext is a **47-key JSON object** (`src/solver/fo_init_json.rs`).
Key names follow the iframe JS build (same-day `b` captures kept one set even
after fetch went quadratic; branch `g` uses different names). Several keys are
shared with `_cf_chl_opt` (parse those by value). The iframe assigns the literal
to a temp, then `setTimeout(send, 100, url, obj)`. One numeric field is
overwritten with `Date.now() - start` immediately before `send(f4(obj))`. The
orchestrate `PayloadKeyExtractor` looks for an object **literal** as the 4th
`setTimeout` argument and misses this. Do **not** fill values or POST that JSON.
The second `/fo/` POST (~86–88k) uses the **same** `f4`/`N` wrapper (shared
24-char RSA prefix, same URL, `cf-chl-ra: 0`). The send helper does
`send(f4(plaintext))` for both POSTs (minified name rotates: `fz` / `fj`).
After the init response (~822–846k packed `runProgram`), `runProgram` return
value — if a function — is invoked as `fn(initObj, sendHelper)`. That path
emits the follow-up. The follow-up **response** is ~2.4k (not another packed
program). Envelope: `src/solver/fo_followup.rs`. Field-set **kind**: the
mutated init object plus numeric `"1".."N"` VM entries plus extra ident keys
the VM adds (`src/solver/fo_followup_json.rs`). Branch-`b` headed Chrome (same
SolveGate day): 46 of 47 init keys (`MaOkK2` dropped), numeric `"1"`..`"39"`,
and 14 extra ident names. Early `f4` is init + `xBCsP4` with no numeric slots;
the oracle picker prefers the numeric shape. Key **names** come from headed
Chrome Debugger on `f4`'s first argument or the `setTimeout(send, 100)` helper
(kinds/lengths only — do not dump values). `JSON.stringify` of a
`CSSStyleDeclaration` is not the `/fo/` object and is rejected. Do **not** fill
or POST that JSON. Next gap is `handler_semantics`; do not run handlers as a
solver.

`probe_iframe` / `solve_test` should get iframe HTTP 200 + parsed options, then an honest
failure: orchestrate is not the VM, live `/fo/` without a valid init body 400s. `/cmg/1` 404s
(images moved to `/ci/{ray}/...`) and is skipped. Do **not** fill or POST the init JSON,
run the opcode handlers as a solver, or hook `TurnstileTask::solve`.

Static unpack + naive fetch: `cargo run --locked --bin analyze_run_program -- --decode 16 --ray <c_ray> <fo-body>`

Default demo: `https://solvegate.io/demo/invisible` (sitekey `0x4AAAAAAER49t0sMxTcief0`).

### Running the `solve_test` binary
- `TurnstileSolver::new()` reads a private fingerprint dataset from `./workspace/cloudflare_test.json`
  (relative to the current dir). That file is gitignored (`/workspace` in `.gitignore`, i.e. the
  `workspace/` subdirectory) and is **not** included in the repo, so the binary panics until that
  dataset is supplied. Building, linting, `probe_iframe`, and unit tests do not need it.
