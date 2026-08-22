#!/usr/bin/env node
/**
 * Headed Chrome oracle for live Turnstile `/fo/` + `runProgram`.
 *
 * Captures real request headers (CDP Network extraInfo) and injects a log at
 * the interpreter's opcode fetch (`* 36163 + 38392` live linear /
 * `mix*mix*56907+7914*mix+22357` later same-day / `* 19663 + 36376`
 * historical) inside the OOPIF iframe. Logs `{pc, op, key, byte}` so instruction
 * widths are PC deltas — not a 1-byte walk. Debugger on `f4` / `wZ` records the
 * plaintext object's **key names and value kinds** (string lengths, not contents).
 * Leftover extra-ident writes are logged as `{pc, opcode, key, valueKind}` via a
 * Proxy / `defineProperty` wrap on the `fn(initObj, fj)` argument — not values.
 * Fetch-loop Debugger breakpoints stay off unless `ORACLE_FETCH_TUPLES=1`
 * (finite harvest + large-bytecode condition) or `ORACLE_FETCH_LOOP_BP=1`.
 * Always-on pauses stalled `/fo/` because the HTML stub hits the same loop
 * before init POST. The iframe calls a **local** `runProgram`, so wrapping
 * `globalThis.runProgram` does not see the packed argument (`packedMeta` stays
 * null). Capture the init `/fo/` **response** instead (`Fetch.getResponseBody`
 * then `continueRequest` — do not rewrite `/fo/`). Does **not** reconstruct a
 * live `/fo/` POST body, dump full POST bodies, fill JSON values, execute
 * handlers as a solver, or harvest a token.
 *
 * Usage:
 *   DISPLAY=:1 node scripts/chrome_oracle.mjs [url] [out-dir]
 *   node scripts/chrome_oracle.mjs --self-test
 *
 * Env:
 *   CHROME_PATH          default /usr/bin/google-chrome-stable
 *   ORACLE_WAIT_MS       default 22000 (45000 when ORACLE_FETCH_TUPLES=1)
 *   ORACLE_HEADLESS      set to 1 to force headless (not the intended mode)
 *   ORACLE_SITE_ISOLATION set to 1 to keep OOPIF isolation (hooks will miss the iframe)
 *   ORACLE_SKIP_IFRAME_REWRITE set to 1 to save iframe HTML without Fetch.fulfillRequest
 *                    (packed /fo/ recapture; rewrite can stall a new fetch build)
 *   ORACLE_FETCH_TUPLES set to 1 for a finite fetch-loop Debugger harvest
 *                    ({pc,op,key,byte} then removeBreakpoint). Implies skip iframe rewrite.
 *                    Always-on fetch-loop BPs stall /fo/ because the HTML stub runs first.
 */
import fs from "node:fs";
import path from "node:path";
import puppeteer from "puppeteer-core";

const selfTest = process.argv.includes("--self-test");
const positional = process.argv.slice(2).filter((a) => a !== "--self-test");
const url = positional[0] || "https://solvegate.io/demo/invisible";
const outDir = positional[1] || path.join("artifacts", "re-out", "chrome-oracle");
const chrome = process.env.CHROME_PATH || "/usr/bin/google-chrome-stable";
const fetchTuples = process.env.ORACLE_FETCH_TUPLES === "1";
const fetchLoopBp = process.env.ORACLE_FETCH_LOOP_BP === "1";
const wantFetchLoopBp = fetchTuples || fetchLoopBp;
const waitMs = Number(process.env.ORACLE_WAIT_MS || (fetchTuples ? 45_000 : 22_000));
const headed = process.env.ORACLE_HEADLESS !== "1";
const isolateIframes = process.env.ORACLE_SITE_ISOLATION === "1";
const skipIframeRewrite =
  process.env.ORACLE_SKIP_IFRAME_REWRITE === "1" || fetchTuples;
const fetchTupleCap = Number(process.env.ORACLE_FETCH_TUPLE_CAP || 24);
/** Skip the HTML-embedded stub (~7k packed). Live `/fo/` packed is ~600k+. */
const FETCH_LOOP_BP_CONDITION =
  '(function(){try{if(globalThis.__cfPackedMeta&&globalThis.__cfPackedMeta.packedLen>10000)return true;var g=this&&this.g;if(!g)return false;if(typeof this.l==="number"&&g[this.l]&&g[this.l].length>10000)return true;for(var i=0;i<Math.min(g.length||0,48);i++){var v=g[i];if(v&&v.length>10000)return true;}return false;}catch(e){return false;}})()';

const CHROME_ARGS = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--disable-dev-shm-usage",
  "--window-size=1920,1080",
  "--use-gl=angle",
  "--use-angle=swiftshader",
  "--autoplay-policy=no-user-gesture-required",
];
if (!isolateIframes) {
  CHROME_ARGS.push(
    "--disable-site-isolation-trials",
    "--disable-features=IsolateOrigins,site-per-process",
  );
}

if (!selfTest) {
  fs.mkdirSync(outDir, { recursive: true });
}

const PREAMBLE = `(() => {
  if (globalThis.__cfOracleHook) return;
  globalThis.__cfOracleHook = true;
  globalThis.__cfOp = globalThis.__cfOp || [];
  globalThis.__cfXhr = globalThis.__cfXhr || [];
  globalThis.__cfRP = globalThis.__cfRP || [];
  globalThis.__cfFo = globalThis.__cfFo || [];
  globalThis.__cfWrites = globalThis.__cfWrites || [];
  const __cfDefProp = Object.defineProperty;
  const __cfWatched = typeof WeakSet === "function" ? new WeakSet() : { add: function () {}, has: function () { return false; } };
  const __cfLeftover = {
    OQbM0:1, UjLjP6:1, YfDjo7:1, Iqrc9:1, OZgbm6:1, pFyv1:1, SfUI1:1,
    sqKXG6:1, HUDi4:1, DTBF3:1, mQiic7:1, gNcr3:1
  };
  function __cfKind(v) {
    if (v === null) return "null";
    if (Array.isArray(v)) return "array:" + v.length;
    const t = typeof v;
    if (t === "string") return "string:" + v.length;
    if (t === "object") return "object:" + Object.keys(v).length;
    return t;
  }
  function __cfLastOp() {
    const ops = globalThis.__cfOp || [];
    const last = ops.length ? ops[ops.length - 1] : null;
    return {
      pc: last && last.pc,
      opcode: last && last.op,
      fetchKey: last && last.key,
      opCount: ops.length
    };
  }
  function __cfLogWrite(key, value, via) {
    try {
      const k = String(key);
      const writes = globalThis.__cfWrites;
      if (writes.length >= 80) return;
      const isDel = via === "delete";
      if (writes.some(function (w) { return w.key === k && (isDel ? w.via === "delete" : w.via !== "delete"); })) return;
      const op = __cfLastOp();
      writes.push({
        via: via,
        key: k,
        leftover: !!__cfLeftover[k],
        numeric: /^\\d+$/.test(k),
        valueKind: String(__cfKind(value)).split(":")[0],
        pc: op.pc == null ? null : op.pc,
        opcode: op.opcode == null ? null : op.opcode,
        opCount: op.opCount
      });
    } catch (e) {}
  }
  function __cfInstallWatch(obj) {
    if (!obj || typeof obj !== "object") return;
    try {
      if (__cfWatched.has(obj)) return;
      __cfWatched.add(obj);
    } catch (e) { return; }
    for (const name in __cfLeftover) {
      if (Object.prototype.hasOwnProperty.call(obj, name)) continue;
      (function (n) {
        let cur;
        try {
          __cfDefProp(obj, n, {
            configurable: true,
            enumerable: false,
            get: function () { return cur; },
            set: function (v) {
              __cfLogWrite(n, v, "set");
              cur = v;
              try {
                __cfDefProp(obj, n, {
                  configurable: true,
                  enumerable: true,
                  writable: true,
                  value: v
                });
              } catch (e2) {}
            }
          });
        } catch (e) {}
      })(name);
    }
    const baseline = Object.create(null);
    try {
      const keys = Object.keys(obj);
      for (let i = 0; i < keys.length; i++) baseline[keys[i]] = 1;
    } catch (e) {}
    const def = Object.defineProperty;
    try {
      Object.defineProperty = function (o, p, desc) {
        try {
          if (o === obj) {
            __cfLogWrite(p, desc && ("value" in desc) ? desc.value : undefined, "defineProperty");
          }
        } catch (e) {}
        return def.apply(this, arguments);
      };
    } catch (e) {}
    const start = Date.now();
    const poll = setInterval(function () {
      try {
        const keys = Object.keys(obj);
        for (let i = 0; i < keys.length; i++) {
          const k = keys[i];
          if (__cfLeftover[k]) continue;
          if (/^\\d+$/.test(k) || !baseline[k]) {
            __cfLogWrite(k, obj[k], "poll");
            baseline[k] = 1;
          }
        }
        if (baseline["MaOkK2"] && !Object.prototype.hasOwnProperty.call(obj, "MaOkK2")) {
          __cfLogWrite("MaOkK2", undefined, "delete");
        }
        if (Date.now() - start > 12000) clearInterval(poll);
      } catch (e) { clearInterval(poll); }
    }, 5);
  }
  function __cfShape(obj, via) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
    const keys = Object.keys(obj);
    if (keys.length < 20 || keys.length > 250) return null;
    if (keys.indexOf("alignContent") >= 0 && keys.indexOf("webkitAlignContent") >= 0) {
      return null;
    }
    const ident = [];
    const numeric = [];
    const kinds = {};
    let nMin = null;
    let nMax = null;
    for (const k of keys) {
      kinds[k] = __cfKind(obj[k]);
      if (/^\\d+$/.test(k)) {
        numeric.push(k);
        const n = Number(k);
        if (nMin === null || n < nMin) nMin = n;
        if (nMax === null || n > nMax) nMax = n;
      } else ident.push(k);
    }
    return {
      via,
      keyCount: keys.length,
      identKeys: ident,
      numericKeyCount: numeric.length,
      numericKeyMin: nMin,
      numericKeyMax: nMax,
      kinds,
    };
  }
  try {
    const js = JSON.stringify;
    JSON.stringify = function (v) {
      try {
        const s = __cfShape(v, "stringify");
        if (s && globalThis.__cfFo.length < 12) globalThis.__cfFo.push(s);
      } catch {}
      return js.apply(this, arguments);
    };
  } catch (e) {
    globalThis.__cfHookErr = String(e);
  }
  try {
    const proto = XMLHttpRequest.prototype;
    const open = proto.open;
    const srh = proto.setRequestHeader;
    const send = proto.send;
    proto.open = function (method, url) {
      this.__cf = { method: String(method), url: String(url), headers: {} };
      return open.apply(this, arguments);
    };
    proto.setRequestHeader = function (k, v) {
      if (this.__cf) this.__cf.headers[String(k)] = String(v);
      return srh.apply(this, arguments);
    };
    proto.send = function (body) {
      const rec = this.__cf || {};
      const u = rec.url || "";
      if (/\\/fo\\/|challenge-platform/.test(u)) {
        const b = body == null ? "" : String(body);
        const row = {
          method: rec.method,
          url: u,
          headers: rec.headers,
          bodyLen: b.length,
          bodyPrefix: b.slice(0, 24),
        };
        globalThis.__cfXhr.push(row);
        this.addEventListener("loadend", function () {
          row.status = this.status;
          row.respLen = (this.responseText || "").length;
          row.respPrefix = (this.responseText || "").slice(0, 24);
        });
      }
      return send.apply(this, arguments);
    };
  } catch (e) {
    globalThis.__cfHookErr = String(e);
  }
  try {
    const st = setTimeout;
    setTimeout = function (fn, ms) {
      try {
        if (ms === 100) {
          for (let i = 2; i < arguments.length; i++) {
            const s = __cfShape(arguments[i], "setTimeout");
            if (s && globalThis.__cfFo.length < 12) globalThis.__cfFo.push(s);
          }
          const orig = fn;
          fn = function () {
            const obj = arguments.length > 1 ? arguments[1] : undefined;
            const r = orig.apply(this, arguments);
            try { if (obj && typeof obj === "object") __cfInstallWatch(obj); } catch (e) {}
            return r;
          };
        }
      } catch {}
      return st.apply(this, arguments);
    };
  } catch (e) {
    globalThis.__cfHookErr = (globalThis.__cfHookErr || "") + String(e);
  }
  try {
    function wrapRP(v) {
      if (typeof v !== "function" || v.__cfRPWrapped) return v;
      const wrapped = function (packed, helper) {
        try {
          globalThis.__cfRP.push({
            packedType: typeof packed,
            packedLen: packed && packed.length,
            packedPrefix: String(packed || "").slice(0, 20),
          });
          if (typeof packed === "string" && packed.length > 50000 && !globalThis.__cfPackedMeta) {
            globalThis.__cfPackedMeta = {
              packedLen: packed.length,
              packedPrefix: packed.slice(0, 20),
            };
            globalThis.__cfPacked = packed;
          }
        } catch {}
        const ret = v.apply(this, arguments);
        if (typeof ret === "function") {
          return function (initObj, sendFn) {
            try {
              const s0 = __cfShape(initObj, "rpReturn");
              if (s0 && globalThis.__cfFo.length < 12) globalThis.__cfFo.push(s0);
              try { __cfInstallWatch(initObj); } catch (e) {}
              let last = s0 && s0.keyCount;
              const start = Date.now();
              const poll = setInterval(function () {
                try {
                  const s = __cfShape(initObj, "rpMutate");
                  if (s && s.keyCount !== last && (s.numericKeyCount > 0 || s.keyCount > (last || 0))) {
                    last = s.keyCount;
                    if (globalThis.__cfFo.length < 12) globalThis.__cfFo.push(s);
                  }
                  if (Date.now() - start > 12000) clearInterval(poll);
                } catch (e) {
                  clearInterval(poll);
                }
              }, 25);
            } catch {}
            return ret.apply(this, arguments);
          };
        }
        return ret;
      };
      wrapped.__cfRPWrapped = true;
      return wrapped;
    }
    let rp;
    Object.defineProperty(globalThis, "runProgram", {
      configurable: true,
      enumerable: true,
      set(v) {
        rp = wrapRP(v);
      },
      get() {
        return rp;
      },
    });
    setInterval(function () {
      try {
        const cur = globalThis.runProgram;
        if (typeof cur === "function" && !cur.__cfRPWrapped) {
          globalThis.runProgram = wrapRP(cur);
        }
      } catch {}
    }, 20);
  } catch (e) {
    globalThis.__cfHookErr = (globalThis.__cfHookErr || "") + String(e);
  }
})();`;

function fetchSnippet(html) {
  for (const marker of [
    "23196",
    "32619",
    "19372",
    "*31579,59205",
    "I*I*8904",
    "*8904,",
    "14792",
    "39695",
    "56907",
    "36163)+38392",
    "19663)+36376",
    "*28814",
    "36163",
    "19663",
  ]) {
    const idx = html.indexOf(marker);
    if (idx >= 0) {
      return html.slice(Math.max(0, idx - 280), idx + 220);
    }
  }
  return null;
}

/** HTML fetch schedule. `init_key` is not here — that needs opcode tuples. */
function extractFetchQuadratic(html) {
  if (!html) return null;
  const idx = html.search(
    /(\w+)\*\1\*\d{4,5}|\d{4,5}\*\((\w+)\*\2\)|,\d{4,5}\),[\s\S]{0,48}\(\w+,\d{4,5}\)/,
  );
  const window = idx >= 0 ? html.slice(Math.max(0, idx - 240), idx + 420) : html;
  const sq = window.match(
    /(\w+)\*\1\*(\d{4,5}),[\s\S]{0,96}?\(\1,(\d{4,5})\)\)\+(\d{4,5}),255/,
  );
  const sqPlus = window.match(
    /(\w+)\*\1\*(\d{4,5})\+[\s\S]{0,96}?\(\1,(\d{4,5})\)\+(\d{4,5}),255/,
  );
  const alt = window.match(
    /(\d{4,5})\*\((\w+)\*\2\)\+[\s\S]{0,96}?\(\2,(\d{4,5})\),(\d{4,5})\)&255/,
  );
  const mulStar = window.match(
    /(\d{4,5})\*\((\w+)\*\2\),(\2)\*(\d{4,5})\)\+(\d{4,5}),255/,
  );
  const sqAmp = window.match(
    /(\w+)\*\1\*(\d{4,5})\+[\s\S]{0,96}?\(\1,(\d{4,5})\)\+(\d{4,5})&255/,
  );
  const nestMul = window.match(
    /\((\w+),\1\),(\d{4,5})\),[\s\S]{0,96}?\(\1,(\d{4,5})\)\)\+(\d{4,5}),255/,
  );
  const starMix = window.match(
    /\((\w+),\1\)\*(\d{4,5})\+\1\*(\d{4,5})\+(\d{4,5}),255/,
  );
  const mulTimesSq = window.match(
    /(\d{4,5})\*\((\w+)\*\2\)\+[\s\S]{0,96}?\(\2,(\d{4,5})\)\+(\d{4,5})&255/,
  );
  const biasM = window.match(/\]-(\d{2,3}),256\)&255/);
  const biasAdd = window.match(/\[(\w+)\],(\d{2,3})\)\+256/);
  const biasPlus = window.match(/\((\d{2,3})\+\w+\[\w+\],255\)/);
  const caseM = window.match(/\{case (\d+):/);
  const hit = sq || sqPlus || sqAmp || nestMul || starMix || mulTimesSq || alt || mulStar;
  if (!hit) return null;
  let keyMul;
  let keyQuadB;
  let keyAdd;
  let spelling;
  if (sq) {
    keyMul = Number(sq[2]);
    keyQuadB = Number(sq[3]);
    keyAdd = Number(sq[4]);
    spelling = "mix*mix*mul";
  } else if (sqPlus) {
    keyMul = Number(sqPlus[2]);
    keyQuadB = Number(sqPlus[3]);
    keyAdd = Number(sqPlus[4]);
    spelling = "mix*mix*mul+";
  } else if (sqAmp) {
    keyMul = Number(sqAmp[2]);
    keyQuadB = Number(sqAmp[3]);
    keyAdd = Number(sqAmp[4]);
    spelling = "mix*mix*mul+helper&255";
  } else if (nestMul) {
    keyMul = Number(nestMul[2]);
    keyQuadB = Number(nestMul[3]);
    keyAdd = Number(nestMul[4]);
    spelling = "helper(mix,mix),mul";
  } else if (starMix) {
    keyMul = Number(starMix[2]);
    keyQuadB = Number(starMix[3]);
    keyAdd = Number(starMix[4]);
    spelling = "(mix,mix)*mul+mix*b";
  } else if (mulTimesSq) {
    keyMul = Number(mulTimesSq[1]);
    keyQuadB = Number(mulTimesSq[3]);
    keyAdd = Number(mulTimesSq[4]);
    spelling = "mul*(mix*mix)+helper&255";
  } else if (mulStar) {
    keyMul = Number(mulStar[1]);
    keyQuadB = Number(mulStar[4]);
    keyAdd = Number(mulStar[5]);
    spelling = "mul*(mix*mix),mix*b";
  } else {
    keyMul = Number(alt[1]);
    keyQuadB = Number(alt[3]);
    keyAdd = Number(alt[4]);
    spelling = "mul*(mix*mix)";
  }
  return {
    keyMul,
    keyQuadB,
    keyAdd,
    byteBias: biasM
      ? Number(biasM[1])
      : biasAdd
        ? Number(biasAdd[2])
        : biasPlus
          ? (256 - Number(biasPlus[1])) & 255
          : null,
    firstSwitchCase: caseM ? Number(caseM[1]) : null,
    spelling,
    note: "HTML formula only; init_key needs opcode tuples. Not FETCH_LIVE.",
  };
}

/** Linear `((key+op)*mul+add)&255`. Same honesty rule as the quadratic extractor. */
function extractFetchLinear(html) {
  if (!html) return null;
  const idx = html.search(
    /\*\d{4,5},\d{4,5}\)&255|\d{4,5}\)\+\d{4,5}&255|\+\w+,\d{4,5}\),\d{4,5}\)&255/,
  );
  const window = idx >= 0 ? html.slice(Math.max(0, idx - 280), idx + 360) : html;
  const mulAdd = window.match(/\*(\d{4,5}),(\d{4,5})\)&255(?:\.\d+)?,(\w+)\)\{case (\d+):/);
  const plus = window.match(/(\d{4,5})\)\+(\d{4,5})&255(?:\.\d+)?,(\w+)\)\{case (\d+):/);
  const addMix = window.match(
    /\(\w+\+\w+,(\d{4,5})\),(\d{4,5})\)&255(?:\.\d+)?,(\w+)\)\{case (\d+):/,
  );
  const biasAdd = window.match(/\[(\w+)\],(\d{2,3})\)\+256/);
  const biasSub = window.match(/\[(\w+)\]-(\d{2,3}),256/);
  if (!mulAdd && !plus && !addMix) return null;
  const keyMul = mulAdd ? Number(mulAdd[1]) : plus ? Number(plus[1]) : Number(addMix[1]);
  const keyAdd = mulAdd ? Number(mulAdd[2]) : plus ? Number(plus[2]) : Number(addMix[2]);
  const firstSwitchCase = mulAdd
    ? Number(mulAdd[4])
    : plus
      ? Number(plus[4])
      : Number(addMix[4]);
  return {
    kind: "linear",
    keyMul,
    keyAdd,
    byteBias: biasAdd ? Number(biasAdd[2]) : biasSub ? Number(biasSub[2]) : null,
    firstSwitchCase,
    spelling: mulAdd ? "*mul,add)&255" : plus ? "mul)+add&255" : "(mix,mul),add)&255",
    note: "HTML formula only; init_key needs opcode tuples. Not FETCH_LIVE.",
  };
}

function extractVmEntryKey(html) {
  if (!html) return null;
  const ctor = String(html).match(/new \w+\(\w+\)\(0,(\d{1,3}),\[\]\)/);
  if (ctor) return Number(ctor[1]);
  const method = String(html).match(
    /new \w+\(\w+\)\[\w+\([^)]{0,40}\)\]\(0,(\d{1,3}),\[\]\)/,
  );
  if (method) return Number(method[1]);
  const bare = String(html).match(/\(0,(\d{1,3}),\[\]\)/);
  return bare ? Number(bare[1]) : null;
}

function extractFetchSchedule(html) {
  const s = extractFetchQuadratic(html) || extractFetchLinear(html);
  if (!s) return null;
  const initKeyCandidate = extractVmEntryKey(html);
  if (initKeyCandidate != null) s.initKeyCandidate = initKeyCandidate;
  return s;
}

/** Markers observed in headed iframe HTML (not FETCH_LIVE). 8904 alone matches SVG. */
const FETCH_SOURCE_MARKERS = [
  "23196",
  "32619",
  "19372",
  "56907",
  "39695",
  "36163",
  "19663",
  "28814",
  "31579",
  "59205",
  "I*I*8904",
  "*8904,",
];

function fetchMarkerInSource(src) {
  if (!src) return null;
  const schedule = extractFetchSchedule(src);
  for (const marker of FETCH_SOURCE_MARKERS) {
    const idx = src.indexOf(marker);
    if (idx >= 0) {
      return { marker, idx, schedule, hasInject: src.includes("__cfOp.push") };
    }
  }
  if (schedule && schedule.keyMul != null) {
    const marker = String(schedule.keyMul);
    const idx = src.indexOf(marker);
    if (idx >= 0) return { marker, idx, schedule, hasInject: src.includes("__cfOp.push") };
  }
  return null;
}

/**
 * Instrument both fetch loops. The arithmetic is stable; wrapping rotates:
 *   switch(state[pc]=pc+1, ...)
 *   switch(state[pc]=add(pc,1), ...)
 *   key = ((key+op)*mul+add)&255   as either `*mul+add,255` or `mul)+add&255.xx`
 *   key = (mix*mix*56907 + 7914*mix + 22357)&255  (later same-day b)
 *   key = (mix*mix*8904 + 14792*mix + 11229)&255  (evening b; byte-232)
 * PC is snapshotted from `if(pc=state[slot],pc!==pc)return ...;switch(`.
 */
function injectOpcodeLog(html, opts = {}) {
  if (!html) {
    return { html, injected: false, replacements: 0, snippet: null };
  }
  const jsOnly = !!opts.jsOnly;
  const snippet = fetchSnippet(html);
  let n = 0;
  let out = html;

  out = out.replace(
    /if\((\w+)=(\w+)\[(\w+)\],\1!==\1\)return \2\[(\w+)\];switch\(/g,
    (_full, pc, st, slot, ret) => {
      n++;
      return (
        `if(${pc}=${st}[${slot}],${pc}!==${pc})return ${st}[${ret}];` +
        `switch((globalThis.__cfT={pc:${pc}}),`
      );
    },
  );
  // Same NaN check via helper(pc, pc) instead of pc!==pc.
  out = out.replace(
    /if\((\w+)=(\w+)\[(\w+)\],(\w+\[[^\]]{0,80}\])\(\1,\1\)\)return \2\[(\w+)\];switch\(/g,
    (_full, pc, st, slot, eq, ret) => {
      n++;
      return (
        `if(${pc}=${st}[${slot}],${eq}(${pc},${pc}))return ${st}[${ret}];` +
        `switch((globalThis.__cfT={pc:${pc}}),`
      );
    },
  );

  out = out.replace(
    /(\w+)=(\w+)\[(\w+)\]\^([\s\S]{0,80}?\((\w+)\[\1\],(?:37|62)\)\+256&255,)/g,
    (_full, op, st, keySlot, rest, arr) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${op}]&255),${st}[${keySlot}])^${rest}`;
    },
  );
  // 39695 try: oF=st[key]^helper(arr[pc],133)+256&255 (pc kept in a second local)
  out = out.replace(
    /(\w+)=(\w+)\[(\w+)\]\^([\s\S]{0,96}?\((\w+)\[(\w+)\],(\d{2,3})\)\+256&255)/g,
    (_full, op, st, keySlot, rest, arr, pcVar) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${pcVar}]&255),${st}[${keySlot}])^${rest}`;
    },
  );
  // 39695 catch: xor(st[key], and(add(arr[op],133)+256,255))
  out = out.replace(
    /(\w+)=(\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],(\w+\[[^\]]{0,80}\])\((\w+\[[^\]]{0,80}\])\((\w+)\[\1\],(\d{2,3})\)\+256,255\)\)/g,
    (_full, op, xorCallee, st, keySlot, andCallee, addCallee, arr, bias) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${op}]&255),${xorCallee}(${st}[${keySlot}],${andCallee}(${addCallee}(${arr}[${op}],${bias})+256,255)))`;
    },
  );
  // Helper xor: D=xor(st[key], add(arr[D],113)+256&255)
  out = out.replace(
    /(\w+)=(\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],(\w+\[[^\]]{0,80}\])\((\w+)\[\1\],(\d{2,3})\)\+256&255\)/g,
    (_full, op, xorCallee, st, keySlot, addCallee, arr, bias) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${op}]&255),${xorCallee}(${st}[${keySlot}],${addCallee}(${arr}[${op}],${bias})+256&255))`;
    },
  );

  out = out.replace(
    /(\w+)=(\w+\[[^\]]{0,48}\])\((\w+)\[(\w+)\],219\+(\w+)\[(\w+)\]&255\)/g,
    (_full, op, callee, st, keySlot, arr, pc) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${pc}]&255),${callee}(${st}[${keySlot}],219+${arr}[${pc}]&255))`;
    },
  );

  out = out.replace(
    /(\w+)=(\w+)\[(\w+)\]\^3\+(\w+)\[\1\]&255(?:\.\d+)?,/g,
    (_full, op, st, keySlot, arr) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${op}]&255),${st}[${keySlot}])^3+${arr}[${op}]&255,`;
    },
  );

  // Catch copy: xor(key, add(sub(byte,253),256)&255)
  out = out.replace(
    /(\w+)=(\w+\[[^\]]{0,64}\])\((\w+)\[(\w+)\],(\w+\[[^\]]{0,64}\])\((\w+\[[^\]]{0,64}\])\((\w+)\[(\w+)\],253\),256\)&255(?:\.\d+)?\)/g,
    (_full, op, xorCallee, st, keySlot, addCallee, subCallee, arr, pc) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${pc}]&255),${xorCallee}(${st}[${keySlot}],${addCallee}(${subCallee}(${arr}[${pc}],253),256)&255))`;
    },
  );

  out = out.replace(/\*36163\+38392,255\),(\w+)\)/g, (_full, opVar) => {
    n++;
    return logAfterKeyUpdate(`*36163+38392,255)`, opVar);
  });
  out = out.replace(/36163\)\+38392&255(?:\.\d+)?,(\w+)\)/g, (_full, opVar) => {
    n++;
    return logAfterKeyUpdate(`36163)+38392&255`, opVar);
  });
  out = out.replace(/36163\+38392&255(?:\.\d+)?,(\w+)\)\{case/g, (_full, opVar) => {
    n++;
    return `${logAfterKeyUpdate("36163+38392&255", opVar)}{case`;
  });
  out = out.replace(/\*19663\+36376,255\),(\w+)\)/g, (_full, opVar) => {
    n++;
    return logAfterKeyUpdate(`*19663+36376,255)`, opVar);
  });
  out = out.replace(/19663\)\+36376&255(?:\.\d+)?,(\w+)\)/g, (_full, opVar) => {
    n++;
    return logAfterKeyUpdate(`19663)+36376&255`, opVar);
  });
  // Quadratic try: (Xm(Xm(mix*mix,56907),7914*mix)+22357&255, op)
  out = out.replace(
    /56907\),7914\*(\w+)\)\+22357&255,(\w+)\)/g,
    (_full, mixVar, opVar) => {
      n++;
      return logAfterKeyUpdate(`56907),7914*${mixVar})+22357&255`, opVar);
    },
  );
  // Quadratic catch: (Xm(Xm(mix,mix),56907)+7914*mix+22357,255), op)
  out = out.replace(
    /56907\)\+7914\*(\w+)\+22357,255\),(\w+)\)/g,
    (_full, mixVar, opVar) => {
      n++;
      return logAfterKeyUpdate(`56907)+7914*${mixVar}+22357,255`, opVar);
    },
  );
  // Later spelling: 56907*(mix*mix) + (mix,7914) + 22357
  out = out.replace(
    /56907\*\((\w+)\*\1\)([\s\S]{0,120}?)\+22357&255(?:\.\d+)?,(\w+)\)/g,
    (_full, mixVar, mid, opVar) => {
      n++;
      return logAfterKeyUpdate(`56907*(${mixVar}*${mixVar})${mid}+22357&255`, opVar);
    },
  );

  // Linear rotation: ((key+op)*28814+40641)&255 (bias 17 / +239)
  out = out.replace(/\*28814,40641\)&255(?:\.\d+)?,(\w+)\)/g, (_full, opVar) => {
    n++;
    return logAfterKeyUpdate(`*28814,40641)&255`, opVar);
  });
  out = out.replace(/\*28814\+40641&255(?:\.\d+)?,(\w+)\)/g, (_full, opVar) => {
    n++;
    return logAfterKeyUpdate(`*28814+40641&255`, opVar);
  });
  // Any linear `((key+op)*mul+add)&255` spelled `*mul,add)&255` / `(mix,mul),add)&255`.
  out = out.replace(
    /\*(\d{4,5}),(\d{4,5})\)&255(?:\.\d+)?,(\w+)\)/g,
    (_full, mul, add, opVar) => {
      n++;
      return logAfterKeyUpdate(`*${mul},${add})&255`, opVar);
    },
  );
  out = out.replace(
    /(\d{4,5})\)\+(\d{4,5})&255(?:\.\d+)?,(\w+)\)/g,
    (_full, mul, add, opVar) => {
      n++;
      return logAfterKeyUpdate(`${mul})+${add}&255`, opVar);
    },
  );
  out = out.replace(
    /\),(\d{4,5})\)&255(?:\.\d+)?,(\w+)\)\{case/g,
    (_full, add, opVar) => {
      n++;
      return `${logAfterKeyUpdate(`),${add})&255`, opVar)}{case`;
    },
  );

  // Evening b: opcode = key ^ wrapping_sub(byte, 232)
  // Happy: D=aP[af]^helper(ae[D]-232,256)&255
  out = out.replace(
    /(\w+)=(\w+)\[(\w+)\]\^([\s\S]{0,96}?\((\w+)\[\1\]-(\d{2,3}),256\)&255)/g,
    (_full, op, st, keySlot, rest, arr) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${op}]&255),${st}[${keySlot}])^${rest}`;
    },
  );
  // Catch: Qv=xor(key, and(add(arr[pc]-113,256),255))
  out = out.replace(
    /(\w+)=(\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],(\w+\[[^\]]{0,80}\])\((\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\]-(\d{2,3}),256\),255\)/g,
    (_full, op, xorCallee, st, keySlot, andCallee, addCallee, arr, pc, bias) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${pc}]&255),${xorCallee}(${st}[${keySlot}],${andCallee}(${addCallee}(${arr}[${pc}]-${bias},256),255)))`;
    },
  );

  // Catch evening quadratic: aJ=xor(st[key], helper(arr[pc]-232,256)&255)
  out = out.replace(
    /(\w+)=(\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],(\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\]-(\d{2,3}),256\)&255/g,
    (_full, op, xorCallee, st, keySlot, subCallee, arr, pc, bias) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${pc}]&255),${xorCallee}(${st}[${keySlot}],${subCallee}(${arr}[${pc}]-${bias},256)&255))`;
    },
  );

  // Evening quadratic happy: helper(mix*mix*8904, helper(mix,14792))+11229,255), op
  out = out.replace(
    /(\w+)\*\1\*(\d{4,5}),([\s\S]{0,96}?)\(\1,(\d{4,5})\)\)\+(\d{4,5}),255\),(\w+)\)/g,
    (_full, mixVar, mul, mid, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mixVar}*${mixVar}*${mul},${mid}(${mixVar},${quadB}))+${add},255`,
        opVar,
      );
    },
  );
  // Evening quadratic catch: 8904*(mix*mix)+helper(mix,14792),11229)&255, op
  out = out.replace(
    /(\d{4,5})\*\((\w+)\*\2\)\+([\s\S]{0,96}?)\(\2,(\d{4,5})\),(\d{4,5})\)&255(?:\.\d+)?,(\w+)\)/g,
    (_full, mul, mixVar, mid, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mul}*(${mixVar}*${mixVar})+${mid}(${mixVar},${quadB}),${add})&255`,
        opVar,
      );
    },
  );

  // 39695 try: mix*mix*39695+helper(mix,3159)+64171,255), op
  out = out.replace(
    /(\w+)\*\1\*(\d{4,5})\+([\s\S]{0,120}?)\(\1,(\d{4,5})\)\+(\d{4,5}),255\),(\w+)\)/g,
    (_full, mixVar, mul, mid, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mixVar}*${mixVar}*${mul}+${mid}(${mixVar},${quadB})+${add},255`,
        opVar,
      );
    },
  );
  // 39695 catch: 39695*(mix*mix),mix*3159)+64171,255), op
  out = out.replace(
    /(\d{4,5})\*\((\w+)\*\2\),(\2)\*(\d{4,5})\)\+(\d{4,5}),255\),(\w+)\)/g,
    (_full, mul, mixVar, _mix2, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mul}*(${mixVar}*${mixVar}),${mixVar}*${quadB})+${add},255`,
        opVar,
      );
    },
  );

  out = out.replace(
    /(\w+)=(\w+)\[(\w+)\]\^((?:\w+\[[^\]]{0,80}\])\((\d{2,3})\+(\w+)\[\1\],255\))/g,
    (_full, op, st, keySlot, rest, _add, arr) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${op}]&255),${st}[${keySlot}])^${rest}`;
    },
  );
  out = out.replace(
    /(\w+)=(\w+)\[(\w+)\]\^([\s\S]{0,96}?\((\w+)\[(\w+)\]-(\d{2,3}),256\)&255)/g,
    (_full, op, st, keySlot, rest, arr, pcVar) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${pcVar}]&255),${st}[${keySlot}])^${rest}`;
    },
  );
  out = out.replace(
    /\((\w+),\1\),(\d{4,5})\),([\s\S]{0,96}?)\(\1,(\d{4,5})\)\)\+(\d{4,5}),255\),(\w+)\)/g,
    (_full, mixVar, mul, mid, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `(${mixVar},${mixVar}),${mul}),${mid}(${mixVar},${quadB}))+${add},255`,
        opVar,
      );
    },
  );
  out = out.replace(
    /\((\w+),\1\)\*(\d{4,5})\+\1\*(\d{4,5})\+(\d{4,5}),255\),(\w+)\)/g,
    (_full, mixVar, mul, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `(${mixVar},${mixVar})*${mul}+${mixVar}*${quadB}+${add},255`,
        opVar,
      );
    },
  );

  out = out.replace(
    /(\d{4,5})\*\((\w+)\*\2\)\+([\s\S]{0,96}?)\(\2,(\d{4,5})\)\+(\d{4,5})&255(?:\.\d+)?,(\w+)\)/g,
    (_full, mul, mixVar, mid, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mul}*(${mixVar}*${mixVar})+${mid}(${mixVar},${quadB})+${add}&255`,
        opVar,
      );
    },
  );

  if (jsOnly) {
    if (n > 0 && !out.includes("__cfOracleHook")) {
      out = `${PREAMBLE};${out}`;
    }
    return { html: out, injected: n > 0, replacements: n, snippet };
  }

  const nonceScript = /<script([^>]*nonce="[^"]+"[^>]*)>/i;
  if (nonceScript.test(out)) {
    out = out.replace(nonceScript, `<script$1>${PREAMBLE}`);
  } else if (/<head[\s>]/i.test(out)) {
    out = out.replace(/<head([^>]*)>/i, `<head$1><script>${PREAMBLE}</script>`);
  } else {
    out = `<script>${PREAMBLE}</script>` + out;
  }
  return { html: out, injected: n > 0, replacements: n, snippet };
}

function logAfterKeyUpdate(prefix, opVar) {
  return (
    `${prefix},(globalThis.__cfT&&(globalThis.__cfT.op=${opVar}&255),` +
    `globalThis.__cfOp=globalThis.__cfOp||[],` +
    `globalThis.__cfOp.length<2500&&(globalThis.__cfOp.push({` +
    `pc:globalThis.__cfT&&globalThis.__cfT.pc,op:${opVar}&255,` +
    `key:globalThis.__cfT&&globalThis.__cfT.key,byte:globalThis.__cfT&&globalThis.__cfT.byte}),` +
    `console.debug("__cfOp",globalThis.__cfOp[globalThis.__cfOp.length-1])),${opVar})`
  );
}

function pcDeltas(ops) {
  const rows = [];
  for (let i = 1; i < ops.length; i++) {
    const a = ops[i - 1];
    const b = ops[i];
    if (a?.pc == null || b?.pc == null) continue;
    rows.push({
      pc: a.pc,
      op: a.op,
      width: b.pc - a.pc,
      key: a.key,
      byte: a.byte,
    });
  }
  return rows;
}

function isCompleteTuple(r) {
  return (
    r &&
    Number.isFinite(Number(r.pc)) &&
    Number.isFinite(Number(r.op)) &&
    Number.isFinite(Number(r.key)) &&
    Number.isFinite(Number(r.byte))
  );
}

function inferLocalOpMix(rows) {
  const names = new Set();
  for (const r of rows) {
    for (const k of Object.keys(r.locals || {})) names.add(k);
  }
  let opKey;
  let mixKey;
  for (const k of names) {
    const vals = rows.map((r) => r.locals && r.locals[k]).filter((v) => typeof v === "number");
    if (vals.length < 2) continue;
    const uniq = new Set(vals);
    if (uniq.size <= 1) continue;
    const max = Math.max(...vals);
    if (max <= 255 && opKey == null) opKey = k;
    else if (max > 255 && mixKey == null) mixKey = k;
  }
  return { opKey, mixKey };
}

function inferPcSlotFromGNums(rows) {
  if (!rows.length || !rows[0].gNums) return null;
  for (const idx of Object.keys(rows[0].gNums)) {
    const vals = rows.map((r) => r.gNums && r.gNums[idx]).filter((v) => typeof v === "number");
    if (vals.length < rows.length) continue;
    let inc = vals.length >= 2;
    for (let i = 1; i < vals.length; i++) {
      if (vals[i] <= vals[i - 1]) inc = false;
    }
    if (inc && vals[0] >= 0 && vals[0] <= 2) return Number(idx);
  }
  return null;
}

/** 56907 Chrome: pause at the mul is after `pc+=1` (first observed pcSlot 1). */
function finalizeFetchLoopRows(rows) {
  const fl = (rows || []).filter((r) => r && r.via === "fetchLoop");
  if (!fl.length) return [];
  const large = fl.filter((r) => (r.bcLen || 0) > 10000);
  const use = large.length ? large : fl;
  const { opKey, mixKey } = inferLocalOpMix(use);
  const pcFromG = inferPcSlotFromGNums(use);
  return use.map((r) => {
    let pcSlot = r.pcSlot;
    if (!Number.isFinite(pcSlot) && pcFromG != null && r.gNums && Number.isFinite(r.gNums[pcFromG])) {
      pcSlot = r.gNums[pcFromG];
    }
    const adjust = Number.isFinite(pcSlot) && pcSlot >= 1;
    const pc = Number.isFinite(pcSlot) ? (adjust ? pcSlot - 1 : pcSlot) : r.pc;
    let op = r.op;
    let mix = r.mix;
    let key = r.key;
    if (op == null && opKey && r.locals && typeof r.locals[opKey] === "number") {
      op = r.locals[opKey] & 255;
    }
    if (mix == null && mixKey && r.locals && typeof r.locals[mixKey] === "number") {
      mix = r.locals[mixKey];
    }
    if (key == null && Number.isFinite(r.keySlot)) key = r.keySlot & 255;
    if (op == null && Number.isFinite(mix) && Number.isFinite(key)) {
      op = (mix - key) & 255;
    }
    if (key == null && Number.isFinite(mix) && Number.isFinite(op)) {
      key = (mix - op) & 255;
    }
    let byte = r.byte;
    if (byte == null) {
      byte = adjust ? r.byteAtPcMinus1 : r.byteAtPc;
    }
    return {
      via: "fetchLoop",
      pc,
      op: Number.isFinite(op) ? op & 255 : undefined,
      key: Number.isFinite(key) ? key & 255 : undefined,
      byte: Number.isFinite(byte) ? byte & 255 : undefined,
      mix: Number.isFinite(mix) ? mix : undefined,
      bcLen: r.bcLen,
      pcSlot,
      byteVia: Number.isFinite(byte) ? "vm" : undefined,
    };
  });
}

function fillBytesFromPacked(rows, packedStr) {
  if (!packedStr) return rows;
  let bc;
  try {
    bc = Buffer.from(String(packedStr).replace(/\s/g, ""), "base64");
  } catch {
    return rows;
  }
  if (!bc.length) return rows;
  return (rows || []).map((r) => {
    if (!r || Number.isFinite(r.byte) || !Number.isFinite(r.pc)) return r;
    if (r.pc < 0 || r.pc >= bc.length) return r;
    return { ...r, byte: bc[r.pc], byteVia: "packed" };
  });
}

/** Breakpoint locals rotate; opcode is the 0–255 varying number, mix is often >255. */
function normalizeBreakpointOps(rows) {
  const kept = [];
  for (const r of rows || []) {
    if (!r) continue;
    if (r.via === "breakpoint" && r.op == null && r.byte == null && r.pc == null && r.mix == null) {
      continue;
    }
    kept.push(r);
  }
  const bp = kept.filter((r) => r.via === "breakpoint" && !isCompleteTuple(r));
  const keys = new Set();
  for (const r of bp) {
    for (const k of Object.keys(r)) {
      if (
        k === "via" ||
        k === "op" ||
        k === "mix" ||
        k === "key" ||
        k === "pc" ||
        k === "gLen" ||
        k === "keySlot" ||
        k === "byte" ||
        k === "bcLen" ||
        k === "pcSlot" ||
        k === "byteVia"
      ) {
        continue;
      }
      keys.add(k);
    }
  }
  let opKey;
  let mixKey;
  for (const k of keys) {
    const vals = bp.map((r) => r[k]).filter((v) => typeof v === "number");
    const uniq = new Set(vals);
    if (uniq.size <= 3 || vals.length < 4) continue;
    const max = Math.max(...vals);
    if (max <= 255 && opKey == null) opKey = k;
    else if (max > 255 && mixKey == null) mixKey = k;
  }
  return kept.map((r) => {
    if (r.via === "fetchLoop" || (r.via === "breakpoint" && isCompleteTuple(r))) {
      const row = {
        via: r.via,
        pc: r.pc,
        op: Number.isFinite(r.op) ? r.op & 255 : undefined,
        key: Number.isFinite(r.key) ? r.key & 255 : undefined,
        byte: Number.isFinite(r.byte) ? r.byte & 255 : undefined,
      };
      if (Number.isFinite(r.mix)) row.mix = r.mix;
      if (r.byteVia) row.byteVia = r.byteVia;
      if (r.bcLen) row.bcLen = r.bcLen;
      return row;
    }
    if (r.via !== "breakpoint") return r;
    const op = r.op != null ? r.op : opKey != null ? r[opKey] & 255 : undefined;
    const mix = r.mix != null ? r.mix : mixKey != null ? r[mixKey] : undefined;
    const key =
      r.key != null
        ? r.key
        : typeof op === "number" && typeof mix === "number"
          ? (mix - op) & 255
          : undefined;
    const row = { via: "breakpoint", pc: r.pc, op, mix, key };
    if (Number.isFinite(r.byte)) row.byte = r.byte & 255;
    return row;
  });
}

function widthHistogram(deltas) {
  const m = {};
  for (const row of deltas) {
    if (row.op == null) continue;
    const op = String(row.op);
    const w = String(row.width);
    m[op] = m[op] || {};
    m[op][w] = (m[op][w] || 0) + 1;
  }
  return m;
}

const CHARSET_BRANCH_B =
  "eoUfnCPsq3FtDYIAyr5hGd18az9ju+HbL-m$KJ0S24BpMQZVlvTkx6gXciW7REONw";

function uniqueAlphabet(s) {
  return [...new Set(String(s || ""))]
    .sort()
    .join("");
}

function charsetIsWellFormed(s) {
  if (!s || s.length !== 65) return false;
  const set = new Set(s);
  return (
    set.size === 65 &&
    s.includes("$") &&
    s.includes("+") &&
    s.includes("-") &&
    !s.includes("/") &&
    !s.includes("=")
  );
}

function extractCompressorCharset(html) {
  if (!html) return null;
  const re = /[`'"]([A-Za-z0-9$+\-]{65})[`'"]/g;
  let m;
  while ((m = re.exec(html))) {
    if (charsetIsWellFormed(m[1])) return m[1];
  }
  return null;
}

function charsInCharset(s, charset) {
  if (!charset || !s) return false;
  const set = new Set(charset);
  return [...String(s)].every((c) => set.has(c));
}

function classifyBodyLen(len) {
  if (len >= 3000 && len <= 5000) return "init";
  if (len >= 70000 && len <= 100000) return "followUp";
  return "other";
}

function classifyFoResponseLen(len) {
  if (len >= 700000 && len <= 950000) return "packedRunProgram";
  if (len >= 1500 && len <= 4000) return "followUpAck";
  return "other";
}

function rayFromFoUrl(u) {
  const m = String(u || "").match(/\/fo\/[^/]+\/([0-9a-fA-F]{16})\//);
  return m ? m[1].toLowerCase() : null;
}

function foBodyShape(foNet, xhr, iframeHtml) {
  const charset = extractCompressorCharset(iframeHtml || "");
  const rows = [];
  const seen = new Set();
  for (const n of [...(foNet || []), ...(xhr || [])]) {
    const prefix = String(n.bodyPrefix || "").slice(0, 24);
    const len = n.bodyLen || 0;
    if (!prefix && !len) continue;
    const key = `${len}:${prefix}`;
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push({
      bodyLen: len,
      bodyPrefix: prefix,
      prefixInCharset: charset ? charsInCharset(prefix, charset) : null,
      uniqueAlphabet: uniqueAlphabet(prefix),
      band: classifyBodyLen(len),
    });
  }
  return {
    compressorLiveName: "f4",
    compressorHistoricalName: "wZ",
    charsetLen: charset ? charset.length : 0,
    charsetUnique: charset ? new Set(charset).size : 0,
    charsetHasDollar: charset ? charset.includes("$") : false,
    charsetMatchesBranchB: charset === CHARSET_BRANCH_B,
    prefixesInCharset:
      charset && rows.length
        ? rows.every((r) => r.prefixInCharset)
        : null,
    note: "N is once per iframe so paired POSTs share a 24-char RSA prefix. Do not dump full bodies or fill init JSON.",
    rows,
  };
}

function braceEnd(js, start) {
  if (js[start] !== "{") return -1;
  let depth = 0;
  let inStr = null;
  for (let i = start; i < js.length; i++) {
    const c = js[i];
    if (inStr) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === inStr) inStr = null;
    } else if (c === '"' || c === "'" || c === "`") {
      inStr = c;
    } else if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

function quotedObjectKeys(obj) {
  const keys = [];
  const re = /"([A-Za-z][A-Za-z0-9]{1,11})":/g;
  let m;
  while ((m = re.exec(obj))) keys.push(m[1]);
  return keys;
}

function extractInitJsonKeys(html) {
  if (!html) return null;
  let search = 0;
  while (true) {
    const at = html.indexOf(":JSON[", search);
    if (at < 0) return null;
    const windowStart = Math.max(0, at - 8000);
    const prefix = html.slice(windowStart, at);
    const objRel = prefix.lastIndexOf("={");
    if (objRel >= 0) {
      const objStart = windowStart + objRel + 1;
      const objEnd = braceEnd(html, objStart);
      if (objEnd > objStart) {
        const obj = html.slice(objStart, objEnd);
        const keys = quotedObjectKeys(obj);
        const after = html.slice(objEnd, objEnd + 800);
        if (keys.length >= 40 && after.includes("setTimeout")) {
          return {
            keyCount: keys.length,
            keys,
            hasJsonStringify: obj.includes(":JSON["),
            setTimeoutNearby: true,
          };
        }
      }
    }
    search = at + 6;
  }
}

/** Key names + kinds only. `init` if the ident set is the first POST; `followUp` if VM numeric/extra keys appear. */
function looksLikeCssStyleShape(shape) {
  const ident = shape?.identKeys || [];
  if (ident.includes("alignContent") || ident.includes("webkitAlignContent")) {
    return true;
  }
  if ((shape?.numericKeyCount || 0) >= 200) return true;
  if ((shape?.keyCount || 0) > 250) return true;
  return false;
}

function classifyFoPlaintext(shape, initKeys) {
  if (!shape || !Array.isArray(shape.identKeys)) return null;
  if (looksLikeCssStyleShape(shape)) {
    return {
      kind: "other",
      via: shape.via || null,
      keyCount: shape.keyCount,
      identCount: shape.identKeys.length,
      numericKeyCount: shape.numericKeyCount || 0,
      numericKeyMin: shape.numericKeyMin ?? null,
      numericKeyMax: shape.numericKeyMax ?? null,
      copiedCount: 0,
      extraIdent: [],
      extraIdentCount: 0,
      rejected: "css-style",
    };
  }
  const initList = initKeys || [];
  const initSet = new Set(initList);
  const ident = shape.identKeys;
  const copied = ident.filter((k) => initSet.has(k));
  const extraIdent = ident.filter((k) => !initSet.has(k));
  const droppedInit = initList.filter((k) => !ident.includes(k));
  let kind = "other";
  if (initSet.size && copied.length < 40) {
    kind = "other";
  } else if ((shape.numericKeyCount || 0) > 0 && copied.length >= 40) {
    kind = "followUp";
  } else if (copied.length >= 40 && extraIdent.length === 0) {
    kind = "init";
  } else if (copied.length >= 40) {
    kind = "followUp";
  } else if (ident.length >= 40 && extraIdent.length === 0 && initSet.size === 0) {
    kind = "init";
  }
  return {
    kind,
    via: shape.via || null,
    keyCount: shape.keyCount,
    identCount: ident.length,
    numericKeyCount: shape.numericKeyCount || 0,
    numericKeyMin: shape.numericKeyMin ?? null,
    numericKeyMax: shape.numericKeyMax ?? null,
    copiedCount: copied.length,
    extraIdent,
    extraIdentCount: extraIdent.length,
    droppedInit,
    droppedInitCount: droppedInit.length,
  };
}

function pickFollowUpShape(shapes, initKeys) {
  const rows = (shapes || [])
    .map((s) => ({ shape: s, cls: classifyFoPlaintext(s, initKeys) }))
    .filter((r) => r.cls && r.cls.kind === "followUp");
  if (!rows.length) return null;
  // Prefer the mutated VM object (numeric slots), not the early 47+1 extra snapshot.
  rows.sort((a, b) => {
    const numeric = (b.cls.numericKeyCount || 0) - (a.cls.numericKeyCount || 0);
    if (numeric) return numeric;
    const extra = (b.cls.extraIdentCount || 0) - (a.cls.extraIdentCount || 0);
    if (extra) return extra;
    return (b.cls.copiedCount || 0) - (a.cls.copiedCount || 0);
  });
  const best = rows[0];
  const kinds = best.shape.kinds || {};
  const extraIdentKinds = {};
  for (const k of best.cls.extraIdent || []) {
    if (kinds[k]) extraIdentKinds[k] = kinds[k].split(":")[0];
  }
  const numericKinds = {};
  let nKindMin = null;
  let nKindMax = null;
  let numericSlotKind = null;
  for (const k of Object.keys(kinds)) {
    if (!/^\d+$/.test(k)) continue;
    numericKinds[k] = kinds[k];
    const head = String(kinds[k]).split(":")[0];
    if (!numericSlotKind) numericSlotKind = head;
    const colon = String(kinds[k]).indexOf(":");
    if (colon >= 0) {
      const n = Number(String(kinds[k]).slice(colon + 1));
      if (Number.isFinite(n)) {
        if (nKindMin == null || n < nKindMin) nKindMin = n;
        if (nKindMax == null || n > nKindMax) nKindMax = n;
      }
    }
  }
  return {
    ...best.cls,
    identKeys: best.shape.identKeys,
    extraIdentKinds,
    numericKinds,
    numericSlotKind,
    numericSlotKeyCountMin: nKindMin,
    numericSlotKeyCountMax: nKindMax,
  };
}

function classifyLeftoverOpcode(op) {
  if (op === 177) return { handler: "XU", writePath: "host_xi" };
  if (op === 226) return { handler: "gC", writePath: "bytecode_string" };
  if (op === 227) return { handler: "gG", writePath: "property_set" };
  if (op === 169) return { handler: "ge", writePath: "property_set" };
  if (op === 138) return { handler: "gN", writePath: "property_set" };
  return { handler: null, writePath: "unseen_in_dumps" };
}

const LEFTOVER_UNSEEN_NAMES = [
  "OQbM0", "UjLjP6", "YfDjo7", "Iqrc9", "OZgbm6", "pFyv1", "SfUI1", "sqKXG6",
  "HUDi4", "DTBF3", "mQiic7", "gNcr3",
];

function leftoverProbeSummary(writes, extraIdent) {
  const byKey = {};
  for (const w of writes || []) {
    if (w && w.key != null && !byKey[w.key]) byKey[w.key] = w;
  }
  const leftoverHits = [];
  for (const n of LEFTOVER_UNSEEN_NAMES) {
    const row = byKey[n];
    if (!row) continue;
    leftoverHits.push({
      name: n,
      ...classifyLeftoverOpcode(row.opcode),
      opcode: row.opcode == null ? null : row.opcode,
      via: row.via || null,
      valueKind: row.valueKind || null,
      pc: row.pc == null ? null : row.pc,
    });
  }
  const extraNow = extraIdent || [];
  const namesRotated =
    leftoverHits.length === 0 &&
    extraNow.length > 0 &&
    LEFTOVER_UNSEEN_NAMES.every((n) => extraNow.indexOf(n) < 0);
  const numericWrites = (writes || []).filter((w) => w && w.numeric);
  const numericOpcodes = [
    ...new Set(numericWrites.map((w) => w.opcode).filter((o) => o != null)),
  ];
  const extraWrites = (writes || []).filter(
    (w) => w && !w.numeric && w.key !== "MaOkK2",
  );
  const extraOpcodes = [
    ...new Set(extraWrites.map((w) => w.opcode).filter((o) => o != null)),
  ];
  return {
    status: leftoverHits.length || extraWrites.length || numericWrites.length
      ? "ran"
      : extraNow.some((n) => LEFTOVER_UNSEEN_NAMES.indexOf(n) >= 0)
        ? "f4-inferred"
        : "empty",
    writeCount: (writes || []).length,
    leftoverHits,
    leftoverHitCount: leftoverHits.length,
    namesRotated,
    numericWriteCount: numericWrites.length,
    numericOpcodes,
    extraOpcodes,
    extraIdentNow: extraNow,
    note: "kinds and opcodes only; do not dump values or POST",
  };
}

function sourceLineCol(scriptSource, idx) {
  const pre = scriptSource.slice(0, idx);
  const lineNumber = (pre.match(/\n/g) || []).length;
  const nl = pre.lastIndexOf("\n");
  const columnNumber = nl < 0 ? pre.length : pre.length - nl - 1;
  return { lineNumber, columnNumber };
}

function compressorBreakpointAt(scriptSource) {
  for (const pat of [
    "function f4(",
    "function wZ(",
    "f4=function(",
    "wZ=function(",
  ]) {
    const idx = scriptSource.indexOf(pat);
    if (idx < 0) continue;
    const brace = scriptSource.indexOf("{", idx);
    if (brace < 0) continue;
    return { ...sourceLineCol(scriptSource, brace), pat, idx };
  }
  return null;
}

function sendHelperBreakpointAt(scriptSource) {
  const m =
    scriptSource.match(/setTimeout,(\w+),100/) ||
    scriptSource.match(/setTimeout\((\w+),100/);
  const name = m && m[1];
  if (!name || name === "function") return null;
  const pat = `function ${name}(`;
  const idx = scriptSource.indexOf(pat);
  if (idx < 0) return null;
  const brace = scriptSource.indexOf("{", idx);
  if (brace < 0) return null;
  return { ...sourceLineCol(scriptSource, brace), pat, idx, name };
}

const TUPLE_HARVEST_EXPR = `(function() {
  const g = this && this.g;
  const thisNums = {};
  if (this) {
    const names = ["i","j","l","h","o","u","n","m","k","p"];
    for (let n = 0; n < names.length; n++) {
      const k = names[n];
      if (typeof this[k] === "number") thisNums[k] = this[k];
    }
  }
  let pcSlot;
  let keySlot;
  let bc;
  if (g && typeof this.j === "number") pcSlot = g[this.j];
  if (g && typeof this.i === "number") keySlot = g[this.i];
  if (g && typeof this.l === "number" && g[this.l] && typeof g[this.l].length === "number") {
    bc = g[this.l];
  }
  if (!bc && g) {
    for (let i = 0; i < Math.min(g.length || 0, 64); i++) {
      const v = g[i];
      if (v && typeof v.length === "number" && v.length > 10000 && typeof v[0] === "number") {
        bc = v;
        break;
      }
    }
  }
  const byteAt = function (p) {
    return (bc && typeof p === "number" && p >= 0 && p < bc.length) ? (bc[p] & 255) : undefined;
  };
  const gNums = {};
  if (g) {
    for (let i = 0; i < Math.min(g.length || 0, 24); i++) {
      if (typeof g[i] === "number") gNums[i] = g[i];
    }
  }
  return {
    via: "fetchLoop",
    thisType: typeof this,
    hasG: !!(g),
    pcSlot: typeof pcSlot === "number" ? pcSlot : undefined,
    keySlot: typeof keySlot === "number" ? (keySlot & 255) : undefined,
    gLen: g && g.length,
    bcLen: bc && bc.length,
    byteAtPc: byteAt(pcSlot),
    byteAtPcMinus1: typeof pcSlot === "number" ? byteAt(pcSlot - 1) : undefined,
    thisNums: thisNums,
    gNums: gNums
  };
}).call(this)`;

const FO_SHAPE_EXPR = `(() => {
  function kind(v) {
    if (v === null) return "null";
    if (Array.isArray(v)) return "array:" + v.length;
    const t = typeof v;
    if (t === "string") return "string:" + v.length;
    if (t === "object") return "object:" + Object.keys(v).length;
    return t;
  }
  function shape(obj, via) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
    const keys = Object.keys(obj);
    if (keys.length < 20 || keys.length > 250) return null;
    if (keys.indexOf("alignContent") >= 0 && keys.indexOf("webkitAlignContent") >= 0) {
      return null;
    }
    const ident = [];
    const numeric = [];
    const kinds = {};
    let nMin = null;
    let nMax = null;
    for (const k of keys) {
      kinds[k] = kind(obj[k]);
      if (/^\\d+$/.test(k)) {
        numeric.push(k);
        const n = Number(k);
        if (nMin === null || n < nMin) nMin = n;
        if (nMax === null || n > nMax) nMax = n;
      } else ident.push(k);
    }
    return {
      via,
      keyCount: keys.length,
      identKeys: ident,
      numericKeyCount: numeric.length,
      numericKeyMin: nMin,
      numericKeyMax: nMax,
      kinds,
    };
  }
  try {
    if (typeof arguments !== "undefined") {
      for (let i = 0; i < Math.min(arguments.length, 4); i++) {
        const s = shape(arguments[i], "f4");
        if (s) {
          try {
            s.writes = (globalThis.__cfWrites || []).slice(0, 80);
            if ((s.numericKeyCount || 0) === 0 && typeof globalThis.__cfInstallWatch === "function") {
              const obj = arguments[i];
              setTimeout(function () {
                try { globalThis.__cfInstallWatch(obj); } catch (e3) {}
              }, 0);
            }
          } catch (e2) {}
          return s;
        }
      }
    }
  } catch (e) {}
  try {
    if (typeof a !== "undefined") {
      const s = shape(a, "f4");
      if (s) {
        try {
          s.writes = (globalThis.__cfWrites || []).slice(0, 80);
          if ((s.numericKeyCount || 0) === 0 && typeof globalThis.__cfInstallWatch === "function") {
            setTimeout(function () {
              try { globalThis.__cfInstallWatch(a); } catch (e3) {}
            }, 0);
          }
        } catch (e2) {}
        return s;
      }
    }
  } catch (e) {}
  return null;
})()`;

function foPostPairs(foNet) {
  const byUrl = new Map();
  for (const n of foNet) {
    const u = n.url || "";
    if (!byUrl.has(u)) byUrl.set(u, []);
    byUrl.get(u).push(n);
  }
  return [...byUrl.values()]
    .filter((g) => g.length >= 2)
    .map((g) => ({
      urlTail: (g[0].url || "").split("/fo/")[1] || "",
      posts: g.map((n) => {
        const h = headerBag(n);
        return {
          status: n.status,
          bodyLen: n.bodyLen,
          bodyPrefix: n.bodyPrefix,
          cfChl: h["cf-chl"] ? "present" : null,
          cfChlRa: h["cf-chl-ra"] || null,
          priority: h.priority || null,
        };
      }),
      sameUrl: true,
      samePrefix: g.every((n) => n.bodyPrefix === g[0].bodyPrefix),
    }));
}

function foFollowUpShape(foNet, xhr) {
  const pairs = foPostPairs(foNet || []);
  const rows = [];
  for (const p of pairs) {
    const init = (p.posts || []).find((x) => classifyBodyLen(x.bodyLen) === "init");
    const fu = (p.posts || []).find((x) => classifyBodyLen(x.bodyLen) === "followUp");
    if (!init || !fu) continue;
    const xhrInit = (xhr || []).find(
      (x) => x.bodyLen === init.bodyLen && x.bodyPrefix === init.bodyPrefix,
    );
    const xhrFu = (xhr || []).find(
      (x) => x.bodyLen === fu.bodyLen && x.bodyPrefix === fu.bodyPrefix,
    );
    rows.push({
      initLen: init.bodyLen,
      followUpLen: fu.bodyLen,
      samePrefix: p.samePrefix,
      cfChlRa: fu.cfChlRa || "0",
      initRespLen: xhrInit?.respLen || null,
      initRespBand: xhrInit?.respLen
        ? classifyFoResponseLen(xhrInit.respLen)
        : null,
      followUpRespLen: xhrFu?.respLen || null,
      followUpRespBand: xhrFu?.respLen
        ? classifyFoResponseLen(xhrFu.respLen)
        : null,
    });
  }
  return {
    compressorLiveName: "f4",
    sendHelper: "fz",
    sameNWrapper: true,
    plaintextKind: "compressed_blob_after_runProgram",
    notPackedProgram: true,
    sentAfterRunProgram: true,
    pairCount: rows.length,
    note: "shape only; same f4/N wrapper; do not reconstruct or POST the plaintext",
    rows,
  };
}

function selfTestInject() {
  const happyOld =
    "if(E=hy[hH],E!==E)return hy[hw];switch(hy[hH]=E+1,E=hy[hY]^G[A1(I2.L)](hj[E],37)+256&255,hy[hY]=G[A1(I2.hC)](hy[hY]+E,36163)+38392&255.07,E){case 8:dN(this);break;}";
  const happyLive =
    "if(o=fM[fs],o!==o)return fM[fa];switch(fM[fs]=fh[FI(cE.fu)](o,1),o=fM[fu]^fh[FI(cE.fV)](219+fd[o],255),fM[fu]=fh[FI(cE.l)]((fM[fu]+o)*36163+38392,255),o){case 8:Cf(this);break;}";
  const catchLive =
    "if(fJ=fM[fs],fJ!==fJ)return fM[fa];switch(fM[fs]=fh[FI(cE.fx)](fJ,1),fS=fh[FI(cE.GU)](fM[fu],x),fM[fu]=fh[FI(cE.Gl)](fh[FI(cE.Go)](fM[fu],fS),36163)+38392&255.41,fS){case 8:Cf(this);break;}";
  const happyQuad =
    "if(Xt=Xw[XQ],Xt!==Xt)return Xw[XY];switch(Xw[XQ]=Xm[dH(ik.A)](Xt,1),Xt=Xw[Xo]^3+XS[Xt]&255.25,XM=Xw[Xo]+Xt,Xw[Xo]=Xm[dH(ik.XQ)](Xm[dH(ik.Xo)](XM*XM,56907),7914*XM)+22357&255,Xt){case 222:Xf(this);break;}";
  const catchQuad =
    "if(XZ=Xw[XQ],XZ!==XZ)return Xw[XY];switch(Xw[XQ]=XZ+1,Xl=Xm[dH(ik.Xt)](Xw[Xo],Xm[dH(ik.aW)](Xm[dH(ik.ah)](XS[XZ],253),256)&255.37),XG=Xw[Xo]+Xl,Xw[Xo]=Xm[dH(ik.Xm)](Xm[dH(ik.aE)](Xm[dH(ik.aE)](XG,XG),56907)+7914*XG+22357,255),Xl){case 222:Xf(this);break;}";
  const happyMulSq =
    "if(A=sP[sU],sJ[AQ(ku.sg)](A,A))return sP[sW];switch(sP[sU]=sJ[AQ(ku.A)](A,1),A=sP[sv]^sJ[AQ(ku.D)](sJ[AQ(ku.sp)](sg[A],253),256)&255.1,D=sJ[AQ(ku.sn)](sP[sv],A),sP[sv]=sJ[AQ(ku.sJ)](56907*(D*D),sJ[AQ(ku.sG)](D,7914))+22357&255.37,A){case 222:Xf(this);break;}";
  const happyLin28814 =
    "if(X=BO[Bl],X!==X)return BO[Ba];switch(BO[Bl]=X+1,X=Bv[jP(x7.j)](BO[Bp],Bv[jP(x7.X)](239+Bb[X],255)),BO[Bp]=Bv[jP(x7.Bb)](Bv[jP(x7.e)](BO[Bp],X)*28814,40641)&255.89,X){case 165:Ib(this);break;}";
  const catchLin28814 =
    "if(BY=BO[Bl],BY!==BY)return BO[Ba];switch(BO[Bl]=BY+1,Bh=Bv[jP(x7.Zg)](BO[Bp],Bv[jP(x7.Bv)](Bb[BY],17)+256&255.72),BO[Bp]=Bv[jP(x7.Zr)](BO[Bp],Bh)*28814+40641&255,Bh){case 165:Ib(this);break;}";
  const happyEve8904 =
    "if(D=aP[aQ],D!==D)return aP[aW];switch(aP[aQ]=D+1,D=aP[af]^au[EO(oV.E)](ae[D]-232,256)&255,I=aP[af]+D,aP[af]=au[EO(oV.D)](au[EO(oV.E)](I*I*8904,au[EO(oV.I)](I,14792))+11229,255),D){case 113:q7[EO(oV.af)](this);break;}";
  const catchEve8904 =
    "if(ag=aP[aQ],ag!==ag)return aP[aW];switch(aP[aQ]=au[EO(oV.E)](ag,1),aJ=au[EO(oV.i)](aP[af],au[EO(oV.E)](ae[ag]-232,256)&255),aO=au[EO(oV.XY)](aP[af],aJ),aP[af]=au[EO(oV.XC)](8904*(aO*aO)+au[EO(oV.I)](aO,14792),11229)&255,aJ){case 113:q7[EO(oV.XK)](this);break;}";
  const happyLin31579 =
    "if(D=Qg[QO],D!==D)return Qg[QV];switch(Qg[QO]=Qs[m1(pj.QZ)](D,1),D=Qs[m1(pj.QN)](Qg[QZ],Qs[m1(pj.i)](Qy[D],113)+256&255),Qg[QZ]=Qs[m1(pj.QZ)](Qs[m1(pj.QZ)](Qg[QZ],D)*31579,59205)&255,D){case 104:Yb[m1(pj.Qy)](this);break;}";
  const catchLin31579 =
    "if(QK=Qg[QO],QK!==QK)return Qg[QV];switch(Qg[QO]=Qs[m1(pj.QZ)](QK,1),Qv=Qs[m1(pj.Qx)](Qg[QZ],Qs[m1(pj.jW)](Qs[m1(pj.m)](Qy[QK]-113,256),255)),Qg[QZ]=Qs[m1(pj.jd)](Qs[m1(pj.QU)](Qg[QZ]+Qv,31579),59205)&255.46,Qv){case 104:Yb[m1(pj.Qo)](this);break;}";
  const happyLin31579Plus =
    "if(D=Qg[QO],D!==D)return Qg[QV];switch(Qg[QO]=Qs[m0(pO.m)](D,1),D=Qg[QZ]^Qs[m0(pO.a)](Qs[m0(pO.QO)](Qy[D],113)+256,255),Qg[QZ]=Qs[m0(pO.D)](Qs[m0(pO.I)](Qg[QZ],D),31579)+59205&255.37,D){case 104:Yb[m0(pO.QZ)](this);break;}";
  const happy39695 =
    "if(oR=od[oq],oV[UP(Wd.hv)](oR,oR))return od[oj];switch(od[oq]=oR+1,oF=od[oQ]^oV[UP(Wd.oj)](oy[oR],133)+256&255,ok=od[oQ]+oF,od[oQ]=oV[UP(Wd.hc)](ok*ok*39695+oV[UP(Wd.hH)](ok,3159)+64171,255),oF){case 79:f9(this);break;}";
  const catch39695 =
    "if(H=od[oq],H!==H)return od[oj];switch(od[oq]=H+1,H=oV[UP(Wd.om)](od[oQ],oV[UP(Wd.ou)](oV[UP(Wd.oj)](oy[H],133)+256,255)),C=od[oQ]+H,od[oQ]=oV[UP(Wd.oG)](oV[UP(Wd.oV)](39695*(C*C),C*3159)+64171,255),H){case 79:f9(this);break;}";
  const a = injectOpcodeLog(happyOld);
  const b = injectOpcodeLog(happyLive);
  const c = injectOpcodeLog(catchLive);
  const d = injectOpcodeLog(happyQuad);
  const e = injectOpcodeLog(catchQuad);
  const f = injectOpcodeLog(happyMulSq);
  const linHappy = injectOpcodeLog(happyLin28814);
  const linCatch = injectOpcodeLog(catchLin28814);
  const eveHappy = injectOpcodeLog(happyEve8904);
  const eveCatch = injectOpcodeLog(catchEve8904);
  const lin31579H = injectOpcodeLog(happyLin31579);
  const lin31579C = injectOpcodeLog(catchLin31579);
  const lin31579F = extractFetchLinear(happyLin31579);
  const lin31579Plus = injectOpcodeLog(happyLin31579Plus);
  const lin31579PlusF = extractFetchLinear(happyLin31579Plus);
  const q39695H = injectOpcodeLog(happy39695);
  const q39695C = injectOpcodeLog(catch39695);
  const q39695F = extractFetchQuadratic(happy39695);
  const q39695Fc = extractFetchQuadratic(catch39695);
  const eveFormula = extractFetchQuadratic(happyEve8904);
  let liveEveOk = true;
  let liveEve = null;
  const liveEvePath = "artifacts/re-out/chrome-oracle-livecheck/iframe-1.html";
  if (fs.existsSync(liveEvePath)) {
    const liveHtml = fs.readFileSync(liveEvePath, "utf8");
    const liveInj = injectOpcodeLog(liveHtml);
    liveEve = {
      replacements: liveInj.replacements,
      pushed: liveInj.html.includes("__cfOp.push"),
      formula: extractFetchQuadratic(liveHtml),
    };
    liveEveOk =
      liveEve.pushed &&
      liveEve.formula &&
      liveEve.formula.keyMul === 8904 &&
      liveEve.formula.byteBias === 232;
  }
  let liveLinOk = true;
  let liveLin = null;
  const liveLinPath = "artifacts/re-out/chrome-oracle-eve8904/iframe-1.html";
  if (fs.existsSync(liveLinPath)) {
    const liveHtml = fs.readFileSync(liveLinPath, "utf8");
    const liveInj = injectOpcodeLog(liveHtml);
    liveLin = {
      replacements: liveInj.replacements,
      pushed: liveInj.html.includes("__cfOp.push"),
      formula: extractFetchSchedule(liveHtml),
    };
    liveLinOk =
      liveLin.pushed &&
      liveLin.formula &&
      liveLin.formula.keyMul === 31579 &&
      liveLin.formula.keyAdd === 59205;
  }
  const charsetHtml = `i=\`${CHARSET_BRANCH_B}\`,D=BigInt`;
  const extracted = extractCompressorCharset(charsetHtml);
  const prefixOk = charsInCharset("+6O6m5UJ8$PH0eF1Vh+4QucV", CHARSET_BRANCH_B);
  const stdReject = !charsInCharset("====hello/", CHARSET_BRANCH_B);
  const fakeKeys = [];
  for (let i = 0; i < 47; i++) fakeKeys.push(`K${i}a`);
  const fakeObj = fakeKeys
    .map((k, i) =>
      i === 17 ? `"${k}":JSON[n](x)` : `"${k}":0`,
    )
    .join(",");
  const initHtml = `Xm={${fakeObj}};setTimeout(fz,100,d,Xm)`;
  const initGot = extractInitJsonKeys(initHtml);
  const fakeInitKeys = fakeKeys;
  const fakeInitShape = {
    via: "stringify",
    keyCount: 47,
    identKeys: fakeInitKeys,
    numericKeyCount: 0,
  };
  const fakeFoShape = {
    via: "f4",
    keyCount: 47 + 12 + 3,
    identKeys: [...fakeInitKeys, "extraA", "extraB", "extraC"],
    numericKeyCount: 12,
    numericKeyMin: 1,
    numericKeyMax: 12,
  };
  const earlyExtraOnly = {
    via: "f4",
    keyCount: 48,
    identKeys: [...fakeInitKeys, "xBCsP4"],
    numericKeyCount: 0,
  };
  const richFollowUp = {
    via: "f4",
    keyCount: 46 + 14 + 39,
    identKeys: [...fakeInitKeys.slice(0, 46), "SMrTl9", "OQbM0", "xBCsP4"],
    numericKeyCount: 39,
    numericKeyMin: 1,
    numericKeyMax: 39,
  };
  const initCls = classifyFoPlaintext(fakeInitShape, fakeInitKeys);
  const foCls = classifyFoPlaintext(fakeFoShape, fakeInitKeys);
  const picked = pickFollowUpShape(
    [fakeInitShape, earlyExtraOnly, richFollowUp, fakeFoShape],
    fakeInitKeys,
  );
  const bp = compressorBreakpointAt(
    "void 0;function f4(a,Et,nT,n,d){return Et={a:1},a}",
  );
  const sendBp = sendHelperBreakpointAt(
    "Z(setTimeout,Q,100,j,V);function Q(Z,c,j){if(u6={Z:1},c)return c}",
  );
  const cssShape = {
    via: "stringify",
    keyCount: 1150,
    identKeys: ["alignContent", "webkitAlignContent", "color"],
    numericKeyCount: 456,
    numericKeyMin: 0,
    numericKeyMax: 455,
  };
  const cssCls = classifyFoPlaintext(cssShape, fakeInitKeys);
  const cssPicked = pickFollowUpShape([cssShape, fakeInitShape], fakeInitKeys);
  const leftoverHit = leftoverProbeSummary(
    [{ key: "OQbM0", opcode: 227, via: "set", valueKind: "undefined", pc: 12 }],
    ["OQbM0"],
  );
  const leftoverRotated = leftoverProbeSummary(
    [{ key: "zzNew1", opcode: 177, via: "set", valueKind: "number", numeric: false }],
    ["zzNew1"],
  );
  const live23196Happy =
    "if(K=zV[zh],K!==K)return zV[zM];switch(zV[zh]=zF[Ef(pe.K)](K,1),K=zV[zs]^zF[Ef(pe.zA)](39+zD[K],255),Q=zV[zs]+K,zV[zs]=zF[Ef(pe.zW)](zF[Ef(pe.zR)](zF[Ef(pe.zx)](zF[Ef(pe.zV)](Q,Q),23196),zF[Ef(pe.zI)](Q,32619))+19372,255),K){case 220:Po(this);break;}";
  const live23196Catch =
    "if(zA=zV[zh],zF[Ef(pe.zs)](zA,zA))return zV[zM];switch(zV[zh]=zF[Ef(pe.vb)](zA,1),zW=zV[zs]^zF[Ef(pe.zZ)](zD[zA]-217,256)&255.61,zR=zV[zs]+zW,zV[zs]=zF[Ef(pe.zA)](zF[Ef(pe.zD)](zR,zR)*23196+zR*32619+19372,255),zW){case 220:Po(this);break;}";
  const live23196H = injectOpcodeLog(live23196Happy, { jsOnly: true });
  const live23196C = injectOpcodeLog(live23196Catch, { jsOnly: true });
  const live23196F = extractFetchQuadratic(live23196Happy);
  const live23196Fc = extractFetchQuadratic(live23196Catch);
  const live23196Entry = extractVmEntryKey("new PD(Y)[EP(pC.Y)](0,63,[])");
  const live23196MulSq =
    "if(V=Yh[YU],V!==V)return Yh[YX];switch(Yh[YU]=M[HJ(uz.V)](V,1),V=M[HJ(uz.YF)](Yh[YA],M[HJ(uz.YL)](Ym[V]-217,256)&255),H=Yh[YA]+V,Yh[YA]=23196*(H*H)+M[HJ(uz.YX)](H,32619)+19372&255.87,V){case 220:Jj(this);break;}";
  const live23196MulSqF = extractFetchQuadratic(live23196MulSq);
  const live23196MulSqI = injectOpcodeLog(live23196MulSq, { jsOnly: true });
  const live23196Sites = fetchLoopBreakpointSites(
    live23196MulSq,
    live23196MulSq.indexOf("23196"),
  );
  const packed2Snippet =
    "new HC(H)(0,63,[]);if(Q=zD[K],Q!==Q)return zD[R];switch(zD[K]=Q+1,Q=zD[k]^xx(zD[Q],217)+256&255,M=zD[k]+Q,zD[k]=M*M*23196+yy(M,32619)+19372&255,Q){case 220:fn(this);break;}";
  const packed2Mark = fetchMarkerInSource(packed2Snippet);
  const packed2Sched = extractFetchQuadratic(packed2Snippet);
  const packed2Entry = extractVmEntryKey(packed2Snippet);
  const svg8904 = fetchMarkerInSource('width="8904" height="12"');
  const fin = finalizeFetchLoopRows([
    {
      via: "fetchLoop",
      pcSlot: 1,
      op: 220,
      keySlot: 63,
      mix: 283,
      byteAtPcMinus1: 77,
      bcLen: 50000,
    },
  ]);
  const filled = fillBytesFromPacked(
    [{ via: "fetchLoop", pc: 0, op: 1, key: 2 }],
    Buffer.from([9, 8, 7]).toString("base64"),
  );
  const droppedShell = normalizeBreakpointOps([{ via: "breakpoint" }]);
  return {
    ok:
      a.injected &&
      b.injected &&
      c.injected &&
      d.injected &&
      e.injected &&
      f.injected &&
      a.html.includes("__cfOp.push") &&
      b.html.includes("__cfOp.push") &&
      c.html.includes("__cfOp.push") &&
      d.html.includes("__cfOp.push") &&
      e.html.includes("__cfOp.push") &&
      f.html.includes("__cfOp.push") &&
      a.html.includes("pc:E") &&
      b.html.includes("pc:o") &&
      c.html.includes("pc:fJ") &&
      d.html.includes("pc:Xt") &&
      e.html.includes("pc:XZ") &&
      f.html.includes("pc:A") &&
      a.replacements >= 2 &&
      b.replacements >= 2 &&
      c.replacements >= 2 &&
      d.replacements >= 3 &&
      e.replacements >= 3 &&
      f.replacements >= 2 &&
      linHappy.injected &&
      linCatch.injected &&
      linHappy.html.includes("__cfOp.push") &&
      linCatch.html.includes("__cfOp.push") &&
      linHappy.html.includes("pc:X") &&
      linCatch.html.includes("pc:BY") &&
      eveHappy.injected &&
      eveCatch.injected &&
      eveHappy.html.includes("__cfOp.push") &&
      eveCatch.html.includes("__cfOp.push") &&
      eveHappy.html.includes("pc:D") &&
      eveCatch.html.includes("pc:ag") &&
      eveFormula &&
      eveFormula.keyMul === 8904 &&
      eveFormula.keyQuadB === 14792 &&
      eveFormula.keyAdd === 11229 &&
      eveFormula.byteBias === 232 &&
      eveFormula.firstSwitchCase === 113 &&
      lin31579H.html.includes("__cfOp.push") &&
      lin31579C.html.includes("__cfOp.push") &&
      lin31579H.html.includes("pc:D") &&
      lin31579C.html.includes("pc:QK") &&
      lin31579F &&
      lin31579F.keyMul === 31579 &&
      lin31579F.keyAdd === 59205 &&
      lin31579F.byteBias === 113 &&
      lin31579F.firstSwitchCase === 104 &&
      lin31579Plus.html.includes("__cfOp.push") &&
      lin31579PlusF &&
      lin31579PlusF.keyMul === 31579 &&
      lin31579PlusF.keyAdd === 59205 &&
      lin31579PlusF.spelling === "mul)+add&255" &&
      q39695H.html.includes("__cfOp.push") &&
      q39695C.html.includes("__cfOp.push") &&
      q39695F &&
      q39695F.keyMul === 39695 &&
      q39695F.keyQuadB === 3159 &&
      q39695F.keyAdd === 64171 &&
      q39695Fc &&
      q39695Fc.keyMul === 39695 &&
      liveEveOk &&
      liveLinOk &&
      extracted === CHARSET_BRANCH_B &&
      prefixOk &&
      stdReject &&
      classifyBodyLen(3735) === "init" &&
      classifyBodyLen(86882) === "followUp" &&
      classifyFoResponseLen(845928) === "packedRunProgram" &&
      classifyFoResponseLen(2400) === "followUpAck" &&
      initGot &&
      initGot.keyCount === 47 &&
      initCls &&
      initCls.kind === "init" &&
      foCls &&
      foCls.kind === "followUp" &&
      foCls.copiedCount === 47 &&
      foCls.extraIdentCount === 3 &&
      picked &&
      picked.kind === "followUp" &&
      picked.numericKeyCount === 39 &&
      picked.droppedInitCount === 1 &&
      bp &&
      bp.pat === "function f4(" &&
      sendBp &&
      sendBp.name === "Q" &&
      cssCls &&
      cssCls.kind === "other" &&
      cssPicked == null &&
      CHROME_ARGS.includes("--disable-site-isolation-trials") &&
      PREAMBLE.includes("rpMutate") &&
      PREAMBLE.includes("setTimeout") &&
      PREAMBLE.includes("__cfWrites") &&
      PREAMBLE.includes("__cfInstallWatch") &&
      leftoverHit.leftoverHitCount === 1 &&
      leftoverHit.leftoverHits[0].writePath === "property_set" &&
      leftoverHit.leftoverHits[0].opcode === 227 &&
      leftoverRotated.namesRotated === true &&
      leftoverRotated.extraOpcodes[0] === 177 &&
      classifyLeftoverOpcode(226).writePath === "bytecode_string" &&
      classifyLeftoverOpcode(177).writePath === "host_xi" &&
      skipIframeRewrite === false &&
      fetchTuples === false &&
      wantFetchLoopBp === false &&
      packed2Mark &&
      packed2Mark.marker === "23196" &&
      packed2Sched &&
      packed2Sched.keyMul === 23196 &&
      packed2Sched.keyQuadB === 32619 &&
      packed2Sched.keyAdd === 19372 &&
      packed2Sched.byteBias === 217 &&
      packed2Sched.firstSwitchCase === 220 &&
      packed2Entry === 63 &&
      live23196H.html.includes("__cfOp.push") &&
      live23196C.html.includes("__cfOp.push") &&
      live23196F &&
      live23196F.keyMul === 23196 &&
      live23196F.keyQuadB === 32619 &&
      live23196F.keyAdd === 19372 &&
      live23196F.byteBias === 217 &&
      live23196Fc &&
      live23196Fc.keyMul === 23196 &&
      live23196MulSqF &&
      live23196MulSqF.keyMul === 23196 &&
      live23196MulSqF.keyQuadB === 32619 &&
      live23196MulSqF.keyAdd === 19372 &&
      live23196MulSqF.byteBias === 217 &&
      live23196MulSqI.html.includes("__cfOp.push") &&
      live23196Sites.some((x) => x.why === "case") &&
      live23196Sites.some((x) => x.why === "switch") &&
      svg8904 == null &&
      fin[0] &&
      fin[0].pc === 0 &&
      fin[0].op === 220 &&
      fin[0].key === 63 &&
      fin[0].byte === 77 &&
      filled[0] &&
      filled[0].byte === 9 &&
      filled[0].byteVia === "packed" &&
      droppedShell.length === 0 &&
      rayFromFoUrl(
        "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/fo/907568659:1:x/a2ee5624d969f508/ch",
      ) === "a2ee5624d969f508" &&
      rayFromFoUrl("https://example.com/") === null,
    happyOld: { replacements: a.replacements, injected: a.injected },
    happyLive: { replacements: b.replacements, injected: b.injected },
    catchLive: { replacements: c.replacements, injected: c.injected },
    happyQuad: { replacements: d.replacements, injected: d.injected },
    catchQuad: { replacements: e.replacements, injected: e.injected },
    happyMulSq: { replacements: f.replacements, injected: f.injected },
    lin28814: {
      happy: { replacements: linHappy.replacements, injected: linHappy.injected },
      catch: { replacements: linCatch.replacements, injected: linCatch.injected },
    },
    eve8904: {
      happy: { replacements: eveHappy.replacements, injected: eveHappy.injected },
      catch: { replacements: eveCatch.replacements, injected: eveCatch.injected },
      formula: eveFormula,
    },
    liveEve8904: liveEve,
    lin31579: {
      happy: { replacements: lin31579H.replacements, injected: lin31579H.injected },
      catch: { replacements: lin31579C.replacements, injected: lin31579C.injected },
      formula: lin31579F,
    },
    liveLin31579: liveLin,
    charset: { extracted, prefixOk, stdReject },
    initJson: initGot && { keyCount: initGot.keyCount },
    foPlaintext: {
      initKind: initCls && initCls.kind,
      followUpKind: foCls && foCls.kind,
      copiedCount: foCls && foCls.copiedCount,
      extraIdentCount: foCls && foCls.extraIdentCount,
      pickedNumeric: picked && picked.numericKeyCount,
      compressorBp: bp && bp.pat,
      sendHelperBp: sendBp && sendBp.name,
      cssRejected: cssCls && cssCls.kind,
    },
    fetchDetect: {
      marker: packed2Mark && packed2Mark.marker,
      keyMul: packed2Sched && packed2Sched.keyMul,
      initKeyCandidate: packed2Entry,
      svgRejected: svg8904 == null,
      finalizePc: fin[0] && fin[0].pc,
    },
  };
}

if (selfTest) {
  const r = selfTestInject();
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ok ? 0 : 1);
}

function interestingUrl(u) {
  return /challenge-platform|turnstile|\/fo\/|challenges\.cloudflare\.com/.test(u || "");
}

function redactedPost(rec) {
  const post = rec.postData || "";
  return {
    ...rec,
    postData: undefined,
    bodyLen: post.length || rec.bodyLen || 0,
    bodyPrefix: (post || rec.bodyPrefix || "").slice(0, 24),
  };
}

const events = [];
const network = [];
const pending = new Map();
const cdpSessions = [];
const liveOps = [];
const liveFo = [];
const liveWrites = [];
const liveFetchRaw = [];
const compressorBreakpoints = new Set();
const compressorScripts = new Set();
const fetchLoopBreakpoints = new Set();
const fetchLoopBpRows = [];
const scriptNotes = [];
let iframeRewrites = 0;
let foInitResponse = null;
let fetchLoopCleared = false;

async function clearFetchLoopBreakpoints() {
  if (fetchLoopCleared) return;
  fetchLoopCleared = true;
  for (const row of fetchLoopBpRows) {
    await row.session
      .send("Debugger.removeBreakpoint", { breakpointId: row.breakpointId })
      .catch(() => {});
  }
  fetchLoopBreakpoints.clear();
  note("fetchLoopBpCleared", { cap: fetchTupleCap, harvested: liveFetchRaw.length });
}

function note(kind, payload) {
  events.push({ t: Date.now(), kind, ...payload });
}

function saveFoResponse(url, text, status, via) {
  const len = (text || "").length;
  const ray = rayFromFoUrl(url);
  const band = classifyFoResponseLen(len);
  const meta = {
    via,
    status,
    respLen: len,
    respPrefix: String(text || "").slice(0, 24),
    ray,
    band,
    urlTail: String(url || "").split("/fo/")[1] || "",
  };
  note("foResponse", meta);
  const packed =
    status === 200 && (band === "packedRunProgram" || len >= 50000);
  if (!packed || selfTest) return meta;
  if (foInitResponse?.saved) return meta;
  try {
    fs.writeFileSync(path.join(outDir, "fo-init-response.txt"), text);
    if (ray) fs.writeFileSync(path.join(outDir, "fo-init-ray.txt"), ray);
    fs.writeFileSync(
      path.join(outDir, "fo-init-response-meta.json"),
      JSON.stringify({ ...meta, saved: len }, null, 2),
    );
    meta.saved = len;
    foInitResponse = meta;
  } catch (e) {
    note("foResponseSaveErr", { error: String(e).slice(0, 160) });
  }
  return meta;
}

async function onFetchPaused(session, evt) {
  const reqUrl = evt.request?.url || "";
  const isIframeDoc =
    evt.responseStatusCode &&
    /\/turnstile\/f\//.test(reqUrl) &&
    (evt.resourceType === "Document" || evt.resourceType === "document");
  try {
    if (isIframeDoc) {
      const body = await session.send("Fetch.getResponseBody", {
        requestId: evt.requestId,
      });
      const text = body.base64Encoded
        ? Buffer.from(body.body, "base64").toString("utf8")
        : body.body;
      iframeRewrites++;
      fs.writeFileSync(
        path.join(outDir, `iframe-${iframeRewrites}.html`),
        text.slice(0, 400000),
      );
      if (skipIframeRewrite) {
        note("iframeSavedNoRewrite", {
          url: reqUrl,
          bytes: text.length,
          has56907: text.includes("56907"),
          has27076: text.includes("27076"),
          hasRunProgram: text.includes("runProgram"),
          fetchSchedule: extractFetchSchedule(text),
        });
        await session
          .send("Fetch.continueRequest", { requestId: evt.requestId })
          .catch(() => {});
        return;
      }
      const { html, injected, replacements, snippet } = injectOpcodeLog(text);
      const headers = (evt.responseHeaders || []).filter(
        (h) => !/^(content-encoding|content-length)$/i.test(h.name),
      );
      headers.push({
        name: "Content-Length",
        value: String(Buffer.byteLength(html)),
      });
      await session.send("Fetch.fulfillRequest", {
        requestId: evt.requestId,
        responseCode: evt.responseStatusCode || 200,
        responseHeaders: headers,
        body: Buffer.from(html).toString("base64"),
      });
      fs.writeFileSync(
        path.join(outDir, `iframe-rewritten-${iframeRewrites}.html`),
        html.slice(0, 400000),
      );
      if (snippet && iframeRewrites <= 2) {
        fs.writeFileSync(
          path.join(outDir, `iframe-19663-${iframeRewrites}.txt`),
          snippet,
        );
      }
      note("iframeRewrite", {
        url: reqUrl,
        injected,
        replacements,
        bytes: html.length,
        has19663: text.includes("19663"),
        has36163: text.includes("36163"),
        has56907: text.includes("56907"),
        has8904: /(?<!\d)8904(?!\d)/.test(text),
        has232: text.includes("-232"),
        fetchSchedule: extractFetchSchedule(text),
        has36376: text.includes("36376"),
        has38392: text.includes("38392"),
        hasRunProgram: text.includes("runProgram"),
        snippet,
      });
      return;
    }
    const isFo =
      evt.responseStatusCode && /\/fo\//.test(reqUrl);
    if (isFo) {
      try {
        const body = await session.send("Fetch.getResponseBody", {
          requestId: evt.requestId,
        });
        const text = body.base64Encoded
          ? Buffer.from(body.body, "base64").toString("utf8")
          : body.body;
        saveFoResponse(reqUrl, text, evt.responseStatusCode, "fetch");
      } catch (e) {
        note("foFetchBodyErr", {
          url: reqUrl.slice(0, 160),
          error: String(e).slice(0, 160),
        });
      }
      await session
        .send("Fetch.continueRequest", { requestId: evt.requestId })
        .catch(() => {});
      return;
    }
  } catch (e) {
    note("fetchRewriteErr", { url: reqUrl, error: String(e) });
  }
  await session.send("Fetch.continueRequest", { requestId: evt.requestId }).catch(() => {});
}

function wireNetwork(session, label) {
  session.on("Network.requestWillBeSent", (evt) => {
    const u = evt.request?.url || "";
    if (!interestingUrl(u) && !/\/fo\//.test(u)) return;
    pending.set(evt.requestId, {
      label,
      requestId: evt.requestId,
      url: u,
      method: evt.request.method,
      headers: evt.request.headers || {},
      postData: evt.request.postData || "",
      type: evt.type,
      wallTime: evt.wallTime,
    });
  });
  session.on("Network.requestWillBeSentExtraInfo", (evt) => {
    const rec = pending.get(evt.requestId);
    if (rec) rec.extraHeaders = evt.headers || {};
  });
  session.on("Network.responseReceived", (evt) => {
    const rec = pending.get(evt.requestId);
    if (!rec) return;
    rec.status = evt.response?.status;
    rec.mimeType = evt.response?.mimeType;
    rec.responseHeaders = evt.response?.headers || {};
  });
  session.on("Network.loadingFinished", (evt) => {
    const rec = pending.get(evt.requestId);
    if (!rec) return;
    rec.encodedDataLength = evt.encodedDataLength;
    network.push(redactedPost(rec));
    pending.delete(evt.requestId);
    const wantFo = /\/fo\//.test(rec.url || "") && rec.status === 200;
    if (!wantFo || selfTest || foInitResponse?.saved) return;
    session
      .send("Network.getResponseBody", { requestId: evt.requestId })
      .then((body) => {
        const text = body.base64Encoded
          ? Buffer.from(body.body, "base64").toString("utf8")
          : body.body;
        saveFoResponse(rec.url, text, rec.status, "network");
      })
      .catch((e) => {
        note("foRespBodyErr", {
          encoded: rec.encodedDataLength,
          error: String(e).slice(0, 160),
        });
      });
  });
}

async function patchExecutedFetchScript(session, s, scriptSource) {
  const inj = injectOpcodeLog(scriptSource, { jsOnly: true });
  if (!inj.injected) {
    note("scriptPatchSkip", {
      replacements: inj.replacements,
      url: (s.url || "").slice(0, 80),
    });
    return false;
  }
  try {
    const result = await session.send("Debugger.setScriptSource", {
      scriptId: s.scriptId,
      scriptSource: inj.html,
      allowTopFrameEditing: true,
    });
    const status = result?.status || "unknown";
    note("scriptPatched", {
      url: (s.url || "").slice(0, 140),
      replacements: inj.replacements,
      status,
      hasPush: inj.html.includes("__cfOp.push"),
    });
    return status === "Ok" || status === "Compiled" || status === "ok";
  } catch (e) {
    note("scriptPatchErr", { error: String(e).slice(0, 220) });
    return false;
  }
}

function fetchLoopBreakpointSites(src, markerIdx) {
  if (!src || markerIdx == null || markerIdx < 0) return [];
  const sites = [];
  const seen = new Set();
  const add = (idx, why) => {
    if (idx == null || idx < 0 || seen.has(idx)) return;
    seen.add(idx);
    sites.push({ idx, why, ...sourceLineCol(src, idx) });
  };
  const window = src.slice(Math.max(0, markerIdx - 400), markerIdx + 25000);
  const winStart = Math.max(0, markerIdx - 400);
  const sw = window.lastIndexOf("switch(", markerIdx - winStart);
  if (sw >= 0) add(winStart + sw, "switch");
  const iff = window.lastIndexOf("if(", markerIdx - winStart);
  if (iff >= 0) add(winStart + iff, "if");
  let from = 0;
  let n = 0;
  while (n < 80) {
    const i = window.indexOf("case ", from);
    if (i < 0) break;
    if (/^case \d+:/.test(window.slice(i, i + 12))) {
      add(winStart + i, "case");
      n++;
    }
    from = i + 5;
  }
  return sites;
}

async function setFetchLoopBreakpointNear(session, s, scriptSource, idx) {
  const sites = fetchLoopBreakpointSites(scriptSource, idx);
  const { lineNumber, columnNumber } = sourceLineCol(scriptSource, idx);
  const tries = [
    ...sites.map((site) => ({
      scriptId: s.scriptId,
      lineNumber: site.lineNumber,
      columnNumber: site.columnNumber,
      why: site.why,
    })),
    { scriptId: s.scriptId, lineNumber, columnNumber, why: "marker" },
  ];
  note("fetchLoopSites", {
    n: sites.length,
    whys: sites.map((x) => x.why).slice(0, 8),
    firstCaseCol: sites.find((x) => x.why === "case")?.columnNumber ?? null,
  });
  let placed = 0;
  for (const loc of tries) {
    if (placed >= 32) break;
    try {
      const bp = await session.send("Debugger.setBreakpoint", {
        location: {
          scriptId: loc.scriptId,
          lineNumber: loc.lineNumber,
          columnNumber: loc.columnNumber,
        },
        condition: FETCH_LOOP_BP_CONDITION,
      });
      if (bp?.breakpointId) {
        fetchLoopBreakpoints.add(bp.breakpointId);
        fetchLoopBpRows.push({ session, breakpointId: bp.breakpointId });
        placed++;
        note("fetchLoopBp", {
          url: (s.url || "").slice(0, 140),
          why: loc.why,
          lineNumber: loc.lineNumber,
          columnNumber: loc.columnNumber,
          breakpointId: bp.breakpointId,
        });
      }
    } catch (e) {
      note("bpErr", {
        error: String(e).slice(0, 180),
        why: loc.why,
        lineNumber: loc.lineNumber,
        columnNumber: loc.columnNumber,
      });
    }
  }
  return placed > 0;
}

async function attachSession(session, targetInfo, waitingForDebugger) {
  const label = `${targetInfo?.type || "?"}:${(targetInfo?.url || "").slice(0, 80)}`;
  cdpSessions.push({ session, label, type: targetInfo?.type || "?" });
  try {
    await session.send("Network.enable").catch(() => {});
    wireNetwork(session, label);
    await session
      .send("Fetch.enable", {
        patterns: [
          {
            urlPattern: "*challenges.cloudflare.com*",
            requestStage: "Response",
          },
        ],
      })
      .catch(() => {});
    session.on("Fetch.requestPaused", (evt) => {
      onFetchPaused(session, evt).catch((e) =>
        note("fetchPausedErr", { error: String(e) }),
      );
    });
    await session.send("Page.enable").catch(() => {});
    await session
      .send("Page.addScriptToEvaluateOnNewDocument", { source: PREAMBLE })
      .catch(() => {});
    await session.send("Runtime.enable").catch(() => {});
    session.on("Runtime.consoleAPICalled", (evt) => {
      const first = evt.args?.[0]?.value;
      const rec = evt.args?.[1]?.value;
      if (first === "__cfOp" && rec && liveOps.length < 400) liveOps.push(rec);
    });
    const parsedJobs = [];
    session.on("Debugger.scriptParsed", (s) => {
      parsedJobs.push(
        (async () => {
          try {
            if (scriptNotes.length < 24) {
              scriptNotes.push({
                phase: "parsed",
                url: (s.url || "").slice(0, 140),
                endLine: s.endLine,
                endColumn: s.endColumn,
              });
            }
            const huge = (s.endColumn || 0) > 8000 || (s.endLine || 0) > 30;
            if (!huge && !(s.url || "").includes("challenges.cloudflare.com")) return;
            const { scriptSource } = await session.send("Debugger.getScriptSource", {
              scriptId: s.scriptId,
            });
            const hit = fetchMarkerInSource(scriptSource);
            const compressor = compressorBreakpointAt(scriptSource);
            const sendHelper = sendHelperBreakpointAt(scriptSource);
            if (!hit && !compressor && !sendHelper) return;
            const hasInject =
              !!(hit && hit.hasInject) || scriptSource.includes("__cfOp.push");
            if (hit) {
              note("scriptFetchConst", {
                url: (s.url || "").slice(0, 140),
                len: scriptSource.length,
                hasInject,
                idx: hit.idx,
                marker: hit.marker,
                fetchSchedule: hit.schedule,
              });
              if (wantFetchLoopBp && !hasInject) {
                const patched = await patchExecutedFetchScript(session, s, scriptSource);
                if (!patched) {
                  await setFetchLoopBreakpointNear(session, s, scriptSource, hit.idx);
                }
              }
            }
            for (const bpInfo of [compressor, sendHelper]) {
              if (!bpInfo) continue;
              const tag = `${s.scriptId}:${bpInfo.pat}`;
              if (compressorScripts.has(tag)) continue;
              compressorScripts.add(tag);
              const bp = await session.send("Debugger.setBreakpoint", {
                location: {
                  scriptId: s.scriptId,
                  lineNumber: bpInfo.lineNumber,
                  columnNumber: bpInfo.columnNumber,
                },
              });
              if (bp?.breakpointId) compressorBreakpoints.add(bp.breakpointId);
              note(bpInfo.name ? "sendHelperBp" : "compressorBp", {
                url: (s.url || "").slice(0, 140),
                pat: bpInfo.pat,
                name: bpInfo.name || null,
                lineNumber: bpInfo.lineNumber,
                columnNumber: bpInfo.columnNumber,
                breakpointId: bp?.breakpointId || null,
              });
            }
          } catch (e) {
            note("bpErr", { error: String(e), url: (s.url || "").slice(0, 80) });
          }
        })(),
      );
    });
    session.on("Debugger.paused", async (evt) => {
      try {
        const frame = evt.callFrames?.[0];
        const fname = frame?.functionName || "";
        const hit = evt.hitBreakpoints || [];
        const compressorHit =
          hit.some((id) => compressorBreakpoints.has(id)) ||
          fname === "f4" ||
          fname === "wZ";
        if (compressorHit && frame && liveFo.length < 12) {
          try {
            const got = await session.send("Debugger.evaluateOnCallFrame", {
              callFrameId: frame.callFrameId,
              expression: FO_SHAPE_EXPR,
              returnByValue: true,
            });
            const v = got.result?.value;
            if (v && v.keyCount >= 20) {
              liveFo.push(v);
              if (Array.isArray(v.writes)) {
                for (const w of v.writes) {
                  if (
                    liveWrites.length < 80 &&
                    !liveWrites.some((x) => x.key === w.key && x.via === w.via)
                  ) {
                    liveWrites.push(w);
                  }
                }
              }
              note("foShape", {
                via: v.via,
                keyCount: v.keyCount,
                identCount: (v.identKeys || []).length,
                numericKeyCount: v.numericKeyCount,
              });
            }
          } catch (e) {
            note("foShapeErr", { error: String(e).slice(0, 160) });
          }
          return;
        }
        const fetchHit = hit.some((id) => fetchLoopBreakpoints.has(id));
        if (fetchHit && frame && liveFetchRaw.length < fetchTupleCap) {
          const row = { via: "fetchLoop", fn: fname };
          const frames = (evt.callFrames || []).slice(0, 6);
          row.frameNames = frames.map((f) => f.functionName || "");
          for (const fr of frames) {
            try {
              const got = await session.send("Debugger.evaluateOnCallFrame", {
                callFrameId: fr.callFrameId,
                expression: TUPLE_HARVEST_EXPR,
                returnByValue: true,
              });
              if (got.exceptionDetails) {
                row.evalEx = String(got.exceptionDetails.text || "").slice(0, 120);
                continue;
              }
              const v = got.result?.value;
              if (v && typeof v === "object" && (v.hasG || v.gLen || v.pcSlot != null)) {
                Object.assign(row, v);
                row.fn = fr.functionName || row.fn;
                break;
              }
              if (v && typeof v === "object" && row.thisType == null) {
                Object.assign(row, v);
              }
            } catch (e) {
              row.evalErr = String(e).slice(0, 120);
            }
          }
          const locals = {};
          for (const fr of frames) {
            for (const sc of fr.scopeChain || []) {
              if (!sc.object?.objectId) continue;
              try {
                const got = await session.send("Runtime.getProperties", {
                  objectId: sc.object.objectId,
                  ownProperties: true,
                });
                for (const p of got.result || []) {
                  if (p.value?.type === "number" && typeof p.value.value === "number") {
                    locals[p.name] = p.value.value;
                  }
                }
              } catch {}
            }
          }
          row.locals = locals;
          const mixHit = Object.values(locals).find((v) => v > 255 && v < 4096);
          const opCands = Object.values(locals).filter(
            (v) => v >= 0 && v <= 255 && v !== row.keySlot,
          );
          if (typeof mixHit === "number") row.mix = mixHit;
          if (opCands.length === 1) row.op = opCands[0] & 255;
          if (typeof row.A === "number") row.op = row.A & 255;
          if (typeof row.D === "number") row.mix = row.D;
          if (row.op == null && typeof row.mix === "number" && Number.isFinite(row.keySlot)) {
            row.op = (row.mix - row.keySlot) & 255;
          }
          if (row.key == null && typeof row.mix === "number" && Number.isFinite(row.op)) {
            row.key = (row.mix - row.op) & 255;
          }
          if (row.key == null && Number.isFinite(row.keySlot)) row.key = row.keySlot;
          liveFetchRaw.push(row);
          if (liveFetchRaw.length === 1 || liveFetchRaw.length === fetchTupleCap) {
            note("fetchLoopTuple", {
              n: liveFetchRaw.length,
              fn: row.fn,
              thisType: row.thisType,
              hasG: row.hasG,
              pcSlot: row.pcSlot,
              op: row.op,
              key: row.key,
              bcLen: row.bcLen,
              byteAtPcMinus1: row.byteAtPcMinus1,
              localCount: Object.keys(row.locals || locals || {}).length,
            });
          }
          if (liveFetchRaw.length >= fetchTupleCap) {
            await clearFetchLoopBreakpoints();
          }
        }
      } catch (e) {
        note("pausedErr", { error: String(e) });
      } finally {
        await session.send("Debugger.resume").catch(() => {});
      }
    });
    await session.send("Debugger.enable").catch(() => {});
    if (waitingForDebugger) {
      await new Promise((r) => setTimeout(r, 150));
    }
    await Promise.all(parsedJobs);
  } catch (e) {
    note("attachErr", { label, error: String(e) });
  } finally {
    if (waitingForDebugger) {
      await session.send("Runtime.runIfWaitingForDebugger").catch(() => {});
    }
  }
}

const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: headed ? false : "new",
  dumpio: false,
  defaultViewport: { width: 1920, height: 1080 },
  args: CHROME_ARGS,
});

const page = await browser.newPage();
await page.setViewport({ width: 1920, height: 1080 });
const main = await page.createCDPSession();
const connection = main.connection();

try {
  await main.send("Target.setAutoAttach", {
    autoAttach: true,
    waitForDebuggerOnStart: true,
    flatten: true,
    filter: [{ type: "page" }, { type: "iframe" }, { type: "worker" }],
  });
} catch {
  await main.send("Target.setAutoAttach", {
    autoAttach: true,
    waitForDebuggerOnStart: true,
    flatten: true,
  });
}

function onAttachedToTarget(evt) {
  const child = connection.session(evt.sessionId);
  if (!child) {
    note("noChildSession", { sessionId: evt.sessionId, url: evt.targetInfo?.url });
    return;
  }
  attachSession(child, evt.targetInfo, evt.waitingForDebugger).catch((e) =>
    note("attachChildErr", { error: String(e), url: evt.targetInfo?.url }),
  );
}
main.on("Target.attachedToTarget", onAttachedToTarget);
connection.on("Target.attachedToTarget", onAttachedToTarget);

await attachSession(main, { type: "page", url: "about:blank" }, false);

await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 }).catch((e) => {
  note("gotoErr", { error: e.message });
});

async function harvestSessions(tag) {
  for (const { session, label, type } of cdpSessions) {
    try {
      const { result } = await session.send("Runtime.evaluate", {
        expression: `({
          label: ${JSON.stringify(label)},
          type: ${JSON.stringify(type)},
          opCount: (globalThis.__cfOp||[]).length,
          ops: (globalThis.__cfOp||[]).slice(0,400),
          xhr: globalThis.__cfXhr||[],
          runProgramCalls: globalThis.__cfRP||[],
          fo: (globalThis.__cfFo||[]).slice(0,12),
          writes: (globalThis.__cfWrites||[]).slice(0,80),
          packedMeta: globalThis.__cfPackedMeta||null
        })`,
        returnByValue: true,
      });
      const v = result?.value;
      if (v?.fo?.length) {
        for (const s of v.fo) {
          if (liveFo.length < 12) liveFo.push(s);
        }
      }
      if (v?.writes?.length) {
        for (const w of v.writes) {
          if (
            liveWrites.length < 80 &&
            !liveWrites.some((x) => x.key === w.key && x.via === w.via)
          ) {
            liveWrites.push(w);
          }
        }
      }
      if (v?.ops?.length) {
        for (const o of v.ops) {
          if (liveOps.length < 400) liveOps.push(o);
        }
        note("harvest", { tag, label, opCount: v.opCount });
      }
    } catch (e) {
      const msg = String(e).slice(0, 160);
      if (!/Session closed|Target closed/i.test(msg)) {
        note("harvestErr", { tag, label, error: msg });
      }
    }
  }
}

const harvestDeadline = Date.now() + waitMs;
while (Date.now() < harvestDeadline) {
  await harvestSessions("poll");
  await new Promise((r) => setTimeout(r, 400));
}
await harvestSessions("final");

const frameDumps = [];
let packedFromFrames = false;
for (const frame of page.frames()) {
  const fu = frame.url();
  if (!interestingUrl(fu) && frame !== page.mainFrame()) continue;
  try {
            const dump = await frame.evaluate(() => ({
      href: location.href,
      world: "frame",
      opCount: (globalThis.__cfOp || []).length,
      ops: (globalThis.__cfOp || []).slice(0, 400),
      reads: (globalThis.__cfReads || []).slice(0, 96),
      xhr: globalThis.__cfXhr || [],
      runProgramCalls: globalThis.__cfRP || [],
      fo: (globalThis.__cfFo || []).slice(0, 8),
      writes: (globalThis.__cfWrites || []).slice(0, 80),
      packedMeta: globalThis.__cfPackedMeta || null,
      hookErr: globalThis.__cfHookErr || null,
    }));
    frameDumps.push(dump);
    if (!packedFromFrames && dump.packedMeta?.packedLen) {
      try {
        const packed = await frame.evaluate(
          () => (typeof globalThis.__cfPacked === "string" ? globalThis.__cfPacked : null),
        );
        if (typeof packed === "string" && packed.length > 50000) {
          fs.writeFileSync(path.join(outDir, "packed-runprogram.txt"), packed);
          dump.packedMeta.saved = packed.length;
          packedFromFrames = true;
        }
      } catch {}
    }
  } catch (e) {
    frameDumps.push({ href: fu, error: String(e) });
  }
}

for (const { session, label, type } of cdpSessions) {
  try {
    const { result } = await session.send("Runtime.evaluate", {
      expression: `({
        label: ${JSON.stringify(label)},
        type: ${JSON.stringify(type)},
        opCount: (globalThis.__cfOp||[]).length,
        ops: (globalThis.__cfOp||[]).slice(0,400),
        xhr: globalThis.__cfXhr||[],
        runProgramCalls: globalThis.__cfRP||[],
        fo: (globalThis.__cfFo||[]).slice(0,12),
        writes: (globalThis.__cfWrites||[]).slice(0,80),
        packedMeta: globalThis.__cfPackedMeta||null,
        hookErr: globalThis.__cfHookErr||null
      })`,
      returnByValue: true,
    });
    if (result?.value) frameDumps.push({ href: label, world: "cdp", ...result.value });
  } catch (e) {
    frameDumps.push({ href: label, world: "cdp", error: String(e) });
  }
}

try {
  for (const worker of page.workers()) {
    const dump = await worker.evaluate(() => ({
      href: "worker",
      world: "worker",
      opCount: (globalThis.__cfOp || []).length,
      ops: (globalThis.__cfOp || []).slice(0, 400),
      hookErr: globalThis.__cfHookErr || null,
    }));
    frameDumps.push(dump);
  }
} catch (e) {
  note("workerEvalErr", { error: String(e) });
}

let screenshot = null;
try {
  const shot = path.join(outDir, "headed-chrome.png");
  await page.screenshot({ path: shot, fullPage: false });
  screenshot = shot;
} catch (e) {
  note("screenshotErr", { error: String(e) });
}

const token = await page
  .evaluate(() => {
    const el = document.querySelector("[name='cf-turnstile-response']");
    const v = el && el.value ? String(el.value) : "";
    return { tokenLen: v.length, tokenPrefix: v.slice(0, 12) };
  })
  .catch(() => ({ tokenLen: 0 }));

let packedMeta = frameDumps.map((f) => f.packedMeta).find((m) => m && m.packedLen);
for (const { session } of cdpSessions) {
  if (packedMeta) break;
  try {
    const { result } = await session.send("Runtime.evaluate", {
      expression: `globalThis.__cfPackedMeta || null`,
      returnByValue: true,
    });
    if (result?.value?.packedLen) packedMeta = result.value;
  } catch {}
}
if (packedMeta?.packedLen) {
  for (const { session } of cdpSessions) {
    try {
      const { result } = await session.send("Runtime.evaluate", {
        expression: `typeof globalThis.__cfPacked === "string" ? globalThis.__cfPacked : null`,
        returnByValue: true,
      });
      const packed = result?.value;
      if (typeof packed === "string" && packed.length > 50000) {
        fs.writeFileSync(path.join(outDir, "packed-runprogram.txt"), packed);
        packedMeta.saved = packed.length;
        break;
      }
    } catch (e) {
      note("packedSaveErr", { error: String(e).slice(0, 160) });
    }
  }
}

await browser.close();

let packedStr = null;
try {
  packedStr = fs.readFileSync(path.join(outDir, "packed-runprogram.txt"), "utf8");
} catch {
  packedStr = null;
}
const fetchLoopFinal = fillBytesFromPacked(finalizeFetchLoopRows(liveFetchRaw), packedStr);
try {
  fs.writeFileSync(
    path.join(outDir, "fetch-loop-raw.json"),
    JSON.stringify({ raw: liveFetchRaw, final: fetchLoopFinal }, null, 2),
  );
} catch {}
const completeTuples = fetchLoopFinal.filter(isCompleteTuple);
const foNet = network.filter((n) => /\/fo\//.test(n.url || ""));
const firstFo = foNet[0] || null;
const ops = normalizeBreakpointOps([
  ...completeTuples,
  ...frameDumps.flatMap((f) => f.ops || []),
  ...liveOps,
]);
const reads = frameDumps.flatMap((f) => f.reads || []);
const xhr = frameDumps.flatMap((f) => f.xhr || []);
const writes = [];
const seenWrite = new Set();
for (const w of [...liveWrites, ...frameDumps.flatMap((f) => f.writes || [])]) {
  if (!w || w.key == null) continue;
  const id = `${w.via || ""}:${w.key}`;
  if (seenWrite.has(id)) continue;
  seenWrite.add(id);
  writes.push(w);
}
for (const s of frameDumps.flatMap((f) => f.fo || [])) {
  if (s && s.keyCount >= 20 && liveFo.length < 12) liveFo.push(s);
}
const foShapes = [];
const seenFo = new Set();
for (const s of liveFo) {
  const key = `${s.via || ""}:${s.keyCount}:${(s.identKeys || []).slice(0, 8).join(",")}:${s.numericKeyCount || 0}`;
  if (seenFo.has(key)) continue;
  seenFo.add(key);
  foShapes.push(s);
}

function headerBag(rec) {
  const extra = rec?.extraHeaders || {};
  const hdrs = rec?.headers || {};
  const out = {};
  for (const [k, v] of Object.entries({ ...hdrs, ...extra })) {
    out[k.toLowerCase()] = String(v);
  }
  return out;
}

const foHeaders = firstFo ? headerBag(firstFo) : {};
const deltas = pcDeltas(ops);
let iframeHtml = "";
try {
  iframeHtml = fs.readFileSync(path.join(outDir, "iframe-1.html"), "utf8");
} catch {
  iframeHtml = "";
}
const bodyShape = foBodyShape(foNet, xhr, iframeHtml);
const followUpShape = foFollowUpShape(foNet, xhr);
const initJson = extractInitJsonKeys(iframeHtml);
const fetchSchedule = extractFetchSchedule(iframeHtml);
const followUpJson = pickFollowUpShape(foShapes, initJson?.keys || []);
const foPlaintextRows = foShapes.map((s) =>
  classifyFoPlaintext(s, initJson?.keys || []),
);
const summary = {
  url,
  headed,
  waitMs,
  iframeRewrites,
  screenshot,
  tokenLen: token.tokenLen,
  foRequests: foNet.map((n) => ({
    method: n.method,
    status: n.status,
    url: n.url,
    bodyLen: n.bodyLen,
    bodyPrefix: n.bodyPrefix,
    headers: headerBag(n),
  })),
  foPostPairs: foPostPairs(foNet),
  foBodyShape: bodyShape,
  foFollowUp: followUpShape,
  foInitJson: initJson
    ? {
        keyCount: initJson.keyCount,
        setTimeoutNearby: initJson.setTimeoutNearby,
        hasJsonStringify: initJson.hasJsonStringify,
        keys: initJson.keys,
        note: "key names only; do not dump values or POST",
      }
    : null,
  fetchSchedule,
  foFollowUpJson: followUpJson
    ? {
        kind: followUpJson.kind,
        via: followUpJson.via,
        keyCount: followUpJson.keyCount,
        identCount: followUpJson.identCount,
        numericKeyCount: followUpJson.numericKeyCount,
        numericKeyMin: followUpJson.numericKeyMin,
        numericKeyMax: followUpJson.numericKeyMax,
        copiedCount: followUpJson.copiedCount,
        extraIdentCount: followUpJson.extraIdentCount,
        extraIdent: followUpJson.extraIdent,
        extraIdentKinds: followUpJson.extraIdentKinds || {},
        numericSlotKind: followUpJson.numericSlotKind || null,
        numericSlotKeyCountMin: followUpJson.numericSlotKeyCountMin ?? null,
        numericSlotKeyCountMax: followUpJson.numericSlotKeyCountMax ?? null,
        droppedInit: followUpJson.droppedInit || [],
        droppedInitCount: followUpJson.droppedInitCount || 0,
        identKeys: followUpJson.identKeys,
        note: "key names and value kinds only; do not dump values or POST",
      }
    : null,
  leftoverProbe: leftoverProbeSummary(writes, followUpJson?.extraIdent || []),
  packedMeta: packedMeta || null,
  foInitResponse: foInitResponse || null,
  fetchTuples,
  fetchTupleCap,
  fetchLoopRawCount: liveFetchRaw.length,
  completeTupleCount: completeTuples.length,
  fetchLoopTuples: completeTuples.slice(0, 128),
  foPlaintextShapes: foShapes.map((s) => ({
    via: s.via,
    keyCount: s.keyCount,
    identCount: (s.identKeys || []).length,
    numericKeyCount: s.numericKeyCount,
    numericKeyMin: s.numericKeyMin ?? null,
    numericKeyMax: s.numericKeyMax ?? null,
    identKeys: s.identKeys,
    kinds: s.kinds,
  })),
  foPlaintextClassify: foPlaintextRows,
  xhrHook: xhr,
  opcodeFetches: ops.slice(0, 128),
  pcDeltas: deltas.slice(0, 96),
  widthHistogram: widthHistogram(deltas),
  bytecodeReads: reads.slice(0, 64),
  opcodeCount: ops.length,
  runProgramCalls: frameDumps.flatMap((f) => f.runProgramCalls || []),
  headerCompare: {
    method: firstFo?.method || xhr[0]?.method || null,
    contentType: foHeaders["content-type"] || null,
    cfChl: foHeaders["cf-chl"] ? "present" : xhr[0]?.headers?.["cf-chl"] ? "xhr" : null,
    cfChlRa: foHeaders["cf-chl-ra"] || xhr[0]?.headers?.["cf-chl-ra"] || null,
    accept: foHeaders["accept"] || null,
    origin: foHeaders["origin"] || null,
    secFetchSite: foHeaders["sec-fetch-site"] || null,
    secFetchMode: foHeaders["sec-fetch-mode"] || null,
    secFetchDest: foHeaders["sec-fetch-dest"] || null,
    secFetchStorageAccess: foHeaders["sec-fetch-storage-access"] || null,
    priority: foHeaders.priority || null,
    referer: foHeaders["referer"] ? "present" : null,
  },
  firstOpcode: ops[0] || null,
  scriptNotes: scriptNotes.slice(0, 8),
  worlds: frameDumps.map((f) => ({
    href: (f.href || f.label || "").slice(0, 100),
    world: f.world,
    opCount: f.opCount,
    error: f.error || null,
    hookErr: f.hookErr || null,
  })),
  events: events.slice(0, fetchTuples ? 80 : 50),
};

fs.writeFileSync(path.join(outDir, "oracle.json"), JSON.stringify(summary, null, 2));
fs.writeFileSync(
  path.join(outDir, "network.json"),
  JSON.stringify({ fo: foNet, allChallenge: network }, null, 2),
);

console.log(
  JSON.stringify(
    {
      ok: foNet.length > 0 || ops.length > 0 || completeTuples.length > 0,
      headed,
      fetchTuples,
      iframeRewrites,
      foCount: foNet.length,
      opcodeCount: ops.length,
      completeTupleCount: completeTuples.length,
      fetchLoopRawCount: liveFetchRaw.length,
      firstCompleteTuple: completeTuples[0] || null,
      readCount: reads.length,
      firstOpcode: ops[0] || null,
      firstWidths: deltas.slice(0, 12),
      widthHistogram: summary.widthHistogram,
      foPostPairs: summary.foPostPairs,
      foBodyShape: {
        charsetLen: bodyShape.charsetLen,
        prefixesInCharset: bodyShape.prefixesInCharset,
        charsetMatchesBranchB: bodyShape.charsetMatchesBranchB,
        rows: bodyShape.rows,
      },
      foFollowUp: {
        pairCount: followUpShape.pairCount,
        plaintextKind: followUpShape.plaintextKind,
        notPackedProgram: followUpShape.notPackedProgram,
        rows: followUpShape.rows,
      },
      foInitJson: initJson
        ? { keyCount: initJson.keyCount, hasJsonStringify: initJson.hasJsonStringify }
        : null,
      fetchSchedule,
      foFollowUpJson: followUpJson
        ? {
            kind: followUpJson.kind,
            keyCount: followUpJson.keyCount,
            copiedCount: followUpJson.copiedCount,
            extraIdentCount: followUpJson.extraIdentCount,
            numericKeyCount: followUpJson.numericKeyCount,
            extraIdent: followUpJson.extraIdent,
            droppedInit: followUpJson.droppedInit,
            numericSlotKind: followUpJson.numericSlotKind || null,
          }
        : null,
      leftoverProbe: summary.leftoverProbe,
      packedMeta: packedMeta || null,
      headerCompare: summary.headerCompare,
      firstFo: foNet[0]
        ? {
            method: foNet[0].method,
            status: foNet[0].status,
            bodyLen: foNet[0].bodyLen,
            bodyPrefix: foNet[0].bodyPrefix,
          }
        : null,
      outDir,
    },
    null,
    2,
  ),
);
