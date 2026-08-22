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
 * before init POST. Case-label pauses are **after** the key update: harvest
 * `{pc, op: caseN, nextKey: keySlot, byte}` — do not treat `keySlot` as the
 * fetch key, and do not take mix from Window/global (`outerWidth` is not mix).
 * The iframe calls a **local** `runProgram`, so wrapping
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
 *   ORACLE_FETCH_TUPLES set to 1 for a finite fetch-loop harvest. Prefers a logpoint on
 *                    the fetch `switch(...){` (discriminant already holds `op`; condition
 *                    returns false so packed `/fo/` is not stalled). Unique handler `{`
 *                    BPs are fallback only. Skips iframe rewrite unless ORACLE_INJECT_IFRAME=1
 *                    (rewrite can hit the wrong document and 400 the follow-up POST).
 *                    Chrome 148 removed setScriptSource. Always-on fetch-loop pauses stall
 *                    /fo/ because the HTML stub runs first.
 *   ORACLE_INJECT_IFRAME set to 1 to Fetch.fulfillRequest-inject `__cfOp.push` into the
 *                    first turnstile iframe document (optional; default off).
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
/** Fetch.fulfillRequest inject into iframe HTML. Off by default: rewrite is not the packed script. */
const injectIframe = process.env.ORACLE_INJECT_IFRAME === "1";
/** Unique packed `case N` hits, then remove those BPs. Default 16. */
const fetchTupleCap = Number(process.env.ORACLE_FETCH_TUPLE_CAP || 16);
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

const handlerNameToOp = new Map();
const ambiguousHandlerNames = new Set();

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
  // Prefer mix² * mul over later helper constants (8696 is key_quad_b, not key_mul).
  let idx = -1;
  for (const x of [
    html.search(/\d{4,5}\*\(([A-Za-z_$][\w$]*)\*\1\)/),
    html.search(/([A-Za-z_$][\w$]*)\*\1\*\d{4,5}/),
    html.search(/([A-Za-z_$][\w$]*)\*\1,\d{4,5}/),
    html.search(/([A-Za-z_$][\w$]*),\1\)\*\d{4,5}/),
  ]) {
    if (x >= 0 && (idx < 0 || x < idx)) idx = x;
  }
  if (idx < 0) {
    idx = html.search(
      /(\w+)\*\1\*\d{4,5}|,\d{4,5}\),[\s\S]{0,48}\(\w+,\d{4,5}\)/,
    );
  }
  const window = idx >= 0 ? html.slice(Math.max(0, idx - 240), idx + 420) : html;
  const sq = window.match(
    /(\w+)\*\1\*(\d{4,5}),[\s\S]{0,96}?\(\1,(\d{4,5})\)\)\+(\d{4,5}),255/,
  );
  const sqBareBmix = window.match(
    /(\w+)\*\1\*(\d{4,5})\+\1\*(\d{4,5})\+(\d{4,5})/,
  );
  const sqBareMulB = window.match(
    /(\w+)\*\1\*(\d{4,5})\+(\d{4,5})\*\1\+(\d{4,5})/,
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
  const mulSqPlusBmix = window.match(
    /(\d{4,5})\*\((\w+)\*\2\)\+(\d{4,5})\*\2,(\d{4,5})\)/,
  );
  const helperPairTimesMul = window.match(
    /(\w+),\1\)\*(\d{4,5})\+[\s\S]{0,96}?\(\1,(\d{4,5})\)\+(\d{4,5})&255/,
  );
  const helperPairCommaAdd = window.match(
    /(\w+),\1\)\*(\d{4,5})\+[\s\S]{0,96}?\(\1,(\d{4,5})\),(\d{4,5})\)/,
  );
  const mulSqBmixPlusAdd = window.match(
    /(\d{4,5})\*\((\w+)\*\2\)\+(\d{4,5})\*\2\+(\d{4,5}),255/,
  );
  // 54260*(L*L),43539*L),20295),255 — helper comma-add chain.
  const mulCommaBmix = window.match(
    /(\d{4,5})\*\((\w+)\*\2\),(\d{4,5})\*\2\),(\d{4,5})\),255/,
  );
  const mulCommaBmixAmp = window.match(
    /(\d{4,5})\*\((\w+)\*\2\),(\d{4,5})\*\2\)\+(\d{4,5})&255/,
  );
  const nestSqCommaBmix = window.match(
    /(\w+)\*\1,(\d{4,5})\),[\s\S]{0,96}?\1\*(\d{4,5})\),(\d{4,5})\)&255/,
  );
  const sqBareMulBCommaAdd = window.match(
    /(\w+)\*\1\*(\d{4,5})\+(\d{4,5})\*\1,(\d{4,5})\)&255/,
  );
  const mulCommaHelper = window.match(
    /(\d{4,5})\*\((\w+)\*\2\),[\s\S]{0,120}?\(\2,(\d{4,5})\)\),(\d{4,5})\)&255/,
  );
  const sqCommaHelper = window.match(
    /(\w+)\*\1\*(\d{4,5}),[\s\S]{0,120}?\(\1,(\d{4,5})\)\)\+(\d{4,5})&255/,
  );
  const biasM = window.match(/\]-(\d{2,3}),256\)&255/);
  const biasAdd = window.match(/\[(\w+)\],(\d{2,3})\)\+256/);
  const biasAddComma = window.match(/\[(\w+)\],(\d{2,3})\),256/);
  const biasPlus = window.match(/\((\d{2,3})\+\w+\[\w+\],255\)/);
  const biasAndAdd = window.match(/255&(\d{2,3})\+\w+\[/);
  const biasPlusAmp = window.match(/(\d{2,3})\+\w+\[[^\]]{0,24}\]&255/);
  const caseM = window.match(/\{case (\d+):/);
  const hit =
    sq ||
    sqBareBmix ||
    sqBareMulB ||
    sqPlus ||
    sqAmp ||
    nestMul ||
    starMix ||
    mulTimesSq ||
    mulSqPlusBmix ||
    mulSqBmixPlusAdd ||
    mulCommaBmix ||
    mulCommaBmixAmp ||
    nestSqCommaBmix ||
    sqBareMulBCommaAdd ||
    helperPairTimesMul ||
    helperPairCommaAdd ||
    mulCommaHelper ||
    sqCommaHelper ||
    alt ||
    mulStar;
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
  } else if (sqBareBmix) {
    keyMul = Number(sqBareBmix[2]);
    keyQuadB = Number(sqBareBmix[3]);
    keyAdd = Number(sqBareBmix[4]);
    spelling = "mix*mix*mul+mix*b+add";
  } else if (sqBareMulB) {
    keyMul = Number(sqBareMulB[2]);
    keyQuadB = Number(sqBareMulB[3]);
    keyAdd = Number(sqBareMulB[4]);
    spelling = "mix*mix*mul+b*mix+add";
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
  } else if (mulSqPlusBmix) {
    keyMul = Number(mulSqPlusBmix[1]);
    keyQuadB = Number(mulSqPlusBmix[3]);
    keyAdd = Number(mulSqPlusBmix[4]);
    spelling = "mul*(mix*mix)+b*mix,add";
  } else if (mulSqBmixPlusAdd) {
    keyMul = Number(mulSqBmixPlusAdd[1]);
    keyQuadB = Number(mulSqBmixPlusAdd[3]);
    keyAdd = Number(mulSqBmixPlusAdd[4]);
    spelling = "mul*(mix*mix)+b*mix+add,255";
  } else if (mulCommaBmix) {
    keyMul = Number(mulCommaBmix[1]);
    keyQuadB = Number(mulCommaBmix[3]);
    keyAdd = Number(mulCommaBmix[4]);
    spelling = "mul*(mix*mix),b*mix),add),255";
  } else if (mulCommaBmixAmp) {
    keyMul = Number(mulCommaBmixAmp[1]);
    keyQuadB = Number(mulCommaBmixAmp[3]);
    keyAdd = Number(mulCommaBmixAmp[4]);
    spelling = "mul*(mix*mix),b*mix)+add&255";
  } else if (nestSqCommaBmix) {
    keyMul = Number(nestSqCommaBmix[2]);
    keyQuadB = Number(nestSqCommaBmix[3]);
    keyAdd = Number(nestSqCommaBmix[4]);
    spelling = "helper(mix*mix,mul),mix*b),add)&255";
  } else if (sqBareMulBCommaAdd) {
    keyMul = Number(sqBareMulBCommaAdd[2]);
    keyQuadB = Number(sqBareMulBCommaAdd[3]);
    keyAdd = Number(sqBareMulBCommaAdd[4]);
    spelling = "mix*mix*mul+b*mix,add)&255";
  } else if (helperPairTimesMul) {
    keyMul = Number(helperPairTimesMul[2]);
    keyQuadB = Number(helperPairTimesMul[3]);
    keyAdd = Number(helperPairTimesMul[4]);
    spelling = "helper(mix,mix)*mul+helper(mix,b)+add";
  } else if (helperPairCommaAdd) {
    keyMul = Number(helperPairCommaAdd[2]);
    keyQuadB = Number(helperPairCommaAdd[3]);
    keyAdd = Number(helperPairCommaAdd[4]);
    spelling = "helper(mix,mix)*mul+helper(mix,b),add";
  } else if (mulCommaHelper) {
    keyMul = Number(mulCommaHelper[1]);
    keyQuadB = Number(mulCommaHelper[3]);
    keyAdd = Number(mulCommaHelper[4]);
    spelling = "mul*(mix*mix),helper),add&255";
  } else if (sqCommaHelper) {
    keyMul = Number(sqCommaHelper[2]);
    keyQuadB = Number(sqCommaHelper[3]);
    keyAdd = Number(sqCommaHelper[4]);
    spelling = "mix*mix*mul,helper)+add&255";
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
    kind: "quadratic",
    keyMul,
    keyQuadB,
    keyAdd,
    byteBias: biasM
      ? Number(biasM[1])
      : biasAdd
        ? Number(biasAdd[2])
        : biasAddComma
          ? Number(biasAddComma[2])
          : biasPlus
            ? (256 - Number(biasPlus[1])) & 255
            : biasAndAdd
              ? (256 - Number(biasAndAdd[1])) & 255
              : biasPlusAmp
                ? (256 - Number(biasPlusAmp[1])) & 255
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
  "55067",
  "54260",
  "43539",
  "20295",
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
  const nested = src.match(/(\d{4,5})\*\([A-Za-z_$][\w$]*\*[A-Za-z_$][\w$]*\)/);
  const sqMul = src.match(/([A-Za-z_$][\w$]*)\*\1\*(\d{4,5})/);
  const extra = nested ? nested[1] : sqMul ? sqMul[2] : null;
  if (extra) {
    const idx = src.indexOf(extra);
    if (idx >= 0) {
      return { marker: extra, idx, schedule, hasInject: src.includes("__cfOp.push") };
    }
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

  // 54260 happy decode: x=helper(st[key],255&96+arr[x])  (xor as two-arg helper)
  out = out.replace(
    /(\w+)=(\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],255&(\d{2,3})\+(\w+)\[\1\]\)/g,
    (_full, op, xorCallee, st, keySlot, add, arr) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${op}]&255),${xorCallee}(${st}[${keySlot}],255&${add}+${arr}[${op}]))`;
    },
  );
  // 54260 catch decode: pH=st[key]^outer(inner(arr[pc],160)+256,255)
  out = out.replace(
    /(\w+)=(\w+)\[(\w+)\]\^(\w+\[[^\]]{0,80}\])\((\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],(\d{2,3})\)\+256,255\)/g,
    (_full, op, st, keySlot, outer, inner, arr, pcVar, bias) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${pcVar}]&255),${st}[${keySlot}]^${outer}(${inner}(${arr}[${pcVar}],${bias})+256,255))`;
    },
  );
  // 54260 happy key: helper(helper(helper(54260*(L*L),43539*L),20295),255),x)
  out = out.replace(
    /(\d{4,5})\*\((\w+)\*\2\),(\d{4,5})\*\2\),(\d{4,5})\),255\),(\w+)\)/g,
    (_full, mul, mixVar, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mul}*(${mixVar}*${mixVar}),${quadB}*${mixVar}),${add}),255`,
        opVar,
      );
    },
  );
  // 54260 catch key: 54260*(py*py),helper(py,43539)),20295)&255,pH)
  out = out.replace(
    /(\d{4,5})\*\((\w+)\*\2\),([\s\S]{0,96}?\(\2,(\d{4,5})\))\),(\d{4,5})\)&255(?:\.\d+)?,(\w+)\)/g,
    (_full, mul, mixVar, mid, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mul}*(${mixVar}*${mixVar}),${mid}),${add})&255`,
        opVar,
      );
    },
  );
  // 54260 plus: helper(54260*(L*L)+43539*L+20295,255),x)
  out = out.replace(
    /(\d{4,5})\*\((\w+)\*\2\)\+(\d{4,5})\*\2\+(\d{4,5}),255\),(\w+)\)/g,
    (_full, mul, mixVar, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mul}*(${mixVar}*${mixVar})+${quadB}*${mixVar}+${add},255`,
        opVar,
      );
    },
  );
  // 54260 catch: helper(helper(mix,mix),mul)+b*mix+add,255),op
  out = out.replace(
    /\((\w+),\1\),(\d{4,5})\)\+(\d{4,5})\*\1\+(\d{4,5}),255\),(\w+)\)/g,
    (_full, mixVar, mul, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `(${mixVar},${mixVar}),${mul})+${quadB}*${mixVar}+${add},255`,
        opVar,
      );
    },
  );
  // 54260 catch decode: xor(st[key], helper(arr[pc],160)+256&255)
  out = out.replace(
    /(\w+)=(\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],(\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],(\d{2,3})\)\+256&255\)/g,
    (_full, op, xorCallee, st, keySlot, addCallee, arr, pcVar, bias) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${pcVar}]&255),${xorCallee}(${st}[${keySlot}],${addCallee}(${arr}[${pcVar}],${bias})+256&255))`;
    },
  );
  // 54260: 255&mix*mix*mul+mix*b+add,op
  out = out.replace(
    /255&(\w+)\*\1\*(\d{4,5})\+\1\*(\d{4,5})\+(\d{4,5}),(\w+)\)/g,
    (_full, mixVar, mul, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `255&${mixVar}*${mixVar}*${mul}+${mixVar}*${quadB}+${add}`,
        opVar,
      );
    },
  );
  // 54260: helper(mix*mix*mul+b*mix+add,255),op
  out = out.replace(
    /(\w+)\*\1\*(\d{4,5})\+(\d{4,5})\*\1\+(\d{4,5}),255\),(\w+)\)/g,
    (_full, mixVar, mul, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mixVar}*${mixVar}*${mul}+${quadB}*${mixVar}+${add},255`,
        opVar,
      );
    },
  );
  // 54260: mul*(mix*mix),b*mix)+add&255,op
  out = out.replace(
    /(\d{4,5})\*\((\w+)\*\2\),(\d{4,5})\*\2\)\+(\d{4,5})&255(?:\.\d+)?,(\w+)\)/g,
    (_full, mul, mixVar, quadB, add, opVar) => {
      n++;
      return logAfterKeyUpdate(
        `${mul}*(${mixVar}*${mixVar}),${quadB}*${mixVar})+${add}&255`,
        opVar,
      );
    },
  );
  // 54260: helper(st[key],96+arr[op]&255)
  out = out.replace(
    /(\w+)=(\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],(\d{2,3})\+(\w+)\[\1\]&255/g,
    (_full, op, xorCallee, st, keySlot, add, arr) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${op}]&255),${xorCallee}(${st}[${keySlot}],${add}+${arr}[${op}]&255))`;
    },
  );

  // 54260 catch decode: xor(st[key], outer(mid(inner(arr[pc],160),256),255))
  out = out.replace(
    /(\w+)=(\w+)\[(\w+)\]\^(\w+\[[^\]]{0,80}\])\((\w+\[[^\]]{0,80}\])\((\w+\[[^\]]{0,80}\])\((\w+)\[(\w+)\],(\d{2,3})\),256\),255\)/g,
    (_full, op, st, keySlot, outer, mid, inner, arr, pcVar, bias) => {
      n++;
      return `${op}=(globalThis.__cfT&&(globalThis.__cfT.key=${st}[${keySlot}]&255,globalThis.__cfT.byte=${arr}[${pcVar}]&255),${st}[${keySlot}]^${outer}(${mid}(${inner}(${arr}[${pcVar}],${bias}),256),255))`;
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
  const packed =
    '(function(){try{var g=this&&this.g;if(!g)return false;if(typeof this.l==="number"&&g[this.l]&&g[this.l].length>10000)return true;for(var i=0;i<Math.min(g.length||0,48);i++){var v=g[i];if(v&&v.length>10000)return true;}return false;}catch(e){return false;}})()';
  return (
    `${prefix},(globalThis.__cfT&&(globalThis.__cfT.op=${opVar}&255),` +
    `globalThis.__cfOp=globalThis.__cfOp||[],` +
    `globalThis.__cfOp.length<128&&${packed}&&(globalThis.__cfOp.push({` +
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

/** Case-label harvest: fetch key is next_key, recovered later. */
function isHarvestTuple(r) {
  return (
    r &&
    Number.isFinite(Number(r.pc)) &&
    Number.isFinite(Number(r.op)) &&
    Number.isFinite(Number(r.byte)) &&
    (Number.isFinite(Number(r.key)) || Number.isFinite(Number(r.nextKey)))
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

function uniqueOpFromFrameNames(
  frameNames,
  nameToOp = handlerNameToOp,
  ambiguous = ambiguousHandlerNames,
) {
  for (const n of frameNames || []) {
    if (!n || ambiguous.has(n)) continue;
    if (nameToOp.has(n)) return { name: n, op: nameToOp.get(n) };
  }
  return null;
}

/** Top named frame only. Do not walk into a unique caller/callee. */
function pausedUniqueHandler(
  frameNames,
  nameToOp = handlerNameToOp,
  ambiguous = ambiguousHandlerNames,
) {
  for (const n of frameNames || []) {
    if (!n || String(n).includes("<computed>")) continue;
    if (ambiguous.has(n)) return null;
    if (nameToOp.has(n)) return { name: n, op: nameToOp.get(n) };
    return null;
  }
  return null;
}

function modalPackedBcLen(rows) {
  const counts = new Map();
  for (const r of rows || []) {
    const n = r && r.bcLen;
    if ((n || 0) > 10000) counts.set(n, (counts.get(n) || 0) + 1);
  }
  let best = null;
  let bestN = 0;
  for (const [k, v] of counts) {
    if (v > bestN) {
      best = k;
      bestN = v;
    }
  }
  return best;
}

/** 56907 Chrome: pause at the mul is after `pc+=1` (first observed pcSlot 1). */
function finalizeFetchLoopRows(rows) {
  const fl = (rows || []).filter((r) => r && r.via === "fetchLoop");
  if (!fl.length) return [];
  const packed = fl.filter((r) => (r.bcLen || 0) > 10000);
  const modal = modalPackedBcLen(packed);
  const use = modal != null ? packed.filter((r) => r.bcLen === modal) : packed;
  const { opKey, mixKey } = inferLocalOpMix(use);
  const pcFromG = inferPcSlotFromGNums(use);
  const out = [];
  const seenPc = new Set();
  for (const r of use) {
    let pcSlot = r.pcSlot;
    if (!Number.isFinite(pcSlot) && pcFromG != null && r.gNums && Number.isFinite(r.gNums[pcFromG])) {
      pcSlot = r.gNums[pcFromG];
    }
    const adjust = Number.isFinite(pcSlot) && pcSlot >= 1;
    const pc = Number.isFinite(pcSlot) ? (adjust ? pcSlot - 1 : pcSlot) : r.pc;
    const stackH = pausedUniqueHandler(r.frameNames);
    const fromCase = r.opFrom === "caseLabel" || Number.isFinite(r.caseOp);
    let op = fromCase && Number.isFinite(r.caseOp)
      ? r.caseOp
      : stackH
        ? stackH.op
        : r.op;
    const fn = r.bpName || r.fn || (stackH && stackH.name);
    const opFrom = fromCase
      ? "caseLabel"
      : stackH
        ? "pausedFn"
        : r.opFrom;
    const bpCaseOp = Number.isFinite(r.bpCaseOp) ? r.bpCaseOp & 255 : undefined;
    let mix = r.mixLocal != null ? r.mixLocal : r.mix;
    let key = r.key;
    let nextKey = Number.isFinite(r.nextKey)
      ? r.nextKey & 255
      : fromCase && Number.isFinite(r.keySlot)
        ? r.keySlot & 255
        : undefined;
    if (!fromCase) {
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
    } else if (
      key == null &&
      Number.isFinite(mix) &&
      mix >= 256 &&
      mix <= 510 &&
      Number.isFinite(op)
    ) {
      const maybe = (mix - op) & 255;
      if (!Number.isFinite(nextKey) || maybe !== nextKey) {
        key = maybe;
      }
    }
    let byte = r.byte;
    if (byte == null) {
      byte = adjust ? r.byteAtPcMinus1 : r.byteAtPc;
    }
    if (Number.isFinite(pc) && seenPc.has(pc)) continue;
    if (Number.isFinite(pc)) seenPc.add(pc);
    const row = {
      via: "fetchLoop",
      pc,
      op: Number.isFinite(op) ? op & 255 : undefined,
      key: Number.isFinite(key) ? key & 255 : undefined,
      byte: Number.isFinite(byte) ? byte & 255 : undefined,
      nextKey: Number.isFinite(nextKey) ? nextKey : undefined,
      mix: Number.isFinite(mix) && mix >= 256 && mix <= 510 ? mix : undefined,
      bcLen: r.bcLen,
      pcSlot,
      caseOp: Number.isFinite(op) ? op & 255 : Number.isFinite(r.caseOp) ? r.caseOp & 255 : undefined,
      opFrom,
      fn,
      bpWhy: r.bpWhy,
      bpName: r.bpName,
      bpCaseOp,
      frameNames: Array.isArray(r.frameNames) ? r.frameNames.slice(0, 6) : undefined,
      vmFrom: r.vmFrom,
      byteVia: Number.isFinite(byte) ? "vm" : undefined,
    };
    out.push(row);
  }
  return out;
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
      if (Number.isFinite(r.nextKey)) row.nextKey = r.nextKey & 255;
      if (Number.isFinite(r.caseOp)) row.caseOp = r.caseOp & 255;
      if (r.opFrom) row.opFrom = r.opFrom;
      if (Number.isFinite(r.mix) && r.mix >= 256 && r.mix <= 510) row.mix = r.mix;
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

function indexFromLineCol(src, lineNumber, columnNumber) {
  if (!src || lineNumber == null || columnNumber == null) return null;
  if (lineNumber === 0) return columnNumber;
  let idx = 0;
  let line = 0;
  while (line < lineNumber && idx < src.length) {
    const nl = src.indexOf("\n", idx);
    if (nl < 0) return src.length;
    idx = nl + 1;
    line++;
  }
  return idx + columnNumber;
}

/** Mix local assigned as `W=state[key]+op` (or helper) just before the quadratic. */
function inferMixVarNearFetch(src, braceIdx, opVar) {
  if (!src || braceIdx == null || braceIdx < 0 || !/^[A-Za-z_$][\w$]*$/.test(opVar || "")) {
    return null;
  }
  const pre = String(src).slice(Math.max(0, braceIdx - 320), braceIdx);
  const plus = pre.match(new RegExp(`(\\w+)=\\w+\\[\\w+\\]\\+${opVar}(?![\\w$])`));
  if (plus) return plus[1];
  const helper = pre.match(
    new RegExp(`(\\w+)=\\w+\\[[^\\]]{0,80}\\]\\(\\w+\\[\\w+\\],${opVar}\\)`),
  );
  if (helper) return helper[1];
  const sq = pre.match(/(\w+)\*\1\*\d{4,5}/);
  if (sq) return sq[1];
  const pair = pre.match(/\((\w+),\1\)\s*\*/);
  if (pair) return pair[1];
  return null;
}

/**
 * Logpoint condition at fetch `switch(...){`. Must be an expression (arrow IIFE)
 * so `try/catch` can swallow lookup errors without pausing. Locals (`op`/`mix`)
 * are visible to the arrow via the call-frame eval scope; `this` is the VM.
 * Always returns false — do not pause packed `/fo/`.
 */
function switchLogCondition(opVar, mixVar) {
  if (!/^[A-Za-z_$][\w$]*$/.test(opVar || "")) return "false";
  const mixOk = /^[A-Za-z_$][\w$]*$/.test(mixVar || "");
  const mixPart = mixOk
    ? `,mix:typeof ${mixVar}==="number"?${mixVar}:null,key:typeof ${mixVar}==="number"?((${mixVar}-${opVar})&255):null`
    : "";
  return (
    `(()=>{try{var __g=this&&this.g;` +
    `if(__g&&typeof this.l==="number"&&__g[this.l]&&__g[this.l].length>10000){` +
    `globalThis.__cfOp=globalThis.__cfOp||[];` +
    `if(globalThis.__cfOp.length<128){` +
    `var __pc=typeof this.j==="number"?((__g[this.j]|0)-1):null;` +
    `var __bc=__g[this.l];` +
    `globalThis.__cfOp.push({pc:__pc,op:(${opVar}&255),` +
    `nextKey:typeof this.i==="number"?(__g[this.i]&255):null,` +
    `byte:(__bc&&__pc>=0&&__pc<__bc.length)?(__bc[__pc]&255):null` +
    `${mixPart},via:"switchLog"});` +
    `typeof console!=="undefined"&&console.debug&&console.debug("__cfOp",globalThis.__cfOp[globalThis.__cfOp.length-1]);` +
    `}} }catch(__e){}return false})()`
  );
}

/**
 * Fetch-loop switch body's `{` after `,op){case N:`. Discriminant already holds `op`.
 * Happy + catch copies only; skip nested decoder `switch(...,x){case 3:`.
 */
function fetchLoopSwitchLogSites(src, markerIdx) {
  if (!src || markerIdx == null || markerIdx < 0) return [];
  const winStart = Math.max(0, markerIdx - 80);
  const window = String(src).slice(winStart, markerIdx + 4000);
  const firstNear = window.match(/\{case (\d+):/);
  const firstCase = firstNear ? Number(firstNear[1]) : null;
  const sites = [];
  const re = /,(\w+)\)\{case (\d+):/g;
  let m;
  while ((m = re.exec(window))) {
    const caseOp = Number(m[2]);
    const abs = winStart + m.index;
    const brace = abs + m[0].indexOf("{");
    const dist = brace - markerIdx;
    if (dist < -80 || dist > 3500) continue;
    if (firstCase != null && caseOp !== firstCase) continue;
    if (firstCase == null && caseOp < 16) continue;
    const pre = String(src).slice(Math.max(0, abs - 48), abs);
    if (/switch\(\w+\[\w+\]=\w+,/.test(pre) && caseOp < 16) continue;
    const opVar = m[1];
    const mixVar = inferMixVarNearFetch(src, brace, opVar);
    sites.push({
      idx: brace,
      why: "switchBrace",
      opVar,
      mixVar,
      caseOp,
      condition: switchLogCondition(opVar, mixVar),
      ...sourceLineCol(src, brace),
    });
    if (sites.length >= 2) break;
  }
  return sites;
}

function switchSiteAt(src, idx, switchSites) {
  if (!switchSites || !switchSites.length) return null;
  let best = switchSites[0];
  for (const s of switchSites) {
    if (s.idx <= idx && (!best || s.idx > best.idx)) best = s;
  }
  return best;
}

/** `switch(` before each fetch `){case`. Discriminant may not have run. */
function fetchLoopSwitchKeywordSites(src, switchSites) {
  const out = [];
  for (const site of switchSites || []) {
    const sw = String(src).lastIndexOf("switch(", site.idx);
    if (sw < 0 || site.idx - sw > 400) continue;
    out.push({
      ...site,
      idx: sw,
      why: "switchKw",
      ...sourceLineCol(src, sw),
    });
  }
  return out;
}

/**
 * Unique `case N:name[` **call** (the handler ident, not the `case` keyword).
 * Still the interpreter frame, so `op`/`mix` locals are in scope.
 */
function fetchLoopCaseCallLogSites(src, markerIdx, switchSites) {
  if (!src || markerIdx == null || markerIdx < 0 || !switchSites?.length) return [];
  const byName = collectHandlerCaseOps(src, markerIdx);
  const winStart = Math.max(0, markerIdx - 400);
  const window = String(src).slice(winStart, markerIdx + 25000);
  const sites = [];
  const seenOp = new Set();
  const re = /case (\d+):(\w+)[\[(]/g;
  let m;
  while ((m = re.exec(window))) {
    const op = Number(m[1]);
    const name = m[2];
    const ops = byName.get(name);
    if (!ops || ops.size !== 1 || [...ops][0] !== op) continue;
    if (seenOp.has(op)) continue;
    seenOp.add(op);
    const nameOff = m[0].indexOf(name);
    const idx = winStart + m.index + nameOff;
    const sw = switchSiteAt(src, idx, switchSites);
    if (!sw) continue;
    sites.push({
      idx,
      why: "caseCallLog",
      opVar: sw.opVar,
      mixVar: sw.mixVar,
      caseOp: op,
      name,
      condition: sw.condition,
      ...sourceLineCol(src, idx),
    });
    if (sites.length >= 48) break;
  }
  return sites;
}

/** Opcode is the `case N:` label at or just before idx. */
function caseOpAt(src, idx) {
  if (!src || idx == null || idx < 0) return null;
  const fwd = String(src).slice(idx, idx + 20).match(/^case (\d+):/);
  if (fwd) return Number(fwd[1]);
  const pre = String(src).slice(Math.max(0, idx - 96), idx + 1);
  const all = [...pre.matchAll(/case (\d+):/g)];
  if (!all.length) return null;
  return Number(all[all.length - 1][1]);
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

const TUPLE_HARVEST_EXPR = `(function(args) {
  function pick(obj) {
    if (!obj || !obj.g) return null;
    const g = obj.g;
    if (typeof obj.j !== "number" && typeof obj.i !== "number") return null;
    return obj;
  }
  let vm = pick(this);
  let vmFrom = vm ? "this" : undefined;
  if (!vm && args && args.length) {
    for (let i = 0; i < Math.min(args.length, 16); i++) {
      vm = pick(args[i]);
      if (vm) {
        vmFrom = "arg" + i;
        break;
      }
    }
  }
  const g = vm && vm.g;
  const thisNums = {};
  if (vm) {
    const names = ["i","j","l","h","o","u","n","m","k","p"];
    for (let n = 0; n < names.length; n++) {
      const k = names[n];
      if (typeof vm[k] === "number") thisNums[k] = vm[k];
    }
  }
  let pcSlot;
  let keySlot;
  let bc;
  if (g && typeof vm.j === "number") pcSlot = g[vm.j];
  if (g && typeof vm.i === "number") keySlot = g[vm.i];
  if (g && typeof vm.l === "number" && g[vm.l] && typeof g[vm.l].length === "number") {
    bc = g[vm.l];
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
    vmFrom: vmFrom,
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
}).call(this, (function (a) {
  try { return Array.prototype.slice.call(a); } catch (e) { return []; }
})(typeof arguments !== "undefined" ? arguments : []))`;

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
  const live55067Comma =
    "switch(tB[ta]=j+1,j=255&173+tV[j]^tB[tz],G=tB[tz]+j,tB[tz]=tL[ro(Xa.U)](tL[ro(Xa.j)](55067*(G*G),tL[ro(Xa.tB)](G,8696)),44379)&255.15,j){case 143:e7[ro(Xa.tF)](this);break;} new qz(P)[po(T4.P)](0,144,[])";
  const live55067Catch =
    "switch(tB[ta]=tv+1,tx=tB[tz]^tL[ro(Xa.Zb)](tV[tv],83)+256&255.41,tR=tB[tz]+tx,tB[tz]=tL[ro(Xa.Zm)](tR*tR*55067,tL[ro(Xa.G)](tR,8696))+44379&255,tx){case 143:e7[ro(Xa.tv)](this);break;}";
  const live55067F = extractFetchQuadratic(live55067Comma);
  const live55067Fc = extractFetchQuadratic(live55067Catch);
  const live55067Mark = fetchMarkerInSource(live55067Comma);
  const live55067Bmix =
    "j=tL[rn(f9.ts)](173+tV[j],255),G=tB[tz]+j,tB[tz]=tL[rn(f9.tD)](tL[rn(f9.tv)](55067*(G*G)+8696*G,44379),255),j){case 143:e7[rn(f9.tx)](this);break;}";
  const live55067BmixF = extractFetchQuadratic(live55067Bmix);
  const live55067BmixMark = fetchMarkerInSource(live55067Bmix);
  const live55067HelperPair =
    "tB[tz]=tL[rn(f9.ZM)](tR,tR)*55067+tL[rn(f9.ZT)](tR,8696)+44379&255,tx){case 143:e7";
  const live55067HelperPairF = extractFetchQuadratic(live55067HelperPair);
  const live55067PairComma =
    "PW[PE]=Pc[pn(MW.Pv)](Pc[pn(MW.PW)](Pc[pn(MW.Pg)](S,S)*55067+Pc[pn(MW.Pn)](S,8696),44379),255),Q){case 143:q7";
  const live55067PairCommaF = extractFetchQuadratic(live55067PairComma);
  const live55067CatchPlus =
    "Pv=PW[PE]^Pc[pn(MW.Q)](Pc[pn(MW.PL)](PL[Pr],83),256)&255.3,Pn=PW[PE]+Pv,PW[PE]=Pc[pn(MW.jU)](55067*(Pn*Pn)+8696*Pn+44379,255),Pv){case 143:q7";
  const live55067CatchPlusF = extractFetchQuadratic(live55067CatchPlus);
  const live54260Happy =
    "if(x=pv[pq],pa[eU(Iw.pb)](x,x))return pv[pb];switch(pv[pq]=x+1,x=pa[eU(Iw.pD)](pv[pB],255&96+pF[x]),L=pa[eU(Iw.x)](pv[pB],x),pv[pB]=pa[eU(Iw.L)](pa[eU(Iw.pJ)](pa[eU(Iw.x)](54260*(L*L),43539*L),20295),255),x){case 191:s7[eU(Iw.pH)](this);break;} new sz(p)[eP(c0.p)](0,166,[])";
  const live54260Catch =
    "if(pD=pv[pq],pD!==pD)return pv[pb];switch(pv[pq]=pa[eU(Iw.pJ)](pD,1),pH=pv[pB]^pa[eU(Iw.ki)](pa[eU(Iw.pv)](pF[pD],160)+256,255),py=pv[pB]+pH,pv[pB]=pa[eU(Iw.kA)](pa[eU(Iw.kR)](54260*(py*py),pa[eU(Iw.pB)](py,43539)),20295)&255,pH){case 191:s7[eU(Iw.kJ)](this);break;}";
  const live54260F = extractFetchQuadratic(live54260Happy);
  const live54260Fc = extractFetchQuadratic(live54260Catch);
  const live54260Mark = fetchMarkerInSource(live54260Happy);
  const live54260H = injectOpcodeLog(live54260Happy, { jsOnly: true });
  const live54260C = injectOpcodeLog(live54260Catch, { jsOnly: true });
  const live54260PlusHappy =
    "if(x=pv[pq],x!==x)return pv[pb];switch(pv[pq]=x+1,x=pv[pB]^pa[ey(ID.pB)](pF[x]-160,256)&255.77,L=pv[pB]+x,pv[pB]=pa[ey(ID.e)](54260*(L*L)+43539*L+20295,255),x){case 191:s7[ey(ID.pQ)](this);break;} new sz(p)[eP(c0.p)](0,166,[])";
  const live54260PlusCatch =
    "if(pD=pv[pq],pa[ey(ID.kE)](pD,pD))return pv[pb];switch(pv[pq]=pa[ey(ID.x)](pD,1),pH=pa[ey(ID.L)](pv[pB],pa[ey(ID.kY)](pF[pD],160)+256&255),py=pv[pB]+pH,pv[pB]=pa[ey(ID.e)](pa[ey(ID.kl)](pa[ey(ID.pv)](py,py),54260)+43539*py+20295,255),pH){case 191:s7[ey(ID.kr)](this);break;}";
  const live54260PlusF = extractFetchQuadratic(live54260PlusHappy);
  const live54260PlusH = injectOpcodeLog(live54260PlusHappy, { jsOnly: true });
  const live54260PlusC = injectOpcodeLog(live54260PlusCatch, { jsOnly: true });
  const live54260AmpHappy =
    "if(B=KI[KQ],B!==B)return KI[Kd];switch(KI[KQ]=KA[iX(fU.KJ)](B,1),B=KA[iX(fU.Kp)](KI[KJ],96+KS[B]&255.77),W=KA[iX(fU.KJ)](KI[KJ],B),KI[KJ]=255&W*W*54260+W*43539+20295,B){case 191:x8[iX(fU.KS)](this);break;} new sz(p)[eP(c0.p)](0,166,[])";
  const live54260AmpCatch =
    "if(KE=KI[KQ],KA[iX(fU.g)](KE,KE))return KI[Kd];switch(KI[KQ]=KE+1,Kw=KI[KJ]^KA[iX(fU.Ug)](KA[iX(fU.UB)](KA[iX(fU.UW)](KS[KE],160),256),255),KP=KA[iX(fU.Uk)](KI[KJ],Kw),KI[KJ]=KA[iX(fU.KA)](54260*(KP*KP),43539*KP)+20295&255,Kw){case 191:x8[iX(fU.UT)](this);break;}";
  const live54260AmpF = extractFetchQuadratic(live54260AmpHappy);
  const live54260AmpH = injectOpcodeLog(live54260AmpHappy, { jsOnly: true });
  const live54260AmpC = injectOpcodeLog(live54260AmpCatch, { jsOnly: true });
  const live54260NestHappy =
    "if(x=pj[pB],pv[en(IT.pQ)](x,x))return pj[pD];switch(pj[pB]=x+1,x=pj[pQ]^pv[en(IT.N)](pv[en(IT.x)](pg[x],160)+256,255),L=pj[pQ]+x,pj[pQ]=pv[en(IT.pF)](pv[en(IT.pF)](pv[en(IT.pg)](L*L,54260),L*43539),20295)&255.77,x){case 191:s8[en(IT.po)](this);break;} new sz(p)[eP(c0.p)](0,166,[])";
  const live54260NestCatch =
    "switch(pj[pB]=pv[en(IT.kY)](pH,1),py=pj[pQ]^255&96+pg[pH],pU=pj[pQ]+py,pj[pQ]=pv[en(IT.pj)](pU*pU*54260+43539*pU,20295)&255,py){case 191:s8[en(IT.kl)](this);break;}";
  const live54260NestF = extractFetchQuadratic(live54260NestHappy);
  const live54260NestFc = extractFetchQuadratic(live54260NestCatch);
  const live54260NestSwitch = fetchLoopSwitchLogSites(
    live54260NestHappy,
    live54260NestHappy.indexOf("54260"),
  );
  const caseCallLogSrc =
    "L=st[k]+x,st[k]=255&L*L*54260+L*43539+20295,x){case 220:Jj[Hq](this);break;case 151:JY[Hq](this);break;case 1:Amb[Hq](this);break;} function Jj(a){return a} function JY(a){return a} function Amb(a){return a} function Amb2(a){return a}";
  const caseCallSw = fetchLoopSwitchLogSites(caseCallLogSrc, caseCallLogSrc.indexOf("54260"));
  const caseCallLogs = fetchLoopCaseCallLogSites(
    caseCallLogSrc,
    caseCallLogSrc.indexOf("54260"),
    caseCallSw,
  );
  const switchKwSites = fetchLoopSwitchKeywordSites(live54260NestHappy, live54260NestSwitch);
  const live54260HelperPair =
    "Kv[iX(Os.g)](W,W)*54260+Kv[iX(Os.KQ)](W,43539),20295)&255,B){case 191:x7[iX(Os.KJ)](this);break;";
  const live54260HelperPairF = extractFetchQuadratic(live54260HelperPair);
  const switchAmp = fetchLoopSwitchLogSites(live54260AmpHappy, live54260AmpHappy.indexOf("54260"));
  const switchHp = fetchLoopSwitchLogSites(
    live54260HelperPair,
    live54260HelperPair.indexOf("54260"),
  );
  const switchCatch = fetchLoopSwitchLogSites(
    "if(Kd=KA[KZ],Kd!==Kd)return KA[Kh];switch(KA[KZ]=Kd+1,KE=Kv[iX(Os.K)](KA[KQ],Kv[iX(Os.KG)](Kv[iX(Os.a)](Kp[Kd]-160,256),255)),Kw=KA[KQ]+KE,KA[KQ]=Kv[iX(Os.Uo)](Kv[iX(Os.Us)](Kw*Kw,54260),Kv[iX(Os.g)](Kw,43539))+20295&255.01,KE){case 191:x7[iX(Os.U1)](this);break;",
    0,
  );
  const falseLinFirst =
    "x=8696)+44379&255,j){case 143:zz();}" + live55067Bmix;
  const falseLinFirstF = extractFetchQuadratic(falseLinFirst);
  const falseLinFirstS = extractFetchSchedule(falseLinFirst);
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
  const finCase = finalizeFetchLoopRows([
    {
      via: "fetchLoop",
      pcSlot: 462740,
      caseOp: 26,
      opFrom: "caseLabel",
      keySlot: 185,
      byteAtPcMinus1: 62,
      bcLen: 463076,
    },
  ]);
  const stubDropped = finalizeFetchLoopRows([
    {
      via: "fetchLoop",
      pcSlot: 1195,
      caseOp: 127,
      opFrom: "caseLabel",
      keySlot: 155,
      byteAtPcMinus1: 172,
      bcLen: 5206,
    },
  ]);
  const outerWidthIgnored = finalizeFetchLoopRows([
    {
      via: "fetchLoop",
      pcSlot: 10,
      caseOp: 35,
      opFrom: "caseLabel",
      keySlot: 9,
      mix: 1922,
      byteAtPcMinus1: 1,
      bcLen: 50000,
    },
  ]);
  const handlerSrc =
    "switch(Q){case 220:Jj[Hq](this);break;case 151:JY[Hq](this);break;case 1:L[Hq](this);break;case 2:L[Hq](this);break;} function Jj(a){return a} function JY(a){return a} function L(a){return a}";
  const handlerSites = fetchLoopHandlerSites(handlerSrc, handlerSrc.indexOf("switch"));
  const uniqueCalls = fetchLoopUniqueCallSites(handlerSrc, handlerSrc.indexOf("switch"));
  const jjCall = uniqueCalls.find((x) => x.name === "Jj");
  const handlerThisGSrc =
    "switch(Q){case 220:Jj[Hq](this);break;} function Jj(a){var z=this.g;return z}";
  const handlerThisGSites = fetchLoopHandlerSites(
    handlerThisGSrc,
    handlerThisGSrc.indexOf("switch"),
  );
  const braceSites = fetchLoopUniqueBraceSites(handlerThisGSrc, handlerThisGSrc.indexOf("switch"));
  const stackMap = new Map([
    ["W", 58],
    ["s9", 205],
    ["sl", 24],
  ]);
  const stackAmb = new Set(["J"]);
  const stackSl = uniqueOpFromFrameNames(
    ["x.<computed>", "sl", "sz"],
    stackMap,
    stackAmb,
  );
  const stackW = uniqueOpFromFrameNames(["W", "s9"], stackMap, stackAmb);
  const stackJ = uniqueOpFromFrameNames(["J", "sz"], stackMap, stackAmb);
  const pausedSl = pausedUniqueHandler(
    ["x.<computed>", "sl", "sz"],
    stackMap,
    stackAmb,
  );
  const pausedJ = pausedUniqueHandler(["J", "s9"], stackMap, stackAmb);
  const pausedS4 = pausedUniqueHandler(["s4", "sh"], new Map([["s4", 51], ["sh", 1]]), stackAmb);
  handlerNameToOp.set("s4", 51);
  const finBpNotStack = finalizeFetchLoopRows([
    {
      via: "fetchLoop",
      pcSlot: 160976,
      caseOp: 33,
      opFrom: "caseLabel",
      fn: "s0",
      bpName: "s0",
      frameNames: ["s4", "sh"],
      keySlot: 22,
      byteAtPcMinus1: 53,
      bcLen: 50000,
    },
  ]);
  handlerNameToOp.delete("s4");
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
      injectIframe === false &&
      packed2Mark &&
      packed2Mark.marker === "23196" &&
      packed2Sched &&
      packed2Sched.keyMul === 23196 &&
      packed2Sched.keyQuadB === 32619 &&
      packed2Sched.keyAdd === 19372 &&
      packed2Sched.byteBias === 217 &&
      packed2Sched.firstSwitchCase === 220 &&
      packed2Entry === 63 &&
      live55067F &&
      live55067F.keyMul === 55067 &&
      live55067F.keyQuadB === 8696 &&
      live55067F.keyAdd === 44379 &&
      live55067F.byteBias === 83 &&
      live55067F.firstSwitchCase === 143 &&
      live55067Fc &&
      live55067Fc.keyMul === 55067 &&
      live55067Mark &&
      live55067Mark.marker === "55067" &&
      live55067BmixF &&
      live55067BmixF.keyMul === 55067 &&
      live55067BmixF.keyQuadB === 8696 &&
      live55067BmixF.keyAdd === 44379 &&
      live55067BmixMark &&
      live55067BmixMark.marker === "55067" &&
      live55067HelperPairF &&
      live55067HelperPairF.keyMul === 55067 &&
      live55067HelperPairF.keyQuadB === 8696 &&
      live55067HelperPairF.keyAdd === 44379 &&
      live55067PairCommaF &&
      live55067PairCommaF.keyMul === 55067 &&
      live55067PairCommaF.keyQuadB === 8696 &&
      live55067PairCommaF.keyAdd === 44379 &&
      live55067CatchPlusF &&
      live55067CatchPlusF.keyMul === 55067 &&
      live55067CatchPlusF.keyQuadB === 8696 &&
      live55067CatchPlusF.keyAdd === 44379 &&
      live55067CatchPlusF.byteBias === 83 &&
      live54260F &&
      live54260F.keyMul === 54260 &&
      live54260F.keyQuadB === 43539 &&
      live54260F.keyAdd === 20295 &&
      live54260F.byteBias === 160 &&
      live54260F.firstSwitchCase === 191 &&
      live54260Mark &&
      live54260Mark.schedule &&
      live54260Mark.schedule.initKeyCandidate === 166 &&
      live54260Fc &&
      live54260Fc.keyMul === 54260 &&
      live54260Fc.keyQuadB === 43539 &&
      live54260Fc.keyAdd === 20295 &&
      live54260Mark &&
      live54260Mark.marker === "54260" &&
      live54260H.injected &&
      live54260H.html.includes("__cfOp.push") &&
      live54260H.html.includes("pc:x") &&
      live54260C.injected &&
      live54260C.html.includes("__cfOp.push") &&
      live54260C.html.includes("pc:pD") &&
      live54260PlusF &&
      live54260PlusF.keyMul === 54260 &&
      live54260PlusF.keyQuadB === 43539 &&
      live54260PlusF.keyAdd === 20295 &&
      live54260PlusF.byteBias === 160 &&
      live54260PlusH.injected &&
      live54260PlusH.html.includes("__cfOp.push") &&
      live54260PlusH.html.includes("pc:x") &&
      live54260PlusC.injected &&
      live54260PlusC.html.includes("__cfOp.push") &&
      live54260PlusC.html.includes("pc:pD") &&
      live54260AmpF &&
      live54260AmpF.keyMul === 54260 &&
      live54260AmpF.keyQuadB === 43539 &&
      live54260AmpF.keyAdd === 20295 &&
      live54260AmpF.byteBias === 160 &&
      live54260AmpH.injected &&
      live54260AmpH.html.includes("__cfOp.push") &&
      live54260AmpH.html.includes("pc:B") &&
      live54260AmpC.injected &&
      live54260AmpC.html.includes("__cfOp.push") &&
      live54260HelperPairF &&
      live54260HelperPairF.keyMul === 54260 &&
      live54260HelperPairF.keyQuadB === 43539 &&
      live54260HelperPairF.keyAdd === 20295 &&
      switchAmp.length === 1 &&
      switchAmp[0].why === "switchBrace" &&
      switchAmp[0].opVar === "B" &&
      switchAmp[0].mixVar === "W" &&
      switchAmp[0].caseOp === 191 &&
      switchAmp[0].condition.includes('via:"switchLog"') &&
      switchAmp[0].condition.includes("return false") &&
      live54260AmpHappy.slice(switchAmp[0].idx, switchAmp[0].idx + 1) === "{" &&
      switchHp.length === 1 &&
      switchHp[0].opVar === "B" &&
      switchHp[0].caseOp === 191 &&
      switchCatch.length === 1 &&
      switchCatch[0].opVar === "KE" &&
      switchCatch[0].mixVar === "Kw" &&
      live54260NestF &&
      live54260NestF.keyMul === 54260 &&
      live54260NestF.keyQuadB === 43539 &&
      live54260NestF.keyAdd === 20295 &&
      live54260NestF.byteBias === 160 &&
      live54260NestF.spelling === "helper(mix*mix,mul),mix*b),add)&255" &&
      live54260NestFc &&
      live54260NestFc.keyMul === 54260 &&
      live54260NestFc.keyQuadB === 43539 &&
      live54260NestFc.keyAdd === 20295 &&
      live54260NestSwitch.length === 1 &&
      live54260NestSwitch[0].opVar === "x" &&
      live54260NestSwitch[0].mixVar === "L" &&
      switchKwSites.length === 1 &&
      live54260NestHappy.slice(switchKwSites[0].idx, switchKwSites[0].idx + 6) === "switch" &&
      caseCallSw.length === 1 &&
      caseCallLogs.some((x) => x.why === "caseCallLog" && x.caseOp === 220 && x.name === "Jj") &&
      caseCallLogs.some((x) => x.why === "caseCallLog" && x.caseOp === 151 && x.name === "JY") &&
      caseCallLogSrc.slice(caseCallLogs.find((x) => x.name === "Jj").idx, caseCallLogs.find((x) => x.name === "Jj").idx + 2) === "Jj" &&
      injectIframe === false &&
      falseLinFirstF &&
      falseLinFirstF.keyMul === 55067 &&
      falseLinFirstS &&
      falseLinFirstS.keyMul === 55067 &&
      falseLinFirstS.kind === "quadratic" &&
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
      live23196Sites.some((x) => x.why === "caseCall" && x.caseOp === 220) &&
      live23196Sites.some((x) => x.why === "case" && x.caseOp === 220) &&
      handlerSites.some((x) => x.why === "handlerFn" && x.caseOp === 220 && x.name === "Jj") &&
      handlerSites.some((x) => x.why === "handlerFn" && x.caseOp === 151 && x.name === "JY") &&
      handlerSites.every((x) => x.name !== "L") &&
      uniqueCalls.some((x) => x.why === "handlerCall" && x.caseOp === 220 && x.name === "Jj") &&
      uniqueCalls.some((x) => x.why === "handlerCall" && x.caseOp === 151 && x.name === "JY") &&
      uniqueCalls.every((x) => x.name !== "L") &&
      jjCall &&
      handlerSrc.slice(jjCall.idx, jjCall.idx + 8) === "case 220" &&
      braceSites.some(
        (x) =>
          x.why === "handlerFn" &&
          x.name === "Jj" &&
          handlerThisGSrc.slice(x.idx, x.idx + 1) === "{",
      ) &&
      handlerThisGSites.some(
        (x) =>
          x.why === "handlerFn" &&
          x.name === "Jj" &&
          handlerThisGSrc.slice(x.idx, x.idx + 6) === "this.g",
      ) &&
      stackSl &&
      stackSl.op === 24 &&
      stackSl.name === "sl" &&
      stackW &&
      stackW.name === "W" &&
      stackJ == null &&
      pausedSl &&
      pausedSl.op === 24 &&
      pausedSl.name === "sl" &&
      pausedJ == null &&
      pausedS4 &&
      pausedS4.name === "s4" &&
      finBpNotStack[0] &&
      finBpNotStack[0].op === 33 &&
      finBpNotStack[0].fn === "s0" &&
      svg8904 == null &&
      fin[0] &&
      fin[0].pc === 0 &&
      fin[0].op === 220 &&
      fin[0].key === 63 &&
      fin[0].byte === 77 &&
      finCase[0] &&
      finCase[0].pc === 462739 &&
      finCase[0].op === 26 &&
      finCase[0].nextKey === 185 &&
      finCase[0].key == null &&
      finCase[0].byte === 62 &&
      stubDropped.length === 0 &&
      outerWidthIgnored[0] &&
      outerWidthIgnored[0].op === 35 &&
      outerWidthIgnored[0].mix == null &&
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
const fetchLoopBpMeta = new Map();
const scriptSources = new Map();
const scriptNotes = [];
let iframeRewrites = 0;
let foInitResponse = null;
let fetchLoopCleared = false;
let fetchLoopBpPlaced = 0;
let fetchLoopBpFailed = 0;

async function removeFetchLoopBreakpoint(session, breakpointId) {
  await session
    .send("Debugger.removeBreakpoint", { breakpointId })
    .catch(() => {});
  fetchLoopBreakpoints.delete(breakpointId);
  fetchLoopBpMeta.delete(breakpointId);
}

async function removeFetchLoopBreakpointsForCaseOp(caseOp) {
  if (caseOp == null) return;
  const ids = [];
  for (const [id, meta] of fetchLoopBpMeta) {
    if (meta && meta.caseOp === caseOp) ids.push(id);
  }
  for (const id of ids) {
    const row = fetchLoopBpRows.find((r) => r.breakpointId === id);
    if (row) await removeFetchLoopBreakpoint(row.session, id);
  }
}

async function clearFetchLoopBreakpoints() {
  if (fetchLoopCleared) return;
  fetchLoopCleared = true;
  for (const row of fetchLoopBpRows) {
    await removeFetchLoopBreakpoint(row.session, row.breakpointId);
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
        if (injectIframe && fetchTuples && iframeRewrites === 1) {
          const inj = injectOpcodeLog(text);
          if (inj.injected && inj.html.includes("__cfOp.push")) {
            const headers = (evt.responseHeaders || []).filter(
              (h) => !/^(content-encoding|content-length)$/i.test(h.name),
            );
            headers.push({
              name: "Content-Length",
              value: String(Buffer.byteLength(inj.html)),
            });
            await session.send("Fetch.fulfillRequest", {
              requestId: evt.requestId,
              responseCode: evt.responseStatusCode || 200,
              responseHeaders: headers,
              body: Buffer.from(inj.html).toString("base64"),
            });
            try {
              fs.writeFileSync(
                path.join(outDir, `iframe-rewritten-${iframeRewrites}.html`),
                inj.html.slice(0, 400000),
              );
            } catch {}
            note("iframeRewrite", {
              url: reqUrl,
              injected: true,
              replacements: inj.replacements,
              bytes: inj.html.length,
              via: "fetchTuplesInject",
              fetchSchedule: extractFetchSchedule(text),
              hasRunProgram: text.includes("runProgram"),
            });
            return;
          }
        }
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
  const add = (idx, why, caseOp) => {
    if (idx == null || idx < 0 || seen.has(idx)) return;
    seen.add(idx);
    const op = caseOp != null ? caseOp : caseOpAt(src, idx);
    sites.push({ idx, why, caseOp: op, ...sourceLineCol(src, idx) });
  };
  const window = src.slice(Math.max(0, markerIdx - 400), markerIdx + 25000);
  const winStart = Math.max(0, markerIdx - 400);
  let from = 0;
  let n = 0;
  while (n < 80) {
    const i = window.indexOf("case ", from);
    if (i < 0) break;
    const slice = window.slice(i, i + 12);
    const m = slice.match(/^case (\d+):/);
    if (m) {
      const abs = winStart + i;
      const op = Number(m[1]);
      const colon = window.indexOf(":", i);
      let callIdx = abs;
      if (colon >= 0) {
        let j = colon + 1;
        while (j < window.length && window[j] === " ") j++;
        callIdx = winStart + j;
      }
      add(callIdx, "caseCall", op);
      add(abs, "case", op);
      n++;
    }
    from = i + 5;
  }
  const sw = window.lastIndexOf("switch(", markerIdx - winStart);
  if (sw >= 0) add(winStart + sw, "switch");
  const iff = window.lastIndexOf("if(", markerIdx - winStart);
  if (iff >= 0) add(winStart + iff, "if");
  return sites;
}

function collectHandlerCaseOps(src, markerIdx) {
  const byName = new Map();
  if (!src || markerIdx == null || markerIdx < 0) return byName;
  const window = src.slice(Math.max(0, markerIdx - 400), markerIdx + 25000);
  const re = /case (\d+):(\w+)[\[(]/g;
  let m;
  while ((m = re.exec(window))) {
    const op = Number(m[1]);
    const name = m[2];
    if (!byName.has(name)) byName.set(name, new Set());
    byName.get(name).add(op);
  }
  return byName;
}

function recordAmbiguousHandlerNames(src, markerIdx) {
  const byName = collectHandlerCaseOps(src, markerIdx);
  for (const [name, ops] of byName) {
    if (ops.size !== 1) {
      ambiguousHandlerNames.add(name);
      handlerNameToOp.delete(name);
    }
  }
  return byName;
}

function uniqueNamedFunctionIdx(src, name) {
  if (!src || !name) return null;
  const pat = `function ${name}(`;
  let from = 0;
  let count = 0;
  let first = -1;
  while (from < src.length) {
    const i = src.indexOf(pat, from);
    if (i < 0) break;
    if (first < 0) first = i;
    count++;
    from = i + pat.length;
  }
  if (count !== 1 || first < 0) return null;
  return first;
}

/** `this.g` inside a unique handler. Body BPs snap past PW++; live capture uses call sites. */
function uniqueHandlerEntryIdx(src, name) {
  if (!src || !name) return null;
  const first = uniqueNamedFunctionIdx(src, name);
  if (first == null) return null;
  const brace = src.indexOf("{", first);
  if (brace < 0) return null;
  const nextFn = src.indexOf("function ", brace + 1);
  const thisG = src.indexOf("this.g", brace);
  if (
    thisG >= 0 &&
    (nextFn < 0 || thisG < nextFn) &&
    thisG - brace < 4000
  ) {
    return thisG;
  }
  return brace;
}

/** Unique `case N:name[` in the fetch switch (after decode, before handler). */
function fetchLoopUniqueCallSites(src, markerIdx) {
  if (!src || markerIdx == null || markerIdx < 0) return [];
  const byName = collectHandlerCaseOps(src, markerIdx);
  const winStart = Math.max(0, markerIdx - 400);
  const window = src.slice(winStart, markerIdx + 25000);
  const sites = [];
  const seenOp = new Set();
  const re = /case (\d+):(\w+)[\[(]/g;
  let m;
  while ((m = re.exec(window))) {
    const op = Number(m[1]);
    const name = m[2];
    const ops = byName.get(name);
    if (!ops || ops.size !== 1 || [...ops][0] !== op) continue;
    if (uniqueNamedFunctionIdx(src, name) == null) continue;
    if (seenOp.has(op)) continue;
    seenOp.add(op);
    const idx = winStart + m.index;
    sites.push({
      idx,
      why: "handlerCall",
      caseOp: op,
      name,
      ...sourceLineCol(src, idx),
    });
  }
  return sites;
}

function matchingBraceIdx(src, brace) {
  if (brace == null || brace < 0) return -1;
  let depth = 0;
  for (let i = brace; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function handlerImmediateBound(src, name) {
  const first = uniqueNamedFunctionIdx(src, name);
  if (first == null) return null;
  const brace = src.indexOf("{", first);
  if (brace < 0) return null;
  const end = matchingBraceIdx(src, brace);
  const thisG = src.indexOf("this.g", brace);
  const plus =
    thisG >= 0 && (end < 0 || thisG < end) ? src.indexOf("++", thisG) : -1;
  return { brace, end, thisG, plus };
}

/** Function `{` for unique handlers — VM slots are post-fetch, body has not run PW++. */
function fetchLoopUniqueBraceSites(src, markerIdx) {
  if (!src || markerIdx == null || markerIdx < 0) return [];
  const byName = collectHandlerCaseOps(src, markerIdx);
  const sites = [];
  const seenIdx = new Set();
  for (const [name, ops] of byName) {
    if (ops.size !== 1) continue;
    if (uniqueNamedFunctionIdx(src, name) == null) continue;
    const first = uniqueNamedFunctionIdx(src, name);
    const brace = src.indexOf("{", first);
    if (brace < 0 || seenIdx.has(brace)) continue;
    seenIdx.add(brace);
    sites.push({
      idx: brace,
      why: "handlerFn",
      caseOp: [...ops][0],
      name,
      ...sourceLineCol(src, brace),
    });
  }
  return sites;
}

function fetchLoopHandlerSites(src, markerIdx) {
  if (!src || markerIdx == null || markerIdx < 0) return [];
  const byName = collectHandlerCaseOps(src, markerIdx);
  const sites = [];
  const seenIdx = new Set();
  for (const [name, ops] of byName) {
    if (ops.size !== 1) continue;
    if (uniqueNamedFunctionIdx(src, name) == null) continue;
    const idx = uniqueHandlerEntryIdx(src, name);
    if (idx == null || seenIdx.has(idx)) continue;
    seenIdx.add(idx);
    sites.push({
      idx,
      why: "handlerFn",
      caseOp: [...ops][0],
      name,
      ...sourceLineCol(src, idx),
    });
  }
  return sites;
}

async function resolveBreakpointLocation(session, loc) {
  try {
    const r = await session.send("Debugger.getPossibleBreakpoints", {
      start: {
        scriptId: loc.scriptId,
        lineNumber: loc.lineNumber,
        columnNumber: Math.max(0, loc.columnNumber),
      },
      end: {
        scriptId: loc.scriptId,
        lineNumber: loc.lineNumber,
        columnNumber: loc.columnNumber + 64,
      },
    });
    const hit = (r.locations || []).find((l) => l && typeof l.columnNumber === "number");
    if (hit) {
      return {
        scriptId: hit.scriptId || loc.scriptId,
        lineNumber: hit.lineNumber,
        columnNumber: hit.columnNumber,
        why: loc.why,
        caseOp: loc.caseOp,
        name: loc.name,
        condition: loc.condition,
        idx: loc.idx,
        switchLog: loc.switchLog,
        resolvedFrom: "possible",
      };
    }
  } catch {}
  return loc;
}

async function trySetFetchLoopBp(session, s, scriptSource, loc) {
  const resolved = await resolveBreakpointLocation(session, loc);
  const attempts = [];
  const seenAttempt = new Set();
  for (const attempt of [loc, resolved]) {
    if (!attempt) continue;
    const k = `${attempt.lineNumber}:${attempt.columnNumber}`;
    if (seenAttempt.has(k)) continue;
    seenAttempt.add(k);
    attempts.push(attempt);
  }
  for (let i = 0; i < attempts.length; i++) {
    const attempt = attempts[i];
    try {
      const bp = await session.send("Debugger.setBreakpoint", {
        location: {
          scriptId: attempt.scriptId || s.scriptId,
          lineNumber: attempt.lineNumber,
          columnNumber: attempt.columnNumber,
        },
        condition: attempt.condition || loc.condition || FETCH_LOOP_BP_CONDITION,
      });
      if (!bp?.breakpointId) continue;
      const actual = bp.actualLocation;
      const reqIdx = indexFromLineCol(
        scriptSource,
        attempt.lineNumber,
        attempt.columnNumber,
      );
      const actIdx =
        actual && typeof actual.columnNumber === "number"
          ? indexFromLineCol(scriptSource, actual.lineNumber, actual.columnNumber)
          : reqIdx;
      const bound =
        loc.why === "switchBrace" || loc.switchLog
          ? null
          : loc.name
            ? handlerImmediateBound(scriptSource, loc.name)
            : null;
      const snappedPastImm =
        bound &&
        bound.plus >= 0 &&
        actIdx != null &&
        actIdx >= bound.plus;
      const snappedOutside =
        bound &&
        actIdx != null &&
        (actIdx < bound.brace || (bound.end >= 0 && actIdx > bound.end));
      const braceIdx = loc.idx;
      const snappedBeforeSwitchBrace =
        loc.why === "switchBrace" &&
        actIdx != null &&
        braceIdx != null &&
        actIdx < braceIdx;
      const snappedIntoCaseBody =
        loc.why === "switchBrace" &&
        actIdx != null &&
        braceIdx != null &&
        actIdx > braceIdx + 20;
      const snappedToHandlerFn =
        loc.why === "caseCallLog" &&
        actIdx != null &&
        loc.idx != null &&
        Math.abs(actIdx - loc.idx) > 80;
      if (
        snappedPastImm ||
        snappedOutside ||
        snappedBeforeSwitchBrace ||
        snappedIntoCaseBody ||
        snappedToHandlerFn
      ) {
        await session
          .send("Debugger.removeBreakpoint", { breakpointId: bp.breakpointId })
          .catch(() => {});
        fetchLoopBpFailed++;
        note("fetchLoopBpSnapped", {
          why: loc.why,
          name: loc.name || null,
          caseOp: loc.caseOp ?? null,
          req: reqIdx,
          act: actIdx,
          plus: bound && bound.plus,
          brace: bound && bound.brace,
          pastImm: !!snappedPastImm,
          outside: !!snappedOutside,
          beforeSwitchBrace: !!snappedBeforeSwitchBrace,
          intoCaseBody: !!snappedIntoCaseBody,
          toHandlerFn: !!snappedToHandlerFn,
        });
        continue;
      }
      fetchLoopBreakpoints.add(bp.breakpointId);
      fetchLoopBpRows.push({ session, breakpointId: bp.breakpointId });
      const resolvedOp =
        loc.caseOp != null
          ? loc.caseOp
          : caseOpAt(
              scriptSource,
              indexFromLineCol(scriptSource, attempt.lineNumber, attempt.columnNumber),
            );
      fetchLoopBpMeta.set(bp.breakpointId, {
        caseOp: loc.why === "switchBrace" ? null : resolvedOp,
        why: loc.why,
        name: loc.name,
        switchLog: loc.why === "switchBrace",
        lineNumber: actual?.lineNumber ?? attempt.lineNumber,
        columnNumber: actual?.columnNumber ?? attempt.columnNumber,
        scriptId: s.scriptId,
      });
      if (
        (loc.why === "handlerFn" || loc.why === "handlerCall") &&
        loc.name &&
        resolvedOp != null
      ) {
        handlerNameToOp.set(loc.name, resolvedOp);
      }
      fetchLoopBpPlaced++;
      note("fetchLoopBp", {
        url: (s.url || "").slice(0, 140),
        why: loc.why,
        name: loc.name || null,
        caseOp: resolvedOp ?? null,
        lineNumber: attempt.lineNumber,
        columnNumber: attempt.columnNumber,
        actualLine: actual?.lineNumber ?? null,
        actualColumn: actual?.columnNumber ?? null,
        breakpointId: bp.breakpointId,
        resolvedFrom: attempt.resolvedFrom || "exact",
      });
      return `${attempt.lineNumber}:${attempt.columnNumber}`;
    } catch (e) {
      fetchLoopBpFailed++;
      note("bpErr", {
        error: String(e).slice(0, 180),
        why: loc.why,
        caseOp: loc.caseOp ?? null,
        lineNumber: attempt.lineNumber,
        columnNumber: attempt.columnNumber,
      });
    }
  }
  return null;
}

async function setFetchLoopBreakpointNear(session, s, scriptSource, idx) {
  scriptSources.set(s.scriptId, scriptSource);
  recordAmbiguousHandlerNames(scriptSource, idx);
  if (fetchTuples) {
    const switchSites = fetchLoopSwitchLogSites(scriptSource, idx);

    async function possibleInSwitchRange() {
      const found = [];
      const seen = new Set();
      for (const site of switchSites) {
        const sw = scriptSource.lastIndexOf("switch(", site.idx);
        if (sw < 0) continue;
        const start = sourceLineCol(scriptSource, sw);
        const endCol = site.columnNumber + 48;
        try {
          const r = await session.send("Debugger.getPossibleBreakpoints", {
            start: {
              scriptId: s.scriptId,
              lineNumber: start.lineNumber,
              columnNumber: start.columnNumber,
            },
            end: {
              scriptId: s.scriptId,
              lineNumber: site.lineNumber,
              columnNumber: endCol,
            },
          });
          for (const loc of r.locations || []) {
            const k = `${loc.lineNumber}:${loc.columnNumber}`;
            if (seen.has(k)) continue;
            seen.add(k);
            const at = indexFromLineCol(scriptSource, loc.lineNumber, loc.columnNumber);
            found.push({
              ...site,
              idx: at,
              why: "switchPossible",
              lineNumber: loc.lineNumber,
              columnNumber: loc.columnNumber,
            });
          }
        } catch (e) {
          note("possibleBpErr", { error: String(e).slice(0, 180) });
        }
      }
      note("fetchLoopSwitchPossible", {
        n: found.length,
        cols: found.map((x) => x.columnNumber).slice(0, 16),
      });
      return found;
    }

    async function placeLogSites(sites, via) {
      let n = 0;
      const seen = new Set();
      for (const site of sites || []) {
        const colKey = `${site.lineNumber}:${site.columnNumber}`;
        if (seen.has(colKey)) continue;
        const used = await trySetFetchLoopBp(session, s, scriptSource, {
          scriptId: s.scriptId,
          lineNumber: site.lineNumber,
          columnNumber: site.columnNumber,
          why: site.why,
          caseOp: site.caseOp,
          name: site.name || site.opVar,
          condition: site.condition,
          idx: site.idx,
          switchLog: true,
        });
        if (used) {
          seen.add(used);
          seen.add(colKey);
          n++;
        }
      }
      if (n) {
        note("fetchLoopBpSummary", {
          placed: fetchLoopBpPlaced,
          failed: fetchLoopBpFailed,
          thisScript: n,
          switchLog: n,
          via,
          skippedUniqueBraces: true,
        });
      }
      return n;
    }

    note("fetchLoopSwitchSites", {
      n: switchSites.length,
      sites: switchSites.map((x) => ({
        why: x.why,
        opVar: x.opVar,
        mixVar: x.mixVar,
        caseOp: x.caseOp,
        lineNumber: x.lineNumber,
        columnNumber: x.columnNumber,
      })),
    });
    if (await placeLogSites(switchSites, "switchBrace")) return true;
    if (await placeLogSites(await possibleInSwitchRange(), "switchPossible")) return true;
    if (await placeLogSites(fetchLoopSwitchKeywordSites(scriptSource, switchSites), "switchKw")) {
      return true;
    }
    const callLogs = fetchLoopCaseCallLogSites(scriptSource, idx, switchSites);
    note("fetchLoopCaseCallLogSites", { n: callLogs.length });
    if (await placeLogSites(callLogs, "caseCallLog")) return true;
    note("fetchLoopSwitchLogMiss", {
      n: switchSites.length,
      error: switchSites.length
        ? "Could not resolve switchBrace/switchKw/caseCallLog"
        : "no ,op){case N: near fetch marker",
    });
    return false;
  }
  const sites = fetchLoopBreakpointSites(scriptSource, idx);
  const uniqueCalls = fetchLoopUniqueCallSites(scriptSource, idx);
  const braces = fetchLoopUniqueBraceSites(scriptSource, idx);
  const handlers = fetchLoopHandlerSites(scriptSource, idx);
  const { lineNumber, columnNumber } = sourceLineCol(scriptSource, idx);
  const caseCalls = sites.filter((x) => x.why === "caseCall");
  const cases = sites.filter((x) => x.why === "case");
  const rest = sites.filter((x) => x.why !== "caseCall" && x.why !== "case");
  const fallback = [
    ...cases.slice(12),
    ...caseCalls.slice(12),
    { scriptId: s.scriptId, lineNumber, columnNumber, why: "marker", caseOp: null },
    ...rest,
  ];
  const preferred = braces.length ? braces : uniqueCalls.length ? uniqueCalls : handlers;
  const tries = (preferred.length ? preferred : fallback).map((site) => ({
    scriptId: s.scriptId,
    lineNumber: site.lineNumber,
    columnNumber: site.columnNumber,
    why: site.why,
    caseOp: site.caseOp,
    name: site.name,
  }));
  note("fetchLoopSites", {
    n: sites.length,
    uniqueCalls: uniqueCalls.length,
    braces: braces.length,
    handlers: handlers.length,
    handlerOps: preferred.map((h) => h.caseOp).slice(0, 12),
    whys: tries.map((x) => x.why).slice(0, 8),
    firstCaseCol: sites.find((x) => x.why === "case")?.columnNumber ?? null,
    firstCaseOp: sites.find((x) => x.why === "case")?.caseOp ?? null,
  });
  let placed = 0;
  const seenCol = new Set();
  for (const loc of tries) {
    if (placed >= 48) break;
    const colKey = `${loc.lineNumber}:${loc.columnNumber}`;
    if (seenCol.has(colKey)) continue;
    const used = await trySetFetchLoopBp(session, s, scriptSource, loc);
    if (used) {
      seenCol.add(used);
      seenCol.add(colKey);
      placed++;
    }
  }
  note("fetchLoopBpSummary", {
    placed: fetchLoopBpPlaced,
    failed: fetchLoopBpFailed,
    thisScript: placed,
  });
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
              scriptSources.set(s.scriptId, scriptSource);
              try {
                fs.writeFileSync(
                  path.join(outDir, `executed-fetch-${s.scriptId}.js`),
                  scriptSource.slice(0, 500000),
                );
              } catch {}
              note("scriptFetchConst", {
                url: (s.url || "").slice(0, 140),
                len: scriptSource.length,
                hasInject,
                idx: hit.idx,
                marker: hit.marker,
                fetchSchedule: hit.schedule,
              });
              if (wantFetchLoopBp && !hasInject) {
                const packedHits = liveFetchRaw.filter((r) => (r.bcLen || 0) > 10000).length;
                if (packedHits >= fetchTupleCap && !fetchTuples) {
                  note("fetchLoopSkipNewScript", { reason: "cap", packedHits });
                } else {
                  const patched = await patchExecutedFetchScript(session, s, scriptSource);
                  if (!patched) {
                    await setFetchLoopBreakpointNear(session, s, scriptSource, hit.idx);
                  }
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
        const switchLogHit = hit.some((id) => {
          const meta = fetchLoopBpMeta.get(id);
          return (
            meta &&
            (meta.switchLog ||
              meta.why === "switchBrace" ||
              meta.why === "switchKw" ||
              meta.why === "switchPossible" ||
              meta.why === "caseCallLog")
          );
        });
        if (switchLogHit) {
          note("fetchLoopSwitchLogPause", { n: hit.length });
          return;
        }
        if (fetchHit && frame && liveFetchRaw.length < fetchTupleCap) {
          let callMeta = null;
          for (const id of hit) {
            const meta = fetchLoopBpMeta.get(id);
            if (
              meta &&
              (meta.why === "handlerCall" || meta.why === "handlerFn") &&
              meta.caseOp != null
            ) {
              callMeta = meta;
              break;
            }
          }
          const frames = (evt.callFrames || []).slice(0, 6);
          const frameNames = frames.map((f) => f.functionName || "");
          const pausedH = pausedUniqueHandler(frameNames);
          if (!callMeta && !pausedH) {
            if (fname && ambiguousHandlerNames.has(fname)) {
              note("fetchLoopSkipAmbiguous", { fn: fname });
              return;
            }
            if (fname && String(fname).includes("<computed>")) {
              note("fetchLoopSkipComputed", { fn: fname });
              return;
            }
            if (!fname || !handlerNameToOp.has(fname)) {
              note("fetchLoopSkipNonUniqueFn", { fn: fname || "" });
              return;
            }
            if (frame.location) {
              const srcForFn =
                scriptSources.get(frame.location.scriptId) ||
                scriptSources.get(String(frame.location.scriptId));
              const entry = srcForFn ? uniqueHandlerEntryIdx(srcForFn, fname) : null;
              const pauseIdx = srcForFn
                ? indexFromLineCol(
                    srcForFn,
                    frame.location.lineNumber,
                    frame.location.columnNumber,
                  )
                : null;
              if (
                entry != null &&
                pauseIdx != null &&
                Math.abs(pauseIdx - entry) > 240
              ) {
                note("fetchLoopSkipDeepHandler", {
                  fn: fname,
                  pauseIdx,
                  entry,
                  delta: pauseIdx - entry,
                });
                return;
              }
            }
          }
          const harvestName =
            (callMeta && callMeta.name) || (pausedH && pausedH.name) || fname;
          const row = { via: "fetchLoop", fn: harvestName };
          row.frameNames = frameNames;
          row.hitBreakpoints = hit;
          if (callMeta && callMeta.name) row.bpName = callMeta.name;
          if (frame.location) {
            row.lineNumber = frame.location.lineNumber;
            row.columnNumber = frame.location.columnNumber;
            row.scriptId = frame.location.scriptId;
          }
          let caseOp;
          if (callMeta && callMeta.caseOp != null) {
            caseOp = callMeta.caseOp;
            row.bpWhy = callMeta.why;
            row.opFrom = "caseLabel";
            if (pausedH && pausedH.op !== callMeta.caseOp) {
              row.stackOp = pausedH.op;
              row.stackFn = pausedH.name;
            }
          } else if (pausedH) {
            caseOp = pausedH.op;
            row.bpWhy = "pausedFn";
            row.opFrom = "pausedFn";
          } else {
            for (const id of hit) {
              const meta = fetchLoopBpMeta.get(id);
              if (meta && meta.caseOp != null) {
                caseOp = meta.caseOp;
                row.bpWhy = meta.why;
                if (meta.name) row.bpName = meta.name;
                break;
              }
            }
            const uniqueOp = handlerNameToOp.get(fname);
            if (caseOp != null && uniqueOp != null && caseOp !== uniqueOp) {
              row.bpCaseOp = caseOp;
              row.bpWhy = "pausedFn";
            } else {
              row.bpWhy = row.bpWhy || "handlerFn";
            }
            caseOp = uniqueOp != null ? uniqueOp : caseOp;
            if (caseOp != null) row.opFrom = "caseLabel";
          }
          if (caseOp != null) {
            row.caseOp = caseOp;
            row.op = caseOp & 255;
            row.opFrom = row.opFrom || "caseLabel";
          }
          const harvestFrames = [
            frame,
            ...frames.filter((fr) => fr && fr.callFrameId !== frame.callFrameId),
          ];
          for (const fr of harvestFrames) {
            const frName = fr.functionName || "";
            if (
              fr.callFrameId !== frame.callFrameId &&
              handlerNameToOp.has(frName) &&
              frName !== fname
            ) {
              continue;
            }
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
                row.fn = harvestName || fname || frName || row.fn;
                break;
              }
              if (v && typeof v === "object" && row.thisType == null) {
                Object.assign(row, v);
              }
            } catch (e) {
              row.evalErr = String(e).slice(0, 120);
            }
          }
          if (caseOp != null) {
            row.caseOp = caseOp;
            row.op = caseOp & 255;
            row.opFrom = "caseLabel";
          }
          if ((row.bcLen || 0) <= 10000) {
            return;
          }
          if (
            row.caseOp != null &&
            liveFetchRaw.some((x) => x.caseOp === row.caseOp && (x.bcLen || 0) > 10000)
          ) {
            await removeFetchLoopBreakpointsForCaseOp(row.caseOp);
            return;
          }
          const locals = {};
          for (const sc of frame.scopeChain || []) {
            if (!sc.object?.objectId) continue;
            if (sc.type === "global" || sc.type === "with") continue;
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
          row.locals = locals;
          const mixHit = Object.values(locals).find((v) => v >= 256 && v <= 510);
          if (typeof mixHit === "number") {
            row.mixLocal = mixHit;
            if (
              row.caseOp != null &&
              Number.isFinite(row.keySlot) &&
              ((mixHit - row.caseOp) & 255) !== (row.keySlot & 255)
            ) {
              row.key = (mixHit - row.caseOp) & 255;
            }
          }
          if (Number.isFinite(row.keySlot)) row.nextKey = row.keySlot & 255;
          liveFetchRaw.push(row);
          if (row.caseOp != null) {
            await removeFetchLoopBreakpointsForCaseOp(row.caseOp);
          }
          if (liveFetchRaw.length === 1 || liveFetchRaw.length >= fetchTupleCap) {
            note("fetchLoopTuple", {
              n: liveFetchRaw.length,
              fn: row.fn,
              vmFrom: row.vmFrom,
              thisType: row.thisType,
              hasG: row.hasG,
              pcSlot: row.pcSlot,
              caseOp: row.caseOp,
              opFrom: row.opFrom,
              nextKey: row.nextKey,
              key: row.key,
              bcLen: row.bcLen,
              byteAtPcMinus1: row.byteAtPcMinus1,
              localCount: Object.keys(row.locals || {}).length,
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
const harvestTuples = fetchLoopFinal.filter(isHarvestTuple);
const completeTuples = fetchLoopFinal.filter(isCompleteTuple);
const foNet = network.filter((n) => /\/fo\//.test(n.url || ""));
const firstFo = foNet[0] || null;
const ops = normalizeBreakpointOps([
  ...harvestTuples,
  ...frameDumps.flatMap((f) => f.ops || []),
  ...liveOps,
]);
const switchLogRows = ops.filter(
  (r) => r && r.via === "switchLog" && (isHarvestTuple(r) || isCompleteTuple(r)),
);
const publishedHarvest = harvestTuples.length ? harvestTuples : switchLogRows;
const publishedComplete = completeTuples.length
  ? completeTuples
  : switchLogRows.filter(isCompleteTuple);
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
function fetchScheduleFromCapture(iframeHtml) {
  const fromIframe = extractFetchSchedule(iframeHtml);
  try {
    for (const n of fs.readdirSync(outDir)) {
      if (!n.startsWith("executed-fetch-") || !n.endsWith(".js")) continue;
      const s = extractFetchSchedule(
        fs.readFileSync(path.join(outDir, n), "utf8"),
      );
      if (s && s.keyMul && s.keyQuadB) return s;
    }
  } catch {}
  return fromIframe;
}
const fetchSchedule = fetchScheduleFromCapture(iframeHtml);
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
  fetchLoopBpPlaced,
  fetchLoopBpFailed,
  fetchLoopRawCount: liveFetchRaw.length,
  harvestTupleCount: publishedHarvest.length,
  completeTupleCount: publishedComplete.length,
  fetchLoopTuples: publishedHarvest.slice(0, 128),
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
  events: events.slice(0, fetchTuples ? 400 : 50),
};

fs.writeFileSync(path.join(outDir, "oracle.json"), JSON.stringify(summary, null, 2));
try {
  fs.writeFileSync(path.join(outDir, "events.json"), JSON.stringify(events, null, 2));
} catch {}
fs.writeFileSync(
  path.join(outDir, "network.json"),
  JSON.stringify({ fo: foNet, allChallenge: network }, null, 2),
);

console.log(
  JSON.stringify(
    {
      ok: foNet.length > 0 || ops.length > 0 || publishedComplete.length > 0,
      headed,
      fetchTuples,
      iframeRewrites,
      foCount: foNet.length,
      opcodeCount: ops.length,
      harvestTupleCount: publishedHarvest.length,
      completeTupleCount: publishedComplete.length,
      fetchLoopRawCount: liveFetchRaw.length,
      fetchLoopBpPlaced,
      fetchLoopBpFailed,
      firstHarvestTuple: publishedHarvest[0] || null,
      firstCompleteTuple: publishedComplete[0] || null,
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
