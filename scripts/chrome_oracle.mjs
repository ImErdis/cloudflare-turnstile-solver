#!/usr/bin/env node
/**
 * Headed Chrome oracle for live Turnstile `/fo/` + `runProgram`.
 *
 * Captures real request headers (CDP Network extraInfo) and injects a log at
 * the interpreter's opcode fetch (`* 36163 + 38392` live linear /
 * `mix*mix*56907+7914*mix+22357` later same-day / `* 19663 + 36376`
 * historical) inside the OOPIF iframe. Logs `{pc, op, key, byte}` so instruction
 * widths are PC deltas — not a 1-byte walk. Does **not** reconstruct a live
 * `/fo/` body (f4 / historical wZ), dump full POST bodies, fill init JSON, execute handlers as a
 * solver, or harvest a token.
 *
 * Usage:
 *   DISPLAY=:1 node scripts/chrome_oracle.mjs [url] [out-dir]
 *   node scripts/chrome_oracle.mjs --self-test
 *
 * Env:
 *   CHROME_PATH          default /usr/bin/google-chrome-stable
 *   ORACLE_WAIT_MS       default 22000
 *   ORACLE_HEADLESS      set to 1 to force headless (not the intended mode)
 */
import fs from "node:fs";
import path from "node:path";
import puppeteer from "puppeteer-core";

const selfTest = process.argv.includes("--self-test");
const positional = process.argv.slice(2).filter((a) => a !== "--self-test");
const url = positional[0] || "https://solvegate.io/demo/invisible";
const outDir = positional[1] || path.join("artifacts", "re-out", "chrome-oracle");
const chrome = process.env.CHROME_PATH || "/usr/bin/google-chrome-stable";
const waitMs = Number(process.env.ORACLE_WAIT_MS || 22_000);
const headed = process.env.ORACLE_HEADLESS !== "1";

if (!selfTest) {
  fs.mkdirSync(outDir, { recursive: true });
}

const PREAMBLE = `(() => {
  if (globalThis.__cfOracleHook) return;
  globalThis.__cfOracleHook = true;
  globalThis.__cfOp = globalThis.__cfOp || [];
  globalThis.__cfXhr = globalThis.__cfXhr || [];
  globalThis.__cfRP = globalThis.__cfRP || [];
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
    let rp;
    Object.defineProperty(globalThis, "runProgram", {
      configurable: true,
      enumerable: true,
      set(v) {
        rp =
          typeof v === "function"
            ? function (packed, helper) {
                try {
                  globalThis.__cfRP.push({
                    packedType: typeof packed,
                    packedLen: packed && packed.length,
                    packedPrefix: String(packed || "").slice(0, 20),
                  });
                } catch {}
                return v.apply(this, arguments);
              }
            : v;
      },
      get() {
        return rp;
      },
    });
  } catch (e) {
    globalThis.__cfHookErr = (globalThis.__cfHookErr || "") + String(e);
  }
})();`;

function fetchSnippet(html) {
  for (const marker of [
    "56907",
    "36163)+38392",
    "19663)+36376",
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

/**
 * Instrument both fetch loops. The arithmetic is stable; wrapping rotates:
 *   switch(state[pc]=pc+1, ...)
 *   switch(state[pc]=add(pc,1), ...)
 *   key = ((key+op)*mul+add)&255   as either `*mul+add,255` or `mul)+add&255.xx`
 *   key = (mix*mix*56907 + 7914*mix + 22357)&255  (later same-day b)
 * PC is snapshotted from `if(pc=state[slot],pc!==pc)return ...;switch(`.
 */
function injectOpcodeLog(html) {
  if (!html) {
    return { html, injected: false, replacements: 0, snippet: null };
  }
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

/** Breakpoint locals rotate; opcode is the 0–255 varying number, mix is often >255. */
function normalizeBreakpointOps(rows) {
  const bp = rows.filter((r) => r.via === "breakpoint");
  const keys = new Set();
  for (const r of bp) {
    for (const k of Object.keys(r)) {
      if (k === "via" || k === "op" || k === "mix" || k === "key" || k === "pc" || k === "gLen" || k === "keySlot") {
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
  return rows.map((r) => {
    if (r.via !== "breakpoint") return r;
    const op = r.op != null ? r.op : opKey != null ? r[opKey] & 255 : undefined;
    const mix = r.mix != null ? r.mix : mixKey != null ? r[mixKey] : undefined;
    const key =
      r.key != null
        ? r.key
        : typeof op === "number" && typeof mix === "number"
          ? (mix - op) & 255
          : undefined;
    return { via: "breakpoint", pc: r.pc, op, mix, key };
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
  const a = injectOpcodeLog(happyOld);
  const b = injectOpcodeLog(happyLive);
  const c = injectOpcodeLog(catchLive);
  const d = injectOpcodeLog(happyQuad);
  const e = injectOpcodeLog(catchQuad);
  const f = injectOpcodeLog(happyMulSq);
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
      extracted === CHARSET_BRANCH_B &&
      prefixOk &&
      stdReject &&
      classifyBodyLen(3735) === "init" &&
      classifyBodyLen(86882) === "followUp" &&
      initGot &&
      initGot.keyCount === 47,
    happyOld: { replacements: a.replacements, injected: a.injected },
    happyLive: { replacements: b.replacements, injected: b.injected },
    catchLive: { replacements: c.replacements, injected: c.injected },
    happyQuad: { replacements: d.replacements, injected: d.injected },
    catchQuad: { replacements: e.replacements, injected: e.injected },
    happyMulSq: { replacements: f.replacements, injected: f.injected },
    charset: { extracted, prefixOk, stdReject },
    initJson: initGot && { keyCount: initGot.keyCount },
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
const scriptNotes = [];
let iframeRewrites = 0;

function note(kind, payload) {
  events.push({ t: Date.now(), kind, ...payload });
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
      iframeRewrites++;
      fs.writeFileSync(
        path.join(outDir, `iframe-${iframeRewrites}.html`),
        text.slice(0, 400000),
      );
      fs.writeFileSync(
        path.join(outDir, `iframe-rewritten-${iframeRewrites}.html`),
        html.slice(0, 200000),
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
        has36376: text.includes("36376"),
        has38392: text.includes("38392"),
        hasRunProgram: text.includes("runProgram"),
        snippet,
      });
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
  });
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
    session.on("Debugger.scriptParsed", async (s) => {
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
        const idxQ = scriptSource.indexOf("56907");
        const idx = scriptSource.indexOf("36163");
        const idxG = scriptSource.indexOf("19663");
        if (idxQ < 0 && idx < 0 && idxG < 0) return;
        const hasInject = scriptSource.includes("__cfOp.push");
        note("scriptFetchConst", {
          url: (s.url || "").slice(0, 140),
          len: scriptSource.length,
          hasInject,
          idx: idxQ >= 0 ? idxQ : idx >= 0 ? idx : idxG,
          marker: idxQ >= 0 ? "56907" : idx >= 0 ? "36163" : "19663",
        });
        const at = idxQ >= 0 ? idxQ : idx >= 0 ? idx : idxG;
        const pre = scriptSource.slice(0, at);
        const lineNumber = (pre.match(/\n/g) || []).length;
        const nl = pre.lastIndexOf("\n");
        const columnNumber = nl < 0 ? pre.length : pre.length - nl - 1;
        if (!hasInject) {
          await session.send("Debugger.setBreakpoint", {
            location: { scriptId: s.scriptId, lineNumber, columnNumber },
          });
        }
      } catch (e) {
        note("bpErr", { error: String(e), url: (s.url || "").slice(0, 80) });
      }
    });
    session.on("Debugger.paused", async (evt) => {
      try {
        const frame = evt.callFrames?.[0];
        if (frame && liveOps.length < 400) {
          const row = { via: "breakpoint" };
          try {
            const got = await session.send("Debugger.evaluateOnCallFrame", {
              callFrameId: frame.callFrameId,
              expression: `(() => {
                const g = this && this.g;
                const pc = g && typeof this.j === 'number' ? g[this.j] : undefined;
                const keySlot = g && typeof this.i === 'number' ? g[this.i] : undefined;
                return { pc, keySlot, gLen: g && g.length };
              })()`,
              returnByValue: true,
            });
            const v = got.result?.value;
            if (v && typeof v === "object") Object.assign(row, v);
          } catch {}
          if (row.op == null) {
            const local = frame.scopeChain?.find((sc) => sc.type === "local");
            if (local?.object?.objectId) {
              const got = await session.send("Runtime.getProperties", {
                objectId: local.object.objectId,
                ownProperties: true,
              });
              for (const p of got.result || []) {
                if (p.value?.type === "number" && typeof p.value.value === "number") {
                  row[p.name] = p.value.value;
                }
              }
              if (typeof row.A === "number") row.op = row.A & 255;
              if (typeof row.D === "number") row.mix = row.D;
            }
          }
          if (typeof row.op === "number" && typeof row.mix === "number") {
            row.key = (row.mix - row.op) & 255;
          }
          liveOps.push(row);
        }
      } catch (e) {
        note("pausedErr", { error: String(e) });
      } finally {
        await session.send("Debugger.resume").catch(() => {});
      }
    });
    await session.send("Debugger.enable").catch(() => {});
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
  args: [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--window-size=1920,1080",
    "--use-gl=angle",
    "--use-angle=swiftshader",
    "--autoplay-policy=no-user-gesture-required",
  ],
});

const page = await browser.newPage();
await page.setViewport({ width: 1920, height: 1080 });
const main = await page.createCDPSession();
const connection = main.connection();

await main.send("Target.setAutoAttach", {
  autoAttach: true,
  waitForDebuggerOnStart: true,
  flatten: true,
});

main.on("Target.attachedToTarget", async (evt) => {
  const child = connection.session(evt.sessionId);
  if (!child) {
    note("noChildSession", { sessionId: evt.sessionId, url: evt.targetInfo?.url });
    return;
  }
  await attachSession(child, evt.targetInfo, evt.waitingForDebugger);
});

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
          runProgramCalls: globalThis.__cfRP||[]
        })`,
        returnByValue: true,
      });
      const v = result?.value;
      if (v?.ops?.length) {
        for (const o of v.ops) {
          if (liveOps.length < 400) liveOps.push(o);
        }
        note("harvest", { tag, label, opCount: v.opCount });
      }
    } catch (e) {
      note("harvestErr", { tag, label, error: String(e).slice(0, 160) });
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
      hookErr: globalThis.__cfHookErr || null,
    }));
    frameDumps.push(dump);
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

await browser.close();

const foNet = network.filter((n) => /\/fo\//.test(n.url || ""));
const firstFo = foNet[0] || null;
const ops = normalizeBreakpointOps([
  ...frameDumps.flatMap((f) => f.ops || []),
  ...liveOps,
]);
const reads = frameDumps.flatMap((f) => f.reads || []);
const xhr = frameDumps.flatMap((f) => f.xhr || []);

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
const initJson = extractInitJsonKeys(iframeHtml);
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
  foInitJson: initJson
    ? {
        keyCount: initJson.keyCount,
        setTimeoutNearby: initJson.setTimeoutNearby,
        hasJsonStringify: initJson.hasJsonStringify,
        keys: initJson.keys,
        note: "key names only; do not dump values or POST",
      }
    : null,
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
  events: events.slice(0, 50),
};

fs.writeFileSync(path.join(outDir, "oracle.json"), JSON.stringify(summary, null, 2));
fs.writeFileSync(
  path.join(outDir, "network.json"),
  JSON.stringify({ fo: foNet, allChallenge: network }, null, 2),
);

console.log(
  JSON.stringify(
    {
      ok: foNet.length > 0 || ops.length > 0,
      headed,
      iframeRewrites,
      foCount: foNet.length,
      opcodeCount: ops.length,
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
      foInitJson: initJson
        ? { keyCount: initJson.keyCount, hasJsonStringify: initJson.hasJsonStringify }
        : null,
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
