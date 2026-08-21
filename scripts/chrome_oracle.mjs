#!/usr/bin/env node
/**
 * Headed Chrome oracle for live Turnstile `/fo/` + `runProgram`.
 *
 * Captures real request headers (CDP Network extraInfo) and injects a log at
 * the interpreter's opcode fetch (`* 19663 + 36376`) inside the OOPIF iframe.
 * Does **not** reconstruct wZ, dump full POST bodies, or harvest a token.
 *
 * Usage:
 *   DISPLAY=:1 node scripts/chrome_oracle.mjs [url] [out-dir]
 *
 * Env:
 *   CHROME_PATH          default /usr/bin/google-chrome-stable
 *   ORACLE_WAIT_MS       default 20000
 *   ORACLE_HEADLESS      set to 1 to force headless (not the intended mode)
 */
import fs from "node:fs";
import path from "node:path";
import puppeteer from "puppeteer-core";

const url = process.argv[2] || "https://solvegate.io/demo/invisible";
const outDir = process.argv[3] || path.join("artifacts", "re-out", "chrome-oracle");
const chrome = process.env.CHROME_PATH || "/usr/bin/google-chrome-stable";
const waitMs = Number(process.env.ORACLE_WAIT_MS || 20_000);
const headed = process.env.ORACLE_HEADLESS !== "1";

fs.mkdirSync(outDir, { recursive: true });

const PREAMBLE = `(() => {
  if (window.__cfOracleHook) return;
  window.__cfOracleHook = true;
  window.__cfOp = window.__cfOp || [];
  window.__cfXhr = window.__cfXhr || [];
  window.__cfRP = window.__cfRP || [];
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
        window.__cfXhr.push(row);
        this.addEventListener("loadend", function () {
          row.status = this.status;
          row.respLen = (this.responseText || "").length;
          row.respPrefix = (this.responseText || "").slice(0, 24);
        });
      }
      return send.apply(this, arguments);
    };
  } catch (e) {
    window.__cfHookErr = String(e);
  }
  try {
    let rp;
    Object.defineProperty(window, "runProgram", {
      configurable: true,
      enumerable: true,
      set(v) {
        rp =
          typeof v === "function"
            ? function (packed, helper) {
                try {
                  window.__cfRP.push({
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
    window.__cfHookErr = (window.__cfHookErr || "") + String(e);
  }
})();`;

function injectOpcodeLog(html) {
  if (!html) {
    return { html, injected: false, replacements: 0, snippet: null };
  }
  const idx19663 = html.indexOf("19663");
  const idx36163 = html.indexOf("36163");
  const idx = idx19663 >= 0 ? idx19663 : idx36163;
  const snippet = idx >= 0 ? html.slice(Math.max(0, idx - 280), idx + 220) : null;
  let n = 0;
  let out = html;
  out = out.replace(
    /([A-Za-z_$][\w$]*)=([A-Za-z_$][\w$]*)\[([A-Za-z_$][\w$]*)\]\^[\s\S]{0,180}?-62,256\),255\),(\2\[\3\]=)/g,
    (full, opVar, stateVar, keyI, assign) => {
      n++;
      const log = `(window.__cfOp=window.__cfOp||[]).length<160&&window.__cfOp.push({loop:1,op:${opVar}&255,key:${stateVar}[${keyI}]&255}),`;
      return full.replace(assign, log + assign);
    },
  );
  out = out.replace(
    /([A-Za-z_$][\w$]*)=([A-Za-z_$][\w$]*)\[([A-Za-z_$][\w$]*)\]\^[\s\S]{0,80}?,37\)\+256&255,(\2\[\3\]=)/g,
    (full, opVar, stateVar, keyI, assign) => {
      n++;
      const log = `(window.__cfOp=window.__cfOp||[]).length<160&&window.__cfOp.push({loop:1b,op:${opVar}&255,key:${stateVar}[${keyI}]&255}),`;
      return full.replace(assign, log + assign);
    },
  );
  out = out.replace(
    /([A-Za-z_$][\w$]*)=\w+\[[^\]]+\]\(([A-Za-z_$][\w$]*)\[([A-Za-z_$][\w$]*)\],[\s\S]{0,180}?-62,256[\s\S]{0,50}?\),(\2\[\3\]=)/g,
    (full, opVar, stateVar, keyI, assign) => {
      n++;
      const log = `(window.__cfOp=window.__cfOp||[]).length<160&&window.__cfOp.push({loop:2,op:${opVar}&255,key:${stateVar}[${keyI}]&255}),`;
      return full.replace(assign, log + assign);
    },
  );
  if (/<head[\s>]/i.test(out)) {
    out = out.replace(/<head([^>]*)>/i, `<head$1><script>${PREAMBLE}</script>`);
  } else {
    out = `<script>${PREAMBLE}</script>` + out;
  }
  return { html: out, injected: n > 0, replacements: n, snippet };
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
        has36376: text.includes("36376"),
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

await new Promise((r) => setTimeout(r, waitMs));

const frameDumps = [];
for (const frame of page.frames()) {
  const fu = frame.url();
  if (!interestingUrl(fu) && frame !== page.mainFrame()) continue;
  try {
                const dump = await frame.evaluate(() => ({
      href: location.href,
      opCount: (window.__cfOp || []).length,
      ops: (window.__cfOp || []).slice(0, 96),
      reads: (window.__cfReads || []).slice(0, 96),
      xhr: window.__cfXhr || [],
      runProgramCalls: window.__cfRP || [],
      hookErr: window.__cfHookErr || null,
    }));
    frameDumps.push(dump);
  } catch (e) {
    frameDumps.push({ href: fu, error: String(e) });
  }
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
const ops = frameDumps.flatMap((f) => f.ops || []);
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
  xhrHook: xhr,
  opcodeFetches: ops.slice(0, 64),
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
    referer: foHeaders["referer"] ? "present" : null,
  },
  firstOpcode: ops[0] || null,
  events: events.slice(0, 40),
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
      firstReads: reads.slice(0, 8),
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
