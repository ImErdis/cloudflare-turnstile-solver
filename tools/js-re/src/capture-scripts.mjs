#!/usr/bin/env node
/**
 * Save JS *and* HTML from a page load, including Cloudflare OOPIF iframes.
 * Uses CDP Target.setAutoAttach(flatten) so challenges.cloudflare.com
 * out-of-process iframes are not dropped (page.on("response") misses them).
 *
 * Usage: node src/capture-scripts.mjs <url> [out-dir]
 */
import fs from "node:fs";
import path from "node:path";
import puppeteer from "puppeteer-core";

const url = process.argv[2];
if (!url) {
  console.error("usage: node src/capture-scripts.mjs <url> [out-dir]");
  process.exit(1);
}
const outDir =
  process.argv[3] ||
  path.join("artifacts/re-out/capture", encodeURIComponent(url).slice(0, 80));
const chrome = process.env.CHROME_PATH || "/usr/bin/google-chrome-stable";
const waitMs = Number(process.env.CAPTURE_WAIT_MS || 12_000);

fs.mkdirSync(outDir, { recursive: true });
fs.mkdirSync(path.join(outDir, "js"), { recursive: true });
fs.mkdirSync(path.join(outDir, "html"), { recursive: true });

const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: "new",
  args: [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-features=IsolateOrigins,site-per-process",
  ],
});

const saved = [];
const iframeSrcs = [];
let n = 0;
const seen = new Set();

function slug(u) {
  try {
    const parsed = new URL(u);
    return `${parsed.hostname}${parsed.pathname}`.replaceAll("/", "_").slice(0, 140);
  } catch {
    return "unknown";
  }
}

async function saveBody(resUrl, status, contentType, body, kindHint) {
  if (!body || seen.has(resUrl + ":" + body.length)) return;
  seen.add(resUrl + ":" + body.length);
  const ct = (contentType || "").toLowerCase();
  const isHtml = kindHint === "html" || ct.includes("text/html") || /\/turnstile\/|\/challenge-platform\//.test(resUrl) && body.trimStart().startsWith("<");
  const isJs =
    kindHint === "js" ||
    ct.includes("javascript") ||
    ct.includes("ecmascript") ||
    /\.js(\?|$)/.test(resUrl);
  if (!isHtml && !isJs) return;
  const i = String(n++).padStart(3, "0");
  const dir = isHtml ? "html" : "js";
  const ext = isHtml ? ".html" : ".js";
  const file = path.join(outDir, dir, `${i}-${slug(resUrl)}${ext}`);
  fs.writeFileSync(file, body);
  saved.push({ url: resUrl, status, bytes: body.length, kind: isHtml ? "html" : "js", file });
}

async function attachSession(session) {
  await session.send("Network.enable").catch(() => {});
  session.on("Network.responseReceived", async (evt) => {
    const { response, requestId, type } = evt;
    const rt = (type || "").toLowerCase();
    const ct = response.mimeType || response.headers?.["content-type"] || "";
    const interesting =
      rt === "script" ||
      rt === "document" ||
      rt === "xhr" ||
      rt === "fetch" ||
      /javascript|ecmascript|html|json/.test(String(ct).toLowerCase()) ||
      /challenge-platform|turnstile|orchestrate|chl_/.test(response.url);
    if (!interesting) return;
    try {
      const got = await session.send("Network.getResponseBody", { requestId });
      const body = got.base64Encoded
        ? Buffer.from(got.body, "base64").toString("utf8")
        : got.body;
      const kind = rt === "document" || String(ct).includes("html") ? "html" : "js";
      await saveBody(response.url, response.status, ct, body, kind);
    } catch {
      /* body not available */
    }
  });
}

const page = await browser.newPage();
const main = await page.createCDPSession();
await main.send("Target.setAutoAttach", {
  autoAttach: true,
  waitForDebuggerOnStart: false,
  flatten: true,
});
await attachSession(main);

main.on("Target.attachedToTarget", async (evt) => {
  try {
    const session = await page.target().createCDPSession();
    // flatten sessions: attach via connection
  } catch {
    /* ignore */
  }
});

browser.on("targetcreated", async (target) => {
  try {
    const turl = target.url();
    if (turl) iframeSrcs.push({ type: target.type(), url: turl });
    const client = await target.createCDPSession().catch(() => null);
    if (client) await attachSession(client);
  } catch {
    /* ignore */
  }
});

page.on("response", async (res) => {
  try {
    const req = res.request();
    const rt = req.resourceType();
    const ct = res.headers()["content-type"] || "";
    if (!["script", "document", "xhr", "fetch"].includes(rt) && !/javascript|html/.test(ct)) {
      return;
    }
    const body = await res.text();
    await saveBody(res.url(), res.status(), ct, body, rt === "document" ? "html" : "js");
  } catch {
    /* ignore */
  }
});

await page.goto(url, { waitUntil: "networkidle2", timeout: 60_000 }).catch((e) => {
  console.error("goto:", e.message);
});

await new Promise((r) => setTimeout(r, waitMs));

const dom = await page.evaluate(() => {
  const iframes = [...document.querySelectorAll("iframe")].map((f) => ({
    src: f.src,
    id: f.id,
    name: f.name,
    title: f.title,
  }));
  const widgets = [...document.querySelectorAll(".cf-turnstile, [data-sitekey]")].map((el) => ({
    sitekey: el.getAttribute("data-sitekey"),
    size: el.getAttribute("data-size"),
    className: el.className,
  }));
  const token = document.querySelector("[name='cf-turnstile-response']")?.value || "";
  return {
    href: location.href,
    title: document.title,
    iframes,
    widgets,
    tokenPrefix: token.slice(0, 24),
    tokenLen: token.length,
  };
}).catch((e) => ({ error: String(e) }));

for (const frame of page.frames()) {
  iframeSrcs.push({ type: "frame", url: frame.url() });
  try {
    const html = await frame.content();
    if (html && html.length > 50) {
      await saveBody(frame.url() || url, 200, "text/html", html, "html");
    }
  } catch {
    /* cross-origin */
  }
}

await browser.close();

const index = { url, waitMs, count: saved.length, iframeSrcs, dom, saved };
fs.writeFileSync(path.join(outDir, "index.json"), JSON.stringify(index, null, 2));
console.log(
  JSON.stringify(
    {
      url,
      count: saved.length,
      html: saved.filter((s) => s.kind === "html").length,
      js: saved.filter((s) => s.kind === "js").length,
      tokenLen: dom?.tokenLen,
      iframes: (dom?.iframes || []).map((f) => f.src).filter(Boolean),
      outDir,
    },
    null,
    2
  )
);
