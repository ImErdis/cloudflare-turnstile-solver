#!/usr/bin/env node
/**
 * Save every JavaScript response from a page load via Chrome DevTools Protocol.
 * This is the usual "Network tab but scriptable" first step in a JS RE.
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
const outDir = process.argv[3] || path.join("artifacts/re-out/capture", encodeURIComponent(url).slice(0, 80));
const chrome =
  process.env.CHROME_PATH || "/usr/bin/google-chrome-stable";

fs.mkdirSync(outDir, { recursive: true });

const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: "new",
  args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
});

const page = await browser.newPage();
const saved = [];
let n = 0;

page.on("response", async (res) => {
  try {
    const req = res.request();
    const rt = req.resourceType();
    const ct = (res.headers()["content-type"] || "").toLowerCase();
    if (rt !== "script" && !ct.includes("javascript") && !ct.includes("ecmascript")) {
      return;
    }
    const body = await res.text();
    const i = String(n++).padStart(3, "0");
    const u = new URL(res.url());
    const base = `${i}-${u.hostname}${u.pathname.replaceAll("/", "_")}`.slice(0, 120);
    const file = path.join(outDir, `${base}.js`);
    fs.writeFileSync(file, body);
    saved.push({
      url: res.url(),
      status: res.status(),
      bytes: body.length,
      file,
    });
  } catch {
    /* navigation abort / CORS body unavailable */
  }
});

await page.goto(url, { waitUntil: "networkidle2", timeout: 45_000 }).catch(() => {});
await new Promise((r) => setTimeout(r, 1500));
await browser.close();

fs.writeFileSync(path.join(outDir, "index.json"), JSON.stringify({ url, saved }, null, 2));
console.log(JSON.stringify({ url, count: saved.length, outDir }, null, 2));
