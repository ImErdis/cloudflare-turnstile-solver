#!/usr/bin/env node
/**
 * Fetch Cloudflare's *public* Turnstile api.js (the widget loader).
 * This is not the per-challenge orchestrate VM script.
 */
import fs from "node:fs";
import path from "node:path";

const outDir = process.argv[2] || "artifacts/re-out";
fs.mkdirSync(outDir, { recursive: true });

const url = "https://challenges.cloudflare.com/turnstile/v0/api.js";
const res = await fetch(url, {
  redirect: "follow",
  headers: {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    Accept: "*/*",
  },
});

if (!res.ok) {
  console.error(`fetch failed: ${res.status} ${res.statusText} for ${res.url}`);
  process.exit(1);
}

const body = await res.text();
const dest = path.join(outDir, "api.js");
fs.writeFileSync(dest, body);
const meta = {
  requested: url,
  finalUrl: res.url,
  status: res.status,
  bytes: body.length,
  saved: dest,
};
fs.writeFileSync(path.join(outDir, "api.meta.json"), JSON.stringify(meta, null, 2));
console.log(JSON.stringify(meta, null, 2));
