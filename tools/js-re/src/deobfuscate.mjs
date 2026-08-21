#!/usr/bin/env node
/**
 * Standard JS-RE first pass: prettier (or js-beautify) then webcrack.
 * Optional --synchrony also runs relative/synchrony (npm package `deobfuscator`).
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as prettier from "prettier";
import { webcrack } from "webcrack";
import beautify from "js-beautify";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const input = process.argv[2];
if (!input) {
  console.error("usage: node src/deobfuscate.mjs <file.js> [out-dir] [--synchrony]");
  process.exit(1);
}
const useSynchrony = process.argv.includes("--synchrony");
const outDir =
  process.argv[3] && !process.argv[3].startsWith("--")
    ? process.argv[3]
    : path.join("artifacts/re-out", path.basename(input, path.extname(input)) + ".deob");

fs.mkdirSync(outDir, { recursive: true });
const source = fs.readFileSync(input, "utf8");
fs.writeFileSync(path.join(outDir, "00-original.js"), source);

let pretty;
try {
  pretty = await prettier.format(source, { parser: "babel", filepath: input });
} catch (e) {
  pretty = beautify.js(source, { indent_size: 2, max_preserve_newlines: 2 });
  fs.writeFileSync(path.join(outDir, "prettier-error.txt"), String(e));
}
fs.writeFileSync(path.join(outDir, "01-prettier.js"), pretty);

let webcrackCode = pretty;
let webcrackNote = "ok";
try {
  const result = await webcrack(pretty);
  webcrackCode = result.code || pretty;
} catch (e) {
  webcrackNote = String(e);
  fs.writeFileSync(path.join(outDir, "webcrack-error.txt"), webcrackNote);
}
fs.writeFileSync(path.join(outDir, "02-webcrack.js"), webcrackCode);

if (useSynchrony) {
  const synBin = path.join(root, "node_modules/.bin/synchrony");
  try {
    execFileSync(synBin, ["deobfuscate", path.join(outDir, "02-webcrack.js"), "-o", path.join(outDir, "03-synchrony.js")], {
      stdio: "inherit",
    });
  } catch (e) {
    fs.writeFileSync(path.join(outDir, "synchrony-error.txt"), String(e));
  }
}

const summary = {
  input,
  outDir,
  originalBytes: source.length,
  prettierBytes: pretty.length,
  webcrackBytes: webcrackCode.length,
  webcrack: webcrackNote,
  synchrony: useSynchrony,
};
fs.writeFileSync(path.join(outDir, "summary.json"), JSON.stringify(summary, null, 2));
console.log(JSON.stringify(summary, null, 2));
