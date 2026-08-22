#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { extractVmProfile } from "./vm-profile/extract.mjs";

const input = process.argv[2];
const output = process.argv[3];
if (!input || !output) {
  console.error("usage: node src/extract-vm-profile.mjs <executed-fetch.js> <profile.json>");
  process.exit(1);
}

const source = fs.readFileSync(input, "utf8");
const { profile, summary } = extractVmProfile(source, { sourceName: input });
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(profile, null, 2)}\n`);
console.log(JSON.stringify({ output, ...summary }, null, 2));
