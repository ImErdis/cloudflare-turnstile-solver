#!/usr/bin/env node
/**
 * Dump a compact Acorn AST summary (node-type histogram + sample of
 * CallExpression callee names). Full ASTs of CF scripts are huge; this is
 * what REs actually grep first.
 */
import fs from "node:fs";
import * as acorn from "acorn";

const input = process.argv[2];
if (!input) {
  console.error("usage: node src/dump-ast.mjs <file.js> [out.json]");
  process.exit(1);
}
const source = fs.readFileSync(input, "utf8");
let ast;
try {
  ast = acorn.parse(source, {
    ecmaVersion: "latest",
    sourceType: "script",
    locations: false,
    ranges: false,
    allowReturnOutsideFunction: true,
    allowHashBang: true,
  });
} catch (first) {
  try {
    ast = acorn.parse(source, {
      ecmaVersion: "latest",
      sourceType: "module",
      allowReturnOutsideFunction: true,
      allowHashBang: true,
    });
  } catch (second) {
    console.error(`parse failed: ${second}`);
    process.exit(1);
  }
}

const counts = Object.create(null);
const callees = Object.create(null);
const strings = Object.create(null);

function walk(node) {
  if (!node || typeof node !== "object") return;
  if (typeof node.type === "string") {
    counts[node.type] = (counts[node.type] || 0) + 1;
    if (node.type === "CallExpression") {
      const c = node.callee;
      let name = "?";
      if (c?.type === "Identifier") name = c.name;
      else if (c?.type === "MemberExpression" && c.property?.name) name = "." + c.property.name;
      callees[name] = (callees[name] || 0) + 1;
    }
    if (node.type === "Literal" && typeof node.value === "string" && node.value.length >= 6 && node.value.length <= 80) {
      strings[node.value] = (strings[node.value] || 0) + 1;
    }
  }
  for (const v of Object.values(node)) {
    if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object" && v.type) walk(v);
  }
}
walk(ast);

const summary = {
  input,
  bytes: source.length,
  nodeCounts: Object.fromEntries(Object.entries(counts).sort((a, b) => b[1] - a[1])),
  topCallees: Object.fromEntries(
    Object.entries(callees)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 40)
  ),
  interestingStrings: Object.keys(strings)
    .filter((s) => /cf_|chl|turnstile|orchestrate|ray|sitekey/i.test(s))
    .slice(0, 80),
};

const out = process.argv[3];
if (out) {
  fs.writeFileSync(out, JSON.stringify(summary, null, 2));
  console.log("wrote", out);
} else {
  console.log(JSON.stringify(summary, null, 2));
}
