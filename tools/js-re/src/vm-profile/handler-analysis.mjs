import { canonicalJson, sha256Hex } from "./canonicalize.mjs";
import { collect, contains, propertyName, walk } from "./ast-utils.mjs";
import { collectDecoderAliases } from "./static-decoder.mjs";

function numericPropertyMap(object) {
  if (
    object?.type !== "ObjectExpression" ||
    !object.properties.length ||
    !object.properties.every(
      (property) => property.type === "Property" && typeof property.value?.value === "number",
    )
  ) {
    return null;
  }
  return Object.fromEntries(
    object.properties.map((property) => [propertyName(property.key), property.value.value]),
  );
}

function helperObject(object) {
  if (object?.type !== "ObjectExpression") return null;
  const helpers = object.properties.filter(
    (property) =>
      property.type === "Property" &&
      ["FunctionExpression", "ArrowFunctionExpression"].includes(property.value?.type),
  );
  if (!helpers.length) return null;
  return new Map(helpers.map((property) => [propertyName(property.key), property.value]));
}

function returnedExpression(fn) {
  if (fn.body.type !== "BlockStatement") return fn.body;
  const returns = collect(fn.body, (node) => node.type === "ReturnStatement");
  return returns.length === 1 ? returns[0].argument : null;
}

export function indexFunction(fn, { decoder, globalDecoderAliases }) {
  const parents = new WeakMap();
  walk(fn, (node, parent) => {
    if (parent) parents.set(node, parent);
  });
  const numericMaps = new Map();
  const helperObjects = new Map();
  for (const assignment of collect(
    fn,
    (node) =>
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      node.left.type === "Identifier",
  )) {
    const numeric = numericPropertyMap(assignment.right);
    if (numeric) numericMaps.set(assignment.left.name, numeric);
    const helpers = helperObject(assignment.right);
    if (helpers) helperObjects.set(assignment.left.name, helpers);
  }
  const decoderAliases = new Set(globalDecoderAliases);
  let changed = true;
  while (changed) {
    changed = false;
    for (const assignment of collect(
      fn,
      (node) =>
        node.type === "AssignmentExpression" &&
        node.operator === "=" &&
        node.left.type === "Identifier" &&
        node.right.type === "Identifier",
    )) {
      if (decoderAliases.has(assignment.right.name) && !decoderAliases.has(assignment.left.name)) {
        decoderAliases.add(assignment.left.name);
        changed = true;
      }
    }
  }
  return {
    fn,
    decoder,
    decoderAliases,
    numericMaps,
    helperObjects,
    parents,
  };
}

function resolveStaticNumber(node, context) {
  if (node?.type === "Literal" && typeof node.value === "number") return node.value;
  if (node?.type !== "MemberExpression" || node.object.type !== "Identifier") return null;
  const map = context.numericMaps.get(node.object.name);
  const key = node.computed ? propertyName(node.property) : node.property.name;
  return map && Object.hasOwn(map, key) ? map[key] : null;
}

function resolveDecodedKey(node, context) {
  if (
    node?.type !== "CallExpression" ||
    node.callee.type !== "Identifier" ||
    !context.decoderAliases.has(node.callee.name) ||
    node.arguments.length !== 1
  ) {
    return null;
  }
  const index = resolveStaticNumber(node.arguments[0], context);
  if (!Number.isInteger(index)) return null;
  try {
    return context.decoder.decode(index);
  } catch {
    return null;
  }
}

function resolveHelper(node, context) {
  if (
    node?.type !== "CallExpression" ||
    node.callee.type !== "MemberExpression" ||
    node.callee.object.type !== "Identifier"
  ) {
    return null;
  }
  const helpers = context.helperObjects.get(node.callee.object.name);
  if (!helpers) return null;
  const key = node.callee.computed
    ? resolveDecodedKey(node.callee.property, context)
    : propertyName(node.callee.property);
  const fn = helpers.get(key);
  const expression = fn && returnedExpression(fn);
  if (!expression || fn.params.some((param) => param.type !== "Identifier")) return null;
  return { fn, expression };
}

function semanticRead(node) {
  return (
    node?.type === "MemberExpression" &&
    node.computed &&
    node.object.type === "Identifier" &&
    node.property.type === "UpdateExpression" &&
    node.property.operator === "++" &&
    node.property.argument.type === "Identifier"
  );
}

function semantic(node, context, environment = new Map(), depth = 0) {
  if (!node || depth > 64) return { type: "unknown" };
  if (semanticRead(node)) {
    return {
      type: "read",
      start: node.start,
      buffer: node.object.name,
      pc: node.property.argument.name,
    };
  }
  switch (node.type) {
    case "Literal":
      return { type: "literal", value: node.value };
    case "Identifier":
      if (environment.has(node.name)) {
        return semantic(environment.get(node.name), context, environment, depth + 1);
      }
      return { type: "identifier", name: node.name };
    case "ThisExpression":
      return { type: "this" };
    case "BinaryExpression":
    case "LogicalExpression":
      return {
        type: "binary",
        operator: node.operator,
        left: semantic(node.left, context, environment, depth + 1),
        right: semantic(node.right, context, environment, depth + 1),
      };
    case "UnaryExpression":
      return {
        type: "unary",
        operator: node.operator,
        argument: semantic(node.argument, context, environment, depth + 1),
      };
    case "AssignmentExpression":
      if (node.operator !== "=") {
        return {
          type: "binary",
          operator: node.operator.slice(0, -1),
          left: semantic(node.left, context, environment, depth + 1),
          right: semantic(node.right, context, environment, depth + 1),
        };
      }
      return semantic(node.right, context, environment, depth + 1);
    case "SequenceExpression":
      return {
        type: "sequence",
        expressions: node.expressions.map((expression) =>
          semantic(expression, context, environment, depth + 1),
        ),
      };
    case "ConditionalExpression":
      return {
        type: "conditional",
        test: semantic(node.test, context, environment, depth + 1),
        consequent: semantic(node.consequent, context, environment, depth + 1),
        alternate: semantic(node.alternate, context, environment, depth + 1),
      };
    case "MemberExpression":
      return {
        type: "member",
        computed: node.computed,
        object: semantic(node.object, context, environment, depth + 1),
        property: semantic(node.property, context, environment, depth + 1),
      };
    case "UpdateExpression":
      return {
        type: "update",
        operator: node.operator,
        argument: semantic(node.argument, context, environment, depth + 1),
      };
    case "CallExpression": {
      const helper = resolveHelper(node, context);
      if (helper && helper.fn.params.length === node.arguments.length) {
        const nested = new Map(environment);
        helper.fn.params.forEach((param, index) => nested.set(param.name, node.arguments[index]));
        return semantic(helper.expression, context, nested, depth + 1);
      }
      return {
        type: "call",
        callee: semantic(node.callee, context, environment, depth + 1),
        arguments: node.arguments.map((argument) =>
          semantic(argument, context, environment, depth + 1),
        ),
      };
    }
    case "ArrayExpression":
      return {
        type: "array",
        elements: node.elements.map((element) => semantic(element, context, environment, depth + 1)),
      };
    default:
      return { type: node.type.toLowerCase() };
  }
}

function semanticContains(node, predicate) {
  if (!node || typeof node !== "object") return false;
  if (predicate(node)) return true;
  return Object.values(node).some((value) =>
    Array.isArray(value)
      ? value.some((child) => semanticContains(child, predicate))
      : semanticContains(value, predicate),
  );
}

function flattenBinary(node, operator, out = []) {
  if (
    node?.type === "binary" &&
    node.operator === "&" &&
    ((node.left?.type === "literal" && toInt32(node.left.value) === 255) ||
      (node.right?.type === "literal" && toInt32(node.right.value) === 255))
  ) {
    const unmasked =
      node.left.type === "literal" && toInt32(node.left.value) === 255
        ? node.right
        : node.left;
    return flattenBinary(unmasked, operator, out);
  }
  if (node?.type === "binary" && node.operator === operator) {
    flattenBinary(node.left, operator, out);
    flattenBinary(node.right, operator, out);
  } else {
    out.push(node);
  }
  return out;
}

function toInt32(value) {
  if (!Number.isFinite(value)) return null;
  return value >> 0;
}

function decodeCandidate(node, readStart) {
  if (!node || typeof node !== "object") return null;
  if (node.type === "binary" && node.operator === "^") {
    const terms = flattenBinary(node, "^");
    const readTerms = terms.filter((term) =>
      semanticContains(term, (candidate) => candidate.type === "read" && candidate.start === readStart),
    );
    const identifierTerms = terms.filter((term) => term?.type === "identifier");
    const literalTerms = terms.filter(
      (term) => term?.type === "literal" && typeof term.value === "number",
    );
    if (
      readTerms.length === 1 &&
      identifierTerms.length === 1 &&
      readTerms.length + identifierTerms.length + literalTerms.length === terms.length
    ) {
      let extra = 0;
      for (const literal of literalTerms) {
        const int = toInt32(literal.value);
        if (int == null) return null;
        extra ^= int;
      }
      return {
        extra: extra & 255,
        keyIdentifier: identifierTerms[0].name,
      };
    }
  }
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) {
      for (const child of value) {
        const candidate = decodeCandidate(child, readStart);
        if (candidate) return candidate;
      }
    } else if (value && typeof value === "object") {
      const candidate = decodeCandidate(value, readStart);
      if (candidate) return candidate;
    }
  }
  return null;
}

function dominantReadPair(fn) {
  const reads = collect(fn, semanticRead);
  const counts = new Map();
  for (const read of reads) {
    const key = `${read.object.name}\0${read.property.argument.name}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  if (!sorted.length || (sorted[1] && sorted[0][1] === sorted[1][1])) return null;
  const [buffer, pc] = sorted[0][0].split("\0");
  return {
    buffer,
    pc,
    reads: reads
      .filter(
        (read) =>
          read.object.name === buffer && read.property.argument.name === pc,
      )
      .sort((a, b) => a.start - b.start),
  };
}

function readDecode(read, context) {
  let current = read;
  let best = null;
  for (let depth = 0; current && depth < 16; depth += 1) {
    const expanded = semantic(current, context);
    const candidate = decodeCandidate(expanded, read.start);
    if (candidate) best = candidate;
    current = context.parents.get(current);
  }
  return best;
}

function assignmentForRead(read, context) {
  let current = read;
  while (current && current !== context.fn) {
    if (
      current.type === "AssignmentExpression" &&
      current.left.type === "Identifier" &&
      contains(current.right, (node) => node === read)
    ) {
      return current;
    }
    current = context.parents.get(current);
  }
  return null;
}

function expandedComparison(node, context) {
  const expanded = semantic(node, context);
  if (
    expanded.type !== "binary" ||
    !["===", "==", "!==", "!="].includes(expanded.operator)
  ) {
    return null;
  }
  const pairs = [
    [expanded.left, expanded.right],
    [expanded.right, expanded.left],
  ];
  for (const [identifier, literal] of pairs) {
    if (
      identifier?.type === "identifier" &&
      literal?.type === "literal" &&
      Number.isInteger(literal.value) &&
      literal.value >= 0 &&
      literal.value <= 255
    ) {
      return {
        identifier: identifier.name,
        tag: literal.value,
        equal: expanded.operator === "===" || expanded.operator === "==",
      };
    }
  }
  return null;
}

function tagBranches(context, tagIdentifier) {
  const branches = new Map();
  for (const ifStatement of collect(context.fn, (node) => node.type === "IfStatement")) {
    const comparisons = collect(ifStatement.test, (node) =>
      ["BinaryExpression", "CallExpression"].includes(node.type),
    )
      .map((node) => expandedComparison(node, context))
      .filter((comparison) => comparison?.identifier === tagIdentifier);
    for (const comparison of comparisons) {
      const branch = comparison.equal ? ifStatement.consequent : ifStatement.alternate;
      if (branch && !branches.has(comparison.tag)) branches.set(comparison.tag, branch);
    }
  }
  return branches;
}

function branchReadExtras(node, pair, context) {
  return pair.reads
    .filter((read) => read.start >= node.start && read.end <= node.end)
    .map((read) => readDecode(read, context)?.extra)
    .filter((extra) => extra != null);
}

function charsetReadExtras(node, pair, context) {
  const extras = [];
  for (const member of collect(
    node,
    (candidate) =>
      candidate.type === "MemberExpression" &&
      candidate.computed &&
      candidate.object.type === "Identifier" &&
      candidate.object.name !== pair.buffer,
  )) {
    for (const read of pair.reads) {
      if (read.start >= member.property.start && read.end <= member.property.end) {
        const extra = readDecode(read, context)?.extra;
        if (extra != null) extras.push(extra);
      }
    }
  }
  return extras;
}

function hasIdentifier(node, name) {
  return contains(node, (candidate) => candidate.type === "Identifier" && candidate.name === name);
}

function inferTaggedPayload(tag, branch, pair, context) {
  const extras = branchReadExtras(branch, pair, context);
  const hasRegexp = hasIdentifier(branch, "RegExp");
  const hasMath = hasIdentifier(branch, "Math");
  const hasVoid = contains(branch, (node) => node.type === "UnaryExpression" && node.operator === "void");
  const hasNull = contains(branch, (node) => node.type === "Literal" && node.value === null);
  const arrays = collect(branch, (node) => node.type === "ArrayExpression");
  const loops = collect(branch, (node) =>
    ["ForStatement", "WhileStatement", "DoWhileStatement"].includes(node.type),
  );
  const charsetExtras = charsetReadExtras(branch, pair, context);
  const hasCharsetIndex = charsetExtras.length > 0;
  const hasPush = contains(
    branch,
    (node) =>
      node.type === "CallExpression" &&
      node.callee.type === "MemberExpression" &&
      (propertyName(node.callee.property) === "push" ||
        (node.callee.computed &&
          resolveDecodedKey(node.callee.property, context) === "push")),
  );

  if (hasRegexp) {
    if (charsetExtras.length !== 2) return null;
    const flagsLength = extras.find(
      (extra) => extra !== 0 && !charsetExtras.includes(extra),
    );
    if (flagsLength == null) return null;
    return {
      kind: "regexp",
      pattern_length_byte_xor: 0,
      pattern_char_xor: charsetExtras[0],
      flags_length_xor: flagsLength,
      flags_char_xor: charsetExtras[1],
    };
  }
  if (hasMath) {
    const boundSix = contains(
      branch,
      (node) => node.type === "Literal" && node.value === 6,
    );
    if (!boundSix || extras.some((extra) => extra !== 0)) return null;
    return { kind: "fixed_reads", extra_xors: Array(8).fill(0) };
  }
  if (arrays.some((array) => array.elements.length >= 4) && extras.length >= 4) {
    return { kind: "fixed_reads", extra_xors: extras.slice(0, 4) };
  }
  if (arrays.some((array) => array.elements.length === 0) && loops.length && hasPush) {
    const charXor = extras.findLast((extra) => extra !== 0);
    if (charXor == null) return null;
    return { kind: "bytes", length_byte_xor: 0, char_xor: charXor };
  }
  if (hasCharsetIndex && loops.length) {
    const charXor = extras.findLast((extra) => extra !== 0);
    if (charXor == null) return null;
    return { kind: "string", length_byte_xor: 0, char_xor: charXor };
  }
  if (extras.length === 1) {
    return { kind: "fixed_reads", extra_xors: extras };
  }
  if (loops.some((loop) => loop.type === "DoWhileStatement") && extras.every((extra) => extra === 0)) {
    return { kind: "leb", byte_xor: 0 };
  }
  if (!extras.length && (hasVoid || hasNull || tag >= 0)) return { kind: "none" };
  return null;
}

export function recognizeTaggedLoad(fn, analysis) {
  const context = indexFunction(fn, analysis);
  const pair = dominantReadPair(fn);
  if (!pair || pair.reads.length < 8) return null;

  const candidates = pair.reads.slice(0, 4).flatMap((read, index) => {
    const assignment = assignmentForRead(read, context);
    if (!assignment) return [];
    const comparisons = collect(fn, (node) =>
      ["BinaryExpression", "CallExpression"].includes(node.type),
    )
      .map((node) => expandedComparison(node, context))
      .filter(
        (comparison) =>
          comparison?.equal && comparison.identifier === assignment.left.name,
      );
    return comparisons.length >= 8
      ? [{ read, index, assignment, comparisons }]
      : [];
  });
  if (!candidates.length) return null;
  const tagIdentifiers = new Set(candidates.map((candidate) => candidate.assignment.left.name));
  if (tagIdentifiers.size !== 1) return null;
  const tag = candidates.sort((a, b) => a.index - b.index)[0];
  const other = pair.reads
    .slice(0, 4)
    .map((read, index) => ({ read, index, assignment: assignmentForRead(read, context) }))
    .find(
      (candidate) =>
        candidate.assignment &&
        candidate.assignment !== tag.assignment &&
        readDecode(candidate.read, context),
    );
  if (!other) return null;
  const tagDecode = readDecode(tag.read, context);
  const dstDecode = readDecode(other.read, context);
  if (!tagDecode || !dstDecode || tagDecode.keyIdentifier !== dstDecode.keyIdentifier) return null;

  const branches = tagBranches(context, tag.assignment.left.name);
  if (branches.size < 10) return null;
  const tags = [];
  for (const [tagValue, branch] of [...branches].sort((a, b) => a[0] - b[0])) {
    const payload = inferTaggedPayload(tagValue, branch, pair, context);
    if (!payload) return null;
    tags.push({ tag: tagValue, payload });
  }
  const spec = {
    kind: "tagged_load",
    operand_order: tag.index < other.index ? "tag_then_dst" : "dst_then_tag",
    tag_xor: tagDecode.extra,
    dst_xor: dstDecode.extra,
    tags,
  };
  const evidence = {
    kind: "tagged_load",
    readPair: { count: pair.reads.length },
    spec,
  };
  return {
    spec,
    handlerFingerprint: sha256Hex(canonicalJson(evidence)),
    evidence,
  };
}

export function recognizeLebTable(fn, analysis) {
  const context = indexFunction(fn, analysis);
  const pair = dominantReadPair(fn);
  if (!pair || pair.reads.length < 4) return null;
  const doWhiles = collect(fn, (node) => node.type === "DoWhileStatement");
  const forLoops = collect(fn, (node) => node.type === "ForStatement");
  const objectAllocs = collect(
    fn,
    (node) => node.type === "ObjectExpression" && node.properties.length === 0,
  );
  const voids = collect(
    fn,
    (node) => node.type === "UnaryExpression" && node.operator === "void",
  );
  if (doWhiles.length !== 2 || !forLoops.length || !objectAllocs.length || !voids.length) return null;
  const extras = pair.reads.map((read) => readDecode(read, context)?.extra);
  if (extras.some((extra) => extra !== 0)) return null;
  const hasContinuationMasks = doWhiles.every((loop) =>
    contains(loop.test, (node) => node.type === "Literal" && Math.trunc(node.value) === 128),
  );
  const hasPayloadMasks = contains(
    fn,
    (node) => node.type === "Literal" && Math.trunc(node.value) === 127,
  );
  const hasShiftSeven = contains(
    fn,
    (node) => node.type === "Literal" && Math.trunc(node.value) === 7,
  );
  if (!hasContinuationMasks || !hasPayloadMasks || !hasShiftSeven) return null;

  const spec = {
    kind: "leb_table",
    count_byte_xor: 0,
    index_byte_xor: 0,
    max_count: 1_048_576,
  };
  const evidence = {
    kind: "leb_table",
    readPair: { count: pair.reads.length },
    doWhileCount: doWhiles.length,
    hasCountedFor: true,
    spec,
  };
  return {
    spec,
    handlerFingerprint: sha256Hex(canonicalJson(evidence)),
    evidence,
  };
}

export function recognizeJumpStop(fn, analysis) {
  const context = indexFunction(fn, analysis);
  const pair = dominantReadPair(fn);
  if (!pair || pair.reads.length < 3) return null;
  const pcAliases = new Set(
    collect(
      fn,
      (node) =>
        node.type === "AssignmentExpression" &&
        node.left.type === "Identifier" &&
        node.right.type === "MemberExpression" &&
        node.right.object.type === "ThisExpression",
    ).map((assignment) => assignment.left.name),
  );
  const writesPcSlot = collect(
    fn,
    (node) =>
      node.type === "AssignmentExpression" &&
      node.left.type === "MemberExpression" &&
      node.left.computed &&
      node.left.property.type === "Identifier" &&
      pcAliases.has(node.left.property.name),
  );
  if (writesPcSlot.length !== 1) return null;
  const shifts = new Set(
    collect(
      fn,
      (node) =>
        node.type === "BinaryExpression" &&
        node.operator === "<<" &&
        node.right.type === "Literal" &&
        [8, 16].includes(Math.trunc(node.right.value)),
    ).map((node) => Math.trunc(node.right.value)),
  );
  if (!shifts.has(8) || !shifts.has(16)) return null;
  const extras = pair.reads.map((read) => readDecode(read, context)?.extra);
  if (extras.some((extra) => extra == null)) return null;
  const evidence = {
    kind: "jump_stop",
    readPair: { count: pair.reads.length },
    readXors: extras,
    assemblesU24: true,
  };
  return {
    spec: {
      kind: "jump_stop",
      reason: "statically proven write to the current program-counter slot",
    },
    handlerFingerprint: sha256Hex(canonicalJson(evidence)),
    evidence,
  };
}

export function structuralUnknownFingerprint(fn, caseVariant) {
  const summary = {
    kind: "unknown",
    caseVariant: caseVariant ?? null,
    byteReadCount: collect(fn, semanticRead).length,
    loops: {
      for: collect(fn, (node) => node.type === "ForStatement").length,
      while: collect(fn, (node) => node.type === "WhileStatement").length,
      doWhile: collect(fn, (node) => node.type === "DoWhileStatement").length,
    },
    numericSwitchCases: collect(
      fn,
      (node) => node.type === "SwitchCase" && typeof node.test?.value === "number",
    )
      .map((node) => node.test.value)
      .sort((a, b) => a - b),
    hasNew: contains(fn, (node) => node.type === "NewExpression"),
    writesThisMember: contains(
      fn,
      (node) =>
        node.type === "AssignmentExpression" &&
        node.left.type === "MemberExpression" &&
        node.left.object.type === "ThisExpression",
    ),
  };
  return sha256Hex(canonicalJson(summary));
}

export function createHandlerAnalysis(ast, source, decoder) {
  return {
    ast,
    source,
    decoder,
    globalDecoderAliases: collectDecoderAliases(ast, decoder.decoderFunctionName),
  };
}
