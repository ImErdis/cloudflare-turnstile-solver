import * as acorn from "acorn";
import { collect, contains } from "./ast-utils.mjs";
import { canonicalJson, sha256Hex } from "./canonicalize.mjs";
import {
  createHandlerAnalysis,
  recognizeJumpStop,
  recognizeLebTable,
  recognizeTaggedLoad,
  structuralUnknownFingerprint,
} from "./handler-analysis.mjs";
import { finalizeProfile, VM_SKIP_PROFILE_SCHEMA_VERSION } from "./schema.mjs";
import { extractStaticStringDecoder } from "./static-decoder.mjs";

function fail(message) {
  throw new Error(`VM profile extraction: ${message}`);
}

function numericCases(switchStatement) {
  return switchStatement.cases.filter(
    (switchCase) =>
      switchCase.test?.type === "Literal" &&
      Number.isInteger(switchCase.test.value) &&
      switchCase.test.value >= 0 &&
      switchCase.test.value <= 255,
  );
}

function caseCall(switchCase) {
  const calls = switchCase.consequent
    .filter((statement) => statement.type === "ExpressionStatement")
    .map((statement) => statement.expression)
    .filter(
      (expression) =>
        expression.type === "CallExpression" &&
        expression.arguments[0]?.type === "ThisExpression",
    );
  if (calls.length !== 1) return null;
  const call = calls[0];
  let handlerLabel = null;
  if (call.callee.type === "Identifier") handlerLabel = call.callee.name;
  if (
    call.callee.type === "MemberExpression" &&
    call.callee.object.type === "Identifier"
  ) {
    handlerLabel = call.callee.object.name;
  }
  if (!handlerLabel) return null;
  const variant =
    call.arguments.length === 2 &&
    call.arguments[1].type === "Literal" &&
    Number.isInteger(call.arguments[1].value)
      ? call.arguments[1].value
      : null;
  if (call.arguments.length > 2 || (call.arguments.length === 2 && variant == null)) return null;
  return { handlerLabel, variant };
}

function dispatchCandidates(ast) {
  return collect(ast, (node) => node.type === "SwitchStatement")
    .map((switchStatement) => {
      const cases = numericCases(switchStatement);
      const rows = cases.map((switchCase) => {
        const call = caseCall(switchCase);
        return call && {
          opcode: switchCase.test.value,
          handlerLabel: call.handlerLabel,
          variant: call.variant,
        };
      });
      if (cases.length < 32 || rows.some((row) => !row)) return null;
      const opcodes = rows.map((row) => row.opcode);
      if (new Set(opcodes).size !== opcodes.length) return null;
      return { switchStatement, rows };
    })
    .filter(Boolean);
}

function dispatchSignature(candidate) {
  return canonicalJson(
    candidate.rows.map(({ opcode, handlerLabel, variant }) => [
      opcode,
      handlerLabel,
      variant,
    ]),
  );
}

function selectDispatch(ast) {
  const candidates = dispatchCandidates(ast);
  if (!candidates.length) fail("no >=32-case this-call dispatch switch found");
  const maxCases = Math.max(...candidates.map((candidate) => candidate.rows.length));
  const largest = candidates.filter((candidate) => candidate.rows.length === maxCases);
  const groups = new Map();
  for (const candidate of largest) {
    const signature = dispatchSignature(candidate);
    if (!groups.has(signature)) groups.set(signature, []);
    groups.get(signature).push(candidate);
  }
  if (groups.size !== 1) {
    fail(`${largest.length} maximal dispatch candidates have ${groups.size} conflicting maps`);
  }
  const equivalent = [...groups.values()][0].sort(
    (a, b) => a.switchStatement.start - b.switchStatement.start,
  );
  return { primary: equivalent[0], equivalent };
}

function integerLiterals(node) {
  return collect(
    node,
    (candidate) =>
      candidate.type === "Literal" &&
      Number.isInteger(candidate.value) &&
      candidate.value >= 0,
  ).map((literal) => literal.value);
}

function assignmentExpressions(switchStatement) {
  if (switchStatement.discriminant.type !== "SequenceExpression") return [];
  return switchStatement.discriminant.expressions.filter(
    (expression) => expression.type === "AssignmentExpression",
  );
}

function containsMemberRead(node) {
  return contains(
    node,
    (candidate) =>
      candidate.type === "MemberExpression" &&
      candidate.computed &&
      !(
        candidate.property.type === "Literal" &&
        typeof candidate.property.value === "string"
      ),
  );
}

function inferBias(opcodeAssignment) {
  const adds = collect(
    opcodeAssignment.right,
    (node) =>
      node.type === "BinaryExpression" &&
      node.operator === "+" &&
      ((node.left.type === "Literal" && containsMemberRead(node.right)) ||
        (node.right.type === "Literal" && containsMemberRead(node.left))),
  );
  for (const add of adds) {
    const value = add.left.type === "Literal" ? add.left.value : add.right.value;
    if (Number.isInteger(value) && value >= 0 && value <= 255) return (256 - value) & 255;
  }
  const subtracts = collect(
    opcodeAssignment.right,
    (node) =>
      node.type === "BinaryExpression" &&
      node.operator === "-" &&
      containsMemberRead(node.left) &&
      node.right.type === "Literal" &&
      Number.isInteger(node.right.value) &&
      node.right.value >= 0 &&
      node.right.value <= 255,
  );
  return subtracts.length === 1 ? subtracts[0].right.value : null;
}

function inferLinearFetch(candidate) {
  const assignments = assignmentExpressions(candidate.switchStatement);
  const discriminant = candidate.switchStatement.discriminant.expressions.at(-1);
  if (discriminant?.type !== "Identifier") return null;
  const opcodeAssignment = assignments.find(
    (assignment) =>
      assignment.left.type === "Identifier" &&
      assignment.left.name === discriminant.name &&
      containsMemberRead(assignment.right),
  );
  if (!opcodeAssignment) return null;
  const keyAssignments = assignments.filter((assignment) => {
    const constants = integerLiterals(assignment.right);
    return constants.some((value) => value >= 1_000 && value <= 65_535);
  });
  for (const keyAssignment of keyAssignments) {
    const multiplications = collect(
      keyAssignment.right,
      (node) =>
        node.type === "BinaryExpression" &&
        node.operator === "*" &&
        ((node.left.type === "Literal" &&
          Number.isInteger(node.left.value) &&
          node.left.value >= 1_000) ||
          (node.right.type === "Literal" &&
            Number.isInteger(node.right.value) &&
            node.right.value >= 1_000)),
    );
    if (multiplications.length !== 1) continue;
    const multiply = multiplications[0];
    const keyMul =
      multiply.left.type === "Literal" ? multiply.left.value : multiply.right.value;
    const large = [...new Set(integerLiterals(keyAssignment.right).filter((value) => value >= 1_000))];
    const adds = large.filter((value) => value !== keyMul);
    if (adds.length !== 1) continue;
    const byteBias = inferBias(opcodeAssignment);
    if (byteBias == null) continue;
    return {
      byteBias,
      keyMul,
      keyAdd: adds[0],
      keyQuadB: 0,
    };
  }
  return null;
}

function inferFetch(dispatch) {
  const exact = dispatch.equivalent
    .map(inferLinearFetch)
    .filter(Boolean);
  if (!exact.length) fail("no exact linear fetch recurrence in equivalent dispatches");
  const unique = new Map(exact.map((fetch) => [canonicalJson(fetch), fetch]));
  if (unique.size !== 1) fail("equivalent dispatches disagree on the fetch recurrence");
  return [...unique.values()][0];
}

function inferEntry(ast) {
  const entries = collect(
    ast,
    (node) =>
      ["CallExpression", "NewExpression"].includes(node.type) &&
      node.arguments?.length === 3 &&
      node.arguments[0]?.type === "Literal" &&
      Number.isInteger(node.arguments[0].value) &&
      node.arguments[0].value >= 0 &&
      node.arguments[1]?.type === "Literal" &&
      Number.isInteger(node.arguments[1].value) &&
      node.arguments[1].value >= 0 &&
      node.arguments[1].value <= 255 &&
      node.arguments[2]?.type === "ArrayExpression" &&
      node.arguments[2].elements.length === 0,
  ).map((node) => ({
    initPc: node.arguments[0].value,
    initKey: node.arguments[1].value,
  }));
  const unique = new Map(entries.map((entry) => [canonicalJson(entry), entry]));
  if (unique.size !== 1) fail(`expected one VM entry state, found ${unique.size}`);
  return [...unique.values()][0];
}

function recognizedHandler(fn, analysis) {
  const recognizers = [
    recognizeTaggedLoad(fn, analysis),
    recognizeLebTable(fn, analysis),
    recognizeJumpStop(fn, analysis),
  ].filter(Boolean);
  if (recognizers.length > 1) return null;
  return recognizers[0] ?? null;
}

export function extractVmProfile(source, { sourceName = "<memory>" } = {}) {
  const ast = acorn.parse(source, {
    ecmaVersion: "latest",
    sourceType: "script",
    allowReturnOutsideFunction: true,
    ranges: true,
  });
  const functions = new Map(
    collect(ast, (node) => node.type === "FunctionDeclaration" && node.id?.name).map((fn) => [
      fn.id.name,
      fn,
    ]),
  );
  const dispatch = selectDispatch(ast);
  const fetch = { ...inferEntry(ast), ...inferFetch(dispatch) };
  const decoder = extractStaticStringDecoder(ast);
  const analysis = createHandlerAnalysis(ast, source, decoder);
  const rows = [...dispatch.primary.rows].sort((a, b) => a.opcode - b.opcode);
  const handlers = rows.map((row) => {
    const fn = functions.get(row.handlerLabel);
    if (!fn) fail(`case ${row.opcode} handler ${row.handlerLabel} has no FunctionDeclaration`);
    const recognized = recognizedHandler(fn, analysis);
    const evidence = recognized
      ? { caseVariant: row.variant, ...recognized.evidence }
      : null;
    return {
      opcode: row.opcode,
      handlerLabel: row.handlerLabel,
      handlerFingerprint: recognized
        ? sha256Hex(canonicalJson(evidence))
        : structuralUnknownFingerprint(fn, row.variant),
      spec: recognized?.spec ?? {
        kind: "unknown",
        reason: "no exact static recognizer for this normalized handler",
      },
    };
  });
  const profile = finalizeProfile({
    schemaVersion: VM_SKIP_PROFILE_SCHEMA_VERSION,
    sourceSha256: sha256Hex(source),
    semanticFingerprint: "0".repeat(64),
    fetch,
    switchOpcodes: rows.map((row) => row.opcode),
    handlers,
  });
  return {
    profile,
    summary: {
      sourceName,
      sourceBytes: Buffer.byteLength(source),
      equivalentDispatches: dispatch.equivalent.length,
      switchCaseCount: rows.length,
      decoder: {
        offset: decoder.offset,
        rotations: decoder.rotations,
      },
      recognized: handlers
        .filter((handler) => handler.spec.kind !== "unknown")
        .map((handler) => ({ opcode: handler.opcode, kind: handler.spec.kind })),
      unknownCount: handlers.filter((handler) => handler.spec.kind === "unknown").length,
    },
  };
}
