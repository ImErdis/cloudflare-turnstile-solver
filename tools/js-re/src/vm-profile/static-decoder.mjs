import { collect, contains, propertyName } from "./ast-utils.mjs";

function fail(message) {
  throw new Error(`static string decoder: ${message}`);
}

function findStringTable(functions) {
  const matches = [];
  for (const fn of functions.values()) {
    const templates = collect(
      fn,
      (node) => node.type === "TemplateLiteral" && node.quasis.length === 1,
    );
    for (const template of templates) {
      const cooked = template.quasis[0].value.cooked;
      if (typeof cooked !== "string") continue;
      const values = cooked.split(";");
      if (values.length >= 256) matches.push({ fn, values });
    }
  }
  if (matches.length !== 1) fail(`expected one large static table, found ${matches.length}`);
  return matches[0];
}

function findDecoder(functions, tableFunctionName) {
  const matches = [];
  for (const fn of functions.values()) {
    const tableCalls = collect(
      fn,
      (node) => node.type === "CallExpression" && node.callee?.name === tableFunctionName,
    );
    if (!tableCalls.length) continue;
    const subtracts = collect(
      fn,
      (node) =>
        node.type === "AssignmentExpression" &&
        node.operator === "=" &&
        node.left.type === "Identifier" &&
        node.right.type === "BinaryExpression" &&
        node.right.operator === "-" &&
        node.right.left.type === "Identifier" &&
        node.right.left.name === node.left.name &&
        node.right.right.type === "Literal" &&
        Number.isInteger(node.right.right.value),
    );
    for (const subtract of subtracts) {
      if (fn.params.some((param) => param.type === "Identifier" && param.name === subtract.left.name)) {
        matches.push({ fn, offset: subtract.right.right.value });
      }
    }
  }
  if (matches.length !== 1) fail(`expected one index decoder, found ${matches.length}`);
  return matches[0];
}

function findRotation(ast, tableFunctionName) {
  const matches = collect(
    ast,
    (node) =>
      node.type === "CallExpression" &&
      node.callee?.type === "FunctionExpression" &&
      node.arguments?.[0]?.type === "Identifier" &&
      node.arguments[0].name === tableFunctionName &&
      node.arguments?.[1]?.type === "Literal" &&
      Number.isFinite(node.arguments[1].value) &&
      contains(
        node.callee,
        (child) =>
          child.type === "CallExpression" &&
          child.callee?.type === "MemberExpression" &&
          ["push", "shift"].includes(propertyName(child.callee.property)),
      ),
  );
  if (matches.length !== 1) fail(`expected one static table rotation, found ${matches.length}`);
  return matches[0];
}

function numericObjectAssignment(fn) {
  const matches = collect(
    fn,
    (node) =>
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      node.left.type === "Identifier" &&
      node.right.type === "ObjectExpression" &&
      node.right.properties.length > 0 &&
      node.right.properties.every(
        (property) => property.type === "Property" && typeof property.value?.value === "number",
      ),
  );
  if (matches.length !== 1) fail(`rotation numeric map count ${matches.length}`);
  const assignment = matches[0];
  return {
    name: assignment.left.name,
    values: Object.fromEntries(
      assignment.right.properties.map((property) => [
        propertyName(property.key),
        property.value.value,
      ]),
    ),
  };
}

function scoreAssignment(fn) {
  const matches = collect(
    fn,
    (node) =>
      node.type === "AssignmentExpression" &&
      contains(
        node.right,
        (child) => child.type === "CallExpression" && child.callee?.name === "parseInt",
      ),
  );
  if (matches.length !== 1) fail(`rotation score assignment count ${matches.length}`);
  return matches[0];
}

function evaluateRotationExpression(
  node,
  { map, mapName, target, targetName, decoderNames, decode },
) {
  switch (node.type) {
    case "Literal":
      return node.value;
    case "Identifier":
      if (node.name === targetName) return target;
      fail(`unsupported rotation identifier ${node.name}`);
      break;
    case "MemberExpression": {
      if (node.object?.name !== mapName) fail("unsupported rotation member expression");
      const key = node.computed
        ? evaluateRotationExpression(node.property, {
            map,
            mapName,
            target,
            targetName,
            decoderNames,
            decode,
          })
        : propertyName(node.property);
      if (!Object.hasOwn(map, key)) fail(`unknown rotation map key ${key}`);
      return map[key];
    }
    case "UnaryExpression": {
      const value = evaluateRotationExpression(node.argument, {
        map,
        mapName,
        target,
        targetName,
        decoderNames,
        decode,
      });
      if (node.operator === "-") return -value;
      if (node.operator === "+") return +value;
      fail(`unsupported rotation unary ${node.operator}`);
      break;
    }
    case "BinaryExpression": {
      const left = evaluateRotationExpression(node.left, {
        map,
        mapName,
        target,
        targetName,
        decoderNames,
        decode,
      });
      const right = evaluateRotationExpression(node.right, {
        map,
        mapName,
        target,
        targetName,
        decoderNames,
        decode,
      });
      if (node.operator === "+") return left + right;
      if (node.operator === "-") return left - right;
      if (node.operator === "*") return left * right;
      if (node.operator === "/") return left / right;
      fail(`unsupported rotation binary ${node.operator}`);
      break;
    }
    case "CallExpression": {
      if (node.callee?.name === "parseInt") {
        return Number.parseInt(
          evaluateRotationExpression(node.arguments[0], {
            map,
            mapName,
            target,
            targetName,
            decoderNames,
            decode,
          }),
          10,
        );
      }
      if (decoderNames.has(node.callee?.name) && node.arguments.length === 1) {
        return decode(
          evaluateRotationExpression(node.arguments[0], {
            map,
            mapName,
            target,
            targetName,
            decoderNames,
            decode,
          }),
        );
      }
      fail(`unsupported rotation call ${node.callee?.name ?? node.callee?.type}`);
      break;
    }
    default:
      fail(`unsupported rotation expression ${node.type}`);
  }
}

export function extractStaticStringDecoder(ast) {
  const functions = new Map(
    collect(ast, (node) => node.type === "FunctionDeclaration" && node.id?.name).map((fn) => [
      fn.id.name,
      fn,
    ]),
  );
  const table = findStringTable(functions);
  const decoder = findDecoder(functions, table.fn.id.name);
  const rotation = findRotation(ast, table.fn.id.name);
  const rotationFn = rotation.callee;
  const target = rotation.arguments[1].value;
  const targetName = rotationFn.params[1]?.name;
  if (!targetName) fail("rotation target parameter is missing");
  const map = numericObjectAssignment(rotationFn);
  const score = scoreAssignment(rotationFn);
  const decoderNames = new Set([
    decoder.fn.id.name,
    rotationFn.params[3]?.name,
  ]);
  const values = [...table.values];

  const decode = (index) => {
    if (!Number.isInteger(index)) fail(`decoder index ${index} is not an integer`);
    const slot = index - decoder.offset;
    if (slot < 0 || slot >= values.length) fail(`decoder slot ${slot} is out of bounds`);
    return values[slot];
  };

  let rotations = 0;
  for (; rotations < values.length; rotations += 1) {
    const current = evaluateRotationExpression(score.right, {
      map: map.values,
      mapName: map.name,
      target,
      targetName,
      decoderNames,
      decode,
    });
    if (current === target) break;
    values.push(values.shift());
  }
  if (rotations === values.length) fail("rotation target was never reached");

  return {
    tableFunctionName: table.fn.id.name,
    decoderFunctionName: decoder.fn.id.name,
    offset: decoder.offset,
    rotations,
    values,
    decode,
  };
}

export function collectDecoderAliases(ast, decoderFunctionName) {
  const aliases = new Set([decoderFunctionName]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const assignment of collect(
      ast,
      (node) =>
        node.type === "AssignmentExpression" &&
        node.operator === "=" &&
        node.left.type === "Identifier" &&
        node.right.type === "Identifier",
    )) {
      if (aliases.has(assignment.right.name) && !aliases.has(assignment.left.name)) {
        aliases.add(assignment.left.name);
        changed = true;
      }
    }
  }
  return aliases;
}
