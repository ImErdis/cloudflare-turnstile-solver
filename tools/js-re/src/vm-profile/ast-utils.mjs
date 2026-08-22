export function walk(node, visit, parent = null) {
  if (!node || typeof node !== "object") return;
  if (typeof node.type === "string") visit(node, parent);
  for (const [key, value] of Object.entries(node)) {
    if (key === "start" || key === "end" || key === "loc" || key === "raw") continue;
    if (Array.isArray(value)) {
      for (const child of value) walk(child, visit, node);
    } else if (value && typeof value === "object" && typeof value.type === "string") {
      walk(value, visit, node);
    }
  }
}

export function collect(node, predicate) {
  const values = [];
  walk(node, (candidate, parent) => {
    if (predicate(candidate, parent)) values.push(candidate);
  });
  return values;
}

export function contains(node, predicate) {
  let found = false;
  walk(node, (candidate, parent) => {
    if (!found && predicate(candidate, parent)) found = true;
  });
  return found;
}

export function propertyName(property) {
  if (!property) return null;
  if (property.type === "Identifier") return property.name;
  if (property.type === "Literal" && typeof property.value === "string") return property.value;
  return null;
}

export function nodeSource(source, node) {
  return source.slice(node.start, node.end);
}
