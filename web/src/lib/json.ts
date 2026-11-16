// structuredClone needs Chrome 98 / Safari 15.4; it does not exist in older WebViews
// (some WeChat X5 kernels, old Android WebViews) and calling it directly throws a
// ReferenceError that takes the whole page down. Everything deep-copied in those
// scenarios is plain JSON, so a JSON round-trip is an equivalent and safe fallback.
export function cloneJson<T>(value: T): T {
  if (typeof structuredClone === "function") return structuredClone(value);
  return JSON.parse(JSON.stringify(value)) as T;
}
