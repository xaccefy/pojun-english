// Compatibility listener for MediaQueryList.
//
// addEventListener requires Safari 14 / Chrome 84. The WeChat/QQ in-app browsers common
// on Chinese phones (X5 kernel) and older Android WebViews may still be Chrome 77 era,
// where only addListener/removeListener exist. Calling addEventListener directly throws
// a TypeError — throwing that inside useEffect is enough to turn the whole page into
// "Application error: a client-side exception has occurred"
// (symptom: the page errors out on phones while desktop is fine).
export function listenMedia(mql: MediaQueryList, fn: () => void): () => void {
  const modern = mql as unknown as { addEventListener?: unknown; removeEventListener?: unknown };
  if (typeof modern.addEventListener === "function") {
    mql.addEventListener("change", fn);
    return () => mql.removeEventListener("change", fn);
  }
  const legacy = mql as unknown as {
    addListener?: (cb: () => void) => void;
    removeListener?: (cb: () => void) => void;
  };
  legacy.addListener?.(fn);
  return () => legacy.removeListener?.(fn);
}

// matchesMedia is a safe wrapper around matchMedia: it returns false when the
// environment has no matchMedia instead of throwing.
export function matchesMedia(query: string): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia(query).matches;
}
