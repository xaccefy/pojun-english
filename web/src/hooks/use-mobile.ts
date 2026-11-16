import * as React from "react";

import { listenMedia } from "@/lib/media-query";

const MOBILE_BREAKPOINT = 768;

export function useIsMobile() {
  // Start as undefined (renders as false) and let the effect correct it against the
  // real viewport: the static export's first HTML frame is produced without a window,
  // so reading innerWidth here would cause a hydration mismatch.
  const [isMobile, setIsMobile] = React.useState<boolean | undefined>(undefined);

  React.useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mql = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`);
    const onChange = () => setIsMobile(window.innerWidth < MOBILE_BREAKPOINT);
    onChange();
    return listenMedia(mql, onChange);
  }, []);

  return !!isMobile;
}
