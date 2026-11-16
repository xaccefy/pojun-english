"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

// The root route redirects to the main workspace. Note: do not use a server-side
// redirect() — `next build` static export (NEXT_EXPORT=1) does not support it; the
// redirect is dropped and the root route exports as a not-found page (the actual
// behaviour up to v0.3.87: opening http://host:8787/ returned 404). A client-side
// redirect exports fine under SSG and replaces immediately after hydration, leaving no
// history entry.
export default function Home() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/function/tasks");
  }, [router]);
  return (
    <div className="flex h-dvh items-center justify-center text-muted-foreground">
      Entering the workspace…
    </div>
  );
}
