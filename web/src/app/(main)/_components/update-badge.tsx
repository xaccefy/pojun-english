"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowUpCircleIcon } from "lucide-react";

import { api } from "@/lib/api";

/**
 * The top bar's "new version available" hint: checked once per full page load, shown next
 * to the version number when an update exists, and clicking goes straight to the "Version
 * and updates" card on the system settings page.
 *
 * The backend caches its GitHub query for 30 minutes, so checking on every mount here is
 * safe — the unauthenticated GitHub API allows only 60 requests/hour/IP, and without that
 * cache a few open tabs would burn the quota, leaving the real update check unable to run.
 *
 * Failures are always silent: the top bar is not the place for errors; the reason is shown
 * when the user opens settings and clicks "check for updates".
 */
export function UpdateBadge() {
  const [latest, setLatest] = React.useState("");

  React.useEffect(() => {
    let alive = true;
    api
      .checkUpdate()
      .then((r) => {
        // has_update already includes the "versions are comparable" check, so development
        // builds never light this hint up.
        if (alive && r.has_update && r.latest) setLatest(r.latest.replace(/^v(?=\d)/, ""));
      })
      .catch(() => {
        // Silent: neither being offline nor GitHub rate limiting should raise an error in
        // the top bar.
      });
    return () => {
      alive = false;
    };
  }, []);

  if (!latest) return null;

  return (
    <Link
      href="/system/settings"
      title={`New version ${latest} available; click to update`}
      className="inline-flex items-center gap-1.5 rounded-full bg-primary px-2.5 py-1 font-medium text-primary-foreground text-xs transition-opacity hover:opacity-90"
    >
      {/* Breathing dot: the top bar is busy and plain text gets ignored, so motion makes it
      obvious at a glance. */}
      <span className="relative flex size-1.5">
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-primary-foreground opacity-75" />
        <span className="relative inline-flex size-1.5 rounded-full bg-primary-foreground" />
      </span>
      <ArrowUpCircleIcon className="size-3.5" />
      <span className="hidden sm:inline">New version {latest}</span>
      <span className="sm:hidden">New version</span>
    </Link>
  );
}
