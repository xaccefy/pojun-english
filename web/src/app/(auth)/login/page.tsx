"use client";

import { useEffect, useRef, useState } from "react";

import { useRouter } from "next/navigation";

import { AlertTriangle, ShieldHalf } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

// Anti-fingerprinting conventions for the auth page (public deployment scenario):
//   1. No product name in copy or structure, and no reference to /logo.png (image hashes
//      are the easiest thing to map); the top geometric mark is inline SVG that follows
//      the theme and needs no separate asset.
//   2. v0.4.43 visual upgrade: double animated glow background + glassmorphism card +
//      entrance animation + micro-interactions (input focus glow, button gradient), all
//      pure CSS with no external resources.
export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [agreed, setAgreed] = useState(false);
  const [termsOpen, setTermsOpen] = useState(false);
  const [readToEnd, setReadToEnd] = useState(false);
  const [focused, setFocused] = useState(false);
  const termsBodyRef = useRef<HTMLDivElement>(null);

  function handleTermsScroll() {
    const el = termsBodyRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 8) setReadToEnd(true);
  }

  useEffect(() => {
    if (!termsOpen) return;
    setReadToEnd(false);
    const el = termsBodyRef.current;
    if (el && el.scrollHeight <= el.clientHeight + 8) setReadToEnd(true);
  }, [termsOpen]);

  useEffect(() => {
    const token = auth.getToken();
    if (token) {
      auth.setToken(token);
      window.location.replace("/function/tasks");
      return;
    }
    api
      .authStatus()
      .then(({ initialized }) => {
        if (!initialized) router.replace("/setup");
      })
      .catch(() => setError("Cannot reach the backend service"))
      .finally(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!agreed) {
      setError("Please read and accept the Security and Compliance Notice first");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.login("POJUN", password);
      auth.setToken(token);
      window.location.replace("/function/tasks");
    } catch (e) {
      const err = e as Error & { status?: number };
      if (!err.status) {
        setError("Cannot reach the backend service; make sure it is running");
      } else if (err.status === 429) {
        setError(err.message || "Too many attempts; the account is temporarily locked. Try again later");
      } else if (err.status === 403 && err.message.includes("not initialized")) {
        setError("The password is not initialized yet; complete the first-time setup first");
      } else if (err.status === 401) {
        setError("Wrong username or password");
      } else {
        setError(err.message || "Sign-in failed; try again later");
      }
    } finally {
      setLoading(false);
    }
  }

  if (checking) {
    return (
      <div role="status" className="flex min-h-dvh items-center justify-center text-muted-foreground">
        <div className="flex items-center gap-3">
          <ShieldHalf className="size-5 animate-pulse text-primary" />
          Checking sign-in status…
        </div>
      </div>
    );
  }

  return (
    <div className="relative flex min-h-dvh flex-col items-center justify-center overflow-hidden p-6">
      {/* Background: double animated glow + fine grid + bottom fade */}
      <div aria-hidden className="pointer-events-none absolute inset-0">
        <div className="absolute inset-0 bg-background" />
        <div
          className="absolute inset-0 opacity-[0.18]"
          style={{
            backgroundImage:
              "linear-gradient(to right, hsl(var(--border)) 1px, transparent 1px), linear-gradient(to bottom, hsl(var(--border)) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
            maskImage: "radial-gradient(ellipse 75% 65% at 50% 40%, black 20%, transparent 78%)",
            WebkitMaskImage: "radial-gradient(ellipse 75% 65% at 50% 40%, black 20%, transparent 78%)",
          }}
        />
        <div
          className="absolute -top-[30%] left-1/2 h-[60vh] w-[80vw] -translate-x-1/2 rounded-full opacity-[0.07]"
          style={{ background: "radial-gradient(ellipse, hsl(35 90% 55%) 0%, transparent 70%)" }}
        />
        <div
          className="absolute -bottom-[20%] left-1/2 h-[50vh] w-[70vw] -translate-x-1/2 rounded-full opacity-[0.05]"
          style={{ background: "radial-gradient(ellipse, hsl(210 80% 50%) 0%, transparent 70%)" }}
        />
        <div
          className="absolute left-1/2 top-1/2 h-[80vh] w-[60vw] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-[0.04]"
          style={{ background: "radial-gradient(ellipse, hsl(var(--primary)) 0%, transparent 70%)" }}
        />
      </div>

      <div className="relative w-full max-w-sm animate-in fade-in slide-in-from-bottom-6 duration-500">
        <div className="rounded-2xl border bg-card/80 p-8 shadow-xl backdrop-blur-md">
          <div className="mb-8 flex flex-col items-center gap-4 text-center">
            <div className="relative">
              <div
                aria-hidden
                className="absolute -inset-2 rounded-2xl bg-primary/5 blur-md"
                style={{ animation: "pulse 4s cubic-bezier(0.4,0,0.6,1) infinite" }}
              />
              <svg
                aria-hidden
                viewBox="0 0 48 48"
                className="relative size-14 text-primary"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <rect x="9" y="20" width="30" height="22" rx="4" />
                <path d="M17 20v-6a7 7 0 0 1 14 0v6" />
                <circle cx="24" cy="31" r="2.5" fill="currentColor" stroke="none" />
              </svg>
            </div>
            <div>
              <h1 className="font-semibold text-2xl tracking-tight">Console sign-in</h1>
              <p className="mt-1.5 text-muted-foreground text-sm">Authorized operators only</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="flex flex-col gap-5">
            <div className="space-y-1.5">
              <Label htmlFor="username" className="text-muted-foreground text-xs">Username</Label>
              <Input
                id="username"
                value="POJUN"
                readOnly
                className="border-border/60 bg-muted/50 font-mono text-muted-foreground"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-muted-foreground text-xs">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoFocus
                  autoComplete="current-password"
                  onFocus={() => setFocused(true)}
                  onBlur={() => setFocused(false)}
                  className="border-border/60 pr-10 transition-shadow duration-200"
                />
                <div
                  aria-hidden
                  className={`absolute -bottom-px left-1/2 h-px -translate-x-1/2 bg-primary transition-all duration-300 ${
                    focused ? "w-full opacity-100" : "w-0 opacity-0"
                  }`}
                />
              </div>
            </div>
            <div className="flex items-start gap-2">
              <Checkbox
                id="agree-terms"
                checked={agreed}
                onCheckedChange={(v) => setAgreed(v === true)}
                className="mt-0.5"
              />
              <Label htmlFor="agree-terms" className="font-normal text-muted-foreground text-sm leading-relaxed">
                I have read and accept
                <button
                  type="button"
                  onClick={() => setTermsOpen(true)}
                  className="mx-0.5 font-medium text-primary underline-offset-4 hover:underline"
                >
                  the Security and Compliance Notice
                </button>
              </Label>
            </div>
            {error && (
              <p className="animate-in fade-in slide-in-from-top-1 text-destructive text-sm">{error}</p>
            )}
            <Button
              type="submit"
              className="h-10 w-full font-medium tracking-wide transition-all duration-200 hover:shadow-md"
              disabled={loading || !password || !agreed}
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="inline-block size-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
                  Signing in…
                </span>
              ) : (
                "Sign in"
              )}
            </Button>
          </form>
        </div>

        <p className="mt-6 text-center text-muted-foreground/60 text-xs">
          Repeated sign-in failures trigger a temporary lockout
        </p>
      </div>

      <Dialog open={termsOpen} onOpenChange={setTermsOpen}>
        <DialogContent className="gap-0 p-0 sm:max-w-xl">
          <DialogHeader className="flex-row items-center gap-3 border-b px-6 py-4">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
              <AlertTriangle className="size-5" />
            </div>
            <DialogTitle className="text-base">Security and Compliance Notice</DialogTitle>
          </DialogHeader>
          <div
            ref={termsBodyRef}
            onScroll={handleTermsScroll}
            className="max-h-[55vh] space-y-4 overflow-y-auto px-6 py-5 text-muted-foreground text-sm leading-relaxed"
          >
            <p>
              This system is for authorized personnel to conduct security assessments within a lawful
              authorization scope only. By signing in you confirm that you understand and accept the
              following constraints:
            </p>
            <ul className="ml-5 list-disc space-y-2">
              <li>
                You may only test targets for which you have **explicit written authorization**;
                scanning, probing or exploiting any unauthorized system is a breach of policy and may
                be illegal;
              </li>
              <li>
                This system can execute commands on servers — guard your access credentials well;
                leaked credentials are equivalent to leaked server control;
              </li>
              <li>
                The built-in interception and approval mechanisms reduce the risk of mistakes but are
                not a guarantee that use is lawful; all legal responsibility arising from use rests
                with the user;
              </li>
              <li>Using this system for any activity that violates the laws or regulations of your country or
                region is strictly forbidden.</li>
            </ul>
          </div>
          <DialogFooter className="mx-0 mb-0 flex-col items-stretch gap-2 rounded-b-xl px-6 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-muted-foreground text-xs">
              {readToEnd ? "You have read all the terms" : "Scroll to the bottom of the terms before confirming"}
            </p>
            <DialogClose asChild>
              <Button
                type="button"
                disabled={!readToEnd}
                onClick={() => {
                  setAgreed(true);
                  setError("");
                }}
              >
                I have read and accept
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
