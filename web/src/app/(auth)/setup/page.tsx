"use client";

import { useEffect, useState } from "react";

import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export default function SetupPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  // When the initialization state cannot be read, do not default to "not initialized" —
  // that would show the setup form for an instance that already has a password, and the
  // user filling it in would overwrite the existing one. Close the entry point instead.
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    api
      .authStatus()
      .then(({ initialized }) => {
        if (initialized) router.replace("/login");
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "Cannot reach the backend service");
        setUnavailable(true);
      })
      .finally(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("The two passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("The password must be at least 8 characters");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.initPassword(password);
      auth.setToken(token);
      router.replace("/function/tasks");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed");
    } finally {
      setLoading(false);
    }
  }

  if (checking) return null;

  return (
    <div className="flex min-h-dvh items-center justify-center bg-muted/40 p-6">
      {/* Same shape as the sign-in page: one centred card with no hashable image assets */}
      <div className="w-full max-w-sm">
        <div className="space-y-10 rounded-2xl border bg-card p-8 shadow-lg lg:p-10">
          <div className="space-y-4 text-center">
            <h2 className="font-medium text-2xl tracking-tight">{unavailable ? "Cannot determine the setup state" : "Set up the password"}</h2>
            <p className="mx-auto max-w-xl text-muted-foreground">
              {unavailable
                ? "The backend or database is temporarily unavailable. To avoid overwriting the password already set on this instance, the setup entry point is temporarily closed — restore the service and retry."
                : "First use: set a sign-in password for the account (at least 8 characters)"}
            </p>
          </div>
          {unavailable ? (
            <div className="flex flex-col gap-4">
              {error && <p className="text-center text-destructive text-sm">{error}</p>}
              <Button type="button" className="w-full" onClick={() => window.location.reload()}>
                Retry
              </Button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="password">New password</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="At least 8 characters"
                  autoFocus
                  autoComplete="new-password"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirm">Confirm password</Label>
                <Input
                  id="confirm"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="Enter the password again"
                  autoComplete="new-password"
                />
              </div>
              {error && <p className="text-destructive text-sm">{error}</p>}
              <Button type="submit" className="w-full" disabled={loading || !password || !confirm}>
                {loading ? "Saving..." : "Set password and sign in"}
              </Button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
