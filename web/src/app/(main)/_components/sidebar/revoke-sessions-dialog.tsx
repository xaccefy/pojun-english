"use client";

import * as React from "react";

import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { api } from "@/lib/api";

// Audit B1: revoke every signed-in session (including this device). A dangerous admin action — the
// backend requires confirm:true, so the frontend asks for one more confirmation; on success it drops
// the local token and goes to the login page.
export function RevokeSessionsDialog({
  open,
  onOpenChange,
}: {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
}) {
  const [busy, setBusy] = React.useState(false);

  function confirm() {
    setBusy(true);
    api
      .revokeAllSessions()
      .then(() => {
        toast.success("All sessions revoked — sign in again");
        // Hard redirect for a fresh login state (the token is dead; keeping it only yields repeated 401s)
        window.location.href = "/login";
      })
      .catch((err) => toast.error(`Revocation failed: ${(err as Error).message}`))
      .finally(() => {
        setBusy(false);
        onOpenChange(false);
      });
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke every session?</AlertDialogTitle>
          <AlertDialogDescription>
            Every signed-in device (this one included) is signed out and must enter the password again. Use it when a
            token is suspected leaked but you don't want to change the password; changing the password also
            invalidates every old session immediately.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            disabled={busy}
            className="bg-destructive text-white hover:bg-destructive/90"
            onClick={(e) => {
              e.preventDefault();
              confirm();
            }}
          >
            {busy ? "Revoking…" : "Revoke all"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
