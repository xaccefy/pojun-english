"use client";

import * as React from "react";

import { getLocalStorageValue, setLocalStorageValue } from "@/lib/local-storage.client";

// Send/newline key binding for the chat composer. Pure front-end preference: it only
// lands in localStorage, never in the DB, and does not sync with the account, so a
// different browser needs it set again. See issue #39 — 0.3.2 changed sending from
// Ctrl+Enter to Enter; this brings the old binding back as an option.
export type ChatSendMode = "enter" | "ctrl-enter";

export const CHAT_SEND_MODE_KEY = "pojun_chat_send_mode";
export const DEFAULT_CHAT_SEND_MODE: ChatSendMode = "enter";

export const CHAT_SEND_MODE_OPTIONS: { value: ChatSendMode; label: string }[] = [
  { value: "enter", label: "Enter to send, Shift+Enter for a new line" },
  { value: "ctrl-enter", label: "Ctrl+Enter to send, Enter for a new line" },
];

function parseMode(raw: string | null): ChatSendMode {
  return raw === "ctrl-enter" || raw === "enter" ? raw : DEFAULT_CHAT_SEND_MODE;
}

// Subscribers within the same tab. localStorage's storage event only fires in *other*
// tabs, so after changing the setting on this page we emit to notify the composer in
// the same tab; otherwise it would only take effect after a refresh.
const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  window.addEventListener("storage", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", listener);
  };
}

// The return value is a string literal, so Object.is compares by value and
// useSyncExternalStore does not loop.
function getSnapshot(): ChatSendMode {
  return parseMode(getLocalStorageValue(CHAT_SEND_MODE_KEY));
}

// The server has no localStorage, so render the default first and let getSnapshot
// correct it after hydration.
function getServerSnapshot(): ChatSendMode {
  return DEFAULT_CHAT_SEND_MODE;
}

export function useChatSendMode(): ChatSendMode {
  return React.useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

export function setChatSendMode(mode: ChatSendMode) {
  setLocalStorageValue(CHAT_SEND_MODE_KEY, mode);
  for (const listener of listeners) listener();
}

// shouldSubmitOnKey decides whether a key press should send the message.
// isComposing / keyCode 229 mean an IME (Chinese and others) is still composing: that must
// pass through, otherwise pressing Enter to pick a candidate would send by mistake.
// enter mode only excludes Shift, byte-for-byte the same as 0.3.2 — users who never touch
// the setting keep the same feel. ctrl-enter mode accepts both Ctrl and Cmd (macOS).
export function shouldSubmitOnKey(e: React.KeyboardEvent, mode: ChatSendMode): boolean {
  if (e.key !== "Enter") return false;
  if (e.nativeEvent.isComposing || e.nativeEvent.keyCode === 229) return false;
  if (mode === "ctrl-enter") return e.ctrlKey || e.metaKey;
  return !e.shiftKey;
}
