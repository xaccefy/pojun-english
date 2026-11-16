# Real Tool Execution via the Chat Endpoint

> Short-form pointer. What you are identifying is: "the identity endpoint blocks, the chat endpoint still accepts, and the tool list contains a tool that runs commands".  
> **Not** jailbreak / prompt injection (don't open with `llm-security-test.md`).  
> **Not** cloud IDE weak passwords + `command/exec` RPC (that set is in `cloud-ide-codex-rce-chain.md`).  
> For unauthorized history reads see `idor-test.md`, "Assistant history: unauthorized read of others' tasks" (full write-up only in that one).  
> Whether to write it up follows only `vuln-report-format.md`. Commands are limited to harmless markers / `id`.

## What to Identify

Any of the following:

1. Identity / whoami / profile-style endpoints return not-logged-in, 401, `unauthenticated`, while the **chat endpoint** of the same frontend (`/chat` / `createTask` style) still accepts requests without cookies  
2. **Attack even without a whoami control**: a public page lets you POST to create a session, with a body containing only `message` (or similar)

Plus: JS or the tool list contains a tool that runs commands (common names `bash` / `shell` / `code_interpreter` / `python` / `execute`; **the name list is not exhaustive** — what matters is that it executes).

Common frontends: helix-assistant, cloud-h5, cloud assistants with tool streams. Recognize reskins too; don't fixate on product names.

## Where to Attack (Without Logging In)

1. If there is an identity endpoint, verify it should block; if there is no identity endpoint, don't treat that as "no vulnerability"  
2. POST the chat endpoint and get the model to **use that tool** to run `id` (or `echo MARKER && id`), or use Python to compute an md5 you can also compute locally. Don't just ask "please execute" without naming the tool. `id` only proves the command really ran — **you must follow up**  
3. Watch the event stream / tool responses. **If SSE has only deltas and no `toolName`, don't stop**: compare the 32-char hex in the stream with local hashlib; or have it list the working directory and look for `AGENT.md` / `IDENTITY.md` / `SOUL.md` that never appeared in the prompt  
4. If there is a `fileUrls` / attachment URL parameter: put an external site and see whether the server pulls the title/ICP back into the conversation  
5. Once commands run, follow up on these three (if there is an entry point, attack it; if not, write the reason): the SRC-provided internal verification-platform flag; cloud metadata / temporary keys; another principal's business content in the sandbox (chat history, tickets, key files). A public homepage does not count as reaching the internal network

When you have a session, still fire the same shot: with identity passed, does the chat endpoint tool still accept the command you craft?

## What Counts as Success

stdout / SSE contains any of the following:

- SRC verification-platform flag (`ssrf-` style)  
- Cloud credentials (temporary tickets / permanent AKSK, where you can also elicit the account)  
- Another principal's business content (not the marker you just injected)

Sandbox `uid=`, a local md5, or a sandbox filename never mentioned in the prompt only prove the command ran — **they do not count as success**.

## False Positives

- The model only says verbally that it executed, the numbers don't match local, the sandbox filename was written in the prompt  
- The sandbox rejects commands, empty tool list  
- The chat endpoint also requires login, same gate as the identity endpoint  
- Only prompt jailbreak, no tool execution (that's not this shot)  
- Only curling public sites (Baidu homepage / ICP number) and calling it internal-network access

## When to Stop

No such endpoint → this shot is N/A, go back and attack change-id / password-change / the other four-piece set.  
Endpoint exists but only yields sandbox `uid=`, no flag / cloud key / other principal's content → falsify and stop, don't grind until you get root.  
Once identified, attack only the **current site**; do not FOFA the whole web for assistants with the same skin over this.
