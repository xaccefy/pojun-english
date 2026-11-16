# Side-question long conversations and context budget

Fixed 2026-09-11. The original implementation treated the character count of the request JSON directly as tokens and inherited the main task's 32K output reservation, so normal side questions were rejected early when there was a lot of HTML, JS, and tool results.

## Open-source implementation cross-check

- [Grok CLI side-question context](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/agent/agent.ts#L739): extracts snippets from the most recent user and assistant text, with a character budget of about 2000 and at most 400 characters per item. It does not maintain continuous side-question Q&A history on this path.
- [Grok CLI standalone request](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/utils/side-question.ts): independent cancellation signal; output cap of 2048 tokens when the model supports it; no tools provided.
- [Grok CLI main-session compaction](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/agent/compaction.ts): estimates tokens, keeps recent content, folds new content into the old summary, and handles cross-turn truncation.
- [OpenCode session compaction](https://github.com/anomalyco/opencode/blob/b3f1a96c6dd7adeb28b36dd11add1998fc84d67b/packages/core/src/session/compaction.ts): full request estimation, output/buffer reservation, recent content plus a rolling summary, tool-free summary requests; this implementation defaults to a recent budget of 8000 and a summary output cap of 4096 tokens.
- [OpenCode overflow recovery](https://github.com/anomalyco/opencode/blob/b3f1a96c6dd7adeb28b36dd11add1998fc84d67b/packages/core/src/session/runner/llm.ts): attempts overflow recovery only before assistant output has begun, and the recovered call does not re-enter the same overflow-recovery path.

ARTEX draws on the separate output budget, recent content plus rolling summary, and bounded recovery. It keeps norma v0.3.6's structured messages and tool pairing, does not copy Grok's text extraction, and does not write OpenCode's main-session compaction events into the ARTEX main transcript.

## Request budget and execution

- Messages keep norma's UTF-8 byte estimation by content block with a 4/3 margin; system prompt, tool schemas, and message-envelope overhead are counted additionally. The estimate is not an exact model token count.
- Side-question output defaults to at most 8192 tokens and also does not exceed the output cap already set in the main config. The service environment variable `POJUN_BTW_MAX_OUTPUT_TOKENS` can set a cap in the range 256–32768; the product's default model and main-task parameters are not modified.
- The input budget is the context window minus the output cap and a safety margin; an unknown window uses the platform default of 200K. The safety margin is 5% of the window, minimum 128 and maximum 8192 tokens.
- Successful Q&A pairs are loaded in batches of at most 20 by ascending ordinal. At most 20 pairs of original text are retained, their token budget being at most 1/4 of the input budget and no more than 16K.
- Excess Q&A pairs are folded into a rolling summary. The summary carries history provenance and context time; a historical assistant reply is not equivalent to new tool evidence, and on conflict the latest main snapshot takes precedence.
- When the main context is still too long, only old messages in the summary copy are trimmed, keeping at most 8K tokens of recent content; the cut point never splits a tool call from its result. An oversized single pair goes into the summary in its entirety.
- Summary input is chunked in a UTF-8-safe way against the actual remaining window, with an output cap of 2048 tokens; empty summaries, truncation, tool calls, or exceeding the summary budget are not written to cache. At most 12 summary calls per side question, all subject to the same 120-second timeout; hitting the limit fails explicitly rather than looping indefinitely.
- If the model first returns a context-over-limit error and has not yet emitted text or a tool call, it retries at most once after further reduction; if the estimated size did not decrease, recovery stops immediately. Other model errors and partial streaming output do not trigger this recovery.
- All usage obtained, including for summaries, failed attempts, and cancellations, is accumulated into the same side-question request. When the Provider returns no usage, only zero can be recorded; estimates must not be passed off as actual usage.

## Persistence and UI

`side_question_sessions.memory` stores the summary of old Q&A, the covered ordinal, and the main-context summary cached by snapshot identity. `side_question_requests.context_info` stores the preparation stage, the number of replayed pairs, summary usage, and budget estimates.

A summary is saved only while the original request is still running and the cleanup version matches; clearing also removes the cache, and late writes cannot restore cleared data. A new snapshot does not reuse the old snapshot's summary. The summary fields are saved with v3 task archiving; when restoring an old v3 with missing fields, empty objects are filled in, and v1/v2 remain compatible.

POST accepts and returns the request first; preparation and compaction run in the background without holding the admission lock or a database transaction. SSE / history display the preparation, Q&A tidying, copy compaction, and answering stages; a compaction failure is saved as the failed terminal state of that side-question request. The frontend retains the error and restores the draft of this failed question, rather than covering the input box with a floating notification; history polling no longer clears submission errors.

## Validation record

- Replay of 19/20/21/50 groups, retention of conclusions older than 20 groups, and summary-cache reuse across restart: automated pass.
- Overly long Chinese answers and code context, chunked request budgets, tool pairing, unchanged snapshots, and new-snapshot cache invalidation: automated pass.
- Summary failure / cancellation / truncation / over-length / tool return, clear races, call limits, single overflow recovery only, and no retry for partial streams: automated pass.
- With a separate PostgreSQL: paging, restart, v1/v2/v3 archiving, summary cache and budget metadata archive / restore, old v3 missing new fields, and 20 parent sessions sharing four concurrency slots: pass.
- Go candidate service build, frontend TypeScript check, Biome check of modified components, and Next.js production build in a separate directory: pass.
- Built-in browser with a separate UI fixture verified the tidying stage, summary-scope hint, draft restoration after failure, no floating error notifications, no horizontal overflow, and no console errors at 1280×720 and 390×844. The temporary fixture has been removed.
- Read-only replay of an existing local Worker snapshot passed the new budget check; for example, Worker #3's 293085-character snapshot is no longer misjudged and rejected by the local character count. No external model calls were made for this item.
- The real-conversation test that would send private Worker snapshots to Grok was rejected by automatic approval review, was not executed, and is not counted as a pass.
- At 00:37 on 2026-09-11, the local backend was restarted at the user's request, reusing the original database, data directory, and login configuration. The running files' SHA-256 matches the candidate binary; `/api/health` returned normal for both the backend and the frontend proxy.

Verification commands (using only a separate test database):

```sh
go test -race ./sidequestion ./db ./server -run 'TestSide|TestCheckpoint|TestSnapshot|TestBuildRequest|TestService|TestMainSide|TestTaskArchive' -count=1
go build ./cmd/pojun
npx tsc --noEmit
npm run build -- --webpack
```

The frontend production build uses a separate copy to avoid overwriting the currently previewed `.next`. The candidate service is at `/private/tmp/artex-btw-budget-candidate`, copied to `/private/tmp/artex-btw-preview/artex` and started; the original binary was backed up as `artex.before-context-budget` in the same directory.
