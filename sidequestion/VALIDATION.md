# `/btw` Validation Record

Date: 2026-09-10. Branch: `codex/btw-side-question`. Baseline: `8dae851b9b622f2ff2631f332fde9719d0b16fba`.

A separate PostgreSQL test database and data directory were used; real model credentials were injected only into the isolated test environment, never written into the code or this record, and the product's default model was not changed. Go 1.26.3, norma v0.3.6, Next.js 16.2.9.

The actual model conversations, returned objects, engineering assertions, and Qwen's raw review text are stored in [validation-2026-09-10.json](validation-2026-09-10.json), which contains no API credentials.

## Engineering checks

| Scope | Result | Evidence |
| --- | --- | --- |
| Structured messages, deep copy of tool arguments | Pass | `TestCheckpointDeepCopyAndBoundaries` |
| Summary / compaction requests do not overwrite, full replies and terminal state published, partial replies excluded | Pass | `TestCheckpointDeepCopyAndBoundaries`, `TestSnapshotExcludesPartialStreamAndSelectsPoolMember` |
| Actual model pool member identity | Pass | `TestSnapshotExcludesPartialStreamAndSelectsPoolMember` |
| Tool pairing, 20 replay groups, budget trimming and over-limit errors | Pass | `TestBuildRequestCompactionToolPairingAndBudget` |
| Main/side parallelism, bidirectional cancellation isolation | Pass | Blocking Provider, `TestMainSideConcurrencyAndIndependentCancellation` |
| No tool execution, streaming / non-streaming, usage already present on failure | Pass | `TestServiceNoToolsAndUsageOnFailure` |
| Real norma ChatAgent + local Read tool, main transcript / activity isolation | Pass | `TestSideActualChatCheckpointToolResultAndTranscriptIsolation`, streaming and non-streaming subcases |
| Persistence, paging, idempotency, partial answers preserved across restart | Pass | `TestSideHistoryIdempotencyPagingAndRecovery` |
| Clear vs. late-write races, parent resource deletion, version comparison | Pass | `TestSideClearLateWritersAndDeletedParent` |
| MainAgent / Worker archiving and restore, v1/v2/v3 | Pass | `TestSideTaskArchiveVersions` |
| Three parent interfaces, authentication, resource ownership, Worker soft deletion | Pass | `TestSideHTTPGlobalLimitTaskWorkerAndDeletion`, `TestSideCheckpointPersistsBeforeAdmissionAndRestart` |
| Busy main session allows side questions, independent SSE reconnect / disconnect, cancel, clear | Pass | `TestSideHTTPBusyIsolationClearAndReconnect` |
| 1 per parent session / 4 global concurrency | Pass | two `TestSideHTTP…` cases |
| Snapshot persisted before commit, follow-up after restart, old sessions cannot forge snapshots | Pass | `TestSideCheckpointPersistsBeforeAdmissionAndRestart` |
| Refuse to continue after cached config is deleted or model changed | Pass | `TestSideRejectsDeletedOrChangedCachedProfile` |
| Cancel before archiving and wait for final reply and usage to persist | Pass | `TestSideTaskDrainPersistsBeforeArchive` |
| Usage recorded only once and side attribution when streaming consumer cancels early | Pass | `TestSideUsageRecordedOnceOnConsumerCancellation` |
| Restored Worker / deadline run context continues publishing new snapshots | Pass | `TestSideRestoredWorkerRuntimePublishesNewCheckpoint` |
| Race check of related packages | Pass | commands below |
| TypeScript and production build | Pass | `npx tsc --noEmit`, `npm run build` |
| Biome on new frontend modules | Pass | `biome check`, 3 new modules |

After configuring `POJUN_PG_DSN` against a separate disposable database, the automated checks can be reproduced (do not point at the production database):

```sh
go test -race ./agent ./db ./server ./sidequestion ./llmrec ./llmpool \
  -run 'Test(Side|Checkpoint|Snapshot|BuildRequest|Service|MainSide|CaptureRun|TaskArchive|CompleteForwards|StopIntent|CancelIntent)' -count=1
cd web
npx tsc --noEmit
npx biome check src/lib/side-questions.ts src/hooks/use-side-questions.ts src/components/side-question-workspace.tsx
npm run build
```

The full Go regression is not all green: two pre-existing tests in the `server` package fail during temporary-directory cleanup, both reporting `TempDir RemoveAll … directory not empty`:

- `TestInheritedActivityDetailAndRelationDeletion`
- `TestTaskMetadataPatchReturnsRenameAndPin`

After exporting the source from the unmodified baseline above and rerunning the `server` package in the same isolated environment, these two cleanup failures reproduce as well. The baseline run also produced a target-node-count assertion failure in `TestCoreTaskLifecyclePG`; the final modified `server` regression does not have that assertion failure. Other packages pass, and the side-question-related cases and race checks in this round pass. Baseline issues were not marked as passing acceptance for this change, nor were existing assertions modified to hide problems.

The Next.js build emits the pre-existing multiple-lockfile / workspace-root inference warnings; the build completes and all pages generate successfully.

## Browser checks

Using the Codex In-app Browser, connected to a separate local Go service and Next.js dev server. The following manual automation was performed on desktop and a narrow 390 × 844 screen, inspecting screenshots and browser logs:

- Enter `/btw` during a normal chat run; main content and side content both display; desktop sidebar behaves normally.
- Consecutive follow-up questions; after stopping the side question the generated partial answer is retained; the main flow continues.
- Closing the panel keeps the request running, and reopening restores the completed answer; refreshing the page with an empty `/btw` restores history.
- On the narrow-screen Drawer, input, buttons, history, and close operations work normally, with no horizontal overflow.
- Clear uses a confirmation dialog; after clearing the history disappears while the main transcript and snapshot are retained.
- Questions asked and switched separately for the task MainAgent and two Workers; Agent labels and history do not leak across conversations.
- A blocking local-model fixture keeps the Worker running; submit `/btw` from the Worker's main input box; after stopping the side question the Worker still shows live running and its own pause button, and the side question saves the partial answer.
- Browser error / warning logs are empty.

Controlled fixtures were used to verify concurrency timing precisely, without depending on real model output speed. During debugging, two Worker runtime checks did not form a valid concurrency window (the task had ended / the reply ended early); after fixing the fixture they were redone and passed; these initial attempts are not counted as valid passes.

## Real model conversations

Probed `grok-4.6` first, via the OpenAI-compatible endpoint `http://127.0.0.1:12580/tingly/openai`. The probe returned HTTP 200, model name `grok-4.6` and `READY`, in 2.82 seconds. The first choice was available, so the Tingly `glm` and Zhipu `glm-5.3` fallback chains were not enabled; these two fallback services were not verified this round.

| Scenario | Actual result |
| --- | --- |
| Asked about assets, targets, and tags while the main session was running | Returned `redhaze.top`, homepage read and summarized target, `BTW-REAL-0910`; side question completed, 16.97 seconds |
| Asked about tool evidence after the main session finished reading the homepage | Correctly cited WebFetch 200, curl redirect 301 → 302 → 200, page title; 7.24 seconds |
| Side question requested Bash to create a test file | Execution refused, target file not created; 7.74 seconds |
| Completed side question does not change main context | Main transcript SHA-256 consistent with main activity record; side question tool execution count 0 |
| Follow-up after truly stopping / restarting the Go service | Prior 3 side-question history entries retained; answered assets, tags and title directly from the persisted snapshot without re-running the main Agent |
| New session using Grok non-streaming config | Correctly answered assets and `ATOMIC-0910`; returned and saved usage: input 11734, output 138, cache_read 11520 |

The main session for the asset case used WebFetch and Bash/curl to read a public homepage, with the landing page at `https://id.redhaze.top/home` and the title "RedHaze Technology RedHaze Group · Global Conglomerate Portal". Bash staged the response in a local test file; no writes were executed against the remote host. This fact was verified separately from "the side question executed no tools".

Main transcript checksum: `e7e61f135a4a120954b539f357e8c4205d7d5cd7460dcaf3dc0fd066463e1d00`.

**Usage limitation:** Tingly's Grok streaming responses returned no usage. A separate direct test sending `stream_options.include_usage=true` returned HTTP 200, 12 data frames, 0 usage frames. Therefore a 0 in the streaming tests means the endpoint did not provide usage, and cannot be interpreted as no billing. Non-streaming usage and fixture failure / cancellation usage were all saved correctly.

## Qwen review

Review model `qwen-flash`, OpenAI-compatible endpoint `https://dashscope.aliyuncs.com/compatible-mode/v1`, HTTP 200. Provided the first three real side-question conversations, main-session tool evidence, and engineering assertions; returned `verdict: accept`, `concerns: []`, judging the answers consistent with the assets, tags, and page-read evidence, and the side-question tool refusal compliant with constraints. Review usage: prompt 6625, completion 312, total 6937.

This Qwen review did not cover the later-added service-restart and non-streaming tests. Qwen's generalization of "no writes" was too broad: the main session's curl did create a local temporary response file, as explicitly recorded above. Concurrency, zero tool execution, and transcript isolation were judged by engineering assertions; the model review only helped assess answer quality.
