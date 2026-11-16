# Desktop task folder (permanent mandate · task-root format)

> User mandate (re-confirmed 2026-08-04; **2026-08-04 hardened again: separate `js/` + assets hold only public URLs**):  
> When you are asked to do a task, **create the task root directory on the desktop in the "{target}_SRC-hunting" format**; folders clearly separated, rules clear.  
> **Forbidden** to pile reports/scripts/assets/js directly on the desktop root; **forbidden** to just drop one flat `xxx_dig` and stuff reports into dig as a makeshift.

---

## 1. Standard directory format (permanent template)

Desktop task root naming: `{target/topic}_SRC-hunting` or an equally clear name.

**When starting a new task you must create all of these together:**

```
Desktop\{task name}_SRC-hunting\
  README.md          ← task description, directory structure, progress, resume commands
  assets\            ← "publicly reachable URL assets" discovered while hunting (domain/URL lists)
  js\                ← JS source files extracted/downloaded from the site (for analysis)
  reports\           ← formal reports
  {short name}_dig\  ← scripts, queue, state, findings, logs, ad-hoc probes
```

**Reference example (must match):** `Desktop\{target}_SRC-hunting\`

| Subdirectory | What goes in | What does not |
|--------|--------|----------|
| `assets/` | Publicly reachable URL/domain lists (target assets discovered and accumulated while hunting: url lists, subdomains, endpoint entry URLs, attackable surfaces from FOFA exports, etc.); **free jumping additionally requires `seed-queue.md`** (business name/brand/SRC domain/wholly-owned domains + pending/doing/done, see dig-scope §1.4; no cap on the count) | **Forbidden** to stuff extracted `.js` in here; no reports, no scanning scripts |
| `js/` | JS files **extracted/downloaded** from the target site (LinkFinder/manual capture/bulk-downloaded frontend bundles), for endpoint reversing | No formal reports; do not stuff the "URL asset list" here |
| `reports/` | Formal report `.md` (filename = vulnerability title) | Scripts, state, half-finished logs, raw JS |
| `{name}_dig/` | dig scripts, queue/state/findings, small verification scripts, logs, ad-hoc probes; **a new task must have `thread-must-read.md` (the iteration gate, see `hunt-iter`)** | Final delivery reports; **finalised extracted JS should land in `js/`, do not just pile it in dig as assets** |
| `README.md` | Structure description, progress table, resume commands, collection discipline; **must have the one-line iteration gate** (see `hunt-iter.md`) | — |

### 1.1 Assets vs js (mandatory separation)

| Content | Correct path |
|------|----------|
| Publicly reachable URL / domain / entry lists (surfaces discovered along the way that can still be hit) | `assets/` |
| `.js` source files pulled from the page/CDN | `js/` |
| Temporarily downloaded, half-finished, one-probe-only JS/HTML caches | May start in `{name}_dig/`; **formally extracted files with analysis value → move into `js/`** |

**Forbidden (the user named this):** putting extracted JS into `assets/` again.

---

## 2. Hard rules

1. **One task, one root directory**, created at the outset before producing anything.
2. **Four separated folders + dig**: `assets/` + `js/` + `reports/` + `{name}_dig/` — **clear rules, no mixing**.
3. Report path is fixed: `{task root}/reports/`; `REPORT_DIR` in scripts must point here.
4. Extracted JS path is fixed: `{task root}/js/`; download/extraction scripts output here by default.
5. URL asset path is fixed: `{task root}/assets/`; write only public URL/domain lists, never JS files.
6. Resuming, incremental work, Pass2/3/4 → **still into the same task root**; do not open loose desktop files.
7. The desktop root **must not** receive report `.md`, queue, state, or scattered py/js.
8. When the user has specified a path, the user's path wins; otherwise → this format.
9. **Starting a new task must carry the iteration gate:** at the outset create `{name}_dig/thread-must-read.md` and write "for iteration see `hunt-iter.md`". Pin the same sentence at the top of `README.md` and, for free jumping, `assets/seed-queue.md`. A spawned sub-thread's delivery must include iteration. The clauses live only in `hunt-iter.md`.

---

## 3. When the user says "clean up" (operations)

The wording is governed only by the "Cleanup" row in `vuln-report-format.md`. This file only covers how to delete, what to delete, and leaving the browser alone.

Deciding "has reports": `{task root}/reports/` exists and holds at least 1 formal report `.md`. Missing or empty folder = no reports.

### 3.1 No reports → wipe the whole root

| Action | Notes |
|------|-----|
| **Delete the entire task root directory** | Remove `Desktop\{task}_SRC-hunting\` wholesale |
| Including everything inside | `assets/`, `js/`, `{name}_dig/`, `README.md`, process junk — **delete together**, do not keep assets separately |

Applies to: tasks with no bugs, tasks that only ran dig/assets/js without submitting a report, empty `reports/` folders.

### 3.2 Has reports → keep only "assets + reports"

| Keep (do not delete) | Delete (may clean) |
|----------------|--------------|
| `{task root}/reports/` and every file inside | The whole `{name}_dig/` folder |
| `{task root}/assets/` and every file inside | The whole `js/` folder |
| The task root directory itself (keep the shell) | `README.md`, other scattered scripts/logs/temp files |
| | This task's junk mistakenly dropped on the desktop root |

With reports: **forbidden** to delete `reports/`, `assets/`; **forbidden** to move reports/assets away and then delete the whole task root.  
Shape after cleanup:

```
Desktop\{task}_SRC-hunting\
  assets\     ← kept
  reports\    ← kept
```

(No `js/`, no `*_dig/`, and no README is acceptable.)

### 3.3 Scope

1. The user says "clean up" and **names a task** → handle only that task root.  
2. The user says "clean up" referring to **all task folders / tidy up the rule rollout** → handle every `*_SRC-hunting` (and equivalent task root) on the desktop one by one per §3.1 / §3.2.  
3. Directories that are **not** task folders (tools, SRC document material folders, ordinary software installers, etc.) must **not** be mistaken for task roots and deleted.  
4. In-session **desktop** `.playwright-mcp` snapshot/console **files** for this round may be cleaned (only the temp screenshots/logs inside that directory).

### 3.3.1 Browser account passwords and configuration — permanently forbidden to clean (named by the user 2026-08-04)

> The user stated explicitly: **from now on, cleanup must not wipe the account passwords saved in the browser.**

During cleanup it is **always forbidden** to touch, delete, reset or clear the following objects (even if the user only said "clean up"):

| Forbidden object | Notes |
|----------|------|
| Accounts / passwords / autofill already saved in the browser | Chrome/Edge password store, Login Data, Autofill |
| Browser user profile directories | The whole `User Data`, `Default`, Profile, `Login Data`, `Web Data`, Cookies store folders |
| The profile of the real browser connected via CDP/9222 | No `ClearBrowserCookies` on the whole store, no disabling "save passwords", no wiping credentials |
| Credential storage in a Playwright persistent context | Do not clear login saves the user relies on in storage state (temp cookie files inside a task's dig may be deleted with dig) |

**Browser-related junk that may be cleaned (only):**

- **snapshot / console temp files** under desktop `Desktop\.playwright-mcp\` (page snapshots, console exports)  
- Process cookie text and probe caches inside a task's `{name}_dig/` (**not** the browser password store)

**Forbidden** to do the following "for cleanup": close the browser profile, delete a Profile, `Clear-Site-Data` site-wide, reset the browser, clear "passwords and forms", or perform a global storage clear on the 9222 browser.

### 3.4 Execution order

1. List the task roots to handle (named, or desktop `*_SRC-hunting` etc.)  
2. For each task root check whether `reports/` **has files**  
3. **No reports** → `Remove-Item` the whole task root  
4. **Has reports** → delete only dig / js / README / others; **lock and keep** `reports/` + `assets/`  
5. If there are reports but no `assets/` folder → you may keep an empty `assets/` or not create one; **never touch `reports/`**  
6. Browser: only the desktop `.playwright-mcp` temp snapshot/console may be cleaned; **never touch the password store/Profile**

### 3.5 Self-check (before cleanup)

- [ ] Did you first count whether `reports/` has files?  
- [ ] With no reports, did you delete the whole root (including assets/js/dig)?  
- [ ] With reports, did you keep only `assets/` + `reports/` without deleting reports by mistake?  
- [ ] Did you mistakenly delete a non-task directory (e.g. the `SRC-docs` material folder) as a task root?  
- [ ] **Would you mistakenly clear the browser's saved account passwords / Profile / Login Data? If so, forbidden — do not continue.**

---

## 4. Self-check (before writing files / submitting reports / starting a new task)

- [ ] Does `Desktop\{task}_SRC-hunting\` already exist (or an equivalent structure specified by the user)?  
- [ ] Do `assets/` `js/` `reports/` `{name}_dig/` `README.md` all exist?  
- [ ] Is the extracted JS only in `js/` (**not** in `assets/`)?  
- [ ] Is `assets/` only public URL/domain lists?  
- [ ] Are reports written only in `reports/`?  
- [ ] Are dig state and scripts only in `{name}_dig/`?  
- [ ] Did anything land on the desktop root by mistake? If so, **move it into the matching subfolder** (do not fudge it by deleting)

---

**In one line:** a new task = `README + assets (public URLs) + js (extracted JS) + reports + *_dig`; **JS never goes into assets**. Cleanup wording is governed only by `vuln-report-format`.
