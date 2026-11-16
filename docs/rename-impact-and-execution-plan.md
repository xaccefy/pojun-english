# Project Rename: Impact Inventory and Execution Plan (2026-11-02)

> Status: **executed**. On 2026-11-02 the name **Pojun / Pojun (pojun)** was chosen; code identifiers, binaries,
> install directory, environment variables, images and the GitHub repository have all been switched (v0.4.19). This
> document is retained as the impact inventory and migration reference for the rename.

## 1. Candidate names and clearance checks (done before naming)

| Chinese | English/repo name | Meaning | Recommendation |
|---|---|---|---|
| Pojun | Pojun / `pojun` | The seventh star of the Big Dipper, presiding over destruction | ★★★★★ |
| Zhulong | Zhulong / `zhulong` | Classic of Mountains and Seas: opening its eyes makes day | ★★★★ |
| Shrike | Shrike / `shrike` | A precise, ferocious bird of prey | ★★★☆ |
| Changying | Changying / `changying` | To bind the grey dragon | ★★★ |

Three things to do immediately after naming, before starting work:
1. GitHub repository name availability (does a same-named repo already exist under the user/organization)
2. A rough check for same-named PyPI/npm/GitHub projects and trademarks (avoid colliding with malware or well-known products)
3. Domain availability (a rough `.com`/`.io` check, for README and image-name reference)

## 2. Impact inventory (full-repo scan completed)

| Layer | Location | Scale | Notes |
|---|---|---|---|
| Go module | `github.com/chu0119/pojun` | **177 .go files** | Changing the module path = replacing imports repo-wide |
| Binaries | `artex` / `pojun-hostd` / `pojun-maint` | 13 files (build.sh, install.sh, CI, docs) | Main program / privileged helper / maintenance tool |
| Release repo | `chu0119/Pojun` (install.sh REPO) | 1 constant + README/doc links | Every URL changes after renaming the GitHub repo |
| Self-update | `selfupdate.Repo = "chu0119/pojun"` | 1 variable (overridable via ldflags) | Must be synced with the repo rename |
| Image | `ghcr.io/chu0119/pojun` (install.sh IMAGE) | 1 spot + Dockerfile/compose | The image must be pushed again |
| Install layout | `INSTALL_DIR=/opt/pojun`, `SERVICE=artex`, `RUN_USER=artex` | install.sh + systemd template | Changing directory/service names requires migration |
| Environment variables | `POJUN_*` | 35 files | e.g. `POJUN_PG_DSN` |
| Frontend branding | 11 files (sidebar/login page/app-config/auth/mock/document titles etc.) | 11 | Plus favicon/logo/HTML title |
| Docs | README 21 spots, deployment manual 61 spots | 2 large files + the rest of docs | The README must be rewritten for the new brand |
| DB / data | Table names, settings keys, the `data/` directory | Table names unchanged; the data directory follows the install layout | Migration script in §4 batch 4 |

## 3. Naming decision table (filled in after naming)

Let the new name be: Chinese `{CN}`, English `{EN}` (lowercase `{en}`):

| Item | Current value | New value |
|---|---|---|
| Go module | `github.com/chu0119/pojun` | `github.com/chu0119/{en}` (or a new organization) |
| Main binary | `artex` | `{en}` |
| Privileged helper | `pojun-hostd` | `{en}-hostd` |
| Maintenance tool | `pojun-maint` | `{en}-maint` |
| Install directory | `/opt/pojun` | `/opt/{en}` |
| systemd | `artex.service` | `{en}.service` |
| Run user | `artex` | `{en}` |
| Environment variables | `POJUN_*` | `{EN}_*` |
| Data directory | `data/` | Follows the install directory (a compatibility symlink may be kept) |
| Frontend title/brand | ARTEX | `{CN}` / `{EN}` |
| GitHub repository | `chu0119/Pojun` | `chu0119/{EN}` (or the pinyin of `{CN}`) |
| Image | `ghcr.io/chu0119/pojun` | `ghcr.io/chu0119/{en}` |

## 4. Execution plan (5 batches, in dependency order)

### Batch 1: branding and docs (low risk, can ship first)
- Frontend: `app-config`, sidebar, login page, document title, favicon/logo, empty-state copy
- Rewrite the README for the new brand (positioning/capabilities/architecture/install/screenshots)
- Replace the brand name throughout docs (keep the old name in the historical CHANGELOG and note it as a former name)
- **Redo the screenshots**: use the current real UI, masking sensitive parts (target domains/IPs, ID card/phone numbers, task names, tokens)
- Verification: `npm run build:static` + visual inspection of the pages

### Batch 2: distribution identifiers (affects external links; needs a small downtime window)
- Rename the GitHub repository (old links 301-redirect automatically, but direct release-asset links change)
- `install.sh`'s `REPO`/`INSTALL_DIR`/`SERVICE`/`RUN_USER`/`IMAGE`
- The `selfupdate.Repo` default (or inject via ldflags at install time)
- CI (image/asset names in release.yml), Dockerfile/docker-compose service names
- Verification: on a clean machine, run `install.sh --with-tools` end to end

### Batch 3: code identifiers (the largest change)
- Change the `go.mod` module path + replace imports repo-wide (177 files; `gofmt -w` + a full `go build ./...` as the safety net)
- Binary names/build scripts/install scripts/service templates/log prefixes
- `POJUN_*` -> `{EN}_*`, **while still reading the old variable names for one version** (so environment variables do not break after upgrade)
- Frontend API constants, localStorage keys, page titles
- Verification: `go test ./...` (with a temporary local PG) + CI green + `build:static`

### Batch 4: deployment migration (real Kali machine)
- Data directory: `/opt/pojun` -> `/opt/{en}` (keep a symlink, or a one-off mv + systemd update)
- Service: stop the old `artex` -> start the new `{en}` (keep the old unit file for one version for rollback)
- Old-version upgrade path: machines installed by the old `install.sh` must be recognized and migrated by the new install.sh
- Database: table names unchanged (no migration needed); connection strings/config keys carried over
- Verification: after migrating the real Kali machine, login, task list, attachments and Word export all work

### Batch 5: verification and rollback
- Full suite: `go build ./...`, `go test`, `build:static`, `bash -n install.sh`
- GitHub: the new repo's CI is green, release asset names are correct, old links 301 correctly
- Rollback: each batch is its own commit/tag; batches 3/4 keep the old-name symlink and the old service file

## 5. Decisions you need to make first

1. **GitHub repository**: rename the existing `chu0119/Pojun` (preserving star/issue history, old links 301) or create a new repo? (Recommended: rename)
2. **Go module**: `github.com/chu0119/{en}`, or keep the old path and only change the binary branding? (Recommended: change both, avoiding code that is "inconsistent inside and out")
3. **Data directory**: a new `/opt/{en}` with a one-off migration, or keep `/opt/pojun` and only change the brand? (Recommended: migrate, but keep a compatibility symlink)
4. **Keep an `artex` command alias** (symlinked to the new binary) for one version?
5. **English name casing**: use `{EN}` (readable) or `{en}` (convention) for the repo?

## 6. Screenshot masking checklist (go through it item by item when executing batch 1)

- Target domain/IP/port -> mask or replace with `target.example.com`
- ID card numbers, phone numbers, names, card numbers -> mask
- Task names/company names/commissioning parties -> mask
- Cookie/Token/JWT -> mask
- Real user directories in file paths -> mask
