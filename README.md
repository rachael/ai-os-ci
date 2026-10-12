# AI-OS CI

Shared Git and GitHub Actions checks for projects developed with AI-OS. The tools
live here once; each project has a small workflow caller and its own test commands.
No agent session, model API, or personal AI-OS checkout is needed in CI.

## Checks

- Gitleaks scans credentials using a checksum-verified release.
- The disclosure guard checks added lines and commit messages for credential
  patterns and, in public projects, sensitive-context vocabulary.
- actionlint validates workflow syntax and expressions.
- Project commands in `.ai-os-ci.json` run as the test suite.

Git hooks scan the staged snapshot and outgoing commits. PR checks scan the commit
range. A manual/full-history scan before first publication is still necessary:
CI runs after uploading, and cannot undo a disclosure. These are heuristic checks,
not a complete PII detector or a sandbox against authorized workflow changes.
Failures print categories and locations, not matched private text. Scanner failures
are errors, never clean results. Private projects still scan credentials, but do
not reject their legitimate personal-context vocabulary.

## Enroll a project

Use a reviewed full commit SHA from this repository for both workflow and tools.

```sh
python3 install.py /path/to/project --ref FULL_COMMIT_SHA --profile public \
  --check 'tests=python3 -m unittest discover -s tests' --apply
```

This writes `.ai-os-ci.json` and two small files in `.github/workflows/`. It never
copies scanner code into the project. `--profile private` is for private local
repositories; hosted CI takes the visibility from GitHub event metadata. Without
`--apply`, installation is a preview. Existing project test commands are preserved;
customized workflow callers cause an explicit conflict instead of being overwritten.
Commit the files. The workflow starts on PRs, pushes to `main`, and manual dispatch.

The shared job uses standard Ubuntu runners, a read-only token, immutable action
pins, a ten-minute timeout, and no repository secrets. It runs project code only
in that unprivileged job. Public projects use GitHub's free standard runner tier;
private runs consume their owner's Actions allowance and may incur overage under
the account's existing billing settings. No paid reviewers or larger runners are enabled.

## Local installation and updates

Clone this repository alongside AI-OS (or configure `aios.ciRoot` / `AI_OS_CI_ROOT`).
Run AI-OS's `dev/skills/devops-devex/tools/setup.py --ci /path/to/ai-os-ci --apply`
once on each machine. It installs central Git hooks, preserves repo-local hooks,
and backs up the previous global wrappers. Then install verified tools:

```sh
python3 tools.py install
python3 run.py check --repo /path/to/project --base FULL_BASE_COMMIT_SHA
```

Tool downloads use TLS and release SHA-256 checksums. Hooks do not download tools.
The initial supported platforms are Linux x86-64 and macOS arm64; other platforms
fail explicitly until a verified release asset is added. The binary cache is
`~/.cache/ai-os/ci` (`AI_OS_CI_CACHE` overrides it).

Local Git hooks use the installed shared checkout. CI uses the commit pinned by the
project. Update central tools through a tested PR, then rerun `install.py` with the
new SHA to update callers. Workflow local edits are preserved as conflicts. Keep
both workflow and tooling pins equal. Roll back by reverting the caller-pin commit
and checking out the previously verified local tooling revision.

## Review requests and merge enforcement

The separate review workflow reads PR metadata only: it never checks out or executes
PR code. Set repository variable `AI_OS_REVIEWERS` to comma-separated collaborator
logins or `organization/team` names. It defaults to the owner and skips requesting
the author's own review. It does not start an AI reviewer or incur model costs.

Configure required status checks/rulesets for merge enforcement when the account's
plan supports them. A red check alone is not server-enforced protection. For a
private repository on a plan without rulesets, local hooks and CI still report
failures, but authorized users can bypass them. Configure the actual observed
shared check name (`AI-OS checks`) after its first run; job prefixes may be included
in the GitHub ruleset picker.

## Publication and MIT

AI-OS defaults its owner's repositories to MIT when published. Private repositories
do not need a license added just to enroll in CI. For an explicitly authorized release:

```sh
python3 publish.py /path/to/project --github-repo OWNER/REPOSITORY \
  --copyright-holder 'Your Name' --apply
```

Without `--apply`, this previews. With it, a missing MIT license is committed,
all history is scanned, the branch is pushed, and GitHub visibility changes last.
Only repositories owned by the authenticated user are supported. Existing licenses
are preserved; non-MIT licenses and upstream forks need an explicit decision.
Public CI requires the MIT notice. Repository visibility changes through GitHub's
website cannot be intercepted by a local Git hook; use the publication command.

## Private terms and exceptions

Private term files remain machine-local. An explicitly configured
`PUBLIC_GUARD_TERMS_FILE` must exist; no private terms are supplied to ordinary
hosted or fork PR jobs. Do not put real terms into this repository, project
configuration, logs, or workflow artifacts. Tests use synthetic fixtures only.

The disclosure guard supports narrow, reviewed `path:category` regex exceptions
in `.public-guard-allow`. Gitleaks uses its built-in rules and supports reviewed
fingerprint exclusions via `.gitleaksignore`; inline suppression comments are
disabled. Changes to exceptions and CI deserve review like code changes.

## Maintenance

```sh
python3 tools.py install
python3 -m unittest discover -s tests -v
```

Pinned tools: Gitleaks 8.30.1 (MIT) and actionlint 1.7.12 (MIT), downloaded from
their official GitHub releases. Neither binary is bundled. Dependabot maintains
GitHub Actions pins; tool releases/checksums are updated explicitly in `tools.lock.json`.

[MIT license](LICENSE). Copyright (c) 2026 Rachael Passov.
