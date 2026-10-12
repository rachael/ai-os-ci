#!/usr/bin/env python3
"""Keep sensitive context out of public repos.

Rae, 2026-10-04: "no sensitive context eval for repos before going public and public
commits before push. internal rules to never write sensitive context to public repos
or commits". Draft, not reviewed by Rae yet.

  public-guard.py pre-push REMOTE URL   git pre-push hook (refs on stdin). Pushes to a
                                        private GitHub repo pass untouched; pushes to a
                                        public one, a repo that doesn't exist yet, or one
                                        whose visibility can't be checked (offline) get
                                        their outgoing commits scanned.
  public-guard.py scan-repo [PATH]      every commit on every ref, plus the tracked files
                                        now. Run it before a repo goes public.
  public-guard.py claude-hook           Claude Code PreToolUse hook: blocks `gh repo create
                                        --public` and `gh repo edit --visibility public`
                                        until scan-repo passes for that repo.

What it looks for, in added lines, commit messages and author identities:
  - credential shapes (same set as dark-factory-rae/tools/scan-sensitive.sh)
  - health, benefits, legal and personal-finance wording
  - literal private terms, one per line, from ~/.config/ai-os/sensitive-terms.txt and
    ~/.config/dark-factory/private-patterns.txt (both kept outside every repo)
Findings print file, line and category, never the matched text.

A repo can list known-fine findings in `.public-guard-allow` at its root: one regex per
line, matched against "path:category" (e.g. `^server/brains/persona\\.mjs:health$` for a
guardrail word list). A human-reviewed push can set PUBLIC_GUARD_REVIEWED="<why>"; it is
logged. Agents set it only when Rae has approved that exact push.
"""
import argparse, json, os, re, shutil, subprocess, sys, time

HOME = os.path.expanduser("~")
CACHE = os.path.join(HOME, ".cache/ai-os/public-guard/visibility.json")
LOG = os.environ.get('PUBLIC_GUARD_LOG', os.path.join(HOME, ".local/state/ai-os/public-guard.log"))
TERM_FILES = [os.path.join(HOME, ".config/ai-os/sensitive-terms.txt"),
              os.path.join(HOME, ".config/dark-factory/private-patterns.txt")]
ZERO = "0" * 40

CATEGORIES = {
    "credential": re.compile(
        r"(sk-(ant-)?[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}"
        r"|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
        r"|[Bb]earer [A-Za-z0-9._-]*[0-9][A-Za-z0-9._-]{19,}"
        r"|[A-Z0-9_]*(API_KEY|TOKEN|SECRET|PASSWORD)=[^\s$<{]{8,})"),
    "health": re.compile(
        r"\b(illness(es)?|chronic (pain|illness|condition)|so much pain|neuromuscular|neurolog\w*"
        r"|diagnos(is|ed|es)|psychiatr\w*|therapist|medications?|prescriptions?|my condition"
        r"|health (news|condition|issues?|interruptions?)|trauma|ptsd|disabilit(y|ies))\b", re.I),
    "benefits": re.compile(r"\b(SSDI|IHSS|Medi-Cal|Medicaid|Medicare|SOC 873|SOC 295|disability benefits?)\b"),
    "legal": re.compile(r"\b(divorce|dates? of separation|custody|attorneys?|schedule of assets)\b", re.I),
    "finance": re.compile(
        r"\b(credit (score|utilization)|(medical|credit card|personal) debt|debt from|bankrupt\w*"
        r"|card ending( in)? \d{4}|…\d{4}|account (number|ending))\b", re.I),
}


PLACEHOLDER = re.compile(r"(\.\.\.|…|x{4,}|X{4,}|your|example|changeme|placeholder|<|\(|\[|\$\{|\{\{)", re.I)


def private_terms():
    out = []
    explicit = os.environ.get('PUBLIC_GUARD_TERMS_FILE')
    for f in ([explicit] if explicit else TERM_FILES):
        try:
            for line in open(f, encoding="utf-8"):
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line.lower())
        except OSError:
            if explicit:
                raise ValueError('Configured private-term file is unavailable')
    ident = subprocess.run(["git", "config", "--global", "user.email"], capture_output=True, text=True).stdout.strip()
    return out, ident


def git(*args, cwd=None):
    result = subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd, errors="replace")
    if result.returncode:
        raise ValueError('Git scan input could not be read; no clean result was produced')
    return result.stdout


def slug_of(url):
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(\.git)?/?$", url or "")
    return m.group(1) if m else None


def visibility(slug):
    """'private', 'public', 'missing' or 'unknown' (offline, not GitHub)."""
    if not slug:
        return "unknown"
    try:
        cache = json.load(open(CACHE))
    except (OSError, ValueError):
        cache = {}
    hit = cache.get(slug)
    if hit and time.time() - hit["t"] < 3600 and hit["v"] == "private":
        return "private"          # only trust a cached "private"; recheck anything else
    gh = shutil.which("gh") or next((p for p in ("/opt/homebrew/bin/gh", "/usr/local/bin/gh") if os.path.exists(p)), None)
    try:
        if not gh:
            raise OSError("gh not found")
        r = subprocess.run([gh, "api", f"repos/{slug}", "--jq", ".private"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        # Can't ask GitHub (no gh, offline): fall back to the last known good answer, but
        # only a "private" one -- a repo once seen public is never trusted blind (Rae's
        # last-known-good principle, 2026-10-03; applied here 2026-10-11).
        log(f"visibility check failed for {slug}: {e!r}; cached={hit and hit['v']}")
        return "private" if hit and hit["v"] == "private" else "unknown"
    if r.returncode == 0:
        v = "private" if r.stdout.strip() == "true" else "public"
    elif "Not Found" in r.stderr or "404" in r.stderr:
        v = "missing"
    else:
        return "private" if hit and hit["v"] == "private" else "unknown"
    cache[slug] = {"v": v, "t": time.time()}
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    json.dump(cache, open(CACHE, "w"))
    return v


def allow_rules(root):
    try:
        return [re.compile(l.strip()) for l in open(os.path.join(root, ".public-guard-allow"))
                if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def check_text(text, where, terms, ident, allow, findings, file_for_allow, credentials_only=False):
    low = text.lower()
    hits = [c for c, rx in CATEGORIES.items() if (not credentials_only or c == 'credential') and rx.search(text)]
    if "credential" in hits and all(PLACEHOLDER.search(m.group(0)) for m in CATEGORIES["credential"].finditer(text)):
        hits.remove("credential")   # placeholders ("sk-ant-..."), regexes and template slots
    if not credentials_only and any(t in low for t in terms):
        hits.append("private-term")
    if not credentials_only and ident and ident.lower() in low:
        hits.append("identity")
    for c in hits:
        if not any(r.search(f"{file_for_allow}:{c}") for r in allow):
            findings.add((where, c))


def scan_patch(patch, terms, ident, allow, findings, credentials_only=False):
    path, ln, commit = "?", 0, "?"
    in_message = False
    for line in patch.split("\n"):
        if line.startswith("\x1ecommit "):
            commit = line.split()[1][:9]
            in_message = False
            continue
        if line.startswith("\x1fmsg "):
            in_message = True
            check_text(line[5:], f"{commit} commit message", terms, ident, allow, findings, "COMMIT_MSG", credentials_only)
            continue
        if line.startswith('diff --git '):
            in_message = False
        elif in_message:
            check_text(line, f'{commit} commit message', terms, ident, allow, findings, 'COMMIT_MSG', credentials_only)
            continue
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else line[4:]
            continue
        m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
        if m:
            ln = int(m.group(1)); continue
        if line.startswith("+"):
            check_text(line[1:], f"{commit} {path}:{ln}", terms, ident, allow, findings, path, credentials_only)
            ln += 1
        elif not line.startswith("-"):
            ln += 1


def scan_revs(rev_args, root):
    terms, ident = private_terms()
    allow = allow_rules(root)
    findings = set()
    patch = git("log", "-p", "--no-color", "--no-ext-diff", "--format=%x1ecommit %H%n%x1fmsg %s %b",
                *rev_args, cwd=root)
    scan_patch(patch, terms, ident, allow, findings)
    return findings


def report(findings, what):
    if not findings:
        print(f"public-guard: {what}: clean")
        return 0
    print(f"public-guard: {what}: {len(findings)} finding(s). Matched text is not shown; open each place to read it.", file=sys.stderr)
    for where, cat in sorted(findings)[:60]:
        print(f"  {cat:13} {where}", file=sys.stderr)
    if len(findings) > 60:
        print(f"  … {len(findings) - 60} more", file=sys.stderr)
    print("Fix: remove it (rewrite history if it was committed), move it to a private repo, or, if it is\n"
          "fine to publish, add a `path:category` regex to .public-guard-allow. A push Rae approved can\n"
          "set PUBLIC_GUARD_REVIEWED=\"<why>\".", file=sys.stderr)
    return 1


def log(msg):
    if LOG == '-':
        return
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {os.getcwd()} {msg}\n")


def pre_push(remote, url):
    slug = slug_of(url)
    vis = visibility(slug)
    if vis == "private":
        return 0
    root = git("rev-parse", "--show-toplevel").strip()
    findings = set()
    for line in sys.stdin.read().splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[1] == ZERO:
            continue
        local, remote_sha = parts[1], parts[3]
        revs = [local, "--not", f"--remotes={remote}"] if remote_sha == ZERO else [f"{remote_sha}..{local}"]
        findings |= scan_revs(revs, root)
    rc = report(findings, f"push to {slug or url} ({vis})")
    if rc and os.environ.get("PUBLIC_GUARD_REVIEWED"):
        log(f"bypass {slug or url}: {os.environ['PUBLIC_GUARD_REVIEWED']} ({len(findings)} findings)")
        print("public-guard: PUBLIC_GUARD_REVIEWED set; push allowed and logged.", file=sys.stderr)
        return 0
    if rc:
        log(f"blocked {slug or url}: {len(findings)} findings")
    return rc


def scan_changes(root, base=None, head='HEAD', staged=False, credentials_only=False):
    """Portable PR/staged check. Never sends data to a service or logs matches."""
    root = git('rev-parse', '--show-toplevel', cwd=root).strip()
    terms, ident = ([], '') if credentials_only else private_terms()
    findings = set()
    allow = allow_rules(root)
    if staged:
        patch = git('diff', '--cached', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=0', cwd=root)
    else:
        # Only object IDs/HEAD, not arbitrary revision expressions from webhook input.
        for ref in [head] + ([base] if base else []):
            if ref != 'HEAD' and not re.fullmatch(r'[0-9a-fA-F]{40,64}', ref):
                raise ValueError('Expected a full commit ID or HEAD')
            git('cat-file', '-e', ref + '^{commit}', cwd=root)
        revs = [base + '..' + head] if base else [head]
        patch = git('log', '-p', '--no-color', '--no-ext-diff', '--no-textconv',
                    '--format=%x1ecommit %H%n%x1fmsg %s %b', *revs, cwd=root)
    scan_patch(patch, terms, ident, allow, findings, credentials_only)
    # JSON-escape locations: untrusted filenames must not become workflow commands.
    for where, category in sorted(findings)[:60]:
        print(json.dumps({'location': where, 'category': category}), file=sys.stderr)
    print(f'public-guard: {len(findings)} finding(s); matched text omitted')
    return 1 if findings else 0


def scan_repo(path):
    root = git("rev-parse", "--show-toplevel", cwd=path).strip() if os.path.isdir(path) else ""
    if not root:
        print(f"public-guard: not a git repo: {path}", file=sys.stderr)
        return 2
    findings = scan_revs(["--all"], root)
    # the tree as it is now, in case history was rewritten but a file still holds it
    terms, ident = private_terms()
    allow = allow_rules(root)
    for f in git("ls-files", cwd=root).splitlines():
        try:
            for n, line in enumerate(open(os.path.join(root, f), encoding="utf-8", errors="ignore"), 1):
                check_text(line, f"tree {f}:{n}", terms, ident, allow, findings, f)
        except (OSError, IsADirectoryError):
            pass
    rc = report(findings, f"repo {root} (all history)")
    if rc == 0:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        head = git("rev-parse", "HEAD", cwd=root).strip()
        log(f"scan-repo clean {root} {head}")
    return rc


PUBLIC_CMD = re.compile(r"\bgh\s+repo\s+(create\b.*--public\b|edit\b.*--visibility[ =]public\b)"
                        r"|\bgh\s+api\b.*repos/[^ ]+.*-f\s+(visibility=public|private=false)")


def claude_hook():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return 0
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not PUBLIC_CMD.search(cmd):
        return 0
    cwd = data.get("cwd") or os.getcwd()
    m = re.search(r"--source[ =]([^ ]+)", cmd)
    path = os.path.expanduser(m.group(1).strip("'\"")) if m else cwd
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    from pathlib import Path
    from publish import is_mit
    if not is_mit(Path(path)):
        print('MIT is missing. Use AI-OS CI publish.py to prepare the license and scans before publication; existing licenses are preserved.', file=sys.stderr)
        return 2
    print("public-guard: this makes a repo public, so its whole history is scanned first.", file=sys.stderr)
    rc = scan_repo(path)
    if rc:
        print("Blocked. Clear the findings above (or get Rae's decision on them), then run it again.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ['scan-changes']:
        parser = argparse.ArgumentParser(description='Scan staged content or a commit range without disclosing matches')
        parser.add_argument('--repo', default='.')
        parser.add_argument('--base')
        parser.add_argument('--head', default='HEAD')
        parser.add_argument('--staged', action='store_true')
        parser.add_argument('--credentials-only', action='store_true')
        args = parser.parse_args(a[1:])
        try:
            sys.exit(scan_changes(args.repo, args.base, args.head, args.staged, args.credentials_only))
        except (OSError, ValueError) as exc:
            print(f'public-guard: {exc}', file=sys.stderr)
            sys.exit(2)
    if a[:1] == ["pre-push"] and len(a) >= 3:
        sys.exit(pre_push(a[1], a[2]))
    if a[:1] == ["scan-repo"]:
        sys.exit(scan_repo(a[1] if len(a) > 1 else "."))
    if a[:1] == ["claude-hook"]:
        sys.exit(claude_hook())
    print(__doc__)
    sys.exit(2)
