#!/usr/bin/env python3
"""
safe-repo-scan - zero-execution security scanner for untrusted repositories.

It only reads files. It never runs git, package managers, hooks or any file from the
target, never follows symlinks while walking, and never opens non-regular files
(FIFOs, devices), so a hostile repository cannot make it execute code or hang.

Exit codes: 0 = no HIGH/CRITICAL findings, 1 = HIGH/CRITICAL findings,
            2 = usage error (target missing or not a directory).
"""

import argparse
import json
import os
import re
import shutil
import stat
import sys
import time
import unicodedata
from pathlib import Path

__version__ = "2.0.0"

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 20000
# Dependency/build output folders: huge, rarely hand-written, and not auto-executed on open.
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", ".tox",
             ".mypy_cache", ".pytest_cache", ".next", ".nuxt", ".svelte-kit", ".output", ".turbo",
             ".parcel-cache", "coverage", "dist", "build", "target"}
NPM_LIFECYCLE = ["preinstall", "install", "postinstall", "prepublish", "preprepare",
                 "prepare", "postprepare", "prepack", "postpack"]
NPM_INSTALL_HOOKS = {"preinstall", "install", "postinstall"}  # also run when installed as a dependency


def rx(pattern):
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


# (regex, severity, label) - shell-level indicators for hooks, scripts and config values.
COMMAND_PATTERNS = [(rx(p), s, l) for p, s, l in [
    (r"/dev/(tcp|udp)/", "CRITICAL", "bash network socket (/dev/tcp)"),
    (r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", "HIGH", "output piped into a shell"),
    (r"\bbase64\s+(-d|--decode|-D)\b", "HIGH", "base64 decoding"),
    (r"\bbash\s+-i\b", "HIGH", "interactive shell (reverse shell)"),
    (r"\b(ncat|netcat|socat)\b|\bnc\s+-", "HIGH", "netcat/socat"),
    (r"\bmkfifo\b", "HIGH", "named pipe (reverse shell building block)"),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "HIGH", "URL to a raw IP address"),
    (r"(?<![\w-])(invoke-webrequest|invoke-expression|iwr|iex|downloadstring|downloadfile|frombase64string)\b",
     "HIGH", "PowerShell download/execute"),
    (r"\bcertutil\b.*-urlcache", "HIGH", "certutil download"),
    (r"\b(curl|wget)\b", "MEDIUM", "network download (curl/wget)"),
    (r"\b(python[23]?|perl|ruby|node|php)\s+-[ce]\b", "MEDIUM", "inline interpreter code"),
    (r"\b(powershell|pwsh)(\.exe)?\b", "MEDIUM", "PowerShell"),
]]

# Loader tricks seen in malicious JS/Python projects ("fake job interview" repos etc).
CODE_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".php", ".rb"}
CODE_PATTERNS = [(rx(p), s, l) for p, s, l in [
    (r"\S[ \t]{150,}\S", "HIGH", "code hidden after long whitespace padding (off-screen)"),
    (r"\b(eval|Function)\s*\(\s*(atob|Buffer\.from|String\.fromCharCode|unescape|decodeURIComponent)\b",
     "HIGH", "eval of decoded data"),
    (r"\b(eval|Function)\s*\(\s*\w+\.data\b", "HIGH", "eval of a network response (remote code loader)"),
    (r"\bexec\s*\(\s*(base64|zlib|marshal|codecs|bytes\.fromhex|__import__)", "HIGH", "Python exec of decoded data"),
    (r"['\"`][A-Za-z0-9+/]{400,}={0,2}['\"`]", "MEDIUM", "large embedded base64 blob"),
]]
# Config files that dev servers/bundlers execute on `npm run dev/build`.
TOOL_CONFIG_RE = re.compile(r"(\.config\.[cm]?[jt]s|^(gulpfile|gruntfile)\.[cm]?[jt]s)$", re.I)
# An npm script that executes a file from the repo (node x.js, sh ./x.sh, ./x).
RUNS_FILE_RE = rx(r"\b(node|sh|bash|zsh|python[23]?|deno|bun|tsx|ts-node)\s+[\w./-]|(^|[\s;&|(\"])\.{1,2}/")
TOOL_CONFIG_EXEC_RE = re.compile(r"\b(child_process|execSync|spawnSync)\b|\beval\s*\(|\bnew\s+Function\b")

INJECTION_PATTERNS = [rx(p) for p in [
    r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(of\s+)?(the\s+|your\s+)?"
    r"(previous|prior|above|earlier|preceding|system|original)\s+(instructions|prompts?|rules|directions|guidelines)",
    r"\byou\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|god|unrestricted)\s*mode",
    r"\b(do\s+not|don'?t|never)\s+(tell|inform|notify|alert|warn)\s+(this\s+to\s+)?the\s+user",
    r"\b(note|message|attention)\s+(to|for)\s+(the\s+|any\s+)?"
    r"(ai|llm|assistant|agent|model|claude|gpt|gemini|copilot|cursor)\b",
    r"\b(ai|llm|assistant|agent|claude|gemini|copilot|cursor|gpt)s?\s*[:,]\s*(please\s+)?"
    r"(run|execute|install|curl|wget|download|send|upload|read|cat|open)\b",
    r"\b(run|execute)\s+(the\s+)?(following|this|these)\s+(bash\s+|shell\s+)?(commands?|scripts?)\s+"
    r"(first|before|immediately|now)\b",
    r"\bbefore\s+(analy[sz]ing|reviewing|reading|answering|you\s+(start|begin|continue|respond)|doing\s+anything)\b"
    r"[^.\n]{0,60}\b(run|execute|install)\b",
    r"\b(send|upload|exfiltrate|transmit|leak)\b[^.\n]{0,60}"
    r"(\.env\b|id_rsa|id_ed25519|\.ssh/|\.aws/credentials|private\s+keys?)",
    r"\b(cat|read|print|dump)\s+[^\n]{0,30}(id_rsa|id_ed25519|id_ecdsa|\.aws/credentials|/etc/shadow)",
    r"\bsystem\s*:\s*(execute|run)\b",
    r"\bhidden\s+instructions?\b",
]]
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
AI_WORD = rx(r"\b(ai|llm|agents?|assistants?|claude|gpt|gemini|copilot|cursor|model)\b")
ACTION_WORD = rx(r"\b(run|execute|install|curl|wget|ignore|send|upload|download|delete|read)\b")

TAG_RE = re.compile("[\U000E0000-\U000E007F]")  # invisible "ASCII smuggling" characters
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")  # Trojan Source
ZW_RE = re.compile("[\u200b\u200c\u2060-\u2064\ufeff\u180e]")  # U+200D (emoji joiner) left out on purpose
HIDDEN_RE = re.compile("[\U000E0000-\U000E007F\u202a-\u202e\u2066-\u2069\u200b\u200c\u2060-\u2064\ufeff\u180e]")

AGENT_FILE_NAMES = {"claude.md", "claude.local.md", "agents.md", "gemini.md", ".cursorrules",
                    ".windsurfrules", ".clinerules", ".roorules", "copilot-instructions.md"}
AGENT_DIRS = ("/.cursor/rules/", "/.claude/commands/", "/.claude/agents/", "/.claude/skills/",
              "/.windsurf/rules/", "/.github/instructions/", "/.agents/skills/", "/.gemini/commands/")
CLAUDE_SETTINGS = ("/.claude/settings.json", "/.claude/settings.local.json")
CLAUDE_EXEC_KEYS = ("hooks", "apiKeyHelper", "statusLine", "awsAuthRefresh", "awsCredentialExport",
                    "otelHeadersHelper", "enableAllProjectMcpServers")
MCP_CONFIGS = ("/.mcp.json", "/.cursor/mcp.json", "/.vscode/mcp.json", "/.roo/mcp.json", "/.gemini/settings.json")
DEVCONTAINER_KEYS = ("initializeCommand", "onCreateCommand", "updateContentCommand",
                     "postCreateCommand", "postStartCommand", "postAttachCommand")
SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".command", ".mk"}
SCRIPT_NAMES = {"makefile", "gnumakefile", "setup.py", "build.rs"}

# Git settings whose value is executed as a command, and when git runs it.
EXEC_SETTINGS = {
    "core.fsmonitor": "runs a command on every git status/diff/add/commit",
    "core.hookspath": "redirects git hooks to a folder chosen by the repo author",
    "core.pager": "runs whenever git pages output (log, diff, show)",
    "core.editor": "runs when git opens an editor (commit, rebase, tag)",
    "core.sshcommand": "runs on every fetch/pull/push over SSH",
    "core.askpass": "runs when git asks for credentials",
    "core.gitproxy": "runs on git:// network operations",
    "core.alternaterefscommand": "runs on fetch/push when alternates are used",
    "sequence.editor": "runs on interactive rebase",
    "diff.external": "runs on every git diff",
    "gpg.program": "runs when commits/tags are signed or verified",
    "gpg.*.program": "runs when commits/tags are signed or verified",
    "interactive.difffilter": "runs on git add -p",
    "uploadpack.packobjectshook": "runs when this repo serves a fetch",
    "sendemail.sendmailcmd": "runs on git send-email",
    "filter.*.clean": "runs on git add/status for files matched in .gitattributes",
    "filter.*.smudge": "runs on checkout for files matched in .gitattributes",
    "filter.*.process": "runs as a filter process on checkout/add",
    "diff.*.textconv": "runs on git diff/log -p for matched files",
    "diff.*.command": "runs on git diff for matched files",
    "merge.*.driver": "runs on merges of matched files",
    "mergetool.*.cmd": "runs on git mergetool",
    "difftool.*.cmd": "runs on git difftool",
    "man.*.cmd": "runs on git help",
    "browser.*.cmd": "runs on git help --web / web--browse",
    "remote.*.uploadpack": "runs on fetch from this remote",
    "remote.*.receivepack": "runs on push to this remote",
}
BOOLISH = {"", "true", "false", "yes", "no", "on", "off", "0", "1"}

SECTION_RE = re.compile(r'\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]')
KEY_RE = re.compile(r"\s*([A-Za-z][A-Za-z0-9-]*)\s*(?:=(.*))?$")


def parse_git_config(text):
    """Parses git config text the way git splits it (on \\n only).

    Returns entries with section, sub (None if absent), key (lowercased), value, the
    0-based line span start..end (continuation lines included) and inline (the section
    header text when the key shares its line, e.g. `[core] editor = x`)."""
    lines = text.split("\n")
    entries, section, sub = [], "", None
    i = 0
    while i < len(lines):
        line, start, inline = lines[i].rstrip("\r"), i, None
        m = SECTION_RE.match(line)
        if m:
            section, sub = m.group(1).lower(), m.group(2)
            if sub is None and "." in section:  # legacy [section.subsection]
                section, sub = section.split(".", 1)
            rest = line[m.end():]
            if not rest.strip() or rest.strip()[0] in "#;":
                i += 1
                continue
            inline, line = line[:m.end()], rest
        if not line.strip() or line.strip()[0] in "#;":
            i += 1
            continue
        km = KEY_RE.match(line)
        value = (km.group(2) or "") if km else ""
        while line.endswith("\\") and i + 1 < len(lines):
            i += 1
            line = lines[i].rstrip("\r")
            value = value[:-1] + line
        if km and section:
            entries.append({"section": section, "sub": sub, "key": km.group(1).lower(),
                            "value": value.strip(), "start": start, "end": i, "inline": inline})
        i += 1
    return entries


def config_name(e):
    return f"{e['section']}.{e['sub']}.{e['key']}" if e["sub"] is not None else f"{e['section']}.{e['key']}"


def classify_config(e):
    """Returns (severity, reason) for a dangerous git setting, else None."""
    section, sub, key = e["section"], e["sub"], e["key"]
    pattern = f"{section}.*.{key}" if sub is not None else f"{section}.{key}"
    v = e["value"].replace('"', "").strip().lower()
    if pattern == "core.fsmonitor" or (section == "pager" and sub is None):
        if v in BOOLISH:  # fsmonitor=true is git's built-in daemon; pager.<cmd>=true/false only toggles paging
            return None
        return "CRITICAL", EXEC_SETTINGS.get(pattern, "runs as the pager for that git command")
    if pattern in EXEC_SETTINGS:
        return "CRITICAL", EXEC_SETTINGS[pattern]
    if section == "alias" and v.startswith("!"):
        return "CRITICAL", "is a shell alias that runs a command when invoked"
    if pattern == "submodule.*.update" and v.startswith("!"):
        return "CRITICAL", "runs a command on git submodule update"
    if pattern in ("remote.*.url", "remote.*.pushurl") and v.startswith("ext::"):
        return "CRITICAL", "uses the ext:: transport, which runs a command on fetch/push"
    if section == "url" and sub is not None and sub.lower().startswith("ext::"):
        return "CRITICAL", "rewrites URLs to the ext:: transport, which runs a command"
    if pattern in ("credential.helper", "credential.*.helper"):
        sev = "CRITICAL" if v.startswith("!") or "/" in v else "HIGH"
        return sev, "runs a credential helper program when git needs credentials"
    if pattern in ("include.path", "includeif.*.path"):
        return "HIGH", "loads extra git settings from another file"
    if pattern == "core.worktree":
        return "HIGH", "points git at a different working tree"
    if pattern in ("protocol.allow", "protocol.*.allow") and v == "always":
        return "HIGH", "allows every transport, including ext:: (runs commands)"
    return None


def clean(value, limit=300):
    """Makes untrusted text safe to print: no terminal escapes, no invisible characters."""
    s = str(value)
    out = []
    for ch in s[:limit]:
        if ch == "\n":
            out.append(" \u23ce ")
        elif ch == "\t":
            out.append(" ")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cs"):
            out.append("\\u{%x}" % ord(ch))
        else:
            out.append(ch)
    return "".join(out) + ("\u2026" if len(s) > limit else "")


def read_text(path):
    """Reads a regular file as text. Returns None for symlinks, FIFOs, devices,
    binaries and files over MAX_FILE_BYTES (opened non-blocking, so FIFOs can't hang us)."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = None
            data = fh.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def is_git_dir(p):
    return (p / "HEAD").is_file() and (p / "config").is_file() and (p / "objects").is_dir() and (p / "refs").is_dir()


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def hits(text, patterns):
    """First match of each pattern: (severity, label, line number, line text)."""
    out = []
    for pat, sev, label in patterns:
        m = pat.search(text)
        if m:
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            out.append((sev, label, line_of(text, m.start()), text[start:end if end != -1 else len(text)].strip()))
    return out


def top(severities):
    return max(severities, key=SEVERITIES.index)


def unique(p):
    """First free path p, p.1, p.2 ... so backups and quarantined files never overwrite each other."""
    cand, n = p, 1
    while cand.exists() or cand.is_symlink():
        cand = p.with_name(f"{p.name}.{n}")
        n += 1
    return cand


class Scanner:
    def __init__(self, target):
        self.root = Path(os.path.realpath(target))
        self.findings = []
        self.files_scanned = 0
        self.truncated = False
        self._seen_git = set()
        self._seen_cfg = set()
        self._agent_dirs = {}

    def rel(self, path):
        try:
            return Path(path).relative_to(self.root).as_posix()
        except ValueError:
            return str(path)

    def inside(self, path, follow=True):
        if follow:
            p = os.path.realpath(path)
        else:  # the entry itself (e.g. a symlinked hook), not what it points to
            p = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
        return p == str(self.root) or p.startswith(str(self.root) + os.sep)

    def add(self, severity, category, message, path=None, line=None, details=None, fix=None):
        self.findings.append({
            "severity": severity,
            "category": category,
            "message": clean(message, 400),
            "file": clean(self.rel(path)) if path is not None else None,
            "line": line,
            "details": clean(details, 500) if details else None,
            "_fix": fix,
        })

    @property
    def risk(self):
        sevs = [f["severity"] for f in self.findings if f["severity"] != "INFO"]
        return top(sevs) if sevs else "CLEAN"

    # ---------------------------------------------------------------- scanning
    def scan(self):
        self.scan_root_git()
        self.walk()
        self.findings.sort(key=lambda f: (-SEVERITIES.index(f["severity"]), f["file"] or "", f["line"] or 0))
        return self.findings

    def scan_root_git(self):
        dotgit = self.root / ".git"
        if dotgit.is_symlink():
            self.add("HIGH", "GIT_REDIRECT", "'.git' is a symlink; git would use the repository it points to",
                     dotgit, details=f"-> {os.readlink(dotgit)}")
            if dotgit.is_dir():
                self.scan_git_dir(dotgit)
        elif dotgit.is_dir():
            self.scan_git_dir(dotgit)
        elif dotgit.is_file():
            m = re.search(r"^gitdir:\s*(.+?)\s*$", read_text(dotgit) or "", re.M)
            if m:
                gd = Path(m.group(1))
                gd = Path(os.path.realpath(gd if gd.is_absolute() else self.root / gd))
                where = "inside" if self.inside(gd) else "OUTSIDE"
                self.add("MEDIUM" if where == "inside" else "HIGH", "GIT_REDIRECT",
                         f"'.git' is a file that points git to a folder {where} this repository; "
                         "its hooks and config apply here", dotgit, details=f"gitdir: {m.group(1)}")
                if gd.is_dir():
                    self.scan_git_dir(gd)
        if is_git_dir(self.root):
            self.scan_git_dir(self.root)

    def scan_git_dir(self, gd):
        key = os.path.realpath(gd)
        if key in self._seen_git:
            return
        self._seen_git.add(key)
        gd = Path(key)
        for cfg in [gd / "config", gd / "config.worktree"] + sorted(gd.glob("worktrees/*/config.worktree")):
            if cfg.exists() or cfg.is_symlink():
                self.scan_config(cfg)
        self.scan_hooks(gd / "hooks", quarantine=True)
        modules = gd / "modules"  # submodule repositories
        if modules.is_dir():
            for dirpath, dirnames, _ in os.walk(modules):
                if is_git_dir(Path(dirpath)):
                    self.scan_git_dir(Path(dirpath))
                    dirnames[:] = []

    def scan_config(self, cfg, depth=0):
        key = os.path.realpath(cfg)
        if key in self._seen_cfg or depth > 5:
            return
        self._seen_cfg.add(key)
        if cfg.is_symlink():
            self.add("HIGH", "GIT_CONFIG", "Git config file is a symlink", cfg, details=f"-> {os.readlink(cfg)}")
            return
        text = read_text(cfg)
        if text is None:
            return
        for e in parse_git_config(text):
            verdict = classify_config(e)
            if not verdict:
                continue
            sev, why = verdict
            name = config_name(e)
            self.add(sev, "GIT_CONFIG", f"{name} {why}", cfg, line=e["start"] + 1,
                     details=f"{name} = {e['value']}", fix=("config", cfg, e))
            value = os.path.expanduser(e["value"].strip().strip('"'))
            if e["key"] == "path" and e["section"] in ("include", "includeif"):
                inc = Path(value) if os.path.isabs(value) else cfg.parent / value
                if self.inside(inc) and inc.is_file():
                    self.scan_config(Path(os.path.realpath(inc)), depth + 1)
            elif name == "core.hookspath":
                hp = Path(value) if os.path.isabs(value) else self.root / value
                if self.inside(hp) and hp.is_dir():
                    self.scan_hooks(hp, quarantine=False)  # removing core.hooksPath already disarms it

    def scan_hooks(self, hooks_dir, quarantine):
        if not hooks_dir.is_dir() or hooks_dir.is_symlink():
            return
        for item in sorted(hooks_dir.iterdir()):
            if item.name.endswith(".sample"):
                continue
            fix = ("hook", item) if quarantine else None
            if item.is_symlink():
                self.add("HIGH", "GIT_HOOK", f"Hook '{item.name}' is a symlink; git runs whatever it points to",
                         item, details=f"-> {os.readlink(item)}", fix=fix)
                continue
            if not item.is_file():
                continue
            text = read_text(item)
            exe = "yes" if item.stat().st_mode & 0o111 else "no (git skips non-executable hooks on Unix)"
            if text is None:
                self.add("CRITICAL", "GIT_HOOK", f"Hook '{item.name}' is a binary or oversized file",
                         item, details=f"executable: {exe}", fix=fix)
                continue
            found = hits(text, COMMAND_PATTERNS)
            details = f"executable: {exe}"
            if found:
                details += "; matched: " + ", ".join(h[1] for h in found)
            details += "; content: " + text[:300]
            self.add("CRITICAL" if found else "HIGH", "GIT_HOOK",
                     f"Active git hook '{item.name}' runs automatically on git operations",
                     item, details=details, fix=fix)

    def walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root):  # followlinks=False
            d = Path(dirpath)
            keep = []
            for name in sorted(dirnames):
                p = d / name
                if p.is_symlink():
                    self.check_symlink(p)
                elif name == ".git":
                    if d != self.root:
                        self.add("MEDIUM", "NESTED_REPO", "Nested git repository; git commands run inside "
                                 "that folder use its own hooks and config", p)
                        self.scan_git_dir(p)
                elif name in SKIP_DIRS:
                    pass
                elif is_git_dir(p):
                    self.add("HIGH", "NESTED_REPO", "Embedded bare git repository; git commands run inside "
                             "it use its hooks and config", p)
                    self.scan_git_dir(p)
                else:
                    keep.append(name)
            dirnames[:] = keep
            for name in sorted(filenames):
                p = d / name
                if p.is_symlink():
                    self.check_symlink(p)
                    continue
                if name == ".git":  # gitdir pointer: root one handled already, nested ones point into .git/modules
                    continue
                if self.files_scanned >= MAX_FILES:
                    self.truncated = True
                    return
                self.files_scanned += 1
                self.scan_file(p)

    def check_symlink(self, p):
        if not self.inside(p):
            self.add("MEDIUM", "SYMLINK_ESCAPE", "Symlink points outside the repository; tools and AI agents "
                     "reading it read that file instead", p, details=f"-> {os.readlink(p)}")

    def scan_file(self, p):
        text = read_text(p)
        if text is None:
            return
        low = "/" + self.rel(p).lower()
        lname = p.name.lower()
        ext = os.path.splitext(lname)[1]
        if lname == "package.json":
            self.check_package_json(p, text)
        if low.endswith("/.vscode/tasks.json"):
            self.check_vscode_tasks(p, text)
        if lname in ("devcontainer.json", ".devcontainer.json"):
            self.check_devcontainer(p, text)
        if low.endswith(CLAUDE_SETTINGS):
            self.check_agent_exec(p, text, CLAUDE_EXEC_KEYS)
        elif low.endswith(MCP_CONFIGS):
            self.check_agent_exec(p, text, ("command", "hooks"))
        agent_dir = next((d for d in AGENT_DIRS if d in low), None)
        if agent_dir:
            self.note_agent_dir(p, low, agent_dir)
        elif lname in AGENT_FILE_NAMES:
            self.add("MEDIUM", "AGENT_INSTRUCTIONS", "AI coding agents load this file automatically as "
                     "instructions; read it yourself before starting an agent session here", p)
        if ext in SCRIPT_EXTS or lname in SCRIPT_NAMES:
            self.check_script(p, text)
        if ext in CODE_EXTS and not lname.endswith((".min.js", ".min.mjs", ".min.cjs")):
            self.check_code(p, lname, text)
        self.check_injection(p, text)

    def note_agent_dir(self, p, low, agent_dir):
        """One finding per agent folder (.claude/skills, .cursor/rules...) with a file count."""
        end = low.find(agent_dir) + len(agent_dir) - 1
        folder = self.rel(p)[:end - 1]
        if folder not in self._agent_dirs:
            self.add("MEDIUM", "AGENT_INSTRUCTIONS", "AI coding agents load files in this folder as instructions, "
                     "commands or skills; read them yourself before starting an agent session here",
                     self.root / folder)
            self._agent_dirs[folder] = self.findings[-1]
        f = self._agent_dirs[folder]
        f["details"] = f"{int((f['details'] or '0').split()[0]) + 1} file(s)"

    def check_package_json(self, p, text):
        try:
            data = json.loads(text)
        except ValueError:
            self.add("LOW", "NPM_LIFECYCLE", "package.json is not valid JSON; inspect it manually", p)
            return
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            return
        for hook in NPM_LIFECYCLE:
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            found = hits(cmd, COMMAND_PATTERNS)
            if any(h[0] in ("HIGH", "CRITICAL") for h in found):
                sev = "CRITICAL"
            elif hook in NPM_INSTALL_HOOKS or RUNS_FILE_RE.search(cmd):
                sev = "HIGH"
            else:  # prepare/prepack running a known tool (svelte-kit sync, husky, tsc): review, but common
                sev = "MEDIUM"
            m = re.search(r'"%s"\s*:' % hook, text)
            self.add(sev, "NPM_LIFECYCLE", f"package.json '{hook}' script runs automatically during npm/yarn/pnpm "
                     "install", p, line=line_of(text, m.start()) if m else None, details=cmd,
                     fix=("npm", p, hook))

    def check_vscode_tasks(self, p, text):
        if re.search(r'"runOn"\s*:\s*"folderOpen"', text, re.I):
            cmds = re.findall(r'"command"\s*:\s*"([^"]*)"', text)[:3]
            self.add("CRITICAL", "IDE_AUTORUN", "VS Code task runs automatically when the folder is opened "
                     "(runOn: folderOpen)", p, details="command: " + " | ".join(cmds), fix=("file", p))

    def check_devcontainer(self, p, text):
        keys = [k for k in DEVCONTAINER_KEYS if re.search(r'"%s"\s*:' % k, text)]
        if not keys:
            return
        sev = "HIGH" if "initializeCommand" in keys else "MEDIUM"
        if sev == "HIGH" and any(h[0] in ("HIGH", "CRITICAL") for h in hits(text, COMMAND_PATTERNS)):
            sev = "CRITICAL"
        self.add(sev, "DEVCONTAINER", "Dev container runs commands on open/create (initializeCommand runs on "
                 "your host machine)", p, details="keys: " + ", ".join(keys))

    def check_agent_exec(self, p, text, keys):
        found = [k for k in keys if re.search(r'"%s"\s*:' % k, text)]
        if not found:
            return
        dangerous = [h for h in hits(text, COMMAND_PATTERNS) if h[0] in ("HIGH", "CRITICAL")]
        self.add("CRITICAL" if dangerous else "HIGH", "AGENT_CONFIG",
                 "AI agent config defines commands an agent may run (" + ", ".join(found) + ")", p,
                 details="; ".join(f"L{h[2]}: {h[3]}" for h in dangerous[:3]) or None)

    def check_script(self, p, text):
        found = hits(text, COMMAND_PATTERNS)
        if found:
            found.sort(key=lambda h: -SEVERITIES.index(h[0]))
            self.add(found[0][0], "SCRIPT", "Script contains " + ", ".join(h[1] for h in found), p,
                     line=found[0][2], details=found[0][3])

    def check_code(self, p, lname, text):
        for sev, label, ln, line in hits(text, CODE_PATTERNS):
            self.add(sev, "OBFUSCATED_CODE", label.capitalize(), p, line=ln, details=line[:200])
        if TOOL_CONFIG_RE.search(lname):
            m = TOOL_CONFIG_EXEC_RE.search(text)
            if m:
                self.add("HIGH", "OBFUSCATED_CODE", "Build/dev-server config file (executed by npm run dev/build) "
                         "spawns processes or evaluates code", p, line=line_of(text, m.start()))

    def check_injection(self, p, text):
        matches = []
        for pat in INJECTION_PATTERNS:
            m = pat.search(text)
            if m:
                matches.append((line_of(text, m.start()), text[max(0, m.start() - 40):m.end() + 80]))
        for m in HTML_COMMENT.finditer(text):
            body = m.group(1)
            if AI_WORD.search(body) and ACTION_WORD.search(body):
                matches.append((line_of(text, m.start()), "<!--" + body[:150] + "-->"))
        if matches:
            matches.sort()
            self.add("HIGH", "PROMPT_INJECTION", f"Text that tries to instruct an AI agent ({len(matches)} match(es))",
                     p, line=matches[0][0], details=" | ".join(f"L{n}: {s}" for n, s in matches[:5]))
        if not HIDDEN_RE.search(text):
            return
        tags = TAG_RE.findall(text)
        if tags:
            hidden = "".join(chr(ord(c) - 0xE0000) for c in tags)
            self.add("CRITICAL", "HIDDEN_UNICODE", f"{len(tags)} invisible Unicode tag characters (ASCII smuggling: "
                     "text only an AI model reads)", p, line=line_of(text, TAG_RE.search(text).start()),
                     details="decoded hidden text: " + hidden)
        m = BIDI_RE.search(text)
        if m:
            self.add("HIGH", "HIDDEN_UNICODE", "Bidirectional control characters (Trojan Source: text displays "
                     "differently than it is read/run)", p, line=line_of(text, m.start()))
        bom = 1 if text.startswith("\ufeff") else 0  # a leading byte-order mark is normal
        zw = ZW_RE.findall(text, bom)
        if zw:
            self.add("MEDIUM", "HIDDEN_UNICODE", f"{len(zw)} zero-width characters (can hide text or split "
                     "keywords)", p, line=line_of(text, ZW_RE.search(text, bom).start()))

    # ---------------------------------------------------------------- disarming
    def disarm(self):
        """Neutralizes auto-execution vectors found by scan(). Only touches paths inside the
        target; every modified file gets a timestamped backup that is never overwritten."""
        ts = time.strftime("%Y%m%d-%H%M%S")
        actions, configs, npms = [], {}, {}
        for f in self.findings:
            fix = f.get("_fix")
            if not fix:
                continue
            kind, path = fix[0], Path(fix[1])
            if not self.inside(path, follow=False):
                actions.append(f"SKIPPED {self.rel(path)}: outside the scanned folder")
            elif kind == "config":
                configs.setdefault(path, []).append(fix[2])
            elif kind == "npm":
                npms.setdefault(path, []).append(fix[2])
            elif path.exists() or path.is_symlink():
                try:
                    actions.append(self._quarantine(kind, path, ts))
                except OSError as e:
                    actions.append(f"FAILED {self.rel(path)}: {e}")
        for path, entries in configs.items():
            try:
                actions.append(self._clean_config(path, entries, ts))
            except OSError as e:
                actions.append(f"FAILED {self.rel(path)}: {e}")
        for path, hooks in npms.items():
            try:
                actions.append(self._clean_npm(path, hooks, ts))
            except (OSError, ValueError) as e:
                actions.append(f"FAILED {self.rel(path)}: {e}")
        return [clean(a, 500) for a in actions]

    def _quarantine(self, kind, path, ts):
        if kind == "hook":
            qdir = path.parent.parent / "hooks_quarantine"
            qdir.mkdir(exist_ok=True)
            dest = unique(qdir / f"{path.name}.disabled-{ts}")
            link = path.is_symlink()
            os.rename(path, dest)
            if not link:
                os.chmod(dest, 0o600)
            return f"Quarantined hook {self.rel(path)} -> {self.rel(dest)} (not executable)"
        dest = unique(path.with_name(f"{path.name}.disabled-{ts}"))
        os.rename(path, dest)
        return f"Disabled {self.rel(path)} -> {self.rel(dest)}"

    def _clean_config(self, path, entries, ts):
        lines = read_text(path).split("\n")
        drop, header = set(), {}
        for e in entries:
            if e["inline"] is not None:  # keep the section header the key shared a line with
                header[e["start"]] = e["inline"]
                drop.update(range(e["start"] + 1, e["end"] + 1))
            else:
                drop.update(range(e["start"], e["end"] + 1))
        out = [header.get(i, line) for i, line in enumerate(lines) if i in header or i not in drop]
        backup = unique(path.with_name(f"{path.name}.backup-{ts}"))
        shutil.copy2(path, backup)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write("\n".join(out))
        names = ", ".join(config_name(e) for e in entries)
        return f"Removed {len(entries)} setting(s) from {self.rel(path)} ({names}); original saved as {self.rel(backup)}"

    def _clean_npm(self, path, hooks, ts):
        data = json.loads(read_text(path))
        scripts = data["scripts"]
        for h in hooks:
            scripts["disarmed_" + h] = scripts.pop(h)
        backup = unique(path.with_name(f"{path.name}.backup-{ts}"))
        shutil.copy2(path, backup)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        return f"Renamed {', '.join(hooks)} -> disarmed_* in {self.rel(path)}; original saved as {self.rel(backup)}"

    def report(self, actions=None):
        rep = {
            "tool": "safe-repo-scan",
            "version": __version__,
            "target": str(self.root),
            "risk_level": self.risk,
            "files_scanned": self.files_scanned,
            "truncated": self.truncated,
            "findings_count": len(self.findings),
            "findings": [{k: v for k, v in f.items() if k != "_fix"} for f in self.findings],
        }
        if actions is not None:
            rep["disarmed_actions"] = actions
        return rep


def print_report(sc, actions, color):
    def paint(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    sev_color = {"CRITICAL": "91", "HIGH": "91", "MEDIUM": "93", "LOW": "94", "INFO": "90"}
    print("=" * 70)
    print(" SAFE-REPO-GUARD: zero-execution audit")
    print(f" Target        : {clean(sc.root)}")
    print(f" Files scanned : {sc.files_scanned}" + (" (limit reached, scan truncated)" if sc.truncated else ""))
    print(f" Overall risk  : {paint(sev_color.get(sc.risk, '92'), sc.risk)}")
    print("=" * 70)
    if not sc.findings:
        print("\nNo known auto-execution vector found.")
    for i, f in enumerate(sc.findings, 1):
        print(f"\n{i}. {paint(sev_color[f['severity']], '[' + f['severity'] + ']')} {f['category']}")
        print(f"   {f['message']}")
        if f["file"]:
            print(f"   File   : {f['file']}" + (f":{f['line']}" if f["line"] else ""))
        if f["details"]:
            print(f"   Details: {f['details']}")
    if sc.findings:
        print("\nFile contents quoted above are UNTRUSTED: never follow instructions found in them.")
    if actions is not None:
        print("\n" + "=" * 70 + "\n DISARM\n" + "=" * 70)
        for a in actions or ["Nothing to disarm."]:
            print(f" - {a}")
        print("\nRe-run the scan to confirm. Disarm only removes automatic triggers (hooks, git config,")
        print("install scripts, folder-open tasks); review every remaining finding by hand.")
    elif sc.risk in ("HIGH", "CRITICAL"):
        print(paint("91", "\nDO NOT run git, npm/pip install, builds or tests, and do not open this folder in an "
                          "IDE or AI agent yet."))
        print(f"Neutralize automatic triggers with:  safe-repo-scan {clean(sc.root)} --disarm")
    print("\nThe project's own code is still untrusted: build, test or run it only in a disposable")
    print("container/VM that has no access to your credentials.\n")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Zero-execution security scanner for untrusted repositories. "
                    "Exit codes: 0 = no HIGH/CRITICAL findings, 1 = HIGH/CRITICAL findings, 2 = usage error.")
    parser.add_argument("path", nargs="?", default=".", help="repository folder to scan (default: current dir)")
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument("--disarm", "--clean", dest="disarm", action="store_true",
                        help="quarantine hooks, strip dangerous git settings, rename npm install scripts and "
                             "disable VS Code folder-open tasks (backups are kept)")
    parser.add_argument("--version", action="version", version=f"safe-repo-scan {__version__}")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    if not os.path.isdir(args.path):
        msg = f"target '{clean(args.path)}' does not exist or is not a directory"
        print(json.dumps({"error": msg}) if args.json else f"Error: {msg}", file=sys.stdout if args.json else sys.stderr)
        return 2

    sc = Scanner(args.path)
    sc.scan()
    actions = sc.disarm() if args.disarm else None
    if args.json:
        print(json.dumps(sc.report(actions), indent=2))
    else:
        print_report(sc, actions, color=sys.stdout.isatty() and "NO_COLOR" not in os.environ)
    return 1 if sc.risk in ("HIGH", "CRITICAL") else 0


if __name__ == "__main__":
    sys.exit(main())
