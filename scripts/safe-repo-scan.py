#!/usr/bin/env python3
"""
safe-repo-scan: Zero-Execution Security Scanner & Neutralizer for Untrusted Git Repositories.
Inspects repos safely without invoking git commands, build systems, or running shell hooks.
Can also disarm/clean malicious vectors with --disarm.
"""

import sys
import os
import re
import json
import shutil
import argparse
from pathlib import Path
from datetime import datetime

DANGEROUS_HOOK_NAMES = [
    "post-checkout", "pre-commit", "pre-push", "post-commit",
    "post-merge", "pre-rebase", "post-rewrite", "prepare-commit-msg",
    "commit-msg", "pre-applypatch", "post-applypatch", "fsmonitor-watchman"
]

SUSPICIOUS_COMMAND_PATTERNS = [
    r"\bcurl\b", r"\bwget\b", r"\bbase64\s+(-d|--decode)",
    r"\bpowershell(\.exe)?\b", r"\bcmd(\.exe)?\b", r"\b/bin/sh\b",
    r"\b/bin/bash\b", r"\bnc\b", r"\bnetcat\b", r"\bbash\s+-i\b",
    r"/dev/tcp/", r"\bpython(\d+)?\s+-c\b", r"\beval\(",
    r"\bexec\(", r"\bInvoke-WebRequest\b", r"\bInvoke-Expression\b"
]

SUSPICIOUS_CONFIG_KEYS = [
    "hookpath", "fsmonitor", "pager", "editor", "ext"
]

PROMPT_INJECTION_INDICATORS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"you\s+are\s+now\s+in\s+developer\s+mode",
    r"run\s+the\s+following\s+(bash|shell|command|script)\s+first",
    r"before\s+analyzing,\s+execute",
    r"system\s*:\s*execute",
    r"hidden\s+instruction"
]

class SafeRepoScanner:
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir).resolve()
        self.findings = []
        self.risk_level = "CLEAN" # CLEAN, LOW, MEDIUM, CRITICAL
        self.remediated_items = []

    def add_finding(self, severity: str, category: str, message: str, file_path: str = None, details: str = None):
        self.findings.append({
            "severity": severity,
            "category": category,
            "message": message,
            "file": file_path,
            "details": details
        })
        if severity == "CRITICAL":
            self.risk_level = "CRITICAL"
        elif severity == "HIGH" and self.risk_level != "CRITICAL":
            self.risk_level = "HIGH"
        elif severity == "MEDIUM" and self.risk_level not in ["CRITICAL", "HIGH"]:
            self.risk_level = "MEDIUM"

    def scan_git_hooks(self):
        hooks_dir = self.target_dir / ".git" / "hooks"
        if not hooks_dir.exists():
            return

        for item in hooks_dir.iterdir():
            if item.is_file() and not item.name.endswith(".sample"):
                try:
                    content = item.read_text(encoding="utf-8", errors="ignore")
                    matched_patterns = []
                    for pat in SUSPICIOUS_COMMAND_PATTERNS:
                        if re.search(pat, content, re.IGNORECASE):
                            matched_patterns.append(pat)

                    if matched_patterns:
                        self.add_finding(
                            severity="CRITICAL",
                            category="GIT_HOOK_EXPLOIT",
                            message=f"Active git hook '{item.name}' contains suspicious remote execution patterns!",
                            file_path=str(item),
                            details=f"Matched: {', '.join(matched_patterns)}\\nSnippet: {content[:300].strip()}"
                        )
                    else:
                        self.add_finding(
                            severity="HIGH",
                            category="ACTIVE_GIT_HOOK",
                            message=f"Active git hook '{item.name}' found in untrusted repository.",
                            file_path=str(item),
                            details=f"Snippet: {content[:200].strip()}"
                        )
                except Exception as e:
                    self.add_finding(
                        severity="MEDIUM",
                        category="GIT_HOOK_READ_ERROR",
                        message=f"Could not read hook file {item.name}: {e}",
                        file_path=str(item)
                    )

    def scan_git_config(self):
        config_file = self.target_dir / ".git" / "config"
        if not config_file.is_file():
            return

        try:
            content = config_file.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                line_lower = line.lower()
                for key in SUSPICIOUS_CONFIG_KEYS:
                    if key in line_lower and "=" in line:
                        self.add_finding(
                            severity="CRITICAL",
                            category="GIT_CONFIG_HIJACK",
                            message=f"Git config hijacking vector detected: '{key}'",
                            file_path=str(config_file),
                            details=line.strip()
                        )
        except Exception as e:
            self.add_finding(
                severity="LOW",
                category="CONFIG_READ_ERROR",
                message=f"Could not read .git/config: {e}"
            )

    def scan_build_and_lifecycle_scripts(self):
        pkg_json = self.target_dir / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                scripts = data.get("scripts", {})
                for hook in ["preinstall", "install", "postinstall", "prepare", "prepack"]:
                    if hook in scripts:
                        val = scripts[hook]
                        severity = "HIGH"
                        for pat in SUSPICIOUS_COMMAND_PATTERNS:
                            if re.search(pat, val, re.IGNORECASE):
                                severity = "CRITICAL"
                                break
                        self.add_finding(
                            severity=severity,
                            category="NPM_LIFECYCLE_SCRIPT",
                            message=f"package.json defines automatic '{hook}' script.",
                            file_path=str(pkg_json),
                            details=f"Command: {val}"
                        )
            except Exception:
                pass

        for script_file in self.target_dir.glob("*.sh"):
            try:
                content = script_file.read_text(encoding="utf-8", errors="ignore")
                for pat in SUSPICIOUS_COMMAND_PATTERNS:
                    if re.search(pat, content, re.IGNORECASE):
                        self.add_finding(
                            severity="HIGH",
                            category="SUSPICIOUS_SHELL_SCRIPT",
                            message=f"Root shell script '{script_file.name}' matches suspicious pattern '{pat}'",
                            file_path=str(script_file)
                        )
                        break
            except Exception:
                pass

    def scan_prompt_injection(self):
        doc_files = list(self.target_dir.glob("README*")) + list(self.target_dir.glob("INSTRUCTIONS*")) + list(self.target_dir.glob("*.md"))
        for doc in doc_files[:10]:
            try:
                content = doc.read_text(encoding="utf-8", errors="ignore")
                for pat in PROMPT_INJECTION_INDICATORS:
                    match = re.search(pat, content, re.IGNORECASE)
                    if match:
                        self.add_finding(
                            severity="CRITICAL",
                            category="PROMPT_INJECTION",
                            message=f"Potential prompt injection detected in {doc.name}",
                            file_path=str(doc),
                            details=f"Matched pattern: {pat}\\nContext: {content[max(0, match.start()-50):min(len(content), match.end()+100)]}"
                        )
            except Exception:
                pass

    def disarm(self):
        """Neutralizes and cleans malicious vectors in the repository."""
        # 1. Quarantine active Git Hooks
        hooks_dir = self.target_dir / ".git" / "hooks"
        if hooks_dir.exists():
            quarantine_dir = self.target_dir / ".git" / "hooks_quarantine"
            quarantine_dir.mkdir(exist_ok=True)
            for item in hooks_dir.iterdir():
                if item.is_file() and not item.name.endswith(".sample"):
                    dest = quarantine_dir / f"{item.name}.disabled_{int(datetime.now().timestamp())}"
                    shutil.move(str(item), str(dest))
                    self.remediated_items.append(f"Moved active hook '{item.name}' -> '{dest.name}'")

        # 2. Sanitize .git/config
        config_file = self.target_dir / ".git" / "config"
        if config_file.is_file():
            try:
                backup = config_file.with_suffix(".backup")
                shutil.copy2(str(config_file), str(backup))
                content = config_file.read_text(encoding="utf-8", errors="ignore")
                clean_lines = []
                stripped_keys = []
                for line in content.splitlines():
                    line_lower = line.lower()
                    skip = False
                    for key in SUSPICIOUS_CONFIG_KEYS:
                        if key in line_lower and "=" in line:
                            stripped_keys.append(line.strip())
                            skip = True
                            break
                    if not skip:
                        clean_lines.append(line)
                
                if stripped_keys:
                    config_file.write_text("\n".join(clean_lines) + "\n", encoding="utf-8")
                    self.remediated_items.append(f"Sanitized .git/config (Removed {len(stripped_keys)} dangerous entries, backup saved to .git/config.backup)")
            except Exception as e:
                self.remediated_items.append(f"Failed to sanitize .git/config: {e}")

        # 3. Disarm npm lifecycle scripts in package.json (replaces preinstall/postinstall with disarmed_*)
        pkg_json = self.target_dir / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                scripts = data.get("scripts", {})
                modified = False
                for hook in ["preinstall", "install", "postinstall", "prepare", "prepack"]:
                    if hook in scripts:
                        scripts[f"disarmed_{hook}"] = scripts.pop(hook)
                        modified = True
                        self.remediated_items.append(f"Disarmed npm script '{hook}' -> 'disarmed_{hook}' in package.json")
                if modified:
                    backup_pkg = pkg_json.with_suffix(".backup")
                    shutil.copy2(str(pkg_json), str(backup_pkg))
                    pkg_json.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            except Exception as e:
                self.remediated_items.append(f"Failed to disarm package.json: {e}")

        return self.remediated_items

    def scan(self):
        if not self.target_dir.exists():
            print(f"Error: Target directory '{self.target_dir}' does not exist.")
            sys.exit(1)

        self.scan_git_hooks()
        self.scan_git_config()
        self.scan_build_and_lifecycle_scripts()
        self.scan_prompt_injection()
        return self.findings

def main():
    parser = argparse.ArgumentParser(description="Zero-Execution Security Scanner & Neutralizer for Untrusted Repositories")
    parser.add_argument("path", nargs="?", default=".", help="Path to repository or directory to scan (default: current dir)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--disarm", "--clean", action="store_true", dest="disarm", help="Neutralize and quarantine detected threats (disarm hooks, clean config, neutralize lifecycle scripts)")
    args = parser.parse_args()

    scanner = SafeRepoScanner(args.path)
    findings = scanner.scan()

    if args.json:
        result = {
            "target": str(scanner.target_dir),
            "risk_level": scanner.risk_level,
            "findings_count": len(findings),
            "findings": findings
        }
        if args.disarm:
            result["disarmed_actions"] = scanner.disarm()
        print(json.dumps(result, indent=2))
        return

    colors = {
        "CRITICAL": "\033[91m[CRITICAL]\033[0m",
        "HIGH": "\033[93m[HIGH]\033[0m",
        "MEDIUM": "\033[94m[MEDIUM]\033[0m",
        "LOW": "\033[92m[LOW]\033[0m",
        "RESET": "\033[0m"
    }

    print("=" * 70)
    print(" 🛡️  SAFE-REPO-GUARD: Untrusted Codebase Security Audit")
    print(f" Target Path : {scanner.target_dir}")
    print(f" Overall Risk: {scanner.risk_level}")
    print("=" * 70)

    if not findings:
        print("\n✅ SAFE: No active git hooks, config hijacking, or suspicious lifecycle scripts detected.")
        print("You may proceed with careful read-only analysis.\n")
        return

    print(f"\n⚠️  Found {len(findings)} security alert(s):\n")
    for idx, f in enumerate(findings, 1):
        sev_tag = colors.get(f['severity'], f"[{f['severity']}]")
        print(f"{idx}. {sev_tag} {f['category']}")
        print(f"   Message : {f['message']}")
        if f.get('file'):
            print(f"   File    : {f['file']}")
        if f.get('details'):
            print(f"   Details : {f['details']}")
        print()

    if args.disarm:
        print("=" * 70)
        print(" 🧹 CLEANING & DISARMING REPOSITORY...")
        print("=" * 70)
        actions = scanner.disarm()
        if actions:
            for act in actions:
                print(f" ✔️  {act}")
            print("\n✅ REPOSITORY DISARMED: Threats neutralized and quarantined.")
            print("The repository is now safe from automatic trigger execution.")
        else:
            print("No actionable hooks or config modifications needed.")
        print()
    else:
        if scanner.risk_level in ["CRITICAL", "HIGH"]:
            print("\033[91m❌ DO NOT EXECUTE 'git checkout', 'git status', 'npm install', OR SCRIPTS IN THIS REPO!\033[0m")
            print("👉 Run with --disarm to automatically quarantine hooks and clean configuration:")
            print(f"   safe-repo-scan {scanner.target_dir} --disarm\n")

if __name__ == "__main__":
    main()
