#!/usr/bin/env bash
# safe-repo-scan.sh - Zero-Execution Bash Scanner for Untrusted Repos
# Checks .git/hooks, .git/config, and lifecycle scripts WITHOUT executing git or project files.

set -euo pipefail

TARGET="${1:-.}"
TARGET="$(cd "$TARGET" 2>/dev/null && pwd || echo "$TARGET")"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================================================"
echo " 🛡️  SAFE-REPO-GUARD: Zero-Execution Audit (Bash CLI)"
echo " Target : $TARGET"
echo "========================================================================"

FOUND_ISSUES=0

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    FOUND_ISSUES=$((FOUND_ISSUES + 1))
}

danger() {
    echo -e "${RED}[DANGER/CRITICAL]${NC} $1"
    FOUND_ISSUES=$((FOUND_ISSUES + 1))
}

# 1. Audit Git Hooks
if [ -d "$TARGET/.git/hooks" ]; then
    echo -e "\n${BLUE}--> [1/4] Checking .git/hooks for active scripts...${NC}"
    ACTIVE_HOOKS=$(find "$TARGET/.git/hooks" -maxdepth 1 -type f ! -name "*.sample" 2>/dev/null || true)
    if [ -n "$ACTIVE_HOOKS" ]; then
        for hook in $ACTIVE_HOOKS; do
            hook_name=$(basename "$hook")
            if grep -E -i -q '(curl|wget|base64|powershell|cmd\.exe|/bin/sh|/bin/bash|nc|/dev/tcp)' "$hook" 2>/dev/null; then
                danger "Active hook '$hook_name' contains remote download/execution payloads!"
                echo "      Snippet: $(head -n 5 "$hook" | tr '\n' ' ')"
            else
                warn "Active hook '$hook_name' found without .sample extension."
            fi
        done
    else
        echo "    No active git hooks found. (OK)"
    fi
fi

# 2. Audit Git Config
if [ -f "$TARGET/.git/config" ]; then
    echo -e "\n${BLUE}--> [2/4] Checking .git/config for parameter hijacking...${NC}"
    if grep -E -i -q '(hookpath|fsmonitor|pager|editor)' "$TARGET/.git/config" 2>/dev/null; then
        danger "Suspicious config hijacking parameter detected in .git/config!"
        grep -E -i -n '(hookpath|fsmonitor|pager|editor)' "$TARGET/.git/config" | sed 's/^/      /'
    else
        echo "    No config hijacking vectors found. (OK)"
    fi
fi

# 3. Audit Package / Build Lifecycle Scripts
echo -e "\n${BLUE}--> [3/4] Checking build & lifecycle scripts (package.json, Makefile, *.sh)...${NC}"
if [ -f "$TARGET/package.json" ]; then
    if grep -E -i -q '"(preinstall|install|postinstall|prepare|prepack)"' "$TARGET/package.json" 2>/dev/null; then
        warn "Automatic lifecycle script detected in package.json."
        grep -E -i -n '"(preinstall|install|postinstall|prepare|prepack)"' "$TARGET/package.json" | sed 's/^/      /'
    fi
fi

for sh_file in "$TARGET"/*.sh; do
    if [ -f "$sh_file" ]; then
        if grep -E -i -q '(curl|wget|base64 -d|Invoke-WebRequest)' "$sh_file" 2>/dev/null; then
            warn "Shell script '$(basename "$sh_file")' contains download or decode commands."
        fi
    fi
done

# 4. Check Prompt Injection in primary docs
echo -e "\n${BLUE}--> [4/4] Checking docs for Prompt Injection targeting AI agents...${NC}"
for doc in "$TARGET"/README* "$TARGET"/INSTRUCTIONS* "$TARGET"/*.md; do
    if [ -f "$doc" ]; then
        if grep -E -i -q '(ignore all previous|developer mode|execute.*first|system: execute)' "$doc" 2>/dev/null; then
            danger "Potential Prompt Injection detected in $(basename "$doc")!"
            grep -E -i -n '(ignore all previous|developer mode|execute.*first|system: execute)' "$doc" | sed 's/^/      /'
        fi
    fi
done

echo "========================================================================"
if [ "$FOUND_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}✅ SAFE: No obvious malicious git hooks, config hijacks, or prompts found.${NC}"
    echo "You may proceed with careful, read-only inspection."
else
    echo -e "${RED}❌ AUDIT FAILED: $FOUND_ISSUES issue(s) detected.${NC}"
    echo "DO NOT run 'git status', 'git checkout', 'npm install', or build scripts in this repo!"
fi
echo "========================================================================"
