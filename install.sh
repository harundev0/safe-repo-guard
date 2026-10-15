#!/usr/bin/env bash
# install.sh - installs the safe-repo-guard scanners, agent skill and global agent rules.
#
# Read this file before running it (it is short): it only copies files from this repo
# into your home directory. It downloads nothing and needs no root.
#
# Idempotent: rule blocks are wrapped in markers and replaced on every re-install.
# Usage: ./install.sh              install or update
#        ./install.sh --uninstall  remove everything this script installed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin"
START="<!-- safe-repo-guard:start -->"
END="<!-- safe-repo-guard:end -->"
MODE="${1:-install}"

case "$MODE" in
    install|--uninstall) ;;
    *) echo "Usage: $0 [--uninstall]" >&2; exit 2 ;;
esac

# Removes our marked block (and trailing blank lines) from a file, keeping everything else.
strip_block() {
    [ -f "$1" ] || return 0
    local tmp
    tmp="$(mktemp)"
    awk -v s="$START" -v e="$END" '
        $0 == s { skip = 1; next }
        skip && $0 == e { skip = 0; next }
        skip { next }
        { a[++n] = $0 }
        END { while (n > 0 && a[n] == "") n--; for (i = 1; i <= n; i++) print a[i] }' "$1" > "$tmp"
    cat "$tmp" > "$1"
    rm -f "$tmp"
}

# put_block RULES_FILE TARGET_FILE: (re)writes our block at the end of TARGET_FILE.
put_block() {
    mkdir -p "$(dirname "$2")"
    touch "$2"
    strip_block "$2"
    { [ -s "$2" ] && echo; echo "$START"; cat "$1"; echo "$END"; } >> "$2"
    if grep -q "^# Safe Repo" "$2" && [ "$(grep -c "^# Safe Repo" "$2")" -gt 1 ]; then
        echo "   ! $2 still contains an older unmarked copy of these rules (from install.sh v1)."
        echo "     Delete the duplicate block outside the safe-repo-guard markers by hand."
    fi
    echo "✅ Rules -> $2"
}

install_skill() { # install_skill SKILLS_DIR
    mkdir -p "$1/safe-repo-review"
    cp "$SCRIPT_DIR/skills/safe-repo-review/SKILL.md" "$1/safe-repo-review/SKILL.md"
    echo "✅ Skill -> $1/safe-repo-review/"
}

# Global rule files per agent; each is only touched if that agent's config dir exists.
RULE_TARGETS=(
    "$HOME/.claude|rules/CLAUDE.md|$HOME/.claude/CLAUDE.md"
    "$HOME/.codex|rules/AGENTS.md|$HOME/.codex/AGENTS.md"
    "$HOME/.config/opencode|rules/AGENTS.md|$HOME/.config/opencode/AGENTS.md"
    "$HOME/.gemini|rules/GEMINI.md|$HOME/.gemini/GEMINI.md"
    "$HOME/.codeium/windsurf|rules/.windsurfrules|$HOME/.codeium/windsurf/memories/global_rules.md"
)
SKILL_DIRS=("$HOME/.agents/skills")
[ -d "$HOME/.claude" ] && SKILL_DIRS+=("$HOME/.claude/skills")
[ -d "$HOME/.config/opencode" ] && SKILL_DIRS+=("$HOME/.config/opencode/skills")

if [ "$MODE" = "--uninstall" ]; then
    rm -f "$BIN/safe-repo-scan" "$BIN/safe-repo-scan-sh"
    for d in "${SKILL_DIRS[@]}"; do rm -rf "$d/safe-repo-review"; done
    for t in "${RULE_TARGETS[@]}"; do strip_block "${t##*|}"; done
    echo "✅ safe-repo-guard removed (scanners, skill, marked rule blocks)."
    exit 0
fi

echo "========================================================================"
echo " Installing Safe Repo Guard"
echo "========================================================================"

mkdir -p "$BIN"
cp "$SCRIPT_DIR/scripts/safe-repo-scan.py" "$BIN/safe-repo-scan"
cp "$SCRIPT_DIR/scripts/safe-repo-scan.sh" "$BIN/safe-repo-scan-sh"
chmod +x "$BIN/safe-repo-scan" "$BIN/safe-repo-scan-sh"
echo "✅ Scanners -> $BIN/safe-repo-scan, $BIN/safe-repo-scan-sh"
command -v python3 >/dev/null 2>&1 || echo "   ! python3 not found: use safe-repo-scan-sh until you install it."
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "   ! $BIN is not on your PATH. Add to your shell profile: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

for d in "${SKILL_DIRS[@]}"; do install_skill "$d"; done

for t in "${RULE_TARGETS[@]}"; do
    IFS='|' read -r dir rules target <<< "$t"
    [ -d "$dir" ] && put_block "$SCRIPT_DIR/$rules" "$target"
done

echo "========================================================================"
echo " Done. Per-project rules (copy into a project only if you want them there):"
echo "   Cursor: rules/cursor-rule.mdc -> .cursor/rules/   Windsurf: rules/.windsurfrules"
echo " Try it:  safe-repo-scan /path/to/untrusted-repo"
echo " Or ask your agent: 'Use safe-repo-review to check this repo before doing anything.'"
echo "========================================================================"
