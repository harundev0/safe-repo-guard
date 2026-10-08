#!/usr/bin/env bash
# install.sh - Universal installer for safe-repo-guard rules, skills, and CLI scanner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================================================"
echo " 🛡️  Installing Safe Repo Guard..."
echo "========================================================================"

# 1. Install CLI Scanner to ~/.local/bin
mkdir -p "$HOME/.local/bin"
cp "$SCRIPT_DIR/scripts/safe-repo-scan.py" "$HOME/.local/bin/safe-repo-scan"
chmod +x "$HOME/.local/bin/safe-repo-scan"
cp "$SCRIPT_DIR/scripts/safe-repo-scan.sh" "$HOME/.local/bin/safe-repo-scan-sh"
chmod +x "$HOME/.local/bin/safe-repo-scan-sh"
echo "✅ Installed CLI scanners to ~/.local/bin/safe-repo-scan"

# 2. Install Skill for OpenCode and Claude Agents
mkdir -p "$HOME/.agents/skills/safe-repo-review"
cp "$SCRIPT_DIR/skills/safe-repo-review/SKILL.md" "$HOME/.agents/skills/safe-repo-review/SKILL.md"

if [ -d "$HOME/.config/opencode/skills" ]; then
    mkdir -p "$HOME/.config/opencode/skills/safe-repo-review"
    cp "$SCRIPT_DIR/skills/safe-repo-review/SKILL.md" "$HOME/.config/opencode/skills/safe-repo-review/SKILL.md"
    echo "✅ Installed Skill to ~/.config/opencode/skills/safe-repo-review/"
fi
echo "✅ Installed Skill to ~/.agents/skills/safe-repo-review/"

# 3. Add global rules if directories exist
# For Claude Code
if [ -d "$HOME/.claude" ]; then
    cat "$SCRIPT_DIR/rules/CLAUDE.md" >> "$HOME/.claude/CLAUDE.md" 2>/dev/null || true
    echo "✅ Appended safe repo rules to ~/.claude/CLAUDE.md"
fi

# For Gemini / Antigravity
if [ -f "$HOME/GEMINI.md" ]; then
    echo "✅ Rules are already configured in ~/GEMINI.md"
fi

# For OpenCode global instructions
if [ -f "$HOME/.config/opencode/AGENTS.md" ]; then
    if ! grep -q "Safe Repo" "$HOME/.config/opencode/AGENTS.md" 2>/dev/null; then
        echo "" >> "$HOME/.config/opencode/AGENTS.md"
        cat "$SCRIPT_DIR/rules/AGENTS.md" >> "$HOME/.config/opencode/AGENTS.md"
        echo "✅ Appended safe repo rules to ~/.config/opencode/AGENTS.md"
    fi
fi

echo "========================================================================"
echo " 🎉 Installation Complete!"
echo " You can now run:"
echo "   safe-repo-scan /path/to/untrusted-repo"
echo " Or ask your AI agent (Claude Code, OpenCode, Cursor, Gemini):"
echo "   'Gunakan safe-repo-review untuk memeriksa repo ini'"
echo "========================================================================"
