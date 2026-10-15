#!/usr/bin/env bash
# safe-repo-scan.sh - zero-execution scanner for untrusted repositories (Bash fallback).
#
# Reads files only: never runs git, package managers, hooks or files from the target.
# Checks git hooks and config, npm install scripts, VS Code folder-open tasks, dev
# containers, AI-agent config/instruction files, suspicious scripts, whitespace-padded
# code and prompt injection in docs. The Python scanner (safe-repo-scan) also follows
# git config includes, detects hidden Unicode and more loader tricks: prefer it when
# python3 is available.
#
# Usage: safe-repo-scan-sh [PATH] [--disarm]
# Exit:  0 = no HIGH/CRITICAL findings, 1 = HIGH/CRITICAL findings, 2 = usage error.
# Portable: bash 3.2+ with POSIX find/grep/awk/sed (Linux, macOS, Git Bash/WSL).

set -uo pipefail

TARGET="."
DISARM=0
for arg in "$@"; do
    case "$arg" in
        --disarm|--clean) DISARM=1 ;;
        -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "Unknown option: $arg" >&2; exit 2 ;;
        *) TARGET="$arg" ;;
    esac
done

if [ ! -d "$TARGET" ]; then
    echo "Error: target '$TARGET' does not exist or is not a directory" >&2
    exit 2
fi
TARGET="$(cd "$TARGET" && pwd -P)"
TS="$(date +%Y%m%d-%H%M%S)"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; GREEN=$'\033[0;32m'; NC=$'\033[0m'
else
    RED=""; YELLOW=""; BLUE=""; GREEN=""; NC=""
fi

CRIT=0; HIGH=0; MED=0
QUAR_HOOKS=(); FIX_CONFIGS=(); FIX_NPM=(); FIX_FILES=(); GITDIRS=()
LIFECYCLE='preinstall|install|postinstall|prepublish|preprepare|prepare|postprepare|prepack|postpack'
# An npm script that executes a file from the repo (node x.js, sh ./x.sh, ./x).
RUNS_FILE_ERE='(^|[^[:alnum:]_])(node|s[h]|b[a]sh|z[s]h|python[23]?|deno|bun|tsx|ts-node)[[:space:]]+[[:alnum:]_./-]|(^|[[:space:];&|("])\.{1,2}/'

# Untrusted text -> printable: drop control chars (terminal escapes), cap length.
clean() { LC_ALL=C tr -d '\000-\010\013-\037\177' | LC_ALL=C cut -c "1-${1:-200}"; }
rel() { printf '%s' "${1#"$TARGET"/}" | clean 300; }

finding() { # finding SEVERITY CATEGORY MESSAGE [DETAILS]
    local color="$BLUE"
    case "$1" in
        CRITICAL) CRIT=$((CRIT + 1)); color="$RED" ;;
        HIGH) HIGH=$((HIGH + 1)); color="$RED" ;;
        MEDIUM) MED=$((MED + 1)); color="$YELLOW" ;;
    esac
    printf '%s[%s]%s %s: %s\n' "$color" "$1" "$NC" "$2" "$3"
    if [ -n "${4:-}" ]; then printf '      %s\n' "$4"; fi
}

# Regular files in the target, skipping dependency/build folders, NUL-separated.
find_files() {
    find "$TARGET" -mindepth 1 \( -type d \( -name .git -o -name node_modules -o -name vendor -o -name .venv \
        -o -name venv -o -name __pycache__ -o -name dist -o -name build -o -name target -o -name .next -o -name .nuxt \
        -o -name .svelte-kit -o -name .output -o -name .turbo -o -name .parcel-cache -o -name coverage \) -prune \) \
        -o \( -type f "$@" -print0 \)
}

# "SEVERITY :: ERE :: label" - shell-level indicators (same set as the Python scanner).
# The [x] brackets match the same text but stop the patterns from matching this file itself.
CMD_PATTERNS='CRITICAL :: /dev/(tcp|udp)/ :: bash network socket
HIGH :: \|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da|k)?sh([^[:alnum:]_]|$) :: output piped into a shell
HIGH :: base64[[:space:]]+(-d|--decode|-D)([^[:alnum:]_]|$) :: base64 decoding
HIGH :: (^|[^[:alnum:]_])bash[[:space:]]+-i([^[:alnum:]_]|$) :: interactive shell (reverse shell)
HIGH :: (^|[^[:alnum:]_])(n[c]at|netc[a]t|soc[a]t)([^[:alnum:]_]|$)|(^|[^[:alnum:]_])nc[[:space:]]+- :: raw network relay tool
HIGH :: (^|[^[:alnum:]_])mk[f]ifo([^[:alnum:]_]|$) :: named pipe (reverse shell building block)
HIGH :: https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} :: URL to a raw IP address
HIGH :: (^|[^[:alnum:]_-])(invoke-[w]ebrequest|invoke-[e]xpression|i[w]r|i[e]x|download[s]tring|download[f]ile|frombase64[s]tring)([^[:alnum:]_]|$) :: Windows download/execute cmdlets
HIGH :: cert[u]til.*-urlcache :: Windows certificate tool used as downloader
MEDIUM :: (^|[^[:alnum:]_])(c[u]rl|w[g]et)([^[:alnum:]_]|$) :: network download
MEDIUM :: (^|[^[:alnum:]_])(python[23]?|perl|ruby|node|php)[[:space:]]+-[ce]([^[:alnum:]_]|$) :: inline interpreter code
MEDIUM :: (^|[^[:alnum:]_])(p[o]wershell|p[w]sh)(\.exe)?([^[:alnum:]_]|$) :: Windows shell'

# cmd_hits FILE -> prints "SEVERITY label (line N)" per matching pattern, highest first.
cmd_hits() {
    local line sev rest re label n
    while IFS= read -r line; do
        sev="${line%% :: *}"; rest="${line#* :: }"; re="${rest%% :: *}"; label="${rest#* :: }"
        n=$(grep -n -E -i -m 1 -e "$re" "$1" 2>/dev/null | cut -d: -f1)
        if [ -n "$n" ]; then printf '%s %s (line %s)\n' "$sev" "$label" "$n"; fi
    done <<EOF
$CMD_PATTERNS
EOF
}
top_sev() { # top_sev HITS DEFAULT
    case "$1" in *CRITICAL*) echo CRITICAL ;; *HIGH*) echo HIGH ;; *MEDIUM*) echo MEDIUM ;; *) echo "$2" ;; esac
}
inside() { case "$1" in "$TARGET"/*) return 0 ;; *) return 1 ;; esac; }
unique() { local p="$1" n=1; while [ -e "$p" ] || [ -L "$p" ]; do p="$1.$n"; n=$((n + 1)); done; printf '%s' "$p"; }

# Git config parser. mode=report prints "line<TAB>severity<TAB>name<TAB>value" per dangerous
# setting; mode=clean prints the config without them (section headers and continuation
# lines handled). Mirrors classify_config() in the Python scanner.
GITCFG_AWK='
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
function boolish(v) { return v ~ /^(true|false|yes|no|on|off|0|1)?$/ }
function classify(name, v) {
    if (name == "core.fsmonitor") return boolish(v) ? "" : "CRITICAL"
    if (sec == "pager" && !hassub) return boolish(v) ? "" : "CRITICAL"
    if (name ~ /^core\.(hookspath|pager|editor|sshcommand|askpass|gitproxy|alternaterefscommand)$/) return "CRITICAL"
    if (name ~ /^(sequence\.editor|diff\.external|gpg\.program|gpg\.\*\.program|interactive\.difffilter|uploadpack\.packobjectshook|sendemail\.sendmailcmd)$/) return "CRITICAL"
    if (name ~ /^filter\.\*\.(clean|smudge|process)$/ || name ~ /^diff\.\*\.(textconv|command)$/ || name == "merge.*.driver") return "CRITICAL"
    if (name ~ /^(mergetool|difftool|man|browser)\.\*\.cmd$/ || name ~ /^remote\.\*\.(uploadpack|receivepack)$/) return "CRITICAL"
    if (sec == "alias" && v ~ /^!/) return "CRITICAL"
    if (name == "submodule.*.update" && v ~ /^!/) return "CRITICAL"
    if (name ~ /^remote\.\*\.(url|pushurl)$/ && v ~ /^ext::/) return "CRITICAL"
    if (sec == "url" && hassub && tolower(ssub) ~ /^ext::/) return "CRITICAL"
    if (name ~ /^credential(\.\*)?\.helper$/) return (v ~ /^!/ || v ~ /\//) ? "CRITICAL" : "HIGH"
    if (name == "include.path" || name == "includeif.*.path" || name == "core.worktree") return "HIGH"
    if ((name == "protocol.allow" || name == "protocol.*.allow") && v == "always") return "HIGH"
    return ""
}
{
    raw = $0; line = raw; inline = ""
    if (cont) {
        cont = (raw ~ /\\\r?$/)
        if (!(drop && mode == "clean")) { if (mode == "clean") print raw }
        if (!cont) drop = 0
        next
    }
    if (match(line, /^[ \t]*\[[^]]*\]/)) {
        hdr = substr(line, 1, RLENGTH); rest = substr(line, RLENGTH + 1)
        inner = hdr; sub(/^[ \t]*\[[ \t]*/, "", inner); sub(/[ \t]*\]$/, "", inner)
        hassub = 0; ssub = ""; q = index(inner, "\"")
        if (q > 0) { sec = tolower(trim(substr(inner, 1, q - 1))); ssub = substr(inner, q + 1); sub(/"[ \t]*$/, "", ssub); hassub = 1 }
        else { sec = tolower(trim(inner)); d = index(sec, "."); if (d > 0) { ssub = substr(sec, d + 1); sec = substr(sec, 1, d - 1); hassub = 1 } }
        if (trim(rest) == "" || trim(rest) ~ /^[#;]/) { if (mode == "clean") print raw; next }
        inline = hdr; line = rest
    }
    if (line !~ /^[ \t]*([#;]|\r?$)/ && match(line, /^[ \t]*[A-Za-z][A-Za-z0-9-]*/)) {
        key = tolower(trim(substr(line, 1, RLENGTH))); val = substr(line, RLENGTH + 1)
        if (val ~ /^[ \t]*=/) sub(/^[ \t]*=/, "", val); else val = ""
        c = (raw ~ /\\\r?$/)
        name = hassub ? sec ".*." key : sec "." key
        v = tolower(trim(val)); gsub(/"/, "", v)
        sev = (sec == "") ? "" : classify(name, v)
        if (sev != "") {
            shown = hassub ? sec "." ssub "." key : sec "." key
            if (mode == "report") printf "%d\t%s\t%s\t%s\n", NR, sev, shown, trim(val)
            else if (inline != "") print inline
            if (c) { cont = 1; drop = 1 }
            next
        }
        if (c) cont = 1
    }
    if (mode == "clean") print raw
}'

scan_config() {
    local cfg="$1" out ln sev name val
    if [ -L "$cfg" ]; then finding HIGH GIT_CONFIG "Git config file $(rel "$cfg") is a symlink"; return; fi
    out=$(awk -v mode=report "$GITCFG_AWK" "$cfg" 2>/dev/null) || return
    [ -z "$out" ] && return
    FIX_CONFIGS+=("$cfg")
    while IFS="$(printf '\t')" read -r ln sev name val; do
        finding "$sev" GIT_CONFIG "$name is a git setting that runs commands or loads foreign config ($(rel "$cfg"):$ln)" \
            "$(printf '%s = %s' "$name" "$val" | clean 200)"
    done <<EOF
$out
EOF
}

scan_hookdir() {
    local h hits sev exe
    while IFS= read -r -d '' h; do
        if [ -L "$h" ]; then
            finding HIGH GIT_HOOK "Hook $(rel "$h") is a symlink; git runs whatever it points to" \
                "-> $(readlink "$h" | clean)"
        else
            hits=$(cmd_hits "$h")
            sev=HIGH; [ -n "$hits" ] && sev=CRITICAL
            exe=no; [ -x "$h" ] && exe=yes
            finding "$sev" GIT_HOOK "Active git hook $(rel "$h") runs automatically on git operations" \
                "executable: $exe; $(printf '%s' "$hits" | tr '\n' ';' | clean 200) content: $(head -c 300 "$h" | tr '\n' ' ' | clean 200)"
        fi
        QUAR_HOOKS+=("$h")
    done < <(find "$1" -mindepth 1 -maxdepth 1 \( -type f -o -type l \) ! -name '*.sample' -print0 2>/dev/null)
}

add_gitdir() {
    local d
    for d in ${GITDIRS[@]+"${GITDIRS[@]}"}; do [ "$d" = "$1" ] && return; done
    GITDIRS+=("$1")
}
is_bare() { [ -f "$1/HEAD" ] && [ -f "$1/config" ] && [ -d "$1/objects" ] && [ -d "$1/refs" ]; }

echo "========================================================================"
echo " SAFE-REPO-GUARD: zero-execution audit (Bash scanner)"
echo " Target : $(printf '%s' "$TARGET" | clean 300)"
echo "========================================================================"

# 1. Locate every git directory: .git (dir, symlink or gitdir file), nested repos, bare repos.
if [ -L "$TARGET/.git" ]; then
    finding HIGH GIT_REDIRECT "'.git' is a symlink; git would use the repository it points to" \
        "-> $(readlink "$TARGET/.git" | clean)"
fi
if [ -d "$TARGET/.git" ]; then
    add_gitdir "$(cd "$TARGET/.git" && pwd -P)"
elif [ -f "$TARGET/.git" ]; then
    gd=$(sed -n 's/^gitdir:[[:space:]]*//p' "$TARGET/.git" | head -n 1 | tr -d '\r')
    case "$gd" in /*) ;; *) gd="$TARGET/$gd" ;; esac
    finding MEDIUM GIT_REDIRECT "'.git' is a file pointing git to another folder; its hooks and config apply here" \
        "gitdir: $(printf '%s' "$gd" | clean)"
    if [ -d "$gd" ]; then add_gitdir "$(cd "$gd" && pwd -P)"; fi
fi
if is_bare "$TARGET"; then add_gitdir "$TARGET"; fi
while IFS= read -r -d '' d; do
    finding MEDIUM NESTED_REPO "Nested git repository $(rel "$d"); git commands run inside that folder use its hooks and config"
    add_gitdir "$d"
done < <(find "$TARGET" -mindepth 2 \( -path "$TARGET/.git" -o -name node_modules \) -prune -o -name .git -type d -print0 -prune)
while IFS= read -r -d '' f; do
    d=$(dirname "$f")
    if is_bare "$d" && [ "$(basename "$d")" != .git ]; then
        finding HIGH NESTED_REPO "Embedded bare git repository $(rel "$d"); git commands run inside it use its hooks and config"
        add_gitdir "$d"
    fi
done < <(find "$TARGET" -mindepth 2 \( -name .git -o -name node_modules \) -prune -o -name HEAD -type f -print0)

# 2. Git hooks and config of every git directory (submodules and worktrees included).
for gd in ${GITDIRS[@]+"${GITDIRS[@]}"}; do
    while IFS= read -r -d '' cfg; do scan_config "$cfg"; done \
        < <(find "$gd" -name objects -prune -o \( -type f -o -type l \) \( -name config -o -name config.worktree \) -print0)
    while IFS= read -r -d '' hd; do scan_hookdir "$hd"; done \
        < <(find "$gd" -name objects -prune -o -type d -name hooks -print0)
done

# 3. npm/yarn/pnpm install-time scripts.
while IFS= read -r -d '' f; do
    lines=$(grep -n -E "\"($LIFECYCLE)\"[[:space:]]*:" "$f")
    [ -z "$lines" ] && continue
    tmp=$(mktemp); printf '%s\n' "$lines" > "$tmp"; hits=$(cmd_hits "$tmp"); rm -f "$tmp"
    if [ "$(top_sev "$hits" none)" = CRITICAL ] || [ "$(top_sev "$hits" none)" = HIGH ]; then sev=CRITICAL
    elif printf '%s' "$lines" | grep -q -E '"(preinstall|install|postinstall)"[[:space:]]*:' \
        || printf '%s' "$lines" | grep -q -E -e "$RUNS_FILE_ERE"; then sev=HIGH
    else sev=MEDIUM  # prepare/prepack running a known tool (svelte-kit sync, husky, tsc): review, but common
    fi
    finding "$sev" NPM_LIFECYCLE "$(rel "$f") has scripts that run automatically during install" \
        "$(printf '%s' "$lines" | tr '\n' ' ' | clean 200)"
    FIX_NPM+=("$f")
done < <(find_files -name package.json)

# 4. Things that run when a folder is opened in an IDE, dev container or AI agent.
while IFS= read -r -d '' f; do
    if grep -q -E -i '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f"; then
        finding CRITICAL IDE_AUTORUN "$(rel "$f"): VS Code task runs automatically when the folder is opened (runOn: folderOpen)" \
            "$(grep -E -o '"command"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" | head -n 3 | tr '\n' ' ' | clean 200)"
        FIX_FILES+=("$f")
    fi
done < <(find_files -path '*/.vscode/tasks.json')

while IFS= read -r -d '' f; do
    keys=$(grep -o -E '"(initializeCommand|onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|postAttachCommand)"' "$f" | tr -d '"' | tr '\n' ' ')
    [ -z "$keys" ] && continue
    sev=MEDIUM; case "$keys" in *initializeCommand*) sev=HIGH ;; esac
    finding "$sev" DEVCONTAINER "$(rel "$f"): dev container runs commands on open/create (initializeCommand runs on your host)" "keys: $keys"
done < <(find_files \( -name devcontainer.json -o -name .devcontainer.json \))

while IFS= read -r -d '' f; do
    keys=$(grep -o -E '"(hooks|apiKeyHelper|statusLine|awsAuthRefresh|awsCredentialExport|otelHeadersHelper|enableAllProjectMcpServers|command)"[[:space:]]*:' "$f" \
        | sed 's/"//g; s/[[:space:]]*://' | sort -u | tr '\n' ' ')
    case "$f" in */.claude/settings*.json) keys=$(printf '%s' "$keys" | sed 's/command //') ;; esac
    [ -z "${keys// /}" ] && continue
    sev=HIGH; case "$(top_sev "$(cmd_hits "$f")" none)" in CRITICAL|HIGH) sev=CRITICAL ;; esac
    finding "$sev" AGENT_CONFIG "$(rel "$f"): AI agent config defines commands an agent may run ($keys)"
done < <(find_files \( -path '*/.claude/settings.json' -o -path '*/.claude/settings.local.json' -o -name .mcp.json \
    -o -path '*/.cursor/mcp.json' -o -path '*/.vscode/mcp.json' -o -path '*/.roo/mcp.json' -o -path '*/.gemini/settings.json' \))

AGENT_DIR_PRED=( -path '*/.cursor/rules' -o -path '*/.claude/commands' -o -path '*/.claude/agents' -o -path '*/.claude/skills'
    -o -path '*/.windsurf/rules' -o -path '*/.github/instructions' -o -path '*/.agents/skills' -o -path '*/.gemini/commands' )
while IFS= read -r -d '' d; do
    n=$(find "$d" -type f | wc -l | tr -d ' ')
    [ "$n" -gt 0 ] && finding MEDIUM AGENT_INSTRUCTIONS "$(rel "$d"): AI coding agents load files in this folder as instructions, commands or skills; read them yourself first" "$n file(s)"
done < <(find "$TARGET" -mindepth 1 \( -type d \( -name .git -o -name node_modules -o -name vendor -o -name .venv -o -name venv \) -prune \) \
    -o \( -type d \( "${AGENT_DIR_PRED[@]}" \) -print0 -prune \))
while IFS= read -r -d '' f; do
    case "$f" in */.cursor/rules/*|*/.claude/commands/*|*/.claude/agents/*|*/.claude/skills/*|*/.windsurf/rules/*|*/.github/instructions/*|*/.agents/skills/*|*/.gemini/commands/*) continue ;; esac
    finding MEDIUM AGENT_INSTRUCTIONS "$(rel "$f"): AI coding agents load this file automatically as instructions; read it yourself first"
done < <(find_files \( -iname CLAUDE.md -o -iname CLAUDE.local.md -o -iname AGENTS.md -o -iname GEMINI.md -o -name .cursorrules \
    -o -name .windsurfrules -o -name .clinerules -o -name .roorules -o -name copilot-instructions.md \))

# 5. Scripts with download/exec indicators, and code hidden behind whitespace padding.
while IFS= read -r -d '' f; do
    hits=$(cmd_hits "$f")
    [ -z "$hits" ] && continue
    finding "$(top_sev "$hits" MEDIUM)" SCRIPT "$(rel "$f") contains: $(printf '%s' "$hits" | cut -d' ' -f2- | tr '\n' ';' | clean 200)"
done < <(find_files \( -name '*.sh' -o -name '*.bash' -o -name '*.zsh' -o -name '*.ps1' -o -name '*.bat' -o -name '*.cmd' \
    -o -name '*.command' -o -name '*.mk' -o -name Makefile -o -name GNUmakefile -o -name setup.py -o -name build.rs \))

while IFS= read -r -d '' f; do
    n=$(grep -n -E -m 1 '[^[:space:]][[:blank:]]{150,}[^[:space:]]' "$f" | cut -d: -f1)
    if [ -n "$n" ]; then
        finding HIGH OBFUSCATED_CODE "$(rel "$f"):$n has code hidden after long whitespace padding (off-screen)"
    fi
done < <(find_files \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' \
    -o -name '*.py' -o -name '*.php' -o -name '*.rb' \) ! -name '*.min.js')

# 6. Prompt injection aimed at AI agents (docs and agent rule files).
INJECTION_ERE='(ignore|disregard|forget|override)[[:space:]]+(all[[:space:]]+|any[[:space:]]+)?(the[[:space:]]+|your[[:space:]]+)?(previous|prior|above|earlier|preceding|system|original)[[:space:]]+(instructions|prompts?|rules|directions)|you[[:space:]]+are[[:space:]]+now[[:space:]]+(in[[:space:]]+)?(developer|dan|jailbreak|god|unrestricted)[[:space:]]*mode|(do[[:space:]]+not|never)[[:space:]]+(tell|inform|notify|alert|warn)[[:space:]]+the[[:space:]]+user|(run|execute)[[:space:]]+(the[[:space:]]+)?(following|this|these)[[:space:]]+(bash[[:space:]]+|shell[[:space:]]+)?(commands?|scripts?)[[:space:]]+(first|before|immediately|now)|system[[:space:]]*:[[:space:]]*(execute|run)|hidden[[:space:]]+instructions?'
AI_ERE='(^|[^[:alnum:]])(ai|llm|agents?|assistants?|claude|gpt|gemini|copilot|cursor)([^[:alnum:]]|$)'
ACTION_ERE='(^|[^[:alnum:]])(run|execute|install|c[u]rl|w[g]et|ignore|send|upload|download)([^[:alnum:]]|$)'
while IFS= read -r -d '' f; do
    hits=$(grep -n -E -i -m 3 -e "$INJECTION_ERE" "$f"; grep -n -E -i '<!--.*-->' "$f" | grep -E -i -e "$AI_ERE" | grep -E -i -e "$ACTION_ERE" | head -n 3)
    if [ -n "$hits" ]; then
        finding HIGH PROMPT_INJECTION "$(rel "$f") contains text that tries to instruct an AI agent" \
            "$(printf '%s' "$hits" | tr '\n' ' ' | clean 200)"
    fi
done < <(find_files \( -iname '*.md' -o -iname '*.mdx' -o -iname '*.mdc' -o -iname '*.txt' -o -iname '*.rst' \
    -o -name .cursorrules -o -name .windsurfrules -o -name .clinerules -o -name .roorules \))

# 7. Disarm (only paths inside the target; backups are timestamped and never overwritten).
if [ "$DISARM" -eq 1 ]; then
    echo
    echo "========================================================================"
    echo " DISARM"
    echo "========================================================================"
    did=0
    for h in ${QUAR_HOOKS[@]+"${QUAR_HOOKS[@]}"}; do
        if ! inside "$h"; then echo " - SKIPPED $(rel "$h"): outside the scanned folder"; continue; fi
        qdir="$(dirname "$(dirname "$h")")/hooks_quarantine"
        mkdir -p "$qdir"
        dest=$(unique "$qdir/$(basename "$h").disabled-$TS")
        if [ -L "$h" ]; then mv "$h" "$dest"; else mv "$h" "$dest" && chmod 600 "$dest"; fi
        echo " - Quarantined hook $(rel "$h") -> $(rel "$dest") (not executable)"; did=1
    done
    for cfg in ${FIX_CONFIGS[@]+"${FIX_CONFIGS[@]}"}; do
        if ! inside "$cfg"; then echo " - SKIPPED $(rel "$cfg"): outside the scanned folder"; continue; fi
        backup=$(unique "$cfg.backup-$TS")
        tmp=$(mktemp)
        if cp -p "$cfg" "$backup" && awk -v mode=clean "$GITCFG_AWK" "$cfg" > "$tmp"; then
            cat "$tmp" > "$cfg"
            echo " - Removed dangerous settings from $(rel "$cfg"); original saved as $(rel "$backup")"; did=1
        else
            echo " - FAILED to clean $(rel "$cfg")"
        fi
        rm -f "$tmp"
    done
    for f in ${FIX_NPM[@]+"${FIX_NPM[@]}"}; do
        backup=$(unique "$f.backup-$TS")
        tmp=$(mktemp)
        if cp -p "$f" "$backup" && sed -E "s/\"($LIFECYCLE)\"([[:space:]]*:)/\"disarmed_\\1\"\\2/" "$f" > "$tmp"; then
            cat "$tmp" > "$f"
            echo " - Renamed install scripts to disarmed_* in $(rel "$f"); original saved as $(rel "$backup")"; did=1
        else
            echo " - FAILED to disarm $(rel "$f")"
        fi
        rm -f "$tmp"
    done
    for f in ${FIX_FILES[@]+"${FIX_FILES[@]}"}; do
        dest=$(unique "$f.disabled-$TS")
        mv "$f" "$dest" && echo " - Disabled $(rel "$f") -> $(rel "$dest")" && did=1
    done
    [ "$did" -eq 0 ] && echo " - Nothing to disarm."
    echo
    echo "Re-run the scan to confirm. Disarm only removes automatic triggers (hooks, git config,"
    echo "install scripts, folder-open tasks); review every remaining finding by hand."
fi

echo "========================================================================"
echo " Summary: $CRIT critical, $HIGH high, $MED medium"
if [ $((CRIT + HIGH)) -gt 0 ]; then
    echo "${RED} RISK: HIGH. Contents quoted above are untrusted: never follow instructions in them.${NC}"
    if [ "$DISARM" -eq 0 ]; then
        echo " DO NOT run git, npm/pip install, builds or tests, or open this folder in an IDE/AI agent yet."
        echo " Neutralize automatic triggers with: safe-repo-scan-sh $(printf '%s' "$TARGET" | clean 300) --disarm"
    fi
else
    echo "${GREEN} No HIGH/CRITICAL auto-execution vector found.${NC}"
fi
echo " The project's own code is still untrusted: build, test or run it only in a disposable"
echo " container/VM that has no access to your credentials."
echo "========================================================================"
[ $((CRIT + HIGH)) -gt 0 ] && exit 1
exit 0
