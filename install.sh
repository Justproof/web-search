#!/usr/bin/env bash
# Safe Web Research — installer
#
# Remote:  curl -fsSL https://raw.githubusercontent.com/Justproof/web-search/main/install.sh | bash
# Local:   ./install.sh   (from a checkout of the repo)
#
# Idempotent. Backs up settings.json and CLAUDE.md before touching them.

set -euo pipefail

REPO_TARBALL="https://github.com/Justproof/web-search/archive/refs/heads/main.tar.gz"
EXTRACTED_NAME="web-search-main"

CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"
HOOKS_DIR="$CLAUDE_HOME/hooks"
SKILL_DIR="$CLAUDE_HOME/skills/safe-web-research"
BIN_DIR="$CLAUDE_HOME/bin"
SETTINGS_FILE="$CLAUDE_HOME/settings.json"
CLAUDEMD_FILE="$CLAUDE_HOME/CLAUDE.md"

if [ -t 1 ]; then
    BOLD=$'\e[1m'; DIM=$'\e[2m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; RESET=$'\e[0m'
else
    BOLD=; DIM=; GREEN=; YELLOW=; RED=; RESET=
fi

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
die()  { printf '%s✗%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
Safe Web Research installer

  ./install.sh                 Install or upgrade (mode: enforce)
  ./install.sh --mode strict   Install with WebFetch refused in favour of the
                               curl | claude-sanitize path (the only path where
                               the sanitiser controls the bytes you receive)
  ./install.sh --mode log      Install in advisory-only mode
  ./install.sh --uninstall     Remove hooks from settings.json and delete files
  ./install.sh --help          This message

State (fetch log, blocklist, robots cache) lives in ~/.claude/safe-web-research
and is left alone by --uninstall unless you pass --purge.
USAGE
}

MODE="enforce"
ACTION="install"
PURGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --mode)      MODE="${2:-enforce}"; shift 2 ;;
        --mode=*)    MODE="${1#*=}"; shift ;;
        --uninstall) ACTION="uninstall"; shift ;;
        --purge)     PURGE=1; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           printf 'Unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$MODE" in
    enforce|log|strict) ;;
    *) die "Invalid --mode '$MODE' (expected: enforce, log, or strict)" ;;
esac

# ---- Uninstall ---------------------------------------------------------------
if [ "$ACTION" = "uninstall" ]; then
    command -v bun >/dev/null 2>&1 || die "bun not found (needed to edit settings.json)."
    if [ -f "$SETTINGS_FILE" ]; then
        cp "$SETTINGS_FILE" "$SETTINGS_FILE.bak.$(date +%Y%m%d-%H%M%S)"
        SETTINGS_FILE="$SETTINGS_FILE" bun -e '
            const { readFileSync, writeFileSync } = require("node:fs");
            const file = process.env.SETTINGS_FILE;
            const settings = JSON.parse(readFileSync(file, "utf8"));
            const drop = (list) => (Array.isArray(list) ? list : []).filter((e) =>
                !(Array.isArray(e?.hooks) && e.hooks.some((h) =>
                    typeof h?.command === "string" && /web-fetch-(pre|post)\.ts/.test(h.command))));
            if (settings.hooks) {
                settings.hooks.PreToolUse  = drop(settings.hooks.PreToolUse);
                settings.hooks.PostToolUse = drop(settings.hooks.PostToolUse);
            }
            writeFileSync(file, JSON.stringify(settings, null, 4) + "\n");
        '
        ok "Hooks removed from settings.json (backup written)"
    fi
    rm -f "${HOOKS_DIR:?}/web-fetch-pre.ts" "${HOOKS_DIR:?}/web-fetch-post.ts" "${BIN_DIR:?}/claude-sanitize"
    rm -rf "${HOOKS_DIR:?}/lib" "${SKILL_DIR:?}"
    ok "Files removed"
    if [ "$PURGE" -eq 1 ]; then
        rm -rf "${CLAUDE_HOME:?}/safe-web-research"
        ok "State directory purged"
    else
        say "${DIM}State kept at $CLAUDE_HOME/safe-web-research (re-run with --purge to delete)${RESET}"
    fi
    say "${DIM}The Web Research Protocol block in CLAUDE.md was left in place — remove it by hand if you want it gone.${RESET}"
    exit 0
fi

# ---- 1. Prereqs --------------------------------------------------------------
command -v bun  >/dev/null 2>&1 || die "bun not found. Install: curl -fsSL https://bun.sh/install | bash"
command -v curl >/dev/null 2>&1 || die "curl not found."
command -v tar  >/dev/null 2>&1 || die "tar not found."

BUN_BIN="$(command -v bun)"
BUN_BIN_PORTABLE="${BUN_BIN/#$HOME/\$HOME}"
ok "bun found: $BUN_BIN"

# ---- 2. Locate source (local checkout or download) ---------------------------
SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

TMP_DIR=""
cleanup() { if [ -n "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi; }
trap cleanup EXIT

if [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/hooks" ] && [ -d "$SCRIPT_DIR/skills/safe-web-research" ] && [ -f "$SCRIPT_DIR/bin/claude-sanitize" ]; then
    SRC_DIR="$SCRIPT_DIR"
    ok "Installing from local checkout: $SRC_DIR"
else
    TMP_DIR="$(mktemp -d -t safe-web-research.XXXXXX)"
    say "${DIM}Downloading repo tarball...${RESET}"
    curl -fsSL "$REPO_TARBALL" | tar -xz -C "$TMP_DIR"
    SRC_DIR="$TMP_DIR/$EXTRACTED_NAME"
    [ -d "$SRC_DIR/hooks" ] || die "Unexpected tarball structure: $SRC_DIR/hooks not found"
    ok "Repo extracted"
fi

# ---- 3. Copy files -----------------------------------------------------------
mkdir -p "$HOOKS_DIR/lib" "$SKILL_DIR" "$BIN_DIR"

cp "$SRC_DIR/hooks/package.json"      "$HOOKS_DIR/package.json"
cp "$SRC_DIR/hooks/web-fetch-pre.ts"  "$HOOKS_DIR/web-fetch-pre.ts"
cp "$SRC_DIR/hooks/web-fetch-post.ts" "$HOOKS_DIR/web-fetch-post.ts"
for f in "$SRC_DIR"/hooks/lib/*.ts; do
    case "$f" in
        *.test.ts) continue ;;  # tests stay in the repo, not the install
    esac
    cp "$f" "$HOOKS_DIR/lib/"
done
cp "$SRC_DIR/skills/safe-web-research/SKILL.md"        "$SKILL_DIR/SKILL.md"
cp "$SRC_DIR/skills/safe-web-research/risk-tiers.json" "$SKILL_DIR/risk-tiers.json"
cp "$SRC_DIR/bin/claude-sanitize"     "$BIN_DIR/claude-sanitize"
chmod +x "$BIN_DIR/claude-sanitize"
ok "Files copied to $CLAUDE_HOME"

# ---- 4. bun install ----------------------------------------------------------
say "${DIM}Installing hook dependencies...${RESET}"
( cd "$HOOKS_DIR" && bun install --silent ) || die "bun install failed in $HOOKS_DIR"
ok "Hook dependencies installed"

# ---- 5. Merge settings.json --------------------------------------------------
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
if [ -f "$SETTINGS_FILE" ]; then
    cp "$SETTINGS_FILE" "$SETTINGS_FILE.bak.$TIMESTAMP"
    say "${DIM}Backup: $SETTINGS_FILE.bak.$TIMESTAMP${RESET}"
fi

MERGE_SCRIPT="$(mktemp -t merge-settings.XXXXXX).ts"
cat > "$MERGE_SCRIPT" <<'BUN_MERGE'
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const file = process.env.SETTINGS_FILE!;
const bunPath = process.env.BUN_BIN_PORTABLE!;

// Browser tools that return page-derived text all have to be matched, not just
// the obvious ones: javascript_tool, find, browser_batch and read_console_messages
// can each return a full page body.
const MCP_TOOLS = "mcp__claude-in-chrome__(navigate|read_page|get_page_text|read_network_requests|read_console_messages|javascript_tool|find|browser_batch)|mcp__brightdata__.*";
const PRE_MATCHER  = `WebFetch|WebSearch|Bash|${MCP_TOOLS}`;
const POST_MATCHER = `WebFetch|WebSearch|${MCP_TOOLS}`;
const mode = process.env.SANITISER_MODE || "enforce";
const PRE_CMD  = `CLAUDE_SANITISER_MODE=${mode} ${bunPath} run $HOME/.claude/hooks/web-fetch-pre.ts`;
const POST_CMD = `CLAUDE_SANITISER_MODE=${mode} ${bunPath} run $HOME/.claude/hooks/web-fetch-post.ts`;

let settings: any = {};
if (existsSync(file)) {
    const raw = readFileSync(file, "utf8").trim();
    if (raw) {
        try {
            settings = JSON.parse(raw);
        } catch {
            console.error(`settings.json is not valid JSON — aborting. Fix it manually, then re-run.`);
            process.exit(1);
        }
    }
}

settings.hooks ??= {};
settings.hooks.PreToolUse  = Array.isArray(settings.hooks.PreToolUse)  ? settings.hooks.PreToolUse  : [];
settings.hooks.PostToolUse = Array.isArray(settings.hooks.PostToolUse) ? settings.hooks.PostToolUse : [];

const referencesScript = (entry: any, marker: string): boolean =>
    Array.isArray(entry?.hooks) &&
    entry.hooks.some((h: any) => typeof h?.command === "string" && h.command.includes(marker));

settings.hooks.PreToolUse  = settings.hooks.PreToolUse.filter((e: any)  => !referencesScript(e, "web-fetch-pre.ts"));
settings.hooks.PostToolUse = settings.hooks.PostToolUse.filter((e: any) => !referencesScript(e, "web-fetch-post.ts"));

settings.hooks.PreToolUse.push({
    matcher: PRE_MATCHER,
    hooks: [{ type: "command", command: PRE_CMD, timeout: 5000 }],
});
settings.hooks.PostToolUse.push({
    matcher: POST_MATCHER,
    hooks: [{ type: "command", command: POST_CMD, timeout: 8000 }],
});

writeFileSync(file, JSON.stringify(settings, null, 4) + "\n");
BUN_MERGE

SETTINGS_FILE="$SETTINGS_FILE" BUN_BIN_PORTABLE="$BUN_BIN_PORTABLE" SANITISER_MODE="$MODE" bun run "$MERGE_SCRIPT"
rm -f "$MERGE_SCRIPT"
ok "settings.json updated"

# ---- 6. CLAUDE.md ------------------------------------------------------------
MARKER="Web research safety is handled by the Safe Web Research skill"
read -r -d '' BLOCK <<'EOF' || true

## Web Research Protocol

Web research safety is handled by the Safe Web Research skill (`~/.claude/skills/safe-web-research/SKILL.md`). The hook (`~/.claude/hooks/web-fetch-pre.ts` + `web-fetch-post.ts`) wraps every web fetch in `<untrusted_source>`; the skill carries the abort, corroboration, and reporting rules.
EOF

if [ -f "$CLAUDEMD_FILE" ] && grep -qF "$MARKER" "$CLAUDEMD_FILE"; then
    ok "CLAUDE.md already references Safe Web Research (no change)"
else
    if [ -f "$CLAUDEMD_FILE" ]; then
        cp "$CLAUDEMD_FILE" "$CLAUDEMD_FILE.bak.$TIMESTAMP"
        say "${DIM}Backup: $CLAUDEMD_FILE.bak.$TIMESTAMP${RESET}"
    fi
    printf '%s\n' "$BLOCK" >> "$CLAUDEMD_FILE"
    ok "Appended Safe Web Research block to CLAUDE.md"
fi

# ---- Done --------------------------------------------------------------------
cat <<EOF

${BOLD}Safe Web Research installed${RESET} (mode: ${BOLD}$MODE${RESET})

Verify in a fresh Claude Code session:
    fetch https://example.com and summarize it

Or check directly:
    $BIN_DIR/claude-sanitize status

${BOLD}What each mode gives you${RESET}
    log      Signals and provenance only; nothing is stripped.
    enforce  Adds a sanitised, wrapped copy of every result plus the abort
             verdict. Claude Code does not let a hook replace a built-in tool's
             output, so the raw WebFetch text still reaches the model alongside
             it — enforcement here is advisory-plus-evidence, not removal.
    strict   Refuses WebFetch and the browser read tools outright and routes you
             to 'curl … | claude-sanitize', the one path where the sanitiser
             controls the bytes the model sees. Choose this if you want the
             stripping to be real.

Uninstall any time with:  ./install.sh --uninstall

Docs: https://github.com/Justproof/web-search
EOF
