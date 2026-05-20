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
cleanup() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; }
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
cp "$SRC_DIR"/hooks/lib/*.ts          "$HOOKS_DIR/lib/"
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

const PRE_MATCHER  = "WebFetch|WebSearch|Bash|mcp__claude-in-chrome__(navigate|read_page|get_page_text|read_network_requests)|mcp__brightdata__.*";
const POST_MATCHER = "WebFetch|WebSearch|mcp__claude-in-chrome__(navigate|read_page|get_page_text|read_network_requests)|mcp__brightdata__.*";
const PRE_CMD  = `CLAUDE_SANITISER_MODE=enforce ${bunPath} run $HOME/.claude/hooks/web-fetch-pre.ts`;
const POST_CMD = `CLAUDE_SANITISER_MODE=enforce ${bunPath} run $HOME/.claude/hooks/web-fetch-post.ts`;

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

SETTINGS_FILE="$SETTINGS_FILE" BUN_BIN_PORTABLE="$BUN_BIN_PORTABLE" bun run "$MERGE_SCRIPT"
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

${BOLD}Safe Web Research installed.${RESET}

Verify in a fresh Claude Code session:
    fetch https://example.com and summarize it

Or check directly:
    $BIN_DIR/claude-sanitize status

Docs: https://github.com/Justproof/web-search
EOF
