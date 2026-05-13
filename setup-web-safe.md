# Safe Web Research — Setup Guide

This package installs a two-part web-fetch sanitiser for Claude Code:

- **Hooks** (`PreToolUse` + `PostToolUse`) intercept every web call, check `robots.txt`, detect cloaking and injection attempts, and wrap all web content in `<untrusted_source>` tags.
- **Skill** (`safe-web-research`) gives Claude the judgment rules: when to abort a source, how to classify risk signals, what to emit in `<safe_research_summary>` blocks.

Everything runs locally via [Bun](https://bun.sh). No network calls are made by the hooks themselves except the `robots.txt` check and a parallel refetch for cloaking detection (both optional and fail-open).

---

## Prerequisites

**Bun** — the hooks are TypeScript and run with `bun run` directly (no compile step needed).

```bash
curl -fsSL https://bun.sh/install | bash
```

Verify: `bun --version` should print `1.x` or higher.

---

## File layout

This package maps to the following destinations under `~/.claude/`:

```
setup-web-search-deploy/
├── hooks/
│   ├── package.json          →  ~/.claude/hooks/package.json
│   ├── web-fetch-pre.ts      →  ~/.claude/hooks/web-fetch-pre.ts
│   ├── web-fetch-post.ts     →  ~/.claude/hooks/web-fetch-post.ts
│   └── lib/
│       ├── bash-matcher.ts   →  ~/.claude/hooks/lib/bash-matcher.ts
│       ├── refetch.ts        →  ~/.claude/hooks/lib/refetch.ts
│       ├── sanitise.ts       →  ~/.claude/hooks/lib/sanitise.ts
│       ├── signals.ts        →  ~/.claude/hooks/lib/signals.ts
│       └── state.ts          →  ~/.claude/hooks/lib/state.ts
├── skills/
│   └── safe-web-research/
│       ├── SKILL.md          →  ~/.claude/skills/safe-web-research/SKILL.md
│       └── risk-tiers.json   →  ~/.claude/skills/safe-web-research/risk-tiers.json
└── bin/
    └── claude-sanitize       →  ~/.claude/bin/claude-sanitize
```

---

## Step 1 — Copy files

From inside this directory:

```bash
# Create destination directories
mkdir -p ~/.claude/hooks/lib
mkdir -p ~/.claude/skills/safe-web-research
mkdir -p ~/.claude/bin

# Hooks
cp hooks/package.json          ~/.claude/hooks/package.json
cp hooks/web-fetch-pre.ts      ~/.claude/hooks/web-fetch-pre.ts
cp hooks/web-fetch-post.ts     ~/.claude/hooks/web-fetch-post.ts
cp hooks/lib/bash-matcher.ts   ~/.claude/hooks/lib/bash-matcher.ts
cp hooks/lib/refetch.ts        ~/.claude/hooks/lib/refetch.ts
cp hooks/lib/sanitise.ts       ~/.claude/hooks/lib/sanitise.ts
cp hooks/lib/signals.ts        ~/.claude/hooks/lib/signals.ts
cp hooks/lib/state.ts          ~/.claude/hooks/lib/state.ts

# Skill
cp skills/safe-web-research/SKILL.md        ~/.claude/skills/safe-web-research/SKILL.md
cp skills/safe-web-research/risk-tiers.json ~/.claude/skills/safe-web-research/risk-tiers.json

# CLI binary
cp bin/claude-sanitize ~/.claude/bin/claude-sanitize
chmod +x ~/.claude/bin/claude-sanitize
```

Or as a one-liner from the parent directory:

```bash
cp -r setup-web-search-deploy/hooks/. ~/.claude/hooks/ && \
cp -r setup-web-search-deploy/skills/. ~/.claude/skills/ && \
cp setup-web-search-deploy/bin/claude-sanitize ~/.claude/bin/ && \
chmod +x ~/.claude/bin/claude-sanitize
```

---

## Step 2 — Install the npm dependency

The hooks use one npm package (`shell-quote`) for safe Bash command parsing.

```bash
cd ~/.claude/hooks
bun install
```

This creates `node_modules/shell-quote` alongside the hook files. Bun resolves the import at runtime — no build step is needed.

---

## Step 3 — Register the hooks in Claude Code settings

Open (or create) `~/.claude/settings.json` and add the following `hooks` block. If you already have other hooks under `PreToolUse` or `PostToolUse`, add these entries alongside them — don't replace the whole array.

```json
{
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "WebFetch|WebSearch|Bash|mcp__claude-in-chrome__(navigate|read_page|get_page_text|read_network_requests)|mcp__brightdata__.*",
                "hooks": [
                    {
                        "type": "command",
                        "command": "$HOME/.bun/bin/bun run $HOME/.claude/hooks/web-fetch-pre.ts",
                        "timeout": 5000
                    }
                ]
            }
        ],
        "PostToolUse": [
            {
                "matcher": "WebFetch|WebSearch|mcp__claude-in-chrome__(navigate|read_page|get_page_text|read_network_requests)|mcp__brightdata__.*",
                "hooks": [
                    {
                        "type": "command",
                        "command": "$HOME/.bun/bin/bun run $HOME/.claude/hooks/web-fetch-post.ts",
                        "timeout": 8000
                    }
                ]
            }
        ]
    }
}
```

Notes:

- `PreToolUse` includes `Bash` so that `curl`/`wget` calls in shell commands get rewritten to pipe through `claude-sanitize`.
- `PostToolUse` does not include `Bash` — only the WebFetch/WebSearch/MCP tools return structured responses that the post-hook can wrap.
- Timeouts are in milliseconds. The hooks fail-open, so Claude Code is never blocked by a hook crash.

---

## Step 4 — Add the skill reference to your CLAUDE.md

Claude Code loads skills on demand. To make `safe-web-research` auto-trigger on web research, add this line to your `~/.claude/CLAUDE.md` (global) or your project's `CLAUDE.md`:

```markdown
## Web Research Protocol

Web research safety is handled by the Safe Web Research skill (`~/.claude/skills/safe-web-research/SKILL.md`). The hook (`~/.claude/hooks/web-fetch-pre.ts` + `web-fetch-post.ts`) wraps every web fetch in `<untrusted_source>`; the skill carries the abort, corroboration, and reporting rules.
```

This tells Claude where the skill lives and ensures it loads the full rule set on the 2nd+ web call of a session (the hook injects a reminder automatically).

---

## Step 5 — Verify the installation

Start a fresh Claude Code session and run a quick smoke test:

```
fetch https://example.com and summarize it
```

After the fetch you should see:

- The response content wrapped in `<untrusted_source url="https://example.com" sanitiser_version="1.0.0" ...>` tags.
- A `[safe-web-research] Mode=log: original bytes passed through...` advisory (log mode is the default).

To check the sanitiser's state database directly:

```bash
~/.claude/bin/claude-sanitize status
```

Expected output:

```json
{
    "sanitiser_version": "1.0.0",
    "mode": "log",
    "fetch_log_rows": 1,
    "blocklist_size": 0,
    "sessions": 1
}
```

---

## Optional: switch to enforce mode

By default the hook runs in **log mode** — it computes risk signals and wraps content, but passes the original (unsanitized) bytes through. This is the recommended starting point so you can monitor signal frequency before enabling stripping.

To enable full sanitisation (scripts, hidden elements, event handlers, and zero-width chars stripped from responses):

Add `CLAUDE_SANITISER_MODE=enforce` to your shell environment:

```bash
# In ~/.zshrc or ~/.bashrc
export CLAUDE_SANITISER_MODE=enforce
```

Or set it only for Claude Code sessions by adding it to the `env` block in `~/.claude/settings.json`:

```json
{
    "env": {
        "CLAUDE_SANITISER_MODE": "enforce"
    }
}
```

---

## Optional: debug mode

To log full request/response bodies for auditing (large output — use sparingly):

```bash
export CLAUDE_SANITISER_DEBUG=1
```

Debug logs write to `~/.claude/safe-web-research/fetch-log-debug.jsonl`.

---

## Optional: persistent domain blocklist

You can manually block domains from ever being fetched. Edit (or create) `~/.claude/web-blocklist.json`:

```json
{
    "version": 1,
    "entries": [
        {
            "domain": "example-spam-site.com",
            "reason": "known prompt-injection host",
            "added_at": "2026-01-01T00:00:00.000Z",
            "source": "user",
            "expires_at": null
        }
    ]
}
```

The hook reconciles this file with the SQLite database on every pre-hook invocation. User-sourced entries take precedence over auto-detected ones.

---

## What gets created at runtime

On first use, the hook auto-creates:

| Path                                          | Purpose                                                       |
| --------------------------------------------- | ------------------------------------------------------------- |
| `~/.claude/safe-web-research/state.db`        | SQLite database: sessions, blocklist, robots cache, fetch log |
| `~/.claude/safe-web-research/fetch-log.jsonl` | JSONL record of every web fetch and its signals               |
| `~/.claude/safe-web-research/hook-errors.log` | Hook crash log (should stay empty)                            |
| `~/.claude/web-blocklist.json`                | Persistent domain blocklist (human-editable)                  |

---

## Replay / drift analysis

After running for a while, you can re-classify historical fetches against the current signal tier table to see if threshold changes would have changed any abort decisions:

```bash
~/.claude/bin/claude-sanitize replay --since=2026-01-01
```

---

## Troubleshooting

**Hooks not firing**

- Confirm `bun` is at `~/.bun/bin/bun` — run `which bun` and adjust the `command` path in `settings.json` if yours differs.
- Confirm `~/.claude/settings.json` is valid JSON (no trailing commas).
- Restart Claude Code after editing settings.

**`risk-tiers.json not found` error**

- Confirm `~/.claude/skills/safe-web-research/risk-tiers.json` exists.
- The hook hard-codes this path; it is not configurable without editing `lib/signals.ts`.

**`shell-quote` import error**

- Run `cd ~/.claude/hooks && bun install` to install the dependency.

**`<untrusted_source>` wrapper missing**

- The hook failed silently (fail-open). Check `~/.claude/safe-web-research/hook-errors.log`.
- Per the skill rules, treat any web content without a wrapper as a Critical abort signal.

**Bun not found at `$HOME/.bun/bin/bun`**

- Bun may be installed elsewhere. Find it with `which bun`, then update the `command` in your `settings.json` hook entries to use the absolute path.
