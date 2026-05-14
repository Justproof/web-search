# safe-web-research

Claude ships with a built-in web fetch tool. Handy. Also a little naive.

Without guardrails, it will cheerfully read a shady webpage that opens with "ignore your previous instructions" and politely follow along. No questions asked.

> **Curious?** Ask Claude: *"Are there built-in protections when you do web fetch?"*
> You'll get a polite answer, and the [official docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-fetch-tool) quietly back it up: there aren't any promt injection guardrails.
> That's exactly why Safe Web Research guardrails are necessary.

**Safe Web Research** fixes that with two quiet layers:

- **Custom TypeScript hooks** that intercept, inspect, and clean every web response before Claude reads a single byte.
- **A clear judgment skill** that helps Claude spot trouble and respond wisely instead of blind trust.

No paranoia. Just everyday common sense, like sending a teenager out for milk and your certain they are not distracted or completing 8 side missions . Claude stays helpful and fast. It just stops being gullible.

Ready to set it up? Grab a coffee and follow along. This takes about five minutes.

**[github.com/Justproof/web-search](https://github.com/Justproof/web-search)**

---

## What's in the box

| Component | What it does |
| --- | --- |
| **Hooks** (`PreToolUse` + `PostToolUse`) | Intercept `WebFetch`, `WebSearch`, `curl`/`wget` in Bash, and browser MCP tools. Check `robots.txt`, detect cloaking and injection attempts, compute risk signals, and wrap all web content in `<untrusted_source>` tags before Claude reads a single byte. |
| **Skill** (`safe-web-research`) | Gives Claude the judgment rules: when to abort a source, how to classify risk signals, what to emit in `<safe_research_summary>` blocks, and how to handle corroboration and output discipline. |

The hooks handle mechanics. The skill handles reasoning. Neither can be argued out of its job by a web page.

---

## Prerequisites

**[Bun](https://bun.sh)** — the hooks are TypeScript and run with `bun run` directly (no compile step).

```bash
curl -fsSL https://bun.sh/install | bash
```

Verify: `bun --version` should print `1.x` or higher.

---

## Install

### 1. Copy files

From inside this repo:

```bash
mkdir -p ~/.claude/hooks/lib
mkdir -p ~/.claude/skills/safe-web-research
mkdir -p ~/.claude/bin

cp hooks/package.json          ~/.claude/hooks/package.json
cp hooks/web-fetch-pre.ts      ~/.claude/hooks/web-fetch-pre.ts
cp hooks/web-fetch-post.ts     ~/.claude/hooks/web-fetch-post.ts
cp hooks/lib/bash-matcher.ts   ~/.claude/hooks/lib/bash-matcher.ts
cp hooks/lib/refetch.ts        ~/.claude/hooks/lib/refetch.ts
cp hooks/lib/sanitise.ts       ~/.claude/hooks/lib/sanitise.ts
cp hooks/lib/signals.ts        ~/.claude/hooks/lib/signals.ts
cp hooks/lib/state.ts          ~/.claude/hooks/lib/state.ts
cp skills/safe-web-research/SKILL.md        ~/.claude/skills/safe-web-research/SKILL.md
cp skills/safe-web-research/risk-tiers.json ~/.claude/skills/safe-web-research/risk-tiers.json
cp bin/claude-sanitize ~/.claude/bin/claude-sanitize
chmod +x ~/.claude/bin/claude-sanitize
```

Or as a one-liner from the parent directory:

```bash
cp -r hooks/. ~/.claude/hooks/ && \
cp -r skills/. ~/.claude/skills/ && \
cp bin/claude-sanitize ~/.claude/bin/ && \
chmod +x ~/.claude/bin/claude-sanitize
```

### 2. Install the npm dependency

```bash
cd ~/.claude/hooks && bun install
```

This installs `shell-quote` for safe Bash command parsing. No build step needed.

### 3. Register hooks in Claude Code settings

Add to `~/.claude/settings.json` (merge with any existing `hooks` block):

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

`PreToolUse` includes `Bash` so `curl`/`wget` calls get rewritten to pipe through `claude-sanitize`. `PostToolUse` covers structured web tool responses only.

Hooks are fail-open — a hook crash never blocks Claude Code.

### 4. Add the skill reference to your CLAUDE.md

Add this to `~/.claude/CLAUDE.md`:

```markdown
## Web Research Protocol

Web research safety is handled by the Safe Web Research skill (`~/.claude/skills/safe-web-research/SKILL.md`). The hook (`~/.claude/hooks/web-fetch-pre.ts` + `web-fetch-post.ts`) wraps every web fetch in `<untrusted_source>`; the skill carries the abort, corroboration, and reporting rules.
```

### 5. Verify

Start a fresh Claude Code session:

```
fetch https://example.com and summarize it
```

You should see the response wrapped in `<untrusted_source url="https://example.com" sanitiser_version="1.0.0" ...>` tags. Or check the state database directly:

```bash
~/.claude/bin/claude-sanitize status
```

---

## How it works

Every web fetch goes through two checkpoints:

**Pre-hook** — before the request:
- URL-level checks: homoglyphs, non-ASCII hostnames, embedded credentials, zero-width chars
- `robots.txt` fetch and cache (24h TTL); disallowed AI user-agents skip the fetch entirely
- Bash command rewriting: `curl`/`wget` pipes get redirected through `claude-sanitize`

**Post-hook** — after the response:
- Strips scripts, hidden elements, event handlers, and zero-width characters (in `enforce` mode)
- Computes risk signals (injection phrases, cloaking, oversized responses, tarpit patterns)
- Runs a parallel refetch to detect cloaking (the page serving different content to Claude than to a browser)
- Wraps everything in `<untrusted_source>` with signal metadata

**Skill** — when Claude reads the result:
- Abort rules fire before any analysis, quoting, or downstream actions
- Per-source `<safe_research_summary>` blocks for every cited URL
- Aborted sources have zero downstream gravity — they don't influence tool selection, code generation, or package recommendations

---

## Risk signals

**Critical** (any one = abort):

- `injection_phrase` — matches curated prompt-injection patterns
- `cloaking_suspected` — parallel refetch diverged from the agent's fetch
- `oversized_response` — above size cap
- `repeating_substring_ratio_high` — Markov-style repetition (poisoning / honeypot)
- `url_cardinality_explosion` — tarpit signature

**Elevated** (three or more = abort):

- `zero_width_chars`
- `hidden_content_ratio_high`
- `redirect_chain_long` (> 5 hops)
- `content_type_mismatch`
- `near_duplicate_to_session`

Tier assignments live in `skills/safe-web-research/risk-tiers.json` and can be overridden via the SQLite config.

---

## Modes

| Mode | Behavior |
| --- | --- |
| `log` (default) | Computes signals and wraps content, but passes the **original** bytes through. Good for a soak period to understand signal frequency before enabling stripping. |
| `enforce` | Returns sanitized + wrapped responses. Scripts, hidden elements, event handlers, and zero-width chars are stripped. |

Switch modes via environment variable:

```bash
export CLAUDE_SANITISER_MODE=enforce
```

Or in `~/.claude/settings.json`:

```json
{
    "env": {
        "CLAUDE_SANITISER_MODE": "enforce"
    }
}
```

---

## Domain blocklist

Manually block domains from ever being fetched. Edit `~/.claude/web-blocklist.json`:

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

The hook reconciles this file with its SQLite database on every pre-hook invocation.

---

## Runtime files

Created automatically on first use:

| Path | Purpose |
| --- | --- |
| `~/.claude/safe-web-research/state.db` | SQLite: sessions, blocklist, robots cache, fetch log |
| `~/.claude/safe-web-research/fetch-log.jsonl` | Every web fetch and its signals |
| `~/.claude/safe-web-research/hook-errors.log` | Hook crash log (should stay empty) |
| `~/.claude/web-blocklist.json` | Persistent domain blocklist |

---

## Drift analysis

Re-classify historical fetches against the current signal tier table:

```bash
~/.claude/bin/claude-sanitize replay --since=2026-01-01
```

Useful for seeing whether threshold changes would have changed any abort decisions.

---

## Troubleshooting

**Hooks not firing** — confirm `bun` is at `~/.bun/bin/bun` (`which bun`), that `~/.claude/settings.json` is valid JSON, and restart Claude Code after editing settings.

**`risk-tiers.json not found`** — confirm `~/.claude/skills/safe-web-research/risk-tiers.json` exists.

**`shell-quote` import error** — run `cd ~/.claude/hooks && bun install`.

**`<untrusted_source>` wrapper missing** — the hook failed silently. Check `~/.claude/safe-web-research/hook-errors.log`. Per the skill rules, treat unwrapped web content as a Critical abort signal.

**Bun not at `$HOME/.bun/bin/bun`** — find it with `which bun`, then update the `command` paths in `settings.json`.

---

## License

MIT
