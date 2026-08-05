# safe-web-research

Claude has two built-in web tools <a href="https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-fetch-tool">Web Fetch</a> and <a href="https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool">Web Search</a> which are available to use in every Claude Code installation. With a fresh Claude install, the default permission mode asks for approval before each use. 

Most people approve or switch default Mode to "auto", which allows web searching with full permission. Full auto is a reasonable choice, but consider what this means when using AI to search the internet: not every site out there has good intentions for an AI crawler, and certain <a href="https://pcdrama.com/blog/ai-tarpits#why-web-admins-send-non-sense-to-ai">"Stay off my lawn / website" web admins</a> are punching back by relaying non-sense to bots, causing AI to struggle through AI tarpits.
Without guardrails, it will cheerfully read a shady webpage that opens with "ignore your previous instructions" and politely follow along. No questions asked.

> **Curious?** Ask Claude: *"Are there built-in protections when using web fetch or web search tools?"*
> You'll get a polite answer, and the [official docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-fetch-tool) back up this response: No. there aren't any prompt injection guardrails. That's exactly why Safe Web Research guardrails are necessary.
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
| **Hooks** (`PreToolUse` + `PostToolUse`) | Intercept `WebFetch`, `WebSearch`, `curl`/`wget`/`wget2`/`aria2c`/`httpie` in Bash, interpreter one-liners (Python, Node, Ruby, Perl, PHP), and browser MCP tools. Check `robots.txt`, detect cloaking and injection attempts, compute risk signals, and wrap all web content in `<untrusted_source>` tags before Claude reads a single byte. |
| **Skill** (`safe-web-research`) | Gives Claude the judgment rules: when to abort a source, how to classify risk signals, what to emit in `<safe_research_summary>` blocks, and how to handle corroboration and output discipline. |

The hooks handle mechanics. The skill handles reasoning. Neither can be argued out of its job by a web page.

---

## Prerequisites

**[Claude Code](https://code.claude.com/docs/en/quickstart)** — install and sign in first. The hooks and skill in this repo plug into a working Claude Code setup; if `~/.claude/` doesn't exist yet, run Claude Code at least once before continuing.

**[Bun](https://bun.sh)** — the hooks are TypeScript and run with `bun run` directly (no compile step).

```bash
curl -fsSL https://bun.sh/install | bash
```

Verify: `bun --version` should print `1.x` or higher.

---

## Install

One line. Checks for Bun, grabs the repo, drops files into `~/.claude/`, merges your `settings.json`, and appends the skill reference to `~/.claude/CLAUDE.md`. Anything it touches gets a timestamped backup first.

```bash
curl -fsSL https://raw.githubusercontent.com/Justproof/web-search/main/install.sh | bash
```

Safe to re-run. Running it twice doesn't duplicate hooks or paste the skill block twice, so treat it as your upgrade command too.

Prefer to read what you eat? Same recipe in two steps:

```bash
curl -fsSL https://raw.githubusercontent.com/Justproof/web-search/main/install.sh -o install.sh
less install.sh && bash install.sh
```

Want to see every step laid out by hand instead of trusting a script? Skip to [Manual install](#manual-install) at the bottom.

### Verify

Start a fresh Claude Code session:

```
fetch https://example.com and summarize it
```

You should see the response wrapped in `<untrusted_source url="https://example.com" sanitiser_version="1.1.0" nonce="..." ...>` tags. Or check the state database directly:

```bash
~/.claude/bin/claude-sanitize status
```

Run the test suite against a checkout:

```bash
cd hooks && bun install && bun test
```

To remove everything: `./install.sh --uninstall` (add `--purge` to delete the state database too).

---

## Real-world scenarios

### The poisoned package README

A developer asks Claude to evaluate an unfamiliar npm package before adding it as a dependency. Claude fetches the package page, the linked GitHub repo, and a few Stack Overflow threads. One of those pages — maybe the package's own README, maybe a tutorial — opens with content designed to redirect Claude's behavior. Without guardrails, Claude reads it and follows along. With the hook, every response is wrapped in `<untrusted_source>` before Claude reads a byte, and injection phrases fire a Critical signal that aborts the source before Claude quotes a word of it. The research completes. The poisoned page has zero influence on the output.

```
what does the "event-stream" npm package do and is it safe to use?
```

---

### Claude goes somewhere you didn't send it

A developer running Claude in full-auto mode asks for a multi-source research task. Claude fetches a page that contains instructions telling it to follow a link, fetch a second URL, or install a package to "see the full content." Without guardrails, Claude may comply — it has no reason not to. With abort rules loaded, a source that tries to redirect Claude's tool use is aborted on the injection signal before any downstream action happens. The task continues from clean sources. The detour never occurs.

```
compare the architecture of three popular background job libraries for Node.js
```

---

### A link arrives from somewhere you don't fully trust

A URL shows up in a Slack message, a bug report, or a client email. Before Claude makes any network request, the pre-hook inspects the raw URL string — not the parsed version, the raw string. Embedded credentials, lookalike Unicode hostname characters, zero-width chars in the path, and multi-`@` authority tricks are refused before a single byte leaves the machine. The attack surface that exists before the page even loads is closed entirely.

```
fetch https://user:pass@httpbin.org/get and summarize it
```

No request is made:

> `[safe-web-research] FR-27 blocked: embedded credentials in URL (user:pass@ pattern). Fetch refused. Do not retry this URL.`

---

### A web page tells Claude to run a shell command

Claude is helping debug a build failure and fetches a documentation page. That page contains instructions telling Claude to run a curl command to download a fix script. Without guardrails, Claude runs it — the script's output arrives in context as trusted text. With the hook, the Bash command is intercepted before execution and rewritten to pipe stdout through `claude-sanitize`. The download still happens. But the output arrives wrapped in `<untrusted_source>`, labeled as untrusted, and Claude treats it accordingly instead of executing its contents.

The rewrite is visible in the approval dialog:

`( curl https://example.com/fix.sh ) | ~/.claude/bin/claude-sanitize --url=bash-stdin`

Works the same for `wget`, `wget2`, `aria2c`, `httpie`, and Python/Node/Ruby one-liners with a URL in the inline code.

---

### Reviewing what got through before you tightened thresholds

A developer has been running Claude in auto mode for two weeks and just updated `risk-tiers.json` to lower the elevated-signal abort threshold. Before deciding whether the change is right, they replay history against the new config to see which past fetches would now be aborted that weren't before. Two fetches from last Tuesday would have been caught — both from a domain that has since shown up in public blocklists. The threshold change is validated and committed.

```bash
# see sessions, blocked domains, robots cache, and recent signal activity
~/.claude/bin/claude-sanitize status

# compare stored decisions against current config
~/.claude/bin/claude-sanitize replay --last=50
```

`stored_abort` is what the hook decided at fetch time. `current_abort` is what it would decide now. Rows that disagree are the concrete cost or benefit of the config change — before it affects a live session.

---

## How it works

Every web fetch goes through two checkpoints:

**Pre-hook** — before the request:
- URL-level checks: literal homoglyphs, **pre-encoded punycode homoglyphs** (`xn--pypal-4ve.com` → `раypal.com`, and whole-script spoofs like `xn--80ak6aa92e.com` → `аррӏе.com`), embedded credentials, invisible chars in host or path, multi-`@` authority tricks, non-web schemes — hard deny, no fetch
- `robots.txt` fetch and cache (24h TTL), parsed with `Allow`/`Disallow` precedence and `*`/`$` wildcards. A group naming an AI crawler (`ClaudeBot`, `GPTBot`, `Google-Extended`, …) is reported as a stated position on AI access; the hook does not block, Claude decides
- Blocklisted domains (and their subdomains) trigger a permission **prompt** rather than a reminder — an abort-unless-overridden rule should require a human, not a model's discretion
- Search queries are never treated as fetches: `WebSearch` skips the robots.txt and URL gates (those apply when a result is fetched) and just counts toward the per-session skill reminder
- Bash command rewriting: `curl`, `wget`, `xh`, `httpie`, `aria2c`, `lynx`, `w3m`, `links`, and interpreter one-liners (Python/Node/Bun/Deno/Ruby/Perl/PHP with inline URL) get piped through `claude-sanitize` — including behind wrappers (`command`, `env`, `timeout`, `sudo`, `nohup`, `exec`, `nice`), inside `bash -c`, in `$(…)`, and via `xargs`
- Trusted domains in the `meta_allowlist` have a single `injection_phrase` signal downgraded from Critical abort to advisory — useful for security research and documentation sites

**Post-hook** — after the response:
- Strips scripts, hidden elements (including `hidden`, off-screen, and zero-size CSS), event handlers, and the full invisible-Unicode range — zero-width, bidi controls, variation selectors, and the U+E0000 tag-character smuggling channel. `<header>` and `<footer>` are intentionally preserved — they carry bylines, dates, and citations inside articles that stripping would destroy
- Neutralises wrapper-shaped markup in the body, so a page cannot close its own `<untrusted_source>` block or forge a `<safe_research_summary>` verdict; the opening and closing tags carry a matching random nonce
- Computes risk signals (injection phrases matched against a **normalised** body, cloaking, oversized responses, tarpit patterns)
- Runs a parallel refetch to detect cloaking; refuses to issue that unattended request to private, loopback, or link-local targets, re-checks every redirect hop, and caps how much it will read
- Vets the URLs inside search results (first 50 distinct): blocklisted domains and URLs failing the URL checks fire Elevated signals and an advisory naming the results Claude must not open
- Promotes a domain to a session-scoped blocklist after repeated aborts against it (default 3), so the next fetch needs user approval
- Wraps everything in `<untrusted_source>` with signal metadata; in `log` mode the wrapper includes a `rules_pending` attribute listing what would have been stripped

**Skill** — when Claude reads the result:
- Abort rules fire before any analysis, quoting, or downstream actions
- Per-source `<safe_research_summary>` blocks for every cited URL
- Aborted sources have zero downstream gravity — they don't influence tool selection, code generation, or package recommendations

---

## Risk signals

**Critical** (any one = abort):

- `injection_phrase` — matches curated prompt-injection patterns, after normalising away invisible characters, NFKC forms, and Cyrillic/Greek homoglyphs, so `ig<ZWSP>nore previous instructions` and `ignоre` (Cyrillic о) both match
- `wrapper_escape_attempt` — the page contained markup shaped like a closing wrapper tag or a forged control block. No benign cause exists
- `unicode_tag_chars` — U+E0000–E007F tag characters, the invisible ASCII smuggling channel; the advisory reports the decoded payload
- `cloaking_suspected` — parallel refetch diverged from the agent's fetch
- `oversized_response` — above size cap
- `repeating_substring_ratio_high` — Markov-style repetition (poisoning / honeypot)
- `url_cardinality_explosion` — tarpit signature

**Elevated** (three or more = abort):

- `zero_width_chars`
- `bidi_control_chars` — bidirectional overrides that reorder rendered text (trojan-source)
- `hidden_content_ratio_high`
- `redirect_chain_long` (> 5 hops)
- `content_type_mismatch`
- `near_duplicate_to_session`
- `blocklisted_result_domain` — a search result's domain is blocklisted
- `suspicious_result_url` — a search result URL fails the homoglyph / credential / zero-width checks

Tier assignments live in `skills/safe-web-research/risk-tiers.json` and can be overridden via the SQLite config.

---

## Modes

### The constraint you need to know first

Claude Code does **not** let a `PostToolUse` hook replace the result of a built-in tool ([anthropics/claude-code#32105](https://github.com/anthropics/claude-code/issues/32105)). For `WebFetch` and `WebSearch`, the raw response reaches the model no matter what this project does; the hook's sanitised copy arrives *alongside* it. MCP tool output *can* be replaced, so for browser/scraper MCP tools the stripping is real.

That constraint is why there are three modes rather than two, and why `enforce` does not claim to remove anything from a built-in tool's output.

| Mode | Behavior |
| --- | --- |
| `enforce` (default) | Emits the `<untrusted_source>` wrapper, the risk verdict, and — only when the sanitised bytes actually differ from what the tool returned — the sanitised copy, with an instruction to prefer it and treat raw-only content as hostile. Real replacement for MCP tools; evidence-plus-advisory for built-ins. Identical bodies are never duplicated, so a clean fetch costs no extra tokens. |
| `strict` | The pre-hook **denies** `WebFetch` and the browser read tools and points Claude at `curl … \| claude-sanitize`, the one path where the sanitiser controls the bytes the model sees. `WebSearch` still runs (no shell equivalent exists) and is still wrapped and scored. Choose this if you want stripping to be more than advisory. |
| `log` | Computes signals and wraps metadata, but strips nothing and emits no sanitised copy. The wrapper lists what *would* have been stripped in `rules_pending`. For understanding signal frequency on your own traffic. |

Set it in each hook command in `~/.claude/settings.json` (the installer does this automatically):

```json
"command": "CLAUDE_SANITISER_MODE=enforce $HOME/.bun/bin/bun run $HOME/.claude/hooks/web-fetch-post.ts"
```

Or install directly into the mode you want: `./install.sh --mode strict`.

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

## Manual install

The one-line installer does these four steps. If you'd rather skip the pipe-to-bash and run them yourself, here they are.

### 1. Copy files

From inside a checkout of this repo:

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
cp hooks/lib/url-checks.ts     ~/.claude/hooks/lib/url-checks.ts
cp skills/safe-web-research/SKILL.md        ~/.claude/skills/safe-web-research/SKILL.md
cp skills/safe-web-research/risk-tiers.json ~/.claude/skills/safe-web-research/risk-tiers.json
cp bin/claude-sanitize ~/.claude/bin/claude-sanitize
chmod +x ~/.claude/bin/claude-sanitize
```

Or as a one-liner from the repo root:

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

Open `~/.claude/settings.json`. If it doesn't exist yet (fresh Claude Code installs often don't have one until you've changed a setting), create it with the full block below. If it does exist, merge the `hooks` key into what's already there — don't clobber existing keys.

```json
{
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "WebFetch|WebSearch|Bash|mcp__claude-in-chrome__(navigate|read_page|get_page_text|read_network_requests)|mcp__brightdata__.*",
                "hooks": [
                    {
                        "type": "command",
                        "command": "CLAUDE_SANITISER_MODE=enforce $HOME/.bun/bin/bun run $HOME/.claude/hooks/web-fetch-pre.ts",
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
                        "command": "CLAUDE_SANITISER_MODE=enforce $HOME/.bun/bin/bun run $HOME/.claude/hooks/web-fetch-post.ts",
                        "timeout": 8000
                    }
                ]
            }
        ]
    }
}
```

`PreToolUse` includes `Bash` so `curl`, `wget`, `wget2`, `aria2c`, `httpie`, and interpreter one-liners (Python/Node/Ruby/Perl/PHP with an inline URL) get rewritten to pipe through `claude-sanitize`. `PostToolUse` covers structured web tool responses only.

Hooks are fail-open — a hook crash never blocks Claude Code.

### 4. Add the skill reference to your CLAUDE.md

Open `~/.claude/CLAUDE.md` and append the block below. If the file doesn't exist yet (it's not created by default), just create it with this content as the whole file:

```markdown
## Web Research Protocol

Web research safety is handled by the Safe Web Research skill (`~/.claude/skills/safe-web-research/SKILL.md`). The hook (`~/.claude/hooks/web-fetch-pre.ts` + `web-fetch-post.ts`) wraps every web fetch in `<untrusted_source>`; the skill carries the abort, corroboration, and reporting rules.
```

---

## License

MIT
