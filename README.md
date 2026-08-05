# safe-web-research

Claude has two built-in web tools <a href="https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-fetch-tool">Web Fetch</a> and <a href="https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool">Web Search</a> which are available to use in every Claude Code installation. With a fresh Claude install, the default permission mode asks for approval before each use. 

Most people approve or switch default Mode to "auto", which allows web searching with full permission. Full auto is a reasonable choice, but consider what this means when using AI to search the internet: not every site out there has good intentions for an AI crawler, and certain <a href="https://pcdrama.com/blog/ai-tarpits#why-web-admins-send-non-sense-to-ai">"Stay off my lawn / website" web admins</a> are punching back by relaying non-sense to bots, causing AI to struggle through AI tarpits.
Without guardrails, it will cheerfully read a shady webpage that opens with "ignore your previous instructions" and politely follow along. No questions asked.

> **Curious?** Ask Claude: *"Are there built-in protections when using web fetch or web search tools?"*
> You'll get a polite answer, and the [official docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-fetch-tool) back up this response: No. there aren't any prompt injection guardrails. That's exactly why Safe Web Research guardrails are necessary.
> That's exactly why Safe Web Research guardrails are necessary.

**Safe Web Research** fixes that with two quiet layers:

- **Custom TypeScript hooks** that intercept every web request and response, refuse hostile URLs outright, strip the dangerous parts, and label what's left as untrusted.
- **A clear judgment skill** that helps Claude spot trouble and respond wisely instead of blind trust.

One caveat stated up front, because it shapes everything below: Claude Code does not let a hook replace the result of a *built-in* tool, so for `WebFetch` and `WebSearch` the raw response reaches Claude no matter what this project does — the sanitised copy and the risk verdict arrive alongside it. Shell fetches and MCP browser tools *are* fully controlled. If you want the stripping to be real rather than advisory, `strict` mode routes everything down the path where it is. See [Modes](#modes).

No paranoia. Just everyday common sense, like sending a teenager out for milk and your certain they are not distracted or completing 8 side missions . Claude stays helpful and fast. It just stops being gullible.

Ready to set it up? Grab a coffee and follow along. This takes about five minutes.

**[github.com/Justproof/web-search](https://github.com/Justproof/web-search)**

---

## What's in the box

| Component | What it does |
| --- | --- |
| **Hooks** (`PreToolUse` + `PostToolUse`) | Intercept `WebFetch`, `WebSearch`, shell fetches (`curl`, `wget`, `xh`, `curlie`, `httpie`, `aria2c`, `lynx`, `w3m`, `links` — including behind `sudo`/`env`/`timeout` and inside `bash -c`, `$(…)` and `xargs`), interpreter one-liners (Python, Node, Bun, Deno, Ruby, Perl, PHP), and browser MCP tools. Refuse hostile URLs before the request, check `robots.txt`, detect cloaking and injection attempts, compute risk signals, and wrap web content in `<untrusted_source>` tags with a nonce a page can't forge. |
| **Skill** (`safe-web-research`) | Gives Claude the judgment rules: when to abort a source, how to classify risk signals, what to emit in `<safe_research_summary>` blocks, and how to handle corroboration and output discipline. |
| **CLI** (`claude-sanitize`) | The same sanitiser as a stdin/stdout filter, plus `status` and `replay`. It's what shell fetches get piped through, and the path `strict` mode routes everything to. |

The hooks handle mechanics. The skill handles reasoning. Neither can be argued out of its job by a web page.

Everything is covered by a test suite — 157 tests, run in CI on every push: unit tests per rule, subprocess-integration tests that run the hooks the way Claude Code runs them, and a fixture corpus (below).

### The fixture corpus

`fixtures/` holds frozen snapshots of six real pages — a minimal page, a 297 KB Wikipedia article, technical docs, an institutional site, a plain-text RFC, and a JSON API — plus twelve handcrafted adversarial pages, each aimed at one detection or one past bug.

It exists because the two worst bugs this project has had were invisible to unit tests. A signal fired on every styled page, and a single `<img aria-hidden="true">` deleted 98% of an article — each rule passed its own test while the pipeline destroyed real pages. Every fixture asserts a **content-retention band**, so a collapse fails CI instead of failing silently in your context window.

```bash
cd hooks && bun test              # includes the corpus
bun run fixtures/capture.ts       # re-capture the real pages (network; run by hand)
```

The snapshots are deliberately frozen: CI must not depend on the live internet, and a page changing under you should be a deliberate re-capture, not a mystery failure. `fixtures/real/manifest.json` records each source URL, capture date, and SHA-256.

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

A developer asks Claude to evaluate an unfamiliar npm package before adding it as a dependency. Claude fetches the package page, the linked GitHub repo, and a few Stack Overflow threads. One of those pages — maybe the package's own README, maybe a tutorial — opens with content designed to redirect Claude's behavior. Without guardrails, Claude reads it and follows along. With the hook, the response is wrapped in `<untrusted_source>` and carries a verdict, and injection phrases fire a Critical signal that aborts the source before Claude quotes a word of it. The match runs against a normalised copy of the page, so hiding a zero-width space inside the phrase — or swapping one Latin letter for its Cyrillic twin — doesn't get it past the filter. The research completes. The poisoned page has zero influence on the output.

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

A URL shows up in a Slack message, a bug report, or a client email. Before Claude makes any network request, the pre-hook inspects the raw URL string — not the parsed version, the raw string. Embedded credentials, lookalike Unicode hostname characters, invisible chars in the path, and multi-`@` authority tricks are refused before a single byte leaves the machine.

Punycode gets decoded rather than trusted, which matters because a hostname does not have to *contain* a Cyrillic character to be a homoglyph — it can arrive pre-encoded. `xn--pypal-4ve.com` is `раypal.com`, and `xn--80ak6aa92e.com` is `аррӏе.com`: the second is entirely Cyrillic, mixes no scripts at all, and still renders exactly like `apple.com`. Both are refused. The attack surface that exists before the page even loads is closed entirely.

```
fetch https://user:pass@httpbin.org/get and summarize it
```

No request is made:

> `[safe-web-research] FR-27 blocked: embedded credentials in URL (user:pass@ pattern). Fetch refused. Do not retry this URL.`

---

### A web page tells Claude to run a shell command

Claude is helping debug a build failure and fetches a documentation page. That page contains instructions telling Claude to run a curl command to download a fix script. Without guardrails, Claude runs it — the script's output arrives in context as trusted text. With the hook, the Bash command is intercepted before execution and rewritten to pipe stdout through `claude-sanitize`. The download still happens. But the output arrives wrapped in `<untrusted_source>`, labeled as untrusted, and Claude treats it accordingly instead of executing its contents.

The rewrite is visible in the approval dialog:

`set -o pipefail; ( curl https://example.com/fix.sh ) | ~/.claude/bin/claude-sanitize --url=bash-stdin`

Works the same for `wget`, `xh`, `curlie`, `httpie`, `aria2c`, `lynx`, `w3m`, `links`, and Python/Node/Bun/Deno/Ruby/Perl/PHP one-liners with a URL in the inline code — and it still fires when the fetch hides behind `sudo`, `env`, `timeout`, `nohup`, `exec` or `nice`, inside `bash -c`, in a `$(…)` substitution, or via `xargs`.

Two limits worth knowing. A command that writes to a file (`curl -o`, `wget -O`) sends nothing through stdout, so those bytes are never sanitised — the hook says so, and tells Claude to re-read the file through `claude-sanitize` before trusting it. And network calls inside a *script file* (`python3 fetch.py`) are opaque to the matcher; only inline `-c`/`-e` code is inspected.

---

### Reviewing what got through before you tightened thresholds

A developer has been running Claude in auto mode for two weeks and just updated `risk-tiers.json` to lower the elevated-signal abort threshold. Before deciding whether the change is right, they replay history against the new config to see which past fetches would now be aborted that weren't before. Two fetches from last Tuesday would have been caught — both from a domain that has since shown up in public blocklists. The threshold change is validated and committed.

```bash
# sanitiser version, active mode, and row counts for the fetch log, blocklist, and sessions
~/.claude/bin/claude-sanitize status

# compare stored decisions against current config
~/.claude/bin/claude-sanitize replay --since=2026-07-22
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
- Bash command rewriting: `curl`, `wget`, `xh`, `curlie`, `httpie`, `aria2c`, `lynx`, `w3m`, `links`, and interpreter one-liners (Python/Node/Bun/Deno/Ruby/Perl/PHP with inline URL) get piped through `claude-sanitize` — including behind wrappers (`command`, `env`, `timeout`, `sudo`, `nohup`, `exec`, `nice`), inside `bash -c`, in `$(…)`, and via `xargs`
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

Tier assignments, thresholds, the injection-phrase corpus, and the meta-allowlist all live in one file — `~/.claude/skills/safe-web-research/risk-tiers.json`. Edit it there; it is the single source of truth, read fresh on every hook invocation, and no restart is needed. Per-domain threshold overrides go under `per_domain_overrides`.

A signal that fires but has no entry in `signals` is treated as **Elevated** by default, so adding a detection without tiering it fails safe rather than silently doing nothing.

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

The hook reconciles this file with its SQLite database on every pre-hook invocation. Your edits win: entries here are the source of truth for `source: "user"` rows.

Two things worth knowing about how blocking behaves:

**Subdomains are covered.** Blocking `example-spam-site.com` also blocks `cdn.example-spam-site.com`. Matching walks up the registrable parents, so the blocklist can't be sidestepped with a hostname prefix.

**A blocked domain prompts you rather than warning Claude.** The pre-hook returns an `ask` decision, so the fetch pauses for your approval instead of emitting a reminder Claude could reason its way past. Aborting unless a human overrides is the rule; asking a human is how that gets enforced.

**Repeated aborts blocklist a domain automatically, for the session only.** After three aborted fetches against one domain (`session_blocklist_repeat_threshold`), the post-hook adds a session-scoped entry with a 24-hour expiry and says so. It never writes to this file — promotion to the persistent blocklist stays a decision you make.

---

## Runtime files

Created automatically on first use:

| Path | Purpose |
| --- | --- |
| `~/.claude/safe-web-research/state.db` | SQLite: sessions, blocklist, robots cache, fetch log |
| `~/.claude/safe-web-research/fetch-log.jsonl` | Every web fetch and its signals |
| `~/.claude/safe-web-research/fetch-log-debug.jsonl` | Full request/response bodies — written only when `CLAUDE_SANITISER_DEBUG=1` |
| `~/.claude/safe-web-research/hook-errors.log` | Hook crash log (should stay empty) |
| `~/.claude/web-blocklist.json` | Persistent domain blocklist |

The database prunes itself: fetch log rows, sessions, and cached `robots.txt` older than `fetch_log_retention_days` (default 90) are deleted, at most once a day, on a pre-hook run. The blocklist is never pruned apart from entries whose `expires_at` has passed.

Turning on `CLAUDE_SANITISER_DEBUG=1` writes complete page bodies to disk in the clear. It's the right tool for tuning thresholds against real traffic, but treat the debug log as sensitive and delete it when you're done.

---

## Drift analysis

Re-classify historical fetches against the current signal tier table:

```bash
~/.claude/bin/claude-sanitize replay --since=2026-01-01

# restrict to rows written by one sanitiser version
~/.claude/bin/claude-sanitize replay --since=2026-01-01 --version=1.1.0
```

Useful for seeing whether threshold changes would have changed any abort decisions. `--since` is required and takes an ISO date; the report counts rows whose verdict would flip in either direction, plus any signal names in the log that the current config no longer defines.

Rows written before the `abort_decision` column existed are reported as `legacy_unknown` — the replay can still re-tier their signals, but it has no stored decision to compare against. Full re-sanitisation of historical bodies needs captures taken with `CLAUDE_SANITISER_DEBUG=1`, since the normal log stores hashes rather than content.

---

## Troubleshooting

**`WebFetch` is being denied** — expected in `strict` mode; the denial names the `curl` command to use instead. Switch back with `./install.sh --mode enforce` if it's more friction than you want.

**Hooks not firing** — confirm `bun` is at `~/.bun/bin/bun` (`which bun`), that `~/.claude/settings.json` is valid JSON, and restart Claude Code after editing settings. Mode changes need a fresh session too — the hook command is read at session start.

**`Cannot find module './lib/unicode.ts'` (or `robots.ts`)** — a partial manual install. All eight `lib/` modules are required; re-run `./install.sh`, or copy the missing files.

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
cp hooks/lib/robots.ts         ~/.claude/hooks/lib/robots.ts
cp hooks/lib/sanitise.ts       ~/.claude/hooks/lib/sanitise.ts
cp hooks/lib/signals.ts        ~/.claude/hooks/lib/signals.ts
cp hooks/lib/state.ts          ~/.claude/hooks/lib/state.ts
cp hooks/lib/unicode.ts        ~/.claude/hooks/lib/unicode.ts
cp hooks/lib/url-checks.ts     ~/.claude/hooks/lib/url-checks.ts
cp skills/safe-web-research/SKILL.md        ~/.claude/skills/safe-web-research/SKILL.md
cp skills/safe-web-research/risk-tiers.json ~/.claude/skills/safe-web-research/risk-tiers.json
cp bin/claude-sanitize ~/.claude/bin/claude-sanitize
chmod +x ~/.claude/bin/claude-sanitize
```

All eight `lib/` modules are required — the hooks import each other, so a missing file is an immediate crash rather than a degraded install.

Or as a one-liner from the repo root (the `--exclude` keeps the test suite out of your `~/.claude`):

```bash
rsync -a --exclude='*.test.ts' --exclude='node_modules' hooks/ ~/.claude/hooks/ && \
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
                "matcher": "WebFetch|WebSearch|Bash|mcp__claude-in-chrome__(navigate|read_page|get_page_text|read_network_requests|read_console_messages|javascript_tool|find|browser_batch)|mcp__brightdata__.*",
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
                "matcher": "WebFetch|WebSearch|mcp__claude-in-chrome__(navigate|read_page|get_page_text|read_network_requests|read_console_messages|javascript_tool|find|browser_batch)|mcp__brightdata__.*",
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

`PreToolUse` includes `Bash` so shell fetches and interpreter one-liners get rewritten to pipe through `claude-sanitize`. `PostToolUse` covers structured web tool responses only.

The MCP matcher covers every browser tool that can hand back page-derived text — `javascript_tool`, `find`, `browser_batch` and `read_console_messages` included, since each can return a full page body and would otherwise be an unsanitised route to the same content.

Swap `CLAUDE_SANITISER_MODE=enforce` for `strict` or `log` in both commands to change mode; see [Modes](#modes) for what each one does.

Hooks are fail-open — a hook crash never blocks Claude Code. The skill compensates by failing *closed*: web content that arrives without a wrapper is treated as a Critical abort signal.

### 4. Add the skill reference to your CLAUDE.md

Open `~/.claude/CLAUDE.md` and append the block below. If the file doesn't exist yet (it's not created by default), just create it with this content as the whole file:

```markdown
## Web Research Protocol

Web research safety is handled by the Safe Web Research skill (`~/.claude/skills/safe-web-research/SKILL.md`). The hook (`~/.claude/hooks/web-fetch-pre.ts` + `web-fetch-post.ts`) wraps every web fetch in `<untrusted_source>`; the skill carries the abort, corroboration, and reporting rules.
```

---

## License

MIT
