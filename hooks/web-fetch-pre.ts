#!/usr/bin/env bun
// PreToolUse hook for web-bound tools.
//
// FR-3: robots.txt cache + advisory reminder
// FR-4: Bash command rewriting through claude-sanitize (pipe wrapper)
// FR-5: per-session 2nd-call reminder pointing at safe-web-research skill
// FR-18: fail-open on any internal error (3s budget)

import { matchBashCommand } from "./lib/bash-matcher.ts";
import {
    ensureStateDir,
    ERROR_LOG,
    getRobotsCache,
    incrementSessionCounter,
    isDomainBlocked,
    reconcileBlocklistJson,
    setRobotsCache,
} from "./lib/state.ts";
import { loadRiskTiersConfig } from "./lib/signals.ts";
import { appendFileSync } from "node:fs";

interface PreToolUseInput {
    session_id?: string;
    hook_event_name?: string;
    tool_name?: string;
    tool_input?: Record<string, unknown>;
    cwd?: string;
}

interface HookOutput {
    hookSpecificOutput?: {
        hookEventName: "PreToolUse";
        permissionDecision?: "allow" | "deny" | "ask";
        permissionDecisionReason?: string;
        additionalContext?: string;
        updatedInput?: Record<string, unknown>;
    };
    additionalContext?: string;
    systemMessage?: string;
}

const WEB_TOOL_NAMES = new Set(["WebFetch", "WebSearch"]);

const MCP_WEB_PATTERNS = [
    /^mcp__claude-in-chrome__(navigate|read_page|get_page_text|read_network_requests)$/,
    /^mcp__brightdata__/,
];

const isWebTool = (toolName: string): boolean => {
    if (WEB_TOOL_NAMES.has(toolName)) {
        return true;
    }
    return MCP_WEB_PATTERNS.some((re) => re.test(toolName));
};

const extractDomain = (urlStr: string): string | null => {
    try {
        return new URL(urlStr).hostname.toLowerCase();
    } catch {
        return null;
    }
};

const fetchRobotsTxt = async (
    domain: string,
): Promise<{ body: string | null; status: number | null }> => {
    const url = `https://${domain}/robots.txt`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    try {
        const res = await fetch(url, {
            signal: controller.signal,
            redirect: "follow",
        });
        const body = await res.text();
        return { body, status: res.status };
    } catch {
        return { body: null, status: null };
    } finally {
        clearTimeout(timer);
    }
};

const parseDisallow = (robotsTxt: string): string[] => {
    // Conservative parser: only respects User-agent: * and the explicit AI bots.
    // Returns Disallow paths that apply to the agent.
    const lines = robotsTxt.split(/\r?\n/);
    const groups: { agents: string[]; disallows: string[] }[] = [];
    let current: { agents: string[]; disallows: string[] } | null = null;
    for (const raw of lines) {
        const line = raw.replace(/#.*$/, "").trim();
        if (!line) {
            continue;
        }
        const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
        if (!m) {
            continue;
        }
        const key = m[1]!.toLowerCase();
        const val = m[2]!.trim();
        if (key === "user-agent") {
            if (!current || current.disallows.length > 0) {
                current = { agents: [], disallows: [] };
                groups.push(current);
            }
            current.agents.push(val.toLowerCase());
        } else if (current && key === "disallow") {
            current.disallows.push(val);
        }
    }
    const relevantAgents = new Set([
        "*",
        "claudebot",
        "anthropic-ai",
        "claude-web",
    ]);
    const out: string[] = [];
    for (const g of groups) {
        if (g.agents.some((a) => relevantAgents.has(a))) {
            out.push(...g.disallows);
        }
    }
    return out;
};

const robotsDisallowsPath = (
    disallows: string[],
    pathName: string,
): boolean => {
    for (const rule of disallows) {
        if (rule === "") {
            continue;
        }
        if (rule === "/") {
            return true;
        }
        if (pathName.startsWith(rule)) {
            return true;
        }
    }
    return false;
};

const renderReminder = (lines: string[]): string =>
    `<system-reminder>\n${lines.join("\n")}\n</system-reminder>`;

const ZERO_WIDTH_URL_RE = /[​‌‍⁠᠎﻿]/;

// Extract the raw hostname from the URL string before URL parsing normalises
// Unicode to punycode — homoglyph attacks are invisible after normalisation.
const extractRawHost = (urlStr: string): string | null => {
    const m = /^[a-z][a-z0-9+\-.]*:\/\/([^/?#]*)/i.exec(urlStr);
    if (!m) {
        return null;
    }
    const authority = m[1]!;
    const atIdx = authority.lastIndexOf("@");
    const hostPort = atIdx >= 0 ? authority.slice(atIdx + 1) : authority;
    if (hostPort.startsWith("[")) {
        const end = hostPort.indexOf("]");
        return end >= 0 ? hostPort.slice(0, end + 1) : null;
    }
    return hostPort.split(":")[0] ?? null;
};

// FR-27: URL-level adversarial input checks. Returns a reason string if the
// URL should be refused, null if clean. Runs before any bytes are pulled.
const checkUrlAdversarial = (urlStr: string): string | null => {
    let parsed: URL;
    try {
        parsed = new URL(urlStr);
    } catch {
        return null;
    }

    // Embedded credentials (phishing / SSRF vector)
    if (parsed.username || parsed.password) {
        return "embedded credentials in URL (user:pass@ pattern)";
    }

    // Multiple @ in authority — parsers disagree on which part is the host
    const afterScheme = urlStr.slice(urlStr.indexOf("://") + 3);
    const rawAuthority = afterScheme.split(/[/?#]/)[0] ?? "";
    if ((rawAuthority.match(/@/g) ?? []).length > 1) {
        return "multiple @ characters in URL authority";
    }

    // Zero-width chars in host or path
    if (
        ZERO_WIDTH_URL_RE.test(parsed.hostname) ||
        ZERO_WIDTH_URL_RE.test(parsed.pathname)
    ) {
        return "zero-width characters in URL host or path";
    }

    // Non-ASCII in hostname — inspect the raw string before punycode normalisation
    // hides the homoglyph. Any non-ASCII label without an explicit xn-- prefix is refused.
    const rawHost = extractRawHost(urlStr);
    if (rawHost !== null) {
        for (const label of rawHost.split(".")) {
            if (label.startsWith("xn--")) {
                continue;
            }
            for (let i = 0; i < label.length; i++) {
                if (label.charCodeAt(i) > 127) {
                    return `non-ASCII characters in hostname label "${label}" — possible homoglyph/IDN attack`;
                }
            }
        }
    }

    return null;
};

const handleWebUrlTool = async (
    input: PreToolUseInput,
    url: string,
    cfg: ReturnType<typeof loadRiskTiersConfig>,
): Promise<HookOutput> => {
    const messages: string[] = [];
    const domain = extractDomain(url);
    if (!domain) {
        return {};
    }

    // FR-27: URL-level adversarial checks — deny before any fetch happens.
    const adversarialReason = checkUrlAdversarial(url);
    if (adversarialReason) {
        return {
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "deny",
                permissionDecisionReason: `[safe-web-research] FR-27 blocked: ${adversarialReason}. Fetch refused. Do not retry this URL.`,
            },
        };
    }

    // Per-session counter (FR-5). Subagent fetches share the parent session_id
    // so this counter naturally includes them.
    const sessionId = input.session_id ?? "unknown";
    const callCount = incrementSessionCounter(sessionId);
    if (callCount >= 2) {
        messages.push(
            `[safe-web-research] This is web tool call #${callCount} this session. Load skills/safe-web-research/SKILL.md before continuing — apply hygiene rules, abort criteria, and the <safe_research_summary> emission requirement to every cited source.`,
        );
    }

    // Blocklist check (FR-22.3)
    const blocked = isDomainBlocked(domain);
    if (blocked) {
        messages.push(
            `[safe-web-research] Domain ${domain} is on the ${blocked.source} blocklist (reason: ${blocked.reason}). Per FR-22 the source must be aborted unless the user explicitly overrides.`,
        );
    }

    // robots.txt (FR-3)
    const ttl = cfg.thresholds.robots_cache_ttl_hours;
    let cached = getRobotsCache(domain, ttl);
    if (!cached) {
        const fetched = await fetchRobotsTxt(domain);
        const parsedDisallows = fetched.body ? parseDisallow(fetched.body) : [];
        setRobotsCache({
            domain,
            fetched_at: new Date().toISOString(),
            body: fetched.body,
            parsed_disallow_paths: JSON.stringify(parsedDisallows),
            status_code: fetched.status,
        });
        cached = {
            domain,
            fetched_at: new Date().toISOString(),
            body: fetched.body,
            parsed_disallow_paths: JSON.stringify(parsedDisallows),
            status_code: fetched.status,
        };
    }

    const disallows: string[] = cached.parsed_disallow_paths
        ? (JSON.parse(cached.parsed_disallow_paths) as string[])
        : [];
    let pathName = "/";
    try {
        pathName = new URL(url).pathname;
    } catch {
        /* keep default */
    }
    if (robotsDisallowsPath(disallows, pathName)) {
        messages.push(
            `[safe-web-research] robots.txt for ${domain} disallows ${pathName} for AI agents (or User-agent: *). The hook does not block — you decide whether to proceed. If proceeding, document the choice in your <safe_research_summary>.`,
        );
    }

    if (messages.length === 0) {
        return {};
    }
    return {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            additionalContext: renderReminder(messages),
        },
        additionalContext: renderReminder(messages),
    };
};

const handleBash = (input: PreToolUseInput): HookOutput => {
    const cmd = (input.tool_input?.command as string | undefined) ?? "";
    if (!cmd) {
        return {};
    }
    const m = matchBashCommand(cmd);
    if (!m.matched && !m.parseFailed) {
        return {};
    }
    if (m.parseFailed) {
        return {
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                additionalContext: renderReminder([
                    `[safe-web-research] Bash command could not be parsed by shell-quote AST (${m.reason}). If this command performs web fetches, prefer WebFetch instead — sanitiser cannot wrap unparseable Bash output. Proceeding unwrapped.`,
                ]),
            },
        };
    }
    const sessionId = input.session_id ?? "unknown";
    incrementSessionCounter(sessionId);
    const advisoryMsg = m.interpreterDetected
        ? `[safe-web-research] Detected probable web fetch via ${m.bins.join(", ")} (inline -c/-e code with URL). Rewriting command to pipe stdout through ~/.claude/bin/claude-sanitize. Note: only inline code is intercepted — network calls inside script files are not wrapped by this hook. Apply abort rules from skills/safe-web-research/SKILL.md to the wrapped result.`
        : `[safe-web-research] Detected web fetch via ${m.bins.join(", ")}. Rewriting command to pipe stdout through ~/.claude/bin/claude-sanitize so output is wrapped in <untrusted_source>. Apply abort rules from skills/safe-web-research/SKILL.md to the wrapped result.`;
    return {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            additionalContext: renderReminder([advisoryMsg]),
            updatedInput: { ...input.tool_input, command: m.rewrittenCommand },
        },
    };
};

const main = async (): Promise<void> => {
    ensureStateDir();
    const stdin = await Bun.stdin.text();
    let input: PreToolUseInput = {};
    try {
        input = JSON.parse(stdin) as PreToolUseInput;
    } catch {
        process.exit(0);
    }

    const cfg = loadRiskTiersConfig();
    reconcileBlocklistJson();

    const toolName = input.tool_name ?? "";
    let out: HookOutput = {};

    if (toolName === "Bash") {
        out = handleBash(input);
    } else if (isWebTool(toolName)) {
        const url =
            (input.tool_input?.url as string | undefined) ??
            (input.tool_input?.query as string | undefined) ??
            "";
        if (url && url.startsWith("http")) {
            out = await handleWebUrlTool(input, url, cfg);
        } else if (toolName === "WebSearch") {
            // No URL to robots-check; just bump counter + maybe inject reminder
            const sessionId = input.session_id ?? "unknown";
            const callCount = incrementSessionCounter(sessionId);
            if (callCount >= 2) {
                out = {
                    hookSpecificOutput: {
                        hookEventName: "PreToolUse",
                        additionalContext: renderReminder([
                            `[safe-web-research] Web tool call #${callCount} this session. Load skills/safe-web-research/SKILL.md.`,
                        ]),
                    },
                };
            }
        }
    }

    if (Object.keys(out).length === 0) {
        process.exit(0);
    }
    process.stdout.write(JSON.stringify(out));
    process.exit(0);
};

main().catch((err) => {
    // FR-18: fail open
    try {
        appendFileSync(
            ERROR_LOG,
            `${new Date().toISOString()} pre-hook error: ${(err as Error).stack ?? err}\n`,
        );
    } catch {
        /* swallow */
    }
    process.exit(0);
});
