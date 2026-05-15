// Bash command matcher (FR-2). Parse via shell-quote AST — never regex on
// the raw command string. Detects two categories:
//   1. Dedicated CLI HTTP tools (curl, wget, aria2c, etc.) — confident detection.
//   2. Interpreter inline code (python3 -c "...https://...") — partial detection;
//      script files (python3 script.py) are opaque and not intercepted.

import { parse, quote } from "shell-quote";

// Dedicated CLI HTTP tools — primary purpose is fetching URLs.
const FETCH_BINS = new Set([
    "curl",
    "wget",
    "wget2",
    "http",
    "httpie",
    "aria2c",
    "lynx",
    "w3m",
]);

// Interpreter binaries that can make HTTP requests via -c/-e inline code.
// We only match these when the inline argument contains a URL pattern — we
// cannot intercept network calls inside script files (python3 script.py etc.).
const INTERPRETER_BINS = new Set([
    "python",
    "python3",
    "node",
    "nodejs",
    "ruby",
    "perl",
    "php",
]);

const INLINE_FLAG = new Set(["-c", "-e"]);
const INLINE_URL_RE = /https?:\/\//i;

const SANITIZER_BIN = `${process.env.HOME}/.claude/bin/claude-sanitize`;

export interface BashMatch {
    matched: boolean;
    bins: string[];
    interpreterDetected: boolean;
    rewrittenCommand: string | null;
    parseFailed: boolean;
    reason: string | null;
}

type ParsedToken =
    | string
    | { op: string }
    | { command: string }
    | { pattern: string }
    | { comment: string };

const stripEnvPrefix = (tokens: ParsedToken[]): ParsedToken[] => {
    let i = 0;
    while (i < tokens.length) {
        const t = tokens[i];
        if (typeof t === "string" && /^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
            i++;
            continue;
        }
        break;
    }
    return tokens.slice(i);
};

const containsFetchBin = (
    tokens: ParsedToken[],
): { found: string | null; afterEnv: ParsedToken[] } => {
    const trimmed = stripEnvPrefix(tokens);
    if (trimmed.length === 0) {
        return { found: null, afterEnv: trimmed };
    }
    const head = trimmed[0];
    if (typeof head !== "string") {
        return { found: null, afterEnv: trimmed };
    }
    const basename = head.split("/").pop() ?? head;
    if (FETCH_BINS.has(basename)) {
        return { found: basename, afterEnv: trimmed };
    }
    // xargs invocations: xargs curl, xargs -n1 curl
    if (basename === "xargs") {
        for (let i = 1; i < trimmed.length; i++) {
            const next = trimmed[i];
            if (typeof next !== "string") {
                continue;
            }
            if (next.startsWith("-")) {
                continue;
            }
            const nextBase = next.split("/").pop() ?? next;
            if (FETCH_BINS.has(nextBase)) {
                return { found: nextBase, afterEnv: trimmed };
            }
            break;
        }
    }
    // Interpreter inline-code invocations: python3 -c "...", node -e "...", etc.
    // Only matches when the inline argument contains a URL — we cannot intercept
    // network calls inside script files (python3 script.py is opaque to this hook).
    if (INTERPRETER_BINS.has(basename)) {
        for (let i = 1; i < trimmed.length - 1; i++) {
            const flag = trimmed[i];
            if (typeof flag !== "string" || !INLINE_FLAG.has(flag)) {
                continue;
            }
            const code = trimmed[i + 1];
            if (typeof code === "string" && INLINE_URL_RE.test(code)) {
                return { found: basename, afterEnv: trimmed };
            }
        }
    }
    return { found: null, afterEnv: trimmed };
};

const splitByOperators = (tokens: ParsedToken[]): ParsedToken[][] => {
    const segments: ParsedToken[][] = [];
    let current: ParsedToken[] = [];
    for (const tok of tokens) {
        if (typeof tok === "object" && tok !== null && "op" in tok) {
            if (current.length > 0) {
                segments.push(current);
            }
            current = [];
            continue;
        }
        current.push(tok);
    }
    if (current.length > 0) {
        segments.push(current);
    }
    return segments;
};

const collectFetchBinsFromAst = (tokens: ParsedToken[]): string[] => {
    const bins: string[] = [];
    const segments = splitByOperators(tokens);
    for (const seg of segments) {
        const { found } = containsFetchBin(seg);
        if (found) {
            bins.push(found);
        }
        // Inspect command-substitution payloads recursively: shell-quote represents
        // them as { op: '$()' , … } in some cases, but the simpler representation
        // tokenises the inner string — so also re-parse any string token that looks
        // like it embeds $() / `…`.
        for (const tok of seg) {
            if (
                typeof tok === "string" &&
                (tok.includes("$(") || tok.includes("`"))
            ) {
                const inner = extractCommandSubstitutions(tok);
                for (const sub of inner) {
                    try {
                        const subTokens = parse(sub) as ParsedToken[];
                        bins.push(...collectFetchBinsFromAst(subTokens));
                    } catch {
                        // unparseable substitution — already handled at top level
                    }
                }
            }
        }
    }
    return bins;
};

const extractCommandSubstitutions = (s: string): string[] => {
    const out: string[] = [];
    let i = 0;
    while (i < s.length) {
        if (s[i] === "$" && s[i + 1] === "(") {
            let depth = 1;
            let j = i + 2;
            while (j < s.length && depth > 0) {
                if (s[j] === "(") {
                    depth++;
                } else if (s[j] === ")") {
                    depth--;
                }
                j++;
            }
            if (depth === 0) {
                out.push(s.slice(i + 2, j - 1));
            }
            i = j;
        } else if (s[i] === "`") {
            const j = s.indexOf("`", i + 1);
            if (j === -1) {
                break;
            }
            out.push(s.slice(i + 1, j));
            i = j + 1;
        } else {
            i++;
        }
    }
    return out;
};

export const matchBashCommand = (raw: string): BashMatch => {
    let tokens: ParsedToken[];
    try {
        tokens = parse(raw) as ParsedToken[];
    } catch (err) {
        return {
            matched: false,
            bins: [],
            interpreterDetected: false,
            rewrittenCommand: null,
            parseFailed: true,
            reason: (err as Error).message,
        };
    }

    const bins: string[] = [];

    // Check for `bash -c "…"` / `sh -c "…"` and recurse into the inner command
    if (tokens.length >= 3) {
        const head = typeof tokens[0] === "string" ? tokens[0] : null;
        const flag = typeof tokens[1] === "string" ? tokens[1] : null;
        const inner = typeof tokens[2] === "string" ? tokens[2] : null;
        if (
            head &&
            flag === "-c" &&
            inner &&
            /^(?:bash|sh|zsh|dash)$/.test(head.split("/").pop() ?? head)
        ) {
            try {
                const innerTokens = parse(inner) as ParsedToken[];
                bins.push(...collectFetchBinsFromAst(innerTokens));
            } catch {
                return {
                    matched: false,
                    bins: [],
                    interpreterDetected: false,
                    rewrittenCommand: null,
                    parseFailed: true,
                    reason: "bash -c inner unparseable",
                };
            }
        }
    }

    bins.push(...collectFetchBinsFromAst(tokens));

    const dedup = [...new Set(bins)];
    if (dedup.length === 0) {
        return {
            matched: false,
            bins: [],
            interpreterDetected: false,
            rewrittenCommand: null,
            parseFailed: false,
            reason: null,
        };
    }

    const interpreterDetected = dedup.some((b) => INTERPRETER_BINS.has(b));

    // Conservative rewrite: wrap the whole command with a pipe through claude-sanitize.
    // Subshell containment ensures pipefail / set -e in the parent shell don't
    // change semantics; we deliberately don't try to surgically splice the AST
    // since shell-quote doesn't round-trip lossless across all input shapes.
    // If the command already contains operators we still wrap — sanitiser
    // operates on stdout regardless of upstream complexity.
    const rewritten = `( ${raw} ) | ${quote([SANITIZER_BIN, "--url=bash-stdin"])}`;

    return {
        matched: true,
        bins: dedup,
        interpreterDetected,
        rewrittenCommand: rewritten,
        parseFailed: false,
        reason: null,
    };
};
