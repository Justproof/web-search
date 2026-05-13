// Sanitise — shared core used by the PostToolUse hook AND the
// ~/.claude/bin/claude-sanitize stdin/stdout binary. Single source of truth
// for the strip rules in PRD FR-6 and the wrapper format in FR-9.
//
// No DOM library is used: parsing real-world HTML is a swamp, and the hook
// must run in a 3-second budget (FR-18). The rules below are deliberately
// regex/scanner-based, ordered, and bounded.

import { createHash } from "node:crypto";

export const SANITISER_VERSION = "1.0.0";
export const SANITISER_MAJOR = 1;

export type StripRule =
    | "comments"
    | "hidden"
    | "scripts"
    | "event_handlers"
    | "boilerplate"
    | "zwsp";

export interface SanitiseOptions {
    url?: string;
    fetchedAt?: string;
    contentType?: string;
}

export interface SanitiseResult {
    sanitised: string;
    rulesApplied: StripRule[];
    originalBytes: number;
    sanitisedBytes: number;
    contentSha256: string;
    zeroWidthCount: number;
    strippedBytes: number;
    hiddenContentRatio: number;
    diffSummary: string[];
}

const ZERO_WIDTH_CHARS = /[​‌‍⁠᠎﻿]/g;

const HTML_COMMENT_RE = /<!--[\s\S]*?-->/g;

const SCRIPT_BLOCK_RE = /<script\b[^>]*>[\s\S]*?<\/script\s*>/gi;
const STYLE_BLOCK_RE = /<style\b[^>]*>[\s\S]*?<\/style\s*>/gi;
const IFRAME_BLOCK_RE = /<iframe\b[^>]*>[\s\S]*?<\/iframe\s*>/gi;
const SELF_CLOSING_SCRIPT_RE = /<script\b[^>]*\/?>(?!.*?<\/script\s*>)/gi;
const SELF_CLOSING_IFRAME_RE = /<iframe\b[^>]*\/?>(?!.*?<\/iframe\s*>)/gi;

const EVENT_HANDLER_ATTR_RE = /\s+on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi;
const JS_URI_RE =
    /(href|src|action|formaction)\s*=\s*("javascript:[^"]*"|'javascript:[^']*'|javascript:[^\s>]+)/gi;
const DATA_URI_NON_IMAGE_RE =
    /(href|src|action|formaction)\s*=\s*("data:(?!image\/)[^"]*"|'data:(?!image\/)[^']*'|data:(?!image\/)[^\s>]+)/gi;

const BOILERPLATE_TAGS = [
    "nav",
    "header",
    "footer",
    "noscript",
    "svg",
    "aside",
];

const HIDDEN_TAG_OPEN_RE =
    /<([a-z][a-z0-9]*)\b([^>]*?)\b(?:style\s*=\s*("[^"]*?(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^"]*?"|'[^']*?(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^']*?')|aria-hidden\s*=\s*("true"|'true'))[^>]*>/gi;

const sha256Hex = (s: string): string =>
    createHash("sha256").update(s, "utf8").digest("hex");

const stripBetween = (input: string, openIdx: number, tag: string): string => {
    const closeRe = new RegExp(`</${tag}\\s*>`, "i");
    const remainder = input.slice(openIdx);
    const match = closeRe.exec(remainder);
    if (!match) {
        return input.slice(0, openIdx);
    }
    return (
        input.slice(0, openIdx) +
        input.slice(openIdx + match.index + match[0].length)
    );
};

const stripBoilerplateTags = (
    input: string,
): { out: string; removed: number } => {
    let out = input;
    let removed = 0;
    for (const tag of BOILERPLATE_TAGS) {
        const openRe = new RegExp(`<${tag}\\b[^>]*>`, "gi");
        let safety = 0;
        while (safety++ < 200) {
            openRe.lastIndex = 0;
            const m = openRe.exec(out);
            if (!m) {
                break;
            }
            const before = out.length;
            out = stripBetween(out, m.index, tag);
            const after = out.length;
            if (after === before) {
                break;
            }
            removed += before - after;
        }
    }
    return { out, removed };
};

const stripHiddenElements = (
    input: string,
): { out: string; removed: number } => {
    let out = input;
    let removed = 0;
    let safety = 0;
    while (safety++ < 500) {
        HIDDEN_TAG_OPEN_RE.lastIndex = 0;
        const m = HIDDEN_TAG_OPEN_RE.exec(out);
        if (!m) {
            break;
        }
        const tag = m[1].toLowerCase();
        const before = out.length;
        out = stripBetween(out, m.index, tag);
        const after = out.length;
        if (after === before) {
            break;
        }
        removed += before - after;
    }
    return { out, removed };
};

export const sanitise = (input: string): SanitiseResult => {
    const originalBytes = Buffer.byteLength(input, "utf8");
    const contentSha256 = sha256Hex(input);
    const rulesApplied: StripRule[] = [];
    const diffSummary: string[] = [];
    let working = input;
    let strippedBytes = 0;

    // 1. HTML comments
    let removed = 0;
    working = working.replace(HTML_COMMENT_RE, (m) => {
        removed += Buffer.byteLength(m, "utf8");
        return "";
    });
    if (removed > 0) {
        rulesApplied.push("comments");
        diffSummary.push(`comments: -${removed}B`);
        strippedBytes += removed;
    }

    // 2. Hidden / off-screen / aria-hidden elements
    const hiddenResult = stripHiddenElements(working);
    if (hiddenResult.removed > 0) {
        working = hiddenResult.out;
        rulesApplied.push("hidden");
        diffSummary.push(`hidden: -${hiddenResult.removed}B`);
        strippedBytes += hiddenResult.removed;
    }

    // 3. <script>, <style>, <iframe>
    let blockRemoved = 0;
    for (const re of [
        SCRIPT_BLOCK_RE,
        STYLE_BLOCK_RE,
        IFRAME_BLOCK_RE,
        SELF_CLOSING_SCRIPT_RE,
        SELF_CLOSING_IFRAME_RE,
    ]) {
        working = working.replace(re, (m) => {
            blockRemoved += Buffer.byteLength(m, "utf8");
            return "";
        });
    }
    if (blockRemoved > 0) {
        rulesApplied.push("scripts");
        diffSummary.push(`scripts/style/iframe: -${blockRemoved}B`);
        strippedBytes += blockRemoved;
    }

    // 4. Inline event handlers + javascript:/data: URIs
    let attrRemoved = 0;
    for (const re of [
        EVENT_HANDLER_ATTR_RE,
        JS_URI_RE,
        DATA_URI_NON_IMAGE_RE,
    ]) {
        working = working.replace(re, (m) => {
            attrRemoved += Buffer.byteLength(m, "utf8");
            return "";
        });
    }
    if (attrRemoved > 0) {
        rulesApplied.push("event_handlers");
        diffSummary.push(`event_handlers/js_uris: -${attrRemoved}B`);
        strippedBytes += attrRemoved;
    }

    // 5. Boilerplate chrome — nav, header, footer, noscript, svg, aside
    const boilerplateResult = stripBoilerplateTags(working);
    if (boilerplateResult.removed > 0) {
        working = boilerplateResult.out;
        rulesApplied.push("boilerplate");
        diffSummary.push(`boilerplate: -${boilerplateResult.removed}B`);
        strippedBytes += boilerplateResult.removed;
    }

    // 6. Zero-width Unicode
    const zwspMatches = working.match(ZERO_WIDTH_CHARS);
    const zeroWidthCount = zwspMatches ? zwspMatches.length : 0;
    if (zeroWidthCount > 0) {
        working = working.replace(ZERO_WIDTH_CHARS, "");
        rulesApplied.push("zwsp");
        diffSummary.push(`zwsp: -${zeroWidthCount} chars`);
        strippedBytes += zeroWidthCount * 3;
    }

    const sanitisedBytes = Buffer.byteLength(working, "utf8");
    const hiddenContentRatio =
        originalBytes === 0 ? 0 : strippedBytes / originalBytes;

    return {
        sanitised: working,
        rulesApplied,
        originalBytes,
        sanitisedBytes,
        contentSha256,
        zeroWidthCount,
        strippedBytes,
        hiddenContentRatio,
        diffSummary,
    };
};

export interface WrapOptions {
    url: string;
    fetchedAt?: string;
    riskSignals?: string[];
    result: SanitiseResult;
}

export const wrap = (opts: WrapOptions): string => {
    const fetchedAt = opts.fetchedAt ?? new Date().toISOString();
    const signals = (opts.riskSignals ?? []).join(",");
    const rules = opts.result.rulesApplied.join(",");
    const attrs = [
        `url="${escapeAttr(opts.url)}"`,
        `fetched_at="${fetchedAt}"`,
        `sanitiser_version="${SANITISER_VERSION}"`,
        `rules_applied="${rules}"`,
        `original_bytes="${opts.result.originalBytes}"`,
        `content_sha256="${opts.result.contentSha256}"`,
        `risk_signals="${signals}"`,
    ].join(" ");
    return `<untrusted_source ${attrs}>\n${opts.result.sanitised}\n</untrusted_source>`;
};

const escapeAttr = (s: string): string =>
    s
        .replace(/&/g, "&amp;")
        .replace(/"/g, "&quot;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");

export const isWrapperVersionCompatible = (
    raw: string,
): { compatible: boolean; foundVersion: string | null } => {
    const m = /sanitiser_version\s*=\s*"([^"]+)"/.exec(raw);
    if (!m) {
        return { compatible: false, foundVersion: null };
    }
    const major = Number.parseInt(m[1].split(".")[0]!, 10);
    if (Number.isNaN(major)) {
        return { compatible: false, foundVersion: m[1] };
    }
    return { compatible: major <= SANITISER_MAJOR, foundVersion: m[1] };
};
