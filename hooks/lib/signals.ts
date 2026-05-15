// Risk signals (FR-8). Each function returns whether the signal fires.
// Severity tiers and thresholds live in risk-tiers.json.

import { existsSync, readFileSync } from "node:fs";
import { distinctPathsForDomain, recentSessionFetches } from "./state.ts";

export type Tier = "critical" | "elevated";

export interface SignalDefinition {
    tier: Tier;
    description: string;
}

export interface RiskTiersConfig {
    thresholds: {
        oversized_response_bytes: number;
        repeating_substring_ratio_max: number;
        url_cardinality_explosion_count: number;
        url_cardinality_explosion_window_minutes: number;
        zero_width_chars_max: number;
        hidden_content_ratio_max: number;
        redirect_chain_max_hops: number;
        near_duplicate_hamming_distance: number;
        abort_on_elevated_count: number;
        robots_cache_ttl_hours: number;
        session_blocklist_repeat_threshold: number;
        auto_blocklist_ttl_days: number;
    };
    signals: Record<string, SignalDefinition>;
    per_domain_overrides: Record<
        string,
        Partial<RiskTiersConfig["thresholds"]>
    >;
    refetch_skip_domains: string[];
    injection_phrases: string[];
    meta_allowlist?: {
        hosts: string[];
    };
}

const DEFAULT_CONFIG_PATH = `${process.env.HOME}/.claude/skills/safe-web-research/risk-tiers.json`;

let _config: RiskTiersConfig | null = null;

export const loadRiskTiersConfig = (
    path: string = DEFAULT_CONFIG_PATH,
): RiskTiersConfig => {
    if (_config) {
        return _config;
    }
    if (!existsSync(path)) {
        throw new Error(`risk-tiers.json not found at ${path}`);
    }
    _config = JSON.parse(readFileSync(path, "utf8")) as RiskTiersConfig;
    return _config;
};

// Reset the module-level config cache. Call this between tests that load
// different risk-tiers.json fixtures — mirrors closeDb() in state.ts.
export const resetConfigCache = (): void => {
    _config = null;
};

export const thresholdsForDomain = (
    domain: string,
    cfg: RiskTiersConfig,
): RiskTiersConfig["thresholds"] => {
    const override = cfg.per_domain_overrides[domain];
    if (!override) {
        return cfg.thresholds;
    }
    return { ...cfg.thresholds, ...override };
};

export interface SignalContext {
    url: string;
    domain: string;
    body: string;
    contentTypeHeader: string | null;
    redirectHops: number;
    zeroWidthCount: number;
    strippedBytes: number;
    originalBytes: number;
    simhash: string | null;
    sessionId: string | null;
    cfg: RiskTiersConfig;
}

export interface SignalResult {
    fired: string[];
    detail: Record<string, unknown>;
}

export const computeSignals = (ctx: SignalContext): SignalResult => {
    const fired: string[] = [];
    const detail: Record<string, unknown> = {};
    const t = thresholdsForDomain(ctx.domain, ctx.cfg);

    // injection_phrase
    const lowerBody = ctx.body.toLowerCase();
    const matchedPhrase = ctx.cfg.injection_phrases.find((p) =>
        lowerBody.includes(p.toLowerCase()),
    );
    if (matchedPhrase) {
        fired.push("injection_phrase");
        detail.injection_phrase = matchedPhrase;
    }

    // oversized_response
    if (ctx.originalBytes > t.oversized_response_bytes) {
        fired.push("oversized_response");
        detail.oversized_response = ctx.originalBytes;
    }

    // repeating_substring_ratio_high (cheap autocorrelation proxy: longest repeated 16-gram density)
    const repeatRatio = repeatingSubstringRatio(ctx.body);
    detail.repeat_ratio = repeatRatio;
    if (repeatRatio > t.repeating_substring_ratio_max) {
        fired.push("repeating_substring_ratio_high");
    }

    // url_cardinality_explosion
    if (ctx.sessionId) {
        const distinct = distinctPathsForDomain(
            ctx.sessionId,
            ctx.domain,
            t.url_cardinality_explosion_window_minutes,
        );
        detail.distinct_paths_in_window = distinct;
        if (distinct >= t.url_cardinality_explosion_count) {
            fired.push("url_cardinality_explosion");
        }
    }

    // zero_width_chars
    if (ctx.zeroWidthCount > t.zero_width_chars_max) {
        fired.push("zero_width_chars");
        detail.zero_width_count = ctx.zeroWidthCount;
    }

    // hidden_content_ratio_high
    const ratio =
        ctx.originalBytes === 0 ? 0 : ctx.strippedBytes / ctx.originalBytes;
    detail.hidden_content_ratio = ratio;
    if (ratio > t.hidden_content_ratio_max) {
        fired.push("hidden_content_ratio_high");
    }

    // redirect_chain_long
    if (ctx.redirectHops > t.redirect_chain_max_hops) {
        fired.push("redirect_chain_long");
        detail.redirect_hops = ctx.redirectHops;
    }

    // content_type_mismatch
    const sniffedMime = sniffMime(ctx.body);
    if (
        ctx.contentTypeHeader &&
        sniffedMime &&
        !mimeFamilyMatch(ctx.contentTypeHeader, sniffedMime)
    ) {
        fired.push("content_type_mismatch");
        detail.content_type_mismatch = {
            declared: ctx.contentTypeHeader,
            sniffed: sniffedMime,
        };
    }

    // near_duplicate_to_session
    if (ctx.simhash && ctx.sessionId) {
        const recent = recentSessionFetches(
            ctx.sessionId,
            ctx.domain,
            t.url_cardinality_explosion_window_minutes,
        );
        for (const r of recent) {
            if (!r.simhash || r.url === ctx.url) {
                continue;
            }
            const dist = hammingDistance(ctx.simhash, r.simhash);
            if (dist <= t.near_duplicate_hamming_distance) {
                fired.push("near_duplicate_to_session");
                detail.near_duplicate_to = r.url;
                detail.near_duplicate_distance = dist;
                break;
            }
        }
    }

    return { fired, detail };
};

// FR-28: returns true if domain matches a meta-allowlist host or any registrable parent.
// e.g. "www.owasp.org" matches allowlist entry "owasp.org".
export const isMetaAllowlisted = (
    domain: string,
    cfg: RiskTiersConfig,
): boolean => {
    const hosts = cfg.meta_allowlist?.hosts ?? [];
    return hosts.some((h) => domain === h || domain.endsWith("." + h));
};

export const partitionByTier = (
    fired: string[],
    cfg: RiskTiersConfig,
): { critical: string[]; elevated: string[]; unknown: string[] } => {
    const critical: string[] = [];
    const elevated: string[] = [];
    const unknown: string[] = [];
    for (const name of fired) {
        const def = cfg.signals[name];
        if (!def) {
            unknown.push(name);
            continue;
        }
        if (def.tier === "critical") {
            critical.push(name);
        } else {
            elevated.push(name);
        }
    }
    return { critical, elevated, unknown };
};

const repeatingSubstringRatio = (s: string): number => {
    if (s.length < 256) {
        return 0;
    }
    const sample = s.length > 32_768 ? s.slice(0, 32_768) : s;
    const grams = new Map<string, number>();
    const N = 16;
    let total = 0;
    for (let i = 0; i + N <= sample.length; i++) {
        const g = sample.slice(i, i + N);
        grams.set(g, (grams.get(g) ?? 0) + 1);
        total++;
    }
    if (total === 0) {
        return 0;
    }
    let repeats = 0;
    for (const count of grams.values()) {
        if (count > 1) {
            repeats += count - 1;
        }
    }
    return repeats / total;
};

const sniffMime = (body: string): string | null => {
    const head = body.slice(0, 512).trimStart().toLowerCase();
    if (head.startsWith("<!doctype html") || head.startsWith("<html")) {
        return "text/html";
    }
    if (
        head.startsWith("<?xml") ||
        head.startsWith("<rss") ||
        head.startsWith("<feed")
    ) {
        return "application/xml";
    }
    if (head.startsWith("{") || head.startsWith("[")) {
        return "application/json";
    }
    if (head.startsWith("%pdf-")) {
        return "application/pdf";
    }
    return null;
};

const mimeFamilyMatch = (declared: string, sniffed: string): boolean => {
    const dHead = declared.split(";")[0]!.trim().toLowerCase();
    if (dHead === sniffed) {
        return true;
    }
    if (dHead.startsWith("text/") && sniffed === "text/html") {
        return true;
    }
    if (dHead.includes("xml") && sniffed === "application/xml") {
        return true;
    }
    if (dHead.includes("json") && sniffed === "application/json") {
        return true;
    }
    return false;
};

export const computeSimhash = (s: string): string => {
    // 64-bit simhash on shingled tokens. Returns hex string.
    // Ideographic chars (CJK and extensions via \p{Ideographic}) and Japanese
    // syllabaries (Hiragana U+3040-30FF) are tokenised individually — each
    // character carries word-level meaning. Hangul syllables (U+AC00-D7FF)
    // are similarly individual units. All other Unicode letters require 2+
    // characters so single-char ASCII/Latin noise doesn't dominate the hash.
    const tokens =
        s
            .toLowerCase()
            .match(
                /\p{Ideographic}|[぀-ヿ가-퟿]|\p{L}{2,}/gu,
            ) ?? [];
    if (tokens.length === 0) {
        return "0".repeat(16);
    }
    const v = new Array<number>(64).fill(0);
    for (const tok of tokens) {
        const h = fnv64(tok);
        for (let i = 0; i < 64; i++) {
            const bit = (h >> BigInt(i)) & 1n;
            v[i] += bit === 1n ? 1 : -1;
        }
    }
    let out = 0n;
    for (let i = 0; i < 64; i++) {
        if (v[i]! > 0) {
            out |= 1n << BigInt(i);
        }
    }
    return out.toString(16).padStart(16, "0");
};

const FNV_OFFSET = 14695981039346656037n;
const FNV_PRIME = 1099511628211n;
const FNV_MASK = (1n << 64n) - 1n;

const fnv64 = (s: string): bigint => {
    let h = FNV_OFFSET;
    for (let i = 0; i < s.length; i++) {
        h ^= BigInt(s.charCodeAt(i));
        h = (h * FNV_PRIME) & FNV_MASK;
    }
    return h;
};

export const hammingDistance = (a: string, b: string): number => {
    let x = BigInt("0x" + a) ^ BigInt("0x" + b);
    let d = 0;
    while (x !== 0n) {
        x &= x - 1n;
        d++;
    }
    return d;
};
