// Parallel refetch (FR-7). Fetches the same URL from the local machine with
// no auth/cookies and a 5s timeout, then compares simhash to the agent's
// WebFetch result. Divergence past threshold = cloaking_suspected.
//
// Bun's built-in fetch is undici-based, so no extra dep needed.

import {
    computeSimhash,
    hammingDistance,
    type RiskTiersConfig,
} from "./signals.ts";

export interface RefetchResult {
    ok: boolean;
    status: number | null;
    body: string | null;
    redirectHops: number;
    contentType: string | null;
    error: string | null;
    durationMs: number;
}

export const refetch = async (
    url: string,
    timeoutMs = 5000,
): Promise<RefetchResult> => {
    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let redirectHops = 0;
    try {
        let currentUrl = url;
        let res: Response | null = null;
        for (let i = 0; i <= 5; i++) {
            res = await fetch(currentUrl, {
                signal: controller.signal,
                redirect: "manual",
                headers: {
                    "user-agent":
                        "Mozilla/5.0 (claude-sanitiser refetch) Gecko/20100101 Firefox/120.0",
                    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            });
            if (res.status >= 300 && res.status < 400) {
                const loc = res.headers.get("location");
                if (!loc) {
                    break;
                }
                currentUrl = new URL(loc, currentUrl).toString();
                redirectHops++;
                continue;
            }
            break;
        }
        if (!res) {
            return {
                ok: false,
                status: null,
                body: null,
                redirectHops,
                contentType: null,
                error: "no_response",
                durationMs: Date.now() - started,
            };
        }
        const contentType = res.headers.get("content-type");
        const body = await res.text();
        return {
            ok: res.ok,
            status: res.status,
            body,
            redirectHops,
            contentType,
            error: null,
            durationMs: Date.now() - started,
        };
    } catch (err) {
        return {
            ok: false,
            status: null,
            body: null,
            redirectHops,
            contentType: null,
            error: (err as Error).message ?? "fetch_failed",
            durationMs: Date.now() - started,
        };
    } finally {
        clearTimeout(timer);
    }
};

export const shouldSkipRefetch = (
    domain: string,
    cfg: RiskTiersConfig,
): boolean => {
    for (const pat of cfg.refetch_skip_domains) {
        if (pat.startsWith("*.")) {
            const suffix = pat.slice(1);
            if (domain.endsWith(suffix)) {
                return true;
            }
        } else if (pat === domain) {
            return true;
        }
    }
    return false;
};

export const compareForCloaking = (
    agentBody: string,
    refetchBody: string,
    cfg: RiskTiersConfig,
    domain: string,
): {
    suspected: boolean;
    distance: number;
    threshold: number;
    agentHash: string;
    refetchHash: string;
} => {
    const agentHash = computeSimhash(agentBody);
    const refetchHash = computeSimhash(refetchBody);
    const distance = hammingDistance(agentHash, refetchHash);
    const t =
        cfg.per_domain_overrides[domain]?.near_duplicate_hamming_distance ??
        cfg.thresholds.near_duplicate_hamming_distance;
    // Cloaking threshold is intentionally looser than near-duplicate detection:
    // the two responses ought to be nearly identical, so anything beyond
    // (threshold * 2) is divergence worth flagging. Conservative for v1 (R7).
    const cloakingThreshold = t * 2;
    return {
        suspected: distance > cloakingThreshold,
        distance,
        threshold: cloakingThreshold,
        agentHash,
        refetchHash,
    };
};
