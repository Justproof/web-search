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
import { isPrivateHost } from "./url-checks.ts";

// This request is made from the user's machine, from inside their network,
// without them asking for it. Anything that would let a fetched URL steer that
// request at an internal target is refused before a socket is opened.
const MAX_REFETCH_BYTES = 8 * 1024 * 1024;

export interface RefetchResult {
	ok: boolean;
	status: number | null;
	body: string | null;
	redirectHops: number;
	contentType: string | null;
	error: string | null;
	durationMs: number;
}

const refused = (
	reason: string,
	redirectHops: number,
	started: number,
): RefetchResult => ({
	ok: false,
	status: null,
	body: null,
	redirectHops,
	contentType: null,
	error: reason,
	durationMs: Date.now() - started,
});

const hostOf = (u: string): string | null => {
	try {
		return new URL(u).hostname;
	} catch {
		return null;
	}
};

const schemeOf = (u: string): string | null => {
	try {
		return new URL(u).protocol;
	} catch {
		return null;
	}
};

// Bounded read: a refetch must never pull an unbounded body into the hook's
// memory just because the origin decided to serve one.
const readCapped = async (res: Response): Promise<string> => {
	const declared = Number.parseInt(res.headers.get("content-length") ?? "", 10);
	if (Number.isFinite(declared) && declared > MAX_REFETCH_BYTES) {
		return "";
	}
	if (!res.body) {
		return "";
	}
	const reader = res.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	while (total < MAX_REFETCH_BYTES) {
		const { done, value } = await reader.read();
		if (done) {
			break;
		}
		if (value) {
			chunks.push(value);
			total += value.byteLength;
		}
	}
	try {
		await reader.cancel();
	} catch {
		/* already closed */
	}
	return new TextDecoder().decode(
		chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks),
	);
};

export const refetch = async (
	url: string,
	timeoutMs = 5000,
): Promise<RefetchResult> => {
	const started = Date.now();
	let redirectHops = 0;

	const initialScheme = schemeOf(url);
	if (initialScheme !== "http:" && initialScheme !== "https:") {
		return refused("refused_scheme", redirectHops, started);
	}
	const initialHost = hostOf(url);
	if (!initialHost || isPrivateHost(initialHost)) {
		return refused("refused_private_host", redirectHops, started);
	}

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
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
					accept:
						"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				},
			});
			if (res.status >= 300 && res.status < 400) {
				const loc = res.headers.get("location");
				if (!loc) {
					break;
				}
				const next = new URL(loc, currentUrl).toString();
				// Re-check every hop: a public URL redirecting to 169.254.169.254
				// is exactly the SSRF shape this guard exists for.
				const nextScheme = schemeOf(next);
				const nextHost = hostOf(next);
				if (nextScheme !== "http:" && nextScheme !== "https:") {
					return refused("refused_redirect_scheme", redirectHops, started);
				}
				if (!nextHost || isPrivateHost(nextHost)) {
					return refused(
						"refused_redirect_to_private_host",
						redirectHops,
						started,
					);
				}
				currentUrl = next;
				redirectHops++;
				continue;
			}
			break;
		}
		if (!res) {
			return refused("no_response", redirectHops, started);
		}
		const contentType = res.headers.get("content-type");
		const body = await readCapped(res);
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
