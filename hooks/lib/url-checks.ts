// URL-level adversarial checks (FR-27) shared by the Pre and Post hooks,
// plus the search-result URL scanner (FR-31).

export const ZERO_WIDTH_URL_RE = /[​‌‍⁠᠎﻿]/;

// Extract the raw hostname from the URL string before URL parsing normalises
// Unicode to punycode — homoglyph attacks are invisible after normalisation.
export const extractRawHost = (urlStr: string): string | null => {
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
export const checkUrlAdversarial = (urlStr: string): string | null => {
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

// FR-31: scan a WebSearch result blob for URLs whose domain is blocklisted or
// whose URL fails the FR-27 checks. The scan runs over the raw (pre-sanitise)
// body so zero-width and homoglyph payloads are still visible to it.

// Zero-width chars are deliberately NOT excluded from the token: a URL smuggling
// them must match whole so checkUrlAdversarial can see them.
const RESULT_URL_RE = /https?:\/\/[^\s"'<>()[\]{}|\\]+/g;

const MAX_SCANNED_URLS = 50;

export interface BlockedResultDomain {
    domain: string;
    reason: string;
    source: string;
}

export interface SuspiciousResultUrl {
    url: string;
    reason: string;
}

export interface ResultUrlScan {
    blockedDomains: BlockedResultDomain[];
    suspiciousUrls: SuspiciousResultUrl[];
    scannedUrls: number;
    truncated: boolean;
}

export const scanResultUrls = (
    body: string,
    lookupBlocked: (
        domain: string,
    ) => { reason: string; source: string } | null,
): ResultUrlScan => {
    const seen = new Set<string>();
    const blockedByDomain = new Map<string, BlockedResultDomain>();
    const suspiciousUrls: SuspiciousResultUrl[] = [];
    let truncated = false;

    for (const m of body.matchAll(RESULT_URL_RE)) {
        const url = m[0]!;
        if (seen.has(url)) {
            continue;
        }
        if (seen.size >= MAX_SCANNED_URLS) {
            truncated = true;
            break;
        }
        seen.add(url);

        const reason = checkUrlAdversarial(url);
        if (reason) {
            suspiciousUrls.push({ url, reason });
        }

        let domain: string | null = null;
        try {
            domain = new URL(url).hostname.toLowerCase();
        } catch {
            /* unparseable — the FR-27 check above already had its shot */
        }
        if (domain && !blockedByDomain.has(domain)) {
            const blocked = lookupBlocked(domain);
            if (blocked) {
                blockedByDomain.set(domain, {
                    domain,
                    reason: blocked.reason,
                    source: blocked.source,
                });
            }
        }
    }

    return {
        blockedDomains: [...blockedByDomain.values()],
        suspiciousUrls,
        scannedUrls: seen.size,
        truncated,
    };
};
