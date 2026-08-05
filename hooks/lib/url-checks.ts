// URL-level adversarial checks (FR-27) shared by the Pre and Post hooks,
// plus the search-result URL scanner (FR-31).

import {
	foldConfusables,
	foldsToPureLatin,
	hasMixedConfusableScripts,
	INVISIBLE_CHARS,
} from "./unicode.ts";

// Non-global copy: .test() on a /g regex is stateful across calls.
export const ZERO_WIDTH_URL_RE = new RegExp(INVISIBLE_CHARS.source, "u");

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

// ---- Punycode ---------------------------------------------------------------
// RFC 3492 decoder. Needed because the v1.0 check skipped any label starting
// with "xn--", which meant an attacker only had to pre-encode the homoglyph:
// "раypal.com" ships as "xn--pypal-4ve.com" and sailed straight through the
// check that existed to stop it.

const PUNY_BASE = 36;
const PUNY_TMIN = 1;
const PUNY_TMAX = 26;
const PUNY_SKEW = 38;
const PUNY_DAMP = 700;
const PUNY_INITIAL_BIAS = 72;
const PUNY_INITIAL_N = 128;

const basicToDigit = (cp: number): number => {
	if (cp >= 0x30 && cp <= 0x39) {
		return cp - 0x30 + 26; // 0-9 -> 26..35
	}
	if (cp >= 0x41 && cp <= 0x5a) {
		return cp - 0x41; // A-Z -> 0..25
	}
	if (cp >= 0x61 && cp <= 0x7a) {
		return cp - 0x61; // a-z -> 0..25
	}
	return PUNY_BASE;
};

const adaptBias = (
	delta: number,
	numPoints: number,
	firstTime: boolean,
): number => {
	let d = firstTime ? Math.floor(delta / PUNY_DAMP) : delta >> 1;
	d += Math.floor(d / numPoints);
	let k = 0;
	while (d > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) >> 1) {
		d = Math.floor(d / (PUNY_BASE - PUNY_TMIN));
		k += PUNY_BASE;
	}
	return k + Math.floor(((PUNY_BASE - PUNY_TMIN + 1) * d) / (d + PUNY_SKEW));
};

// Decodes the part after the "xn--" prefix. Returns null on malformed input —
// callers treat that as its own suspicious condition.
export const punycodeDecode = (encoded: string): string | null => {
	const output: number[] = [];
	let n = PUNY_INITIAL_N;
	let i = 0;
	let bias = PUNY_INITIAL_BIAS;

	const delim = encoded.lastIndexOf("-");
	if (delim > 0) {
		for (let j = 0; j < delim; j++) {
			const cp = encoded.charCodeAt(j);
			if (cp > 0x7f) {
				return null;
			}
			output.push(cp);
		}
	}

	for (let idx = delim > 0 ? delim + 1 : 0; idx < encoded.length; ) {
		const oldi = i;
		let w = 1;
		for (let k = PUNY_BASE; ; k += PUNY_BASE) {
			if (idx >= encoded.length) {
				return null;
			}
			const digit = basicToDigit(encoded.charCodeAt(idx++));
			if (digit >= PUNY_BASE) {
				return null;
			}
			i += digit * w;
			if (i > 0x10ffff * 4) {
				return null;
			}
			const t =
				k <= bias ? PUNY_TMIN : k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias;
			if (digit < t) {
				break;
			}
			w *= PUNY_BASE - t;
		}
		const out = output.length + 1;
		bias = adaptBias(i - oldi, out, oldi === 0);
		n += Math.floor(i / out);
		i %= out;
		if (n > 0x10ffff) {
			return null;
		}
		output.splice(i++, 0, n);
	}

	try {
		return String.fromCodePoint(...output);
	} catch {
		return null;
	}
};

// ---- Private / internal hosts ------------------------------------------------
// The parallel refetch (FR-7) runs on the user's machine with the user's
// network position. Claude Code's own WebFetch cannot reach 192.168.x.x or the
// cloud metadata endpoint; an unguarded local refetch can. Any URL the agent is
// handed would otherwise become a request the user never asked for.

const INTERNAL_SUFFIXES = [
	".local",
	".localhost",
	".internal",
	".intranet",
	".lan",
	".home.arpa",
];

const ipv4ToOctets = (host: string): number[] | null => {
	// Handles dotted-quad plus the decimal / hex / octal forms browsers accept
	// (http://2130706433/ and http://0x7f000001/ are both 127.0.0.1).
	const parts = host.split(".");
	const parseNum = (s: string): number | null => {
		if (/^0[xX][0-9a-fA-F]+$/.test(s)) {
			return Number.parseInt(s, 16);
		}
		if (/^0[0-7]+$/.test(s)) {
			return Number.parseInt(s, 8);
		}
		if (/^\d+$/.test(s)) {
			return Number.parseInt(s, 10);
		}
		return null;
	};
	if (parts.length === 4) {
		const nums = parts.map(parseNum);
		if (nums.some((v) => v === null || v! < 0 || v! > 255)) {
			return null;
		}
		return nums as number[];
	}
	if (parts.length === 1) {
		const v = parseNum(host);
		if (v === null || v < 0 || v > 0xffffffff) {
			return null;
		}
		return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
	}
	return null;
};

export const isPrivateHost = (hostnameRaw: string): boolean => {
	const hostname = hostnameRaw.toLowerCase().replace(/\.$/, "");
	if (!hostname) {
		return true;
	}
	if (hostname === "localhost") {
		return true;
	}
	if (INTERNAL_SUFFIXES.some((s) => hostname.endsWith(s))) {
		return true;
	}

	// IPv6 (URL.hostname keeps the brackets)
	if (hostname.startsWith("[")) {
		const inner = hostname.slice(1, -1);
		if (inner === "::1" || inner === "::" || inner === "0:0:0:0:0:0:0:1") {
			return true;
		}
		// Unique-local fc00::/7 and link-local fe80::/10
		if (
			/^f[cd][0-9a-f]{0,2}:/.test(inner) ||
			/^fe[89ab][0-9a-f]?:/.test(inner)
		) {
			return true;
		}
		// IPv4-mapped ::ffff:127.0.0.1
		const mapped = /::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(inner);
		if (mapped) {
			return isPrivateHost(mapped[1]!);
		}
		return false;
	}

	const octets = ipv4ToOctets(hostname);
	if (octets) {
		const [a, b] = octets as [number, number, number, number];
		if (a === 0 || a === 127) {
			return true; // this-network, loopback
		}
		if (a === 10) {
			return true;
		}
		if (a === 172 && b >= 16 && b <= 31) {
			return true;
		}
		if (a === 192 && b === 168) {
			return true;
		}
		if (a === 169 && b === 254) {
			return true; // link-local, incl. 169.254.169.254 metadata
		}
		if (a === 100 && b >= 64 && b <= 127) {
			return true; // CGNAT
		}
		if (a === 192 && b === 0) {
			return true; // 192.0.0.0/24 IETF protocol assignments
		}
		if (a >= 224) {
			return true; // multicast + reserved
		}
		return false;
	}

	// A bare hostname with no dot is an intranet name, not a public site.
	if (!hostname.includes(".")) {
		return true;
	}
	return false;
};

// ---- URL inspection ----------------------------------------------------------

export interface UrlInspection {
	// Non-null means: do not fetch this URL at all.
	refuse: string | null;
	// Advisory findings — surfaced to the agent, not auto-blocking.
	warnings: string[];
}

export const inspectUrl = (urlStr: string): UrlInspection => {
	const warnings: string[] = [];
	let parsed: URL;
	try {
		parsed = new URL(urlStr);
	} catch {
		return { refuse: null, warnings };
	}

	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		return {
			refuse: `non-web URL scheme "${parsed.protocol}"`,
			warnings,
		};
	}

	// Embedded credentials (phishing / SSRF vector)
	if (parsed.username || parsed.password) {
		return {
			refuse: "embedded credentials in URL (user:pass@ pattern)",
			warnings,
		};
	}

	// Multiple @ in authority — parsers disagree on which part is the host
	const afterScheme = urlStr.slice(urlStr.indexOf("://") + 3);
	const rawAuthority = afterScheme.split(/[/?#]/)[0] ?? "";
	if ((rawAuthority.match(/@/g) ?? []).length > 1) {
		return {
			refuse: "multiple @ characters in URL authority",
			warnings,
		};
	}

	// Zero-width chars in host or path. The host is checked in its RAW form:
	// new URL() punycodes the authority, so by the time it reaches
	// parsed.hostname a smuggled ZWSP has become an xn-- label and the more
	// accurate diagnosis is lost.
	const rawHost = extractRawHost(urlStr);
	if (
		(rawHost !== null && ZERO_WIDTH_URL_RE.test(rawHost)) ||
		ZERO_WIDTH_URL_RE.test(parsed.hostname) ||
		ZERO_WIDTH_URL_RE.test(parsed.pathname)
	) {
		return {
			refuse: "zero-width characters in URL host or path",
			warnings,
		};
	}

	// Non-ASCII in hostname — inspect the raw string before punycode normalisation
	// hides the homoglyph, and decode any xn-- label so a pre-encoded homoglyph
	// gets the same scrutiny as a literal one.
	if (rawHost !== null) {
		for (const label of rawHost.split(".")) {
			if (label.toLowerCase().startsWith("xn--")) {
				const decoded = punycodeDecode(label.slice(4));
				if (decoded === null) {
					return {
						refuse: `malformed punycode label "${label}"`,
						warnings,
					};
				}
				if (hasMixedConfusableScripts(decoded)) {
					return {
						refuse: `punycode label "${label}" decodes to "${decoded}", which mixes Latin with Cyrillic/Greek lookalikes — homoglyph attack`,
						warnings,
					};
				}
				if (foldsToPureLatin(decoded)) {
					return {
						refuse: `punycode label "${label}" decodes to "${decoded}", a whole-script homoglyph that renders as "${foldConfusables(decoded.toLowerCase())}"`,
						warnings,
					};
				}
				warnings.push(
					`internationalised hostname label "${label}" decodes to "${decoded}" — confirm it is the site you intended`,
				);
				continue;
			}
			for (let i = 0; i < label.length; i++) {
				if (label.charCodeAt(i) > 127) {
					return {
						refuse: `non-ASCII characters in hostname label "${label}" — possible homoglyph/IDN attack`,
						warnings,
					};
				}
			}
		}
	}

	// Private / internal targets are not refused here: fetching localhost during
	// local development is legitimate and the agent's own fetch is sandboxed.
	// The refetch path (which runs on the user's machine, unattended) refuses
	// them outright — see refetch.ts.
	if (isPrivateHost(parsed.hostname)) {
		warnings.push(
			`host ${parsed.hostname} is a private, loopback, or link-local address — no parallel refetch will run and the target is not a public source`,
		);
	}

	return { refuse: null, warnings };
};

// FR-27: URL-level adversarial input checks. Returns a reason string if the
// URL should be refused, null if clean. Runs before any bytes are pulled.
export const checkUrlAdversarial = (urlStr: string): string | null =>
	inspectUrl(urlStr).refuse;

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
	lookupBlocked: (domain: string) => { reason: string; source: string } | null,
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
