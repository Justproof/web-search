import { describe, expect, test } from "bun:test";
import {
	checkUrlAdversarial,
	inspectUrl,
	isPrivateHost,
	punycodeDecode,
	scanResultUrls,
} from "./url-checks.ts";

describe("punycode decoding", () => {
	test("decodes a known label", () => {
		// xn--80ak6aa92e is the all-Cyrillic homoglyph of "apple"
		expect(punycodeDecode("80ak6aa92e")).toBe("аррӏе");
	});

	test("returns null on malformed input", () => {
		expect(punycodeDecode("!!!!")).toBeNull();
	});
});

describe("FR-27 URL refusals", () => {
	test("refuses embedded credentials", () => {
		expect(checkUrlAdversarial("https://user:pass@example.com/")).toContain(
			"embedded credentials",
		);
	});

	test("refuses multiple @ in authority", () => {
		expect(checkUrlAdversarial("https://a@b@example.com/")).not.toBeNull();
	});

	test("refuses literal non-ASCII hostnames", () => {
		expect(checkUrlAdversarial("https://раypal.com/")).toContain("homoglyph");
	});

	test("refuses PRE-ENCODED punycode homoglyphs", () => {
		// The v1.0 check skipped every xn-- label, so this sailed through.
		expect(checkUrlAdversarial("https://xn--pypal-4ve.com/")).toContain(
			"homoglyph",
		);
	});

	test("refuses whole-script punycode homoglyphs", () => {
		// Entirely Cyrillic, so it mixes no scripts — but it renders as "apple".
		expect(checkUrlAdversarial("https://xn--80ak6aa92e.com/")).toContain(
			"whole-script homoglyph",
		);
	});

	test("allows a legitimate single-script IDN but warns", () => {
		const r = inspectUrl("https://xn--80aswg.xn--p1ai/"); // сайт.рф
		expect(r.refuse).toBeNull();
		expect(r.warnings.join(" ")).toContain("decodes to");
	});

	test("refuses zero-width characters in the host", () => {
		expect(checkUrlAdversarial("https://exa​mple.com/")).toContain("zero-width");
	});

	test("refuses non-web schemes", () => {
		expect(checkUrlAdversarial("file:///etc/passwd")).toContain(
			"non-web URL scheme",
		);
	});

	test("allows an ordinary URL", () => {
		expect(checkUrlAdversarial("https://example.com/a/b?c=1")).toBeNull();
	});
});

describe("private host detection", () => {
	test.each([
		"localhost",
		"127.0.0.1",
		"10.1.2.3",
		"192.168.0.5",
		"172.16.0.1",
		"169.254.169.254",
		"100.64.0.1",
		"2130706433", // decimal 127.0.0.1
		"0x7f000001", // hex 127.0.0.1
		"printer", // no dot -> intranet name
		"db.internal",
		"nas.local",
		"[::1]",
		"[fd00::1]",
	])("treats %s as private", (host) => {
		expect(isPrivateHost(host)).toBe(true);
	});

	test.each(["example.com", "8.8.8.8", "sub.domain.co.uk", "[2606:4700::1]"])(
		"treats %s as public",
		(host) => {
			expect(isPrivateHost(host)).toBe(false);
		},
	);

	test("private targets warn rather than refuse", () => {
		const r = inspectUrl("http://localhost:3000/health");
		expect(r.refuse).toBeNull();
		expect(r.warnings.join(" ")).toContain("private");
	});
});

describe("FR-31 search result scanning", () => {
	test("flags blocklisted domains and suspicious URLs", () => {
		const body = `
      Result 1: https://good.example/article
      Result 2: https://bad.example/page
      Result 3: https://xn--pypal-4ve.com/login
    `;
		const scan = scanResultUrls(body, (d) =>
			d === "bad.example" ? { reason: "test", source: "user" } : null,
		);
		expect(scan.blockedDomains.map((b) => b.domain)).toEqual(["bad.example"]);
		expect(scan.suspiciousUrls).toHaveLength(1);
		expect(scan.suspiciousUrls[0]!.url).toContain("xn--pypal");
	});

	test("caps the scan and reports truncation", () => {
		const body = Array.from(
			{ length: 60 },
			(_, i) => `https://example.com/${i}`,
		).join(" ");
		const scan = scanResultUrls(body, () => null);
		expect(scan.truncated).toBe(true);
		expect(scan.scannedUrls).toBe(50);
	});
});
