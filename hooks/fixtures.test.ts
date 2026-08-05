// Fixture corpus: runs the real sanitise + signal + tier pipeline over frozen
// snapshots of real pages and over handcrafted adversarial ones.
//
// The unit tests check rules in isolation. This suite exists because the two
// worst bugs this project has had were only visible on real pages: a signal
// that fired on every styled page, and a void element that deleted 98% of an
// article. Both were byte-level regressions that isolated rule tests passed
// straight through.
//
// The retention band is the load-bearing assertion. Content destruction is
// silent — nothing throws, the wrapper looks healthy, the page is just gone.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import {
	ADVERSARIAL,
	type FixtureExpectation,
} from "../fixtures/adversarial.ts";
import { sanitise } from "./lib/sanitise.ts";
import {
	computeSignals,
	computeSimhash,
	loadRiskTiersConfig,
	partitionByTier,
} from "./lib/signals.ts";

const FIXTURE_DIR = join(import.meta.dir, "..", "fixtures");
const CONFIG_PATH = join(
	import.meta.dir,
	"..",
	"skills",
	"safe-web-research",
	"risk-tiers.json",
);

const cfg = loadRiskTiersConfig(CONFIG_PATH);

interface ManifestEntry {
	url: string;
	note: string;
	captured_at: string;
	content_type: string | null;
	raw_bytes: number;
	sha256: string;
}

const manifest: Record<string, ManifestEntry> = JSON.parse(
	readFileSync(join(FIXTURE_DIR, "real", "manifest.json"), "utf8"),
);

const expected: Record<string, FixtureExpectation> = JSON.parse(
	readFileSync(join(FIXTURE_DIR, "expected.json"), "utf8"),
);

const analyse = (body: string, url: string, contentType: string | null) => {
	const r = sanitise(body);
	const domain = (() => {
		try {
			return new URL(url).hostname.toLowerCase();
		} catch {
			return url;
		}
	})();
	const signals = computeSignals({
		url,
		domain,
		body,
		contentTypeHeader: contentType,
		redirectHops: 0,
		zeroWidthCount: r.zeroWidthCount,
		tagCharCount: r.tagCharCount,
		concealedBytes: r.concealedBytes,
		originalBytes: r.originalBytes,
		simhash: computeSimhash(r.sanitised),
		sessionId: null,
		cfg,
	});
	const tiers = partitionByTier(signals.fired, cfg);
	const aborts =
		tiers.critical.length > 0 ||
		tiers.elevated.length >= cfg.thresholds.abort_on_elevated_count;
	return {
		result: r,
		fired: [...signals.fired].sort(),
		verdict: aborts ? "ABORT" : signals.fired.length > 0 ? "Caution" : "Clean",
		retention: r.originalBytes === 0 ? 1 : r.sanitisedBytes / r.originalBytes,
	};
};

const assertExpectation = (
	label: string,
	body: string,
	url: string,
	contentType: string | null,
	exp: FixtureExpectation,
): void => {
	const a = analyse(body, url, contentType);
	const context = `${label}: retention=${a.retention.toFixed(3)} signals=[${a.fired.join(",")}] verdict=${a.verdict}`;

	if (exp.retention) {
		const [lo, hi] = exp.retention;
		expect(
			a.retention,
			`${context} — retention below floor`,
		).toBeGreaterThanOrEqual(lo);
		expect(
			a.retention,
			`${context} — retention above ceiling`,
		).toBeLessThanOrEqual(hi);
	}
	for (const needle of exp.mustContain ?? []) {
		expect(a.result.sanitised, `${context} — missing "${needle}"`).toContain(
			needle,
		);
	}
	for (const needle of exp.mustNotContain ?? []) {
		expect(a.result.sanitised, `${context} — leaked "${needle}"`).not.toContain(
			needle,
		);
	}
	if (exp.signals) {
		expect(a.fired, context).toEqual([...exp.signals].sort());
	}
	if (exp.verdict) {
		expect(a.verdict, context).toBe(exp.verdict);
	}
};

describe("real page corpus", () => {
	const names = Object.keys(manifest);

	test("every captured page has an expectation", () => {
		for (const name of names) {
			expect(
				expected[name],
				`no expectation for fixture ${name}`,
			).toBeDefined();
		}
	});

	for (const name of Object.keys(manifest)) {
		const entry = manifest[name]!;
		test(`${name} (${entry.url})`, () => {
			const raw = gunzipSync(
				readFileSync(join(FIXTURE_DIR, "real", `${name}.gz`)),
			).toString("utf8");
			// The snapshot must be the bytes the manifest claims.
			expect(Buffer.byteLength(raw, "utf8")).toBe(entry.raw_bytes);
			assertExpectation(
				name,
				raw,
				entry.url,
				entry.content_type,
				expected[name]!,
			);
		});
	}
});

describe("adversarial corpus", () => {
	for (const fixture of ADVERSARIAL) {
		test(`${fixture.name} — ${fixture.note}`, () => {
			assertExpectation(
				fixture.name,
				fixture.html,
				"https://fixture.test/page",
				"text/html",
				fixture.expect,
			);
		});
	}
});
