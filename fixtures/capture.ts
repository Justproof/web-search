#!/usr/bin/env bun

// Fixture capture — run by hand, never in CI.
//
//   bun run fixtures/capture.ts            # refresh every real fixture
//   bun run fixtures/capture.ts wikipedia  # refresh one
//
// Pages are stored gzipped with a manifest recording the URL, capture date and
// SHA-256 of the raw bytes. The corpus is a frozen snapshot on purpose: the
// test suite must not depend on the live internet, and a page changing under
// us should be a deliberate re-capture, not a silent test failure.
//
// This script fetches with Bun's fetch rather than curl because it needs the
// RAW bytes on disk — sanitised fixtures would defeat the point. It is a script
// file, so the Bash hook does not wrap it (a documented limit of FR-2).

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const DIR = join(import.meta.dir, "real");
const MANIFEST = join(DIR, "manifest.json");

// Chosen for structural diversity, stability, and permissive access.
const SOURCES: { name: string; url: string; note: string }[] = [
	{
		name: "example-com",
		url: "https://example.com/",
		note: "Minimal HTML. Mostly a <style> block — the page that exposed the hidden_content_ratio false positive.",
	},
	{
		name: "wikipedia-article",
		url: "https://en.wikipedia.org/wiki/Robots.txt",
		note: "Large encyclopedia article: heavy nav, many hidden elements, void tags. Exposed the void-element truncation bug.",
	},
	{
		name: "python-docs",
		url: "https://docs.python.org/3/library/urllib.robotparser.html",
		note: "Technical documentation: sidebars, code blocks, cross-reference chrome.",
	},
	{
		name: "iana-page",
		url: "https://www.iana.org/help/example-domains",
		note: "Small institutional HTML page with ordinary site furniture.",
	},
	{
		name: "rfc-plaintext",
		url: "https://www.rfc-editor.org/rfc/rfc9309.txt",
		note: "text/plain. No markup at all — nothing should ever be stripped.",
	},
	{
		name: "json-api",
		url: "https://api.github.com/",
		note: "A JSON API response, to confirm structured non-HTML passes through intact.",
	},
];

const only = process.argv[2];
mkdirSync(DIR, { recursive: true });

const manifest: Record<string, unknown> = existsSync(MANIFEST)
	? JSON.parse(readFileSync(MANIFEST, "utf8"))
	: {};

for (const src of SOURCES) {
	if (only && src.name !== only) {
		continue;
	}
	process.stdout.write(`${src.name.padEnd(20)} ${src.url} ... `);
	try {
		const res = await fetch(src.url, {
			headers: { "user-agent": "safe-web-research fixture capture" },
			signal: AbortSignal.timeout(20_000),
		});
		const body = await res.text();
		writeFileSync(
			join(DIR, `${src.name}.gz`),
			gzipSync(Buffer.from(body, "utf8")),
		);
		manifest[src.name] = {
			url: src.url,
			note: src.note,
			captured_at: new Date().toISOString().slice(0, 10),
			status: res.status,
			content_type: res.headers.get("content-type"),
			raw_bytes: Buffer.byteLength(body, "utf8"),
			sha256: createHash("sha256").update(body, "utf8").digest("hex"),
		};
		console.log(`${res.status}  ${Buffer.byteLength(body, "utf8")} B`);
	} catch (err) {
		console.log(`FAILED: ${(err as Error).message}`);
	}
}

writeFileSync(MANIFEST, JSON.stringify(manifest, null, 4) + "\n");
console.log(`\nmanifest written: ${MANIFEST}`);
