// Invisible / format character handling and normalisation for matching.
//
// Two jobs:
//   1. Enumerate the characters an attacker can use to smuggle text past a
//      human reader and past substring matching (FR-6 zwsp rule, FR-8
//      zero_width_chars / unicode_tag_chars signals).
//   2. Produce the normalised form that injection-phrase matching runs against,
//      so "ig<ZWSP>nore previous instructions" and Cyrillic-homoglyph variants
//      still match the curated corpus.
//
// Every character class below is written with \u escapes on purpose: a literal
// invisible character in source is unreviewable in a diff.

// Unicode tag characters (U+E0000-E007F). These mirror ASCII one-for-one and
// render as nothing everywhere — there is no legitimate use in web content, so
// their presence is treated as a Critical signal rather than a count threshold.
export const UNICODE_TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;

// Bidirectional formatting controls: embeddings, overrides, isolates, marks.
// Legitimate on RTL pages, but also the trojan-source vector — they reorder
// rendered text without changing the underlying bytes.
export const BIDI_CONTROL_CHARS = /[‎‏‪-‮⁦-⁩]/g;

// Everything invisible, in code-point order:
//   U+00AD soft hyphen                     U+034F combining grapheme joiner
//   U+061C Arabic letter mark              U+115F-1160 Hangul fillers
//   U+17B4-17B5 Khmer inherent vowels      U+180B-180E Mongolian selectors/separator
//   U+200B-200F zero-width + LRM/RLM       U+202A-202E bidi embed/override
//   U+2060-2064 word joiner + invisible operators
//   U+2066-206F isolates + deprecated format chars
//   U+3164 Hangul filler                   U+FE00-FE0F variation selectors
//   U+FEFF BOM / zero-width no-break       U+FFA0 halfwidth Hangul filler
//   U+E0000-E01EF tag chars + variation selectors supplement
//
// Deliberately wider than the v1.0 set, which covered only U+200B/C/D, U+2060,
// U+180E and U+FEFF — that set missed the entire ASCII-smuggling channel.
export const INVISIBLE_CHARS = /[­͏؜ᅟᅠ឴឵᠋-᠎​-‏‪-‮⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ]|[\u{E0000}-\u{E01EF}]/gu;

export const countMatches = (s: string, re: RegExp): number => {
	const m = s.match(new RegExp(re.source, re.flags));
	return m ? m.length : 0;
};

// Decode a run of Unicode tag characters back to the ASCII it encodes, so an
// operator reading the log can see what was actually being smuggled.
export const decodeTagChars = (s: string, maxChars = 120): string => {
	const out: string[] = [];
	for (const ch of s) {
		const cp = ch.codePointAt(0)!;
		if (cp >= 0xe0000 && cp <= 0xe007f) {
			out.push(String.fromCharCode(cp - 0xe0000));
			if (out.length >= maxChars) {
				out.push("...");
				break;
			}
		}
	}
	return out.join("");
};

// Confusables that NFKC does not fold: Cyrillic and Greek letters that render
// identically to Latin ones. Scoped to the letters that actually appear in the
// injection corpus and in phishing hostnames — this is a matching aid, not a
// general Unicode confusables table.
const CONFUSABLE_MAP: Record<string, string> = {
	// Cyrillic
	а: "a", // а
	в: "b", // в
	е: "e", // е
	к: "k", // к
	м: "m", // м
	н: "h", // н
	о: "o", // о
	р: "p", // р
	с: "c", // с
	т: "t", // т
	у: "y", // у
	х: "x", // х
	ѕ: "s", // ѕ
	і: "i", // і
	ј: "j", // ј
	ԁ: "d", // ԁ
	ԛ: "q", // ԛ
	ѡ: "w", // ѡ
	ԝ: "w", // ԝ
	ӏ: "l", // ӏ palochka — the letter in the classic аррӏе.com spoof
	һ: "h", // һ
	ѵ: "v", // ѵ
	ԥ: "p", // ԥ
	ә: "e", // ә
	ғ: "f", // ғ
	// Greek
	α: "a", // α
	β: "b", // β
	ε: "e", // ε
	ι: "i", // ι
	κ: "k", // κ
	μ: "u", // μ
	ν: "v", // ν
	ο: "o", // ο
	ρ: "p", // ρ
	σ: "o", // σ
	τ: "t", // τ
	υ: "u", // υ
	χ: "x", // χ
	γ: "y", // γ
};

export const foldConfusables = (s: string): string => {
	let out = "";
	for (const ch of s) {
		out += CONFUSABLE_MAP[ch] ?? ch;
	}
	return out;
};

// True if the string mixes Latin letters with Cyrillic or Greek ones — the
// signature of a homoglyph hostname (paypal.com with a Cyrillic 'a').
export const hasMixedConfusableScripts = (s: string): boolean => {
	const hasLatin = /[a-z]/i.test(s);
	const hasCyrillic = /[Ѐ-ӿԀ-ԯ]/.test(s);
	const hasGreek = /[Ͱ-Ͽ]/.test(s);
	return hasLatin && (hasCyrillic || hasGreek);
};

// True when a non-ASCII string folds to something that reads as a plain Latin
// word — the whole-script confusable case. "аррӏе" is entirely Cyrillic, so it
// mixes no scripts, yet it renders identically to "apple"; a mixed-script check
// alone misses the best-known homoglyph attack there is.
export const foldsToPureLatin = (s: string): boolean => {
	if (!/[^\u0000-\u007F]/.test(s)) {
		return false; // already ASCII — nothing was disguised
	}
	const folded = foldConfusables(s.toLowerCase());
	return /^[a-z0-9-]+$/.test(folded);
};

// The form injection_phrase matching runs against. Removing invisibles first is
// the load-bearing step: a single ZWSP inside a phrase used to defeat the
// substring match while staying under the zero_width_chars count threshold.
export const normaliseForMatching = (s: string): string =>
	foldConfusables(
		s.replace(INVISIBLE_CHARS, "").normalize("NFKC").toLowerCase(),
	).replace(/\s+/g, " ");
