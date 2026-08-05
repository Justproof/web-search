// Bash command matcher (FR-2). Parse via shell-quote AST — never regex on
// the raw command string. Detects two categories:
//   1. Dedicated CLI HTTP tools (curl, wget, aria2c, etc.) — confident detection.
//   2. Interpreter inline code (python3 -c "...https://...") — partial detection;
//      script files (python3 script.py) are opaque and not intercepted.

import { parse, quote } from "shell-quote";

// Dedicated CLI HTTP tools — primary purpose is fetching URLs.
const FETCH_BINS = new Set([
	"curl",
	"curlie",
	"wget",
	"wget2",
	"http",
	"https",
	"httpie",
	"xh",
	"aria2c",
	"lynx",
	"w3m",
	"links",
	"elinks",
]);

// Wrappers that take another command as their argument. Without this the
// matcher only ever inspected token 0, so `command curl …`, `env curl …`,
// `timeout 5 curl …`, `sudo curl …` and friends all bypassed the sanitiser.
const WRAPPER_BINS = new Set([
	"command",
	"builtin",
	"env",
	"exec",
	"nohup",
	"sudo",
	"doas",
	"timeout",
	"nice",
	"ionice",
	"stdbuf",
	"caffeinate",
	"setsid",
	"unbuffer",
	"time",
]);

// Interpreter binaries that can make HTTP requests via -c/-e inline code.
// We only match these when the inline argument contains a URL pattern — we
// cannot intercept network calls inside script files (python3 script.py etc.).
const INTERPRETER_BINS = new Set([
	"python",
	"python3",
	"node",
	"nodejs",
	"bun",
	"deno",
	"ruby",
	"perl",
	"php",
]);

const INLINE_FLAG = new Set(["-c", "-e", "--eval", "-E"]);
const INLINE_URL_RE = /https?:\/\//i;

// Flags that send the response to a file instead of stdout. Piping stdout
// through the sanitiser does nothing for these — the bytes land on disk raw.
const OUTPUT_TO_FILE_FLAGS = new Set([
	"-o",
	"-O",
	"--output",
	"--output-document",
	"--remote-name",
	"-P",
	"--directory-prefix",
	"--create-dirs",
]);

const SANITIZER_BIN = `${process.env.HOME}/.claude/bin/claude-sanitize`;

export interface BashMatch {
	matched: boolean;
	bins: string[];
	interpreterDetected: boolean;
	writesToFile: boolean;
	// True when the command mentions a URL or a fetch/interpreter binary at all.
	// Callers use it to decide whether an unparseable command is worth
	// mentioning: on `git commit`, it never is.
	possibleFetch: boolean;
	rewrittenCommand: string | null;
	parseFailed: boolean;
	reason: string | null;
}

type ParsedToken =
	| string
	| { op: string }
	| { command: string }
	| { pattern: string }
	| { comment: string };

const asString = (t: ParsedToken | undefined): string | null =>
	typeof t === "string" ? t : null;

const basenameOf = (s: string): string => s.split("/").pop() ?? s;

const isEnvAssignment = (s: string): boolean =>
	/^[A-Za-z_][A-Za-z0-9_]*=/.test(s);

// Duration arguments to `timeout` (5, 5s, 1m, 0.5) — skipped so the real
// command head can be reached.
const isDurationArg = (s: string): boolean => /^\d+(\.\d+)?[smhd]?$/.test(s);

// Walk past env assignments and command wrappers to the token that is actually
// the command being run.
const resolveCommandHead = (
	tokens: ParsedToken[],
): { head: string | null; rest: ParsedToken[] } => {
	let i = 0;
	let consumedWrapper = false;
	while (i < tokens.length) {
		const tok = asString(tokens[i]);
		if (tok === null) {
			return { head: null, rest: tokens.slice(i) };
		}
		if (isEnvAssignment(tok)) {
			i++;
			continue;
		}
		const base = basenameOf(tok);
		if (WRAPPER_BINS.has(base)) {
			consumedWrapper = true;
			i++;
			continue;
		}
		if (consumedWrapper && (tok.startsWith("-") || isDurationArg(tok))) {
			i++;
			continue;
		}
		return { head: base, rest: tokens.slice(i) };
	}
	return { head: null, rest: [] };
};

const containsFetchBin = (tokens: ParsedToken[]): string | null => {
	const { head, rest } = resolveCommandHead(tokens);
	if (head === null) {
		return null;
	}
	if (FETCH_BINS.has(head)) {
		return head;
	}
	// xargs invocations: xargs curl, xargs -n1 curl
	if (head === "xargs") {
		for (let i = 1; i < rest.length; i++) {
			const next = asString(rest[i]);
			if (next === null) {
				continue;
			}
			if (next.startsWith("-")) {
				continue;
			}
			const nextBase = basenameOf(next);
			if (FETCH_BINS.has(nextBase)) {
				return nextBase;
			}
			break;
		}
	}
	// Interpreter inline-code invocations: python3 -c "...", node -e "...", etc.
	// Only matches when the inline argument contains a URL — we cannot intercept
	// network calls inside script files (python3 script.py is opaque to this hook).
	if (INTERPRETER_BINS.has(head)) {
		for (let i = 1; i < rest.length - 1; i++) {
			const flag = asString(rest[i]);
			if (flag === null || !INLINE_FLAG.has(flag)) {
				continue;
			}
			const code = asString(rest[i + 1]);
			if (code !== null && INLINE_URL_RE.test(code)) {
				return head;
			}
		}
	}
	return null;
};

const segmentWritesToFile = (tokens: ParsedToken[]): boolean =>
	tokens.some((t) => {
		const s = asString(t);
		return s !== null && OUTPUT_TO_FILE_FLAGS.has(s);
	});

const splitByOperators = (tokens: ParsedToken[]): ParsedToken[][] => {
	const segments: ParsedToken[][] = [];
	let current: ParsedToken[] = [];
	for (const tok of tokens) {
		if (typeof tok === "object" && tok !== null && "op" in tok) {
			if (current.length > 0) {
				segments.push(current);
			}
			current = [];
			continue;
		}
		current.push(tok);
	}
	if (current.length > 0) {
		segments.push(current);
	}
	return segments;
};

interface AstScan {
	bins: string[];
	writesToFile: boolean;
}

const collectFetchBinsFromAst = (tokens: ParsedToken[]): AstScan => {
	const bins: string[] = [];
	let writesToFile = false;
	const segments = splitByOperators(tokens);
	for (const seg of segments) {
		const found = containsFetchBin(seg);
		if (found) {
			bins.push(found);
			if (segmentWritesToFile(seg)) {
				writesToFile = true;
			}
		}
		// Inspect command-substitution payloads recursively: shell-quote represents
		// them as { op: '$()' , … } in some cases, but the simpler representation
		// tokenises the inner string — so also re-parse any string token that looks
		// like it embeds $() / `…`.
		for (const tok of seg) {
			if (
				typeof tok === "string" &&
				(tok.includes("$(") || tok.includes("`"))
			) {
				const inner = extractCommandSubstitutions(tok);
				for (const sub of inner) {
					try {
						const subTokens = parse(sub) as ParsedToken[];
						const scan = collectFetchBinsFromAst(subTokens);
						bins.push(...scan.bins);
						writesToFile ||= scan.writesToFile;
					} catch {
						// unparseable substitution — already handled at top level
					}
				}
			}
		}
	}
	return { bins, writesToFile };
};

const extractCommandSubstitutions = (s: string): string[] => {
	const out: string[] = [];
	let i = 0;
	while (i < s.length) {
		if (s[i] === "$" && s[i + 1] === "(") {
			let depth = 1;
			let j = i + 2;
			while (j < s.length && depth > 0) {
				if (s[j] === "(") {
					depth++;
				} else if (s[j] === ")") {
					depth--;
				}
				j++;
			}
			if (depth === 0) {
				out.push(s.slice(i + 2, j - 1));
			}
			i = j;
		} else if (s[i] === "`") {
			const j = s.indexOf("`", i + 1);
			if (j === -1) {
				break;
			}
			out.push(s.slice(i + 1, j));
			i = j + 1;
		} else {
			i++;
		}
	}
	return out;
};

// Remove the bodies of quoted heredocs (<<'EOF' / <<"EOF"), which the shell
// treats as literal data: no quote pairing, no expansion, no command inside.
// Counting their contents as shell syntax made every `git commit <<'MSG'`
// whose message contained an apostrophe look like an unterminated quote.
//
// Unquoted heredocs (<<EOF) are deliberately left in place — those DO expand
// $(…), so a fetch hidden in one is a real command the matcher must still see.
export const stripQuotedHeredocBodies = (raw: string): string => {
	const opener = /<<-?\s*(['"])([A-Za-z_][A-Za-z0-9_]*)\1/g;
	let out = "";
	let cursor = 0;
	let m: RegExpExecArray | null;
	while ((m = opener.exec(raw)) !== null) {
		const delimiter = m[2]!;
		const lineEnd = raw.indexOf("\n", m.index + m[0].length);
		if (lineEnd === -1) {
			break; // opener with no body yet — nothing to strip
		}
		// Terminator: a line containing only the delimiter (leading whitespace
		// allowed, since <<- strips tabs).
		const terminator = new RegExp(`^[ \\t]*${delimiter}[ \\t]*$`, "m");
		const rest = raw.slice(lineEnd + 1);
		const t = terminator.exec(rest);
		const bodyEnd =
			t === null ? raw.length : lineEnd + 1 + t.index + t[0].length;
		out += raw.slice(cursor, lineEnd + 1);
		cursor = bodyEnd;
		opener.lastIndex = bodyEnd;
	}
	return out + raw.slice(cursor);
};

// Cheap pre-check: does this command plausibly touch the network at all? Used
// to keep the unparseable-command advisory off the ~99% of Bash calls that
// have nothing to do with fetching, where it is pure noise.
//
// A URL scheme is the primary trigger. The first version also matched any
// fetch or interpreter binary appearing anywhere in the string, which meant
// `bun run x.ts` and a commit message mentioning curl both tripped it.
//
// Requiring a URL and nothing else would be too tight in one specific way:
// `curl "$URL` — unparseable, genuinely a fetch, no literal scheme — would go
// unmentioned, and an unwrappable fetch is exactly what the advisory exists to
// flag. So a fetch binary still counts, but only in COMMAND position: at the
// start, after a shell operator, or directly behind a wrapper like sudo/env.
// A bare mention inside an argument or a message no longer qualifies.
const COMMAND_POSITION_FETCH_RE = new RegExp(
	`(?:^|[\\n;&|(]|\\b(?:${[...WRAPPER_BINS].join("|")})\\s+)\\s*(?:[\\w./-]*/)?(?:${[...FETCH_BINS].join("|")})(?:\\s|$)`,
	"i",
);

export const looksLikeFetch = (raw: string): boolean =>
	/\bhttps?:\/\//i.test(raw) || COMMAND_POSITION_FETCH_RE.test(raw);

// shell-quote parses an unterminated quote without complaining, but wrapping
// such a command in `( … ) | sanitiser` changes what the shell actually runs —
// the trailing paren and pipe get swallowed by the open quote. Detect it and
// decline to rewrite rather than emit a command that means something else.
export const hasUnbalancedQuotes = (raw: string): boolean => {
	let inSingle = false;
	let inDouble = false;
	for (let i = 0; i < raw.length; i++) {
		const c = raw[i];
		if (c === "\\" && !inSingle) {
			i++;
			continue;
		}
		if (c === "'" && !inDouble) {
			inSingle = !inSingle;
		} else if (c === '"' && !inSingle) {
			inDouble = !inDouble;
		}
	}
	return inSingle || inDouble;
};

export const matchBashCommand = (raw: string): BashMatch => {
	// Heredoc bodies with quoted delimiters are literal data. Analysing them as
	// shell syntax produced both false "unbalanced quotes" verdicts and phantom
	// command substitutions from backticks inside prose.
	const analysed = stripQuotedHeredocBodies(raw);
	const possibleFetch = looksLikeFetch(analysed);

	if (hasUnbalancedQuotes(analysed)) {
		return {
			matched: false,
			bins: [],
			interpreterDetected: false,
			writesToFile: false,
			possibleFetch,
			rewrittenCommand: null,
			parseFailed: true,
			reason:
				"unbalanced quotes — rewriting would change the command's meaning",
		};
	}

	let tokens: ParsedToken[];
	try {
		tokens = parse(analysed) as ParsedToken[];
	} catch (err) {
		return {
			matched: false,
			bins: [],
			interpreterDetected: false,
			writesToFile: false,
			possibleFetch,
			rewrittenCommand: null,
			parseFailed: true,
			reason: (err as Error).message,
		};
	}

	const bins: string[] = [];
	let writesToFile = false;

	// Check for `bash -c "…"` / `sh -c "…"` and recurse into the inner command
	if (tokens.length >= 3) {
		const head = asString(tokens[0]);
		const flag = asString(tokens[1]);
		const inner = asString(tokens[2]);
		if (
			head &&
			flag === "-c" &&
			inner &&
			/^(?:bash|sh|zsh|dash|ksh)$/.test(basenameOf(head))
		) {
			try {
				const innerTokens = parse(inner) as ParsedToken[];
				const scan = collectFetchBinsFromAst(innerTokens);
				bins.push(...scan.bins);
				writesToFile ||= scan.writesToFile;
			} catch {
				return {
					matched: false,
					bins: [],
					interpreterDetected: false,
					writesToFile: false,
					possibleFetch,
					rewrittenCommand: null,
					parseFailed: true,
					reason: "bash -c inner unparseable",
				};
			}
		}
	}

	const topScan = collectFetchBinsFromAst(tokens);
	bins.push(...topScan.bins);
	writesToFile ||= topScan.writesToFile;

	const dedup = [...new Set(bins)];
	if (dedup.length === 0) {
		return {
			matched: false,
			bins: [],
			interpreterDetected: false,
			writesToFile: false,
			possibleFetch,
			rewrittenCommand: null,
			parseFailed: false,
			reason: null,
		};
	}

	const interpreterDetected = dedup.some((b) => INTERPRETER_BINS.has(b));

	// Conservative rewrite: wrap the whole command with a pipe through claude-sanitize.
	// Subshell containment ensures pipefail / set -e in the parent shell don't
	// change semantics; we deliberately don't try to surgically splice the AST
	// since shell-quote doesn't round-trip lossless across all input shapes.
	// pipefail is set inside the subshell so a failed fetch still surfaces as a
	// non-zero exit — without it the sanitiser's own exit code masks the failure.
	const rewritten = `set -o pipefail; ( ${raw} ) | ${quote([SANITIZER_BIN, "--url=bash-stdin"])}`;

	return {
		matched: true,
		bins: dedup,
		interpreterDetected,
		writesToFile,
		possibleFetch,
		rewrittenCommand: rewritten,
		parseFailed: false,
		reason: null,
	};
};
