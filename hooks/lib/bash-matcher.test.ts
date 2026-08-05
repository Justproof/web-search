import { describe, expect, test } from "bun:test";
import { looksLikeFetch, matchBashCommand } from "./bash-matcher.ts";

const bins = (cmd: string) => matchBashCommand(cmd).bins;

describe("direct fetch binaries", () => {
	test.each([
		"curl https://example.com",
		"wget https://example.com",
		"http GET https://example.com",
		"xh https://example.com",
		"lynx -dump https://example.com",
	])("matches %s", (cmd) => {
		expect(matchBashCommand(cmd).matched).toBe(true);
	});

	test("ignores unrelated commands", () => {
		expect(matchBashCommand("ls -la /tmp").matched).toBe(false);
		expect(matchBashCommand("echo curl").matched).toBe(false);
	});
});

describe("wrapper binaries (v1.0 bypasses)", () => {
	test.each([
		"command curl https://example.com",
		"env curl https://example.com",
		"env FOO=bar curl https://example.com",
		"timeout 5 curl https://example.com",
		"timeout 5s curl https://example.com",
		"nohup curl https://example.com",
		"sudo curl https://example.com",
		"exec curl https://example.com",
		"nice -n 10 curl https://example.com",
		"/usr/bin/env curl https://example.com",
	])("no longer bypasses: %s", (cmd) => {
		const m = matchBashCommand(cmd);
		expect(m.matched).toBe(true);
		expect(m.bins).toContain("curl");
	});
});

describe("nested and indirect invocations", () => {
	test("bash -c inner command", () => {
		expect(bins(`bash -c "curl https://example.com"`)).toContain("curl");
	});

	test("command substitution", () => {
		expect(bins("echo $(curl https://example.com)")).toContain("curl");
	});

	test("pipelines and operators", () => {
		expect(bins("curl https://example.com | jq .")).toContain("curl");
		expect(bins("ls && wget https://example.com")).toContain("wget");
	});

	test("xargs", () => {
		expect(bins("cat urls.txt | xargs -n1 curl")).toContain("curl");
	});

	test("interpreter inline code with a URL", () => {
		const m = matchBashCommand(
			`python3 -c "import urllib.request; print(urllib.request.urlopen('https://x.test').read())"`,
		);
		expect(m.matched).toBe(true);
		expect(m.interpreterDetected).toBe(true);
	});

	test("interpreter inline code without a URL is left alone", () => {
		expect(matchBashCommand(`python3 -c "print(1+1)"`).matched).toBe(false);
	});
});

describe("rewrite", () => {
	test("pipes through the sanitiser with pipefail set", () => {
		const m = matchBashCommand("curl https://example.com");
		expect(m.rewrittenCommand).toContain("set -o pipefail");
		expect(m.rewrittenCommand).toContain("claude-sanitize");
		expect(m.rewrittenCommand).toContain("( curl https://example.com )");
	});

	test("flags commands whose bytes go to a file instead of stdout", () => {
		expect(
			matchBashCommand("curl -o page.html https://x.test").writesToFile,
		).toBe(true);
		expect(
			matchBashCommand("wget -O page.html https://x.test").writesToFile,
		).toBe(true);
		expect(matchBashCommand("curl https://x.test").writesToFile).toBe(false);
	});

	test("an apostrophe in a quoted heredoc is not an unbalanced quote", () => {
		// Regression: `git commit <<'MSG' … don't … MSG` was reported as
		// unparseable, so every commit with an apostrophe drew a web-hygiene
		// advisory. Quoted heredoc bodies are literal data, not shell syntax.
		const cmd = "git commit -F - <<'MSG'\ndon't do this\nMSG";
		const m = matchBashCommand(cmd);
		expect(m.parseFailed).toBe(false);
		expect(m.matched).toBe(false);
	});

	test("backticks inside a quoted heredoc are not command substitutions", () => {
		const cmd =
			"git commit -F - <<'MSG'\nmentions `curl -sL https://x.test` in prose\nMSG";
		expect(matchBashCommand(cmd).matched).toBe(false);
	});

	test("an unquoted heredoc still gets scanned — it expands substitutions", () => {
		const cmd = "cat <<EOF\n$(curl https://x.test)\nEOF";
		expect(matchBashCommand(cmd).bins).toContain("curl");
	});

	test("possibleFetch gates the noisy advisory", () => {
		expect(matchBashCommand("git commit -m \"it's fine").possibleFetch).toBe(
			false,
		);
		expect(matchBashCommand(`curl "https://x.test`).possibleFetch).toBe(true);
	});
});

describe("looksLikeFetch", () => {
	test.each([
		["a literal URL anywhere", "deno run --allow-net https://x.test/a.ts"],
		["fetch bin at the start", `curl "$URL`],
		["fetch bin after an operator", `cat f | curl -d @- "$DEST`],
		["fetch bin behind a wrapper", `sudo curl "$URL`],
		["fetch bin with a path prefix", `/usr/bin/curl "$URL`],
	])("fires on %s", (_label, cmd) => {
		expect(looksLikeFetch(cmd)).toBe(true);
	});

	test.each([
		["an interpreter running a script file", "bun run hooks/web-fetch-pre.ts"],
		["node on a local file", "node scripts/build.js"],
		["a bin name mentioned in a message", `git commit -m "see the curl docs"`],
		["a bin name inside an argument", "rg --files-with-matches wget src/"],
		["a word merely containing a bin name", "./curlicue-generator --run"],
		["ordinary work", "ls -la && git status"],
	])("stays quiet on %s", (_label, cmd) => {
		expect(looksLikeFetch(cmd)).toBe(false);
	});

	test("reports unparseable input instead of silently passing", () => {
		const m = matchBashCommand(`curl "https://x.test`);
		expect(m.parseFailed).toBe(true);
		expect(m.rewrittenCommand).toBeNull();
	});
});
