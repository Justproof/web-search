import { describe, expect, test } from "bun:test";
import { evaluateRobots, isPathDisallowed, pathMatchesRule } from "./robots.ts";

describe("path matching", () => {
	test("plain prefix", () => {
		expect(pathMatchesRule("/admin", "/admin/users")).toBe(true);
		expect(pathMatchesRule("/admin", "/public")).toBe(false);
	});

	test("wildcards", () => {
		// v1.0 treated this as a literal prefix, so it never matched anything.
		expect(pathMatchesRule("/*?", "/search?q=1")).toBe(true);
		expect(pathMatchesRule("/a/*/c", "/a/b/c")).toBe(true);
	});

	test("end anchor", () => {
		expect(pathMatchesRule("/page$", "/page")).toBe(true);
		expect(pathMatchesRule("/page$", "/page/sub")).toBe(false);
	});

	test("empty rule never matches", () => {
		expect(pathMatchesRule("", "/anything")).toBe(false);
	});
});

describe("Allow / Disallow precedence", () => {
	test("more specific Allow beats a broad Disallow", () => {
		const rules = { allow: ["/public/docs"], disallow: ["/"] };
		expect(isPathDisallowed(rules, "/public/docs/a")).toBe(false);
		expect(isPathDisallowed(rules, "/private")).toBe(true);
	});

	test("empty Disallow value means everything is allowed", () => {
		expect(isPathDisallowed({ allow: [], disallow: [""] }, "/x")).toBe(false);
	});
});

describe("group selection", () => {
	test("wildcard group applies when no AI group is present", () => {
		const txt = `User-agent: *\nDisallow: /private`;
		expect(evaluateRobots(txt, "/private/x").disallowed).toBe(true);
		expect(evaluateRobots(txt, "/public").disallowed).toBe(false);
	});

	test("an AI-specific group overrides the wildcard group", () => {
		const txt = `User-agent: *\nDisallow:\n\nUser-agent: ClaudeBot\nDisallow: /`;
		const v = evaluateRobots(txt, "/anything");
		expect(v.disallowed).toBe(true);
		expect(v.aiAgentRule).toBe("claudebot");
	});

	test("consecutive User-agent lines share one rule group", () => {
		const txt = `User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /no-ai`;
		expect(evaluateRobots(txt, "/no-ai/page").disallowed).toBe(true);
		expect(evaluateRobots(txt, "/fine").disallowed).toBe(false);
	});

	test("comments and blank lines are ignored", () => {
		const txt = `# comment\nUser-agent: *\n\n  Disallow: /x  # trailing`;
		expect(evaluateRobots(txt, "/x/y").disallowed).toBe(true);
	});
});
