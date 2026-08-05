// robots.txt parsing (FR-3). Advisory only — the hook never blocks on this,
// it reports and the skill decides.
//
// The v1.0 parser understood neither Allow: nor the * / $ wildcards, so
// "Disallow: /*?" was treated as a literal prefix and never matched anything,
// while "Disallow: /" followed by "Allow: /public" over-warned on every path.

export interface RobotsGroup {
	agents: string[];
	allow: string[];
	disallow: string[];
}

export interface RobotsRules {
	// Rules from a group whose User-agent is *
	wildcard: { allow: string[]; disallow: string[] };
	// Rules from groups naming an AI crawler specifically
	aiAgent: { agent: string; allow: string[]; disallow: string[] } | null;
}

// User-agent tokens that identify this agent or AI crawlers generally. A site
// naming any of these is stating a position on AI access specifically, which
// the skill weighs more heavily than a generic wildcard rule.
export const AI_USER_AGENTS = new Set([
	"claudebot",
	"claude-web",
	"claude-searchbot",
	"anthropic-ai",
	"gptbot",
	"chatgpt-user",
	"oai-searchbot",
	"ccbot",
	"google-extended",
	"perplexitybot",
	"cohere-ai",
	"bytespider",
	"ai2bot",
	"meta-externalagent",
]);

export const parseRobotsGroups = (robotsTxt: string): RobotsGroup[] => {
	const lines = robotsTxt.split(/\r?\n/);
	const groups: RobotsGroup[] = [];
	let current: RobotsGroup | null = null;
	let lastWasAgent = false;

	for (const rawLine of lines) {
		const line = rawLine.replace(/#.*$/, "").trim();
		if (!line) {
			continue;
		}
		const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
		if (!m) {
			continue;
		}
		const key = m[1]!.toLowerCase();
		const val = m[2]!.trim();

		if (key === "user-agent") {
			// Consecutive User-agent lines share one group; a User-agent after
			// any rule line starts a new one.
			if (!current || !lastWasAgent) {
				current = { agents: [], allow: [], disallow: [] };
				groups.push(current);
			}
			current.agents.push(val.toLowerCase());
			lastWasAgent = true;
			continue;
		}

		if (!current) {
			continue;
		}
		if (key === "disallow") {
			current.disallow.push(val);
			lastWasAgent = false;
		} else if (key === "allow") {
			current.allow.push(val);
			lastWasAgent = false;
		}
	}
	return groups;
};

export const rulesFor = (groups: RobotsGroup[]): RobotsRules => {
	const wildcard = { allow: [] as string[], disallow: [] as string[] };
	let aiAgent: RobotsRules["aiAgent"] = null;

	for (const g of groups) {
		for (const agent of g.agents) {
			if (agent === "*") {
				wildcard.allow.push(...g.allow);
				wildcard.disallow.push(...g.disallow);
			} else if (AI_USER_AGENTS.has(agent)) {
				if (!aiAgent) {
					aiAgent = { agent, allow: [], disallow: [] };
				}
				aiAgent.allow.push(...g.allow);
				aiAgent.disallow.push(...g.disallow);
			}
		}
	}
	return { wildcard, aiAgent };
};

// Path matching per the REP draft: * matches any sequence, $ anchors the end,
// everything else is a literal prefix match.
export const pathMatchesRule = (rule: string, path: string): boolean => {
	if (rule === "") {
		return false;
	}
	if (!rule.includes("*") && !rule.endsWith("$")) {
		return path.startsWith(rule);
	}
	const anchored = rule.endsWith("$");
	const body = anchored ? rule.slice(0, -1) : rule;
	const escaped = body
		.split("*")
		.map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
		.join(".*");
	return new RegExp(`^${escaped}${anchored ? "$" : ""}`).test(path);
};

// Most specific rule wins; Allow wins ties. Matches Google's documented
// precedence, which is the de-facto standard.
export const isPathDisallowed = (
	rules: { allow: string[]; disallow: string[] },
	path: string,
): boolean => {
	let bestAllow = -1;
	let bestDisallow = -1;
	for (const rule of rules.allow) {
		if (pathMatchesRule(rule, path)) {
			bestAllow = Math.max(bestAllow, rule.length);
		}
	}
	for (const rule of rules.disallow) {
		if (rule === "") {
			continue; // "Disallow:" with empty value means allow everything
		}
		if (pathMatchesRule(rule, path)) {
			bestDisallow = Math.max(bestDisallow, rule.length);
		}
	}
	if (bestDisallow < 0) {
		return false;
	}
	return bestDisallow > bestAllow;
};

export interface RobotsVerdict {
	disallowed: boolean;
	// Set when an AI-specific user-agent group is what disallows the path.
	aiAgentRule: string | null;
}

export const evaluateRobots = (
	robotsTxt: string,
	path: string,
): RobotsVerdict => {
	const rules = rulesFor(parseRobotsGroups(robotsTxt));
	if (rules.aiAgent) {
		// An AI-specific group overrides the wildcard group entirely — that is
		// how user-agent matching works: the most specific group applies.
		const disallowed = isPathDisallowed(rules.aiAgent, path);
		return {
			disallowed,
			aiAgentRule: disallowed ? rules.aiAgent.agent : null,
		};
	}
	return {
		disallowed: isPathDisallowed(rules.wildcard, path),
		aiAgentRule: null,
	};
};
