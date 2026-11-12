import {
	API_ORDER,
	evaluate,
	inOrder,
	judgeNetwork,
	type AccessRefusal,
	type Condition,
	type ConditionKind,
	type Facts,
	type NetworkFacts
} from './conditions.js';
import {
	decideTool,
	decodeMcpName,
	isOldClient,
	type ToolRefusal,
	type ToolRow,
	type ToolsTableView
} from './tools.js';
import {
	requirementUnmet,
	type SignInRule,
	type UnmetRequirement
} from '../resources/sign_in_rule.js';

/*
 * What an API checked at the proxy answers one request, once its token is read (specs/131 research R4): the API's own
 * conditions, its sign-in requirement (specs/130), the MCP headers and the tools table, then the conditions of the
 * one tool row the request names. The check and the console's "Check access" both ask this function, so what the
 * console says is what the check does (AGENTS.md: "The decision is one pure function the console shares").
 *
 * It looks nothing up. Who the person is, where the believed address is and what is known about it are handed in.
 * Imports only pure modules: the console bundles it.
 */

export interface ApiView {
	readonly signIn?: SignInRule;
	/* The tools table, holding the API's own conditions in `access`. */
	readonly tools?: ToolsTableView;
}

export interface ApiPerson {
	readonly groupIds: readonly string[];
	readonly attributes: Readonly<Record<string, string>>;
	/* False when the person is locked, deactivated or otherwise unable to sign in now. */
	readonly canSignIn: boolean;
}

export interface McpHeaders {
	/* `Mcp-Method` as forwarded, or null. */
	readonly method: string | null;
	/* `Mcp-Name` as forwarded (still encoded), or null. */
	readonly name: string | null;
	/* `MCP-Protocol-Version` as forwarded, or null. */
	readonly protocolVersion: string | null;
}

export interface ApiCallFacts {
	readonly token: {
		readonly scopes: ReadonlySet<string>;
		/* Seconds since the epoch, or null for a token no sign-in stands behind. */
		readonly signedInAt: number | null;
		readonly signedInWithCode: boolean;
	};
	readonly headers: McpHeaders;
	/* Null for a token that names nobody of this project. Looked up only when a condition in play needs it. */
	readonly person: ApiPerson | null;
	/* The address the check believed, as text. */
	readonly address: string | null;
	/* Looked up only when a condition in play asks about network facts. */
	readonly network?: NetworkFacts;
	/* Epoch milliseconds. */
	readonly at: number;
	/* The console: an input not given is "unknown" instead of a refusal. Never true at the check. */
	readonly explain: boolean;
}

export type ApiRefusal = AccessRefusal | 'cannot_sign_in' | ToolRefusal;

export type ApiDecision =
	| { outcome: 'allow'; tool: string | null }
	| { outcome: 'refuse'; reason: ApiRefusal; tool: string | null }
	| { outcome: 'insufficient'; needed: readonly string[]; tool: string }
	| { outcome: 'sign_in'; unmet: UnmetRequirement }
	/* Only with `explain`: every condition that could be judged passed, and these could not be. */
	| {
			outcome: 'unknown';
			kinds: readonly ConditionKind[];
			tool: string | null;
	  };

const REFUSAL_OF: Record<ConditionKind, AccessRefusal> = {
	group: 'not_in_group',
	attribute: 'attribute_mismatch',
	network: 'not_from_network',
	time: 'outside_hours',
	/* Never on an API: freshness belongs to an app's session. */
	fresh: 'not_from_network'
};

/*
 * The row a request names, when the table would reach it: a new client's `tools/call` with a readable name the table
 * lists. Anything else judges no row.
 */
function namedRow(
	table: ToolsTableView | undefined,
	headers: McpHeaders
): ToolRow | undefined {
	if (!table || table.rows.length === 0) return undefined;
	if (headers.method !== 'tools/call' || headers.name === null)
		return undefined;
	if (isOldClient(headers.method, headers.protocolVersion)) return undefined;
	const decoded = decodeMcpName(headers.name);
	if (decoded.bad) return undefined;
	return table.rows.find((row) => row.name === decoded.name);
}

/*
 * The conditions a request will be judged on (research R6): the API's own, and the named row's. The check looks up the
 * person and the network facts only when these need them, so a request to a tool without conditions costs what it
 * did before tool rows had any.
 */
export function conditionsInPlay(
	api: ApiView,
	headers: McpHeaders
): Condition[] {
	return [
		...(api.tools?.access?.conditions ?? []),
		...(namedRow(api.tools, headers)?.conditions ?? [])
	];
}

type Judged =
	| { kind: 'pass' }
	| { kind: 'refuse'; reason: AccessRefusal | 'cannot_sign_in' }
	| { kind: 'unknown'; kinds: ConditionKind[] };

/*
 * One set of conditions (the API's, or a row's), in the API order: the person first, since a token that stands for
 * nobody fails every condition about a person, and a person who cannot sign in now fails them too. Judged here
 * rather than by `decideAccess` so that, in the console, a condition whose input was not given is "unknown" and not a
 * refusal; at the check a missing input refuses, exactly as `decideAccess` does.
 */
function judge(
	conditions: readonly Condition[],
	facts: ApiCallFacts,
	timeZone: string | null
): Judged {
	if (conditions.length === 0) return { kind: 'pass' };
	const aboutPerson = conditions.some(
		(c) => c.kind === 'group' || c.kind === 'attribute'
	);
	if (aboutPerson) {
		if (!facts.person) return { kind: 'refuse', reason: 'no_person' };
		if (!facts.person.canSignIn) {
			return { kind: 'refuse', reason: 'cannot_sign_in' };
		}
	}
	const judgedOn: Facts = {
		address: facts.address,
		at: facts.at,
		timeZone,
		person: facts.person
			? {
					groupIds: facts.person.groupIds,
					attributes: facts.person.attributes
				}
			: null,
		...(facts.network ? { network: facts.network } : {}),
		explain: facts.explain
	};
	const unknown: ConditionKind[] = [];
	for (const { condition } of inOrder(
		conditions.map((c) => ({ condition: c })),
		API_ORDER
	)) {
		if (condition.kind === 'network') {
			const judged = judgeNetwork(condition, judgedOn);
			if (judged.result === 'pass') continue;
			if (judged.result === 'unknown' && facts.explain) {
				unknown.push('network');
				continue;
			}
			return {
				kind: 'refuse',
				reason:
					judged.verdict === 'unknown'
						? 'network_facts_unknown'
						: 'not_from_network'
			};
		}
		const result = evaluate(condition, judgedOn);
		if (result === 'pass') continue;
		if (result === 'unknown' && facts.explain) {
			unknown.push(condition.kind);
			continue;
		}
		return { kind: 'refuse', reason: REFUSAL_OF[condition.kind] };
	}
	return unknown.length > 0
		? { kind: 'unknown', kinds: unknown }
		: { kind: 'pass' };
}

/* The tool a request names, for the decision event; null when it names none or none readably. */
function toolNamed(headers: McpHeaders): string | null {
	if (headers.name === null) return null;
	const decoded = decodeMcpName(headers.name);
	return decoded.bad ? null : decoded.name;
}

export function decideApiCall(api: ApiView, facts: ApiCallFacts): ApiDecision {
	const tool = toolNamed(facts.headers);
	const timeZone = api.tools?.access?.timeZone ?? null;
	const unknown: ConditionKind[] = [];

	/* Who may call the API at all (specs/124), before anything a new sign-in could change. */
	const access = judge(api.tools?.access?.conditions ?? [], facts, timeZone);
	/* Refusals before the tools table name no tool in the decision event, as they never have. */
	if (access.kind === 'refuse') {
		return { outcome: 'refuse', reason: access.reason, tool: null };
	}
	if (access.kind === 'unknown') unknown.push(...access.kinds);

	/*
	 * How the person signed in (specs/130 research R6). A token with no sign-in time stands for nobody a sign-in could
	 * fix, so it is refused rather than asked to sign in again: a machine asked that would loop.
	 */
	if (api.signIn) {
		if (facts.token.signedInAt === null) {
			return { outcome: 'refuse', reason: 'no_person', tool: null };
		}
		const unmet = requirementUnmet(
			api.signIn,
			{
				withCode: facts.token.signedInWithCode,
				authTime: facts.token.signedInAt
			},
			Math.floor(facts.at / 1000)
		);
		if (unmet) return { outcome: 'sign_in', unmet };
	}

	/* The tools table (specs/123 research R6): the row's scopes before its conditions (specs/131, S12). */
	const decided = decideTool({
		table: api.tools,
		method: facts.headers.method,
		name: facts.headers.name,
		protocolVersion: facts.headers.protocolVersion,
		scopes: facts.token.scopes
	});
	if (decided.outcome === 'refuse') {
		return { outcome: 'refuse', reason: decided.reason, tool };
	}
	if (decided.outcome === 'insufficient') {
		return {
			outcome: 'insufficient',
			needed: decided.needed,
			tool: decided.row.name
		};
	}

	const row = judge(decided.row?.conditions ?? [], facts, timeZone);
	if (row.kind === 'refuse') {
		return { outcome: 'refuse', reason: row.reason, tool };
	}
	if (row.kind === 'unknown') unknown.push(...row.kinds);

	return unknown.length > 0
		? { outcome: 'unknown', kinds: unknown, tool }
		: { outcome: 'allow', tool };
}
