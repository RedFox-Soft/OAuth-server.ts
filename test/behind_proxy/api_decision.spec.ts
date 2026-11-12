import { describe, expect, it } from 'bun:test';
import fc from 'fast-check';

import {
	decideApiCall,
	type ApiCallFacts,
	type ApiDecision,
	type ApiView
} from 'lib/behind_proxy/api_decision.ts';
import {
	decideAccess,
	type Condition,
	type NetworkFacts
} from 'lib/behind_proxy/conditions.ts';

/**
 * @proves The decision an API checked at the proxy gives one request, as the check and the console's "Check access"
 * both read it (specs/131 data-model §2): the API's own conditions first, then its sign-in requirement, then the MCP
 * headers and the tool's scopes, then the tool's own conditions. A row never lets through a request the API refuses,
 * a request naming a conditioned tool never passes without meeting the tool's conditions, a token without the tool's
 * scope is refused for the scope whatever the conditions, and only the console ever hears "unknown".
 */

/* Monday 16 November 2026, 10:00 UTC. */
const AT = Date.UTC(2026, 10, 16, 10);
const OFFICE = '203.0.113.10';
const ELSEWHERE = '198.51.100.7';

const OPS: Condition = { kind: 'group', groupIds: ['ops'] };
const STAFF: Condition = { kind: 'group', groupIds: ['staff'] };
const FROM_OFFICE: Condition = {
	kind: 'network',
	only: ['203.0.113.0/24'],
	not: []
};
const NOT_TOR: Condition = {
	kind: 'network',
	only: [],
	not: [],
	facts: { categories: ['tor'], outcome: { kind: 'refuse' } }
};
const WORKING_HOURS: Condition = {
	kind: 'time',
	windows: [{ days: [0, 1, 2, 3, 4], start: 540, end: 1080 }]
};

function view(
	rowConditions: Condition[],
	options: {
		api?: Condition[];
		signIn?: ApiView['signIn'];
		otherTools?: 'refuse' | 'token';
		withoutMethod?: 'refuse' | 'token';
		scopes?: string[];
	} = {}
): ApiView {
	return {
		...(options.signIn ? { signIn: options.signIn } : {}),
		tools: {
			rows: [
				{
					name: 'delete_files',
					scopes: options.scopes ?? ['files:write'],
					...(rowConditions.length > 0 ? { conditions: rowConditions } : {})
				},
				{ name: 'search_files', scopes: ['files:read'] }
			],
			otherTools: options.otherTools ?? 'refuse',
			withoutMethod: options.withoutMethod ?? 'refuse',
			access: { conditions: options.api ?? [], timeZone: 'UTC' }
		}
	};
}

function facts(overrides: Partial<ApiCallFacts> = {}): ApiCallFacts {
	return {
		token: {
			scopes: new Set(['files:read', 'files:write']),
			signedInAt: Math.floor(AT / 1000) - 60,
			signedInWithCode: false
		},
		headers: {
			method: 'tools/call',
			name: 'delete_files',
			protocolVersion: '2026-07-28'
		},
		person: { groupIds: ['ops', 'staff'], attributes: {}, canSignIn: true },
		address: OFFICE,
		at: AT,
		explain: false,
		...overrides
	};
}

/* The decision as one comparable line. */
function line(decision: ApiDecision): string {
	switch (decision.outcome) {
		case 'allow':
			return 'allow';
		case 'refuse':
			return `refuse ${decision.reason}`;
		case 'insufficient':
			return `insufficient ${decision.needed.join(' ')}`;
		case 'sign_in':
			return `sign_in${decision.unmet.code ? ' code' : ''}${decision.unmet.recent ? ' recent' : ''}`;
		case 'unknown':
			return `unknown ${decision.kinds.join(' ')}`;
	}
}

const outsider = { groupIds: ['staff'], attributes: {}, canSignIn: true };
const tor: NetworkFacts = { known: true, categories: ['tor'], country: null };

const TABLE: [string, ApiView, ApiCallFacts, string][] = [
	['an Ops member calling the tool', view([OPS]), facts(), 'allow'],
	[
		'someone outside Ops calling the tool',
		view([OPS]),
		facts({ person: outsider }),
		'refuse not_in_group'
	],
	[
		'someone outside Ops calling another tool',
		view([OPS]),
		facts({
			person: outsider,
			headers: {
				method: 'tools/call',
				name: 'search_files',
				protocolVersion: '2026-07-28'
			}
		}),
		'allow'
	],
	[
		'someone outside Ops listing tools',
		view([OPS]),
		facts({
			person: outsider,
			headers: {
				method: 'tools/list',
				name: null,
				protocolVersion: '2026-07-28'
			}
		}),
		'allow'
	],
	[
		"a token without the tool's scope, outside Ops",
		view([OPS]),
		facts({
			person: outsider,
			token: {
				scopes: new Set(['files:read']),
				signedInAt: Math.floor(AT / 1000),
				signedInWithCode: false
			}
		}),
		'insufficient files:write'
	],
	[
		'a token that stands for no person, on a tool with a group',
		view([OPS]),
		facts({ person: null }),
		'refuse no_person'
	],
	[
		'a person who can no longer sign in, on a tool with a group',
		view([OPS]),
		facts({ person: { groupIds: ['ops'], attributes: {}, canSignIn: false } }),
		'refuse cannot_sign_in'
	],
	[
		'a token that stands for no person, on a tool with no person condition',
		view([FROM_OFFICE]),
		facts({ person: null }),
		'allow'
	],
	['a call from the office', view([FROM_OFFICE]), facts(), 'allow'],
	[
		'a call from elsewhere',
		view([FROM_OFFICE]),
		facts({ address: ELSEWHERE }),
		'refuse not_from_network'
	],
	[
		'a call whose address the check did not believe',
		view([FROM_OFFICE]),
		facts({ address: null }),
		'refuse not_from_network'
	],
	[
		'a call kept from Tor with facts not looked up',
		view([NOT_TOR]),
		facts(),
		'refuse network_facts_unknown'
	],
	[
		'a call kept from Tor with facts unknown',
		view([NOT_TOR]),
		facts({ network: { known: false } }),
		'refuse network_facts_unknown'
	],
	[
		'a call from Tor',
		view([NOT_TOR]),
		facts({ network: tor }),
		'refuse not_from_network'
	],
	['a call in working hours', view([WORKING_HOURS]), facts(), 'allow'],
	[
		'a call at 20:00',
		view([WORKING_HOURS]),
		facts({ at: AT + 10 * 3_600_000 }),
		'refuse outside_hours'
	],
	[
		'a row with only a condition and no scope',
		view([OPS], { scopes: [] }),
		facts({
			token: {
				scopes: new Set(),
				signedInAt: Math.floor(AT / 1000),
				signedInWithCode: false
			}
		}),
		'allow'
	],
	[
		'the API limited to Staff and the tool to Ops, a person in Ops only',
		view([OPS], { api: [STAFF] }),
		facts({ person: { groupIds: ['ops'], attributes: {}, canSignIn: true } }),
		'refuse not_in_group'
	],
	[
		'the API limited to Staff and the tool to Ops, a person in both',
		view([OPS], { api: [STAFF] }),
		facts(),
		'allow'
	],
	[
		'an unmet code requirement, before the tool',
		view([OPS], { signIn: { code: true } }),
		facts({ person: outsider }),
		'sign_in code'
	],
	[
		'a sign-in older than the API allows, before the tool',
		view([OPS], { signIn: { code: false, maxAgeSeconds: 3600 } }),
		facts({
			token: {
				scopes: new Set(['files:write']),
				signedInAt: Math.floor(AT / 1000) - 7200,
				signedInWithCode: false
			}
		}),
		'sign_in recent'
	],
	[
		'a token with no sign-in time and a requirement',
		view([], { signIn: { code: true } }),
		facts({
			token: {
				scopes: new Set(['files:write']),
				signedInAt: null,
				signedInWithCode: false
			}
		}),
		'refuse no_person'
	],
	[
		'an app too old to name its tool',
		view([OPS]),
		facts({
			headers: {
				method: 'tools/call',
				name: 'delete_files',
				protocolVersion: '2025-06-18'
			}
		}),
		'refuse old_client'
	],
	[
		'a tool the table does not list, while other tools are refused',
		view([OPS]),
		facts({
			headers: {
				method: 'tools/call',
				name: 'export_billing',
				protocolVersion: '2026-07-28'
			}
		}),
		'refuse tool_not_listed'
	],
	[
		'a tool the table does not list, while other tools need a token',
		view([OPS], { otherTools: 'token' }),
		facts({
			person: outsider,
			headers: {
				method: 'tools/call',
				name: 'export_billing',
				protocolVersion: '2026-07-28'
			}
		}),
		'allow'
	],
	[
		'the console, with no address given for an office tool',
		view([FROM_OFFICE]),
		facts({ address: null, explain: true }),
		'unknown network'
	],
	[
		'the console, with the facts of the address not looked up',
		view([NOT_TOR]),
		facts({ explain: true }),
		'unknown network'
	],
	[
		'the console, with a refusal it can judge and one it cannot',
		view([NOT_TOR, OPS]),
		facts({ explain: true, person: outsider }),
		'refuse not_in_group'
	]
];

describe('what an API checked at the proxy answers one request', () => {
	it.each(TABLE)('%s', (_what, api, given, expected) => {
		expect(line(decideApiCall(api, given))).toBe(expected);
	});
});

const conditionArb = fc.constantFrom<Condition>(
	OPS,
	STAFF,
	FROM_OFFICE,
	NOT_TOR,
	WORKING_HOURS
);
const conditionsArb = fc
	.uniqueArray(conditionArb, { maxLength: 3, selector: (c) => c.kind })
	.map((list) => [...list]);
const factsArb = fc.record({
	groups: fc.subarray(['ops', 'staff']),
	person: fc.boolean(),
	address: fc.constantFrom<string | null>(OFFICE, ELSEWHERE, null),
	network: fc.constantFrom<NetworkFacts | undefined>(
		undefined,
		{ known: false },
		tor,
		{ known: true, categories: [], country: 'DE' }
	),
	hourOffset: fc.integer({ min: 0, max: 23 }),
	scopes: fc.subarray(['files:read', 'files:write']),
	named: fc.constantFrom('delete_files', 'search_files', 'export_billing')
});

type Drawn = typeof factsArb extends fc.Arbitrary<infer T> ? T : never;

function factsFrom(f: Drawn, explain = false): ApiCallFacts {
	return facts({
		person: f.person
			? { groupIds: f.groups, attributes: {}, canSignIn: true }
			: null,
		address: f.address,
		...(f.network ? { network: f.network } : {}),
		at: AT + f.hourOffset * 3_600_000,
		token: {
			scopes: new Set(f.scopes),
			signedInAt: Math.floor(AT / 1000),
			signedInWithCode: false
		},
		headers: {
			method: 'tools/call',
			name: f.named,
			protocolVersion: '2026-07-28'
		},
		explain
	});
}

function refusedBy(
	conditions: readonly Condition[],
	given: ApiCallFacts
): boolean {
	return (
		decideAccess(conditions, {
			address: given.address,
			at: given.at,
			timeZone: 'UTC',
			person: given.person,
			...(given.network ? { network: given.network } : {}),
			explain: false
		}) !== null
	);
}

describe('what a tool row can never do', () => {
	it('never lets through a request the API’s own conditions refuse', () => {
		fc.assert(
			fc.property(conditionsArb, conditionsArb, factsArb, (api, row, f) => {
				const given = factsFrom(f);
				fc.pre(refusedBy(api, given));
				expect(decideApiCall(view(row, { api }), given).outcome).not.toBe(
					'allow'
				);
			})
		);
	});

	it('never lets through a call of a conditioned tool that does not meet its conditions', () => {
		fc.assert(
			fc.property(conditionsArb, factsArb, (row, f) => {
				const given = factsFrom({ ...f, named: 'delete_files' });
				fc.pre(row.length > 0 && refusedBy(row, given));
				expect(decideApiCall(view(row), given).outcome).not.toBe('allow');
			})
		);
	});

	it("answers a token without the tool's scope for the scope, whatever the tool's conditions", () => {
		fc.assert(
			fc.property(conditionsArb, factsArb, (row, f) => {
				const given = factsFrom({
					...f,
					named: 'delete_files',
					scopes: f.scopes.filter((s) => s !== 'files:write')
				});
				expect(decideApiCall(view(row), given).outcome).toBe('insufficient');
			})
		);
	});

	it('answers "unknown" only to the console, never to the check', () => {
		fc.assert(
			fc.property(conditionsArb, conditionsArb, factsArb, (api, row, f) => {
				expect(
					decideApiCall(view(row, { api }), factsFrom(f, false)).outcome
				).not.toBe('unknown');
			})
		);
	});
});
