import { describe, it, expect } from 'bun:test';
import fc from 'fast-check';

import { decide, type PathRule } from 'lib/behind_proxy/decide.ts';
import {
	decideAccess,
	type Condition,
	type NetworkCategory,
	type NetworkFacts,
	type NetworkFactsPart
} from 'lib/behind_proxy/conditions.ts';
import { loosenedConditions } from 'lib/behind_proxy/condition_widening.ts';

/**
 * @proves The evaluation table of specs/129 data-model §8: for every combination of believed address, facts, kept-out
 * categories, countries and outcome, the console's `decide()` reaches the decision the table states; an API refuses
 * on the same facts; and a change the console lists as no looser never lets in an address the old condition refused.
 */

const AT = Date.UTC(2026, 10, 11, 12, 0);
const PUBLIC = '45.10.20.30';
const PRIVATE = '10.1.2.3';

const known = (
	categories: readonly NetworkCategory[],
	country: string | null
): NetworkFacts => ({ known: true, categories, country });
const UNKNOWN: NetworkFacts = { known: false };

function rules(part: NetworkFactsPart): PathRule[] {
	return [
		{
			path: '/',
			who: {
				kind: 'conditional',
				who: { kind: 'project' },
				conditions: [{ kind: 'network', only: [], not: [], facts: part }]
			}
		}
	];
}

const REFUSE = { kind: 'refuse' } as const;
const AGAIN = { kind: 'sign_in_again', maxAgeMinutes: 15 } as const;

function decided(
	part: NetworkFactsPart,
	facts: NetworkFacts | undefined,
	options: { address?: string | null; signedInAgo?: number | null } = {}
) {
	const signedInAgo =
		options.signedInAgo === undefined ? 1 : options.signedInAgo;
	return decide({
		rules: rules(part),
		method: 'GET',
		rawPath: '/',
		person:
			signedInAgo === null
				? null
				: {
						canSignIn: true,
						groupIds: [],
						signedInAt: Math.floor((AT - signedInAgo * 60_000) / 1000)
					},
		address: options.address === undefined ? PUBLIC : options.address,
		...(facts ? { network: facts } : {}),
		at: AT
	});
}

describe('Network facts in "From where", as the decision reads them', () => {
	const torOut: NetworkFactsPart = { categories: ['tor'], outcome: REFUSE };

	it('refuses a kept-out category before any sign-in', () => {
		const d = decided(torOut, known(['tor'], 'DE'), { signedInAgo: null });
		expect([d.outcome, d.reason, d.networkPart]).toEqual([
			'deny',
			'not_from_network',
			'facts'
		]);
	});

	it('lets an address with no record through a kept-out category', () => {
		expect(decided(torOut, known([], null)).outcome).toBe('allow');
	});

	it('closes the path on unknown facts, whatever the outcome', () => {
		for (const outcome of [REFUSE, AGAIN]) {
			const d = decided({ categories: ['tor'], outcome }, UNKNOWN);
			expect([d.outcome, d.reason]).toEqual(['deny', 'network_facts_unknown']);
		}
	});

	it('closes the path when the check looked nothing up for a believed address', () => {
		expect(decided(torOut, undefined).reason).toBe('network_facts_unknown');
	});

	it('refuses as "From where" does when the check believed no address', () => {
		const d = decided(torOut, undefined, { address: null });
		expect([d.outcome, d.reason, d.networkPart]).toEqual([
			'deny',
			'not_from_network',
			'ranges'
		]);
	});

	it('refuses an address with no country under "only from" countries', () => {
		const only: NetworkFactsPart = {
			categories: [],
			countries: { mode: 'only', codes: ['AT', 'DE'] },
			outcome: REFUSE
		};
		expect(decided(only, known([], 'DE')).outcome).toBe('allow');
		expect(decided(only, known([], 'FR')).reason).toBe('not_from_network');
		expect(decided(only, known([], null)).reason).toBe('not_from_network');
	});

	it('lets an address with no country through "not from" countries', () => {
		const not: NetworkFactsPart = {
			categories: [],
			countries: { mode: 'not', codes: ['FR'] },
			outcome: REFUSE
		};
		expect(decided(not, known([], null)).outcome).toBe('allow');
		expect(decided(not, known([], 'FR')).reason).toBe('not_from_network');
	});

	it("lets the proxy's own network through kept-out categories and countries, unlike kept-out ranges", () => {
		const both: NetworkFactsPart = {
			categories: ['tor', 'vpn', 'hosting'],
			countries: { mode: 'not', codes: ['FR'] },
			outcome: REFUSE
		};
		expect(decided(both, known([], null), { address: PRIVATE }).outcome).toBe(
			'allow'
		);
		const ranges = decide({
			rules: [
				{
					path: '/',
					who: {
						kind: 'conditional',
						who: { kind: 'project' },
						conditions: [{ kind: 'network', only: [], not: ['192.0.2.0/24'] }]
					}
				}
			],
			method: 'GET',
			rawPath: '/',
			person: { canSignIn: true, groupIds: [] },
			address: PRIVATE,
			at: AT
		});
		expect(ranges.reason).toBe('not_from_network');
	});

	it('asks a matching address for a sign-in within N instead of refusing', () => {
		const again: NetworkFactsPart = { categories: ['vpn'], outcome: AGAIN };
		const stale = decided(again, known(['vpn'], 'FR'), { signedInAgo: 30 });
		expect([stale.outcome, stale.reason, stale.maxAgeSeconds]).toEqual([
			'sign_in',
			'sign_in_again',
			900
		]);
		expect(
			decided(again, known(['vpn'], 'FR'), { signedInAgo: 10 }).outcome
		).toBe('allow');
		expect(decided(again, known([], 'FR'), { signedInAgo: 300 }).outcome).toBe(
			'allow'
		);
	});

	it('asks a first sign-in from a matching address for a code when the outcome wants one', () => {
		const d = decided(
			{ categories: ['vpn'], outcome: { ...AGAIN, withCode: true } },
			known(['vpn'], 'FR'),
			{ signedInAgo: null }
		);
		expect([d.outcome, d.reason, d.maxAgeSeconds, d.requireCode]).toEqual([
			'sign_in',
			'no_session',
			900,
			true
		]);
	});

	it('asks once, with the shorter interval, when the path also asks for a fresh sign-in', () => {
		const d = decide({
			rules: [
				{
					path: '/',
					who: {
						kind: 'conditional',
						who: { kind: 'project' },
						conditions: [
							{
								kind: 'network',
								only: [],
								not: [],
								facts: { categories: ['vpn'], outcome: AGAIN }
							},
							{ kind: 'fresh', maxAgeMinutes: 60 }
						]
					}
				}
			],
			method: 'GET',
			rawPath: '/',
			person: {
				canSignIn: true,
				groupIds: [],
				signedInAt: Math.floor((AT - 30 * 60_000) / 1000)
			},
			address: PUBLIC,
			network: known(['vpn'], null),
			at: AT
		});
		expect([d.outcome, d.maxAgeSeconds]).toEqual(['sign_in', 900]);
	});

	it('shows network facts as not checked in the console when no address was entered', () => {
		const d = decide({
			rules: rules(torOut),
			method: 'GET',
			rawPath: '/',
			person: { canSignIn: true, groupIds: [] },
			address: null,
			at: AT,
			explain: true
		});
		expect(d.conditions?.[0]?.result).toBe('unknown');
	});
});

describe('Network facts on an API checked at the proxy', () => {
	const conditions: Condition[] = [
		{
			kind: 'network',
			only: [],
			not: [],
			facts: { categories: ['tor'], outcome: REFUSE }
		}
	];
	const facts = (network: NetworkFacts) => ({
		address: PUBLIC,
		at: AT,
		timeZone: null,
		person: null,
		network,
		explain: false
	});

	it('refuses a matching address', () => {
		expect(decideAccess(conditions, facts(known(['tor'], null)))).toBe(
			'not_from_network'
		);
	});

	it('refuses on unknown facts with a reason of its own', () => {
		expect(decideAccess(conditions, facts(UNKNOWN))).toBe(
			'network_facts_unknown'
		);
	});

	it('lets an address with no record through', () => {
		expect(decideAccess(conditions, facts(known([], null)))).toBeNull();
	});
});

const category = fc.constantFrom(
	'tor' as const,
	'vpn' as const,
	'hosting' as const
);
const country = fc.constantFrom('AT', 'DE', 'FR', 'NL');
const part: fc.Arbitrary<NetworkFactsPart> = fc
	.record({
		categories: fc.uniqueArray(category, { maxLength: 3 }),
		countries: fc.option(
			fc.record({
				mode: fc.constantFrom('only' as const, 'not' as const),
				codes: fc.uniqueArray(country, { minLength: 1, maxLength: 4 })
			}),
			{ nil: undefined }
		),
		outcome: fc.oneof(
			fc.constant({ kind: 'refuse' } as const),
			fc.record({
				kind: fc.constant('sign_in_again' as const),
				maxAgeMinutes: fc.constantFrom(5, 15, 60),
				withCode: fc.option(fc.constant(true as const), { nil: undefined })
			})
		)
	})
	.map((p) =>
		p.countries === undefined
			? { categories: p.categories, outcome: p.outcome }
			: p
	);

describe('Changing a network facts condition', () => {
	it('lists as a loosening every change that lets in an address the old condition refused', () => {
		fc.assert(
			fc.property(
				part,
				part,
				fc.uniqueArray(category, { maxLength: 3 }),
				fc.option(country, { nil: null }),
				fc.constantFrom(null, 1, 10, 30, 120),
				fc.boolean(),
				(before, after, cats, place, signedInAgo, withCode) => {
					const wrap = (p: NetworkFactsPart): Condition => ({
						kind: 'network',
						only: [],
						not: [],
						facts: p
					});
					const loosened = loosenedConditions([wrap(before)], [wrap(after)]);
					if (loosened.length > 0) return true;
					const person =
						signedInAgo === null
							? null
							: {
									canSignIn: true,
									groupIds: [],
									signedInAt: Math.floor((AT - signedInAgo * 60_000) / 1000),
									signedInWithCode: withCode
								};
					const judge = (p: NetworkFactsPart) =>
						decide({
							rules: rules(p),
							method: 'GET',
							rawPath: '/',
							person,
							address: PUBLIC,
							network: known(cats, place),
							at: AT
						}).outcome;
					return !(judge(after) === 'allow' && judge(before) !== 'allow');
				}
			),
			{ numRuns: 400 }
		);
	});
});
