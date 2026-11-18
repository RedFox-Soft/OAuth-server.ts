import { describe, expect, it } from 'bun:test';

import type { PersonActivityRow } from 'lib/adapters/types.ts';
import { judge } from 'lib/sign_in_alerts/judge.ts';

let n = 0;

function signIn(
	minutes: number,
	fields: Partial<PersonActivityRow> = {}
): PersonActivityRow {
	const at = new Date(Date.UTC(2026, 10, 18, 9, minutes));
	n += 1;
	return {
		_id: `row-${String(n)}`,
		bucketId: 'acme',
		accountId: 'anna',
		day: '2026-11-18',
		kind: 'signIn',
		outcome: 'let_in',
		reason: 'signed_in',
		place: { clientId: 'web' },
		method: 'password',
		address: '203.0.113.7',
		addressFrom: 'sign_in',
		count: 1,
		firstAt: at,
		lastAt: at,
		expiresAt: new Date(at.getTime() + 90 * 86_400_000),
		...fields
	};
}

const CHROME = { browser: 'chrome', system: 'windows' } as const;
const FIREFOX = { browser: 'firefox', system: 'linux' } as const;
const asn = (value: number) => ({ asn: value });

/**
 * @proves A successful sign-in is new when no earlier sign-in of the last 90 days came from its network (the network
 * owner when both sides know one, else the country) or its browser on its system; a different address inside a known
 * network is not new; with nothing to compare, or nothing known on one side, nothing is judged new.
 */
describe('what makes a sign-in new', () => {
	it('is a new network when its network owner is new', () => {
		const known = signIn(0, { lookup: asn(64500), device: CHROME });
		const now = signIn(10, { lookup: asn(64501), device: CHROME });
		expect(judge(now, [known])).toBe('network');
	});

	it('is nothing new from another address inside a known network', () => {
		const known = signIn(0, { lookup: asn(64500), device: CHROME });
		const now = signIn(10, {
			address: '203.0.113.200',
			lookup: asn(64500),
			device: CHROME
		});
		expect(judge(now, [known])).toBeNull();
	});

	it('falls back to the country when a side knows no network owner', () => {
		const known = signIn(0, {
			facts: { country: 'DE', categories: [] },
			device: CHROME
		});
		const now = signIn(10, {
			lookup: asn(64501),
			facts: { country: 'NL', categories: [] },
			device: CHROME
		});
		expect(judge(now, [known])).toBe('network');
	});

	it('does not judge the network when neither an owner nor a country is known on both sides', () => {
		const known = signIn(0, { device: CHROME });
		const now = signIn(10, { lookup: asn(64501), device: CHROME });
		expect(judge(now, [known])).toBeNull();
	});

	it('is a new browser when the browser or system is new', () => {
		const known = signIn(0, { lookup: asn(64500), device: CHROME });
		const now = signIn(10, { lookup: asn(64500), device: FIREFOX });
		expect(judge(now, [known])).toBe('browser');
	});

	it('is both when the network and the browser are new', () => {
		const known = signIn(0, { lookup: asn(64500), device: CHROME });
		const now = signIn(10, { lookup: asn(64501), device: FIREFOX });
		expect(judge(now, [known])).toBe('both');
	});

	it('judges nothing with nothing to compare', () => {
		const now = signIn(10, { lookup: asn(64501), device: FIREFOX });
		expect(judge(now, [])).toBeNull();
	});

	it('compares only with earlier sign-ins', () => {
		const now = signIn(10, { lookup: asn(64501), device: FIREFOX });
		const later = signIn(20, { lookup: asn(64501), device: FIREFOX });
		const earlier = signIn(0, { lookup: asn(64500), device: CHROME });
		expect(judge(now, [now, later, earlier])).toBe('both');
	});

	it('counts only successful sign-ins of the same account as history', () => {
		const refused = signIn(0, {
			outcome: 'refused',
			reason: 'wrong_password',
			lookup: asn(64501),
			device: FIREFOX
		});
		const other = signIn(1, {
			accountId: 'bob',
			lookup: asn(64501),
			device: FIREFOX
		});
		const known = signIn(2, { lookup: asn(64500), device: CHROME });
		const now = signIn(10, { lookup: asn(64501), device: FIREFOX });
		expect(judge(now, [refused, other, known])).toBe('both');
	});
});
