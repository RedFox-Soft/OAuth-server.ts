import type { Outcome, PathRule, Reason } from 'lib/behind_proxy/decide.ts';
import type { Condition } from 'lib/behind_proxy/conditions.ts';

/*
 * The decision table of specs/124 quickstart §2, held once and driven twice: through the live check, as a proxy on
 * the new recipe sends it, and through `decide()`, as the console's "Check access" runs it (C1, SC-007).
 */

export const ZONE = 'Europe/Moscow';

/* Moscow has kept UTC+3 all year since 2014, so a Moscow wall clock is UTC plus three hours. */
const MOSCOW = 3;
/* 2026-11-05 is a Thursday. */
export const MOMENTS = {
	thu1400: Date.UTC(2026, 10, 5, 14 - MOSCOW, 0),
	sat1400: Date.UTC(2026, 10, 7, 14 - MOSCOW, 0),
	sat0300: Date.UTC(2026, 10, 7, 3 - MOSCOW, 0)
} as const;
export type Moment = keyof typeof MOMENTS;

export const NETWORK: Condition = {
	kind: 'network',
	only: ['203.0.113.0/24'],
	not: []
};
export const WORKING_HOURS: Condition = {
	kind: 'time',
	windows: [{ days: [0, 1, 2, 3, 4], start: 8 * 60, end: 20 * 60 }]
};
export const FRESH: Condition = { kind: 'fresh', maxAgeMinutes: 15 };
export const OPS: Condition = {
	kind: 'attribute',
	attribute: 'department',
	values: ['Ops']
};
export const REPORTS_NETWORK: Condition = {
	kind: 'network',
	only: ['198.51.100.0/24'],
	not: []
};
export const NOT_TEST_NET: Condition = {
	kind: 'network',
	only: [],
	not: ['192.0.2.0/24']
};

export interface TableGroups {
	staff: string;
	admins: string;
}

/* The rules as the admin routes take them. */
export function edgeRules(groups: TableGroups, root: Condition = NETWORK) {
	return [
		{
			path: '/',
			who: { kind: 'groups' as const, groups: [groups.staff] },
			conditions: [root, WORKING_HOURS]
		},
		{
			path: '/admin',
			who: { kind: 'groups' as const, groups: [groups.admins] },
			conditions: [FRESH, OPS]
		},
		{ path: '/health', who: { kind: 'public' as const, subtree: false } },
		{
			path: '/reports',
			who: { kind: 'groups' as const, groups: [groups.staff] },
			conditions: [REPORTS_NETWORK]
		}
	];
}

/* The same rules as they are stored and decided. */
export function storedRules(
	groups: TableGroups,
	root: Condition = NETWORK
): PathRule[] {
	return [
		{
			path: '/',
			who: {
				kind: 'conditional',
				who: { kind: 'groups', groupIds: [groups.staff] },
				conditions: [root, WORKING_HOURS]
			}
		},
		{
			path: '/admin',
			who: {
				kind: 'conditional',
				who: { kind: 'groups', groupIds: [groups.admins] },
				conditions: [FRESH, OPS]
			}
		},
		{ path: '/health', who: { kind: 'public', subtree: false } },
		{
			path: '/reports',
			who: {
				kind: 'conditional',
				who: { kind: 'groups', groupIds: [groups.staff] },
				conditions: [REPORTS_NETWORK]
			}
		}
	];
}

export type Who = 'none' | 'staff' | 'adminOps' | 'adminSales';

export interface Row {
	uri: string;
	/* The address the proxy writes, or null when it sends no key. */
	address: string | null;
	at: Moment;
	who: Who;
	/* Minutes since the person signed in. */
	signedInAgo?: number;
	/* The root's network condition, when the row needs another one. */
	root?: Condition;
	outcome: Outcome;
	reason: Reason;
}

export const ROWS: readonly Row[] = [
	{
		uri: '/health',
		address: '192.0.2.5',
		at: 'sat0300',
		who: 'none',
		outcome: 'allow',
		reason: 'public'
	},
	{
		uri: '/dash',
		address: '192.0.2.5',
		at: 'thu1400',
		who: 'none',
		outcome: 'deny',
		reason: 'not_from_network'
	},
	{
		uri: '/dash',
		address: '203.0.113.9',
		at: 'sat1400',
		who: 'none',
		outcome: 'deny',
		reason: 'outside_hours'
	},
	{
		uri: '/dash',
		address: '203.0.113.9',
		at: 'thu1400',
		who: 'none',
		outcome: 'sign_in',
		reason: 'no_session'
	},
	{
		uri: '/dash',
		address: '203.0.113.9',
		at: 'thu1400',
		who: 'staff',
		signedInAgo: 60,
		outcome: 'allow',
		reason: 'allowed'
	},
	{
		uri: '/admin',
		address: '203.0.113.9',
		at: 'thu1400',
		who: 'adminOps',
		signedInAgo: 3,
		outcome: 'allow',
		reason: 'allowed'
	},
	{
		uri: '/admin',
		address: '203.0.113.9',
		at: 'thu1400',
		who: 'adminOps',
		signedInAgo: 20,
		outcome: 'sign_in',
		reason: 'sign_in_again'
	},
	{
		uri: '/admin',
		address: '203.0.113.9',
		at: 'thu1400',
		who: 'adminSales',
		signedInAgo: 3,
		outcome: 'deny',
		reason: 'attribute_mismatch'
	},
	{
		uri: '/admin',
		address: '192.0.2.5',
		at: 'thu1400',
		who: 'adminOps',
		signedInAgo: 3,
		outcome: 'deny',
		reason: 'not_from_network'
	},
	{
		uri: '/dash',
		address: null,
		at: 'thu1400',
		who: 'staff',
		signedInAgo: 60,
		outcome: 'deny',
		reason: 'not_from_network'
	},
	{
		uri: '/dash',
		address: '198.51.100.7',
		at: 'thu1400',
		who: 'staff',
		signedInAgo: 60,
		outcome: 'deny',
		reason: 'not_from_network'
	},
	{
		uri: '/reports',
		address: '203.0.113.9',
		at: 'thu1400',
		who: 'staff',
		signedInAgo: 60,
		outcome: 'deny',
		reason: 'not_from_network'
	},
	{
		uri: '/dash',
		address: '203.0.113.9',
		at: 'thu1400',
		who: 'staff',
		signedInAgo: 60,
		root: NOT_TEST_NET,
		outcome: 'allow',
		reason: 'allowed'
	}
];

export function rowName(row: Row): string {
	return `${row.uri} from ${row.address ?? 'no key'} at ${row.at} by ${row.who}${row.signedInAgo === undefined ? '' : ` signed in ${String(row.signedInAgo)} min ago`}${row.root === NOT_TEST_NET ? ' (root Not from)' : ''}`;
}
