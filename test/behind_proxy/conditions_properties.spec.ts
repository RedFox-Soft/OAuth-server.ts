/*
 * Conditions at the proxy (specs/124), checked against generated input rather than examples. Address and time
 * comparisons are where an example passes while the property does not: one IPv6 spelling, one daylight-saving night,
 * one window past midnight. These are pure functions of their arguments, so nothing here needs the harness.
 */

import { describe, expect, it } from 'bun:test';
import { BlockList, isIPv6 } from 'node:net';
import fc from 'fast-check';

import {
	inAnyWindow,
	minuteOfWeek,
	type TimeWindow
} from 'lib/behind_proxy/clock.ts';
import type { Condition } from 'lib/behind_proxy/conditions.ts';
import {
	baseWho,
	conditionsOf,
	decide,
	widenings,
	withConditions,
	type PathRule
} from 'lib/behind_proxy/decide.ts';
import {
	inRange,
	parseAddress,
	parseRange,
	type Range
} from 'lib/behind_proxy/net.ts';

const RUNS = { numRuns: 400 };

function v4(value: number): string {
	return [24, 16, 8, 0]
		.map((shift) => String((value >>> shift) & 255))
		.join('.');
}

/* Every group written out in full: a spelling unlike the one the module under test writes. */
function v6(groups: readonly number[]): string {
	return groups.map((g) => g.toString(16).padStart(4, '0')).join(':');
}

function maskedV4(value: number, bits: number): number {
	return bits === 0 ? 0 : (value & (0xffffffff << (32 - bits))) >>> 0;
}

function maskedV6(groups: readonly number[], bits: number): number[] {
	return groups.map((group, i) => {
		const left = bits - i * 16;
		if (left >= 16) return group;
		if (left <= 0) return 0;
		return group & ((0xffff << (16 - left)) & 0xffff);
	});
}

const group = fc.integer({ min: 0, max: 0xffff });
/* Outside the IPv4-mapped space, where an IPv6 address is read as the IPv4 address it carries. */
const v6Groups = fc
	.array(group, { minLength: 8, maxLength: 8 })
	.filter((g) => !(g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff));

/**
 * @proves For every generated address and range, the address module agrees with the operating system's own
 * matcher, so a range an operator writes means exactly what their firewall would take it to mean.
 */
describe('addresses and ranges, against node:net', () => {
	it('an IPv4 address is in a range exactly when node:net says so', () => {
		fc.assert(
			fc.property(
				fc.nat({ max: 0xffffffff }),
				fc.nat({ max: 0xffffffff }),
				fc.integer({ min: 1, max: 32 }),
				(address, base, bits) => {
					const network = maskedV4(base, bits);
					const list = new BlockList();
					list.addSubnet(v4(network), bits, 'ipv4');
					const range = parseRange(`${v4(network)}/${String(bits)}`) as Range;
					const parsed = parseAddress(v4(address));
					if (!parsed) throw new Error(`${v4(address)} should parse`);
					expect(inRange(parsed, range)).toBe(list.check(v4(address), 'ipv4'));
				}
			),
			RUNS
		);
	});

	it('an IPv6 address is in a range exactly when node:net says so', () => {
		fc.assert(
			fc.property(
				v6Groups,
				v6Groups,
				fc.integer({ min: 1, max: 128 }),
				(address, base, bits) => {
					const network = v6(maskedV6(base, bits));
					if (!isIPv6(network)) return;
					const list = new BlockList();
					list.addSubnet(network, bits, 'ipv6');
					const range = parseRange(`${network}/${String(bits)}`);
					if ('error' in range) return;
					const parsed = parseAddress(v6(address));
					if (!parsed) throw new Error(`${v6(address)} should parse`);
					expect(inRange(parsed, range)).toBe(list.check(v6(address), 'ipv6'));
				}
			),
			RUNS
		);
	});

	it('an address in any spelling a parser could read differently is no address', () => {
		const loose = fc.oneof(
			fc.nat({ max: 0xffffffff }).map((a) => `${v4(a)}:80`),
			fc.nat({ max: 0xffffffff }).map((a) => `[${v4(a)}]`),
			fc.nat({ max: 0xffffffff }).map((a) => ` ${v4(a)}`),
			fc.nat({ max: 0xffffffff }).map((a) => String(a)),
			fc.integer({ min: 1, max: 9 }).map((d) => `0${String(d)}.1.2.3`),
			fc.constantFrom('1.2.3', '1.2', '1', '256.0.0.1', '1.2.3.4.5'),
			v6Groups.map((g) => `${v6(g)}%eth0`),
			v6Groups.map((g) => `[${v6(g)}]`),
			v6Groups.map((g) => `[${v6(g)}]:443`),
			fc.constantFrom('64:ff9b::1.2.3.4', '::1.2.3.4', '1.2.3.4, 5.6.7.8', '')
		);
		fc.assert(
			fc.property(loose, (text) => {
				expect(parseAddress(text)).toBeNull();
			}),
			RUNS
		);
	});
});

const ZONES = ['Europe/Moscow', 'America/New_York', 'Australia/Lord_Howe'];

/* The wall clock in `zone` read through a different door than the module: calendar parts, then the UTC weekday. */
function wallMinuteOfWeek(at: number, zone: string): number {
	const parts = Object.fromEntries(
		new Intl.DateTimeFormat('en-GB', {
			timeZone: zone,
			year: 'numeric',
			month: '2-digit',
			day: '2-digit',
			hour: '2-digit',
			minute: '2-digit',
			hourCycle: 'h23'
		})
			.formatToParts(at)
			.map((part) => [part.type, part.value])
	);
	const weekday = new Date(
		Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day))
	).getUTCDay();
	const monday = (weekday + 6) % 7;
	return monday * 1440 + Number(parts.hour) * 60 + Number(parts.minute);
}

/* The windows as concrete stretches of the week, wrapping past Sunday night, and membership by plain arithmetic. */
function referenceIn(windows: readonly TimeWindow[], minute: number): boolean {
	for (const window of windows) {
		for (const day of window.days) {
			const start = day * 1440 + window.start;
			const length =
				window.end > window.start
					? window.end - window.start
					: 1440 - window.start + window.end;
			const offset = (minute - start + 10080) % 10080;
			if (offset < length) return true;
		}
	}
	return false;
}

const step = fc.integer({ min: 0, max: 95 }).map((n) => n * 15);
const timeWindow = fc
	.record({
		days: fc.uniqueArray(fc.integer({ min: 0, max: 6 }), {
			minLength: 1,
			maxLength: 7
		}),
		start: step,
		end: step
	})
	.filter((w) => w.start !== w.end);

/**
 * @proves For every generated moment, zone and set of windows — daylight-saving nights and windows past midnight
 * included — the time condition opens exactly when a reference built from the local calendar says it does.
 */
describe('time windows, against the local calendar', () => {
	it('a moment is inside the windows exactly when the reference says so', () => {
		fc.assert(
			fc.property(
				fc.integer({
					min: Date.UTC(2026, 0, 1),
					max: Date.UTC(2027, 11, 31)
				}),
				fc.constantFrom(...ZONES),
				fc.array(timeWindow, { minLength: 1, maxLength: 3 }),
				(at, zone, windows) => {
					expect(minuteOfWeek(at, zone)).toBe(wallMinuteOfWeek(at, zone));
					expect(inAnyWindow(windows, minuteOfWeek(at, zone))).toBe(
						referenceIn(windows, wallMinuteOfWeek(at, zone))
					);
				}
			),
			RUNS
		);
	});
});

/* --- widening ------------------------------------------------------------------------------------------------- */

const ZONE = 'Europe/Moscow';
const GROUPS = ['g1', 'g2'];
const PATHS = ['/', '/a', '/a/b'];
const ADDRESSES = [
	'10.0.0.5',
	'10.1.0.5',
	'203.0.113.9',
	'203.0.113.200',
	'198.51.100.7',
	'192.0.2.5'
];
const RANGES = [
	'10.0.0.0/8',
	'10.1.0.0/16',
	'203.0.113.0/24',
	'203.0.113.0/25',
	'198.51.100.0/24'
];

const networkCondition = fc
	.record({
		kind: fc.constant('network' as const),
		only: fc.uniqueArray(fc.constantFrom(...RANGES), { maxLength: 2 }),
		not: fc.uniqueArray(fc.constantFrom(...RANGES), { maxLength: 2 })
	})
	.filter((c) => c.only.length + c.not.length > 0);
const condition = fc.oneof(
	networkCondition,
	fc.record({
		kind: fc.constant('time' as const),
		windows: fc.array(timeWindow, { minLength: 1, maxLength: 2 })
	}),
	fc.record({
		kind: fc.constant('attribute' as const),
		attribute: fc.constant('department'),
		values: fc.uniqueArray(fc.constantFrom('Ops', 'Sales', 'SRE'), {
			minLength: 1,
			maxLength: 2
		})
	}),
	fc.record({
		kind: fc.constant('fresh' as const),
		maxAgeMinutes: fc.constantFrom(5, 15, 60)
	})
);
const who = fc.oneof(
	fc.constant({ kind: 'project' as const }),
	fc
		.uniqueArray(fc.constantFrom(...GROUPS), { minLength: 1, maxLength: 2 })
		.map((groupIds) => ({ kind: 'groups' as const, groupIds })),
	fc.constant({ kind: 'public' as const, subtree: true }),
	fc.constant({ kind: 'none' as const })
);
const rule = (path: string) =>
	fc
		.record({
			who,
			conditions: fc.uniqueArray(condition, {
				maxLength: 2,
				selector: (c) => c.kind
			})
		})
		.map(({ who: plain, conditions }) => ({
			path,
			who: withConditions(plain, conditions)
		}));
const rules = fc
	.tuple(rule('/'), fc.option(rule('/a')), fc.option(rule('/a/b')))
	.map((all) => all.filter((r): r is NonNullable<typeof r> => r !== null));
const request = fc.record({
	path: fc.constantFrom(...PATHS, '/a/b/c'),
	method: fc.constantFrom('GET', 'POST'),
	address: fc.option(fc.constantFrom(...ADDRESSES)),
	at: fc.integer({ min: Date.UTC(2026, 10, 2), max: Date.UTC(2026, 10, 9) }),
	person: fc.option(
		fc.record({
			groupIds: fc.uniqueArray(fc.constantFrom(...GROUPS), { maxLength: 2 }),
			department: fc.option(fc.constantFrom('Ops', 'Sales', 'SRE')),
			signedInAgo: fc.integer({ min: 0, max: 120 })
		})
	)
});

type Probe = typeof request extends fc.Arbitrary<infer T> ? T : never;

function admits(rulesIn: PathRule[], r: Probe): boolean {
	return (
		decide({
			rules: rulesIn,
			method: r.method,
			rawPath: r.path,
			person: r.person
				? {
						canSignIn: true,
						groupIds: r.person.groupIds,
						attributes: r.person.department
							? { department: r.person.department }
							: {},
						signedInAt: Math.floor(r.at / 1000) - r.person.signedInAgo * 60
					}
				: null,
			address: r.address,
			at: r.at,
			timeZone: ZONE
		}).outcome === 'allow'
	);
}

/**
 * @proves For every generated pair of rule sets, when the console reports no widening, no generated request refused
 * under the rules before is allowed under the rules after — so a change that lets more people in always asks first.
 */
describe('widening of rules with conditions', () => {
	/* An "after" that is the "before" with one more condition on one rule: mostly narrower, so the property bites. */
	const narrowedPair = fc
		.tuple(rules, condition, fc.nat({ max: 2 }))
		.map(([before, extra, at]) => {
			const after = before.map((r, i) => {
				if (i !== at % before.length) return r;
				const plain = baseWho(r.who);
				if (plain.kind !== 'groups' && plain.kind !== 'project') return r;
				const own = conditionsOf(r.who).filter((c) => c.kind !== extra.kind);
				return { ...r, who: withConditions(plain, [...own, extra]) };
			});
			return [before, after] as const;
		});

	it('a change reported as no widening lets no refused request through', () => {
		let judged = 0;
		fc.assert(
			fc.property(
				fc.oneof(fc.tuple(rules, rules), narrowedPair),
				fc.array(request, { minLength: 20, maxLength: 20 }),
				([before, after], requests) => {
					if (
						widenings(before, after, { before: ZONE, after: ZONE }).length > 0
					)
						return;
					judged += 1;
					for (const r of requests) {
						if (!admits(before, r)) expect(admits(after, r)).toBe(false);
					}
				}
			),
			{ numRuns: 300 }
		);
		/* Not vacuous: enough pairs were reported as no widening for the property to have been put to the test. */
		expect(judged).toBeGreaterThan(30);
	});

	const base = (conditions: Condition[]): PathRule[] => [
		{ path: '/', who: withConditions({ kind: 'project' }, conditions) }
	];
	const NET = { kind: 'network', only: ['203.0.113.0/24'], not: [] } as const;
	const HOURS = {
		kind: 'time',
		windows: [{ days: [0, 1, 2, 3, 4], start: 480, end: 1200 }]
	} as const;
	const DEPT = {
		kind: 'attribute',
		attribute: 'department',
		values: ['Ops']
	} as const;
	const FRESH15 = { kind: 'fresh', maxAgeMinutes: 15 } as const;

	it.each([
		['removing a condition', [NET], []],
		[
			'adding a range to Only from',
			[NET],
			[{ ...NET, only: ['203.0.113.0/24', '198.51.100.0/24'] }]
		],
		[
			'removing a range from Not from',
			[{ ...NET, only: [], not: ['192.0.2.0/24', '198.51.100.0/24'] }],
			[{ ...NET, only: [], not: ['192.0.2.0/24'] }]
		],
		[
			'widening a window',
			[HOURS],
			[{ ...HOURS, windows: [{ ...HOURS.windows[0], end: 1260 }] }]
		],
		[
			'adding an attribute value',
			[DEPT],
			[{ ...DEPT, values: ['Ops', 'Sales'] }]
		],
		['raising the sign-in age', [FRESH15], [{ ...FRESH15, maxAgeMinutes: 60 }]]
	] as const)('%s is reported as a widening', (_case, from, to) => {
		const found = widenings(
			base(from as unknown as Condition[]),
			base(to as unknown as Condition[]),
			{ before: ZONE, after: ZONE }
		);

		expect(found.some((w) => (w.loosened ?? []).length > 0)).toBe(true);
	});

	it.each([
		['adding a condition', [], [NET]],
		[
			'removing a range from Only from',
			[{ ...NET, only: ['203.0.113.0/24', '198.51.100.0/24'] }],
			[NET]
		],
		[
			'narrowing a window',
			[HOURS],
			[{ ...HOURS, windows: [{ ...HOURS.windows[0], end: 1140 }] }]
		],
		['lowering the sign-in age', [FRESH15], [{ ...FRESH15, maxAgeMinutes: 5 }]]
	] as const)('%s reports nothing', (_case, from, to) => {
		expect(
			widenings(
				base(from as unknown as Condition[]),
				base(to as unknown as Condition[]),
				{
					before: ZONE,
					after: ZONE
				}
			)
		).toEqual([]);
	});

	it('changing the time zone of a window is reported as a widening', () => {
		const found = widenings(
			base([HOURS as unknown as Condition]),
			base([HOURS as unknown as Condition]),
			{
				before: ZONE,
				after: 'America/New_York'
			}
		);

		expect(found.some((w) => (w.loosened ?? []).length > 0)).toBe(true);
	});
});
