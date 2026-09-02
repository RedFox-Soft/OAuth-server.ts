import { describe, it, expect } from 'bun:test';
import {
	SETTINGS_CATALOG,
	SETTING_DOMAINS
} from 'lib/admin/settings/catalog.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { windowFor } from 'lib/login_throttle/consts.ts';
import { generate } from 'lib/helpers/user_codes.ts';
import {
	buildMask,
	cascadeOff,
	dirtyKeys,
	domainsWithDirty,
	groupSizeOptions,
	groupsFor,
	humanDuration,
	isRowEnabled,
	maskStrengthBits,
	matches,
	parseMask,
	pendingChanges,
	riskyChanges,
	sameValue,
	throttleRate,
	type Descriptor,
	type DomainMeta,
	type Values
} from 'lib/admin/ui/settings/model.ts';

/*
 * The console's copy of the descriptor shape, checked against the real thing at type level.
 *
 * The browser bundle cannot import the catalog — it reaches ApplicationConfig and the whole
 * configuration layer — so model.ts mirrors the interface. These two assignments are what stops the
 * mirror from drifting: a field added to SettingDescriptor that the console never learns about, or a
 * domain added to one union and not the other, fails `bun run typecheck` here rather than rendering
 * as a blank control in production. The values are unused on purpose; the assignment is the test.
 */
const _catalogIsAssignableToConsoleShape: Descriptor[] = SETTINGS_CATALOG;
const _domainsAreAssignableToConsoleShape: DomainMeta[] = SETTING_DOMAINS;
void _catalogIsAssignableToConsoleShape;
void _domainsAreAssignableToConsoleShape;

const d = (over: Partial<Descriptor> & { key: string }): Descriptor => ({
	domain: 'grants',
	group: 'G',
	label: over.key,
	summary: `summary of ${over.key}`,
	description: `a longer description of ${over.key}`,
	type: 'boolean',
	...over
});

describe('settings model', () => {
	describe('sameValue', () => {
		it('compares structured values by content, not identity', () => {
			expect(sameValue(['a', 'b'], ['a', 'b'])).toBe(true);
			expect(sameValue({ x: 1 }, { x: 1 })).toBe(true);
			expect(sameValue(['a'], ['b'])).toBe(false);
		});
	});

	describe('dirtyKeys', () => {
		it('reports only the keys whose content differs from the baseline', () => {
			const baseline: Values = { a: true, list: ['x'], n: 5 };
			const values: Values = { a: true, list: ['x'], n: 6 };
			expect(dirtyKeys(values, baseline)).toEqual(['n']);
		});

		/*
		 * The regression this function exists for: a freshly parsed array is a new object every render,
		 * so an identity comparison called every one of them dirty on load and offered to save the whole
		 * catalogue.
		 */
		it('does not call an untouched array dirty', () => {
			const baseline: Values = { list: ['x', 'y'] };
			const values: Values = { list: ['x', 'y'].slice() };
			expect(dirtyKeys(values, baseline)).toEqual([]);
		});
	});

	describe('groupsFor', () => {
		const catalog: Descriptor[] = [
			d({ key: 'f.enabled', group: 'Feature' }),
			d({ key: 'f.detail', group: 'Feature', dependsOn: 'f.enabled' }),
			d({
				key: 'nums.a',
				group: 'Numbers',
				type: 'number',
				unit: 'seconds'
			}),
			d({
				key: 'nums.b',
				group: 'Numbers',
				type: 'number',
				unit: 'seconds'
			}),
			d({ key: 'other.enabled', group: 'Other', domain: 'endpoints' })
		];

		it('returns only the cards of the requested pane', () => {
			expect(groupsFor(catalog, 'grants').map((g) => g.group)).toEqual([
				'Feature',
				'Numbers'
			]);
			expect(groupsFor(catalog, 'endpoints').map((g) => g.group)).toEqual([
				'Other'
			]);
		});

		it('lifts the gating boolean out of the rows and into the card header', () => {
			const [feature] = groupsFor(catalog, 'grants');
			expect(feature.primary?.key).toBe('f.enabled');
			expect(feature.rows.map((r) => r.key)).toEqual(['f.detail']);
		});

		/*
		 * A group of always-live values has no off state, so it gets no header switch. Before this
		 * distinction the page picked the first key with no `dependsOn` as the group's primary, which
		 * made Login throttle's failure cap and Discovery's scope list look like master switches.
		 */
		it('gives a group of plain values no header switch', () => {
			const [, numbers] = groupsFor(catalog, 'grants');
			expect(numbers.primary).toBeNull();
			expect(numbers.rows.map((r) => r.key)).toEqual(['nums.a', 'nums.b']);
		});

		it('files every catalog setting onto exactly one card of one pane', () => {
			const seen: string[] = [];
			for (const domain of SETTING_DOMAINS) {
				for (const g of groupsFor(SETTINGS_CATALOG, domain.id)) {
					if (g.primary) seen.push(g.primary.key as string);
					for (const r of g.rows) seen.push(r.key as string);
				}
			}
			expect(seen.sort()).toEqual(
				SETTINGS_CATALOG.map((x) => x.key as string).sort()
			);
		});
	});

	describe('isRowEnabled', () => {
		it('holds a row open only while its prerequisite is met', () => {
			const row = d({ key: 'x', dependsOn: 'parent' });
			expect(isRowEnabled(row, { parent: true })).toBe(true);
			expect(isRowEnabled(row, { parent: false })).toBe(false);
			expect(isRowEnabled(row, {})).toBe(false);
			expect(isRowEnabled(d({ key: 'y' }), {})).toBe(true);
		});
	});

	describe('cascadeOff', () => {
		const catalog: Descriptor[] = [
			d({ key: 'p' }),
			d({ key: 'child.bool', dependsOn: 'p' }),
			d({
				key: 'child.num',
				type: 'number',
				unit: 'seconds',
				dependsOn: 'p'
			}),
			d({ key: 'unrelated.bool', dependsOn: 'q' })
		];

		it('clears boolean dependents so the merged configuration stays saveable', () => {
			const next = cascadeOff(
				catalog,
				{
					p: true,
					'child.bool': true,
					'child.num': 30,
					'unrelated.bool': true
				},
				'p'
			);
			expect(next.p).toBe(false);
			expect(next['child.bool']).toBe(false);
			expect(next['unrelated.bool']).toBe(true);
		});

		/*
		 * A number under a disabled parent is not a configuration the server refuses, and discarding a
		 * tuned value on a toggle an operator may be about to turn back on loses their work.
		 */
		it('leaves a dependent number at the value the operator set', () => {
			const next = cascadeOff(catalog, { p: true, 'child.num': 30 }, 'p');
			expect(next['child.num']).toBe(30);
		});

		it('does not mutate the values it was given', () => {
			const values: Values = { p: true, 'child.bool': true };
			cascadeOff(catalog, values, 'p');
			expect(values).toEqual({ p: true, 'child.bool': true });
		});
	});

	describe('matches', () => {
		const row = d({
			key: 'rateLimit.strict.max',
			group: 'Rate limiting',
			label: 'Strict allowance — requests per window',
			summary: 'Allowance for token, authorization and other costly routes'
		});

		it('finds a setting by key, label, summary or group, case-insensitively', () => {
			expect(matches(row, 'strict.max')).toBe(true);
			expect(matches(row, 'ALLOWANCE')).toBe(true);
			expect(matches(row, 'costly routes')).toBe(true);
			expect(matches(row, 'rate limiting')).toBe(true);
			expect(matches(row, 'dpop')).toBe(false);
		});

		it('matches everything on an empty or blank query', () => {
			expect(matches(row, '')).toBe(true);
			expect(matches(row, '   ')).toBe(true);
		});
	});

	describe('domainsWithDirty', () => {
		it('names the panes holding an unsaved edit', () => {
			const catalog = [
				d({ key: 'a', domain: 'grants' }),
				d({ key: 'b', domain: 'diagnostics' }),
				d({ key: 'c', domain: 'endpoints' })
			];
			expect([...domainsWithDirty(catalog, ['a', 'c'])].sort()).toEqual([
				'endpoints',
				'grants'
			]);
			expect([...domainsWithDirty(catalog, [])]).toEqual([]);
		});
	});

	describe('pendingChanges', () => {
		const catalog = [
			d({ key: 'first' }),
			d({ key: 'risky', risk: 'security' }),
			d({ key: 'last' })
		];

		it('reads back each edit as from/to in catalog order', () => {
			const changes = pendingChanges(
				catalog,
				{ first: true, risky: true, last: false },
				{ first: false, risky: false, last: false }
			);
			expect(changes.map((c) => c.key)).toEqual(['first', 'risky']);
			expect(changes[0]).toMatchObject({ from: false, to: true });
		});

		it('separates the edits that need confirming', () => {
			const changes = pendingChanges(
				catalog,
				{ first: true, risky: true },
				{ first: false, risky: false }
			);
			expect(riskyChanges(changes).map((c) => c.key)).toEqual(['risky']);
		});

		it('finds nothing to confirm when no flagged setting was touched', () => {
			const changes = pendingChanges(
				catalog,
				{ first: true },
				{ first: false }
			);
			expect(riskyChanges(changes)).toEqual([]);
		});
	});

	describe('mask shape', () => {
		it('reads the shipped mask back as its two decisions', () => {
			expect(parseMask(ApplicationConfig['deviceFlow.mask'])).toEqual({
				length: 8,
				separator: 'hyphen',
				groupSize: 4
			});
		});

		/*
		 * The property that matters: everything the control can build reads back. The first version of
		 * `buildMask` broke it by emitting "***-*" for a group size that does not divide the length, and
		 * this loop is what caught it.
		 */
		it('round-trips every shape the editor can offer', () => {
			for (const separator of ['none', 'hyphen', 'space'] as const) {
				for (const length of [1, 4, 6, 8, 9, 12, 13]) {
					for (const groupSize of [0, ...groupSizeOptions(length)]) {
						const mask = buildMask({ length, separator, groupSize });
						// Whatever it built must be a mask the server accepts.
						expect(mask).toMatch(/^[-* ]+$/);
						expect(mask).toContain('*');

						const read = parseMask(mask);
						expect(read?.length).toBe(length);
						if (separator !== 'none' && groupSize > 1) {
							expect(read?.separator).toBe(separator);
							expect(read?.groupSize).toBe(groupSize);
						}
					}
				}
			}
		});

		/*
		 * A group size that cannot divide the length is not silently turned into uneven groups; the
		 * separator is dropped instead. The control only offers divisors, so this is the guard rather
		 * than the path — but a shape can also arrive from a mask an operator typed by hand.
		 */
		it('drops the separator rather than emitting a short last group', () => {
			expect(buildMask({ length: 4, separator: 'hyphen', groupSize: 3 })).toBe(
				'****'
			);
			expect(buildMask({ length: 8, separator: 'hyphen', groupSize: 4 })).toBe(
				'****-****'
			);
			expect(buildMask({ length: 9, separator: 'space', groupSize: 3 })).toBe(
				'*** *** ***'
			);
		});

		it('offers only group sizes that divide the length', () => {
			expect(groupSizeOptions(8)).toEqual([2, 4]);
			expect(groupSizeOptions(9)).toEqual([3]);
			expect(groupSizeOptions(12)).toEqual([2, 3, 4, 6]);
			// A prime length, or a very short one, has no sensible grouping at all.
			expect(groupSizeOptions(13)).toEqual([]);
			expect(groupSizeOptions(1)).toEqual([]);
		});

		/*
		 * A mask the form cannot draw must not be silently redrawn. Returning null is what lets the
		 * control fall back to editing the template as text, rather than rewriting a valid
		 * configuration into the nearest shape it happens to support.
		 */
		it('declines to represent a mask the editor cannot draw', () => {
			expect(parseMask('***-**')).toBeNull(); // uneven groups
			expect(parseMask('**-** **')).toBeNull(); // both separators
			expect(parseMask('**--**')).toBeNull(); // empty group
			expect(parseMask('---')).toBeNull(); // no random part at all
			expect(parseMask('ab**')).toBeNull(); // characters the server refuses
			expect(parseMask(undefined)).toBeNull();
		});

		/*
		 * Cross-checked against the real generator: a mask this control produces must yield a code of
		 * exactly the promised number of random characters, or the strength figure beside it is a
		 * fiction.
		 */
		it('produces masks whose generated codes match the promised length', () => {
			for (const shape of [
				{ length: 8, separator: 'hyphen', groupSize: 4 } as const,
				{ length: 9, separator: 'space', groupSize: 3 } as const,
				{ length: 6, separator: 'none', groupSize: 0 } as const
			]) {
				const mask = buildMask(shape);
				const code = generate('base-20', mask);
				expect(code.replace(/[- ]/g, '')).toHaveLength(shape.length);
				expect(code).not.toBe(mask);
			}
		});

		it('states strength in bits from the length and the charset', () => {
			// 8 characters of a 20-symbol alphabet: 8 × log2(20) ≈ 34.6 bits.
			expect(maskStrengthBits('****-****', 'base-20')).toBeCloseTo(34.6, 1);
			// The same code in digits is markedly weaker, which is the point of showing it.
			expect(maskStrengthBits('****-****', 'digits')).toBeCloseTo(26.6, 1);
			expect(maskStrengthBits('****', 'base-20')).toBeCloseTo(17.3, 1);
		});

		it('states no strength for a mask or charset it cannot read', () => {
			expect(maskStrengthBits('---', 'base-20')).toBeNull();
			expect(maskStrengthBits('****', 'klingon')).toBeNull();
			expect(maskStrengthBits(undefined, 'base-20')).toBeNull();
		});
	});

	describe('throttleRate', () => {
		/*
		 * The shipped defaults, and the number the catalog's own description quotes. If this ever
		 * disagrees with lib/configs/application.ts the hint is lying to the operator about their own
		 * configuration, which is the whole reason the arithmetic is not inline in a component.
		 */
		it('agrees with the description at the shipped defaults', () => {
			const rate = throttleRate({
				'loginThrottle.failureCap': ApplicationConfig[
					'loginThrottle.failureCap'
				] as number,
				'loginThrottle.windowCeilingSeconds': ApplicationConfig[
					'loginThrottle.windowCeilingSeconds'
				] as number
			});
			expect(rate?.guessesPerDay).toBe(120);
		});

		/*
		 * Cross-checked against the real curve rather than restating the formula: windowFor is what
		 * actually decides the window, so this pins that the hint describes the throttle that ships and
		 * not a second model of it. At a step past the doublings the window IS the ceiling, and the
		 * settled rate is cap per that window.
		 */
		it('matches the window the real escalation curve settles at', () => {
			const cap = 5;
			const windowSeconds = 900;
			const ceilingSeconds = 3600;

			const settled = windowFor(9, windowSeconds, ceilingSeconds);
			expect(settled).toBe(ceilingSeconds);

			const rate = throttleRate({
				'loginThrottle.failureCap': cap,
				'loginThrottle.windowCeilingSeconds': ceilingSeconds
			});
			expect(rate?.guessesPerDay).toBe(Math.round((cap * 86400) / settled));
		});

		it('moves inversely with the ceiling', () => {
			const at = (ceilingSeconds: number) =>
				throttleRate({
					'loginThrottle.failureCap': 5,
					'loginThrottle.windowCeilingSeconds': ceilingSeconds
				})?.guessesPerDay;

			expect(at(900)).toBe(480);
			expect(at(1800)).toBe(240);
			expect(at(3600)).toBe(120);
			expect(at(86400)).toBe(5);
		});

		/*
		 * The page holds whatever an operator has half-typed, including an emptied field. A hint reading
		 * "Infinity guesses a day" would be worse than no hint at all.
		 */
		it('declines to state a rate from an unusable value', () => {
			expect(throttleRate({})).toBeNull();
			expect(
				throttleRate({
					'loginThrottle.failureCap': 5,
					'loginThrottle.windowCeilingSeconds': 0
				})
			).toBeNull();
			expect(
				throttleRate({
					'loginThrottle.failureCap': null,
					'loginThrottle.windowCeilingSeconds': 3600
				})
			).toBeNull();
		});
	});

	describe('humanDuration', () => {
		it('uses the largest unit that divides exactly, and pluralises', () => {
			expect(humanDuration(3600)).toBe('1 hour');
			expect(humanDuration(7200)).toBe('2 hours');
			expect(humanDuration(900)).toBe('15 minutes');
			expect(humanDuration(60)).toBe('1 minute');
			expect(humanDuration(90)).toBe('90 seconds');
		});
	});
});
