import { describe, it, expect } from 'bun:test';
import fc from 'fast-check';

import { ScimError } from 'lib/scim/errors.js';
import { parseGroupFilter } from 'lib/scim/filter.js';
import { applyPatch, GROUP_PATCH } from 'lib/scim/patch.js';

const ALLOWED_FIELDS = [
	'provisionedBy',
	'displayName',
	'externalId',
	'id',
	'member'
];

const PATHS = [
	'displayName',
	'externalId',
	'members',
	'members[value eq "u1"]',
	'members[value eq "u2"].value',
	'members.value',
	'urn:ietf:params:scim:schemas:core:2.0:Group:displayName',
	'id',
	'meta',
	'password',
	'__proto__',
	'constructor.prototype',
	'unknownThing'
];

const anyValue = fc.oneof(
	fc.string({ maxLength: 20 }),
	fc.boolean(),
	fc.constant(''),
	fc.record({
		value: fc.constantFrom('u1', 'u2', 'u3', ''),
		type: fc.constantFrom('User', 'Group')
	}),
	fc.array(fc.record({ value: fc.constantFrom('u1', 'u2', 'u3') }), {
		maxLength: 3
	}),
	fc.dictionary(
		fc.constantFrom('displayName', 'members', 'externalId', 'zzz'),
		fc.string({ maxLength: 5 })
	)
);

/**
 * @proves Over generated input, the `/Groups` filter parser and patch applier keep the promises the `/Users`
 * ones keep — nothing reaches the store except as a value of a declared field, in time linear in the input,
 * and no patch leaves anything but a group of members or no change, never polluting an object
 * (spec 071, FR-025, FR-028).
 */
describe('SCIM group input over generated cases', () => {
	it('for every generated group filter, yields a lookup on declared fields or refuses with invalidFilter, in linear time', () => {
		const filterText = fc.oneof(
			fc.string({ maxLength: 200 }),
			fc
				.array(
					fc.constantFrom(
						'displayName',
						'members',
						'id',
						'externalId',
						'[',
						']',
						' eq ',
						' and ',
						'"',
						'\\',
						'\n',
						'value',
						'.value',
						'__proto__'
					),
					{ maxLength: 60 }
				)
				.map((parts) => parts.join('')),
			fc.nat({ max: 1500 }).map((n) => `displayName eq "${'\n'.repeat(n)}`)
		);
		fc.assert(
			fc.property(filterText, (text) => {
				const started = performance.now();
				try {
					const parsed = parseGroupFilter(text, 'conn');
					for (const key of Object.keys(parsed.filter)) {
						expect(ALLOWED_FIELDS).toContain(key);
					}
					expect(parsed.filter.provisionedBy).toBe('conn');
				} catch (error) {
					expect(error).toBeInstanceOf(ScimError);
					expect((error as ScimError).scimType).toBe('invalidFilter');
				}
				expect(performance.now() - started).toBeLessThan(50);
			}),
			{ numRuns: 500 }
		);
	});

	it('for every generated group patch, yields a group of members or changes nothing', () => {
		const view = {
			displayName: 'Finance',
			members: [{ value: 'u1' }, { value: 'u2' }]
		};
		const operation = fc.record(
			{
				op: fc.constantFrom('add', 'replace', 'remove', 'Remove', 'bogus'),
				path: fc.constantFrom(...PATHS),
				value: anyValue
			},
			{ requiredKeys: ['op'] }
		);
		fc.assert(
			fc.property(
				fc.array(operation, { minLength: 1, maxLength: 4 }),
				fc.boolean(),
				(ops, strict) => {
					const original = structuredClone(view);
					try {
						const patched = applyPatch(
							view,
							{ Operations: ops },
							{ strict },
							GROUP_PATCH
						);
						const members = patched.members;
						expect(members === undefined || Array.isArray(members)).toBe(true);
						for (const key of Object.keys(patched)) {
							expect(['displayName', 'externalId', 'members']).toContain(key);
						}
					} catch (error) {
						expect(error).toBeInstanceOf(ScimError);
						expect((error as ScimError).status).toBe(400);
					}
					expect(view).toEqual(original);
					expect(({} as Record<string, unknown>).polluted).toBeUndefined();
				}
			),
			{ numRuns: 400 }
		);
	});
});
