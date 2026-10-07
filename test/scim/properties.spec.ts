import { describe, it, beforeAll, expect } from 'bun:test';
import fc from 'fast-check';

import { ScimError } from 'lib/scim/errors.js';
import { parseUserFilter } from 'lib/scim/filter.js';
import { applyPatch } from 'lib/scim/patch.js';
import { desiredUserOf } from 'lib/scim/resource.js';
import bootstrap from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.js';
import { connect, provider, scim, scimBucket } from './helpers.ts';

const ALLOWED_FIELDS = [
	'provisionedBy',
	'userName',
	'externalId',
	'id',
	'email'
];

const PATHS = [
	'active',
	'userName',
	'displayName',
	'name.givenName',
	'name',
	'emails',
	'emails[type eq "work"].value',
	'phoneNumbers[type eq "mobile"].value',
	'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department',
	'addresses',
	'password',
	'id',
	'meta',
	'__proto__',
	'constructor.prototype',
	'unknownThing'
];

const anyValue = fc.oneof(
	fc.string({ maxLength: 20 }),
	fc.boolean(),
	fc.constantFrom('True', 'false', ''),
	fc.record({
		value: fc.string({ maxLength: 10 }),
		type: fc.constantFrom('work', 'home')
	}),
	fc.array(fc.record({ value: fc.string({ maxLength: 10 }) }), {
		maxLength: 2
	}),
	fc.dictionary(
		fc.constantFrom('givenName', 'active', 'department', 'zzz'),
		fc.string({ maxLength: 5 })
	)
);

/**
 * @proves Over generated input, the SCIM filter parser and patch applier keep their two promises — no
 * input reaches the store except as a value of a declared field, and no patch leaves anything but a valid
 * user or no change — and paging through SCIM never loses or repeats a user (spec 070, FR-023, FR-025,
 * FR-033, FR-035; research R10, R11).
 */
describe('SCIM input over generated cases', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
	});

	it('for every generated filter, yields a lookup on declared fields or refuses with invalidFilter, in linear time', () => {
		const filterText = fc.oneof(
			fc.string({ maxLength: 200 }),
			fc
				.array(
					fc.constantFrom(
						'userName',
						'emails',
						'[',
						']',
						' eq ',
						' and ',
						'"',
						'\\',
						'\n',
						'x',
						'.value',
						'type'
					),
					{
						maxLength: 60
					}
				)
				.map((parts) => parts.join('')),
			fc.nat({ max: 1500 }).map((n) => `userName eq "${'\n'.repeat(n)}`)
		);
		fc.assert(
			fc.property(filterText, (text) => {
				const started = performance.now();
				try {
					const parsed = parseUserFilter(text, 'conn');
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

	it('for every generated patch, yields a valid user or changes nothing', () => {
		const view = {
			userName: 'gen@contoso.com',
			active: true,
			emails: [{ value: 'gen@contoso.com', type: 'work', primary: true }]
		};
		const operation = fc.record(
			{
				op: fc.constantFrom('add', 'replace', 'remove', 'Replace', 'bogus'),
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
						const patched = applyPatch(view, { Operations: ops }, { strict });
						const desired = desiredUserOf(patched);
						expect(typeof desired.userName).toBe('string');
						expect(desired.email.length).toBeGreaterThan(0);
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

	it('for every generated population and page size, pages through each of the connection’s users exactly once', async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.integer({ min: 0, max: 25 }),
				fc.integer({ min: 1, max: 30 }),
				async (population, pageSize) => {
					const c = await connect(
						await scimBucket([
							provider(`p${Math.random().toString(36).slice(2, 7)}`)
						])
					);
					const created = new Set<string>();
					/*
					 * Seeded through the store: the property is about reading pages, so the setup stays out of
					 * the SCIM surface it is measuring.
					 */
					const store = getUserStore(c.bucket._id);
					for (let i = 0; i < population; i++) {
						const user = await store.create(
							`u${i}@contoso.com`,
							'x',
							true,
							undefined,
							{
								provisionedBy: c.connection._id,
								userName: `u${i}@contoso.com`
							}
						);
						created.add(user._id);
					}
					/* A user of no connection, which no page may ever show. */
					await store.create(`local-${population}@contoso.com`, 'x', true);
					const seen: string[] = [];
					let total = -1;
					for (let start = 1; start <= population; start += pageSize) {
						const page = await scim(
							'GET',
							`${c.base}/Users?startIndex=${start}&count=${pageSize}`,
							{
								token: c.token
							}
						);
						total = page.json.totalResults as number;
						seen.push(
							...(page.json.Resources as { id: string }[]).map((r) => r.id)
						);
					}
					if (population === 0) {
						const page = await scim('GET', `${c.base}/Users`, {
							token: c.token
						});
						total = page.json.totalResults as number;
					}
					expect(total).toBe(population);
					expect(seen.length).toBe(population);
					expect(new Set(seen)).toEqual(created);
				}
			),
			{ numRuns: 15 }
		);
	});
});
