import { describe, it, beforeAll, afterEach, expect } from 'bun:test';

import { ApplicationConfig } from 'lib/configs/application.js';
import { getUserStore } from 'lib/adapters/index.js';
import bootstrap from '../test_helper.js';
import {
	connect,
	scim,
	scimBucket,
	scimUser,
	type Connected,
	slugOf
} from './helpers.ts';

/**
 * @proves Whatever a caller sends — a filter outside the supported set, a path that reaches for an
 * object's prototype, no credential, the wrong media type, an oversized body — the SCIM endpoint refuses it
 * in SCIM's shape and changes nothing; and with SCIM switched off it is indistinguishable from a path the
 * server does not serve (spec 070, User Story 5, scenarios 7–10; FR-014, FR-019, FR-032, FR-035).
 */
describe('hostile and malformed SCIM requests', () => {
	let c: Connected;
	let id: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		c = await connect(await scimBucket());
		id = (
			await scim('POST', `${c.base}/Users`, {
				token: c.token,
				body: scimUser('target@contoso.com')
			})
		).json.id as string;
	});

	afterEach(() => {
		ApplicationConfig['scim.enabled'] = true;
	});

	for (const filter of [
		'userName co "a"',
		'userName sw "a"',
		'userName eq "a" or userName eq "b"',
		'not (userName eq "a")',
		'userName pr',
		'name.familyName eq "x"',
		"userName eq 'single'",
		'(userName eq "a")',
		`userName eq "${'x'.repeat(1100)}"`,
		`userName eq "${'\n'.repeat(40)}`
	]) {
		it(`answers 400 invalidFilter for ${JSON.stringify(filter).slice(0, 40)}`, async () => {
			const res = await scim(
				'GET',
				`${c.base}/Users?filter=${encodeURIComponent(filter)}`,
				{ token: c.token }
			);

			expect(res.status).toBe(400);
			expect(res.json).toMatchObject({ scimType: 'invalidFilter' });
		});
	}

	/*
	 * Written as raw JSON: a `__proto__` key in a JavaScript object literal sets the prototype instead of a
	 * property, so it would never reach the wire — JSON.parse on the server, by contrast, makes it an own key.
	 */
	const PATCH_OP =
		'"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"]';
	for (const [label, operations] of [
		['a path', '[{"op":"replace","path":"__proto__.polluted","value":"yes"}]'],
		[
			'a value key',
			'[{"op":"replace","value":{"constructor":{"prototype":{"polluted":"yes"}}}}]'
		],
		[
			'a nested value key',
			'[{"op":"add","path":"name","value":{"__proto__":{"polluted":"yes"}}}]'
		]
	] as const) {
		it(`refuses a patch naming a prototype key in ${label}, and changes nothing`, async () => {
			const before = await getUserStore(c.bucket._id).find(id);

			const res = await scim('PATCH', `${c.base}/Users/${id}`, {
				token: c.token,
				rawBody: `{${PATCH_OP},"Operations":${operations}}`
			});

			expect(res.status).toBe(400);
			expect(({} as Record<string, unknown>).polluted).toBeUndefined();
			const after = await getUserStore(c.bucket._id).find(id);
			expect(after?.updatedAt).toEqual(before?.updatedAt);
		});
	}

	it('answers 401 pointing at the metadata document when no credential is sent', async () => {
		const res = await scim('GET', `${c.base}/Users`);

		expect(res.status).toBe(401);
		expect(res.headers.get('www-authenticate')).toBe(
			`Bearer resource_metadata="http://e.ly/.well-known/oauth-protected-resource/${slugOf(c.bucket)}/scim/v2"`
		);
	});

	it('answers 415 for another media type and 413 for an oversized body', async () => {
		const wrongType = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			rawBody: 'userName=a',
			contentType: 'application/x-www-form-urlencoded'
		});
		const oversized = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			rawBody: JSON.stringify(
				scimUser('big@contoso.com', { displayName: 'x'.repeat(300_000) })
			)
		});

		expect(wrongType.status).toBe(415);
		expect(oversized.status).toBe(413);
		expect(
			await getUserStore(c.bucket._id).findByEmail('big@contoso.com')
		).toBeNull();
	});

	it('answers every SCIM path as an unserved path while SCIM is switched off', async () => {
		ApplicationConfig['scim.enabled'] = false;

		const users = await scim('GET', `${c.base}/Users`, { token: c.token });
		const metadata = await scim(
			'GET',
			`/.well-known/oauth-protected-resource/${slugOf(c.bucket)}/scim/v2`
		);
		const unserved = await scim(
			'GET',
			`/${slugOf(c.bucket)}/nothing-here/v2/Users`,
			{
				token: c.token
			}
		);

		expect(users.status).toBe(unserved.status);
		expect(metadata.status).toBe(unserved.status);
		expect(users.json).toEqual(unserved.json);
	});
});
