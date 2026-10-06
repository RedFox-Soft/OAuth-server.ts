import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';

import { adapter, getUserStore } from 'lib/adapters/index.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { canSignIn } from 'lib/end_users/can_sign_in.js';
import {
	assignEndUserToConnection,
	lockEndUser
} from 'lib/end_users/service.js';
import bootstrap, { type Setup } from '../test_helper.js';
import { introspect, refresh, signIn } from '../end_user_lifecycle/fixtures.ts';
import {
	connect,
	defaultScimBucket,
	patchOf,
	provider,
	reload,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';

const noAudit = async () => undefined;

async function create(c: Connected, body: Record<string, unknown>) {
	const res = await scim('POST', `${c.base}/Users`, { token: c.token, body });
	expect(res.status).toBe(201);
	return res.json.id as string;
}

/**
 * @proves An identity system maintains a provisioned user over SCIM — finds, replaces, deactivates,
 * reactivates and deletes them — and a deactivation ends access exactly as an administrator's does (spec
 * 070, User Story 1, scenarios 4–8; FR-027, FR-032; IPSIE AL1 §5).
 */
describe('maintaining a provisioned user over SCIM', () => {
	let setup: Setup;
	let root: Connected;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'scim' });
		root = await connect(await defaultScimBucket([provider('corp')]));
	});

	afterEach(() => {
		mock.restore();
	});

	/* A signed-in user of the default bucket, handed to the root connection as the directory knows them. */
	async function provisionedSignIn() {
		const user = await signIn(setup);
		const userName = `signed-${Math.random()}@contoso.com`;
		await assignEndUserToConnection(
			await reload(root.bucket),
			user.accountId,
			{ connectionId: root.connection._id, userName },
			noAudit
		);
		return { ...user, userName };
	}

	it('finds the user by userName in any letter case', async () => {
		const id = await create(root, scimUser('Frank@Contoso.com'));

		const found = await scim(
			'GET',
			`${root.base}/Users?filter=${encodeURIComponent('userName eq "FRANK@contoso.COM"')}`,
			{ token: root.token }
		);

		expect(found.status).toBe(200);
		expect(found.json).toMatchObject({ totalResults: 1 });
		expect((found.json.Resources as { id: string }[])[0].id).toBe(id);
	});

	it('ends the user’s refresh and access tokens when deactivated', async () => {
		const user = await provisionedSignIn();

		const res = await scim('PATCH', `${root.base}/Users/${user.accountId}`, {
			token: root.token,
			body: patchOf([{ op: 'replace', path: 'active', value: false }])
		});

		expect(res.status).toBe(200);
		expect(res.json).toMatchObject({ active: false });
		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
		expect(await introspect(user.accessToken)).toMatchObject({ active: false });
	});

	it('restores only the ability to sign in when reactivated', async () => {
		const user = await provisionedSignIn();
		await scim('PATCH', `${root.base}/Users/${user.accountId}`, {
			token: root.token,
			body: patchOf([{ op: 'replace', path: 'active', value: false }])
		});

		const res = await scim('PATCH', `${root.base}/Users/${user.accountId}`, {
			token: root.token,
			body: patchOf([{ op: 'replace', path: 'active', value: true }])
		});

		expect(res.status).toBe(200);
		const stored = await getUserStore(DEFAULT_BUCKET_ID).find(user.accountId);
		expect(stored && canSignIn(stored)).toBe(true);
		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
	});

	it('leaves the active state unchanged when a replace omits it', async () => {
		const id = await create(root, scimUser('gina@contoso.com'));
		await scim('PATCH', `${root.base}/Users/${id}`, {
			token: root.token,
			body: patchOf([{ op: 'replace', path: 'active', value: false }])
		});
		const replacement = scimUser('gina@contoso.com', { displayName: 'Gina' });
		delete replacement.active;

		const res = await scim('PUT', `${root.base}/Users/${id}`, {
			token: root.token,
			body: replacement
		});

		expect(res.status).toBe(200);
		expect(res.json).toMatchObject({ displayName: 'Gina', active: false });
	});

	it('answers 404 for a deleted user and lets its userName be created again', async () => {
		const id = await create(root, scimUser('hank@contoso.com'));

		const deleted = await scim('DELETE', `${root.base}/Users/${id}`, {
			token: root.token
		});
		const read = await scim('GET', `${root.base}/Users/${id}`, {
			token: root.token
		});
		const again = await scim('POST', `${root.base}/Users`, {
			token: root.token,
			body: scimUser('hank@contoso.com')
		});

		expect(deleted.status).toBe(204);
		expect(read.status).toBe(404);
		expect(again.status).toBe(201);
	});

	it('answers 500 in the SCIM format when a deactivation cannot clear an area, and the user still cannot sign in', async () => {
		const user = await provisionedSignIn();
		spyOn(adapter('RefreshToken'), 'destroyByOwner').mockRejectedValue(
			new Error('the datastore is unavailable')
		);

		const res = await scim('PATCH', `${root.base}/Users/${user.accountId}`, {
			token: root.token,
			body: patchOf([{ op: 'replace', path: 'active', value: false }])
		});

		expect(res.status).toBe(500);
		expect(res.json).toMatchObject({
			schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
			status: '500'
		});
		expect(JSON.stringify(res.json)).not.toContain('datastore');
		const stored = await getUserStore(DEFAULT_BUCKET_ID).find(user.accountId);
		expect(stored && canSignIn(stored)).toBe(false);
	});

	it('keeps a locked user unable to sign in after the directory sets active: true', async () => {
		const id = await create(root, scimUser('ivy@contoso.com'));
		await lockEndUser(
			await reload(root.bucket),
			id,
			{ by: 'admin', reason: 'incident' },
			noAudit
		);

		const res = await scim('PATCH', `${root.base}/Users/${id}`, {
			token: root.token,
			body: patchOf([{ op: 'replace', path: 'active', value: true }])
		});

		expect(res.status).toBe(200);
		const stored = await getUserStore(DEFAULT_BUCKET_ID).find(id);
		expect(stored && canSignIn(stored)).toBe(false);
	});

	describe('filters IPSIE AL1 requires', () => {
		let id: string;

		beforeAll(async () => {
			id = await create(
				root,
				scimUser('jack@contoso.com', {
					externalId: 'oid-jack',
					emails: [{ value: 'jack@contoso.com', type: 'work', primary: true }]
				})
			);
		});

		for (const filter of [
			'userName eq "jack@contoso.com"',
			'externalId eq "oid-jack"',
			'emails[value eq "jack@contoso.com"]',
			'emails[type eq "work" and value eq "jack@contoso.com"]',
			'emails[type eq "work"].value eq "jack@contoso.com"'
		]) {
			it(`finds the user with ${filter}`, async () => {
				const res = await scim(
					'GET',
					`${root.base}/Users?filter=${encodeURIComponent(filter)}`,
					{ token: root.token }
				);

				expect(res.status).toBe(200);
				expect(res.json).toMatchObject({ totalResults: 1 });
				expect((res.json.Resources as { id: string }[])[0].id).toBe(id);
			});
		}

		it('returns an empty list when the email’s type does not match', async () => {
			const res = await scim(
				'GET',
				`${root.base}/Users?filter=${encodeURIComponent('emails[type eq "home" and value eq "jack@contoso.com"]')}`,
				{ token: root.token }
			);

			expect(res.status).toBe(200);
			expect(res.json).toMatchObject({ totalResults: 0, Resources: [] });
		});
	});

	describe('email verification and the connection’s trust policy', () => {
		it('records a trusted connection’s email as verified', async () => {
			const trusted = await connect(await scimBucket([provider('trusty')]), {
				emailTrust: 'trusted'
			});

			const id = await create(trusted, scimUser('kate@contoso.com'));

			const stored = await getUserStore(trusted.bucket._id).find(id);
			expect(stored?.verified).toBe(true);
		});

		it('marks a login email changed by an untrusted connection unverified', async () => {
			const untrusted = await connect(await scimBucket([provider('wary')]));
			const id = await create(untrusted, scimUser('liam@contoso.com'));
			await getUserStore(untrusted.bucket._id).update(id, { verified: true });

			const res = await scim('PATCH', `${untrusted.base}/Users/${id}`, {
				token: untrusted.token,
				body: patchOf([
					{
						op: 'replace',
						path: 'emails[type eq "work"].value',
						value: 'liam.new@contoso.com'
					}
				])
			});

			expect(res.status).toBe(200);
			const stored = await getUserStore(untrusted.bucket._id).find(id);
			expect(stored?.email).toBe('liam.new@contoso.com');
			expect(stored?.verified).toBe(false);
		});
	});
});
