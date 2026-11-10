import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, {
	bindClientToBucket,
	SESSION_COOKIE_PREFIX,
	agent,
	getHeader
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

const PASSWORD = 'correct horse battery';

const buckets: Record<'required' | 'optional', string> = {
	required: '',
	optional: ''
};

async function passwordSignIn(clientId: string, email: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2] ?? '';
	const cookie = response.headers.get('set-cookie') ?? '';
	const res = await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/login`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
			body: new URLSearchParams({
				username: email,
				password: PASSWORD
			}).toString(),
			redirect: 'manual'
		})
	);
	return {
		uid,
		location: res.headers.get('location') ?? '',
		signedIn: (res.headers.get('set-cookie') ?? '').includes(
			SESSION_COOKIE_PREFIX
		)
	};
}

/**
 * @proves For every combination of what the project requires and whether the person holds an authenticator app, a
 * password sign-in asks for a code exactly when the project requires one or the person holds one — and only a project
 * that requires one leads a person without one to setting it up.
 */
describe('when a password sign-in asks for a code', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'totp' });
		resetAdminMemoryStores();
		for (const [kind, clientId, totpRequired] of [
			['required', 'totp-required-app', true],
			['optional', 'totp-optional-app', false]
		] as const) {
			const bucket = await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: `Asked ${kind}`,
				totpRequired
			});
			await bindClientToBucket(clientId, bucket._id);
			buckets[kind] = bucket._id;
		}
	});

	for (const required of [true, false]) {
		for (const enrolled of [true, false]) {
			const expected = enrolled
				? 'the code'
				: required
					? 'setting one up'
					: 'nothing';
			it(`asks for ${expected} when the project ${required ? 'requires' : 'does not require'} one and the person ${enrolled ? 'holds' : 'holds no'} authenticator`, async () => {
				const bucketId = buckets[required ? 'required' : 'optional'];
				const email = `asked-${Math.random()}@x.io`;
				const user = await getUserStore(bucketId).create(
					email,
					await Bun.password.hash(PASSWORD),
					true
				);
				if (enrolled) {
					await getUserStore(bucketId).update(user._id, {
						totp: {
							secret: 'JBSWY3DPEHPK3PXP',
							enrolledAt: new Date(),
							lastStep: 0,
							via: 'self'
						}
					});
				}

				const { uid, location, signedIn } = await passwordSignIn(
					required ? 'totp-required-app' : 'totp-optional-app',
					email
				);

				if (enrolled) {
					expect(location).toBe(`/ui/${uid}/totp`);
					expect(signedIn).toBe(false);
				} else if (required) {
					expect(location).toBe(`/ui/${uid}/totp/enroll`);
					expect(signedIn).toBe(false);
				} else {
					expect(location).not.toContain('/totp');
					expect(signedIn).toBe(true);
				}
			});
		}
	}
});
