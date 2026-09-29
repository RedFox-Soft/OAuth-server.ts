import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { agent, getHeader, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getGroupStore, getProjectStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * Skipping the consent screen is a tenant's decision about its own users, not about anyone else's. Any
 * member of a group can create a project and a client in it with consent switched off, and a project
 * with no bucket signs its clients into the default bucket, which every tenant shares and none owns.
 * Such a client was handed the claims of any default-bucket user who had a session and followed its
 * link — with `prompt=none`, without a page ever being shown.
 */

async function projectHolding(clientId: string, ownerGroupId: string) {
	const project = await getProjectStore().create({
		ownerGroupId,
		name: clientId,
		slug: `${clientId}-${Math.random().toString(36).slice(2)}`
	});
	await getProjectStore().update(project._id, { clientIds: [clientId] });
}

async function authorizeSilently(
	clientId: string,
	redirectUri: string,
	cookie: string
) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		redirect_uri: redirectUri,
		scope: 'openid email',
		prompt: 'none'
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: { cookie }
	});
	return new URL(getHeader(response, 'location'));
}

/**
 * @proves A client that skips consent does so only for users of a bucket its own group owns, and asks
 * the users of any other bucket.
 */
describe('a client that skips consent, signing into a bucket', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await ensureAdminSeed();
		const tenant = await getGroupStore().create({
			name: 'Tenant',
			kind: 'regular',
			members: [{ userId: 'tenant-owner', role: 'owner' }]
		});
		await projectHolding('tenant-app', tenant._id);
		await projectHolding('system-app', UNASSIGNED_GROUP_ID);
	});

	it('asks for consent in a bucket its group does not own', async () => {
		const cookie = await setup.login({ scope: 'openid' });

		const callback = await authorizeSilently(
			'tenant-app',
			'https://tenant.example.com/cb',
			cookie
		);

		expect(callback.searchParams.get('error')).toBe('consent_required');
		expect(callback.searchParams.get('code')).toBeNull();
	});

	it('skips consent in a bucket its group owns', async () => {
		const cookie = await setup.login({ scope: 'openid' });

		const callback = await authorizeSilently(
			'system-app',
			'https://system.example.com/cb',
			cookie
		);

		expect(callback.searchParams.get('code')).toBeTruthy();
	});
});
