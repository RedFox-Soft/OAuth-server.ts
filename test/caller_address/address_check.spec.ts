import { describe, it, beforeAll, beforeEach, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { configStore } from 'lib/adapters/index.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { saveSettings, superAdminCookie } from '../settings_apply/helpers.js';
import { send } from './helper.js';

async function cookieFor(kind: AdminKind): Promise<string> {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

async function check(
	cookie: string,
	peer: string,
	headers: Record<string, string> = {}
) {
	const response = await send('/admin/api/settings/client-address', {
		peer,
		headers: { ...headers, cookie }
	});
	return {
		status: response.status,
		data: response.ok
			? ((await response.json()) as Record<string, unknown>)
			: undefined
	};
}

beforeAll(async () => {
	await bootstrap(import.meta.url);
	await ensureAdminSeed();
});

/**
 * @proves A super administrator can see which address the server attributes to their own request and
 * where it came from, is warned when the choice contradicts what arrived, and cannot save a choice
 * that names no proxy; nobody else can read the check.
 */
describe('the caller address check', () => {
	beforeEach(async () => {
		await configStore.set({});
		ApplicationConfig['clientAddress.source'] = 'automatic';
		ApplicationConfig['clientAddress.trustedProxies'] = [];
	});

	it('shows the attributed address and where it came from', async () => {
		const { data } = await check(await cookieFor('super'), '10.0.0.2', {
			'x-forwarded-for': '203.0.113.7'
		});

		expect(data).toEqual({
			source: 'automatic',
			attributed: { address: '203.0.113.7', from: 'x-forwarded-for' },
			connection: '10.0.0.2',
			forwardedHeaders: ['x-forwarded-for'],
			warning: null
		});
	});

	it('warns when fly is chosen and the request carries no Fly-Client-IP', async () => {
		ApplicationConfig['clientAddress.source'] = 'fly';

		const { data } = await check(await cookieFor('super'), '10.0.0.2', {
			'x-forwarded-for': '203.0.113.7'
		});

		expect(data?.warning).toBe('fly-header-missing');
	});

	it('is refused to an administrator who is not a super administrator', async () => {
		const { status } = await check(await cookieFor('plain'), '10.0.0.2');

		expect(status).toBe(403);
	});

	it('refuses to save listed with no proxy address', async () => {
		const response = await saveSettings(await superAdminCookie(), {
			'clientAddress.source': 'listed'
		});

		expect(response.status).toBe(422);
	});
});
