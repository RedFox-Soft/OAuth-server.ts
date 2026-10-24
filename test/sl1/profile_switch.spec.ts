import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import {
	adminAuditStore,
	configStore,
	getBucketStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { present, shaped } from 'test/shape.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { saveSettings, superAdminCookie } from '../settings_apply/helpers.ts';

/* Everything the profile needs from the other settings, so a case can leave out exactly one. */
const PREREQUISITES = {
	'dpop.enabled': true,
	'encryption.enabled': true
};
const OFF = {
	'ipsieSl1.enabled': false,
	'dpop.enabled': false,
	'encryption.enabled': false,
	'pkce.required': true,
	'registration.enabled': false,
	'par.allowUnregisteredRedirectUris': false
};

const Refusal = Type.Object({ message: Type.String() });

async function refusalOf(res: Response) {
	expect(res.status).toBe(422);
	return shaped(Refusal, await res.json()).message;
}

function loopbackSignIn() {
	return new AuthorizationRequest({
		client_id: 'sl1-loopback',
		scope: 'openid'
	}).authorize();
}

/**
 * @proves An operator cannot turn the IPSIE SL1 profile on over a setting it depends on, or a project that cannot
 * sign with the profile's default algorithm, and turning it on or off takes effect on the next request, audited.
 */
describe('turning the IPSIE SL1 profile on and off', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'profile_switch' });
		cookie = await superAdminCookie();
	});

	beforeEach(async () => {
		await configStore.set({});
		expect((await saveSettings(cookie, OFF)).status).toBe(200);
	});

	describe('refused while a prerequisite is unmet', () => {
		it('is refused while registration is open without an initial access token, naming registration', async () => {
			const message = await refusalOf(
				await saveSettings(cookie, {
					...PREREQUISITES,
					'registration.enabled': true,
					'ipsieSl1.enabled': true
				})
			);

			expect(message).toContain('registration.enabled');
			expect(ApplicationConfig['ipsieSl1.enabled']).toBe(false);
		});

		it('is refused while DPoP is off, naming it', async () => {
			const message = await refusalOf(
				await saveSettings(cookie, {
					'encryption.enabled': true,
					'ipsieSl1.enabled': true
				})
			);

			expect(message).toContain('dpop.enabled');
		});

		it('is refused while PKCE is not required, naming it', async () => {
			const message = await refusalOf(
				await saveSettings(cookie, {
					...PREREQUISITES,
					'pkce.required': false,
					'ipsieSl1.enabled': true
				})
			);

			expect(message).toContain('pkce.required');
		});

		it('is refused while encryption is off, naming it', async () => {
			const message = await refusalOf(
				await saveSettings(cookie, {
					'dpop.enabled': true,
					'ipsieSl1.enabled': true
				})
			);

			expect(message).toContain('encryption.enabled');
		});

		it('is refused while pushed requests accept unregistered redirect URIs, naming it', async () => {
			const message = await refusalOf(
				await saveSettings(cookie, {
					...PREREQUISITES,
					'par.enabled': true,
					'par.allowUnregisteredRedirectUris': true,
					'ipsieSl1.enabled': true
				})
			);

			expect(message).toContain('par.allowUnregisteredRedirectUris');
		});

		it('is refused while a project with an address of its own has no PS256 signing key, naming it', async () => {
			const bucket = await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: 'No PS256 yet',
				slug: 'nops256'
			});
			try {
				const message = await refusalOf(
					await saveSettings(cookie, {
						...PREREQUISITES,
						'ipsieSl1.enabled': true
					})
				);

				expect(message).toContain('nops256');
				expect(ApplicationConfig['ipsieSl1.enabled']).toBe(false);
			} finally {
				await getBucketStore().destroy(bucket._id);
			}
		});
	});

	it('applies without a restart and is recorded in the audit trail', async () => {
		const before = (await adminAuditStore.list({ action: 'settings.update' }))
			.total;

		const res = await saveSettings(cookie, {
			...PREREQUISITES,
			'ipsieSl1.enabled': true
		});

		expect(res.status).toBe(200);
		expect(ApplicationConfig['ipsieSl1.enabled']).toBe(true);
		const { entries, total } = await adminAuditStore.list({
			action: 'settings.update'
		});
		expect(total).toBe(before + 1);
		expect(present(entries[0], 'the newest entry').attributes).toContain(
			'ipsieSl1.enabled'
		);
	});

	it('refuses turning DPoP off while the profile is on', async () => {
		expect(
			(
				await saveSettings(cookie, {
					...PREREQUISITES,
					'ipsieSl1.enabled': true
				})
			).status
		).toBe(200);

		const message = await refusalOf(
			await saveSettings(cookie, { 'dpop.enabled': false })
		);

		expect(message).toContain('dpop.enabled');
		expect(ApplicationConfig['dpop.enabled']).toBe(true);
	});

	it('serves a loopback client again on the next request after the profile is turned off', async () => {
		expect(
			(
				await saveSettings(cookie, {
					...PREREQUISITES,
					'ipsieSl1.enabled': true
				})
			).status
		).toBe(200);
		expect(
			(await saveSettings(cookie, { 'ipsieSl1.enabled': false })).status
		).toBe(200);

		const res = await loopbackSignIn();

		expect(res.status).toBe(303);
		expect(res.headers.get('location')).toContain('/ui/');
	});
});
