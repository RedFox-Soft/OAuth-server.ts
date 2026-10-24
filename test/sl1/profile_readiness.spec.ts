import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { shaped } from 'test/shape.ts';
import { send } from '../feature_gate/helpers.ts';
import { superAdminCookie } from '../settings_apply/helpers.ts';

const Readiness = Type.Object({
	enabled: Type.Boolean(),
	canEnable: Type.Boolean(),
	settings: Type.Array(
		Type.Object({
			key: Type.String(),
			required: Type.Unknown(),
			actual: Type.Unknown()
		})
	),
	issuers: Type.Array(
		Type.Object({
			issuer: Type.String(),
			projectId: Type.Optional(Type.String()),
			signingAlgorithms: Type.Array(Type.String())
		})
	),
	clients: Type.Array(
		Type.Object({
			projectId: Type.String(),
			clientId: Type.String(),
			clientName: Type.Optional(Type.String()),
			violations: Type.Array(
				Type.Object({
					rule: Type.String(),
					attribute: Type.String(),
					value: Type.Optional(Type.String()),
					cites: Type.String()
				})
			)
		})
	)
});

async function readiness(cookie: string) {
	const res = await send('/admin/api/settings/ipsie-sl1/readiness', {
		method: 'GET',
		headers: { cookie }
	});
	expect(res.status).toBe(200);
	return shaped(Readiness, await res.json());
}

/**
 * @proves An operator learns, before switching the IPSIE SL1 profile on and without switching it, every setting
 * that stands in the way, every issuer that cannot sign with its default algorithm, and every application it would
 * refuse, each with the rule it breaks.
 */
describe('IPSIE SL1 readiness', () => {
	let cookie: string;
	let projectId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'profile_switch' });
		await ensureAdminSeed();
		cookie = await superAdminCookie();
		projectId = (
			await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: 'Readiness project',
				slug: 'readyproject'
			})
		)._id;
	});

	it('names the unmet settings, the issuer without a PS256 signer and each refused application, enabling nothing', async () => {
		const answer = await readiness(cookie);

		expect(answer.enabled).toBe(false);
		expect(answer.canEnable).toBe(false);
		const unmet = answer.settings.map((s) => s.key);
		expect(unmet).toContain('dpop.enabled');
		expect(unmet).toContain('encryption.enabled');
		expect(answer.issuers.map((i) => i.projectId)).toContain(projectId);
		const rulesOf = (clientId: string) =>
			answer.clients
				.find((c) => c.clientId === clientId)
				?.violations.map((v) => v.rule);
		expect(rulesOf('sl1-loopback')).toContain('http_redirect_uri');
		expect(rulesOf('sl1-loopback')).toContain('default_algorithm');
		expect(rulesOf('sl1-hmac')).toContain('client_secret_jwt');
		expect(ApplicationConfig['ipsieSl1.enabled']).toBe(false);
	});

	it('leaves the administrators’ project out of the applications it lists', async () => {
		const answer = await readiness(cookie);

		expect(answer.clients.map((c) => c.projectId)).not.toContain(
			ADMIN_BUCKET_ID
		);
	});
});
