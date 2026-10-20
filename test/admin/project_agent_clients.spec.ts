import { describe, it, expect, beforeAll, afterEach } from 'bun:test';
import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { ISSUER } from 'lib/configs/env.js';
import nanoid from 'lib/helpers/nanoid.ts';
import { createAdministrator } from '../administrators.ts';
import { sessionFor } from '../admin_session.ts';

let cookie: string;
let projectId: string;
let slug: string;
const saved = {
	cimd: ApplicationConfig['clientIdMetadataDocument.enabled'],
	registration: ApplicationConfig['registration.enabled'],
	token: ApplicationConfig['registration.initialAccessToken']
};

async function json(path: string, headers: Record<string, string> = {}) {
	const response = await elysia.handle(
		new Request(`${ISSUER}${path}`, { headers })
	);
	return (await response.json()) as Record<string, unknown>;
}

async function stated() {
	const project = await json(`/admin/api/projects/${projectId}`, { cookie });
	return project.agentClients as {
		urlClientIds: boolean;
		selfRegistration: string;
	};
}

/**
 * @proves A project's administrator is told how agent hosts can get a client identity at it, and what they are told
 * is what the project's public discovery document advertises.
 */
describe('how agent hosts get in, as a project states it', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		const user = await createAdministrator('super', `ac-${nanoid()}@x.io`);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
		slug = `ac-${nanoid()
			.toLowerCase()
			.replace(/[^a-z0-9]/g, '')}`;
		projectId = (
			await getBucketStore().create({
				name: 'agent clients',
				slug,
				ownerGroupId: UNASSIGNED_GROUP_ID
			})
		)._id;
		forgetBucketAddresses();
	});

	afterEach(() => {
		ApplicationConfig['clientIdMetadataDocument.enabled'] = saved.cimd;
		ApplicationConfig['registration.enabled'] = saved.registration;
		ApplicationConfig['registration.initialAccessToken'] = saved.token;
	});

	it('reports URL client IDs accepted exactly when its discovery advertises them', async () => {
		for (const enabled of [true, false]) {
			ApplicationConfig['clientIdMetadataDocument.enabled'] = enabled;
			const discovery = await json(`/${slug}/.well-known/openid-configuration`);
			expect((await stated()).urlClientIds).toBe(
				discovery.client_id_metadata_document_supported === true
			);
		}
	});

	it('reports self-registration off exactly when its discovery serves no registration endpoint', async () => {
		for (const enabled of [true, false]) {
			ApplicationConfig['registration.enabled'] = enabled;
			ApplicationConfig['registration.initialAccessToken'] = false;
			const discovery = await json(`/${slug}/.well-known/openid-configuration`);
			const { selfRegistration } = await stated();
			expect(selfRegistration === 'off').toBe(
				discovery.registration_endpoint === undefined
			);
		}
	});
});
