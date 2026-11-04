import { describe, it, expect, beforeAll, afterEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import bootstrap from '../test_helper.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig, applySettings } from 'lib/configs/application.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { situation } from 'lib/admin/ui/pages/applications/situations.ts';
import {
	GUIDE_FLAG_SETTINGS,
	GUIDE_SITUATIONS
} from 'lib/consts/situation_guide.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

const app = new Elysia().use(resolveAdmin).use(clientRoutes);
const client = treaty(app);

/**
 * @proves an application situation the guide offers as ready creates an application the route accepts
 */
describe('creating an application from a guide situation with only the switches it declares', () => {
	let cookie: string;
	let projectId: string;
	const touched = new Map<string, unknown>();

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'presets' });
		await ensureAdminSeed();
		const user = await createAdministrator('super', `gp-${nanoid()}@x.io`);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
		const id = nanoid()
			.toLowerCase()
			.replace(/[^a-z0-9]/g, '');
		projectId = (
			await getBucketStore().create({
				name: `guide presets ${id}`,
				slug: `gp-${id}`,
				ownerGroupId: UNASSIGNED_GROUP_ID
			})
		)._id;
	});

	afterEach(() => {
		applySettings(Object.fromEntries(touched));
		touched.clear();
	});

	for (const guide of GUIDE_SITUATIONS) {
		if (!guide.preset) continue;
		const preset = situation(guide.preset);
		const { expand } = preset;
		if (!expand) continue;
		it(`accepts what "${guide.id}" offers with only ${guide.needs.flags?.join(', ') ?? 'no switch'} on`, async () => {
			const changes: Record<string, unknown> = {};
			for (const flag of guide.needs.flags ?? []) {
				const key = GUIDE_FLAG_SETTINGS[flag];
				touched.set(key, (ApplicationConfig as Record<string, unknown>)[key]);
				changes[key] = true;
			}
			expect(applySettings(changes).state).toBe('applied');

			const created = await client.admin.api
				.projects({ id: projectId })
				.clients.post(
					{
						clientName: `guide ${guide.id}`,
						...expand(preset.devAddress ?? 'http://localhost:3000')
					},
					{ headers: { cookie } }
				);
			expect(created.status).toBe(201);
		});
	}
});
