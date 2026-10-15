import { describe, it, expect, beforeAll } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { provider } from '../scim/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';

const app = new Elysia({ normalize: false }).use(adminApiRoutes);

async function call(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
): Promise<{ status: number; body: unknown }> {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
	const text = await response.text();
	return { status: response.status, body: text ? JSON.parse(text) : null };
}

const Page = Type.Object({
	entries: Type.Array(
		Type.Object({ action: Type.String(), targetId: Type.String() })
	)
});

async function trail(cookie: string, project: string): Promise<string[]> {
	const res = await call(
		'GET',
		`/admin/api/audit?${new URLSearchParams({ project, actionPrefix: 'federation.' }).toString()}`,
		cookie
	);
	expect(res.status).toBe(200);
	return shaped(Page, res.body)
		.entries.map((e) => e.action)
		.sort();
}

interface World {
	ownerCookie: string;
	outsiderCookie: string;
	project: UserBucket;
}

let w: World;

/**
 * @proves A team reads in its project's audit trail every change made to the project's identity providers,
 * as it reads every other change to the project, and an administrator of another team reads none of them.
 */
describe("a project's identity provider changes, in the audit trail", () => {
	beforeAll(async () => {
		await ensureAdminSeed();
		const owner = await createAdministrator('plain');
		const outsider = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		await regularGroup([outsider]);
		const project = await getBucketStore().create({
			name: 'Acme customers',
			slug: `f${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')
				.slice(0, 10)}`,
			ownerGroupId: team._id,
			federation: [provider('corp'), provider('partner')]
		});
		forgetBucketAddresses();
		const ownerCookie = await cookieFor(owner);
		const base = `/admin/api/projects/${project._id}/federation`;
		const steps = [
			await call('PATCH', `${base}/corp`, ownerCookie, {
				displayName: 'Corporate'
			}),
			await call('POST', `${base}/partner/move`, ownerCookie, {
				direction: 'up'
			}),
			await call('DELETE', `${base}/partner`, ownerCookie)
		];
		for (const step of steps) expect(step.status).toBeLessThan(300);
		w = { ownerCookie, outsiderCookie: await cookieFor(outsider), project };
	});

	it('lists the change, the reordering and the removal of a provider to the team that owns the project', async () => {
		expect(await trail(w.ownerCookie, w.project._id)).toEqual([
			'federation.provider.delete',
			'federation.provider.move',
			'federation.provider.update'
		]);
	});

	it('lists none of them to an administrator of another team', async () => {
		expect(await trail(w.outsiderCookie, w.project._id)).toEqual([]);
	});
});
