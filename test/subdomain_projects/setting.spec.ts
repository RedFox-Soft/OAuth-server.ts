import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Type } from '@sinclair/typebox';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { elysia } from 'lib/index.ts';
import { shaped } from 'test/shape.ts';
import {
	call,
	createProject,
	freshSlug,
	saveAddressForms,
	superAdministrator,
	teamOwner,
	type Caller
} from './admin.ts';

const Created = Type.Object({ _id: Type.String() });
const Detail = Type.Object({
	addressForm: Type.String(),
	issuer: Type.Union([Type.String(), Type.Null()])
});
const Me = Type.Object({
	can: Type.Object({ addressForms: Type.Array(Type.String()) })
});
const Refusal = Type.Object({ message: Type.String() });

let operator: Caller;

async function addressFormOf(caller: Caller, id: string): Promise<string> {
	return shaped(
		Detail,
		(await call('GET', `/admin/api/projects/${id}`, caller.cookie)).body
	).addressForm;
}

/**
 * @proves The operator's address-form setting decides which forms a team may give a project — path,
 * subdomain or either — while a super administrator may give any form and a hostname stays theirs alone.
 */
describe('the address forms a team may give a project', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'subdomain_projects' });
		await ensureAdminSeed();
		operator = await superAdministrator();
	});

	beforeEach(() => {
		forgetBucketAddresses();
	});

	describe('under path only', () => {
		beforeEach(async () => {
			await saveAddressForms(operator.cookie, 'path');
		});

		it('gives a team a path', async () => {
			const created = await createProject(await teamOwner(), {
				slug: freshSlug('p')
			});

			expect(created.status).toBe(201);
		});

		it('refuses a team a subdomain, naming the setting', async () => {
			const refused = await createProject(await teamOwner(), {
				slug: freshSlug('s'),
				addressForm: 'subdomain'
			});

			expect(refused.status).toBe(403);
			expect(shaped(Refusal, refused.body).message).toContain(
				'projects.addressForms'
			);
		});

		it('tells a team it may give a path only', async () => {
			const me = await call('GET', '/admin/api/me', (await teamOwner()).cookie);

			expect(shaped(Me, me.body).can.addressForms).toEqual(['path']);
		});
	});

	describe('under subdomain only', () => {
		beforeEach(async () => {
			await saveAddressForms(operator.cookie, 'subdomain');
		});

		it('gives a team a subdomain', async () => {
			const team = await teamOwner();
			const created = await createProject(team, {
				slug: freshSlug('s'),
				addressForm: 'subdomain'
			});

			expect(created.status).toBe(201);
			expect(await addressFormOf(team, shaped(Created, created.body)._id)).toBe(
				'subdomain'
			);
		});

		it('refuses a team a path, naming the setting', async () => {
			const refused = await createProject(await teamOwner(), {
				slug: freshSlug('p'),
				addressForm: 'path'
			});

			expect(refused.status).toBe(403);
			expect(shaped(Refusal, refused.body).message).toContain(
				'projects.addressForms'
			);
		});

		it('refuses a team a slug sent without a form, which means a path', async () => {
			const refused = await createProject(await teamOwner(), {
				slug: freshSlug('p')
			});

			expect(refused.status).toBe(403);
		});
	});

	describe('under both', () => {
		beforeEach(async () => {
			await saveAddressForms(operator.cookie, 'both');
		});

		it('gives a team either form', async () => {
			const team = await teamOwner();
			const subdomain = await createProject(team, {
				slug: freshSlug('s'),
				addressForm: 'subdomain'
			});
			const path = await createProject(team, { slug: freshSlug('p') });

			expect([subdomain.status, path.status]).toEqual([201, 201]);
		});

		it('reads a slug sent without a form as a path', async () => {
			const team = await teamOwner();
			const created = await createProject(team, { slug: freshSlug('p') });

			expect(await addressFormOf(team, shaped(Created, created.body)._id)).toBe(
				'path'
			);
		});

		it('offers a team the subdomain first', async () => {
			const me = await call('GET', '/admin/api/me', (await teamOwner()).cookie);

			expect(shaped(Me, me.body).can.addressForms).toEqual([
				'subdomain',
				'path'
			]);
		});
	});

	describe('whatever the setting', () => {
		beforeEach(async () => {
			await saveAddressForms(operator.cookie, 'path');
		});

		it('gives a super administrator a subdomain', async () => {
			const created = await createProject(operator, {
				slug: freshSlug('s'),
				addressForm: 'subdomain'
			});

			expect(created.status).toBe(201);
		});

		it('gives a super administrator a hostname of its own', async () => {
			const created = await createProject(operator, {
				host: `${freshSlug('h')}.example.org`
			});

			expect(created.status).toBe(201);
		});

		it('refuses a team a hostname of its own under every value', async () => {
			const team = await teamOwner();
			const statuses: number[] = [];
			for (const value of ['path', 'subdomain', 'both'] as const) {
				await saveAddressForms(operator.cookie, value);
				statuses.push(
					(
						await createProject(team, {
							host: `${freshSlug('h')}.example.org`
						})
					).status
				);
			}

			expect(statuses).toEqual([403, 403, 403]);
		});

		it('refuses a form on a hostname, which is a form of its own', async () => {
			const refused = await createProject(operator, {
				host: `${freshSlug('h')}.example.org`,
				addressForm: 'subdomain'
			});

			expect(refused.status).toBe(400);
		});
	});

	describe('after the setting changes', () => {
		it('judges the next request by the saved value, without a restart', async () => {
			const team = await teamOwner();
			await saveAddressForms(operator.cookie, 'path');
			const before = await createProject(team, {
				slug: freshSlug('s'),
				addressForm: 'subdomain'
			});
			await saveAddressForms(operator.cookie, 'subdomain');
			const after = await createProject(team, {
				slug: freshSlug('s'),
				addressForm: 'subdomain'
			});

			expect([before.status, after.status]).toEqual([403, 201]);
		});

		it('keeps serving a subdomain project at its subdomain once subdomains are no longer offered', async () => {
			await saveAddressForms(operator.cookie, 'subdomain');
			const team = await teamOwner();
			const slug = freshSlug('kept');
			await createProject(team, { slug, addressForm: 'subdomain' });
			await saveAddressForms(operator.cookie, 'path');
			forgetBucketAddresses();

			const response = await elysia.handle(
				new Request(`http://${slug}.e.ly/.well-known/openid-configuration`)
			);

			expect(response.status).toBe(200);
			expect(
				shaped(Type.Object({ issuer: Type.String() }), await response.json())
					.issuer
			).toBe(`http://${slug}.e.ly`);
		});

		it('lets the team still edit a project whose form is no longer offered', async () => {
			await saveAddressForms(operator.cookie, 'subdomain');
			const team = await teamOwner();
			const created = await createProject(team, {
				slug: freshSlug('kept'),
				addressForm: 'subdomain'
			});
			await saveAddressForms(operator.cookie, 'path');

			const renamed = await call(
				'PATCH',
				`/admin/api/projects/${shaped(Created, created.body)._id}`,
				team.cookie,
				{ name: 'Renamed' }
			);

			expect(renamed.status).toBe(200);
		});
	});
});
