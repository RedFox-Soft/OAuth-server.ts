import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { BUILT_IN_PLANS } from 'lib/consts/plans.ts';
import { elysia } from 'lib/index.ts';
import * as slugs from 'lib/plans/slug.ts';
import {
	call,
	createProject,
	freshSlug,
	idOf,
	refusalOf,
	storeCatalogue,
	storeFree,
	superAdmin,
	tenant,
	withPlans,
	type Caller
} from './admin.ts';

let operator: Caller;

const GENERATED = /^[a-z0-9]{8}$/;

async function slugOf(id: string): Promise<string | undefined> {
	return (await getBucketStore().find(id))?.slug;
}

async function issuerAt(url: string): Promise<string | undefined> {
	const response = await elysia.handle(new Request(url));
	if (response.status !== 200) return undefined;
	return ((await response.json()) as { issuer?: string }).issuer;
}

async function saveAddressForms(value: 'path' | 'subdomain' | 'both') {
	const saved = await call('PUT', '/admin/api/settings', operator.cookie, {
		'projects.addressForms': value
	});
	if (saved.status !== 200) throw new Error('saving the address forms failed');
}

/**
 * @proves On a plan without a custom slug, a tenant's new project is given a random eight-character address name in
 * whichever form the instance offers and answers there as its issuer; naming one, at creation or by an address
 * change, is refused with the plan named, while switching form under the same name is not; a plan with a custom slug,
 * a super administrator and an instance with plans off name their slug as before.
 */
describe('a project’s address name on its plan', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'plans' });
		await ensureAdminSeed();
		operator = await superAdmin();
	});

	beforeEach(async () => {
		forgetBucketAddresses();
		await storeCatalogue([...BUILT_IN_PLANS]);
		await saveAddressForms('both');
		await withPlans(operator, true);
	});

	it('gives a tenant’s project a generated path, which is its issuer', async () => {
		const id = idOf(
			await createProject(await tenant(), { addressForm: 'path' })
		);
		const slug = String(await slugOf(id));
		forgetBucketAddresses();

		expect(slug).toMatch(GENERATED);
		expect(
			await issuerAt(`http://e.ly/${slug}/.well-known/openid-configuration`)
		).toBe(`http://e.ly/${slug}`);
	});

	it('gives a tenant’s project a generated subdomain, which is its issuer', async () => {
		const id = idOf(
			await createProject(await tenant(), { addressForm: 'subdomain' })
		);
		const slug = String(await slugOf(id));
		forgetBucketAddresses();

		expect(slug).toMatch(GENERATED);
		expect(
			await issuerAt(`http://${slug}.e.ly/.well-known/openid-configuration`)
		).toBe(`http://${slug}.e.ly`);
	});

	it('refuses a slug the tenant names, at creation', async () => {
		const refusal = refusalOf(
			await createProject(await tenant(), { slug: freshSlug('mine') })
		);

		expect(refusal.limit).toEqual({
			name: 'customSlug',
			plan: { id: 'free', name: 'Free' }
		});
	});

	it('refuses a new slug by address change, and admits the same slug in the other form', async () => {
		const owner = await tenant();
		const id = idOf(await createProject(owner, { addressForm: 'path' }));
		const slug = String(await slugOf(id));
		const path = `/admin/api/projects/${id}/address`;

		const renamed = await call('POST', path, owner.cookie, {
			slug: freshSlug('mine')
		});
		const switched = await call('POST', path, owner.cookie, {
			slug,
			addressForm: 'subdomain'
		});

		expect(refusalOf(renamed).limit.name).toBe('customSlug');
		expect(
			(switched.body as { confirmationRequired?: boolean }).confirmationRequired
		).toBe(true);
	});

	it('lets a project on a plan with a custom slug name it', async () => {
		await storeFree({}, { customSlug: true });
		const slug = freshSlug('named');

		const id = idOf(await createProject(await tenant(), { slug }));

		expect(await slugOf(id)).toBe(slug);
	});

	it('lets a super administrator name the slug', async () => {
		const slug = freshSlug('op');

		const id = idOf(await createProject(operator, { slug }));

		expect(await slugOf(id)).toBe(slug);
	});

	it('still needs an address from a tenant while plans are off', async () => {
		await withPlans(operator, false);

		expect((await createProject(await tenant())).status).toBe(400);
	});

	it('draws again when a drawn name is reserved, taken or a reserved subdomain, and uses the first free one', async () => {
		const taken = freshSlug('taken');
		idOf(await createProject(operator, { slug: taken }));
		const free = `free${Math.random().toString(36).slice(2, 6)}`;
		const draws = spyOn(slugs, 'drawSlug')
			.mockReturnValueOnce('admin')
			.mockReturnValueOnce(taken)
			.mockReturnValueOnce('www')
			.mockReturnValueOnce(free);
		try {
			const id = idOf(
				await createProject(await tenant(), { addressForm: 'subdomain' })
			);

			expect(await slugOf(id)).toBe(free);
			expect(draws).toHaveBeenCalledTimes(4);
		} finally {
			draws.mockRestore();
		}
	});

	it('gives up after five refused names, creating nothing', async () => {
		const owner = await tenant();
		const before = (await getBucketStore().listByGroup(owner.teamId)).length;
		const draws = spyOn(slugs, 'drawSlug').mockReturnValue('admin');
		try {
			const answered = await createProject(owner);

			expect(answered.status).toBe(500);
			expect(draws).toHaveBeenCalledTimes(5);
			expect((await getBucketStore().listByGroup(owner.teamId)).length).toBe(
				before
			);
		} finally {
			draws.mockRestore();
		}
	});
});
