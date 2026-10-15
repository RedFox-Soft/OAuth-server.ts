import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Type } from '@sinclair/typebox';
import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { createClient } from 'lib/admin/clients/service.ts';
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
const Preview = Type.Object({
	from: Type.String(),
	to: Type.String(),
	expect: Type.Object({
		applications: Type.Number(),
		connections: Type.Number(),
		providers: Type.Number(),
		resources: Type.Number()
	})
});
const Jwks = Type.Object({
	keys: Type.Array(Type.Object({ kid: Type.String() }))
});
const AuditPage = Type.Object({
	entries: Type.Array(
		Type.Object({
			action: Type.String(),
			from: Type.Optional(Type.String()),
			to: Type.Optional(Type.String())
		})
	)
});

let operator: Caller;

async function ownProject(team: Caller, slug: string): Promise<string> {
	return shaped(Created, (await createProject(team, { slug })).body)._id;
}

/* The preview, then the confirmation carrying its counts — the two calls the console makes. */
async function moveTo(
	team: Caller,
	id: string,
	body: Record<string, unknown>
): Promise<{ status: number; body: unknown }> {
	const path = `/admin/api/projects/${id}/address`;
	const preview = await call('POST', path, team.cookie, body);
	if (preview.status !== 409) return preview;
	return call('POST', path, team.cookie, {
		...body,
		confirm: true,
		expect: shaped(Preview, preview.body).expect
	});
}

async function issuerAt(host: string, path: string): Promise<number> {
	return (await elysia.handle(new Request(`http://${host}${path}`))).status;
}

async function kidsAt(host: string, path: string): Promise<string[]> {
	const response = await elysia.handle(new Request(`http://${host}${path}`));
	return shaped(Jwks, await response.json())
		.keys.map((key) => key.kid)
		.sort();
}

/**
 * @proves A team moves its own project between a path and a subdomain as it changes any address — after a
 * preview it confirms, while nothing depends on the project, and only into a form the operator allows — and
 * the project then answers at the new address alone, with the keys it had, and the trail says which issuer
 * it left and which it took.
 */
describe('moving a project between a path and a subdomain', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'subdomain_projects' });
		await ensureAdminSeed();
		operator = await superAdministrator();
	});

	beforeEach(async () => {
		forgetBucketAddresses();
		await saveAddressForms(operator.cookie, 'both');
	});

	it('answers at the subdomain and no longer at the path once the team confirms, with the same signing keys', async () => {
		const team = await teamOwner();
		const slug = freshSlug('mover');
		const id = await ownProject(team, slug);
		const keysBefore = await kidsAt('e.ly', `/${slug}/jwks`);

		const moved = await moveTo(team, id, { slug, addressForm: 'subdomain' });
		forgetBucketAddresses();

		expect(moved.status).toBe(200);
		expect([
			await issuerAt(`${slug}.e.ly`, '/.well-known/openid-configuration'),
			await issuerAt('e.ly', `/${slug}/.well-known/openid-configuration`)
		]).toEqual([200, 404]);
		expect(await kidsAt(`${slug}.e.ly`, '/jwks')).toEqual(keysBefore);
	});

	it('answers at the path and no longer at the subdomain once moved back', async () => {
		const team = await teamOwner();
		const slug = freshSlug('back');
		const id = await ownProject(team, slug);
		await moveTo(team, id, { slug, addressForm: 'subdomain' });

		const moved = await moveTo(team, id, { slug, addressForm: 'path' });
		forgetBucketAddresses();

		expect(moved.status).toBe(200);
		expect([
			await issuerAt('e.ly', `/${slug}/.well-known/openid-configuration`),
			await issuerAt(`${slug}.e.ly`, '/.well-known/openid-configuration')
		]).toEqual([200, 404]);
	});

	it('changes nothing without confirmation, and previews the issuer left and the issuer taken', async () => {
		const team = await teamOwner();
		const slug = freshSlug('look');
		const id = await ownProject(team, slug);

		const preview = await call(
			'POST',
			`/admin/api/projects/${id}/address`,
			team.cookie,
			{ slug, addressForm: 'subdomain' }
		);
		forgetBucketAddresses();

		expect(preview.status).toBe(409);
		expect(shaped(Preview, preview.body)).toMatchObject({
			from: `http://e.ly/${slug}`,
			to: `http://${slug}.e.ly`
		});
		expect(
			await issuerAt('e.ly', `/${slug}/.well-known/openid-configuration`)
		).toBe(200);
	});

	it('refuses a team the move while an application depends on the project', async () => {
		const team = await teamOwner();
		const slug = freshSlug('used');
		const id = await ownProject(team, slug);
		await createClient(id, {
			clientId: `app-${slug}`,
			redirectUris: ['https://app.example.com/cb'],
			grantTypes: ['authorization_code'],
			tokenEndpointAuthMethod: 'none'
		});

		const refused = await moveTo(team, id, { slug, addressForm: 'subdomain' });

		expect(refused.status).toBe(403);
	});

	it('refuses a team a move into a form the setting no longer offers', async () => {
		const team = await teamOwner();
		const slug = freshSlug('locked');
		const id = await ownProject(team, slug);
		await saveAddressForms(operator.cookie, 'path');

		const refused = await moveTo(team, id, { slug, addressForm: 'subdomain' });

		expect(refused.status).toBe(403);
	});

	it('refuses a move to the address the project already has', async () => {
		const team = await teamOwner();
		const slug = freshSlug('same');
		const id = await ownProject(team, slug);

		const refused = await call(
			'POST',
			`/admin/api/projects/${id}/address`,
			team.cookie,
			{ slug, addressForm: 'path' }
		);

		expect(refused.status).toBe(409);
		expect(JSON.stringify(refused.body)).toContain('already has that address');
	});

	it('records the issuer left and the issuer taken, readable by the team', async () => {
		const team = await teamOwner();
		const slug = freshSlug('traced');
		const id = await ownProject(team, slug);
		await moveTo(team, id, { slug, addressForm: 'subdomain' });

		const trail = await call(
			'GET',
			`/admin/api/audit?${new URLSearchParams({ project: id, actionPrefix: 'project.address.' }).toString()}`,
			team.cookie
		);
		const entry = shaped(AuditPage, trail.body).entries.find(
			(e) => e.action === 'project.address.change'
		);

		expect(entry).toMatchObject({
			from: `http://e.ly/${slug}`,
			to: `http://${slug}.e.ly`
		});
	});
});
