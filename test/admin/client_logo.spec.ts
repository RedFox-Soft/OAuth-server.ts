import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import bootstrap from '../test_helper.js';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	adminAuditStore,
	getBucketStore
} from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	LOGO_FORMAT_MESSAGE,
	LOGO_SIZE_MESSAGE
} from 'lib/consts/client_logo.ts';
import { sessionFor } from '../admin_session.ts';
import { answered } from './answered.ts';
import { createAdministrator } from '../administrators.ts';
import {
	JPEG,
	PNG,
	SVG,
	WEBP
} from '../consent_branding/consent_branding.config.ts';

const app = new Elysia().use(resolveAdmin).use(clientRoutes);
const api = treaty(app);

/* PNG bytes over the limit: the signature, then padding — what matters is what the bytes say and weigh. */
const TOO_LARGE = `data:image/png;base64,${Buffer.concat([
	Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
	Buffer.alloc(65_536)
]).toString('base64')}`;

interface View {
	clientId: string;
	logo?: string;
	hasLogo?: boolean;
	policyUri?: string;
	tosUri?: string;
}

/**
 * @proves An administrator gives a client a logo, replaces and removes it, and sets its privacy policy and
 * terms links, through the same routes as every other change to the client — only images that are what
 * they say, within the limit, are ever stored, a refused change leaves the client as it was, the change is
 * audited by name and never by content, and a deleted client takes its logo with it.
 */
describe('a client’s logo and links through the admin API', () => {
	let cookie: string;
	let bucketId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		const user = await createAdministrator(
			'super',
			`logo-${Math.random()}@x.io`
		);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
		const bucket = await getBucketStore().create({
			name: 'Logos',
			slug: `logos-${String(Math.random()).slice(2)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		bucketId = bucket._id;
	});

	function clients() {
		return api.admin.api.projects({ id: bucketId }).clients;
	}

	async function create(extra: Record<string, unknown> = {}) {
		const response = await clients().post(
			{
				clientName: 'Timesheets',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://app.acme.test/cb'],
				tokenEndpointAuthMethod: 'none',
				...extra
			},
			{ headers: { cookie } }
		);
		return response;
	}

	async function created(extra: Record<string, unknown> = {}): Promise<View> {
		const response = await create(extra);
		expect(response.status).toBe(201);
		return response.data as unknown as View;
	}

	async function patch(clientId: string, body: Record<string, unknown>) {
		return clients()({ clientId }).patch(body, { headers: { cookie } });
	}

	async function view(clientId: string): Promise<View> {
		const response = await clients()({ clientId }).get({ headers: { cookie } });
		expect(response.status).toBe(200);
		return response.data as unknown as View;
	}

	async function errorOf(response: { status: number; error: unknown }) {
		expect(response.status).toBe(422);
		const value = (response.error as { value?: { message?: string } }).value;
		return value?.message;
	}

	it('stores a PNG given on create and returns it on the client’s own view', async () => {
		const { clientId, logo } = await created({ logo: PNG });

		expect(logo).toBe(PNG);
		expect((await view(clientId)).logo).toBe(PNG);
	});

	it('replaces the logo with a JPEG and then a WebP', async () => {
		const { clientId } = await created({ logo: PNG });

		expect((await patch(clientId, { logo: JPEG })).status).toBe(200);
		expect((await view(clientId)).logo).toBe(JPEG);
		expect((await patch(clientId, { logo: WEBP })).status).toBe(200);
		expect((await view(clientId)).logo).toBe(WEBP);
	});

	it('lists clients with whether they have a logo, never the image itself', async () => {
		const withLogo = await created({ logo: PNG });
		const without = await created();

		const response = await clients().get({ headers: { cookie } });
		const list = response.data as unknown as View[];

		const listed = (id: string) => list.find((c) => c.clientId === id);
		expect(listed(withLogo.clientId)?.hasLogo).toBe(true);
		expect(listed(without.clientId)?.hasLogo).toBe(false);
		expect(JSON.stringify(list)).not.toContain('data:image');
	});

	it('removes the logo, and removing it again changes nothing', async () => {
		const { clientId } = await created({ logo: PNG });

		expect((await patch(clientId, { logo: null })).status).toBe(200);
		expect((await view(clientId)).logo).toBeUndefined();
		expect(await adapter('ClientLogo').find(clientId)).toBeUndefined();
		expect((await patch(clientId, { logo: null })).status).toBe(200);
	});

	it('records a logo change by the field’s name, and no entry carries the image', async () => {
		const { clientId } = await created({ logo: PNG });
		await patch(clientId, { logo: WEBP });

		const { entries } = await adminAuditStore.list({
			targetId: clientId,
			action: 'client.update'
		});
		expect(entries.map((e) => e.attributes)).toEqual([['logo']]);
		const all = await adminAuditStore.list({ targetId: clientId });
		expect(JSON.stringify(all.entries)).not.toContain('data:image');
	});

	it('takes the logo with it when the client is deleted', async () => {
		const { clientId } = await created({ logo: PNG });

		const deleted = await clients()({ clientId }).delete(undefined, {
			headers: { cookie }
		});

		expect(deleted.status).toBe(200);
		expect(await adapter('ClientLogo').find(clientId)).toBeUndefined();
	});

	it.each([
		['an SVG', SVG],
		['a GIF', 'data:image/gif;base64,R0lGODlhAQABAAAAACw='],
		['PNG bytes labelled as WebP', PNG.replace('image/png', 'image/webp')],
		['text that is not base64', 'data:image/png;base64,!!!!'],
		['an address instead of an image', 'https://app.acme.test/logo.png']
	])(
		'refuses %s, naming the accepted formats, and keeps the logo it had',
		async (_, logo) => {
			const { clientId } = await created({ logo: PNG });

			expect(await errorOf(await patch(clientId, { logo }))).toBe(
				LOGO_FORMAT_MESSAGE
			);
			expect((await view(clientId)).logo).toBe(PNG);
		}
	);

	it('refuses an image over 64 KiB, stating the limit, and keeps the logo it had', async () => {
		const { clientId } = await created({ logo: PNG });

		expect(await errorOf(await patch(clientId, { logo: TOO_LARGE }))).toBe(
			LOGO_SIZE_MESSAGE
		);
		expect((await view(clientId)).logo).toBe(PNG);
	});

	it('creates no client when the logo given with it is refused', async () => {
		const listed = async () =>
			answered((await clients().get({ headers: { cookie } })).data).map(
				(c) => c.clientId
			);
		const before = await listed();

		expect(await errorOf(await create({ logo: SVG }))).toBe(
			LOGO_FORMAT_MESSAGE
		);
		expect(await listed()).toEqual(before);
	});

	it('sets, returns and clears the privacy policy and terms links', async () => {
		const { clientId } = await created({
			policyUri: 'https://app.acme.test/privacy',
			tosUri: 'https://app.acme.test/terms'
		});
		expect(await view(clientId)).toMatchObject({
			policyUri: 'https://app.acme.test/privacy',
			tosUri: 'https://app.acme.test/terms'
		});

		expect((await patch(clientId, { policyUri: null })).status).toBe(200);

		const after = await view(clientId);
		expect(after.policyUri).toBeUndefined();
		expect(after.tosUri).toBe('https://app.acme.test/terms');
		const { entries } = await adminAuditStore.list({
			targetId: clientId,
			action: 'client.update'
		});
		expect(entries.map((e) => e.attributes)).toEqual([['policyUri']]);
	});

	it.each([
		['policyUri', 'http://app.acme.test/privacy'],
		['tosUri', 'http://app.acme.test/terms'],
		['policyUri', '/privacy']
	])('refuses a %s that is not an https address', async (field, value) => {
		const { clientId } = await created();

		expect(await errorOf(await patch(clientId, { [field]: value }))).toBe(
			`${field} must be an https URL`
		);
		expect((await view(clientId))[field as keyof View]).toBeUndefined();
	});
});
