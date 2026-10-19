import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import bootstrap, { changeClient } from '../test_helper.js';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	adminAuditStore,
	getBucketStore
} from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { PRIMARY_COLOR_MESSAGE } from 'lib/consts/client_branding.ts';
import { paintedAccent } from 'lib/html/theme/accent.ts';
import { sessionFor } from '../admin_session.ts';
import { answered } from './answered.ts';
import { createAdministrator } from '../administrators.ts';

const app = new Elysia().use(resolveAdmin).use(clientRoutes);
const api = treaty(app);

interface View {
	clientId: string;
	primaryColor?: string;
	paintedPrimaryColor?: { light: string; dark: string; adjusted: boolean };
}

/**
 * @proves An administrator gives a client a primary colour, changes and removes it, through the same routes as
 * every other change to the client, and is told the shades its pages will actually show — only a colour written
 * #rrggbb is ever stored, a refused change leaves the client as it was, and the change is audited by name and
 * never by value.
 */
describe('a client’s primary colour through the admin API', () => {
	let cookie: string;
	let bucketId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		const user = await createAdministrator(
			'super',
			`colour-${Math.random()}@x.io`
		);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
		const bucket = await getBucketStore().create({
			name: 'Colours',
			slug: `colours-${String(Math.random()).slice(2)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		bucketId = bucket._id;
	});

	function clients() {
		return api.admin.api.projects({ id: bucketId }).clients;
	}

	async function create(extra: Record<string, unknown> = {}) {
		return clients().post(
			{
				clientName: 'Timesheets',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://app.acme.test/cb'],
				tokenEndpointAuthMethod: 'none',
				...extra
			},
			{ headers: { cookie } }
		);
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

	it('stores a colour given on create in lower case, with the shades its pages will show', async () => {
		const { primaryColor, paintedPrimaryColor } = await created({
			primaryColor: '#2F7D32'
		});
		const painted = paintedAccent('#2f7d32');

		expect(primaryColor).toBe('#2f7d32');
		expect(paintedPrimaryColor).toEqual({
			light: painted?.light.primary ?? '',
			dark: painted?.dark.primary ?? '',
			adjusted: false
		});
	});

	it('replaces the colour on an edit', async () => {
		const { clientId } = await created({ primaryColor: '#2f7d32' });

		expect((await patch(clientId, { primaryColor: '#c2185b' })).status).toBe(
			200
		);
		expect((await view(clientId)).primaryColor).toBe('#c2185b');
	});

	it('accepts a colour too light for a white label, and reports the darker shade its pages will show', async () => {
		const { clientId } = await created();

		await patch(clientId, { primaryColor: '#ffe066' });
		const { primaryColor, paintedPrimaryColor } = await view(clientId);

		expect(primaryColor).toBe('#ffe066');
		expect(paintedPrimaryColor?.adjusted).toBe(true);
		expect(paintedPrimaryColor?.light).toBe(
			paintedAccent('#ffe066')?.light.primary
		);
		expect(paintedPrimaryColor?.light).not.toBe('#ffe066');
	});

	it('removes the colour with null, from the stored record too', async () => {
		const { clientId } = await created({ primaryColor: '#2f7d32' });

		expect((await patch(clientId, { primaryColor: null })).status).toBe(200);

		const after = await view(clientId);
		expect(after.primaryColor).toBeUndefined();
		expect(after.paintedPrimaryColor).toBeUndefined();
		expect(
			(await adapter('Client').find(clientId))?.primaryColor
		).toBeUndefined();
	});

	it('removes nothing, and succeeds, when the client has no colour', async () => {
		const { clientId } = await created();

		expect((await patch(clientId, { primaryColor: null })).status).toBe(200);
		expect((await view(clientId)).primaryColor).toBeUndefined();
	});

	it('keeps the colour when an edit does not name it', async () => {
		const { clientId } = await created({ primaryColor: '#2f7d32' });

		expect((await patch(clientId, { clientName: 'Rota' })).status).toBe(200);
		expect((await view(clientId)).primaryColor).toBe('#2f7d32');
	});

	it('lists the colour, without working out the shades, for every client of the project', async () => {
		const { clientId } = await created({ primaryColor: '#2f7d32' });

		const listed = answered(
			(await clients().get({ headers: { cookie } })).data
		).find((c) => c.clientId === clientId) as View | undefined;

		expect(listed?.primaryColor).toBe('#2f7d32');
		expect(listed?.paintedPrimaryColor).toBeUndefined();
	});

	it('records a colour change by the field’s name, and no entry carries the colour', async () => {
		const { clientId } = await created();
		await patch(clientId, { primaryColor: '#c2185b' });

		const { entries } = await adminAuditStore.list({
			targetId: clientId,
			action: 'client.update'
		});
		expect(entries.map((e) => e.attributes)).toEqual([['primaryColor']]);
		const all = await adminAuditStore.list({ targetId: clientId });
		expect(JSON.stringify(all.entries)).not.toContain('c2185b');
	});

	it.each([
		['shorthand', '#abc'],
		['five digits', '#2f7d3'],
		['eight digits', '#2f7d32ff'],
		['no hash', '2f7d32'],
		['a colour name', 'green'],
		['a colour function', 'rgb(47,125,50)'],
		['a value that would break out of a style rule', '#2f7d32;}body{x:y'],
		['a leading space', ' #2f7d32'],
		['nothing', '']
	])(
		'refuses %s, naming the accepted form, and keeps the colour it had',
		async (_, primaryColor) => {
			const { clientId } = await created({ primaryColor: '#2f7d32' });

			expect(await errorOf(await patch(clientId, { primaryColor }))).toBe(
				PRIMARY_COLOR_MESSAGE
			);
			expect((await view(clientId)).primaryColor).toBe('#2f7d32');
		}
	);

	it('creates no client when the colour given with it is refused', async () => {
		const listed = async () =>
			answered((await clients().get({ headers: { cookie } })).data).map(
				(c) => c.clientId
			);
		const before = await listed();

		expect(await errorOf(await create({ primaryColor: 'green' }))).toBe(
			PRIMARY_COLOR_MESSAGE
		);
		expect(await listed()).toEqual(before);
	});

	it('shows no colour for a stored value that is not a colour', async () => {
		const { clientId } = await created();
		await changeClient(clientId, { primaryColor: '#2f7d32;}body{x:y' });

		const shown = await view(clientId);

		expect(shown.primaryColor).toBeUndefined();
		expect(shown.paintedPrimaryColor).toBeUndefined();
	});
});
