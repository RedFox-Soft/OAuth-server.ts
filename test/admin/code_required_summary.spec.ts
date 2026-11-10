import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getSmtpSettingsStore } from 'lib/adapters/index.ts';
import type { SmtpSettings, UserBucket } from 'lib/adapters/types.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';

async function request(
	method: string,
	path: string,
	cookie: string,
	body?: Readonly<Record<string, unknown>>
): Promise<{ status: number; body: unknown }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text ? (JSON.parse(text) as unknown) : null
	};
}

const Summary = Type.Object({
	codeRequiredApps: Type.Array(
		Type.Object({ id: Type.String(), name: Type.String() })
	)
});
const Readiness = Type.Object({
	projectsWithoutSecondFactor: Type.Array(
		Type.Object({ projectId: Type.String(), name: Type.String() })
	)
});
const Created = Type.Object({ clientId: Type.String() });

const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Accounts',
	fromEmail: 'accounts@example.test'
};
const NO_MAIL: SmtpSettings = { ...MAIL, host: '', fromEmail: '' };

/**
 * @proves The console tells an administrator where a code is asked — the applications of a project that require one
 * are listed on its Sign-in tab — and the IPSIE SL1 readiness names the projects where nobody new could give a second
 * factor, because the project neither requires one nor lets people set one up.
 */
describe('where a code is asked, as the console reads it', () => {
	let cookie: string;
	let superCookie: string;
	let ownerGroupId: string;
	let previousMail: SmtpSettings | null = null;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		const owner = await createAdministrator();
		ownerGroupId = (await regularGroup([owner]))._id;
		cookie = await cookieFor(owner);
		superCookie = await cookieFor(await createAdministrator('super'));
		previousMail = await getSmtpSettingsStore().get();
		await getSmtpSettingsStore().set(MAIL);
	});

	afterAll(async () => {
		await getSmtpSettingsStore().set(previousMail ?? NO_MAIL);
	});

	async function project(fields: Partial<UserBucket> = {}) {
		const created = await getBucketStore().create({
			name: `where ${nanoid()}`,
			slug: `wc-${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')}`,
			ownerGroupId
		});
		return (await getBucketStore().update(created._id, fields)) ?? created;
	}

	it('lists the applications that require a code on the project’s summary', async () => {
		const bucket = await project();
		const created = await request(
			'POST',
			`/admin/api/projects/${bucket._id}/clients`,
			cookie,
			{
				clientName: 'Billing',
				grantTypes: ['authorization_code'],
				tokenEndpointAuthMethod: 'client_secret_basic',
				redirectUris: ['https://billing.example.com/cb'],
				requireCode: true,
				confirm: true,
				expect: { withoutAuthenticator: 0, providerOnly: 0, holders: 0 }
			}
		);
		expect(created.status).toBe(201);
		const { clientId } = shaped(Created, created.body);

		const summary = await request(
			'GET',
			`/admin/api/projects/${bucket._id}/summary`,
			cookie
		);

		expect(shaped(Summary, summary.body).codeRequiredApps).toEqual([
			{ id: clientId, name: 'Billing' }
		]);
	});

	it('names in SL1 readiness a project where nobody new can give a second factor, and not one where they can', async () => {
		const closed = await project({ totpSelfService: false });
		const open = await project();

		const answer = await request(
			'GET',
			'/admin/api/settings/ipsie-sl1/readiness',
			superCookie
		);

		const listed = shaped(
			Readiness,
			answer.body
		).projectsWithoutSecondFactor.map((entry) => entry.projectId);
		expect(listed).toContain(closed._id);
		expect(listed).not.toContain(open._id);
	});
});
