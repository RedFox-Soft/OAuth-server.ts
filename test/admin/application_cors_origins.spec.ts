import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { Type } from '@sinclair/typebox';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adapter, getBucketStore } from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID,
	ADMIN_SESSION_COOKIE
} from 'lib/admin/consts.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { shaped } from 'test/shape.ts';
import { answered } from './answered.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const MessageBody = Type.Object({
	message: Type.String(),
	field: Type.Optional(Type.String())
});

const app = new Elysia().use(resolveAdmin).use(clientRoutes);
const client = treaty(app);

async function sessionCookieFor(kind: AdminKind) {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	const s = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

async function bucketOwnedBy(ownerGroupId: string): Promise<string> {
	return (
		await getBucketStore().create({ name: 'Browser users', ownerGroupId })
	)._id;
}

const BROWSER_APP = {
	clientName: 'Browser app',
	grantTypes: ['authorization_code' as const],
	redirectUris: ['https://app.example.com/cb'],
	tokenEndpointAuthMethod: 'none' as const
};

/* A browser application created in the bucket, with the origins given. */
async function applicationIn(
	bucketId: string,
	cookie: string,
	corsOrigins?: string[]
): Promise<string> {
	const created = await client.admin.api
		.buckets({ id: bucketId })
		.clients.post(
			{ ...BROWSER_APP, ...(corsOrigins ? { corsOrigins } : {}) },
			{ headers: { cookie } }
		);
	expect(created.status).toBe(201);
	return answered(created.data).clientId;
}

async function storedOrigins(clientId: string): Promise<unknown> {
	return (await adapter('Client').find(clientId))?.corsOrigins;
}

/*
 * CORS origins. Validated in the handler rather than by the body schema so a rejection returns the
 * admin_error shape and can name the offending value — a list that looks right but grants nothing is
 * the failure mode worth spending a message on.
 */

/**
 * @proves An administrator lists the web origins whose browser code may call an application: a list is
 * normalized, replaced or cleared as asked, refused whole when any entry is not an exact origin, and
 * changed only by a member of the application's bucket group, never on the administrators' bucket.
 */
describe("an application's browser origins", () => {
	let su: { cookie: string; userId: string };
	let bucketId: string;

	beforeEach(async () => {
		await ensureAdminSeed();
		su = await sessionCookieFor('super');
		bucketId = await bucketOwnedBy(await personalGroupId(su.userId));
	});

	it('accepts origins on create and returns them', async () => {
		const created = await client.admin.api
			.buckets({ id: bucketId })
			.clients.post(
				{ ...BROWSER_APP, corsOrigins: ['https://app.example.com'] },
				{ headers: { cookie: su.cookie } }
			);

		expect(created.status).toBe(201);
		expect(answered(created.data).corsOrigins).toEqual([
			'https://app.example.com'
		]);
	});

	it('defaults to an empty list when omitted', async () => {
		const created = await client.admin.api
			.buckets({ id: bucketId })
			.clients.post(BROWSER_APP, { headers: { cookie: su.cookie } });

		expect(answered(created.data).corsOrigins).toEqual([]);
	});

	it('replaces the list on patch', async () => {
		const clientId = await applicationIn(bucketId, su.cookie, [
			'https://old.example.com'
		]);

		const replaced = await client.admin.api
			.buckets({ id: bucketId })
			.clients({ clientId })
			.patch(
				{ corsOrigins: ['https://new.example.com'] },
				{ headers: { cookie: su.cookie } }
			);

		expect(replaced.status).toBe(200);
		expect(answered(replaced.data).corsOrigins).toEqual([
			'https://new.example.com'
		]);
	});

	it('clears the list with an empty array', async () => {
		const clientId = await applicationIn(bucketId, su.cookie, [
			'https://old.example.com'
		]);

		const cleared = await client.admin.api
			.buckets({ id: bucketId })
			.clients({ clientId })
			.patch({ corsOrigins: [] }, { headers: { cookie: su.cookie } });

		expect(answered(cleared.data).corsOrigins).toEqual([]);
	});

	it('leaves the list untouched when the key is omitted', async () => {
		const clientId = await applicationIn(bucketId, su.cookie, [
			'https://keep.example.com'
		]);

		const renamed = await client.admin.api
			.buckets({ id: bucketId })
			.clients({ clientId })
			.patch({ clientName: 'Renamed' }, { headers: { cookie: su.cookie } });

		expect(answered(renamed.data).corsOrigins).toEqual([
			'https://keep.example.com'
		]);
	});

	it('normalizes host case and collapses duplicates', async () => {
		const created = await client.admin.api
			.buckets({ id: bucketId })
			.clients.post(
				{
					...BROWSER_APP,
					corsOrigins: ['https://APP.Example.com', 'https://app.example.com']
				},
				{ headers: { cookie: su.cookie } }
			);

		expect(answered(created.data).corsOrigins).toEqual([
			'https://app.example.com'
		]);
	});

	it.each([
		['https://app.example.com/', 'a trailing slash'],
		['https://app.example.com/cb', 'a path'],
		['https://app.example.com:443', 'a written default port'],
		['ftp://app.example.com', 'a non-web scheme'],
		['*', 'the any-origin wildcard'],
		['https://*.example.com', 'a wildcard subdomain'],
		['null', 'the null origin'],
		['app.example.com', 'no scheme'],
		['', 'the empty string']
	])('rejects %s (%s) and names the value', async (origin) => {
		const clientId = await applicationIn(bucketId, su.cookie, [
			'https://kept.example.com'
		]);

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.clients({ clientId })
			.patch({ corsOrigins: [origin] }, { headers: { cookie: su.cookie } });

		expect(res.status).toBe(400);
		expect(res.error?.value).toMatchObject({
			error: 'admin_error',
			field: 'corsOrigins'
		});
		expect(shaped(MessageBody, res.error?.value).message).toContain(
			JSON.stringify(origin)
		);
		// All-or-nothing: the stored list must be exactly as it was.
		expect(await storedOrigins(clientId)).toEqual(['https://kept.example.com']);
	});

	it('rejects the whole list when only one entry is invalid', async () => {
		const clientId = await applicationIn(bucketId, su.cookie, [
			'https://kept.example.com'
		]);

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.clients({ clientId })
			.patch(
				{
					corsOrigins: ['https://good.example.com', 'https://bad.example.com/']
				},
				{ headers: { cookie: su.cookie } }
			);

		expect(res.status).toBe(400);
		expect(await storedOrigins(clientId)).toEqual(['https://kept.example.com']);
	});

	it('refuses an invalid list on create, and creates nothing', async () => {
		const before = await adapter('Client').findByIndexed('bucketId', bucketId);

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.clients.post(
				{ ...BROWSER_APP, corsOrigins: ['https://bad.example.com/'] },
				{ headers: { cookie: su.cookie } }
			);

		expect(res.status).toBe(400);
		expect(await adapter('Client').findByIndexed('bucketId', bucketId)).toEqual(
			before
		);
	});

	it('refuses an unauthenticated caller', async () => {
		const clientId = await applicationIn(bucketId, su.cookie, [
			'https://kept.example.com'
		]);

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.clients({ clientId })
			.patch({ corsOrigins: ['https://app.example.com'] });

		expect(res.status).toBe(401);
		expect(await storedOrigins(clientId)).toEqual(['https://kept.example.com']);
	});

	it("refuses an administrator outside the bucket's group", async () => {
		const clientId = await applicationIn(bucketId, su.cookie, [
			'https://kept.example.com'
		]);
		const stranger = await sessionCookieFor('plain');

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.clients({ clientId })
			.patch(
				{ corsOrigins: ['https://app.example.com'] },
				{ headers: { cookie: stranger.cookie } }
			);

		expect(res.status).toBe(403);
		expect(await storedOrigins(clientId)).toEqual(['https://kept.example.com']);
	});

	it("lets a member of the bucket's group set origins", async () => {
		const member = await sessionCookieFor('plain');
		const own = await bucketOwnedBy(await personalGroupId(member.userId));
		const clientId = await applicationIn(own, member.cookie);

		const res = await client.admin.api
			.buckets({ id: own })
			.clients({ clientId })
			.patch(
				{ corsOrigins: ['https://app.example.com'] },
				{ headers: { cookie: member.cookie } }
			);

		expect(res.status).toBe(200);
		expect(await storedOrigins(clientId)).toEqual(['https://app.example.com']);
	});

	// Refused before validation runs, so the guard cannot be probed by submitting a deliberately invalid
	// origin to the console's own client.
	it("refuses the administrators' bucket even to a super administrator, before validating the list", async () => {
		const res = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.clients({ clientId: ADMIN_CLIENT_ID })
			.patch({ corsOrigins: ['*'] }, { headers: { cookie: su.cookie } });

		expect(res.status).toBe(403);
		expect(shaped(MessageBody, res.error?.value).message).toBe(
			"this operation is not available for the administrators' bucket"
		);
	});
});
