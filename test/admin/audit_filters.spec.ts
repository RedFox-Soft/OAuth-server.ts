import { describe, it, expect, beforeAll } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { recordConnectionAudit } from 'lib/admin/audit/record.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import type { User, UserBucket } from 'lib/adapters/types.ts';
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

const Entry = Type.Object({
	action: Type.String(),
	actorId: Type.String(),
	targetType: Type.String(),
	targetId: Type.String(),
	targetScope: Type.Union([Type.String(), Type.Null()]),
	projectId: Type.Optional(Type.Union([Type.String(), Type.Null()])),
	formerProjectId: Type.Optional(Type.Union([Type.String(), Type.Null()])),
	kid: Type.Optional(Type.Union([Type.String(), Type.Null()])),
	actorName: Type.Optional(Type.Union([Type.String(), Type.Null()]))
});
const Page = Type.Object({ entries: Type.Array(Entry), total: Type.Number() });

async function trail(cookie: string, query: Record<string, string>) {
	const res = await call(
		'GET',
		`/admin/api/audit?${new URLSearchParams(query).toString()}`,
		cookie
	);
	expect(res.status).toBe(200);
	return shaped(Page, res.body).entries;
}

function slug(prefix: string): string {
	return `${prefix}${nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '')
		.slice(0, 10)}`;
}

async function bucketOf(ownerGroupId: string, name: string) {
	const bucket = await getBucketStore().create({
		name,
		slug: slug('f'),
		ownerGroupId,
		federation: [provider('corp')]
	});
	forgetBucketAddresses();
	return bucket;
}

/*
 * One team, its two buckets and a third it also owns, and what an owner does to them through the admin API:
 * settings, an end user, a provisioning connection, a signing key and an application in one bucket, and an
 * API declared in the other. Built once: every case below only reads the trail.
 */
interface World {
	owner: User;
	cookie: string;
	a: UserBucket;
	b: UserBucket;
	c: UserBucket;
	clientId: string;
	resourceId: string;
	connectionId: string;
	kid: string;
}

let w: World;

/**
 * @proves The audit trail answers "what happened in this bucket", "what did this directory do and what was
 * done to it" and "which key actions happened", only ever within what the caller may read; key entries name
 * their key, a connection's creation names the connection, and a directory actor is named as it is called
 * now — or as gone.
 */
describe('the audit trail, filtered', () => {
	beforeAll(async () => {
		await ensureAdminSeed();
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const cookie = await cookieFor(owner);
		const a = await bucketOf(team._id, 'Acme customers');
		const b = await bucketOf(team._id, 'Beta customers');
		const c = await bucketOf(team._id, 'Elsewhere');
		const resourceId = `https://${slug('api')}.example.com`;

		const steps = [
			await call('PATCH', `/admin/api/projects/${a._id}`, cookie, {
				name: 'Acme people'
			}),
			await call('PATCH', `/admin/api/projects/${c._id}`, cookie, {
				name: 'Elsewhere still'
			}),
			await call('POST', `/admin/api/projects/${a._id}/users`, cookie, {
				email: `${slug('person')}@acme.test`,
				password: 'a password long enough'
			}),
			await call(
				'POST',
				`/admin/api/projects/${a._id}/provisioning-connections`,
				cookie,
				{ displayName: 'Acme directory', providerId: 'corp' }
			),
			await call('POST', `/admin/api/projects/${a._id}/keys`, cookie, {
				alg: 'ES256'
			}),
			await call('POST', `/admin/api/projects/${a._id}/clients`, cookie, {
				clientName: 'Shop',
				grantTypes: ['authorization_code'],
				tokenEndpointAuthMethod: 'client_secret_basic',
				redirectUris: ['https://shop.example.com/cb']
			}),
			await call('POST', `/admin/api/projects/${b._id}/resources`, cookie, {
				identifier: resourceId,
				name: 'Orders API',
				scopes: ['orders:read']
			})
		];
		for (const step of steps) expect(step.status).toBeLessThan(300);

		const connectionId = shaped(
			Type.Object({ id: Type.String() }),
			steps[3]?.body
		).id;
		const kid = shaped(Type.Object({ kid: Type.String() }), steps[4]?.body).kid;
		const clientId = shaped(
			Type.Object({ clientId: Type.String() }),
			steps[5]?.body
		).clientId;
		/* What the directory itself does, as the SCIM surface records it. */
		await recordConnectionAudit(connectionId, 'enduser.create', 'someone', {
			targetScope: a._id,
			ownerGroupId: team._id
		});

		w = {
			owner,
			cookie,
			a,
			b,
			c,
			clientId,
			resourceId,
			connectionId,
			kid
		};
	});

	it("finds a bucket's settings, people, provisioning, keys and applications, and nothing of another bucket", async () => {
		const entries = await trail(w.cookie, { project: w.a._id });

		expect(new Set(entries.map((e) => e.action))).toEqual(
			new Set([
				'project.update',
				'enduser.create',
				'provisioning.connection.create',
				'project.key.generate',
				'client.create'
			])
		);
		expect(entries.find((e) => e.action === 'client.create')?.targetId).toBe(
			w.clientId
		);
		expect(entries.some((e) => e.targetId === w.c._id)).toBe(false);
		expect(entries.some((e) => e.targetId === w.resourceId)).toBe(false);
	});

	it("finds an API declared in a bucket in that bucket's trail, and nothing of its sibling", async () => {
		const entries = await trail(w.cookie, { project: w.b._id });

		expect(entries.map((e) => [e.action, e.targetId])).toEqual([
			['resource.create', w.resourceId]
		]);
	});

	it('finds what a connection did and what was done to it, and nothing else', async () => {
		const entries = await trail(w.cookie, { connection: w.connectionId });

		expect(entries.map((e) => e.action).sort()).toEqual([
			'enduser.create',
			'provisioning.connection.create'
		]);
	});

	it('finds actions by the start of their name', async () => {
		const entries = await trail(w.cookie, {
			project: w.a._id,
			actionPrefix: 'project.key.'
		});

		expect(entries.map((e) => e.action)).toEqual(['project.key.generate']);
	});

	it('reads a prefix as text, not as a pattern', async () => {
		const entries = await trail(w.cookie, {
			project: w.a._id,
			actionPrefix: 'project.key_'
		});

		expect(entries).toEqual([]);
	});

	it('names the key a bucket key action acted on', async () => {
		const entries = await trail(w.cookie, {
			project: w.a._id,
			action: 'project.key.generate'
		});

		expect(entries.map((e) => e.kid)).toEqual([w.kid]);
	});

	it('targets the connection a creation made', async () => {
		const entries = await trail(w.cookie, {
			action: 'provisioning.connection.create',
			targetId: w.connectionId
		});

		expect(entries.map((e) => [e.targetType, e.targetScope])).toEqual([
			['ProvisioningConnection', w.a._id]
		]);
	});

	it('names a directory actor by its connection as it is called now', async () => {
		const entries = await trail(w.cookie, {
			actor: `connection:${w.connectionId}`
		});

		expect(entries.map((e) => e.actorName)).toEqual(['Acme directory']);
	});

	it('names a directory actor whose connection is gone as gone', async () => {
		const gone = `gone-${nanoid()}`;
		await recordConnectionAudit(gone, 'enduser.create', 'someone', {
			targetScope: w.a._id,
			ownerGroupId: (await getBucketStore().find(w.a._id))?.ownerGroupId
		});

		const entries = await trail(w.cookie, { actor: `connection:${gone}` });

		expect(entries.map((e) => e.actorName)).toEqual([null]);
	});

	it("returns nothing of another group's bucket to a caller outside it", async () => {
		const outsider = await cookieFor(await createAdministrator('plain'));

		expect(await trail(outsider, { project: w.a._id })).toEqual([]);
	});

	it("returns nothing of another group's connection to a caller outside it", async () => {
		const outsider = await cookieFor(await createAdministrator('plain'));

		expect(await trail(outsider, { connection: w.connectionId })).toEqual([]);
	});
});
