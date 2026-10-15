import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getProvisioningConnectionStore
} from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { provider } from '../scim/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import { groupIdFor } from '../admin_session.ts';
import { cookieFor } from './ownership_fixtures.ts';

async function get(path: string, cookie: string): Promise<unknown> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, { headers: { cookie } })
	);
	expect(response.status).toBe(200);
	return response.json();
}

const Holds = Type.Object({
	count: Type.Number(),
	connections: Type.Array(
		Type.Object({
			projectId: Type.String(),
			projectName: Type.String(),
			connectionId: Type.String(),
			displayName: Type.String(),
			since: Type.String(),
			refused: Type.Number()
		})
	)
});
const BucketRows = Type.Array(
	Type.Object({
		_id: Type.String(),
		held: Type.Boolean(),
		heldConnectionId: Type.Optional(Type.String())
	})
);

/* A bucket of `owner`'s own group holding one SCIM connection, held when `held` is set. */
async function bucketOf(owner: User, held: boolean) {
	const id = nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '');
	const bucket = await getBucketStore().create({
		name: `holds ${id}`,
		slug: `hd-${id}`,
		ownerGroupId: await groupIdFor(owner),
		federation: [provider('corp')]
	});
	const connection = await getProvisioningConnectionStore().create({
		_id: nanoid(),
		bucketId: bucket._id,
		displayName: `Directory ${id}`,
		enabled: true,
		providerId: 'corp',
		correlation: { claim: 'oid', attribute: 'externalId' },
		emailTrust: 'untrusted',
		oauthCredential: null
	});
	if (held) {
		await getProvisioningConnectionStore().holdIfFree(connection._id, {
			since: new Date(),
			count: 3
		});
	}
	return { bucket, connection };
}

/**
 * @proves An administrator sees, from anywhere in the console, every connection held by the
 * deprovisioning safeguard in the buckets their bucket list shows them and none in a bucket it does not,
 * and the bucket list leads to the held connection (spec 088, User Story 5).
 */
describe('held provisioning connections across buckets', () => {
	let owner: User;
	let outsider: User;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		owner = await createAdministrator();
		outsider = await createAdministrator();
	});

	it('counts a held connection in a bucket the administrator can see', async () => {
		/* An administrator of their own: the count is exact, and another case holds a bucket of `owner`'s. */
		const counted = await createAdministrator();
		const { bucket, connection } = await bucketOf(counted, true);
		await bucketOf(counted, false);

		const holds = shaped(
			Holds,
			await get('/admin/api/provisioning-holds', await cookieFor(counted))
		);

		expect(holds.count).toBe(1);
		expect(holds.connections).toHaveLength(1);
		expect(holds.connections[0]).toMatchObject({
			projectId: bucket._id,
			projectName: bucket.name,
			connectionId: connection._id,
			displayName: connection.displayName,
			refused: 0
		});
	});

	it('counts nothing held in a bucket the administrator cannot see', async () => {
		const { connection } = await bucketOf(owner, true);

		const holds = shaped(
			Holds,
			await get('/admin/api/provisioning-holds', await cookieFor(outsider))
		);

		expect(holds.connections.map((c) => c.connectionId)).not.toContain(
			connection._id
		);
		expect(holds.count).toBe(holds.connections.length);
	});

	it('links a held bucket’s row in the bucket list to its held connection', async () => {
		const { bucket, connection } = await bucketOf(outsider, true);

		const rows = shaped(
			BucketRows,
			await get('/admin/api/projects', await cookieFor(outsider))
		);

		expect(rows.find((row) => row._id === bucket._id)).toMatchObject({
			held: true,
			heldConnectionId: connection._id
		});
	});

	it('stops counting a connection once its hold is released', async () => {
		const someone = await createAdministrator();
		const { connection } = await bucketOf(someone, true);
		await getProvisioningConnectionStore().releaseHold(connection._id);

		const holds = shaped(
			Holds,
			await get('/admin/api/provisioning-holds', await cookieFor(someone))
		);

		expect(holds.count).toBe(0);
	});
});
