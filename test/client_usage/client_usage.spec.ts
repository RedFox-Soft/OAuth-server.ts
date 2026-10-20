import { describe, it, expect, beforeAll, afterEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import bootstrap, { agent } from '../test_helper.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adapter, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { whenClientUseRecorded } from 'lib/models/client/usage.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import {
	seedBucket,
	seedUser,
	signInAndRedeem,
	startCounting
} from '../activity/fixtures.ts';

const app = new Elysia().use(resolveAdmin).use(clientRoutes);
const admin = treaty(app);

let bucketId: string;
let cookie: string;
let restores: Array<() => void> = [];

type LastUsed = { firstUsedAt: number; lastUsedAt: number } | null;

/* What the application's page reads: its connection's last use. */
async function lastUsedOf(clientId: string): Promise<LastUsed> {
	await whenClientUseRecorded();
	const read = await admin.admin.api
		.projects({ id: bucketId })
		.clients({ clientId })
		.get({ headers: { cookie } });
	return (read.data as unknown as { connection: { lastUsed: LastUsed } })
		.connection.lastUsed;
}

function machineToken(clientId: string, secret: string) {
	return agent.token.post({
		grant_type: 'client_credentials',
		client_id: clientId,
		client_secret: secret
	});
}

/**
 * @proves An application's page says whether it has really been used — after a person signs in through it or a
 * service obtains a token — without the record holding anything about the person, without ever costing a token
 * response, and without a row for an application nobody created.
 */
describe("an application's last use", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_usage' });
		resetAdminMemoryStores();
		await ensureAdminSeed();
		await startCounting();
		bucketId = await seedBucket('Last use', [
			'act-app',
			'act-app-2',
			'act-other',
			'act-throttle',
			'act-service',
			'usage-self-registered'
		]);
		const user = await createAdministrator('super', `usage-${nanoid()}@x.io`);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
	});

	afterEach(() => {
		for (const restore of restores) restore();
		restores = [];
	});

	it('reads as not used until the application receives a token', async () => {
		expect(await lastUsedOf('act-other')).toBeNull();
	});

	it('records the last use once a person signs in through the application', async () => {
		const email = await seedUser(bucketId);
		const tokens = await signInAndRedeem('act-app', email);
		expect(tokens.response.status).toBe(200);

		const used = await lastUsedOf('act-app');
		expect(used).not.toBeNull();
		expect(used?.lastUsedAt).toBeGreaterThan(0);
	});

	it("records a service's last use once it obtains a machine token", async () => {
		const res = await machineToken('act-service', 'act-service-secret');
		expect(res.status).toBe(200);

		expect(await lastUsedOf('act-service')).not.toBeNull();
	});

	it('keeps nothing about the person in the record', async () => {
		const email = await seedUser(bucketId);
		await signInAndRedeem('act-app', email);
		await whenClientUseRecorded();

		const stored = await adapter('ClientUsage').find('act-app');
		expect(Object.keys(stored ?? {}).sort()).toEqual(
			['clientId', 'firstUsedAt', 'lastUsedAt'].sort()
		);
		expect(JSON.stringify(stored)).not.toContain(email);
	});

	it('issues the tokens when the record cannot be written', async () => {
		const upsert = spyOn(adapter('ClientUsage'), 'upsert').mockRejectedValue(
			new Error('the datastore is unavailable')
		);
		const log = spyOn(console, 'error').mockImplementation(() => undefined);
		restores.push(
			() => upsert.mockRestore(),
			() => log.mockRestore()
		);
		const email = await seedUser(bucketId);

		const tokens = await signInAndRedeem('act-throttle', email);
		await whenClientUseRecorded();

		expect(tokens.response.status).toBe(200);
	});

	/*
	 * Operator: the database cost of knowing an application was used grows with the number of applications, not with
	 * their traffic.
	 */
	it('costs a busy application at most one write a minute however many tokens it receives', async () => {
		const upsert = spyOn(adapter('ClientUsage'), 'upsert');
		restores.push(() => upsert.mockRestore());
		const email = await seedUser(bucketId);

		await signInAndRedeem('act-app-2', email);
		await signInAndRedeem('act-app-2', email);
		await whenClientUseRecorded();

		const writes = upsert.mock.calls.filter(([id]) => id === 'act-app-2');
		expect(writes.length).toBe(1);
	});

	it('records nothing for an application that registered itself', async () => {
		const res = await machineToken(
			'usage-self-registered',
			'usage-self-registered-secret'
		);
		expect(res.status).toBe(200);
		await whenClientUseRecorded();

		expect(await adapter('ClientUsage').find('usage-self-registered')).toBe(
			undefined
		);
	});

	it('removes the record with its application', async () => {
		await machineToken('act-service', 'act-service-secret');
		await whenClientUseRecorded();

		const removed = await admin.admin.api
			.projects({ id: bucketId })
			.clients({ clientId: 'act-service' })
			.delete(undefined, { headers: { cookie } });
		expect(removed.status).toBe(200);

		expect(await adapter('ClientUsage').find('act-service')).toBe(undefined);
	});
});
