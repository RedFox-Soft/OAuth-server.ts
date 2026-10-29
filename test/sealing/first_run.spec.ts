import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import bootstrap from '../test_helper.ts';
import { TEST_KEYRING, withTempKeyringDir } from './fixtures.ts';
import { adminSetup } from 'lib/admin/auth/setup.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	getSealingStore,
	resetStoresForTests
} from 'lib/adapters/index.ts';
import { activeKeyring, resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { isSealed } from 'lib/sealing/seal.ts';
import { keyringStatus } from 'lib/sealing/status.ts';
import { pendingPassForTests } from 'lib/sealing/pass.ts';

const app = new Elysia().use(adminSetup);
const client = treaty(app);
const temp = withTempKeyringDir();

async function setUp() {
	return client.admin.api.setup.post({
		email: `root-${Math.random()}@x.io`,
		password: 'correct horse battery'
	});
}

async function storedClientSecret(clientId: string): Promise<unknown> {
	await adapter('Client').upsert(clientId, {
		clientId,
		clientSecret: `${clientId}-secret`,
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	});
	const leaf = (await getSealingStore().scan('clientSecret')).find(
		(candidate) =>
			candidate.target.kind === 'clientSecret' &&
			candidate.target.clientId === clientId
	);
	return leaf?.value;
}

/**
 * @proves The person who creates the first super administrator gets the instance's keyring there and then: put
 * to use at once where a keyring directory exists, shown for the deployment where none does, never made when
 * the deployment supplies one; and their confirmation that they stored it is recorded.
 */
describe('first-run setup without a keyring', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterAll(() => {
		temp.remove();
	});

	beforeEach(async () => {
		resetStoresForTests();
		await ensureAdminSeed();
		resetKeyringForTests(null);
		process.env.KEYRING_FILE = join(temp.dir, `${Math.random()}.keyring`);
	});

	it('the first-run setup writes, shows and uses a keyring without a restart when the keyring directory exists', async () => {
		const { status, data } = await setUp();
		await pendingPassForTests();

		expect(status).toBe(201);
		const keyring = (data as { keyring?: Record<string, unknown> }).keyring;
		expect(keyring?.applied).toBe(true);
		expect(keyring?.location).toBe(process.env.KEYRING_FILE);
		expect(readFileSync(String(keyring?.location), 'utf8').trim()).toBe(
			String(keyring?.value)
		);
		expect(activeKeyring()?.source).toBe('file');
		expect(isSealed(await storedClientSecret('after-setup'))).toBe(true);
	});

	it('the first-run setup shows a keyring and leaves it unused when there is no keyring directory', async () => {
		process.env.KEYRING_FILE = join(temp.dir, 'absent', 'foxauth.keyring');
		const { status, data } = await setUp();

		expect(status).toBe(201);
		const keyring = (data as { keyring?: Record<string, unknown> }).keyring;
		expect(typeof keyring?.value).toBe('string');
		expect(keyring?.applied).toBe(false);
		expect(keyring?.location).toBeUndefined();
		expect(activeKeyring()).toBeNull();
		expect(isSealed(await storedClientSecret('without-keyring'))).toBe(false);
	});

	it('the first-run setup generates no keyring when the deployment supplies one', async () => {
		resetKeyringForTests(TEST_KEYRING);
		const { status, data } = await setUp();

		expect(status).toBe(201);
		expect(data).toEqual({ ok: true });
	});

	it('the setup confirmation records the backup and the reminder disappears', async () => {
		const { data } = await setUp();
		const token = String(
			(data as { keyring?: Record<string, unknown> }).keyring?.confirmToken
		);
		expect((await keyringStatus()).backupConfirmed).toBeNull();

		const confirmed = await client.admin.api.setup['keyring-confirmation'].post(
			{
				token
			}
		);

		expect(confirmed.status).toBe(204);
		expect((await keyringStatus()).backupConfirmed).not.toBeNull();
	});

	it('a setup confirmation token is refused once it has been used', async () => {
		const { data } = await setUp();
		const token = String(
			(data as { keyring?: Record<string, unknown> }).keyring?.confirmToken
		);
		await client.admin.api.setup['keyring-confirmation'].post({ token });

		const again = await client.admin.api.setup['keyring-confirmation'].post({
			token
		});

		expect(again.status).toBe(404);
	});
});
