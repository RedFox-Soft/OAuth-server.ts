import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn
} from 'bun:test';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Elysia } from 'elysia';

import bootstrap from '../test_helper.ts';
import { withTempKeyringDir } from './fixtures.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { adminSetup } from 'lib/admin/auth/setup.ts';
import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { adapter, errorStore, getSealingStore } from 'lib/adapters/index.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { isSealed } from 'lib/sealing/seal.ts';
import { pendingPassForTests } from 'lib/sealing/pass.ts';

const app = new Elysia().use(resolveAdmin).use(adminApiRoutes);
const setupApp = new Elysia().use(adminSetup);
const temp = withTempKeyringDir();

async function superAdminCookie(): Promise<string> {
	const user = await createAdministrator('super', `gen-${Math.random()}@x.io`);
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

async function request(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
) {
	const response = await app.handle(
		new Request(`http://localhost${path}`, {
			method,
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
	return { status: response.status, text: await response.text() };
}

async function generate(cookie: string) {
	const { status, text } = await request('POST', '/admin/api/keyring', cookie);
	return { status, body: JSON.parse(text) as Record<string, unknown> };
}

async function storePlaintextClient(clientId: string): Promise<void> {
	await adapter('Client').upsert(clientId, {
		clientId,
		clientSecret: `${clientId}-secret`,
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	});
}

async function storedSecretOf(clientId: string): Promise<unknown> {
	return (await getSealingStore().scan('clientSecret')).find(
		(leaf) =>
			leaf.target.kind === 'clientSecret' && leaf.target.clientId === clientId
	)?.value;
}

async function confirmSetup(token: string) {
	const response = await setupApp.handle(
		new Request('http://localhost/admin/api/setup/keyring-confirmation', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ token })
		})
	);
	return { status: response.status, text: await response.text() };
}

/**
 * @proves A keyring generated in the console is shown once and never again by any route, never replaces a
 * keyring file, leaks into nothing when it cannot be placed, and seals what was already stored; without one,
 * secrets are stored as before and the status says so.
 */
describe('generating a keyring', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterAll(() => {
		temp.remove();
	});

	beforeEach(() => {
		resetKeyringForTests(null);
		process.env.KEYRING_FILE = join(temp.dir, `${Math.random()}.keyring`);
	});

	it('an existing keyring file is never overwritten by generation', async () => {
		writeFileSync(String(process.env.KEYRING_FILE), 'the operator keyring');

		const { status, body } = await generate(await superAdminCookie());

		expect(status).toBe(201);
		expect(body.applied).toBe(false);
		expect(readFileSync(String(process.env.KEYRING_FILE), 'utf8')).toBe(
			'the operator keyring'
		);
	});

	it('no route returns the keyring after the moment it was generated', async () => {
		const cookie = await superAdminCookie();
		const { body } = await generate(cookie);
		const value = String(body.keyring);
		const key = Object.values(
			(JSON.parse(value) as { keys: Record<string, string> }).keys
		)[0];
		await pendingPassForTests();

		const reads = app.routes.filter(
			(route) =>
				route.method === 'GET' &&
				route.path.startsWith('/admin/api') &&
				!route.path.includes(':')
		);
		expect(reads.length).toBeGreaterThan(10);
		for (const route of reads) {
			const { text } = await request('GET', route.path, cookie);
			expect(text, route.path).not.toContain(key);
		}
	});

	it('the setup keyring confirmation answers alike for a wrong and an absent token', async () => {
		const absent = await confirmSetup('never-issued');
		const wrong = await confirmSetup('x'.repeat(43));

		expect(absent.status).toBe(404);
		expect(wrong).toEqual(absent);
	});

	it('a failure while placing a keyring records no key material', async () => {
		// A file where the keyring directory should be: the write fails after every check has passed.
		const blocker = join(temp.dir, `blocker-${Math.random()}`);
		writeFileSync(blocker, '');
		process.env.KEYRING_FILE = join(blocker, 'foxauth.keyring');
		const logged: string[] = [];
		const spies = (['log', 'warn', 'error', 'info'] as const).map((level) =>
			spyOn(console, level).mockImplementation((...args: unknown[]) => {
				logged.push(args.map(String).join(' '));
			})
		);
		try {
			const { body } = await generate(await superAdminCookie());
			const key = Object.values(
				(JSON.parse(String(body.keyring)) as { keys: Record<string, string> })
					.keys
			)[0];

			expect(body.applied).toBe(false);
			expect(logged.join('\n')).not.toContain(key);
			expect(JSON.stringify(await errorStore.list({}))).not.toContain(key);
		} finally {
			for (const spy of spies) spy.mockRestore();
		}
	});

	it('generating a keyring from the console seals the secrets already stored', async () => {
		await storePlaintextClient('before-generation');
		expect(isSealed(await storedSecretOf('before-generation'))).toBe(false);

		await generate(await superAdminCookie());
		await pendingPassForTests();

		expect(isSealed(await storedSecretOf('before-generation'))).toBe(true);
	});

	it('without a keyring secrets are stored as before and the status says none', async () => {
		await storePlaintextClient('no-keyring');
		const { text } = await request(
			'GET',
			'/admin/api/keyring',
			await superAdminCookie()
		);

		expect(await storedSecretOf('no-keyring')).toBe('no-keyring-secret');
		expect((JSON.parse(text) as { state: string }).state).toBe('none');
	});
});
