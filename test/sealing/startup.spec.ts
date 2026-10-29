import { afterEach, beforeAll, describe, expect, it } from 'bun:test';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import bootstrap from '../test_helper.ts';
import {
	SAME_KID_WRONG_KEYRING,
	TEST_KEYRING,
	withTempKeyringDir
} from './fixtures.ts';
import { adapter, getSealingStore } from 'lib/adapters/index.ts';
import { resetKeyringForTests, serializeKeyring } from 'lib/sealing/keyring.ts';
import { assertKeyring } from 'lib/sealing/startup.ts';

const ROOT = join(import.meta.dir, '..', '..');

/*
 * The keyring is read once, when the module is first imported, and never under test; so a start with the
 * deployment's sources is what a child process importing it shows.
 */
function startWith(env: Record<string, string>) {
	const result = Bun.spawnSync({
		cmd: [process.execPath, '-e', "await import('./lib/sealing/keyring.ts')"],
		cwd: ROOT,
		env: { PATH: process.env.PATH ?? '', NODE_ENV: 'production', ...env },
		stderr: 'pipe',
		stdout: 'pipe'
	});
	return { exitCode: result.exitCode, output: result.stderr.toString() };
}

/**
 * @proves A start with a keyring that would seal what the right key cannot open, or with a keyring supplied
 * twice or malformed, is refused before anything is written, and the refusal never repeats key material.
 */
describe('starting with a keyring', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		// Any sealing write records the suite keyring's fingerprint, as a first start does.
		await adapter('Client').upsert('startup-fingerprint', {
			clientId: 'startup-fingerprint',
			clientSecret: 'fingerprint-secret',
			grantTypes: ['client_credentials'],
			responseTypes: [],
			redirectUris: []
		});
	});

	afterEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	it('startup is refused when a known key id has different key material, and nothing is written', async () => {
		const before = await getSealingStore().scan('clientSecret');
		resetKeyringForTests(SAME_KID_WRONG_KEYRING);

		await expect(assertKeyring()).rejects.toThrow(TEST_KEYRING.write);
		await expect(
			adapter('Client').upsert('startup-refused', {
				clientId: 'startup-refused',
				clientSecret: 'never-stored',
				grantTypes: ['client_credentials'],
				responseTypes: [],
				redirectUris: []
			})
		).rejects.toThrow();
		expect(await getSealingStore().scan('clientSecret')).toEqual(before);
	});

	it('startup is refused when both the environment and a keyring file supply a keyring', () => {
		const { dir, remove } = withTempKeyringDir();
		try {
			const file = join(dir, 'foxauth.keyring');
			writeFileSync(file, serializeKeyring(TEST_KEYRING));
			const { exitCode, output } = startWith({
				KEYRING: serializeKeyring(TEST_KEYRING),
				KEYRING_FILE: file
			});

			expect(exitCode).not.toBe(0);
			expect(output).toContain('KEYRING is set and a keyring file exists');
		} finally {
			remove();
		}
	});

	it('a malformed keyring refuses startup without echoing key material', () => {
		const short = Buffer.alloc(16, 5).toString('base64url');
		const malformed = [
			'{not json',
			JSON.stringify({
				v: 2,
				write: TEST_KEYRING.write,
				keys: TEST_KEYRING.keys
			}),
			JSON.stringify({ v: 1, write: TEST_KEYRING.write, keys: {} }),
			JSON.stringify({ v: 1, write: 'nope', keys: { nope: short } }),
			JSON.stringify({
				v: 1,
				write: '20261029-shrt',
				keys: { '20261029-shrt': short }
			}),
			JSON.stringify({ v: 1, write: '20261029-gone', keys: TEST_KEYRING.keys })
		];
		for (const value of malformed) {
			const { exitCode, output } = startWith({ KEYRING: value });

			expect(exitCode, value).not.toBe(0);
			expect(output, value).toContain('keyring');
			expect(output, value).not.toContain(short);
			expect(output, value).not.toContain(
				TEST_KEYRING.keys[TEST_KEYRING.write]
			);
		}
	});
});
