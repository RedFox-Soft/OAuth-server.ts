import { afterEach, beforeAll, describe, expect, it } from 'bun:test';
import { decodeProtectedHeader } from 'jose';

import bootstrap from '../test_helper.ts';
import { ROTATED_KEYRING, STAGED_KEYRING, TEST_KEYRING } from './fixtures.ts';
import { adapter, getSealingStore } from 'lib/adapters/index.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { runPass } from 'lib/sealing/pass.ts';
import { SEALED_PREFIX } from 'lib/sealing/seal.ts';

async function storeClient(clientId: string): Promise<void> {
	await adapter('Client').upsert(clientId, {
		clientId,
		clientSecret: `${clientId}-secret`,
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	});
}

async function kidOf(clientId: string): Promise<unknown> {
	const leaf = (await getSealingStore().scan('clientSecret')).find(
		(candidate) =>
			candidate.target.kind === 'clientSecret' &&
			candidate.target.clientId === clientId
	);
	const value = String(leaf?.value);
	return decodeProtectedHeader(value.slice(SEALED_PREFIX.length)).kid;
}

/**
 * @proves A key is rotated in two steps without any process meeting a value it cannot open: a staged key is
 * readable before anything is sealed with it, and once it is the write key the pass moves every value to it.
 */
describe('rotating the keyring', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	it('new secrets are written with the write key while a staged key is already readable', async () => {
		resetKeyringForTests(ROTATED_KEYRING);
		await storeClient('sealed-under-next');
		resetKeyringForTests(STAGED_KEYRING);

		await storeClient('sealed-while-staged');

		expect(await kidOf('sealed-while-staged')).toBe(STAGED_KEYRING.write);
		expect(
			(await adapter('Client').find('sealed-under-next'))?.clientSecret
		).toBe('sealed-under-next-secret');
	});

	it('the encryption pass moves values under an older key to the write key', async () => {
		await storeClient('before-rotation');
		resetKeyringForTests(ROTATED_KEYRING);

		const report = await runPass();

		expect(await kidOf('before-rotation')).toBe(ROTATED_KEYRING.write);
		expect(report?.perKid[TEST_KEYRING.write] ?? 0).toBe(0);
	});
});
