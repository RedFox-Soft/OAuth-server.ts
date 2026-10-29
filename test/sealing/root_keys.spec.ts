import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { OTHER_KEYRING, TEST_KEYRING } from './fixtures.ts';
import { invalidateRootKeys, rootKeys } from 'lib/keys/issuer_keys.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { replaceRootKeys } from 'lib/sealing/replace_root_keys.ts';

/**
 * @proves An operator whose root signing keys cannot be opened with the keyring in use, and who therefore
 * cannot sign in to the console, gets signing back from the command line.
 */
describe('root signing keys the keyring cannot open', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		resetKeyringForTests(OTHER_KEYRING);
		invalidateRootKeys();
	});

	afterAll(() => {
		resetKeyringForTests(TEST_KEYRING);
		invalidateRootKeys();
	});

	it('replacing the root keys restores signing when the root keys are unreadable', async () => {
		expect((await rootKeys()).signing.selectForSign({ alg: 'RS256' })).toEqual(
			[]
		);

		await replaceRootKeys();

		expect(
			(await rootKeys()).signing.selectForSign({ alg: 'RS256' }).length
		).toBeGreaterThan(0);
	});
});
