import { beforeAll, describe, expect, it } from 'bun:test';
import { createLocalJWKSet, jwtVerify } from 'jose';

import bootstrap from '../test_helper.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { addresses, machineToken, publishedKeys, tenant } from './tenants.ts';

const {
	slug: PATH_SLUG,
	host: HOST,
	pathOrigin: PATH_ORIGIN,
	hostOrigin: HOST_ORIGIN,
	pathClient,
	hostClient
} = addresses('iso');

async function verifiesAgainst(token: string, keySetUrl: string) {
	const keys = await publishedKeys(keySetUrl);
	try {
		await jwtVerify(token, createLocalJWKSet(keys));
		return true;
	} catch {
		return false;
	}
}

const KEY_SETS = {
	'the path bucket': `${PATH_ORIGIN}/jwks`,
	'the host bucket': `${HOST_ORIGIN}/jwks`,
	'the root issuer': `${ISSUER}/jwks`
};

/**
 * @proves A token an addressable bucket signs verifies only against that bucket's own published key
 * set, never another bucket's or the root issuer's, whichever way the bucket is addressed — so a
 * resource server that skips the `iss` check still cannot be handed another tenant's token.
 */
describe('a token signed by an addressable bucket', () => {
	const tokens: Record<string, string> = {};

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'bucket_keys' });
		forgetBucketAddresses();
		await tenant({ slug: PATH_SLUG }, pathClient);
		await tenant({ host: HOST }, hostClient);
		tokens['the path bucket'] = await machineToken(PATH_ORIGIN, pathClient);
		tokens['the host bucket'] = await machineToken(HOST_ORIGIN, hostClient);
	});

	for (const signer of ['the path bucket', 'the host bucket'] as const) {
		for (const [holder, url] of Object.entries(KEY_SETS)) {
			const expected = holder === signer;
			it(`from ${signer} ${expected ? 'verifies' : 'does not verify'} against the key set of ${holder}`, async () => {
				expect(await verifiesAgainst(tokens[signer], url)).toBe(expected);
			});
		}
	}
});
