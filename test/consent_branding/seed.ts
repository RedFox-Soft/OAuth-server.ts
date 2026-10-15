import { bindClientToBucket, seedBucket, type Setup } from '../test_helper.js';
import { getProtectedResourceStore } from 'lib/adapters/index.ts';
import { writeLogo } from 'lib/models/client/logo.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';

/* A logo as an administrator would have stored it — the stored record, never the client object. */
export async function giveLogo(clientId: string, image: string): Promise<void> {
	await writeLogo(clientId, image);
}

const PARTNER_BUCKET = 'partner-users';
const PARTNER_RESOURCE = 'https://api.partner.test/';

/*
 * A person of another organization's bucket, signed in, and an application of the default bucket that
 * reaches them: `clientId` belongs to the default bucket, and names a resource the partner bucket declared,
 * which is what signs it into that bucket (specs/099). An administrator of this server made the
 * application, but not in the bucket its user belongs to — so the page must not speak of it as their
 * organization's own.
 *
 * Returns the session cookie of that person and the resource to name, so a case opens the consent page
 * exactly as such an application would.
 */
export async function signedInElsewhere(
	setup: Setup,
	clientId: string
): Promise<{ cookie: string; resource: string[] }> {
	await seedBucket({
		bucketId: PARTNER_BUCKET,
		clientId: 'partner-own-app',
		accountId: 'partner-user'
	});
	await getProtectedResourceStore().create({
		namespace: ROOT_NAMESPACE,
		identifier: PARTNER_RESOURCE,
		bucketId: PARTNER_BUCKET,
		name: 'Partner API',
		scopes: ['billing']
	});
	await bindClientToBucket(clientId, DEFAULT_BUCKET_ID);
	const cookie = await setup.login({
		accountId: 'partner-user',
		bucketId: PARTNER_BUCKET,
		scope: 'openid'
	});
	return { cookie, resource: [PARTNER_RESOURCE] };
}
