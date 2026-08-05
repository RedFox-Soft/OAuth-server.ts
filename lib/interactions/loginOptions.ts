import { getBucketStore } from '../adapters/index.js';
import { enabledProviders } from '../federation/providers.js';
import { resolveBucketForClient } from '../admin/auth/resolveBucket.js';

/*
 * What the login page needs to know about a bucket in order to render itself: whether it accepts a password
 * at all, and which providers it offers.
 *
 * One resolver, because four places need the same answer and must not disagree — the GET that renders the
 * page, the POST that re-renders it on a bad password, the federation callback that re-renders it on a
 * decline, and the doors that refuse when password sign-in is off. A page that offered a password form the
 * POST would refuse, or dropped the provider buttons on a re-render, is the drift this prevents.
 */

export interface LoginOptions {
	passwordLogin: boolean;
	/* Only what the page renders: an id to build the link from and a label to show. Never the credentials. */
	providers: { id: string; displayName: string }[];
}

export async function loginOptionsForBucket(
	bucketId: string
): Promise<LoginOptions> {
	const bucket = await getBucketStore().find(bucketId);
	return {
		// Defaulted true for a bucket that predates the field, which the stores also do on read — belt and
		// braces here because a falsy value would silently close the password door.
		passwordLogin: bucket?.passwordLogin !== false,
		providers: enabledProviders(bucket).map((provider) => ({
			id: provider.id,
			displayName: provider.displayName
		}))
	};
}

/* The same answer, reached from the client that started the interaction — which is the only trustworthy
 * route to a bucket: a bucket id taken from a request would let anyone aim the page at any tenant. */
export async function loginOptionsForClient(
	clientId: string | undefined
): Promise<LoginOptions> {
	return loginOptionsForBucket(await resolveBucketForClient(clientId));
}
