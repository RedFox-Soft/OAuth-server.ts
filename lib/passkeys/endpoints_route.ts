import { Elysia } from 'elysia';

import { accountPageBase } from '../account_page/client.js';
import { bucketAtHost } from '../admin/auth/bucketAddress.js';
import { ISSUER } from '../configs/env.js';
import { hasOwnOrigin } from '../configs/issuer.js';
import { routeNames } from '../consts/param_list.js';
import { canonicalHostOf, hostOfRequest } from '../consts/request_host.js';
import { passkeysAccepted } from './accepted.js';
import { passkeysPossible } from './relying_party.js';

/*
 * `/.well-known/passkey-endpoints` (specs/141 research R11, contracts/browser.md): where a password manager's "Manage"
 * and "Create" lead for the passkeys of a site (the W3C passkey-endpoints draft). One file per host, at the bare path,
 * never beneath a project's path segment: a path project has no host of its own to answer for.
 *
 * A project at a site of its own (a subdomain, or a host) names its "Sign-in and security" page. The instance's own
 * host is shared by the root, every path project and the administrators, so it names no page at all (`{}` means
 * "passkeys are supported here, with no addresses"): a page there would send a person into a project their passkey is
 * not for. Anything else is not found. No redirect, no cookie, nothing recorded.
 */

const CANONICAL_HOST = canonicalHostOf(ISSUER);

function answer(body: object | null): Response {
	return new Response(JSON.stringify(body ?? {}), {
		status: body === null ? 404 : 200,
		headers: {
			'content-type': 'application/json',
			'cache-control': 'no-store'
		}
	});
}

export const passkeyEndpointsRoutes = new Elysia({
	name: 'passkey-endpoints'
}).get('/.well-known/passkey-endpoints', async ({ request }) => {
	const host = hostOfRequest(request);
	if (!host || !passkeysPossible(ISSUER)) return answer(null);
	if (host === CANONICAL_HOST) return answer({});
	const bucket = await bucketAtHost(host);
	if (!bucket || !hasOwnOrigin(bucket) || !passkeysAccepted(bucket)) {
		return answer(null);
	}
	const page = `${accountPageBase(bucket)}${routeNames.account_security}`;
	return answer({ enroll: page, manage: page });
});
