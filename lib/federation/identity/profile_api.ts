import { callbackUri } from '../flow.js';
import { clientCredential } from '../credential.js';
import { IdentityError } from './contract.js';
import type { IdentityRequest, UpstreamIdentity } from './contract.js';
import { githubProfile } from './github.js';

/*
 * An identity read back from the provider, for a provider that asserts none.
 *
 * There is no metadata document to discover, so the endpoints come from the catalogue entry, and there is
 * no assertion to verify, so the `nonce` has nothing to be compared against. What protects this leg is
 * therefore the two things that protect it for every provider: the `state` is spent once and found only by
 * its digest, and the code is bound to the request that asked for it.
 *
 * The provider's token is used and dropped inside this function. That is the existing rule for upstream
 * tokens — no feature calls an upstream API beyond this read, so keeping one would create a secret to leak
 * and a refresh lifecycle to maintain.
 */

const READERS = {
	github: githubProfile
} as const;

export async function profileApiIdentity(
	request: IdentityRequest,
	protocol: {
		tokenEndpoint: string;
		reader: keyof typeof READERS;
	}
): Promise<UpstreamIdentity> {
	const token = await exchangeForApiToken(request, protocol.tokenEndpoint);
	return READERS[protocol.reader](token);
}

async function exchangeForApiToken(
	request: IdentityRequest,
	tokenEndpoint: string
): Promise<string> {
	const { provider, code, bucket, codeVerifier } = request;

	const body = new URLSearchParams({
		grant_type: 'authorization_code',
		code,
		redirect_uri: callbackUri(bucket),
		client_id: provider.clientId,
		client_secret: await clientCredential(provider)
	});
	if (codeVerifier) body.set('code_verifier', codeVerifier);

	let response: Response;
	try {
		response = await fetch(tokenEndpoint, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				/*
				 * Asked for explicitly because the endpoint answers form-encoded by default, which the OAuth
				 * spec does not permit and which parses as JSON into nothing. The failure without this is a
				 * token that reads as `undefined` and a sign-in that fails as though the code were invalid.
				 */
				accept: 'application/json'
			},
			body
		});
	} catch (err) {
		throw new IdentityError(
			'upstream',
			err instanceof Error ? err.message : 'unreachable'
		);
	}

	if (!response.ok) {
		throw new IdentityError('upstream', `status ${response.status}`);
	}

	let parsed: unknown;
	try {
		parsed = await response.json();
	} catch {
		throw new IdentityError('upstream', 'token response is not JSON');
	}
	if (typeof parsed !== 'object' || parsed === null) {
		throw new IdentityError('upstream', 'token response is not an object');
	}

	const token = (parsed as Record<string, unknown>).access_token;
	if (typeof token !== 'string' || token.length === 0) {
		/*
		 * `rejected` rather than `upstream`: the endpoint answered, and what it said was that this exchange
		 * is not good for a token. That is the same class as an assertion that fails verification.
		 */
		throw new IdentityError('rejected', 'no access token');
	}
	return token;
}
