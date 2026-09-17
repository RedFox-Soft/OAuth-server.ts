import { SignJWT, exportJWK, exportPKCS8, generateKeyPair } from 'jose';
import type { KeyObject } from 'crypto';

import { mock } from '../fetch_mock.js';
import { forgetDiscovery } from 'lib/federation/discovery.js';

/*
 * Stub upstreams for the three recognised providers that are not Google, over the existing outbound-fetch
 * mock.
 *
 * One module rather than three, because all three share the same awkward problem and it should have one
 * solution. `idp_stub.ts`'s first harness rule is "give each case its own origin", since the discovery and
 * key-set caches are keyed by URL and a second case reusing an origin silently skips a fetch — failing a
 * *different* case than the one that caused it. These three cannot obey it: their origins are real and
 * fixed, which is the whole point of recognising them.
 *
 * So the rule is satisfied a different way, and both halves are needed:
 *
 * - `forgetDiscovery(issuer)` is called when a stub is built, clearing the metadata cache for it. This is
 *   what `assertIssuerResolves` already does before every admin write, for the same reason.
 * - the key set is advertised at a **per-case URL**, because jose's `RemoteJWKSet` is held per `jwks_uri`
 *   with a freshness window of its own and nothing resets it. A query string is enough to make it distinct
 *   and costs the production code nothing: it reads whatever URL the provider advertised.
 *
 * The mock takes a *synchronous* body matcher and a static reply, so anything a case needs to assert about
 * what was **sent** is captured here and asserted there. Apple's credential is the reason that matters:
 * verifying it needs a promise, and it belongs in the case anyway.
 */

const ALG = 'RS256';
const json = { headers: { 'content-type': 'application/json' } };

let caseCounter = 0;
/* Distinct per stub, so no two cases share a cached key set. */
function caseTag(): string {
	caseCounter += 1;
	return `c${caseCounter}`;
}

/* ------------------------------------------------------------------ Microsoft */

export interface MicrosoftStub {
	issuer: string;
	tenant: string;
	clientId: string;
	expectDiscovery(): void;
	/* Microsoft's multi-organisation documents name the issuer as a literal placeholder. */
	expectTemplatedDiscovery(): void;
	/*
	 * Answers the token request for a sign-in already in flight. Two-phase for `idp_stub.ts`'s reason: the
	 * assertion must echo the nonce the start leg minted, which does not exist until that leg has run.
	 *
	 * `assertingTenant` mints an assertion from a *different* organisation, which is the refusal case.
	 */
	answerToken(
		authorizeUrl: URL,
		claims: Record<string, unknown>,
		options?: { assertingTenant?: string }
	): Promise<void>;
}

export async function microsoftStub(
	tenant: string,
	options: { clientId?: string } = {}
): Promise<MicrosoftStub> {
	const origin = 'https://login.microsoftonline.com';
	const issuer = `${origin}/${tenant}/v2.0`;
	const tag = caseTag();
	const jwksPath = `/${tenant}/discovery/v2.0/keys?${tag}`;
	const keyPair = await generateKeyPair(ALG, { extractable: true });
	const kid = `ms-${tag}`;
	const clientId = options.clientId ?? '00001111-aaaa-2222-bbbb-3333cccc4444';

	forgetDiscovery(issuer);
	const target = mock(origin);

	const metadata = (issuerValue: string) => ({
		issuer: issuerValue,
		authorization_endpoint: `${origin}/${tenant}/oauth2/v2.0/authorize`,
		token_endpoint: `${origin}/${tenant}/oauth2/v2.0/token`,
		jwks_uri: `${origin}${jwksPath}`,
		response_types_supported: ['code'],
		subject_types_supported: ['pairwise'],
		id_token_signing_alg_values_supported: [ALG],
		/*
		 * No `code_challenge_methods_supported`, exactly as Microsoft publishes none — which is the fact
		 * the code-binding rule exists for. If this stub advertised one, the guard proving the binding is
		 * sent anyway would pass for the wrong reason.
		 */
		token_endpoint_auth_methods_supported: [
			'client_secret_post',
			'client_secret_basic'
		]
	});

	const discoveryPath = `/${tenant}/v2.0/.well-known/openid-configuration`;

	return {
		issuer,
		tenant,
		clientId,
		expectDiscovery() {
			target
				.intercept({ path: discoveryPath })
				.reply(200, JSON.stringify(metadata(issuer)), json);
		},
		expectTemplatedDiscovery() {
			target
				.intercept({ path: discoveryPath })
				.reply(
					200,
					JSON.stringify(metadata(`${origin}/{tenantid}/v2.0`)),
					json
				);
		},
		async answerToken(authorizeUrl, claims, opts = {}) {
			const jwk = await exportJWK(keyPair.publicKey);
			target
				.intercept({ path: jwksPath })
				.reply(
					200,
					JSON.stringify({ keys: [{ ...jwk, alg: ALG, use: 'sig', kid }] }),
					json
				);

			const now = Math.floor(Date.now() / 1000);
			const idToken = await new SignJWT({
				/*
				 * The real issuer of the assertion. For a multi-organisation endpoint this is the
				 * organisation's own issuer rather than the one configured — the case the templated issuer
				 * rule exists to admit.
				 */
				iss: issuer,
				aud: clientId,
				sub: `ms-subject-${tag}`,
				tid: opts.assertingTenant ?? tenant,
				nonce: authorizeUrl.searchParams.get('nonce'),
				iat: now,
				...claims
			})
				.setProtectedHeader({ alg: ALG, kid })
				.setExpirationTime(now + 300)
				.sign(keyPair.privateKey);

			target
				.intercept({ path: `/${tenant}/oauth2/v2.0/token`, method: 'POST' })
				.reply(200, JSON.stringify({ id_token: idToken }), json);
		}
	};
}

/* ---------------------------------------------------------------------- Apple */

export interface AppleStub {
	issuer: string;
	clientId: string;
	teamId: string;
	keyId: string;
	/* The PKCS#8 text an administrator pastes out of the downloaded file. */
	signingKey: string;
	/* Its public half, so a case can verify what was presented. */
	verificationKey: CryptoKey | KeyObject;
	expectDiscovery(): void;
	answerToken(
		authorizeUrl: URL,
		claims: Record<string, unknown>
	): Promise<void>;
	/*
	 * What the token endpoint was actually sent. Captured rather than verified here: verification needs a
	 * promise and the mock's body matcher is synchronous — and the assertion belongs in the case, which is
	 * where the claim about it is being made.
	 */
	presentedCredential(): string | undefined;
}

export async function appleStub(): Promise<AppleStub> {
	const origin = 'https://appleid.apple.com';
	const tag = caseTag();
	const jwksPath = `/auth/keys?${tag}`;
	const idKeys = await generateKeyPair(ALG, { extractable: true });
	const credentialKeys = await generateKeyPair('ES256', { extractable: true });
	const kid = `apple-${tag}`;
	const clientId = 'com.example.auth';
	let presented: string | undefined;

	forgetDiscovery(origin);
	const target = mock(origin);

	return {
		issuer: origin,
		clientId,
		teamId: 'ABCDE12345',
		keyId: 'KEY1234567',
		signingKey: await exportPKCS8(credentialKeys.privateKey),
		verificationKey: credentialKeys.publicKey,
		presentedCredential: () => presented,
		expectDiscovery() {
			target.intercept({ path: '/.well-known/openid-configuration' }).reply(
				200,
				JSON.stringify({
					issuer: origin,
					authorization_endpoint: `${origin}/auth/authorize`,
					token_endpoint: `${origin}/auth/token`,
					jwks_uri: `${origin}${jwksPath}`,
					response_types_supported: ['code'],
					response_modes_supported: ['query', 'fragment', 'form_post'],
					subject_types_supported: ['pairwise'],
					id_token_signing_alg_values_supported: [ALG],
					/* Exactly one, and no challenge method at all — as Apple publishes it. */
					token_endpoint_auth_methods_supported: ['client_secret_post']
				}),
				json
			);
		},
		async answerToken(authorizeUrl, claims) {
			const jwk = await exportJWK(idKeys.publicKey);
			target
				.intercept({ path: jwksPath })
				.reply(
					200,
					JSON.stringify({ keys: [{ ...jwk, alg: ALG, use: 'sig', kid }] }),
					json
				);

			const now = Math.floor(Date.now() / 1000);
			const idToken = await new SignJWT({
				iss: origin,
				aud: clientId,
				sub: `apple-subject-${tag}`,
				nonce: authorizeUrl.searchParams.get('nonce'),
				iat: now,
				...claims
			})
				.setProtectedHeader({ alg: ALG, kid })
				.setExpirationTime(now + 300)
				.sign(idKeys.privateKey);

			target
				.intercept({
					path: '/auth/token',
					method: 'POST',
					body: (value) => {
						presented =
							new URLSearchParams(value).get('client_secret') ?? undefined;
						return true;
					}
				})
				.reply(200, JSON.stringify({ id_token: idToken }), json);
		}
	};
}

/* --------------------------------------------------------------------- GitHub */

export interface GitHubStub {
	issuer: string;
	clientId: string;
	expectToken(): void;
	expectProfile(profile: Record<string, unknown>): void;
	/* The addresses read. Pass `{ status }` to refuse it instead of answering with a list. */
	expectAddresses(
		addresses: Record<string, unknown>[] | { status: number }
	): void;
}

export function githubStub(): GitHubStub {
	const login = mock('https://github.com');
	const api = mock('https://api.github.com');

	return {
		issuer: 'https://github.com',
		clientId: 'Ov23liExampleClientId',
		expectToken() {
			login
				.intercept({ path: '/login/oauth/access_token', method: 'POST' })
				.reply(
					200,
					JSON.stringify({ access_token: 'gho_stub', token_type: 'bearer' }),
					json
				);
		},
		expectProfile(profile) {
			api
				.intercept({ path: '/user' })
				.reply(200, JSON.stringify(profile), json);
		},
		expectAddresses(addresses) {
			if (!Array.isArray(addresses)) {
				api
					.intercept({ path: '/user/emails' })
					.reply(addresses.status, 'Forbidden');
				return;
			}
			api
				.intercept({ path: '/user/emails' })
				.reply(200, JSON.stringify(addresses), json);
		}
	};
}
