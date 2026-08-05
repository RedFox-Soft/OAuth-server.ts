import { SignJWT, exportJWK, generateKeyPair } from 'jose';

import { mock } from '../fetch_mock.js';

/*
 * A stub upstream OpenID Provider, over the existing outbound-fetch mock. Serves the three documents a
 * federated sign-in reads — discovery metadata, the key set, and the token endpoint — and mints ID
 * tokens, including deliberately broken ones.
 *
 * TWO HARNESS RULES, and every case depends on them:
 *
 * 1. **Give each case its own origin.** The discovery and JWKS caches are module-level and keyed by URL,
 *    and jose's RemoteJWKSet adds its own freshness window and cooldown on top — so a second case reusing
 *    an origin would silently skip a fetch. Interceptors here are single-use and matched exactly on
 *    (origin, path, method), and `assertNoPendingInterceptors()` throws on one that was never hit, so a
 *    skipped fetch fails a *different* case than the one that caused it. `idpStub('https://idp-jit.test')`
 *    per case keeps each fetch count a property of that case alone.
 * 2. **Register exactly the interceptors the case will consume.** An uncached sign-in needs three, in two
 *    phases: `expectDiscovery()` before leg one, then `answerToken(authorizeUrl, …)` once leg one has run.
 *    A case exercising the metadata cache registers discovery once and signs in twice.
 *
 * The two phases are not a convenience. The ID token has to echo the `nonce` the start route minted, and
 * that value does not exist until leg one has run — so a stub that registered everything up front could
 * only ever mint a token the verifier must reject. The first version of this harness did exactly that, and
 * the nonce check caught it.
 *
 * DEVIATION from contracts/upstream-oidc.md § 6, deliberately: the stub signs with its **own** generated
 * key pair rather than this server's test keystore. An upstream provider does not share keys with its
 * relying party, and the difference is load-bearing for what these tests prove — if verification ever
 * resolved keys from the local keystore instead of the provider's `jwks_uri`, a stub signing with our own
 * keys would pass anyway. Independent keys make that bug fail.
 */

const ALG = 'RS256';

export interface IdpStub {
	origin: string;
	/* Everything the provider advertises. Override per case to exercise a capability or its absence. */
	metadata: Record<string, unknown>;
	/*
	 * Answer the token request for a sign-in already in flight: registers JWKS and the token endpoint with
	 * an ID token echoing the `nonce` from the authorization request. Two-phase because that nonce does not
	 * exist until leg one has run.
	 */
	answerToken(
		authorizeUrl: URL,
		claims: Record<string, unknown>,
		opts?: SignOptions
	): Promise<void>;
	/* Register discovery alone — for a case that asserts the metadata cache is used. */
	expectDiscovery(): void;
	/* Register the key set alone. */
	expectJwks(): Promise<void>;
	/* Register the token endpoint returning a caller-supplied body. */
	expectToken(body: Record<string, unknown>): void;
	/* Register the token endpoint returning a raw status, for the unreachable/malformed cases. */
	expectTokenFailure(status: number, body?: string): void;
	/* Register discovery returning a raw status or body, for the same. */
	expectDiscoveryFailure(status: number, body?: string): void;
	/* Mint an ID token. `opts` breaks it in exactly one way per named field. */
	idToken(claims: Record<string, unknown>, opts?: SignOptions): Promise<string>;
	/* The public key set this stub serves, for a case that needs it inline. */
	publicJwks(): Promise<{ keys: Record<string, unknown>[] }>;
}

export interface SignOptions {
	/* Override the issuer claim — for the iss-mismatch case. */
	issuer?: string;
	/* Override the audience — for the aud-mismatch case. */
	audience?: string;
	/* Seconds from now; negative mints an already-expired token. */
	expiresIn?: number;
	/* Seconds from now for `iat`; positive mints one issued in the future. */
	issuedIn?: number;
	/* Omit `sub` entirely. */
	noSubject?: boolean;
	/* Sign with a key the stub does not publish, for the unknown-kid and bad-signature cases. */
	foreignKey?: boolean;
	/* Emit an unsecured token, which must be refused as an algorithm violation. */
	unsecured?: boolean;
	/* Claim an algorithm outside the advertised set. */
	alg?: string;
	/* Echo a nonce other than the one requested — the replay case, which must be refused. */
	nonce?: string;
}

const DEFAULT_METADATA = (origin: string) => ({
	issuer: origin,
	authorization_endpoint: `${origin}/authorize`,
	token_endpoint: `${origin}/token`,
	jwks_uri: `${origin}/jwks`,
	response_types_supported: ['code'],
	subject_types_supported: ['public'],
	id_token_signing_alg_values_supported: [ALG],
	code_challenge_methods_supported: ['S256'],
	token_endpoint_auth_methods_supported: ['client_secret_basic']
});

export async function idpStub(
	origin: string,
	overrides: Record<string, unknown> = {}
): Promise<IdpStub> {
	const keyPair = await generateKeyPair(ALG, { extractable: true });
	const foreignPair = await generateKeyPair(ALG, { extractable: true });
	const kid = 'stub-key-1';

	const metadata = { ...DEFAULT_METADATA(origin), ...overrides };
	const target = mock(origin);
	/*
	 * jose's RemoteJWKSet caches a provider's keys per jwks_uri for its freshness window, so a second
	 * sign-in against the same origin does not refetch them. The stub therefore publishes its key set once
	 * — registering a second interceptor would leave one unhit and fail the case that registered it.
	 */
	let jwksPublished = false;
	const json = { headers: { 'content-type': 'application/json' } };

	async function publicJwks() {
		const jwk = await exportJWK(keyPair.publicKey);
		return { keys: [{ ...jwk, alg: ALG, use: 'sig', kid }] };
	}

	async function idToken(
		claims: Record<string, unknown>,
		opts: SignOptions = {}
	): Promise<string> {
		const now = Math.floor(Date.now() / 1000);
		const payload: Record<string, unknown> = {
			iss: opts.issuer ?? origin,
			aud: opts.audience ?? 'stub-client',
			sub: 'upstream-subject-1',
			iat: now + (opts.issuedIn ?? 0),
			...claims
		};
		if (opts.noSubject) delete payload.sub;

		if (opts.unsecured) {
			// Hand-assembled: jose will not produce an unsecured JWS, which is itself the point.
			const b64 = (value: object) =>
				Buffer.from(JSON.stringify(value)).toString('base64url');
			return `${b64({ alg: 'none', typ: 'JWT' })}.${b64({
				...payload,
				exp: now + (opts.expiresIn ?? 300)
			})}.`;
		}

		return new SignJWT(payload)
			.setProtectedHeader({ alg: opts.alg ?? ALG, kid })
			.setExpirationTime(now + (opts.expiresIn ?? 300))
			.sign(opts.foreignKey ? foreignPair.privateKey : keyPair.privateKey);
	}

	function expectDiscovery() {
		target
			.intercept({ path: '/.well-known/openid-configuration' })
			.reply(200, JSON.stringify(metadata), json);
	}

	function expectDiscoveryFailure(status: number, body?: string) {
		target
			.intercept({ path: '/.well-known/openid-configuration' })
			.reply(status, body, json);
	}

	async function expectJwks() {
		target
			.intercept({ path: '/jwks' })
			.reply(200, JSON.stringify(await publicJwks()), json);
	}

	function expectToken(body: Record<string, unknown>) {
		target
			.intercept({ path: '/token', method: 'POST' })
			.reply(200, JSON.stringify(body), json);
	}

	function expectTokenFailure(status: number, body?: string) {
		target
			.intercept({ path: '/token', method: 'POST' })
			.reply(status, body, json);
	}

	/*
	 * Answer the token request for a sign-in already in flight.
	 *
	 * Two-phase on purpose, and not merely for convenience: the ID token must echo the `nonce` the start
	 * route minted, and that value does not exist until leg one has run. A stub that minted its token up
	 * front could only ever produce one the verifier must reject — which is exactly what the first version
	 * of this harness did, and the nonce check caught it. Reading the nonce out of the authorization request
	 * is also precisely what a real provider does with it.
	 *
	 * `opts.nonce` overrides the echo, for the replay case that must be refused.
	 */
	async function answerToken(
		authorizeUrl: URL,
		claims: Record<string, unknown>,
		opts: SignOptions = {}
	) {
		if (!jwksPublished) {
			await expectJwks();
			jwksPublished = true;
		}
		const nonce = opts.nonce ?? authorizeUrl.searchParams.get('nonce') ?? '';
		expectToken({
			// Both are deliberately present and must be discarded unread: a test that never supplied them
			// could not tell "discarded" from "never received".
			access_token: 'upstream-access-token-must-not-be-stored',
			refresh_token: 'upstream-refresh-token-must-not-be-stored',
			token_type: 'Bearer',
			id_token: await idToken({ nonce, ...claims }, opts)
		});
	}

	return {
		origin,
		metadata,
		answerToken,
		expectDiscovery,
		expectJwks,
		expectToken,
		expectTokenFailure,
		expectDiscoveryFailure,
		idToken,
		publicJwks
	};
}
