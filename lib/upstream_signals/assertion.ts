import {
	decodeJwt,
	decodeProtectedHeader,
	errors as joseErrors,
	jwtVerify,
	type JWTPayload
} from 'jose';

import type { UserBucket } from '../adapters/types.js';
import { clockTolerance } from '../configs/liveTime.js';
import { discover } from '../federation/discovery.js';
import { presentedKeySetFor } from '../federation/jwks.js';
import type { FederationProvider } from '../federation/types.js';
import epochTime from '../helpers/epoch_time.js';
import {
	InvalidToken,
	UpstreamKeysUnavailable,
	UpstreamNotPermitted
} from '../helpers/errors.js';
import { ReplayDetection } from '../models/replay_detection.js';
import { EgressRefused } from '../shared/egress.js';

/*
 * The request "an upstream provider of this bucket asks to end a user's access", whatever format it arrives in
 * (specs/072 FR-006b). Who may ask, how the asker is authenticated, and the refusals that follow from both are
 * decided here once; a format — global token revocation now, inbound back-channel logout or a CAEP event later
 * — supplies only its audience, the token types it accepts, its replay namespace and which provider option
 * admits it. A later format therefore inherits every refusal below rather than restating them.
 *
 * Everything presented here is adversarial input. The sign-in verifier (lib/federation/verifyIdToken.ts) is
 * deliberately not reused: it may assume the token came from the provider's own token endpoint over TLS and is
 * bound by a nonce, and none of that holds for a JWT a third party hands us.
 */

/* The longest an assertion may live, measured from its issue time and from now (spec FR-007). */
const MAX_LIFETIME_SECONDS = 300;

/*
 * Asymmetric algorithms only, whatever any provider, bucket or instance setting says (FR-006a). Keycloak's
 * CVE-2026-18569 is the reason this is a constant and not a configuration: its back-channel logout receiver
 * accepted `alg: none` for a provider whose signature validation an operator had switched off, and the issuer,
 * client id and upstream subject an attacker needed are not secrets. A shared-secret algorithm is refused for
 * the same reason — nobody but the provider may hold the key that signs these.
 */
const ASYMMETRIC_ALGORITHMS = new Set([
	'RS256',
	'RS384',
	'RS512',
	'PS256',
	'PS384',
	'PS512',
	'ES256',
	'ES384',
	'ES512',
	'EdDSA'
]);

export interface UpstreamExpectation {
	/* The exact address the assertion must be audienced to. */
	audience: string;
	/* Accepted `typ` values beside an absent one, lowercase, without an `application/` prefix. */
	types: readonly string[];
	/* Keeps one format's assertion identifiers apart from every other use of the replay store. */
	replayNamespace: string;
	/* Which provider option admits this format; a provider failing it is refused after authentication. */
	permits: (provider: FederationProvider) => boolean;
}

export interface AuthenticatedUpstream {
	provider: FederationProvider;
	claims: JWTPayload;
}

function refused(reason: string): InvalidToken {
	return new InvalidToken(reason);
}

/*
 * The provider is found by its issuer and our client identifier there, compared as two separate values. A key
 * composed from them (or from the provider's own id) can collide across a delimiter — Keycloak #42209 broke
 * brokered logout exactly that way, with a provider alias containing a dot.
 */
function providerFor(
	bucket: UserBucket,
	iss: string,
	sub: string
): FederationProvider | undefined {
	return bucket.federation?.find(
		(provider) => provider.issuer === iss && provider.clientId === sub
	);
}

function typeAccepted(typ: unknown, types: readonly string[]): boolean {
	if (typ === undefined) return true;
	if (typeof typ !== 'string') return false;
	const normalised = typ.toLowerCase().replace(/^application\//, '');
	return normalised === 'jwt' || types.includes(normalised);
}

/* A failure to read the provider's keys is the provider's outage, not the caller's bad credential. */
function keysUnreadable(err: unknown): boolean {
	return (
		err instanceof EgressRefused ||
		err instanceof joseErrors.JWKSTimeout ||
		err instanceof joseErrors.JWKSInvalid ||
		(err instanceof joseErrors.JOSEError &&
			err.code === 'ERR_JOSE_GENERIC' &&
			/JSON Web Key Set/.test(err.message))
	);
}

function audienceIs(aud: JWTPayload['aud'], expected: string): boolean {
	if (typeof aud === 'string') return aud === expected;
	return Array.isArray(aud) && aud.length === 1 && aud[0] === expected;
}

export async function authenticateUpstream(
	bucket: UserBucket,
	jwt: string,
	expected: UpstreamExpectation
): Promise<AuthenticatedUpstream> {
	let header: ReturnType<typeof decodeProtectedHeader>;
	let unverified: JWTPayload;
	try {
		header = decodeProtectedHeader(jwt);
		unverified = decodeJwt(jwt);
	} catch {
		throw refused('malformed');
	}
	const { iss, sub } = unverified;
	if (typeof iss !== 'string' || !iss || typeof sub !== 'string' || !sub) {
		throw refused('unattributable');
	}
	const provider = providerFor(bucket, iss, sub);
	if (!provider) throw refused('unknown_provider');

	if (!typeAccepted(header.typ, expected.types)) throw refused('type');

	let metadata;
	try {
		metadata = await discover(provider.issuer);
	} catch (err) {
		throw new UpstreamKeysUnavailable(
			err instanceof Error ? err.message : undefined
		);
	}
	/* OIDC Discovery §3: a provider that advertises no ID-token algorithm signs with RS256. */
	const advertised = metadata.signingAlgValues.length
		? metadata.signingAlgValues
		: ['RS256'];
	const algorithms = advertised.filter((alg) => ASYMMETRIC_ALGORITHMS.has(alg));
	if (typeof header.alg !== 'string' || !algorithms.includes(header.alg)) {
		throw refused('algorithm');
	}

	let claims: JWTPayload;
	try {
		({ payload: claims } = await jwtVerify(
			jwt,
			presentedKeySetFor(metadata.jwksUri),
			{ issuer: provider.issuer, algorithms, clockTolerance }
		));
	} catch (err) {
		if (keysUnreadable(err)) {
			throw new UpstreamKeysUnavailable(
				err instanceof Error ? err.message : undefined
			);
		}
		throw refused(
			err instanceof joseErrors.JWTExpired
				? 'expired'
				: err instanceof joseErrors.JWTClaimValidationFailed
					? `claim_${err.claim}`
					: 'signature'
		);
	}

	if (!audienceIs(claims.aud, expected.audience)) throw refused('audience');
	const { exp, iat, jti } = claims;
	if (typeof exp !== 'number' || typeof iat !== 'number') {
		throw refused('lifetime');
	}
	if (typeof jti !== 'string' || !jti) throw refused('identifier');
	/*
	 * The lifetime is measured from the issue time and from now, never from `nbf`: Okta sends a not-before five
	 * minutes in the past and an expiry five minutes ahead, and measuring `exp - nbf` would refuse every real
	 * request (spec FR-007). `nbf` itself was checked by jwtVerify above.
	 */
	const now = epochTime();
	if (iat > now + clockTolerance) throw refused('issued_in_future');
	if (
		exp - iat > MAX_LIFETIME_SECONDS + clockTolerance ||
		exp - now > MAX_LIFETIME_SECONDS + clockTolerance
	) {
		throw refused('lifetime');
	}

	/*
	 * The namespace ends in a delimiter because the replay record's id is `sha256(namespace + jti)` with no
	 * separator of its own (lib/models/replay_detection.ts); bucket and provider ids contain no `:`, so two
	 * namespaces cannot run into each other's identifiers.
	 */
	const fresh = await ReplayDetection.unique(
		`${expected.replayNamespace}:${bucket._id}:${provider.id}:`,
		jti,
		exp + clockTolerance
	);
	if (!fresh) throw refused('replayed');

	if (!provider.enabled || !expected.permits(provider)) {
		throw new UpstreamNotPermitted();
	}
	return { provider, claims };
}
