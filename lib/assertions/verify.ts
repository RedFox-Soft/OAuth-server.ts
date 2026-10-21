import {
	decodeJwt,
	decodeProtectedHeader,
	jwtVerify,
	type JWTPayload
} from 'jose';

import { getBucketStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { ApplicationConfig } from '../configs/application.js';
import { issuerFor, type RequestBucket } from '../configs/issuer.js';
import { clockTolerance } from '../configs/liveTime.js';
import { ID_JAG_JWT_TYPE } from '../consts/assertion_grants.js';
import { knownProviderByIssuer } from '../consts/known_providers.js';
import { discover } from '../federation/discovery.js';
import { presentedKeySetFor } from '../federation/jwks.js';
import type { FederationProvider } from '../federation/types.js';
import epochTime from '../helpers/epoch_time.js';
import { InvalidGrant } from '../helpers/errors.js';
import { ASYMMETRIC_ALGORITHMS } from '../upstream_signals/assertion.js';
import { ReplayDetection } from '../models/replay_detection.js';
import { routeNames } from '../consts/param_list.js';

/*
 * The assertion presented to the JWT bearer grant (specs/108), authenticated against the provider of the
 * addressed project that is trusted for it — or refused.
 *
 * Everything presented here is adversarial input, and it is not authenticated by `authenticateUpstream`
 * (lib/upstream_signals/assertion.ts), whose pieces it shares — the key cache, the algorithm list: that one
 * finds a provider by our client identifier there, which an ID-JAG does not carry (it names this server in
 * `aud` and the agent in `client_id`), and it is single-use by construction, which an ID-JAG is not
 * (ID-JAG §4.4.3). The sign-in verifier is not reused either: it relies on a nonce and the provider's own
 * token endpoint, neither of which a presented JWT has.
 *
 * Every refusal is `invalid_grant` (RFC 7521 §4.1.1, RFC 7523 §3.1) with the same description, so a caller
 * cannot learn which issuers a project trusts or whom it knows; the reason travels in `error_detail`, which
 * reaches no response.
 */

export type AssertionProfile = 'id-jag' | 'plain';

export interface VerifiedAssertion {
	profile: AssertionProfile;
	bucket: UserBucket;
	provider: FederationProvider;
	claims: JWTPayload & Record<string, unknown>;
}

/*
 * Types this server or the governing texts reserve for another purpose. Accepting one as a grant would let a
 * token written for one job be replayed as another: a client's own authentication JWT (7523bis §4), a DPoP
 * proof, an access token, a logout or security event token, an introspection response.
 */
const RESERVED_TYPES = new Set([
	'client-authentication+jwt',
	'dpop+jwt',
	'at+jwt',
	'logout+jwt',
	'secevent+jwt',
	'token-introspection+jwt',
	'global-token-revocation+jwt'
]);

function refused(reason: string): InvalidGrant {
	return new InvalidGrant(`assertion:${reason}`);
}

function normalisedType(typ: unknown): string | undefined {
	return typeof typ === 'string'
		? typ.toLowerCase().replace(/^application\//, '')
		: undefined;
}

/* One audience only, as a string or a one-element array: a JWT audienced to several parties is not ours alone. */
function soleAudience(aud: JWTPayload['aud']): string | undefined {
	if (typeof aud === 'string') return aud || undefined;
	if (Array.isArray(aud) && aud.length === 1 && typeof aud[0] === 'string') {
		return aud[0] || undefined;
	}
	return undefined;
}

function trusts(
	provider: FederationProvider,
	profile: AssertionProfile,
	clientId: string
): boolean {
	if (!provider.enabled) return false;
	return profile === 'id-jag'
		? provider.acceptsIdentityAssertions === true
		: (provider.plainAssertions?.clientIds.includes(clientId) ?? false);
}

/*
 * For a provider admitting one organisation: the ID-JAG names it in `tenant` (ID-JAG §3.1, §6.3), or in the
 * claim the provider's own catalogue entry uses for it (Microsoft's `tid`), as a browser sign-in reads it. A
 * missing claim fails closed, as there: the restriction is the whole of what the administrator chose.
 */
function fromPermittedOrganisation(
	provider: FederationProvider,
	claims: Record<string, unknown>
): boolean {
	const tenant = provider.tenant;
	if (!tenant || tenant === 'common' || tenant === 'organizations') return true;
	if (claims.tenant === tenant) return true;
	const claimName = knownProviderByIssuer(provider.issuer)?.organisationClaim;
	return claimName !== undefined && claims[claimName] === tenant;
}

export async function verifyAssertion(
	addressed: RequestBucket,
	jwt: string,
	clientId: string
): Promise<VerifiedAssertion> {
	let header: ReturnType<typeof decodeProtectedHeader>;
	let unverified: JWTPayload;
	try {
		header = decodeProtectedHeader(jwt);
		unverified = decodeJwt(jwt);
	} catch {
		throw refused('malformed');
	}

	const typ = normalisedType(header.typ);
	if (typ !== undefined && RESERVED_TYPES.has(typ)) throw refused('type');
	const profile: AssertionProfile =
		typ === ID_JAG_JWT_TYPE ? 'id-jag' : 'plain';

	const issuer = issuerFor(addressed);
	const { iss } = unverified;
	if (typeof iss !== 'string' || !iss) throw refused('unattributable');
	/*
	 * ID-JAG §9.3: an issuer never honours what it issued itself. A project of this instance trusting another
	 * is a different issuer with keys of its own, which is the boundary the draft asks the ID-JAG to cross.
	 */
	if (iss === issuer) throw refused('own_issuer');

	const bucket = await getBucketStore().find(addressed._id);
	if (!bucket) throw refused('unknown_provider');
	/* Configuration refuses two trusted providers sharing an issuer, so at most one matches. */
	const provider = bucket.federation.find(
		(candidate) =>
			candidate.issuer === iss && trusts(candidate, profile, clientId)
	);
	if (!provider) throw refused('untrusted_issuer');

	let metadata;
	try {
		metadata = await discover(provider.issuer);
	} catch {
		/*
		 * The provider's outage, answered as a refusal rather than a server error: the request cannot be
		 * honoured, nothing here is broken, and an unreachable provider must never make an assertion pass.
		 */
		throw refused('keys_unavailable');
	}
	/* OIDC Discovery §3: a provider that advertises no ID-token algorithm signs with RS256. */
	const advertised = metadata.signingAlgValues.length
		? metadata.signingAlgValues
		: ['RS256'];
	const algorithms = advertised.filter((alg) => ASYMMETRIC_ALGORITHMS.has(alg));
	if (typeof header.alg !== 'string' || !algorithms.includes(header.alg)) {
		throw refused('algorithm');
	}

	let claims: JWTPayload & Record<string, unknown>;
	try {
		({ payload: claims } = await jwtVerify(
			jwt,
			presentedKeySetFor(metadata.jwksUri),
			{ issuer: provider.issuer, algorithms, clockTolerance }
		));
	} catch {
		throw refused('signature_or_time');
	}

	const { sub, jti, iat, exp } = claims;
	if (typeof sub !== 'string' || !sub) throw refused('subject');
	if (typeof jti !== 'string' || !jti) throw refused('identifier');
	if (typeof iat !== 'number' || typeof exp !== 'number') {
		throw refused('lifetime');
	}
	if (iat > epochTime() + clockTolerance) throw refused('issued_in_future');
	/* RFC 7521 §5.2: an expiry "unreasonably far in the future" may be refused; this is how far that is. */
	if (exp - iat > ApplicationConfig['jwtBearer.maxAssertionLifetime']) {
		throw refused('lifetime');
	}

	if (profile === 'id-jag') {
		/*
		 * ID-JAG §4.4.1: the issuer identifier alone, as a string or a one-element array — never the token
		 * endpoint URL, which 7523bis still permits for a plain grant but the profile does not.
		 */
		if (soleAudience(claims.aud) !== issuer) throw refused('audience');
		if (claims.client_id !== clientId) throw refused('client');
	} else {
		/*
		 * draft-ietf-oauth-rfc7523bis §4 item 3a: for the grant, this server may be named by its issuer identifier
		 * or its token endpoint URL, compared exactly; one value only (CHAIN §2.3.3), so it is ours alone.
		 */
		const audience = soleAudience(claims.aud);
		if (audience !== issuer && audience !== `${issuer}${routeNames.token}`) {
			throw refused('audience');
		}
	}

	if (!fromPermittedOrganisation(provider, claims)) {
		throw refused('organisation');
	}

	/*
	 * A plain assertion binds no client, so whoever holds it could present it; it is single-use (RFC 7523 §3
	 * item 7, CHAIN §5.5), spent only after every other check passed so a refused one costs no record. An ID-JAG
	 * is not: ID-JAG §4.4.3 lets the client present it again, and its `client_id` binding is what limits who may.
	 * The namespace ends in a delimiter because the record's id is `sha256(namespace + jti)`.
	 */
	if (profile === 'plain') {
		const fresh = await ReplayDetection.unique(
			`jwtb:${bucket._id}:${provider.id}:`,
			jti,
			exp + clockTolerance
		);
		if (!fresh) throw refused('replayed');
	}

	return { profile, bucket, provider, claims };
}
