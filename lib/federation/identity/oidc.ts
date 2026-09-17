import { knownProviderByIssuer } from '../../consts/known_providers.js';
import { DiscoveryError, discover } from '../discovery.js';
import { ExchangeError, exchangeCode } from '../flow.js';
import {
	FederationIdTokenRejected,
	verifyFederatedIdToken
} from '../verifyIdToken.js';
import { IdentityError } from './contract.js';
import type { IdentityRequest, UpstreamIdentity } from './contract.js';

/*
 * An identity asserted by the provider itself: discover, exchange, verify, read the claims.
 *
 * This is the path that existed before there was a seam, moved rather than rewritten. Two things were
 * added, and each is one provider's published requirement rather than a choice:
 *
 * - the **organisation check**, because one provider issues assertions for every organisation in the world
 *   from one endpoint, and its own documentation says the application must restrict which of them it
 *   accepts. Nothing else does that job: the issuer cannot, for exactly the reason the entry is templated.
 * - the **address fallback**, because that provider does not always answer in the claim the others do.
 */

export async function oidcIdentity(
	request: IdentityRequest
): Promise<UpstreamIdentity> {
	const { provider, code, bucket, nonce, codeVerifier } = request;

	let idToken: string | undefined;
	let metadata;
	try {
		metadata = await discover(provider.issuer);
		idToken = await exchangeCode(
			provider,
			metadata,
			code,
			bucket,
			codeVerifier
		);
	} catch (err) {
		if (err instanceof DiscoveryError || err instanceof ExchangeError) {
			throw new IdentityError('upstream', err.reason);
		}
		throw err;
	}

	let assertion;
	try {
		const entry = knownProviderByIssuer(provider.issuer);
		assertion = await verifyFederatedIdToken(idToken, {
			metadata,
			clientId: provider.clientId,
			nonce,
			/*
			 * Only where the provider's issuer names the organisation. The assertion then legitimately comes
			 * from an issuer that is not the one configured — a real organisation's, where the configured
			 * value may be a placeholder — so the check becomes the shape, and the organisation claim below
			 * decides whether *that* organisation is admitted.
			 */
			...(entry?.issuerRule.kind === 'templated'
				? {
						acceptIssuer: (issuer: string) =>
							(entry.issuerRule as { pattern: RegExp }).pattern.test(issuer)
					}
				: {})
		});
	} catch (err) {
		if (err instanceof FederationIdTokenRejected) {
			throw new IdentityError('rejected', err.reason);
		}
		throw err;
	}

	assertPermittedOrganisation(provider, assertion.claims);

	return {
		subject: assertion.subject,
		claims: withFallbackAddress(provider, assertion.claims)
	};
}

/*
 * The assertion came from the organisation this connection admits.
 *
 * Only asked where the connection names one, and skipped for the words that mean "any". A provider from
 * elsewhere is `rejected` rather than answered with a reason, because this route is unauthenticated and
 * naming the organisation somebody arrived from would tell an unauthenticated caller who is configured
 * here.
 */
function assertPermittedOrganisation(
	provider: { issuer: string; tenant?: string },
	claims: Record<string, unknown>
): void {
	const tenant = provider.tenant;
	if (!tenant) return;
	/*
	 * The three documented words all mean "more than one organisation", so there is nothing to compare —
	 * the administrator chose breadth deliberately and was told what it meant before saving.
	 */
	if (tenant === 'common' || tenant === 'organizations') return;

	const entry = knownProviderByIssuer(provider.issuer);
	const claimName = entry?.organisationClaim;
	if (!claimName) return;

	const asserted = claims[claimName];
	/*
	 * A missing claim fails closed. The alternative — admitting an assertion that says nothing about which
	 * organisation it came from — would make the restriction advisory, and it is the whole of what the
	 * administrator chose.
	 */
	if (typeof asserted !== 'string' || asserted !== tenant) {
		throw new IdentityError('rejected', 'organisation_not_permitted');
	}
}

/*
 * An address from the provider's second field, where it has one and the first was empty.
 *
 * Used **only if the value is actually an address**: the fallback field is documented as possibly holding
 * a phone number or a bare username, and treating one of those as an email address would provision an
 * account under a string no message can reach — and, worse, could collide with another such string.
 *
 * The claims record is copied rather than mutated: it came out of a verified assertion, and rewriting it
 * in place would leave later readers unable to tell what the provider actually said.
 */
function withFallbackAddress(
	provider: { issuer: string; emailClaim: string },
	claims: Record<string, unknown>
): Record<string, unknown> {
	if (typeof claims[provider.emailClaim] === 'string') return claims;

	const entry = knownProviderByIssuer(provider.issuer);
	for (const name of entry?.fallbackEmailClaims ?? []) {
		const value = claims[name];
		if (typeof value === 'string' && looksLikeAddress(value)) {
			return { ...claims, [provider.emailClaim]: value };
		}
	}
	return claims;
}

/*
 * Deliberately weak. It separates an address from a phone number or a bare username, which is the only
 * distinction being drawn here — the decision ladder does the rest, and a strict pattern would refuse
 * addresses that exist.
 */
function looksLikeAddress(value: string): boolean {
	const at = value.indexOf('@');
	return at > 0 && value.indexOf('.', at) > at + 1;
}
