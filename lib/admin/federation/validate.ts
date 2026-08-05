import { AdminError } from '../auth/rbac.js';
import type { UserBucket } from '../../adapters/types.js';
import type { FederationProvider } from '../../federation/types.js';

/*
 * Every rule a provider configuration has to satisfy, and the one rule about the bucket as a whole.
 *
 * The lockout rule lives here rather than in either route because it is reachable from two directions —
 * switching password sign-in off, and disabling or deleting the last enabled provider — and two copies of a
 * lockout rule disagree after the first edit. At which point the two entry points disagree about whether a
 * bucket is reachable at all, which is the state this exists to make impossible.
 */

/* Slug-shaped: it appears in a URL the login page builds, so an operator needs it readable and safe. */
const PROVIDER_ID = /^[a-z0-9-]{1,32}$/;

/* Bare lowercase domains. Not `@acme.com`, not `ACME.com`, not `*.acme.com`. */
const DOMAIN =
	/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

export function assertProviderId(
	id: string,
	existing: FederationProvider[],
	{ replacing }: { replacing?: string } = {}
): void {
	if (!PROVIDER_ID.test(id)) {
		throw new AdminError(
			422,
			`provider id must be 1-32 characters of a-z, 0-9 or '-': ${id}`
		);
	}
	const clash = existing.some(
		(provider) => provider.id === id && provider.id !== replacing
	);
	if (clash) {
		throw new AdminError(422, `a provider with this id already exists: ${id}`);
	}
}

export function assertIssuer(issuer: string): void {
	let parsed: URL;
	try {
		parsed = new URL(issuer);
	} catch {
		throw new AdminError(422, `issuer must be an absolute URL: ${issuer}`);
	}
	/*
	 * https only. An identity assertion's whole value is that it came from the party it names, and a plain
	 * http discovery document can be rewritten in flight by anyone on the path.
	 */
	if (parsed.protocol !== 'https:') {
		throw new AdminError(422, `issuer must use https: ${issuer}`);
	}
}

export function assertScopes(scopes: string[]): void {
	// Without `openid` the response is not an OIDC one and carries no ID token, so there is nothing to verify.
	if (!scopes.includes('openid')) {
		throw new AdminError(422, "scopes must include 'openid'");
	}
}

export function assertEmailDomains(domains: string[]): void {
	for (const domain of domains) {
		if (!DOMAIN.test(domain)) {
			/*
			 * Refused rather than silently normalised: an operator who typed `@acme.com` should learn now, not
			 * discover later that nobody from Acme can sign in.
			 */
			throw new AdminError(
				422,
				`allowed email domains must be bare lowercase domains: ${domain}`
			);
		}
	}
}

/*
 * The one invariant about the bucket as a whole: **somebody must be able to sign in.**
 *
 * Called with the state the request would produce, not the state it starts from, so both entry points ask
 * the same question — "would this leave the bucket unreachable?" — rather than each reasoning about its own
 * kind of change.
 *
 * Deliberately not guarded: removing the last provider while password sign-in is *on*. That bucket is
 * perfectly usable; its login page simply stops offering providers.
 */
export function assertSomeWayToSignIn(next: {
	passwordLogin: boolean;
	federation: FederationProvider[];
}): void {
	if (next.passwordLogin) return;
	if (next.federation.some((provider) => provider.enabled)) return;

	throw new AdminError(
		409,
		'that would leave this bucket with no way to sign in: enable a provider first, or turn password sign-in back on'
	);
}

/* The bucket as it would be after `patch` is applied — the input `assertSomeWayToSignIn` needs. */
export function prospectiveBucket(
	bucket: Pick<UserBucket, 'passwordLogin' | 'federation'>,
	patch: {
		passwordLogin?: boolean;
		federation?: FederationProvider[];
	}
): { passwordLogin: boolean; federation: FederationProvider[] } {
	return {
		passwordLogin: patch.passwordLogin ?? bucket.passwordLogin !== false,
		federation: patch.federation ?? bucket.federation ?? []
	};
}
