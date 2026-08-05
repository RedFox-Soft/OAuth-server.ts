import { getBucketStore } from '../../adapters/index.js';
import { AdminError } from '../auth/rbac.js';
import {
	DiscoveryError,
	discover,
	forgetDiscovery
} from '../../federation/discovery.js';
import { DEFAULT_SCOPES, SECRET_MASK } from '../../federation/consts.js';
import type { UserBucket } from '../../adapters/types.js';
import type { FederationProvider } from '../../federation/types.js';
import {
	assertEmailDomains,
	assertIssuer,
	assertProviderId,
	assertScopes,
	assertSomeWayToSignIn
} from './validate.js';

/*
 * Reading, writing and validating a bucket's upstream providers.
 *
 * The array lives on the bucket document, so every mutation here is a read-modify-write of that one field.
 * Nothing else on the bucket is touched, which is what lets the provider routes and the bucket PATCH stay
 * separate operations with separate audit entries.
 */

/*
 * The client-facing view. The secret is replaced by a fixed mask rather than omitted, so a console form has
 * something to render in a password field and can tell "a secret is stored" from "none is".
 *
 * Applied on every read, for every role including super-admin: the value is write-only, and the audit
 * trail's names-not-values rule means it cannot reach a reader that way either.
 */
export function present(provider: FederationProvider) {
	return { ...provider, clientSecret: SECRET_MASK };
}

export function presentAll(bucket: Pick<UserBucket, 'federation'>) {
	return (bucket.federation ?? []).map(present);
}

function providersOf(bucket: Pick<UserBucket, 'federation'>) {
	return bucket.federation ?? [];
}

function find(
	bucket: Pick<UserBucket, 'federation'>,
	providerId: string
): FederationProvider {
	const provider = providersOf(bucket).find((p) => p.id === providerId);
	if (!provider) throw new AdminError(404, 'provider not found');
	return provider;
}

/*
 * Prove the issuer is real before storing it.
 *
 * Two statuses, and the split is the point: **422** when the document was fetched and disagrees about its
 * own issuer — the submitted value is the wrong thing, which is what catches a copy-pasted tenant URL, a
 * redirect, or a trailing slash — and **502** when the other side could not be reached or parsed, which is
 * not the caller's mistake. Both are better than discovering it at a user's first sign-in.
 *
 * This is also what replaces an admin "test connection" button: validation at write time already proves
 * reachability at the moment it matters.
 */
async function assertIssuerResolves(issuer: string): Promise<void> {
	// Any cached copy is dropped first, so correcting a mistyped issuer takes effect immediately rather
	// than being validated against the previous answer.
	forgetDiscovery(issuer);
	try {
		await discover(issuer);
	} catch (err) {
		if (err instanceof DiscoveryError) {
			if (err.reason === 'issuer_mismatch') {
				throw new AdminError(
					422,
					`the discovery document at ${issuer} names a different issuer`
				);
			}
			throw new AdminError(
				502,
				`could not read the discovery document at ${issuer}`
			);
		}
		throw err;
	}
}

export async function createProvider(
	bucket: UserBucket,
	body: {
		id: string;
		displayName: string;
		issuer: string;
		clientId: string;
		clientSecret: string;
		enabled?: boolean;
		scopes?: string[];
		emailTrusted?: boolean;
		provisioning?: 'jit' | 'existing_only';
		allowedEmailDomains?: string[];
		emailClaim?: string;
	}
): Promise<FederationProvider> {
	const existing = providersOf(bucket);
	assertProviderId(body.id, existing);
	assertIssuer(body.issuer);

	const provider: FederationProvider = {
		id: body.id,
		displayName: body.displayName,
		enabled: body.enabled ?? true,
		issuer: body.issuer,
		clientId: body.clientId,
		clientSecret: body.clientSecret,
		scopes: body.scopes ?? DEFAULT_SCOPES,
		// Both default to the cautious reading: an operator opts in to trusting addresses and opts in to
		// narrowing domains, and neither happens by accident.
		emailTrusted: body.emailTrusted ?? false,
		provisioning: body.provisioning ?? 'jit',
		allowedEmailDomains: body.allowedEmailDomains ?? [],
		emailClaim: body.emailClaim ?? 'email'
	};

	assertScopes(provider.scopes);
	assertEmailDomains(provider.allowedEmailDomains);
	await assertIssuerResolves(provider.issuer);

	await getBucketStore().update(bucket._id, {
		federation: [...existing, provider]
	});
	return provider;
}

export async function updateProvider(
	bucket: UserBucket,
	providerId: string,
	body: Partial<Omit<FederationProvider, 'id'>>
): Promise<FederationProvider> {
	const current = find(bucket, providerId);

	const next: FederationProvider = {
		...current,
		...body,
		// Absent means unchanged. The mask arriving as a value means the same thing, following the SMTP
		// settings precedent — it is never stored either way, and a console that round-trips its own form
		// therefore cannot overwrite a secret with a placeholder.
		clientSecret:
			body.clientSecret && body.clientSecret !== SECRET_MASK
				? body.clientSecret
				: current.clientSecret,
		id: current.id
	};

	if (next.issuer !== current.issuer) {
		assertIssuer(next.issuer);
		await assertIssuerResolves(next.issuer);
	}
	assertScopes(next.scopes);
	assertEmailDomains(next.allowedEmailDomains);

	const federation = providersOf(bucket).map((p) =>
		p.id === providerId ? next : p
	);
	// Disabling the last enabled provider on a bucket with no password door is a lockout, checked by the
	// same function the bucket PATCH uses.
	assertSomeWayToSignIn({
		passwordLogin: bucket.passwordLogin !== false,
		federation
	});

	await getBucketStore().update(bucket._id, { federation });
	return next;
}

export async function deleteProvider(
	bucket: UserBucket,
	providerId: string
): Promise<void> {
	find(bucket, providerId);
	const federation = providersOf(bucket).filter((p) => p.id !== providerId);
	assertSomeWayToSignIn({
		passwordLogin: bucket.passwordLogin !== false,
		federation
	});
	await getBucketStore().update(bucket._id, { federation });
}
