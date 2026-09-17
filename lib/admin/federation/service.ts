import { getBucketStore } from '../../adapters/index.js';
import { AdminError } from '../auth/rbac.js';
import {
	DiscoveryError,
	discover,
	forgetDiscovery
} from '../../federation/discovery.js';
import { DEFAULT_SCOPES, SECRET_MASK } from '../../federation/consts.js';
import {
	issuerForKnownProvider,
	knownProvider,
	knownProviderByIssuer,
	knownProviderIds,
	type KnownProvider
} from '../../consts/known_providers.js';
import type { UserBucket } from '../../adapters/types.js';
import type { FederationProvider } from '../../federation/types.js';
import {
	CredentialError,
	clientCredential
} from '../../federation/credential.js';
import {
	assertAppleIdentifiers,
	assertClientIdShape,
	assertEmailDomains,
	assertIssuer,
	assertProviderId,
	assertScopes,
	assertSomeWayToSignIn,
	assertSuppliedValues,
	assertTenant
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
	/*
	 * Both secret-bearing fields, and masked only where one is actually stored — so a reader can still tell
	 * "a value is held" from "none is", which is what the mask exists for.
	 *
	 * `signingKey` joined this in `specs/053-apple-microsoft-github`. The thing to know before adding a
	 * third: this function is the *only* place either is masked, and `presentBucket` in
	 * lib/admin/buckets/routes.ts reaches it by delegation rather than by repeating the rule. That
	 * delegation is the fix for a leak that ran for a year — the bucket routes returned the containing
	 * document whole while this function guarded the provider routes. Anything new that returns a bucket,
	 * or anything containing one, must come through here too.
	 */
	return {
		...provider,
		...(provider.clientSecret ? { clientSecret: SECRET_MASK } : {}),
		...(provider.signingKey ? { signingKey: SECRET_MASK } : {})
	};
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

/*
 * Every check that can be settled without a human completing a sign-in — which differs by provider,
 * because what a provider publishes differs.
 *
 * The three cases below are not three policies. They are one policy — *establish what is establishable* —
 * applied to three different sets of published facts. The one thing none of them does is claim the
 * connection has been proven to work: whether the callback address is registered upstream lives in the
 * provider's records, and nothing here can see it.
 */
async function assertCheckable(
	provider: FederationProvider,
	entry: KnownProvider | undefined
): Promise<void> {
	const credential = entry?.credential ?? { kind: 'secret' as const };

	if (credential.kind === 'signed_assertion') {
		// Settled here rather than at an end user's first sign-in, which is the whole reason a save-time
		// check earns its place: the failure would otherwise appear on the provider's page, to somebody who
		// cannot fix it.
		try {
			await clientCredential(provider);
		} catch (err) {
			if (err instanceof CredentialError) {
				throw new AdminError(
					422,
					'that key cannot produce the credential Apple requires — check it is the .p8 file you downloaded, and that the Key ID and Team ID belong to it'
				);
			}
			throw err;
		}
	}

	/*
	 * A provider that publishes no metadata document has none to check, and reporting its absence as
	 * "unreachable" would send an administrator looking for a network fault that does not exist.
	 */
	if (entry?.protocol.kind === 'profile_api') return;

	await assertIssuerResolves(provider.issuer);
}

/*
 * The recognised provider a body named, or nothing.
 *
 * The refusal lists what could have been said instead: an administrator who typed `gogle` is one keystroke
 * from success, and a bare "unknown" makes them go looking for a spelling nobody published.
 */
function resolveCatalogue(catalogueId: string): KnownProvider {
	const entry = knownProvider(catalogueId);
	if (!entry) {
		throw new AdminError(
			422,
			`no recognised provider is called '${catalogueId}' — try one of: ${knownProviderIds().join(', ')}`
		);
	}
	return entry;
}

/*
 * One rule for every write-only value: absent means unchanged, and the mask means absent.
 *
 * Extracted when the second such value arrived rather than copied, because two copies of "the mask is
 * never stored" disagree after the first edit — and the disagreement would store a literal `********` as
 * somebody's credential, after which sign-in fails in a way that looks exactly like an upstream outage.
 */
function keptSecret(
	submitted: string | undefined,
	current: string | undefined
): string | undefined {
	if (!submitted || submitted === SECRET_MASK) return current;
	return submitted;
}

/* What a body had to supply itself, now that a catalogue entry may have supplied it. */
function required(
	value: string | undefined,
	field: string,
	fromCatalogue: boolean
): string {
	if (value) return value;
	throw new AdminError(
		422,
		fromCatalogue
			? `${field} is required`
			: `${field} is required unless catalogueId names a recognised provider`
	);
}

export async function createProvider(
	bucket: UserBucket,
	body: {
		catalogueId?: string;
		id?: string;
		displayName?: string;
		issuer?: string;
		clientId: string;
		clientSecret?: string;
		tenant?: string;
		teamId?: string;
		keyId?: string;
		signingKey?: string;
		enabled?: boolean;
		scopes?: string[];
		emailTrusted?: boolean;
		provisioning?: 'jit' | 'existing_only';
		allowedEmailDomains?: string[];
		emailClaim?: string;
	}
): Promise<FederationProvider> {
	const existing = providersOf(bucket);
	/*
	 * The entry fills only what the caller left out — every `??` below reads the body first — so narrowing
	 * a connection to one email domain, or renaming it, is the ordinary case rather than a reason to
	 * abandon the guided route and type eleven fields.
	 *
	 * `catalogueId` never reaches the object constructed below. That is the whole of FR-003: nothing
	 * records which route created a provider, so nothing downstream is *able* to branch on it.
	 */
	const entry = body.catalogueId
		? resolveCatalogue(body.catalogueId)
		: undefined;
	if (entry) {
		assertClientIdShape(entry, body.clientId);
		// Which values a provider asks for is the entry's own statement, so the refusal for a missing one is
		// generic here rather than a list this function keeps in step with the catalogue by hand.
		assertSuppliedValues(entry, body);
	}

	const id = required(
		body.id ?? entry?.defaultProviderId,
		'id',
		Boolean(entry)
	);
	const issuer = required(
		body.issuer ??
			(entry
				? issuerForKnownProvider(entry, { tenant: body.tenant })
				: undefined),
		'issuer',
		Boolean(entry)
	);
	const displayName = required(
		body.displayName ?? entry?.displayName,
		'displayName',
		Boolean(entry)
	);

	assertProviderId(id, existing);
	assertIssuer(issuer);

	const provider: FederationProvider = {
		id,
		displayName,
		enabled: body.enabled ?? true,
		issuer,
		clientId: body.clientId,
		// Each present only when supplied, so a provider carries no empty strings standing in for values it
		// does not have — and `credential.ts` can tell "no secret because none is needed" from "no secret
		// because the connection is half configured".
		...(body.clientSecret ? { clientSecret: body.clientSecret } : {}),
		...(body.tenant ? { tenant: body.tenant } : {}),
		...(body.teamId ? { teamId: body.teamId } : {}),
		...(body.keyId ? { keyId: body.keyId } : {}),
		...(body.signingKey ? { signingKey: body.signingKey } : {}),
		scopes: body.scopes ?? (entry ? [...entry.scopes] : DEFAULT_SCOPES),
		// Both default to the cautious reading: an operator opts in to trusting addresses and opts in to
		// narrowing domains, and neither happens by accident. A catalogue entry may raise the first, because
		// that is a judgement about a named provider somebody made deliberately — it never raises the
		// second, so the guided route cannot leave a bucket more open than the manual one would.
		emailTrusted: body.emailTrusted ?? entry?.emailTrusted ?? false,
		provisioning: body.provisioning ?? 'jit',
		allowedEmailDomains: body.allowedEmailDomains ?? [],
		emailClaim: body.emailClaim ?? entry?.emailClaim ?? 'email'
	};

	assertScopes(provider.scopes, entry?.protocol.kind ?? 'oidc');
	assertEmailDomains(provider.allowedEmailDomains);
	if (provider.tenant) assertTenant(provider.tenant);
	if (provider.teamId || provider.keyId) {
		assertAppleIdentifiers(provider.teamId ?? '', provider.keyId ?? '');
	}
	await assertCheckable(provider, entry);

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
		clientSecret: keptSecret(body.clientSecret, current.clientSecret),
		// The same rule, for the same reason: renaming a provider must not require re-pasting a private key.
		signingKey: keptSecret(body.signingKey, current.signingKey),
		id: current.id
	};

	/*
	 * Resolved from the issuer, not from the body: an update names no catalogue entry, and the provider's
	 * protocol is not something a caller gets to change. Same lookup the sign-in path uses.
	 */
	const entry = knownProviderByIssuer(next.issuer);

	if (next.issuer !== current.issuer) {
		assertIssuer(next.issuer);
		await assertIssuerResolves(next.issuer);
	}
	assertScopes(next.scopes, entry?.protocol.kind ?? 'oidc');
	assertEmailDomains(next.allowedEmailDomains);
	if (next.tenant) assertTenant(next.tenant);
	if (next.teamId || next.keyId) {
		assertAppleIdentifiers(next.teamId ?? '', next.keyId ?? '');
	}

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
