import {
	getBucketStore,
	getProvisioningConnectionStore,
	getUserStore
} from '../../adapters/index.js';
import { AdminError } from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import {
	assertConsoleStaysReachable,
	loadReachabilityState
} from './reachability.js';
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
import { callbackUri } from '../../federation/flow.js';
import { orderProviders } from '../../federation/order.js';
import { defaultCorrelationFor } from '../../provisioning/correlation.js';
import { stabilityOf } from './guidance.js';
import { ApplicationConfig } from '../../configs/application.js';
import { issuerFor } from '../../configs/issuer.js';
import { routeNames } from '../../consts/param_list.js';
import {
	CredentialError,
	clientCredential
} from '../../federation/credential.js';
import {
	assertAppleIdentifiers,
	assertCanAcceptUpstreamSignals,
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
export function present(
	provider: FederationProvider,
	bucket?: Pick<UserBucket, '_id' | 'slug' | 'host'>
) {
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
		...(provider.signingKey ? { signingKey: SECRET_MASK } : {}),
		/*
		 * The address an administrator pastes into the provider's logout configuration (specs/072 FR-005), shown
		 * only while it would be answered — an address that 404s is worse than none.
		 */
		...(bucket &&
		provider.acceptsGlobalTokenRevocation === true &&
		ApplicationConfig['globalTokenRevocation.enabled']
			? {
					globalTokenRevocationEndpoint: `${issuerFor(bucket)}${routeNames.global_token_revocation}`
				}
			: {}),
		/* The address to register as this application's back-channel logout URL there (specs/073), on the same terms. */
		...(bucket &&
		provider.acceptsBackChannelLogout === true &&
		ApplicationConfig['federation.enabled']
			? {
					backChannelLogoutEndpoint: `${issuerFor(bucket)}${routeNames.federation_backchannel_logout}`
				}
			: {})
	};
}

/*
 * A caller holding only the providers gets no endpoint address, since there is no issuer to build it from.
 * In sign-in order (specs/088 R10), so the console's table lists them as the sign-in page shows them.
 *
 * `onSignInPage` says whether the provider's button is on the sign-in page now, which takes both its own
 * switch and the instance's `federation.enabled`. A list, not a document, so the instance switch cannot ride
 * beside it; carried per provider, an agent asking why a connected provider is missing reads the answer in the
 * same response, and the console tells "switched off here" from "switched off for everyone" without a second
 * request. Only in this list view: `present` stays the provider as stored, which a form may send back.
 */
export function presentAll(
	bucket: Pick<UserBucket, 'federation'> &
		Partial<Pick<UserBucket, '_id' | 'slug' | 'host' | 'signInOrder'>>
) {
	const { _id } = bucket;
	const federationOn = ApplicationConfig['federation.enabled'];
	return orderProviders(bucket.federation, bucket.signInOrder).map(
		(provider) => ({
			...present(provider, _id === undefined ? undefined : { ...bucket, _id }),
			onSignInPage: provider.enabled && federationOn
		})
	);
}

export type ProviderWarning =
	| 'callback_provisional'
	| 'signals_capability_off'
	| 'bound_provider_disabled'
	/* Enabled here, but the instance's `federation.enabled` is off, so its button is on no sign-in page. */
	| 'federation_off';

/*
 * One provider with everything its page explains, read from the server rather than worked out in a browser
 * (specs/084 R1): where the upstream must send people back, which logout signals it can send and whether this
 * instance would accept them, which directory it belongs to, and how many people a change to it reaches.
 */
export async function presentDetail(bucket: UserBucket, providerId: string) {
	const provider = find(bucket, providerId);
	const entry = knownProviderByIssuer(provider.issuer);
	const signs = (entry?.protocol.kind ?? 'oidc') === 'oidc';
	const capabilities = {
		globalTokenRevocation: ApplicationConfig['globalTokenRevocation.enabled'],
		backChannelLogout: ApplicationConfig['federation.enabled'],
		/* A try runs the real exchange and ladder, so it needs federation on, as a sign-in does (specs/088). */
		trySignIn: ApplicationConfig['federation.enabled']
	};
	const [bound, linkedUsers] = await Promise.all([
		getProvisioningConnectionStore().findByProvider(bucket._id, provider.id),
		getUserStore(bucket._id).countLinkedTo(provider.id)
	]);
	const callbackStability = stabilityOf(bucket);

	const warnings: ProviderWarning[] = [];
	if (callbackStability === 'provisional')
		warnings.push('callback_provisional');
	if (
		(provider.acceptsGlobalTokenRevocation === true &&
			!capabilities.globalTokenRevocation) ||
		(provider.acceptsBackChannelLogout === true &&
			!capabilities.backChannelLogout)
	) {
		warnings.push('signals_capability_off');
	}
	if (bound && !provider.enabled) warnings.push('bound_provider_disabled');
	if (provider.enabled && !ApplicationConfig['federation.enabled'])
		warnings.push('federation_off');

	return {
		...present(provider, bucket),
		callbackUri: callbackUri(bucket),
		callbackStability,
		recognised: entry?.catalogueId ?? null,
		/* What the provider can send at all: one that publishes no signing keys can authenticate neither. */
		logoutSignals: { globalTokenRevocation: signs, backChannelLogout: signs },
		capabilities,
		boundConnection: bound
			? { id: bound._id, displayName: bound.displayName }
			: null,
		linkedUsers,
		recommendedCorrelation: defaultCorrelationFor(provider),
		warnings
	};
}

function providersOf(bucket: Pick<UserBucket, 'federation'>) {
	return bucket.federation;
}

/* Whether or not it is enabled: what a try needs, since trying a provider before switching it on is the point. */
export function findProvider(
	bucket: Pick<UserBucket, 'federation'>,
	providerId: string
): FederationProvider {
	return find(bucket, providerId);
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
			: `${field} is required unless catalogueId names a recognised provider`,
		{ field }
	);
}

/* Who is changing a provider: enough to decide whether they may touch the console's own bucket. */
export interface ProviderActor {
	superAdmin: boolean;
}

/*
 * The administrators' bucket's providers decide who can sign in to the console, so only a super
 * administrator configures them. The routes' loader already refuses everyone else; this is the second
 * lock, so a future caller that forgets the loader does not open the console (specs/080), as provisioning
 * and bucket groups keep their own.
 */
function assertMayConfigure(bucket: UserBucket, actor: ProviderActor): void {
	if (bucket._id === ADMIN_BUCKET_ID && !actor.superAdmin) {
		throw new AdminError(
			403,
			"only a super administrator may configure the administrators' project's providers"
		);
	}
}

/*
 * With password sign-in to the console off, a provider change that would leave no super administrator a
 * way in is refused (lib/admin/federation/reachability.ts). Ordinary buckets have their own, weaker rule:
 * `assertSomeWayToSignIn` only asks that some door is open.
 */
async function assertConsoleKeepsADoor(
	bucket: UserBucket,
	federation: FederationProvider[],
	what: string
): Promise<void> {
	if (bucket._id !== ADMIN_BUCKET_ID) return;
	const state = await loadReachabilityState();
	assertConsoleStaysReachable(
		{
			...state,
			passwordLogin: bucket.passwordLogin,
			providers: federation
		},
		what
	);
}

export async function createProvider(
	bucket: UserBucket,
	actor: ProviderActor,
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
		acceptsGlobalTokenRevocation?: boolean;
		acceptsBackChannelLogout?: boolean;
	}
): Promise<FederationProvider> {
	assertMayConfigure(bucket, actor);
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
		/*
		 * The console's own bucket defaults to existing accounts only: a provider that creates administrators
		 * is a decision, and a provider that creates them silently would admit anyone its directory vouches
		 * for the moment sign-up is opened (specs/080).
		 */
		provisioning:
			body.provisioning ??
			(bucket._id === ADMIN_BUCKET_ID ? 'existing_only' : 'jit'),
		allowedEmailDomains: body.allowedEmailDomains ?? [],
		emailClaim: body.emailClaim ?? entry?.emailClaim ?? 'email',
		/* Opted into deliberately: it lets a third party end any of this provider's users' sessions here. */
		acceptsGlobalTokenRevocation: body.acceptsGlobalTokenRevocation ?? false,
		/* Opted into deliberately too: it lets a third party end sessions here, if only ones it began. */
		acceptsBackChannelLogout: body.acceptsBackChannelLogout ?? false
	};

	assertScopes(provider.scopes, entry?.protocol.kind ?? 'oidc');
	assertCanAcceptUpstreamSignals(provider, entry?.protocol.kind ?? 'oidc');
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
	actor: ProviderActor,
	providerId: string,
	body: Partial<Omit<FederationProvider, 'id'>>
): Promise<FederationProvider> {
	assertMayConfigure(bucket, actor);
	const current = find(bucket, providerId);
	if (body.provisioning === 'jit') {
		await assertNotBound(
			bucket,
			providerId,
			'switched to just-in-time creation'
		);
	}

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

	if (next.issuer !== current.issuer || next.tenant !== current.tenant) {
		await assertNobodyLinked(bucket, providerId);
	}
	if (next.issuer !== current.issuer) {
		assertIssuer(next.issuer);
		await assertIssuerResolves(next.issuer);
	}
	assertScopes(next.scopes, entry?.protocol.kind ?? 'oidc');
	assertCanAcceptUpstreamSignals(next, entry?.protocol.kind ?? 'oidc');
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
		passwordLogin: bucket.passwordLogin,
		federation
	});
	await assertConsoleKeepsADoor(
		bucket,
		federation,
		`Changing identity provider ${providerId}`
	);

	await getBucketStore().update(bucket._id, { federation });
	return next;
}

/*
 * A provider a SCIM provisioning connection is bound to belongs to that connection's arrangement: its users
 * sign in through it, matched by the connection's correlation rule, and it creates no account of its own —
 * the directory does. Deleting it would strand every provisioned user; switching it to just-in-time creation
 * would let a first sign-in race the directory's create and leave two accounts for one person (issue #62).
 */
async function assertNotBound(
	bucket: UserBucket,
	providerId: string,
	what: string
): Promise<void> {
	const bound = await getProvisioningConnectionStore().findByProvider(
		bucket._id,
		providerId
	);
	if (bound) {
		throw new AdminError(
			409,
			`provider ${providerId} is bound to provisioning connection ${bound._id} and cannot be ${what}`
		);
	}
}

export async function deleteProvider(
	bucket: UserBucket,
	actor: ProviderActor,
	providerId: string
): Promise<void> {
	assertMayConfigure(bucket, actor);
	find(bucket, providerId);
	await assertNotBound(bucket, providerId, 'deleted');
	const federation = providersOf(bucket).filter((p) => p.id !== providerId);
	assertSomeWayToSignIn({
		passwordLogin: bucket.passwordLogin,
		federation
	});
	await assertConsoleKeepsADoor(
		bucket,
		federation,
		`Deleting identity provider ${providerId}`
	);
	/*
	 * The links go with the provider, and before it. A link names the provider only by id, so links left
	 * behind would attach to whatever provider is next created under that id — an upstream whose subjects
	 * mean other people — and its users would sign in to accounts that are not theirs.
	 */
	const users = getUserStore(bucket._id);
	for (const user of await users.findLinkedTo(providerId)) {
		await users.update(user._id, {
			federated: (user.federated ?? []).filter(
				(link) => link.providerId !== providerId
			)
		});
	}
	/*
	 * Its place in the sign-in order goes with it: a provider created later under the same id is a new
	 * provider, and appears after the ordered ones rather than inheriting the deleted one's position.
	 */
	await getBucketStore().update(bucket._id, {
		federation,
		...(bucket.signInOrder?.includes(providerId)
			? { signInOrder: bucket.signInOrder.filter((id) => id !== providerId) }
			: {})
	});
}

/*
 * The order before and after one move (specs/088 R10): the displayed order, with the provider swapped with
 * its neighbour. Refused (409) at an end, so a move in the trail always moved something.
 */
export function plannedMove(
	bucket: UserBucket,
	actor: ProviderActor,
	providerId: string,
	direction: 'up' | 'down'
): { from: string[]; to: string[] } {
	assertMayConfigure(bucket, actor);
	find(bucket, providerId);
	const from = orderProviders(bucket.federation, bucket.signInOrder).map(
		(p) => p.id
	);
	const index = from.indexOf(providerId);
	const target = direction === 'up' ? index - 1 : index + 1;
	if (target < 0 || target >= from.length) {
		throw new AdminError(
			409,
			`provider ${providerId} is already ${direction === 'up' ? 'first' : 'last'}`
		);
	}
	const to = [...from];
	to[index] = from[target];
	to[target] = providerId;
	return { from, to };
}

/*
 * Writes the new order and nothing else: the providers themselves are not rewritten, so a move cannot
 * revert an edit another administrator made a moment earlier. The full id list is stored, so every
 * provider's place is fixed from then on rather than only the moved one's.
 */
export async function moveProvider(
	bucket: UserBucket,
	to: string[]
): Promise<UserBucket> {
	const updated = await getBucketStore().update(bucket._id, {
		signInOrder: to
	});
	if (!updated) throw new AdminError(404, 'no access to this project');
	return updated;
}

/*
 * The issuer (and, for Microsoft, the tenant) decides whose subjects a provider's links name: the same
 * `sub` from another issuer is another person. A link records the provider id and the subject, never the
 * issuer, so pointing a provider people are linked to at a different upstream would hand their accounts
 * to that upstream's users with the same subjects. Moving to another upstream is a new provider.
 */
async function assertNobodyLinked(
	bucket: UserBucket,
	providerId: string
): Promise<void> {
	const linked = await getUserStore(bucket._id).findLinkedTo(providerId, 1);
	if (linked.length > 0) {
		throw new AdminError(
			409,
			`people are linked to provider ${providerId}, so its issuer cannot change: add a new provider for the new issuer instead`
		);
	}
}
