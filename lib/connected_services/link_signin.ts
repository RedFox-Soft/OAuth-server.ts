import type { UserBucket } from '../adapters/types.js';
import { connectedServiceEntry } from '../consts/connected_service_catalogue.js';
import { knownProviderByIssuer } from '../consts/known_providers.js';
import type { FederationProvider } from '../federation/types.js';
import type { ConnectedService } from './types.js';

/*
 * Which sign-in provider may keep a connected service's tokens (specs/120 R2). Tokens belong to the registration
 * that asked for them, and the service refreshes and revokes with its own, so a link needs the same provider and
 * the same client id. "The same provider" is read from the two catalogues the features already have: a catalogue
 * service names the sign-in catalogue entry it stands for, an OpenID Connect service its issuer.
 *
 * Slack is not here on purpose: its user tokens come from `oauth.v2.access` with `user_scope`, which its OpenID
 * Connect sign-in never calls. A plain OAuth 2.0 service has no sign-in counterpart at all.
 */
const LINKABLE_CATALOGUE = new Set(['google', 'microsoft', 'github']);

export type SignInMatch =
	'ok' | 'provider' | 'client_id' | 'tenant' | 'unlinkable';

export function linkableService(service: ConnectedService): boolean {
	if (service.kind === 'oidc') return true;
	return (
		service.kind === 'catalogue' &&
		service.catalogueId !== undefined &&
		LINKABLE_CATALOGUE.has(service.catalogueId)
	);
}

export function signInMatch(
	service: ConnectedService,
	provider: FederationProvider
): SignInMatch {
	if (!linkableService(service)) return 'unlinkable';
	if (service.kind === 'oidc') {
		if (provider.issuer !== service.issuer) return 'provider';
	} else {
		const known = knownProviderByIssuer(provider.issuer);
		if (known?.catalogueId !== service.catalogueId) return 'provider';
		/* Which organisations sign in decides whose tokens arrive; two tenants are two registrations' worth of people. */
		if (
			service.catalogueId === 'microsoft' &&
			(provider.tenant ?? '') !== (service.tenant ?? '')
		) {
			return 'tenant';
		}
	}
	if (provider.clientId !== service.clientId) return 'client_id';
	return 'ok';
}

/* The project's sign-in providers this service could be linked to now: matching, and not linked elsewhere. */
export function linkableSignInProviders(
	bucket: UserBucket,
	service: ConnectedService
): FederationProvider[] {
	const taken = new Set(
		(bucket.connectedServices ?? [])
			.filter((other) => other.id !== service.id && other.signInProviderId)
			.map((other) => other.signInProviderId)
	);
	return bucket.federation.filter(
		(provider) =>
			!taken.has(provider.id) && signInMatch(service, provider) === 'ok'
	);
}

/*
 * The service a sign-in through this provider keeps tokens for, if any. The match is asked again rather than
 * trusted from the stored link: a link the administrator could not have made must keep nothing.
 */
export function serviceKeepingFor(
	bucket: UserBucket | null | undefined,
	providerId: string
): ConnectedService | undefined {
	if (!bucket) return undefined;
	const provider = bucket.federation.find((entry) => entry.id === providerId);
	if (!provider) return undefined;
	return (bucket.connectedServices ?? []).find(
		(service) =>
			service.signInProviderId === providerId &&
			signInMatch(service, provider) === 'ok'
	);
}

export interface KeepRequest {
	scopes: string[];
	params: Record<string, string>;
}

/*
 * What a linked sign-in asks the provider for beyond its own scopes (specs/120 R4): the service's declared scopes,
 * the catalogue's always-scopes (Microsoft's `offline_access`) and its parameters except `prompt`. A connect forces
 * Google's consent screen to be sure of a refresh token; a sign-in never does, since each forced consent mints a new
 * refresh token and Google invalidates the oldest past a hundred per account and client.
 */
export function keepRequest(service: ConnectedService): KeepRequest {
	const entry =
		service.kind === 'catalogue' && service.catalogueId
			? connectedServiceEntry(service.catalogueId)
			: undefined;
	const always = entry ? entry.alwaysScopes : ['openid'];
	const { prompt: _forced, ...params } = entry?.extraAuthorizationParams ?? {};
	return {
		scopes: [...new Set([...always, ...service.scopes])],
		params:
			service.catalogueId === 'google'
				? { ...params, include_granted_scopes: 'true' }
				: params
	};
}
