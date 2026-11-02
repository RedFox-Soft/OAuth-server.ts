import type { RequestBucket } from '../configs/issuer.js';
import { accountPageBase } from '../account_page/client.js';
import { routeNames } from '../consts/param_list.js';
import {
	connectedServiceEntry,
	type CatalogueIdentity,
	type Revocation
} from '../consts/connected_service_catalogue.js';
import {
	issuerForKnownProvider,
	knownProvider
} from '../consts/known_providers.js';
import { discover, type ProviderMetadata } from '../federation/discovery.js';
import type { ConnectedService } from './types.js';

/*
 * Where a provider sends the person back: one fixed address per project, registered at the provider, on the origin
 * the person's account page is served from, so the person's session cookie arrives with them.
 */
export function connectCallbackUri(bucket: RequestBucket): string {
	return `${accountPageBase(bucket)}${routeNames.account_services_callback}`;
}

/*
 * Everything a connect flow needs to know about one service, whichever way it was declared (specs/117 R4): a
 * catalogue entry, an OpenID Connect issuer, or plain OAuth 2.0 endpoints. The flow reads this and nothing
 * else, so a provider's quirks live in the catalogue's data rather than in branches on its name.
 */
export interface ResolvedService {
	authorizationEndpoint: string;
	tokenEndpoint: string;
	tokenAuth: 'basic' | 'post';
	/* Present for an OpenID Connect service: the ID token is verified against it, with a nonce. */
	oidc?: {
		metadata: ProviderMetadata;
		/* For an issuer that names the organisation and so is a pattern rather than a string. */
		acceptIssuer?: (issuer: string) => boolean;
	};
	pkce: boolean;
	scopeParam: 'scope' | 'user_scope';
	scopeSeparator: ' ' | ',';
	responseScopeSeparator: ' ' | ',';
	alwaysScopes: readonly string[];
	extraAuthorizationParams: Readonly<Record<string, string>>;
	tokenPath?: string;
	refreshTokenPath?: string;
	identity: CatalogueIdentity;
	revocation: Revocation;
	manageAccessUrls: readonly string[];
}

export class ServiceUnresolvable extends Error {
	constructor(readonly reason: string) {
		super(`the connected service cannot be used: ${reason}`);
	}
}

/* Basic over post where both are advertised (RFC 6749 §2.3.1), as the sign-in exchange chooses. */
function tokenAuthOf(metadata: ProviderMetadata): 'basic' | 'post' {
	if (metadata.tokenAuthMethods.length === 0) return 'basic';
	if (metadata.tokenAuthMethods.includes('client_secret_basic')) return 'basic';
	if (metadata.tokenAuthMethods.includes('client_secret_post')) return 'post';
	throw new ServiceUnresolvable('unsupported_auth');
}

async function oidcView(
	issuer: string,
	acceptIssuer?: (issuer: string) => boolean
) {
	const metadata = await discover(issuer);
	return {
		authorizationEndpoint: metadata.authorizationEndpoint,
		tokenEndpoint: metadata.tokenEndpoint,
		tokenAuth: tokenAuthOf(metadata),
		oidc: { metadata, ...(acceptIssuer ? { acceptIssuer } : {}) },
		pkce: metadata.codeChallengeMethods.includes('S256')
	};
}

export async function resolveService(
	service: ConnectedService
): Promise<ResolvedService> {
	if (service.kind === 'catalogue') {
		const entry = service.catalogueId
			? connectedServiceEntry(service.catalogueId)
			: undefined;
		if (!entry) throw new ServiceUnresolvable('unknown catalogue entry');
		const shared = {
			scopeParam: entry.scopeParam,
			scopeSeparator: entry.scopeSeparator,
			responseScopeSeparator: entry.responseScopeSeparator,
			alwaysScopes: entry.alwaysScopes,
			extraAuthorizationParams: entry.extraAuthorizationParams,
			...(entry.tokenPath ? { tokenPath: entry.tokenPath } : {}),
			...(entry.refreshTokenPath
				? { refreshTokenPath: entry.refreshTokenPath }
				: {}),
			identity: entry.identity,
			revocation: entry.revocation,
			manageAccessUrls: entry.manageAccessUrls
		};
		if (entry.protocol.kind === 'oauth2') {
			return {
				...shared,
				authorizationEndpoint: entry.protocol.authorizationEndpoint,
				tokenEndpoint: entry.protocol.tokenEndpoint,
				tokenAuth: entry.protocol.tokenAuth,
				pkce: entry.pkce === 'S256'
			};
		}
		const known = knownProvider(entry.protocol.knownProviderId);
		const issuer = known
			? issuerForKnownProvider(known, { tenant: service.tenant })
			: undefined;
		if (!known || !issuer) throw new ServiceUnresolvable('no issuer');
		const rule = known.issuerRule;
		const view = await oidcView(
			issuer,
			rule.kind === 'templated'
				? (value) => rule.pattern.test(value)
				: undefined
		);
		// The catalogue states PKCE where the provider's metadata does not advertise it (Microsoft).
		return { ...shared, ...view, pkce: entry.pkce === 'S256' };
	}

	if (service.kind === 'oidc') {
		if (!service.issuer) throw new ServiceUnresolvable('no issuer');
		const view = await oidcView(service.issuer);
		return {
			...view,
			scopeParam: 'scope',
			scopeSeparator: ' ',
			responseScopeSeparator: ' ',
			alwaysScopes: ['openid'],
			extraAuthorizationParams: {},
			identity: {
				source: 'id_token',
				idPaths: ['sub'],
				labelPath: 'email|name|sub'
			},
			revocation: view.oidc.metadata.revocationEndpoint
				? {
						kind: 'form',
						url: view.oidc.metadata.revocationEndpoint,
						clientAuth: true
					}
				: { kind: 'none' },
			manageAccessUrls: []
		};
	}

	if (
		!service.authorizationEndpoint ||
		!service.tokenEndpoint ||
		!service.identity
	) {
		throw new ServiceUnresolvable('incomplete');
	}
	const declared = service.identity;
	return {
		authorizationEndpoint: service.authorizationEndpoint,
		tokenEndpoint: service.tokenEndpoint,
		tokenAuth: 'basic',
		/* Always sent: a server that does not take PKCE ignores the parameters (RFC 6749 §3.1). */
		pkce: true,
		scopeParam: 'scope',
		scopeSeparator: ' ',
		responseScopeSeparator: ' ',
		alwaysScopes: [],
		extraAuthorizationParams: {},
		identity:
			declared.source === 'endpoint'
				? {
						source: 'endpoint',
						url: declared.url,
						idPaths: [declared.idPath],
						labelPath: declared.labelPath ?? declared.idPath
					}
				: {
						source: 'token',
						idPaths: [declared.idPath],
						labelPath: declared.labelPath ?? declared.idPath
					},
		revocation: service.revocationEndpoint
			? { kind: 'form', url: service.revocationEndpoint, clientAuth: true }
			: { kind: 'none' },
		manageAccessUrls: []
	};
}
