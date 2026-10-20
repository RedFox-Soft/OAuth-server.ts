import crypto from 'node:crypto';
import nanoid from '../../helpers/nanoid.js';
import {
	Client,
	needsSecret,
	registerClient,
	toStored
} from '../../models/client.js';
import { adapter } from '../../adapters/index.js';
import { AdminError } from '../auth/rbac.js';
import { OIDCProviderError } from '../../helpers/errors.js';
import { isHttpsUri } from '../../helpers/valid_url.js';
import {
	InvalidOriginError,
	normalizeOrigins
} from '../../helpers/cors_origin.js';
import {
	LOGO_FORMAT_MESSAGE,
	LOGO_SIZE_MESSAGE
} from '../../consts/client_logo.js';
import {
	clearLogo,
	hasLogo,
	parseLogo,
	readLogo,
	writeLogo
} from '../../models/client/logo.js';
import {
	PRIMARY_COLOR_MESSAGE,
	PRIMARY_COLOR_PATTERN
} from '../../consts/client_branding.js';
import { paintedAccent, readPrimaryColor } from '../../html/theme/accent.js';
import { grantRefusedToPublicClient } from '../../consts/confidential_grants.js';

export interface AdminClientView {
	clientId: string;
	clientName?: string;
	applicationType: string;
	grantTypes: string[];
	responseTypes: string[];
	redirectUris: string[];
	postLogoutRedirectUris: string[];
	tokenEndpointAuthMethod: string;
	scope?: string;
	requireConsent: boolean;
	/* Whether the person may untick individual permissions on the consent page (specs/093). */
	partialConsent: boolean;
	backchannelTokenDeliveryMode?: string;
	backchannelClientNotificationEndpoint?: string;
	authorizationDetailsTypes?: string[];
	jwks?: unknown;
	jwksUri?: string;
	tokenEndpointAuthSigningAlg?: string;
	idTokenSignedResponseAlg?: string;
	authorizationSignedResponseAlg?: string;
	requestObjectSigningAlg?: string;
	requireSignedRequestObject?: boolean;
	requirePushedAuthorizationRequests?: boolean;
	dpopBoundAccessTokens?: boolean;
	backchannelLogoutUri?: string;
	backchannelLogoutSessionRequired?: boolean;
	subjectType?: string;
	sectorIdentifierUri?: string;
	/* Shown on the consent page for this organization's own users only (specs/094). */
	policyUri?: string;
	tosUri?: string;
	logo?: string;
	/* The colour its sign-in pages are painted in, for this organization's own users (specs/106). */
	primaryColor?: string;
	/*
	 * What those pages actually show: the light shade, the dark one, and whether the light one had to move to stay
	 * legible. The dark one always differs — antd paints every colour darker on a dark page — so it is shown, not
	 * flagged.
	 */
	paintedPrimaryColor?: { light: string; dark: string; adjusted: boolean };
	/* The project it belongs to, for life (specs/099). Absent only for a client registered at the root. */
	projectId?: string;
	corsOrigins: string[];
	/* Registered on its own request; such a client is shown, and managed through its registration token. */
	registeredDynamically: boolean;
}

/*
 * A client in a list: whether it has a logo, never the image — a bucket may hold many — and its colour, without
 * the shades, so listing a project works nothing out.
 */
export type AdminClientListItem = Omit<
	AdminClientView,
	'logo' | 'paintedPrimaryColor'
> & {
	hasLogo: boolean;
};

/*
 * The attributes an edit sets or removes one by one — the key and request-protection attributes, and the
 * links the consent page shows — each as the admin surface names it, the key the stored record holds it
 * under (a base attribute canonically, recognised metadata under its wire name), and the property a
 * validated client exposes it as. One table so the three cannot drift apart: a field the route accepts
 * but this builder does not forward is silently discarded, which is the defect the allow-list below
 * already had once.
 */
const KEY_AND_REQUEST_ATTRIBUTES = {
	jwks: { stored: 'jwks', property: 'jwks' },
	jwksUri: { stored: 'jwks_uri', property: 'jwksUri' },
	tokenEndpointAuthSigningAlg: {
		stored: 'token_endpoint_auth_signing_alg',
		property: 'tokenEndpointAuthSigningAlg'
	},
	idTokenSignedResponseAlg: {
		stored: 'id_token_signed_response_alg',
		property: 'idTokenSignedResponseAlg'
	},
	authorizationSignedResponseAlg: {
		stored: 'authorization_signed_response_alg',
		property: 'authorizationSignedResponseAlg'
	},
	requestObjectSigningAlg: {
		stored: 'requestObject.signingAlg',
		property: 'requestObject.signingAlg'
	},
	requireSignedRequestObject: {
		stored: 'require_signed_request_object',
		property: 'requireSignedRequestObject'
	},
	requirePushedAuthorizationRequests: {
		stored: 'authorization.requirePushedAuthorizationRequests',
		property: 'authorization.requirePushedAuthorizationRequests'
	},
	dpopBoundAccessTokens: {
		stored: 'dpop_bound_access_tokens',
		property: 'dpopBoundAccessTokens'
	},
	backchannelLogoutUri: {
		stored: 'backchannel_logout_uri',
		property: 'backchannelLogoutUri'
	},
	backchannelLogoutSessionRequired: {
		stored: 'backchannel_logout_session_required',
		property: 'backchannelLogoutSessionRequired'
	},
	subjectType: { stored: 'subjectType', property: 'subjectType' },
	sectorIdentifierUri: {
		stored: 'sector_identifier_uri',
		property: 'sectorIdentifierUri'
	},
	policyUri: { stored: 'policy_uri', property: 'policyUri' },
	tosUri: { stored: 'tos_uri', property: 'tosUri' }
} as const;

type KeyAndRequestAttribute = keyof typeof KEY_AND_REQUEST_ATTRIBUTES;
type KeyAndRequestInput = {
	[K in KeyAndRequestAttribute]?: AdminClientView[K] | null;
};

// Writes each attribute the input names; `null` removes one the record already holds.
function applyKeyAndRequestAttributes(
	metadata: Record<string, unknown>,
	input: KeyAndRequestInput
) {
	for (const [name, { stored }] of Object.entries(KEY_AND_REQUEST_ATTRIBUTES)) {
		const value = input[name as KeyAndRequestAttribute];
		if (value === null) {
			delete metadata[stored];
		} else if (value !== undefined) {
			metadata[stored] = value;
		}
	}
}

export interface CreateClientInput extends KeyAndRequestInput {
	/*
	 * Supplied when the caller has already allocated the id — which the admin route does, because the
	 * client's audit entry must name it before the client exists. Generated here otherwise.
	 */
	clientId?: string;
	clientName?: string;
	applicationType?: 'web' | 'native';
	grantTypes: readonly string[];
	redirectUris?: readonly string[];
	postLogoutRedirectUris?: readonly string[];
	tokenEndpointAuthMethod: string;
	scope?: string;
	requireConsent?: boolean;
	partialConsent?: boolean;
	backchannelTokenDeliveryMode?: string;
	backchannelClientNotificationEndpoint?: string;
	authorizationDetailsTypes?: readonly string[];
	corsOrigins?: readonly string[];
	/* A `data:` URL; null on an update removes the logo. Never part of the client record. */
	logo?: string | null;
	/* `#rrggbb`, any case; null on an update removes it. */
	primaryColor?: string | null;
}

/*
 * Normalizes a submitted origin list, or refuses the whole request. All-or-nothing on purpose: half a
 * list is a configuration an operator did not ask for, and the browser-facing consequence of a silently
 * dropped entry is an app that cannot reach the server.
 */
function validatedOrigins(
	origins: readonly string[] | undefined
): string[] | undefined {
	if (origins === undefined) return undefined;
	try {
		return normalizeOrigins([...origins]);
	} catch (err) {
		if (err instanceof InvalidOriginError) {
			throw new AdminError(400, err.message, { field: 'corsOrigins' });
		}
		throw err;
	}
}

export type UpdateClientInput = Partial<CreateClientInput>;

/*
 * Checked before anything is written, so a refused logo or link leaves the client exactly as it was. The
 * client's own validation accepts an http policy or terms link (dynamic registration may register one);
 * an administrator is held to https, the only kind the consent page ever shows.
 */
function checkedPresentation(
	input: UpdateClientInput
): string | null | undefined {
	for (const field of ['policyUri', 'tosUri'] as const) {
		const value = input[field];
		if (typeof value === 'string' && !isHttpsUri(value)) {
			throw new AdminError(422, `${field} must be an https URL`);
		}
	}
	if (
		typeof input.primaryColor === 'string' &&
		!PRIMARY_COLOR_PATTERN.test(input.primaryColor)
	) {
		throw new AdminError(422, PRIMARY_COLOR_MESSAGE);
	}
	if (input.logo === undefined || input.logo === null) return input.logo;
	const parsed = parseLogo(input.logo);
	if (!parsed.ok) {
		throw new AdminError(
			422,
			parsed.reason === 'too-large' ? LOGO_SIZE_MESSAGE : LOGO_FORMAT_MESSAGE
		);
	}
	return parsed.image;
}

// Written only once the client record is stored, so a client refused by validation gains no logo.
async function storeLogo(clientId: string, logo: string | null | undefined) {
	if (logo === null) await clearLogo(clientId);
	else if (logo !== undefined) await writeLogo(clientId, logo);
}

async function withLogo(view: AdminClientView): Promise<AdminClientView> {
	const logo = await readLogo(view.clientId);
	return withPaintedColour(logo ? { ...view, logo } : view);
}

// Beside the logo on the single view: what the colour will look like is worked out for one client, never a list.
function withPaintedColour(view: AdminClientView): AdminClientView {
	const accent = view.primaryColor && paintedAccent(view.primaryColor);
	return accent
		? {
				...view,
				paintedPrimaryColor: {
					light: accent.light.primary,
					dark: accent.dark.primary,
					adjusted: accent.adjusted
				}
			}
		: view;
}

function generateSecret(): string {
	return crypto.randomBytes(48).toString('base64url');
}

function responseTypesFor(grantTypes: readonly string[]): string[] {
	return grantTypes.includes('authorization_code') ? ['code'] : [];
}

// Build the client record registerClient expects: base
// attributes use canonical camelCase (redirectUris/grantTypes/…), recognized
// metadata uses snake_case (token_endpoint_auth_method/scope/…), plus the dotted
// `consent.require` key. Mirrors the boundary translation in actions/registration.ts.
function toMetadata(input: CreateClientInput, clientId: string) {
	const metadata: Record<string, unknown> = {
		clientId,
		applicationType: input.applicationType ?? 'web',
		grantTypes: input.grantTypes,
		responseTypes: responseTypesFor(input.grantTypes),
		redirectUris: input.redirectUris ?? [],
		post_logout_redirect_uris: input.postLogoutRedirectUris ?? [],
		token_endpoint_auth_method: input.tokenEndpointAuthMethod,
		'consent.require': input.requireConsent ?? true,
		'consent.partial': input.partialConsent ?? false
	};
	if (input.clientName !== undefined) metadata.client_name = input.clientName;
	if (input.scope !== undefined) metadata.scope = input.scope;
	if (input.backchannelTokenDeliveryMode !== undefined) {
		metadata.backchannel_token_delivery_mode =
			input.backchannelTokenDeliveryMode;
	}
	if (input.backchannelClientNotificationEndpoint !== undefined) {
		metadata.backchannel_client_notification_endpoint =
			input.backchannelClientNotificationEndpoint;
	}
	/*
	 * Forwarded explicitly: this builder is an allow-list, so a field added to the request schema alone
	 * is accepted by the route and then silently discarded here — the same defect a route once had
	 * with `clientIds`. validateClient recognizes this metadata only when the feature is enabled and
	 * validates each value against the configured types, so no gate is restated here.
	 */
	if (input.authorizationDetailsTypes !== undefined) {
		metadata.authorization_details_types = input.authorizationDetailsTypes;
	}
	const origins = validatedOrigins(input.corsOrigins);
	if (origins !== undefined) metadata.corsOrigins = origins;
	if (typeof input.primaryColor === 'string') {
		metadata.primaryColor = input.primaryColor.toLowerCase();
	}
	applyKeyAndRequestAttributes(metadata, input);
	return metadata;
}

// The view is handed out, so its lists are copies rather than the frozen client's own.
function toView(client: Client): AdminClientView {
	const primaryColor = readPrimaryColor(client.primaryColor);
	return {
		clientId: client.clientId,
		clientName: client.clientName,
		applicationType: client.applicationType,
		grantTypes: [...client.grantTypes],
		responseTypes: [...client.responseTypes],
		redirectUris: [...client.redirectUris],
		postLogoutRedirectUris: [...(client.postLogoutRedirectUris ?? [])],
		tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
		scope: client.scope,
		requireConsent: client['consent.require'],
		partialConsent: client['consent.partial'],
		backchannelTokenDeliveryMode: client.backchannelTokenDeliveryMode,
		backchannelClientNotificationEndpoint:
			client.backchannelClientNotificationEndpoint,
		authorizationDetailsTypes: client.authorizationDetailsTypes && [
			...client.authorizationDetailsTypes
		],
		projectId: client.bucketId,
		corsOrigins: [...(client.corsOrigins ?? [])],
		registeredDynamically: client.registeredDynamically === true,
		...(primaryColor ? { primaryColor } : {}),
		...keyAndRequestView(client)
	};
}

// Copied rather than handed out: a validated client is frozen, and the key set is nested.
function keyAndRequestView(client: Client): Partial<AdminClientView> {
	const view: Record<string, unknown> = {};
	const source = client as unknown as Record<string, unknown>;
	for (const [name, { property }] of Object.entries(
		KEY_AND_REQUEST_ATTRIBUTES
	)) {
		const value = source[property];
		if (value !== undefined) view[name] = structuredClone(value);
	}
	return view;
}

/*
 * Validation refuses bad metadata with a protocol error — InvalidClientMetadata, InvalidRedirectUri —
 * and a protocol error leaving an admin route reaches the OAuth error handler first, which answers it
 * as 400 in the protocol's shape: the console got no `message` to show. Re-raised here as the admin
 * plane's own refusal, which that handler stands aside for (wiki/concepts/admin-plane-error-shape.md).
 */
async function validateAndStore(metadata: Record<string, unknown>) {
	const refused = grantRefusedToPublicClient(
		metadata.token_endpoint_auth_method,
		(metadata.grantTypes as string[] | undefined) ?? []
	);
	if (refused) {
		throw new AdminError(
			422,
			`${refused} needs a client that authenticates; choose a token endpoint auth method other than none`
		);
	}
	try {
		return await registerClient(metadata, { store: true });
	} catch (error) {
		if (error instanceof OIDCProviderError) {
			throw new AdminError(422, error.error_description || error.message);
		}
		throw error;
	}
}

/*
 * `bucketId` is an argument, never part of the input: the bucket a client signs people into is the route's,
 * set once here and carried by every later write (specs/099).
 */
export async function createClient(
	bucketId: string,
	input: CreateClientInput
): Promise<{ view: AdminClientView; secret?: string }> {
	const clientId = input.clientId ?? nanoid();
	const logo = checkedPresentation(input);
	const metadata: Record<string, unknown> = {
		...toMetadata(input, clientId),
		bucketId
	};
	let secret: string | undefined;
	if (needsSecret(metadata)) {
		secret = generateSecret();
		metadata.clientSecret = secret;
		metadata.client_secret_expires_at = 0;
	}
	const client = await validateAndStore(metadata);
	await storeLogo(clientId, logo);
	return { view: await withLogo(toView(client)), secret };
}

export async function getClientView(
	clientId: string
): Promise<AdminClientView | null> {
	const client = await Client.tryFind(clientId);
	return client ? withLogo(toView(client)) : null;
}

export async function listClientView(
	clientId: string
): Promise<AdminClientListItem | null> {
	const client = await Client.tryFind(clientId);
	return client
		? { ...toView(client), hasLogo: await hasLogo(clientId) }
		: null;
}

export async function updateClient(
	clientId: string,
	patch: UpdateClientInput
): Promise<AdminClientView> {
	const existing = await Client.tryFind(clientId);
	if (!existing) throw new AdminError(404, 'client not found');
	const logo = checkedPresentation(patch);
	const merged: CreateClientInput = {
		clientName: patch.clientName ?? existing.clientName,
		applicationType: patch.applicationType ?? existing.applicationType,
		grantTypes: patch.grantTypes ?? existing.grantTypes,
		redirectUris: patch.redirectUris ?? existing.redirectUris,
		postLogoutRedirectUris:
			patch.postLogoutRedirectUris ?? existing.postLogoutRedirectUris ?? [],
		tokenEndpointAuthMethod:
			patch.tokenEndpointAuthMethod ?? existing.tokenEndpointAuthMethod,
		scope: patch.scope ?? existing.scope,
		requireConsent: patch.requireConsent ?? existing['consent.require'],
		partialConsent: patch.partialConsent ?? existing['consent.partial'],
		backchannelTokenDeliveryMode:
			patch.backchannelTokenDeliveryMode ??
			existing.backchannelTokenDeliveryMode,
		backchannelClientNotificationEndpoint:
			patch.backchannelClientNotificationEndpoint ??
			existing.backchannelClientNotificationEndpoint,
		authorizationDetailsTypes:
			patch.authorizationDetailsTypes ?? existing.authorizationDetailsTypes,
		corsOrigins: patch.corsOrigins ?? existing.corsOrigins
	};
	/*
	 * Applied over the stored record, not in place of it. The console shows a subset of a client's
	 * attributes, so a record rebuilt from that subset silently loses the rest — a pairwise client came
	 * back public, which changes the subject identifier every relying party keys its accounts on, and a
	 * client authenticating with a private key could not be edited at all once its key set was gone.
	 */
	const stored = (await adapter('Client').find(clientId)) ?? {};
	const metadata: Record<string, unknown> = {
		...stored,
		...toMetadata(merged, clientId)
	};
	// Only what the patch names: the rest of these already survive in `stored`.
	applyKeyAndRequestAttributes(metadata, patch);
	if (patch.primaryColor === null) delete metadata.primaryColor;
	else if (patch.primaryColor !== undefined)
		metadata.primaryColor = patch.primaryColor.toLowerCase();
	// Mirror createClient's secret logic on the merged (post-patch) metadata, not
	// the pre-patch existing client — otherwise a confidential -> public transition
	// leaves a stale clientSecret (so rotateSecret wrongly succeeds on what is now
	// a public client), and a public -> confidential transition throws an unhandled
	// InvalidClientMetadata (clientSecret is mandatory but never gets minted).
	if (needsSecret(metadata)) {
		// keep the existing secret, or mint one if transitioning public -> confidential
		metadata.clientSecret = existing.clientSecret ?? generateSecret();
		metadata.client_secret_expires_at = existing.clientSecret
			? (existing.clientSecretExpiresAt ?? 0)
			: 0;
	} else {
		// The stored record carries the old secret, so dropping it is now an explicit step.
		delete metadata.clientSecret;
		delete metadata.client_secret_expires_at;
	}
	const client = await validateAndStore(metadata);
	await storeLogo(clientId, logo);
	return withLogo(toView(client));
}

export async function rotateSecret(clientId: string): Promise<string> {
	const existing = await Client.tryFind(clientId);
	if (!existing) throw new AdminError(404, 'client not found');
	if (!existing.clientSecret) {
		throw new AdminError(400, 'client has no secret to rotate');
	}
	const secret = generateSecret();
	const metadata = { ...toStored(existing), clientSecret: secret };
	await validateAndStore(metadata);
	return secret;
}

export async function deleteClientRecord(clientId: string): Promise<void> {
	await adapter('Client').destroy(clientId);
}
