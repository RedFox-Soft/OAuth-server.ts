import crypto from 'node:crypto';
import nanoid from '../../helpers/nanoid.js';
import { Client } from '../../models/client.js';
import { adapter } from '../../adapters/index.js';
import { AdminError } from '../auth/rbac.js';

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
	backchannelTokenDeliveryMode?: string;
	backchannelClientNotificationEndpoint?: string;
}

export interface CreateClientInput {
	clientName?: string;
	applicationType?: 'web' | 'native';
	grantTypes: string[];
	redirectUris?: string[];
	postLogoutRedirectUris?: string[];
	tokenEndpointAuthMethod: string;
	scope?: string;
	requireConsent?: boolean;
	backchannelTokenDeliveryMode?: string;
	backchannelClientNotificationEndpoint?: string;
}

export type UpdateClientInput = Partial<CreateClientInput>;

function generateSecret(): string {
	return crypto.randomBytes(48).toString('base64url');
}

function responseTypesFor(grantTypes: string[]): string[] {
	return grantTypes.includes('authorization_code') ? ['code'] : [];
}

// Build the canonical metadata object that Client.validateClient expects: base
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
		'consent.require': input.requireConsent ?? true
	};
	if (input.clientName !== undefined) metadata.client_name = input.clientName;
	if (input.scope !== undefined) metadata.scope = input.scope;
	if (input.backchannelTokenDeliveryMode !== undefined) {
		metadata.backchannel_token_delivery_mode = input.backchannelTokenDeliveryMode;
	}
	if (input.backchannelClientNotificationEndpoint !== undefined) {
		metadata.backchannel_client_notification_endpoint =
			input.backchannelClientNotificationEndpoint;
	}
	return metadata;
}

function toView(client: {
	clientId: string;
	clientName?: string;
	applicationType?: string;
	grantTypes?: string[];
	responseTypes?: string[];
	redirectUris?: string[];
	postLogoutRedirectUris?: string[];
	tokenEndpointAuthMethod?: string;
	scope?: string;
	backchannelTokenDeliveryMode?: string;
	backchannelClientNotificationEndpoint?: string;
	['consent.require']?: boolean;
}): AdminClientView {
	return {
		clientId: client.clientId,
		clientName: client.clientName,
		applicationType: client.applicationType ?? 'web',
		grantTypes: client.grantTypes ?? [],
		responseTypes: client.responseTypes ?? [],
		redirectUris: client.redirectUris ?? [],
		postLogoutRedirectUris: client.postLogoutRedirectUris ?? [],
		tokenEndpointAuthMethod: client.tokenEndpointAuthMethod ?? 'none',
		scope: client.scope,
		requireConsent: client['consent.require'] !== false,
		backchannelTokenDeliveryMode: client.backchannelTokenDeliveryMode,
		backchannelClientNotificationEndpoint:
			client.backchannelClientNotificationEndpoint
	};
}

async function validateAndStore(metadata: Record<string, unknown>) {
	// Client.validateClient throws InvalidClient on bad metadata; the route layer
	// maps that to HTTP 422.
	const client = Client.validateClient(metadata);
	await adapter('Client').upsert(client.clientId, client.metadata());
	return client;
}

export async function createClient(
	input: CreateClientInput
): Promise<{ view: AdminClientView; secret?: string }> {
	const clientId = nanoid();
	const metadata = toMetadata(input, clientId);
	let secret: string | undefined;
	if (Client.needsSecret(metadata)) {
		secret = generateSecret();
		metadata.clientSecret = secret;
		metadata.client_secret_expires_at = 0;
	}
	const client = await validateAndStore(metadata);
	return { view: toView(client as never), secret };
}

export async function getClientView(
	clientId: string
): Promise<AdminClientView | null> {
	const client = await Client.tryFind(clientId);
	return client ? toView(client as never) : null;
}

export async function updateClient(
	clientId: string,
	patch: UpdateClientInput
): Promise<AdminClientView> {
	const existing = await Client.tryFind(clientId);
	if (!existing) throw new AdminError(404, 'client not found');
	const merged: CreateClientInput = {
		clientName: patch.clientName ?? existing.clientName,
		applicationType: (patch.applicationType ??
			existing.applicationType ??
			'web') as 'web' | 'native',
		grantTypes: patch.grantTypes ?? existing.grantTypes ?? [],
		redirectUris: patch.redirectUris ?? existing.redirectUris ?? [],
		postLogoutRedirectUris:
			patch.postLogoutRedirectUris ?? existing.postLogoutRedirectUris ?? [],
		tokenEndpointAuthMethod:
			patch.tokenEndpointAuthMethod ??
			existing.tokenEndpointAuthMethod ??
			'none',
		scope: patch.scope ?? existing.scope,
		requireConsent: patch.requireConsent ?? (existing['consent.require'] !== false),
		backchannelTokenDeliveryMode:
			patch.backchannelTokenDeliveryMode ??
			existing.backchannelTokenDeliveryMode,
		backchannelClientNotificationEndpoint:
			patch.backchannelClientNotificationEndpoint ??
			existing.backchannelClientNotificationEndpoint
	};
	const metadata = toMetadata(merged, clientId);
	// Mirror createClient's secret logic on the merged (post-patch) metadata, not
	// the pre-patch existing client — otherwise a confidential -> public transition
	// leaves a stale clientSecret (so rotateSecret wrongly succeeds on what is now
	// a public client), and a public -> confidential transition throws an unhandled
	// InvalidClientMetadata (clientSecret is mandatory but never gets minted).
	if (Client.needsSecret(metadata)) {
		// keep the existing secret, or mint one if transitioning public -> confidential
		metadata.clientSecret = existing.clientSecret ?? generateSecret();
		metadata.client_secret_expires_at = existing.clientSecret
			? (existing.clientSecretExpiresAt ?? 0)
			: 0;
	}
	// if the new auth method needs no secret, leave clientSecret unset so it's dropped
	const client = await validateAndStore(metadata);
	return toView(client as never);
}

export async function rotateSecret(clientId: string): Promise<string> {
	const existing = await Client.tryFind(clientId);
	if (!existing) throw new AdminError(404, 'client not found');
	if (!existing.clientSecret) {
		throw new AdminError(400, 'client has no secret to rotate');
	}
	const secret = generateSecret();
	const metadata = { ...existing.metadata(), clientSecret: secret };
	await validateAndStore(metadata as Record<string, unknown>);
	return secret;
}

export async function deleteClientRecord(clientId: string): Promise<void> {
	await adapter('Client').destroy(clientId);
}
