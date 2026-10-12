/*
 * The customer directories this server knows how to explain, in their own words (specs/088 R9).
 *
 * DATA, NOT BEHAVIOUR, as lib/consts/known_providers.ts is: a connection's `directory` only chooses which of
 * these the console and an agent read, and nothing at runtime branches on it. The facts live here, on the
 * server, because facts only a console holds are facts an agent never gets — the lesson the providers'
 * PRESETS map taught.
 *
 * Labels are the directories' own field names, so an administrator copies each value without translating
 * it. Okta's OAuth client-credentials option for SCIM is documented on Okta's help pages but not yet in its
 * developer guide, and was not checked against a live organisation; the static token stays its fallback.
 *
 * IMPORT-FREE apart from another import-free declaration, so the console bundle may read it too.
 */

import {
	DEFAULT_CORRELATION,
	MICROSOFT_CORRELATION,
	type CorrelationRule
} from './correlation_rules.js';

export type KnownDirectoryKey = 'entra' | 'okta' | 'generic';

/* The credential kinds an issue accepts, as the guidance names them. */
export type DirectoryCredentialKind = 'secret' | 'static_token' | 'key';

export interface DirectoryLabels {
	readonly scimBaseUrl: string;
	readonly tokenEndpoint?: string;
	readonly clientId?: string;
	readonly clientSecret?: string;
	readonly staticToken?: string;
}

export interface KnownDirectory {
	readonly id: KnownDirectoryKey;
	readonly displayName: string;
	readonly recommendedCredential: DirectoryCredentialKind;
	/* What to use when the directory cannot use the recommended one. */
	readonly fallbackCredential?: DirectoryCredentialKind;
	readonly recommendedCorrelation: CorrelationRule;
	readonly labels: DirectoryLabels;
	readonly steps: readonly string[];
	readonly pitfalls: readonly string[];
}

export const KNOWN_DIRECTORIES: readonly KnownDirectory[] = [
	{
		id: 'entra',
		displayName: 'Microsoft Entra ID',
		recommendedCredential: 'secret',
		recommendedCorrelation: MICROSOFT_CORRELATION,
		labels: {
			scimBaseUrl: 'Tenant URL',
			tokenEndpoint: 'Token Endpoint',
			clientId: 'Client Identifier',
			clientSecret: 'Client Secret',
			staticToken: 'Secret Token'
		},
		steps: [
			'In the Microsoft Entra admin center, open Enterprise applications and create your own application: "Integrate any other application you don\'t find in the gallery (Non-gallery)".',
			'Open Provisioning and set Provisioning Mode to Automatic.',
			'Under Admin Credentials, choose the authentication method "OAuth2 Client Credentials Grant".',
			'Paste the Tenant URL, Token Endpoint, Client Identifier and Client Secret shown here.',
			'Leave Scope blank, or enter scim.',
			'Select Test Connection, then Save.',
			'In Mappings, keep objectId mapped to externalId, then start provisioning.'
		],
		pitfalls: [
			'Set "How credentials are sent" to Header or Body, never Both: a token request carrying the secret twice is refused (RFC 6749 §2.3), and Test Connection fails.',
			'Leave Scope blank or set it to scim; any other scope is refused.',
			'The long-lived Secret Token is not supported for new Entra applications; use the client secret.',
			'Entra quarantines a provisioning job on an invalid credential. After replacing the secret here, paste the new one into Entra within 24 hours.'
		]
	},
	{
		id: 'okta',
		displayName: 'Okta',
		recommendedCredential: 'secret',
		fallbackCredential: 'static_token',
		recommendedCorrelation: DEFAULT_CORRELATION,
		labels: {
			scimBaseUrl: 'SCIM connector base URL',
			tokenEndpoint: 'Token URL',
			clientId: 'Client ID',
			clientSecret: 'Client Secret',
			staticToken: 'Authorization'
		},
		steps: [
			'In the Okta Admin Console, create an app integration with the App Integration Wizard and turn on SCIM provisioning.',
			'On the Provisioning tab, under Integration, paste the SCIM connector base URL shown here.',
			'Set "Unique identifier field for users" to userName.',
			'Choose the provisioning actions: Push New Users, Push Profile Updates and Push Groups.',
			'Set Authentication Mode to OAuth 2 with the grant type Client Credentials, and paste the Token URL, Client ID and Client Secret shown here.',
			'If your Okta organization offers no Client Credentials option, choose HTTP Header instead and paste a static token into Authorization.',
			'Select Test Connector Configuration, then Save, and on To App enable Create Users, Update User Attributes and Deactivate Users.'
		],
		pitfalls: [
			'Okta documents the OAuth Client Credentials option for SCIM in its help pages; if your organization does not have it, use HTTP Header with a static token.',
			'In HTTP Header mode the static token is accepted with or without "Bearer " in front of it.',
			'A static token expires after 90 days or a year. Replace it before then: the old one keeps working until Okta uses the new one.'
		]
	},
	{
		id: 'generic',
		displayName: 'Another directory',
		recommendedCredential: 'key',
		fallbackCredential: 'secret',
		recommendedCorrelation: DEFAULT_CORRELATION,
		labels: {
			scimBaseUrl: 'SCIM base URL',
			tokenEndpoint: 'Token endpoint',
			clientId: 'Client ID',
			clientSecret: 'Client secret',
			staticToken: 'Static token'
		},
		steps: [
			'Configure the directory as a SCIM 2.0 client of the SCIM base URL shown here.',
			'If it can sign a client assertion (private_key_jwt), issue a key credential from its public keys; otherwise issue a client secret.',
			'Have it obtain tokens from the token endpoint with the client-credentials grant, asking for the scope scim or for no scope.',
			'Use a static token only if the directory can send nothing but a fixed bearer token.'
		],
		pitfalls: [
			'Send the client secret once — in the Authorization header or in the body, not both.',
			'Ask for the scope scim or none; any other scope is refused.',
			'A static token expires after 90 days or a year and must be replaced before then.'
		]
	}
];

export function knownDirectory(id: KnownDirectoryKey): KnownDirectory {
	const found = KNOWN_DIRECTORIES.find((entry) => entry.id === id);
	/* Unreachable while the three keys above are the type's three members. */
	if (!found) throw new Error(`no known directory is called ${id}`);
	return found;
}
