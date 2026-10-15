import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Whether a consent page shows a client's logo and links depends on who stands behind the client and where
 * it sends the answer, so this harness holds the organization's own app in each shape that matters — links
 * on its redirect host, on another host, over http, a native app with no host, a program on this computer
 * — plus another tenant's app (signing into another bucket, arranged by the spec) and one that registered
 * itself.
 */
export const ApplicationConfig = {
	scopes: ['openid', 'billing']
};

/* 1×1 images, the smallest each format allows — enough for their bytes to be what they say. */
export const PNG =
	'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
export const JPEG =
	'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=';
export const WEBP =
	'data:image/webp;base64,UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==';
export const SVG = `data:image/svg+xml;base64,${Buffer.from(
	'<svg xmlns="http://www.w3.org/2000/svg"><text>Verified</text></svg>'
).toString('base64')}`;

const app = {
	token_endpoint_auth_method: 'none',
	grantTypes: ['authorization_code'],
	responseTypes: ['code']
};

export const clients = [
	{
		...app,
		clientId: 'own-app',
		client_name: 'Timesheets',
		redirectUris: ['https://app.acme.test/cb'],
		policy_uri: 'https://app.acme.test/privacy',
		tos_uri: 'https://app.acme.test/terms'
	},
	{
		...app,
		clientId: 'own-policy-only',
		client_name: 'Rota',
		redirectUris: ['https://rota.acme.test/cb'],
		policy_uri: 'https://rota.acme.test/privacy',
		tos_uri: 'https://elsewhere.test/terms'
	},
	{
		...app,
		clientId: 'own-other-host',
		client_name: 'Expenses',
		redirectUris: ['https://expenses.acme.test/cb'],
		policy_uri: 'https://elsewhere.test/privacy',
		tos_uri: 'https://elsewhere.test/terms'
	},
	{
		...app,
		clientId: 'own-http-links',
		client_name: 'Intranet',
		redirectUris: ['https://intranet.acme.test/cb'],
		policy_uri: 'http://intranet.acme.test/privacy',
		tos_uri: 'http://intranet.acme.test/terms'
	},
	{
		...app,
		clientId: 'own-native',
		client_name: 'Acme Mobile',
		applicationType: 'native',
		redirectUris: ['com.acme.mobile:/cb'],
		policy_uri: 'https://mobile.acme.test/privacy',
		tos_uri: 'https://mobile.acme.test/terms'
	},
	{
		...app,
		clientId: 'own-loopback',
		client_name: 'Acme CLI',
		applicationType: 'native',
		redirectUris: ['http://127.0.0.1/cb']
	},
	{
		...app,
		clientId: 'tenant-app',
		client_name: 'Partner Tool',
		redirectUris: ['https://partner.test/cb'],
		policy_uri: 'https://partner.test/privacy',
		tos_uri: 'https://partner.test/terms'
	},
	{
		...app,
		clientId: 'self-registered',
		client_name: 'Acme Payroll',
		registeredDynamically: true,
		redirectUris: ['https://payroll.example.net/cb'],
		logo_uri: 'https://payroll.example.net/logo.png',
		policy_uri: 'https://payroll.example.net/privacy',
		tos_uri: 'https://payroll.example.net/terms'
	}
];

export default {
	config
};
