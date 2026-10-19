import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Whether an application's colour reaches its sign-in pages depends on who stands behind it, how the sign-in
 * began and where the answer goes, so this harness holds the organization's own app in each shape that
 * matters — plain, behind a two-step bucket, a device, a program on this computer — plus another tenant's app
 * (placed by the spec) and one that registered itself. The own apps are bound to their buckets by the spec,
 * the way an administrator creating them in a project would.
 */
export const ApplicationConfig = {
	'deviceFlow.enabled': true,
	'resourceIndicators.enabled': true
};

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
		redirectUris: ['https://app.acme.test/cb']
	},
	{
		...app,
		clientId: 'own-plain',
		client_name: 'Rota',
		redirectUris: ['https://rota.acme.test/cb']
	},
	{
		...app,
		clientId: 'own-second',
		client_name: 'Expenses',
		redirectUris: ['https://expenses.acme.test/cb']
	},
	{
		...app,
		clientId: 'own-two-step',
		client_name: 'Payroll',
		redirectUris: ['https://payroll.acme.test/cb']
	},
	{
		...app,
		clientId: 'own-loopback',
		client_name: 'Acme CLI',
		applicationType: 'native',
		redirectUris: ['http://127.0.0.1/cb']
	},
	{
		clientId: 'own-device',
		client_name: 'Acme TV',
		token_endpoint_auth_method: 'none',
		grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
		responseTypes: [],
		redirectUris: [],
		applicationType: 'native'
	},
	{
		...app,
		clientId: 'tenant-app',
		client_name: 'Partner Tool',
		redirectUris: ['https://partner.test/cb']
	},
	{
		...app,
		clientId: 'self-registered',
		client_name: 'Acme Payroll',
		registeredDynamically: true,
		redirectUris: ['https://payroll.example.net/cb']
	}
];

export default {
	config
};
