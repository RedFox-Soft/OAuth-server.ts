import getConfig from '../default.config.js';

/*
 * Harness for declared protected resources.
 *
 * `resourceIndicators.enabled` is deliberately absent: it defaults to true, and the whole point of
 * this feature is that declaring a resource needs no capability switched on (SC-002). Setting it here
 * would hide a regression in that default.
 *
 * `clientCredentials.enabled` is on because it is the shortest path to the thing under test — the
 * token endpoint resolving a `resource` to a descriptor and minting an audience-bound token. The
 * authorization-code path resolves through the very same `checkResource`, so testing it here costs
 * nothing in coverage and removes an interaction dance from every case.
 *
 * `introspection.enabled` is on because the opaque arm of FR-001a is only observable through it —
 * which is also the argument for the self-contained format being the default a reader gets.
 */
export const ApplicationConfig = {
	...getConfig(),
	'clientCredentials.enabled': true,
	'introspection.enabled': true
};

/*
 * `client` belongs to the project that declares the resources these specs use (seeded per spec, since
 * projects are not configuration); `outsider` is a confidential client of some other project, and
 * `stranger` belongs to none — the two a machine token must not reach a declared resource for.
 */
export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'outsider',
		clientSecret: 'outsider-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'stranger',
		clientSecret: 'stranger-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	}
];

export default { config: getConfig() };
