import { type ClientData } from '../models/client/types.ts';

/*
 * ClientDefaults
 *
 * description: Default client metadata assigned when the client leaves it unspecified,
 * e.g. during Dynamic Client Registration or for stored clients. This is the single
 * declaration of every client default, in one key convention (camelCase, matching
 * ClientSchema). Consumers that work in wire-format (snake_case) metadata names translate
 * at their own seam — see lib/models/client/schema.ts.
 */
export const ClientDefaults: Omit<ClientData, 'clientId'> = {
	redirectUris: [],
	applicationType: 'web',
	responseTypes: ['code'],
	grantTypes: ['authorization_code'],
	subjectType: 'public',
	idTokenSignedResponseAlg: 'RS256',
	tokenEndpointAuthMethod: 'client_secret_basic',
	'authorization.requirePushedAuthorizationRequests': false,
	'requestObject.require': false,
	'consent.require': true
};
