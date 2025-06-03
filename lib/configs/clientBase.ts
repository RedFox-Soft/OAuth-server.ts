import { type ClientSchemaType } from './clientSchema.js';

export const ClientDefaults: ClientSchemaType = {
	subjectType: 'public',
	/*
	 * requirePushedAuthorizationRequests
	 *
	 * description: Makes the use of `PAR` required for authorization
	 * request as an authorization server policy.
	 */
	'authorization.requirePushedAuthorizationRequests': false
};
