import { type ClientSchemaType } from './clientSchema.js';

export const ClientDefaults: ClientSchemaType = {
	subjectType: 'public',
	'authorization.requirePushedAuthorizationRequests': false,
	'requestObject.require': false
};
