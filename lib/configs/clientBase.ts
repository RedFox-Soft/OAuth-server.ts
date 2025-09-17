import { type ClientSchemaType } from './clientSchema.js';

export const ClientDefaults: Omit<ClientSchemaType, 'clientId'> = {
	redirectUris: [],
	subjectType: 'public',
	'authorization.requirePushedAuthorizationRequests': false,
	'requestObject.require': false
};
