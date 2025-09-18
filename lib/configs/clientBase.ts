import { type ClientSchemaType } from './clientSchema.js';

export const ClientDefaults: Omit<ClientSchemaType, 'clientId'> = {
	redirectUris: [],
	applicationType: 'web',
	subjectType: 'public',
	'authorization.requirePushedAuthorizationRequests': false,
	'requestObject.require': false
};
