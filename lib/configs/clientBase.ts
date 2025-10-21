import { type ClientSchemaType } from './clientSchema.js';

export const ClientDefaults: Omit<ClientSchemaType, 'clientId'> = {
	redirectUris: [],
	applicationType: 'web',
	responseTypes: ['code'],
	subjectType: 'public',
	'authorization.requirePushedAuthorizationRequests': false,
	'requestObject.require': false
};
