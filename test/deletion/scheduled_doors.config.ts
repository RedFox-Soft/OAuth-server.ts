import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Every door a scheduled bucket has to close must be open on an active one, or a 404 proves nothing:
 * introspection, SCIM and the federation receiver are each off by default.
 */
export const ApplicationConfig = {
	'introspection.enabled': true,
	'revocation.enabled': true,
	'scim.enabled': true,
	'federation.enabled': true,
	'backchannelLogout.enabled': true
};

/*
 * `tenant-app` registered itself at the bucket's address, which is what places its tokens in that bucket
 * wherever they are presented — a client a project uses cannot exist for a scheduled bucket, because a bucket
 * a project uses cannot be scheduled. `bystander` asks about tokens without being part of the story.
 */
export const clients = [
	{
		clientId: 'tenant-app',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://tenant.example.com/cb'],
		registeredAtBucket: 'doors-bucket'
	},
	{
		clientId: 'bystander',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://bystander.example.com/cb']
	}
];

export default {
	config
};
