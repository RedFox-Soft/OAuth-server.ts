import config, {
	ApplicationConfig as ActivityApplicationConfig,
	clients as activityClients
} from '../activity/activity.config.ts';

/*
 * The activity suite's clients — a browser app for every case that needs its own, a service with a secret — plus one
 * client that registered itself, which no "last used" is ever recorded for.
 */
export const ApplicationConfig = ActivityApplicationConfig;

export const clients = [
	...activityClients,
	{
		clientId: 'usage-self-registered',
		clientSecret: 'usage-self-registered-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: [],
		registeredDynamically: true
	}
];

export default config;
