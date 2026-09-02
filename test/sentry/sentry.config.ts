import getConfig from '../default.config.js';
import { ApplicationConfig } from 'lib/configs/application.ts';

/*
 * Bootstraps the provider with outbound reporting armed.
 *
 * Both flags are set on ApplicationConfig directly rather than passed through the config object,
 * because that is where the capture path and the client both read them — flat, per call, so a spec
 * can flip them mid-file. Reporting requires the store: the outbound event is projected from the
 * internal record, so arming one without the other is a configuration the validator refuses.
 *
 * The credential is syntactically valid and deliberately unroutable. Nothing in the suite sends to
 * it in any case — `lib/sentry/client.ts` installs the recording transport whenever NODE_ENV is
 * 'test', which `bun test` sets — but a DSN pointing at a real host would be one edit away from
 * being a live one.
 */
ApplicationConfig['errorStore.enabled'] = true;
ApplicationConfig['sentry.enabled'] = true;
ApplicationConfig['sentry.dsn'] = 'https://publickey@o0.ingest.invalid/1';

const config = getConfig();

export const clients = [
	{
		clientId: 'sentry-app',
		token_endpoint_auth_method: 'client_secret_basic',
		clientSecret: 'sentry-secret-value',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/sentry/callback']
	}
];

export default {
	config
};
