import getConfig from '../default.config.js';
import { ApplicationConfig } from 'lib/configs/application.ts';

/*
 * Bootstraps the provider with the error store switched on.
 *
 * The flag is set on ApplicationConfig directly rather than passed through the config object, because
 * that is where the capture path and the feature gate both read it — flat, per call, so a spec can flip
 * it mid-file. `errorStore.enabled` is off by default in a deployment, so a spec that forgets this sees
 * an empty store rather than a failure, which is the one confusing outcome worth naming here.
 */
ApplicationConfig['errorStore.enabled'] = true;

const config = getConfig();

export const clients = [
	{
		clientId: 'fault-app',
		token_endpoint_auth_method: 'client_secret_basic',
		clientSecret: 'fault-secret-value',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/fault/callback']
	}
];

export default {
	config
};
