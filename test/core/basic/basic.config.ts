import { type CheckPartial } from 'lib/helpers/interaction_policy/prompt.js';
import { Prompt, base } from '../../../lib/helpers/interaction_policy/index.ts';
import getConfig from '../../default.config.js';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

const policy = base();

const check: CheckPartial = {
	reason: 'reason_foo',
	description: 'error_description_foo',
	error: 'error_foo',
	check: (oidc) => {
		// A deployment's own parameter, which the declared request parameters do not name.
		if ((oidc.params as Record<string, unknown>).triggerCustomFail) {
			return true;
		}
		return false;
	}
};

class CustomPrompt extends Prompt {
	name = 'unrequestable';
}

const login = policy.get('login');
if (!login) throw new Error('the base policy has a login prompt');
login.checks.push(check);
policy.add(new CustomPrompt());

// The policy is overridable behavior, registered through the addon seam rather than passed
// as provider configuration. bootstrap() makes this the spec's addon baseline.
export const addons: Partial<AddonImplementations> = {
	interactionPolicy: () => policy
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code', 'none'],
		redirectUris: ['https://client.example.com/cb']
	},
	{
		clientId: 'client-without-none',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb']
	},
	{
		clientId: 'client-no-refresh',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code', 'none'],
		redirectUris: ['https://client.example.com/cb']
	},
	{
		applicationType: 'native',
		clientId: 'client-native',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code', 'none'],
		redirectUris: ['com.example.app:/cb']
	},
	// Two redirect_uri shapes the response-mode cases need: one already carrying a query, with a
	// planted `state` a client must not be able to pin, and one with no path at all.
	{
		clientId: 'client-query-cb',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb?other=stuff&state=planted']
	},
	{
		clientId: 'client-bare-origin-cb',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com']
	},
	{
		clientId: 'client-limited-scope',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb'],
		scope: 'openid',
		grantTypes: ['authorization_code', 'refresh_token']
	}
];

export default {
	config
};
