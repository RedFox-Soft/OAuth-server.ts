import { type CheckPartial } from 'lib/helpers/interaction_policy/prompt.js';
import { Prompt, base } from '../../../lib/helpers/interaction_policy/index.ts';
import getConfig from '../../default.config.js';

const config = getConfig();

config.allowOmittingSingleRegisteredRedirectUri = false;

const policy = base();

const check: CheckPartial = {
	reason: 'reason_foo',
	description: 'error_description_foo',
	error: 'error_foo',
	check: (ctx) => {
		if (ctx.oidc.params.triggerCustomFail) {
			return true;
		}
		return false;
	}
};

class CustomPrompt extends Prompt {
	name = 'unrequestable';
}

policy.get('login').checks.push(check);
policy.add(new CustomPrompt());

config.interactions = { policy };

export default {
	config,
	clients: [
		{
			client_id: 'client',
			client_secret: 'secret',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code', 'none'],
			redirect_uris: ['https://client.example.com/cb']
		},
		{
			client_id: 'client-without-none',
			client_secret: 'secret',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
			redirect_uris: ['https://client.example.com/cb']
		},
		{
			client_id: 'client-no-refresh',
			client_secret: 'secret',
			grant_types: ['authorization_code'],
			response_types: ['code', 'none'],
			redirect_uris: ['https://client.example.com/cb']
		},
		{
			application_type: 'native',
			client_id: 'client-native',
			client_secret: 'secret',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code', 'none'],
			redirect_uris: ['com.example.app:/cb']
		},
		{
			client_id: 'client-limited-scope',
			client_secret: 'secret',
			redirect_uris: ['https://client.example.com/cb'],
			scope: 'openid',
			grant_types: ['authorization_code', 'refresh_token']
		}
	]
};
