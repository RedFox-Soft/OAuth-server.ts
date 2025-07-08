import merge from 'lodash/merge.js';

import { Prompt, base } from '../../lib/helpers/interaction_policy/index.ts';
import getConfig from '../default.config.js';
import { type CheckPartial } from 'lib/helpers/interaction_policy/prompt.js';

const config = getConfig();

merge(config.features, {
	rpInitiatedLogout: { enabled: false }
});

const policy = base();

const check: CheckPartial = {
	reason: 'reason_foo',
	description: 'error_description_foo',
	error: 'error_foo',
	check: (ctx: any) => {
		if (ctx.oidc.params.triggerCustomFail) {
			return true;
		}
		return false;
	}
};

policy.get('login').checks.push(check);

class CustomPrompt extends Prompt {
	name = 'custom';
}
policy.add(new CustomPrompt());

class UnrequestablePrompt extends Prompt {
	name = 'unrequestable';
	requestable = false;
	checks = [
		{
			reason: 'un_foo',
			description: 'un_foo_desc',
			error: 'un_foo_err',
			check: (ctx: any) => {
				if (
					ctx.oidc.params.triggerUnrequestable &&
					(!ctx.oidc.result || !('foo' in ctx.oidc.result))
				) {
					return true;
				}
				return false;
			}
		}
	];
}
policy.add(new UnrequestablePrompt());

config.interactions = { policy };

export default {
	config,
	client: {
		client_id: 'client',
		client_secret: 'secret',
		redirect_uris: ['https://client.example.com/cb']
	}
};
