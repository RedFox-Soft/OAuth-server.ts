import { Prompt, base } from '../../lib/helpers/interaction_policy/index.ts';
import getConfig from '../default.config.js';
import { type CheckPartial } from 'lib/helpers/interaction_policy/prompt.js';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

export const ApplicationConfig = {
	'rpInitiatedLogout.enabled': false
};

const policy = base();

const check: CheckPartial = {
	reason: 'reason_foo',
	description: 'error_description_foo',
	error: 'error_foo',
	check: (oidc: any) => {
		if (oidc.params.triggerCustomFail) {
			return true;
		}
		return false;
	}
};

const login = policy.get('login');
if (!login) throw new Error('the base policy has a login prompt');
login.checks.push(check);

class CustomPrompt extends Prompt {
	name = 'custom';
	requestable = true;
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
			check: (oidc: any) => {
				if (
					oidc.params.triggerUnrequestable &&
					(!oidc.result || !('foo' in oidc.result))
				) {
					return true;
				}
				return false;
			}
		}
	];
}
policy.add(new UnrequestablePrompt());

// The policy is overridable behavior, registered through the addon seam rather than passed
// as provider configuration. bootstrap() makes this the spec's addon baseline.
export const addons: Partial<AddonImplementations> = {
	interactionPolicy: () => policy
};

export const client = {
	clientId: 'client',
	clientSecret: 'secret',
	client_name: 'Test Client App',
	redirectUris: ['https://client.example.com/cb']
};

export default {
	config
};
