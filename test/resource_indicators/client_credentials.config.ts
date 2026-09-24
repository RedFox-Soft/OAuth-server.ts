import * as errors from '../../lib/helpers/errors.ts';
import getConfig from '../default.config.js';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

export const addons: Partial<AddonImplementations> = {
	getResourceServerInfo(oidc, resourceIndicator) {
		const [, wl, format] = resourceIndicator.split(':');
		if (wl.includes('wl')) {
			return {
				scope: 'api:read api:write',
				accessTokenFormat: format || 'opaque'
			};
		}

		throw new errors.InvalidTarget();
	},
	defaultResource(oidc) {
		// A parameter of this deployment's own, sent by the cases that want no default resource.
		if ('nodefault' in oidc.params && oidc.params.nodefault) {
			return undefined;
		}

		return 'urn:wl:opaque:default';
	}
};

export const ApplicationConfig = {
	'clientCredentials.enabled': true
};

export const client = {
	clientId: 'client',
	clientSecret: 'secret',
	grantTypes: ['client_credentials'],
	responseTypes: [],
	redirectUris: []
};

export default {
	config
};
