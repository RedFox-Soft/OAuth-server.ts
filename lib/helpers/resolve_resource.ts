import { InvalidTarget } from './errors.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { useGrantedResource, defaultResource } from '../addon/index.js';

export default async (oidc, model, _config, scopes = model.scopes) => {
	let resource;
	if (ApplicationConfig['resourceIndicators.enabled']) {
		switch (true) {
			case !!oidc.params.resource:
				resource = oidc.params.resource;
				break;
			case !model.payload.resource:
			case Array.isArray(model.payload.resource) &&
				model.payload.resource.length === 0:
				break;
			case model.payload.resource && !!(await useGrantedResource(oidc, model)):
			case !oidc.params.resource &&
				(!ApplicationConfig['userinfo.enabled'] || !scopes.has('openid')):
				resource = model.payload.resource;
				break;
		}

		if (Array.isArray(resource)) {
			resource = await defaultResource(oidc, oidc.client, resource);
		}

		if (Array.isArray(resource)) {
			throw new InvalidTarget(
				'only a single resource indicator value must be requested/resolved during Access Token Request'
			);
		}

		if (resource && !model.resourceIndicators.has(resource)) {
			throw new InvalidTarget();
		}
	}
	return resource;
};
