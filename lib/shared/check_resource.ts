import instance from '../helpers/weak_cache.ts';
import { InvalidTarget } from '../helpers/errors.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import ResourceServer from 'lib/helpers/resource_server.js';

const filterStatics = (oidc) => {
	if (oidc.params.scope && !oidc.params.resource) {
		oidc.params.scope = [...oidc.requestParamOIDCScopes].join(' ');
	}
};

function emptyResource(params) {
	return (
		!params.resource ||
		(Array.isArray(params.resource) && !params.resource.length)
	);
}

export default async function checkResource(oidc) {
	const { params, provider, client, resourceServers } = oidc;

	const { defaultResource, getResourceServerInfo } =
		instance(provider).features.resourceIndicators;

	if (!ApplicationConfig['resourceIndicators.enabled']) {
		filterStatics(oidc);
		return;
	}

	if (params.resource === undefined) {
		// defaultResource is a user-overridable callback expecting a `ctx`-shaped arg
		params.resource = await defaultResource({ oidc }, client);

		if (params.authorization_details && emptyResource(params)) {
			throw new InvalidTarget(
				'resource indicator must be provided or defaulted to when Rich Authorization Requests are used'
			);
		}
	}

	if (params.scope && emptyResource(params)) {
		filterStatics(oidc);
		return;
	}

	let { resource } = params;

	if (params.resource === undefined) {
		return;
	}

	if (!Array.isArray(params.resource)) {
		resource = [resource];
	}

	for (const identifier of resource) {
		const href = URL.parse(identifier)?.href;

		if (!href) {
			throw new InvalidTarget('resource indicator must be an absolute URI');
		}

		// NOTE: we don't check for new URL() => search of hash because of an edge case
		// new URL('https://example.com?#') => search and hash are empty, seems like an inconsistent validation
		if (href.includes('#')) {
			throw new InvalidTarget(
				'resource indicator must not contain a fragment component'
			);
		}

		// getResourceServerInfo is a user-overridable callback expecting a `ctx`-shaped arg
		const resourceServer = await getResourceServerInfo(
			{ oidc },
			identifier,
			client
		);
		resourceServers[identifier] = new ResourceServer(
			identifier,
			resourceServer
		);
	}
}
