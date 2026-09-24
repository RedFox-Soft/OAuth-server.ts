import { InvalidTarget } from '../helpers/errors.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import ResourceServer from 'lib/helpers/resource_server.js';
import { defaultResource, getResourceServerInfo } from '../addon/index.js';
import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import type { TokenParams } from 'lib/actions/token.js';

// The authorization pipeline's context, or the token endpoint's for client credentials.
type ResourceContext = OIDCContext<PipelineParams> | OIDCContext<TokenParams>;

const filterStatics = (oidc: ResourceContext) => {
	if (oidc.params.scope && !oidc.params.resource) {
		oidc.params.scope = [...oidc.requestParamOIDCScopes].join(' ');
	}
};

function emptyResource(params: { resource?: string | string[] }) {
	return (
		!params.resource ||
		(Array.isArray(params.resource) && !params.resource.length)
	);
}

export default async function checkResource(oidc: ResourceContext) {
	const { params, client, resourceServers } = oidc;

	if (!ApplicationConfig['resourceIndicators.enabled']) {
		filterStatics(oidc);
		return;
	}

	if (params.resource === undefined) {
		params.resource = await defaultResource(oidc, client);

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

	if (params.resource === undefined) {
		return;
	}

	const resources = Array.isArray(params.resource)
		? params.resource
		: [params.resource];

	for (const identifier of resources) {
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

		const resourceServer = await getResourceServerInfo(
			oidc,
			identifier,
			client
		);
		resourceServers[identifier] = new ResourceServer(
			identifier,
			resourceServer
		);
	}
}
