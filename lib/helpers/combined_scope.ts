import { type Grant } from 'lib/models/grant.js';

export default (
	grant: Grant,
	requestParamScopes: Set<string> | string[],
	resourceServers: Record<string, { identifier(): string }>
) => {
	const combinedScope = new Set();

	grant
		.getOIDCScopeFiltered(requestParamScopes)
		.split(' ')
		.filter(Boolean)
		.forEach(Set.prototype.add.bind(combinedScope));

	for (const resourceServer of Object.values(resourceServers)) {
		grant
			.getResourceScopeFiltered(resourceServer.identifier(), requestParamScopes)
			.split(' ')
			.filter(Boolean)
			.forEach(Set.prototype.add.bind(combinedScope));
	}

	return combinedScope;
};
