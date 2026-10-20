import { ApplicationConfig } from '../../configs/application.js';

/*
 * How agent hosts (Claude, Cursor, VS Code) can get a client identity at a project (spec 107): by a URL client ID
 * (Client ID Metadata Document) or by registering themselves. Both are instance settings a tenant cannot read, but
 * their effect is public — the project's discovery document advertises them — so stating it to a tenant leaks
 * nothing, and it is computed here because the console cannot read a subdomain or hostname project's discovery.
 * The same gates discovery applies (lib/configs/discoverySupport.ts `featuresKeyMap`).
 */
export interface AgentClients {
	urlClientIds: boolean;
	selfRegistration: 'open' | 'token' | 'off';
}

export function agentClients(): AgentClients {
	const registration = ApplicationConfig['registration.enabled'];
	return {
		urlClientIds: ApplicationConfig['clientIdMetadataDocument.enabled'],
		selfRegistration: !registration
			? 'off'
			: ApplicationConfig['registration.initialAccessToken']
				? 'token'
				: 'open'
	};
}
