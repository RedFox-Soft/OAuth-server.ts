import { pathInserted } from './vouching.js';

/*
 * What a developer protecting a declared API needs from this server (spec 107): the issuer its tokens come from, the
 * exact audience they carry, and the metadata and challenge the API itself must serve (RFC 9728). Stated by the server
 * because the console cannot read a subdomain or hostname project's discovery under its own content policy, and so
 * an agent reading the declaration gets the same values.
 */
export interface ResourceConnection {
	issuer: string;
	audience: string;
	metadata: {
		resource: string;
		authorization_servers: string[];
		scopes_supported: string[];
		bearer_methods_supported: string[];
	};
	/* Where the server looks for that document; null for an identifier that is not a URL, which has no well-known. */
	metadataUrl: string | null;
	/* The `WWW-Authenticate` value of a 401 (RFC 9728 §5.1); null with `metadataUrl`. */
	challenge: string | null;
}

export function resourceConnection(
	resource: { identifier: string; scopes: readonly string[] },
	issuer: string
): ResourceConnection {
	const metadataUrl = URL.canParse(resource.identifier)
		? pathInserted(new URL(resource.identifier))
		: null;
	return {
		issuer,
		audience: resource.identifier,
		metadata: {
			resource: resource.identifier,
			authorization_servers: [issuer],
			scopes_supported: [...resource.scopes],
			bearer_methods_supported: ['header']
		},
		metadataUrl,
		challenge: metadataUrl ? `Bearer resource_metadata="${metadataUrl}"` : null
	};
}
