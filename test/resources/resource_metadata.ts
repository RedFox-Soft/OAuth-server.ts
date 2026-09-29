import { ISSUER } from 'lib/configs/env.js';
import { mock } from '../fetch_mock.js';

/*
 * The protected resource metadata (RFC 9728) a resource serves to say which authorization servers it
 * trusts, for the vouching diagnostic to find the way a real resource would publish it.
 *
 * Built from the identifier the way the RFC builds the well-known address: the well-known segment goes
 * between the host and the resource's path. Single use, like every interceptor here.
 */
export function serveResourceMetadata(
	identifier: string,
	overrides: Record<string, unknown> = {},
	{ atRoot = false }: { atRoot?: boolean } = {}
): void {
	const url = new URL(identifier);
	const suffix = atRoot || url.pathname === '/' ? '' : url.pathname;
	mock(url.origin)
		.intercept({ path: `/.well-known/oauth-protected-resource${suffix}` })
		.reply(
			200,
			JSON.stringify({
				resource: identifier,
				authorization_servers: [ISSUER],
				...overrides
			})
		);
}

/*
 * A resource that names its metadata the first way the MCP specification says a client discovers it:
 * the `resource_metadata` parameter of the `Bearer` challenge on an unauthenticated request. The
 * document is served at an address of the resource's own choosing, which is the point of the
 * mechanism — no well-known address is involved.
 */
export function challengeWithMetadata(
	identifier: string,
	overrides: Record<string, unknown> = {}
): void {
	const url = new URL(identifier);
	const metadataPath = '/meta/where-we-publish.json';
	mock(url.origin)
		.intercept({ path: url.pathname })
		.reply(401, '', {
			headers: {
				'www-authenticate': `Bearer realm="mcp", resource_metadata="${url.origin}${metadataPath}"`
			}
		});
	mock(url.origin)
		.intercept({ path: metadataPath })
		.reply(
			200,
			JSON.stringify({
				resource: identifier,
				authorization_servers: [ISSUER],
				...overrides
			})
		);
}
