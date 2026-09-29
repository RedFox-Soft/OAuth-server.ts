import { ISSUER } from 'lib/configs/env.js';
import { mock } from '../fetch_mock.js';

/*
 * The protected resource metadata (RFC 9728) a resource serves to say which authorization servers it
 * trusts. An administrator who is not a super administrator declares a resource only when its own
 * metadata names this server, so a spec declaring one has to serve it the way a real resource would.
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
