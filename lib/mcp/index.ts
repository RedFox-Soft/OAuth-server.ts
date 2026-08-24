import { Elysia } from 'elysia';
import { createMcpHandler } from '@modelcontextprotocol/server';

import { ISSUER } from '../configs/env.js';
import { eventBus } from '../event_bus.js';
import { UseDpopNonce } from '../helpers/validate_dpop.js';
import { buildMcpServer } from './server.js';
import { McpUnauthorized, resolveMcpPrincipal } from './principal.js';
import { MCP_METADATA_ROUTE, MCP_RESOURCE, MCP_ROUTE } from './consts.js';

/*
 * The administrative MCP control plane's HTTP face.
 *
 * `/mcp` is an OAuth 2.1 protected resource of this very server: the MCP specification requires an MCP
 * server to validate that a token was issued for it as the intended audience and to answer 401
 * otherwise, and to publish RFC 9728 metadata so a client can find the authorization server. Both live
 * here.
 *
 * Both routes are gated on `mcp.enabled` in `lib/consts/route_classification.ts`, so with the capability
 * off they answer exactly as a path this server does not serve — the same body, status and headers,
 * because `featureGate` refuses on `onRequest` before any of this runs.
 */

/* The slice of Elysia's handler context these two routes use. */
interface McpRouteContext {
	request: Request;
	/*
	 * Elysia has already parsed the JSON body by the time a handler runs, which consumes
	 * `request.body`. The SDK cannot read the stream a second time, so it must be handed the parsed
	 * value through `parsedBody` — the option the SDK provides for exactly this situation. Without it
	 * every request answers a JSON-RPC internal error, which is how this was found.
	 */
	body: unknown;
	set: { status?: number | string; headers: Record<string, string> };
}

const issuer = ISSUER.replace(/\/$/, '');

/*
 * The RFC 9728 document, built here rather than with the SDK's `buildOAuthProtectedResourceMetadata`.
 * That helper validates the issuer at call time and throws for any non-HTTPS, non-localhost URL — which
 * is correct for production and wrong for a module-scope constant, since it would take the whole process
 * (and the test suite, whose ISSUER is `http://e.ly`) down at import. The document is five fields defined
 * by the RFC; keeping it literal keeps the failure mode ours.
 *
 * The constitution already requires an https ISSUER in production, so the check this drops is one the
 * deployment rules cover.
 */
const metadata = {
	resource: MCP_RESOURCE,
	authorization_servers: [issuer],
	scopes_supported: ['openid'],
	bearer_methods_supported: ['header'],
	resource_documentation: `${issuer}/admin`
};

/*
 * One handler for the process, and one fresh `McpServer` per request — the factory is called per
 * exchange, so nothing an agent does leaks into the next request or into another operator's session.
 */
const handler = createMcpHandler((ctx) => buildMcpServer(ctx));

/*
 * The single 401 every rejection produces.
 *
 * One answer for every cause, deliberately: which check failed — unknown token, wrong audience, expired,
 * not an administrator, deactivated — is not something an unauthenticated caller gets to probe for. The
 * reason goes to the event bus instead, where a deployment can subscribe to it. Not to the console log,
 * because this route is unauthenticated and an attacker-triggerable log write is a vector of its own;
 * the admin console's callback made the same call for the same reason.
 *
 * `WWW-Authenticate` carries `resource_metadata` so a client that arrives without a token can discover
 * where to get one, which is what the MCP specification asks for.
 */
function challenge(set: McpRouteContext['set']) {
	set.status = 401;
	set.headers['www-authenticate'] =
		`Bearer resource_metadata="${issuer}${MCP_METADATA_ROUTE}", error="invalid_token"`;
	return {
		jsonrpc: '2.0',
		error: { code: -32001, message: 'authorization required' },
		id: null
	};
}

/*
 * POST carries JSON-RPC; GET opens the server-initiated stream. Registered as two routes rather than
 * one `.all`, because the feature-gate classification table declares them individually and its drift
 * guard compares (method, path) pairs exactly — an `ALL` route would match neither entry.
 */
async function serve({ request, body, set }: McpRouteContext) {
	const headers: Record<string, string | undefined> = {};
	request.headers.forEach((value, key) => {
		headers[key.toLowerCase()] = value;
	});

	let principal;
	try {
		// `/mcp` serves only these two methods (both declared in the gate table), so anything else
		// never reaches here. Narrowed because dpopValidate binds the proof to the method.
		const method = request.method === 'GET' ? 'GET' : 'POST';
		principal = await resolveMcpPrincipal(headers, method);
	} catch (err) {
		if (err instanceof UseDpopNonce) {
			/*
			 * A nonce challenge is a protocol step, not a refusal: the caller is being told to retry
			 * with a nonce and must be able to see that. Rethrown so the server's own error handler
			 * renders it, exactly as every other DPoP-protected endpoint does — flattening it into
			 * the generic 401 would leave a compliant client with no way to proceed.
			 */
			err.status = 401;
			throw err;
		}
		eventBus.emit('mcp.auth.error', {
			reason: err instanceof McpUnauthorized ? err.reason : 'unknown'
		});
		return challenge(set);
	}

	/*
	 * `authInfo` is strictly pass-through in the SDK — it never derives identity from headers and
	 * performs no verification of its own. That division is the right one: the token was verified
	 * above, by this server, against its own storage.
	 */
	return handler.fetch(request, {
		parsedBody: body,
		authInfo: {
			token: principal.accessTokenId,
			clientId: principal.clientId,
			scopes: [...principal.scopes],
			resource: new URL(MCP_RESOURCE)
		}
	});
}

export const mcpApp = new Elysia({ name: 'mcp' })
	.get(MCP_METADATA_ROUTE, () => metadata)
	/*
	 * Elysia's handler context is much wider than these two routes read; `McpRouteContext` names the
	 * slice they use, and the cast is the narrowing. Annotating `serve` with the full inferred context
	 * would tie this module to Elysia's generic plumbing for no benefit.
	 */
	.post(MCP_ROUTE, (ctx) => serve(ctx as unknown as McpRouteContext))
	.get(MCP_ROUTE, (ctx) => serve(ctx as unknown as McpRouteContext));
