import { Elysia, t, type Context } from 'elysia';
import { createMcpHandler } from '@modelcontextprotocol/server';

import { ISSUER } from '../configs/env.js';
import { eventBus } from '../event_bus.js';
import { UseDpopNonce } from '../helpers/validate_dpop.js';
import { buildMcpServer } from './server.js';
import {
	McpUnauthorized,
	resolveMcpPrincipal,
	type ProofMethod,
	type RejectionReason
} from './principal.js';
import { withheldOutcome } from './result.js';
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

/*
 * The only request headers this layer reads.
 *
 * `authorization` is required, so a credential-less call is refused in the validation stage and never
 * reaches `serve`. Its absence is not a shape this route has an answer for, and saying so in the schema
 * is what makes that true rather than a convention the handler has to keep. What the schema cannot do
 * is *render* the refusal: Elysia answers a failed header check with a 422 carrying no
 * `WWW-Authenticate`, and that challenge is the only thing telling an unauthenticated MCP client where
 * to obtain a token. The `onError` at the bottom turns it back into the one 401 every other rejection
 * produces.
 *
 * Only the presence of a credential is asserted here, not its grammar. `OIDCContext.getAccessToken`
 * owns Bearer-versus-DPoP, and it reads `dpop.enabled` to do it — restating that as a pattern would put
 * a second, config-blind copy of the rule in the request path.
 *
 * `dpop` stays optional because it genuinely is: sender-constrained tokens are opt-in, and
 * `dpopValidate` decides what a missing proof means from the token's own `jkt`.
 *
 * Everything Streamable HTTP itself needs — `accept`, `content-type`, `mcp-session-id`,
 * `mcp-protocol-version` — is deliberately absent. The SDK validates those against the transport
 * specification and answers a JSON-RPC error when they are wrong; a 422 from this layer would replace
 * that with a shape no MCP client understands.
 *
 * Header schemas admit additional properties by default and Elysia lower-cases every key, so declaring
 * this both documents the contract and gives `serve` the header record `resolveMcpPrincipal` wants
 * without copying `request.headers` by hand.
 */
const mcpHeaders = t.Object({
	authorization: t.String({ minLength: 1 }),
	dpop: t.Optional(t.String())
});

/*
 * Elysia's own context, narrowed by that schema rather than restated. `body` stays `unknown`: the
 * payload is JSON-RPC, which the SDK parses and validates, and a schema here would reject the batches
 * and notifications it accepts.
 */
type McpContext = Context<{ headers: typeof mcpHeaders.static; body: unknown }>;

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
/*
 * Where the reason for a refusal goes, and the only place it goes. Typed against the resolver's own
 * vocabulary so the two callers below cannot invent a reason between them — plus `unknown`, for a
 * failure that was not a refusal at all and so has no `RejectionReason` to report.
 */
function report(reason: RejectionReason | 'unknown') {
	eventBus.emit('mcp.auth.error', { reason });
}

function challenge(set: McpContext['set']) {
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
 * The refusal for an operation an agent names but this surface does not publish.
 *
 * `tools/call` on an unregistered name is the SDK's own `Tool <name> not found`: correct as protocol
 * and useless as guidance, because it makes an operation withheld by operator decision
 * indistinguishable from a typo — so an agent retries or gives up instead of saying where the work can
 * be done. The text comes from `excludedConsoleOperations` by way of `withheldOutcome`, so the message
 * an agent reads and the table that decides absence cannot disagree.
 *
 * It has to be answered here, and the two nearer places were both tried in the design. A registered
 * tool cannot do it: a registered tool appears in `tools/list` however it behaves, which would present
 * a withheld operation as available. Nor can a tool *callback* — the SDK resolves the name against its
 * registry and throws before any callback runs, which is why `withheldOutcome`'s call inside the
 * registration loop can only ever fire for a name that is registered, and therefore never fires.
 *
 * Deliberately narrow. Anything that is not a single `tools/call` object carrying an id falls through
 * to the SDK untouched — a batch, a notification, a shape this does not recognise — so the transport
 * keeps its own handling of them rather than gaining a second, thinner implementation of it. Reached
 * only after the credential resolves, so the exclusion table is not readable by an anonymous caller.
 */
function absentToolRefusal(body: unknown): object | undefined {
	if (!body || typeof body !== 'object' || Array.isArray(body)) return undefined;

	const message = body as {
		method?: unknown;
		id?: unknown;
		params?: unknown;
	};
	if (message.method !== 'tools/call') return undefined;
	// A notification carries no id and takes no response at all.
	if (message.id === undefined || message.id === null) return undefined;
	if (!message.params || typeof message.params !== 'object') return undefined;

	const name = (message.params as { name?: unknown }).name;
	if (typeof name !== 'string') return undefined;

	const outcome = withheldOutcome(name);
	if (!outcome) return undefined;

	/*
	 * A JSON-RPC *result* whose payload is a failed tool call, not a JSON-RPC error: the call was
	 * well-formed and the answer is about the operation, which is the same shape every other refusal on
	 * this surface takes (`toOutcome`), and the shape an agent already knows how to read.
	 */
	return {
		jsonrpc: '2.0',
		id: message.id,
		result: {
			content: [{ type: 'text', text: outcome.message }],
			structuredContent: { ...outcome },
			isError: true
		}
	};
}

/*
 * POST carries JSON-RPC; GET opens the server-initiated stream. Registered as two routes rather than
 * one `.all`, because the feature-gate classification table declares them individually and its drift
 * guard compares (method, path) pairs exactly — an `ALL` route would match neither entry.
 */
async function serve(
	{ request, body, headers, set }: McpContext,
	/*
	 * Taken from the route that registered this handler rather than read back off `request.method`. A
	 * DPoP proof is bound to one method, and the two routes below are the whole set `/mcp` serves — so
	 * the value is known at registration and there is nothing to narrow at runtime.
	 */
	method: ProofMethod
) {
	let principal;
	try {
		principal = await resolveMcpPrincipal(headers, method);
	} catch (err) {
		if (err instanceof UseDpopNonce) {
			/*
			 * A nonce challenge is a protocol step, not a refusal: the caller is being told to retry
			 * with a nonce and must be able to see that. Rethrown so the server's own error handler
			 * renders it, exactly as every other DPoP-protected endpoint does — flattening it into
			 * the generic 401 would leave a compliant client with no way to proceed.
			 *
			 * It answers 401 rather than the authorization server's 400 because `/mcp` is a resource
			 * server (RFC 9449 §7.1). That correction is the error handler's, keyed on the route, so
			 * nothing here has to reach into the error to make it.
			 */
			throw err;
		}
		report(err instanceof McpUnauthorized ? err.reason : 'unknown');
		return challenge(set);
	}

	/*
	 * Before the SDK, because the SDK's answer for a name it does not know is a bare not-found and the
	 * reason an operation is absent lives in the exclusion table. After the credential above, so an
	 * anonymous caller learns nothing about what the table holds.
	 */
	const refusal = absentToolRefusal(body);
	if (refusal) return refusal;

	/*
	 * `parsedBody`, because Elysia has already read the JSON by the time a handler runs and the SDK
	 * cannot consume `request.body` a second time. Without it every request answers a JSON-RPC
	 * internal error, which is how this was found.
	 *
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
	/*
	 * The header schema's refusal, rendered as the same 401 every other rejection produces. Validation
	 * runs before `beforeHandle` and throws rather than returning, so this is the only stage that can
	 * still reach it — and the root error handler recognises `/mcp` and returns nothing precisely to
	 * hand it down here, the way it already does for the admin plane.
	 *
	 * `no_credential` is exact rather than a guess: `authorization` is the one required field, so an
	 * absent or empty header is the only way validation fails. A credential that is present but
	 * unusable fails later, inside `resolveMcpPrincipal`, which reports its own reason.
	 */
	.onError(({ code, set }) => {
		if (code === 'VALIDATION') {
			report('no_credential');
			return challenge(set);
		}
	})
	.get(MCP_METADATA_ROUTE, () => metadata)
	.post(MCP_ROUTE, (ctx) => serve(ctx, 'POST'), { headers: mcpHeaders })
	.get(MCP_ROUTE, (ctx) => serve(ctx, 'GET'), { headers: mcpHeaders });
