import { AccessToken } from '../models/access_token.js';
import { OIDCContext } from '../helpers/oidc_context.js';
import {
	dpopValidate,
	validateReplay,
	InvalidDpopProof,
	UseDpopNonce
} from '../helpers/validate_dpop.js';
import { getUserStore } from '../adapters/index.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { MCP_RESOURCE, MCP_ROUTE } from './consts.js';

/*
 * The identity behind an MCP request: which administrator authorized the agent, and which agent is
 * acting. Both, because the audit trail must attribute an action to the agent *and* the authorizing
 * principal, and only the pair does that.
 */
export interface McpPrincipal {
	readonly accessTokenId: string;
	readonly accountId: string;
	/* The agent's OAuth client. Becomes `viaClientId` on every audit entry it produces. */
	readonly clientId: string;
	readonly scopes: ReadonlySet<string>;
}

/*
 * Why a token was refused. Never sent to the caller — `/mcp` answers one 401 for every cause, because
 * which check failed is not something an unauthenticated caller gets to probe for. Same reasoning as
 * the admin console's callback, which routes its reason to the event bus instead of the response.
 */
export type RejectionReason =
	| 'no_credential'
	| 'malformed_credential'
	| 'unknown_token'
	| 'wrong_audience'
	| 'dpop_failed'
	| 'no_account'
	| 'not_an_admin'
	| 'inactive';

export class McpUnauthorized extends Error {
	constructor(readonly reason: RejectionReason) {
		super(`mcp authorization refused: ${reason}`);
	}
}

/*
 * Resolves the bearer (or DPoP-bound) credential on an MCP request to the administrator it authorizes.
 *
 * The order is deliberate and each step is load-bearing:
 *
 *  1. A credential is present at all.
 *  2. The token exists and has not expired or been revoked — `AccessToken.find` covers all three,
 *     since a revoked or expired token is simply not there.
 *  3. `aud` is exactly MCP_RESOURCE. This is the confused-deputy guard resource indicators exist for:
 *     without it, a token minted for the UserInfo endpoint could administer the server. The converse
 *     already holds — `lib/actions/userinfo.ts` refuses any token carrying an audience at all — so
 *     this single check completes the boundary in both directions.
 *  4. DPoP, when the token is sender-constrained, through the same helpers every other protected
 *     endpoint uses. No reimplementation.
 *  5. The account resolves, lives in the reserved administrator bucket, and is active. An agent
 *     authenticated against any other bucket is not an administrator, whatever its token says.
 *
 * Roles are deliberately NOT read here. They are resolved per request by `resolveAdmin`, so a
 * deactivated account or a reduced role takes effect on the very next tool call rather than at the
 * next reconnection.
 *
 * KNOWN LIMITATION — a sender-constrained (DPoP-bound) token cannot be used for tool calls.
 *
 * A DPoP proof is bound to one method and one URL: the client creates it for `POST /mcp`. When a tool
 * re-dispatches into an admin route, that request carries no proof and could not carry a valid one — a
 * proof for `PATCH /admin/api/...` is not something the client ever made. So step 4 below finds `jkt`
 * set with no proof and refuses.
 *
 * That fails closed, which is the right direction, but it does mean a client using DPoP cannot use this
 * surface while `dpop.enabled` is on. Fixing it properly means the re-dispatch trusting the entry
 * point's validation, and the only safe way to express that trust is a channel the network cannot reach
 * — not a header, which `adminApp` being publicly mounted would make spoofable. Left as a follow-up
 * rather than papered over, and asserted by `test/mcp/dpop_bound.spec.ts` so it is a known state rather
 * than a latent surprise. `dpop.enabled` is off by default.
 */
export async function resolveMcpPrincipal(
	headers: Record<string, string | undefined>,
	/*
	 * The method the credential is being presented on. `/mcp` serves GET and POST; the admin plane also
	 * resolves tokens on PUT, PATCH and DELETE, so the parameter accepts them and narrows below.
	 */
	method: string = 'POST'
): Promise<McpPrincipal> {
	if (!headers.authorization) {
		throw new McpUnauthorized('no_credential');
	}

	const oidc = new OIDCContext({}, headers);
	let accessTokenId: string;
	try {
		accessTokenId = oidc.getAccessToken({ acceptDPoP: true });
	} catch {
		throw new McpUnauthorized('malformed_credential');
	}

	let dPoP: Awaited<ReturnType<typeof dpopValidate>>;
	try {
		/*
		 * `dpopValidate` binds a proof to a method and a route, and only understands GET and POST. A proof
		 * is only ever created for the `/mcp` request itself, so anything else is treated as POST — see the
		 * limitation note on this function.
		 */
		dPoP = await dpopValidate(headers.dpop, {
			accessTokenId,
			method: method === 'GET' ? 'GET' : 'POST',
			route: MCP_ROUTE
		});
	} catch (err) {
		// A nonce challenge is a legitimate protocol step, not a rejection to flatten into the generic
		// 401 — the caller is being told to retry with a nonce and must be able to see that.
		if (err instanceof UseDpopNonce) throw err;
		if (err instanceof InvalidDpopProof)
			throw new McpUnauthorized('dpop_failed');
		throw err;
	}

	const accessToken = await AccessToken.tryFind(accessTokenId);
	if (!accessToken) {
		throw new McpUnauthorized('unknown_token');
	}

	if (accessToken.payload.aud !== MCP_RESOURCE) {
		throw new McpUnauthorized('wrong_audience');
	}

	if (accessToken.payload.jkt) {
		if (!dPoP || accessToken.payload.jkt !== dPoP.thumbprint) {
			throw new McpUnauthorized('dpop_failed');
		}
		await validateReplay(accessToken.payload.clientId, dPoP);
	}

	const accountId = accessToken.payload.accountId;
	if (!accountId) {
		// A client-credentials token has no account, so it authorizes no administrator. The control
		// plane has no notion of an actor that is not a person.
		throw new McpUnauthorized('no_account');
	}

	const user = await getUserStore(ADMIN_BUCKET_ID).find(accountId);
	if (!user) throw new McpUnauthorized('not_an_admin');
	if (!user.active) throw new McpUnauthorized('inactive');

	return {
		accessTokenId,
		accountId,
		clientId: accessToken.payload.clientId,
		scopes: new Set(accessToken.payload.scope?.split(' ').filter(Boolean))
	};
}
