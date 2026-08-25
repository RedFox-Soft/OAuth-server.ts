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
	/*
	 * Raised by the callers, not by the resolver: `/mcp` refuses a credential-less request in its
	 * header schema and the admin plane falls through to its anonymous arm, so neither one ever reaches
	 * `resolveMcpPrincipal` without a credential. It stays in the vocabulary because it is still a
	 * reason that reaches the `mcp.auth.error` channel.
	 */
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
 * The credential headers this resolver reads, and the only ones it is entitled to.
 *
 * `authorization` is required, matching the `/mcp` route schema that produces it. Both callers already
 * establish that before they get here — the route refuses a credential-less request during validation,
 * and the admin plane returns its anonymous context — so an optional field would have described a case
 * neither one can present, and left the resolver a dead branch to carry.
 *
 * `dpop` is optional because sender-constrained tokens are opt-in; `dpopValidate` reads its absence.
 *
 * A type alias rather than an interface on purpose — an alias carries the implicit index signature
 * `OIDCContext` needs when this is passed straight through to it.
 */
export type McpCredentialHeaders = {
	authorization: string;
	dpop?: string;
};

/*
 * The method a DPoP proof was created for. `dpopValidate` binds a proof to one method and one URL and
 * understands only these two, which is the whole set `/mcp` serves.
 */
export type ProofMethod = 'GET' | 'POST';

/*
 * Resolves the bearer (or DPoP-bound) credential on an MCP request to the administrator it authorizes.
 *
 * That a credential is present at all is the caller's to establish, and the parameter type says so.
 * From there the order is deliberate and each step is load-bearing:
 *
 *  1. The credential parses into a token id — `getAccessToken` owns the Bearer/DPoP grammar and reads
 *     `dpop.enabled` to decide it.
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
	headers: McpCredentialHeaders,
	/*
	 * The method the proof was created for, not necessarily the one the request arrived on. `/mcp`
	 * serves exactly these two and passes the literal its route registered; the admin plane resolves
	 * tokens on verbs no proof is ever made for and collapses them before calling — see the limitation
	 * note above for why that collapse is the caller's to make.
	 */
	method: ProofMethod = 'POST'
): Promise<McpPrincipal> {
	const oidc = new OIDCContext({}, headers);
	let accessTokenId: string;
	try {
		accessTokenId = oidc.getAccessToken({ acceptDPoP: true });
	} catch {
		throw new McpUnauthorized('malformed_credential');
	}

	let dPoP: Awaited<ReturnType<typeof dpopValidate>>;
	try {
		// Bound to `/mcp` rather than to the request's own route: a proof is only ever created for the
		// `/mcp` request itself — see the limitation note on this function.
		dPoP = await dpopValidate(headers.dpop, {
			accessTokenId,
			method,
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
