import { Elysia, t } from 'elysia';
import certificateThumbprint from '../helpers/certificate_thumbprint.ts';
import { findAccount } from '../addon/account.js';
import filterClaims from '../helpers/filter_claims.ts';
import {
	dpopValidate,
	setNonceHeader,
	validateReplay
} from '../helpers/validate_dpop.js';
import {
	InvalidToken,
	InsufficientScope,
	InvalidRequest,
	MissingResourceCredential
} from '../helpers/errors.ts';
import { routeNames } from 'lib/consts/param_list.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Claims } from 'lib/helpers/claims.js';
import { IdToken } from 'lib/models/id_token.js';
import { Client } from 'lib/models/client.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';
import { OAuthError, UserinfoResponse } from 'lib/shared/response_schemas.js';
import { accessTokenClientId, corsClientBased } from 'lib/plugins/cors.js';

/*
 * The access token a form-encoded request body carries, if it may carry one.
 *
 * RFC 6750 §2.2 defines this method for a request whose entity body is form-encoded and whose method
 * is one that takes an entity body, so both conditions are checked rather than assumed from the
 * presence of a parsed `access_token`. Neither is a formality: reading it from any other encoding
 * would accept a credential over a transport the specification does not cover, and the content type
 * is the only thing distinguishing the two.
 */
function formEncodedAccessToken(headers, body, method: string) {
	if (method !== 'POST') {
		return undefined;
	}
	const contentType = headers['content-type'] ?? '';
	if (!contentType.startsWith('application/x-www-form-urlencoded')) {
		return undefined;
	}
	const token = (body as Record<string, unknown> | undefined)?.access_token;
	return typeof token === 'string' && token ? token : undefined;
}

/*
 * Which of the two RFC 6750 methods presented the token, and a refusal when the answer is "both".
 *
 * §2 forbids a client using more than one, and §3.1 makes that `invalid_request` — so the question of
 * which one the server would have believed never arises. The query-parameter method of §2.3 is not
 * implemented and is not reached from here: OAuth 2.1 removes it, because a token in a URL reaches
 * access logs, the Referer header and browser history.
 */
function resourceCredential(oidc, headers, body, method: string) {
	const fromBody = formEncodedAccessToken(headers, body, method);

	if (fromBody && headers.authorization) {
		throw new InvalidRequest(
			'access token transmitted by more than one method'
		);
	}

	if (fromBody) {
		/*
		 * RFC 9449 has no body form: a DPoP-bound token is presented with the `DPoP` authentication
		 * scheme, which only exists in the header. Refused rather than ignored, because a proof does
		 * verify against a body-borne token's hash — so ignoring it would accept a sender-constrained
		 * token through a transport no specification binds it to.
		 */
		if (headers.dpop) {
			throw new InvalidRequest(
				'a DPoP-bound access token must be sent in the Authorization header'
			);
		}
		return fromBody;
	}

	if (!headers.authorization) {
		throw new MissingResourceCredential();
	}

	return oidc.getAccessToken({ acceptDPoP: true });
}

async function userInfo({ headers, body, set, request }) {
	const oidc = new OIDCContext({}, headers);
	const { method } = request;

	const accessTokenId = resourceCredential(oidc, headers, body, method);
	/*
	 * No catch to re-status the failure: a DPoP error raised at a resource server answers 401 rather
	 * than the authorization server's 400 (RFC 9449 §7.1), and the error handler makes that correction
	 * from the route it was raised on.
	 */
	const dPoP = await dpopValidate(headers.dpop, {
		accessTokenId,
		method,
		route: routeNames.userinfo
	});
	setNonceHeader(set.headers, dPoP);

	const accessToken = await AccessToken.find(accessTokenId, {
		error: new InvalidToken('access token not found')
	});

	const { scopes } = accessToken;
	if (!scopes.size || !scopes.has('openid')) {
		throw new InsufficientScope('access token missing openid scope', 'openid');
	}

	if (accessToken.payload['x5t#S256']) {
		const cert = oidc.getClientCertificate();
		if (
			!cert ||
			accessToken.payload['x5t#S256'] !== certificateThumbprint(cert)
		) {
			throw new InvalidToken('failed x5t#S256 verification');
		}
	}

	await validateReplay(accessToken.payload.clientId, dPoP);

	if (
		accessToken.payload.jkt &&
		(!dPoP || accessToken.payload.jkt !== dPoP.thumbprint)
	) {
		throw new InvalidToken('failed jkt verification');
	}
	if (accessToken.payload.aud !== undefined) {
		throw new InvalidToken(
			'token audience prevents accessing the userinfo endpoint'
		);
	}

	const client = await Client.find(accessToken.payload.clientId, {
		error: new InvalidToken('associated client not found')
	});

	const account = await findAccount(
		oidc,
		accessToken.payload.accountId,
		accessToken
	);

	if (!account) {
		throw new InvalidToken('associated account not found');
	}

	const grant = await Grant.find(accessToken.payload.grantId, {
		ignoreExpiration: true,
		error: new InvalidToken('grant not found')
	});

	if (grant.isExpired) {
		throw new InvalidToken('grant is expired');
	}

	if (grant.payload.clientId !== accessToken.payload.clientId) {
		throw new InvalidToken('clientId mismatch');
	}

	if (grant.payload.accountId !== accessToken.payload.accountId) {
		throw new InvalidToken('accountId mismatch');
	}

	const claims = filterClaims(accessToken.payload.claims, 'userinfo', grant);
	const rejected = grant.getRejectedOIDCClaims();
	const scope = grant.getOIDCScopeFiltered(
		new Set(accessToken.payload.scope.split(' '))
	);

	if (client.userinfoSignedResponseAlg || client.userinfoEncryptedResponseAlg) {
		const token = new IdToken(
			client,
			await account.claims('userinfo', scope, claims, rejected)
		);

		token.scope = scope;
		token.mask = claims;
		token.rejected = rejected;

		const body = await token.issue('userinfo', {
			expiresAt: accessToken.payload.exp
		});
		return new Response(body, {
			headers: {
				'Content-Type': 'application/jwt; charset=utf-8'
			}
		});
	} else {
		const mask = new Claims(
			client,
			await account.claims('userinfo', scope, claims, rejected)
		);

		mask.scope(scope);
		mask.mask(claims);
		mask.rejected(rejected);

		return await mask.result();
	}
}

const responses = {
	response: {
		200: UserinfoResponse,
		400: OAuthError,
		401: OAuthError,
		403: OAuthError
	}
};

/*
 * Mounted ahead of the guard: a schema refusal happens in the validation stage — after transform,
 * before beforeHandle. Writing the CORS header at transform is what puts it on that refusal and on the
 * 401 DPoP-nonce challenge, which a browser client must be able to read to perform its retry
 * (RFC 9449 §7.1, §8).
 *
 * `authorization` is optional because OIDC Core §5.3.1 admits RFC 6750 §2.2, so a POST may carry the
 * credential in its form body instead. Its absence is therefore not a schema question any more; the
 * handler raises `MissingResourceCredential` when neither method presented one, and the shared error
 * handler answers that with the same challenge the schema refusal used to produce.
 */
export const userinfo = new Elysia()
	.use(corsClientBased(accessTokenClientId))
	.guard({
		schema: 'standalone',
		headers: t.Object({
			authorization: t.Optional(t.String()),
			dpop: t.Optional(t.String())
		})
	})
	.get(routeNames.userinfo, userInfo, responses)
	.post(routeNames.userinfo, userInfo, {
		...responses,
		body: t.Optional(
			t.Object(
				{
					access_token: t.Optional(t.String())
				},
				{ additionalProperties: true }
			)
		)
	});
