import { Elysia, t } from 'elysia';
import certificateThumbprint from '../helpers/certificate_thumbprint.ts';
import instance from '../helpers/weak_cache.ts';
import filterClaims from '../helpers/filter_claims.ts';
import dpopValidate, { DPOP_OK_WINDOW } from '../helpers/validate_dpop.ts';
import epochTime from '../helpers/epoch_time.ts';
import { InvalidToken, InsufficientScope } from '../helpers/errors.ts';
import { routeNames } from 'lib/consts/param_list.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Claims } from 'lib/helpers/claims.js';
import { IdToken } from 'lib/models/id_token.js';
import { ReplayDetection } from 'lib/models/replay_detection.js';
import { Client } from 'lib/models/client.js';
import { provider } from 'lib/provider.js';

export const userinfo = new Elysia()
	.guard({
		schema: 'standalone',
		headers: t.Object({
			authorization: t.String({
				error: 'no access token provided'
			}),
			dpop: t.Optional(t.String())
		})
	})
	.get(routeNames.userinfo, async ({ headers }) => {
		const ctx = {
			headers
		};
		ctx.oidc = new OIDCContext(ctx);

		const accessTokenId = ctx.oidc.getAccessToken({
			acceptDPoP: true
		});
		const dPoP = await dpopValidate(ctx, {
			accessTokenId,
			method: 'GET',
			route: routeNames.userinfo
		});

		const accessToken = await provider.AccessToken.find(accessTokenId);
		if (!accessToken) {
			throw new InvalidToken('access token not found');
		}

		const { scopes } = accessToken;
		if (!scopes.size || !scopes.has('openid')) {
			throw new InsufficientScope(
				'access token missing openid scope',
				'openid'
			);
		}

		if (accessToken['x5t#S256']) {
			const { getCertificate } = instance(provider).features.mTLS;
			const cert = getCertificate(ctx);
			if (!cert || accessToken['x5t#S256'] !== certificateThumbprint(cert)) {
				throw new InvalidToken('failed x5t#S256 verification');
			}
		}

		if (dPoP) {
			const { allowReplay } = instance(provider).features.dPoP;

			if (!allowReplay) {
				const unique = await ReplayDetection.unique(
					accessToken.clientId,
					dPoP.jti,
					epochTime() + DPOP_OK_WINDOW
				);

				ctx.assert(unique, new InvalidToken('DPoP proof JWT Replay detected'));
			}
		}

		if (accessToken.jkt && (!dPoP || accessToken.jkt !== dPoP.thumbprint)) {
			throw new InvalidToken('failed jkt verification');
		}
		if (accessToken.aud !== undefined) {
			throw new InvalidToken(
				'token audience prevents accessing the userinfo endpoint'
			);
		}

		const client = await Client.find(accessToken.clientId);
		if (!client) {
			new InvalidToken('associated client not found');
		}

		const account = await instance(provider).configuration.findAccount(
			ctx,
			accessToken.accountId,
			accessToken
		);

		if (!account) {
			throw new InvalidToken('associated account not found');
		}

		const grant = await provider.Grant.find(accessToken.grantId, {
			ignoreExpiration: true
		});

		if (!grant) {
			throw new InvalidToken('grant not found');
		}

		if (grant.isExpired) {
			throw new InvalidToken('grant is expired');
		}

		if (grant.clientId !== accessToken.clientId) {
			throw new InvalidToken('clientId mismatch');
		}

		if (grant.accountId !== accessToken.accountId) {
			throw new InvalidToken('accountId mismatch');
		}

		const claims = filterClaims(accessToken.claims, 'userinfo', grant);
		const rejected = grant.getRejectedOIDCClaims();
		const scope = grant.getOIDCScopeFiltered(
			new Set(accessToken.scope.split(' '))
		);

		if (
			client.userinfoSignedResponseAlg ||
			client.userinfoEncryptedResponseAlg
		) {
			const token = new IdToken(
				client,
				await account.claims('userinfo', scope, claims, rejected)
			);

			token.scope = scope;
			token.mask = claims;
			token.rejected = rejected;

			const body = await token.issue({
				expiresAt: accessToken.exp,
				use: 'userinfo'
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
	});
