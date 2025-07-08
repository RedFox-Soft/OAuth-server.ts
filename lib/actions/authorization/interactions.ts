import upperFirst from '../../helpers/_/upper_first.ts';
import camelCase from '../../helpers/_/camel_case.ts';
import * as errors from '../../helpers/errors.ts';
import instance from '../../helpers/weak_cache.ts';
import nanoid from '../../helpers/nanoid.ts';
import omitBy from '../../helpers/_/omit_by.ts';
import { cookieNames } from 'lib/consts/param_list.js';
import { ttl } from 'lib/configs/liveTime.js';

export default async function interactions(resumeRouteName, ctx) {
	const { oidc } = ctx;
	let failedCheck;
	let prompt;

	const { policy } = instance(oidc.provider).configuration.interactions;

	for (const poly of policy) {
		const result = await poly.executeChecks(ctx);
		if (result) {
			({ firstError: failedCheck, ...prompt } = result);
			break;
		}
	}

	// no interaction requested
	if (!prompt) {
		// check there's an accountId to continue
		if (!oidc.session.accountId) {
			throw new errors.AccessDenied(
				undefined,
				'authorization request resolved without requesting interactions but no account id was resolved'
			);
		}

		// check there's something granted to continue
		// if only claims parameter is used then it must be combined with openid scope anyway
		// when no scope parameter was provided and none is injected by the AS policy access is
		// denied rather then issuing a code/token without scopes
		if (
			!oidc.grant.getOIDCScopeFiltered(oidc.requestParamOIDCScopes) &&
			Object.keys(ctx.oidc.resourceServers).every(
				(resource) =>
					!oidc.grant.getResourceScopeFiltered(
						resource,
						oidc.requestParamScopes
					)
			) &&
			!oidc.params.authorization_details
		) {
			throw new errors.AccessDenied(
				undefined,
				'authorization request resolved without requesting interactions but no scope was granted'
			);
		}

		oidc.provider.emit('authorization.accepted', ctx);
		return;
	}

	// if interaction needed but prompt=none => throw;
	if (oidc.promptPending('none')) {
		const className = upperFirst(camelCase(failedCheck.error));
		if (errors[className]) {
			throw new errors[className](failedCheck.error_description);
		}
		throw new errors.CustomOIDCProviderError(
			failedCheck.error,
			failedCheck.error_description
		);
	}

	const uid = nanoid();
	const cookieID = nanoid();

	const returnTo = oidc.urlFor(resumeRouteName, { uid });
	const interactionSession = new oidc.provider.Interaction(uid, {
		returnTo,
		prompt,
		cookieID,
		lastSubmission: oidc.result,
		accountId: oidc.session.accountId,
		params: omitBy({ ...oidc.params }, (val) => typeof val === 'undefined'),
		trusted: oidc.trusted,
		session: oidc.session,
		grant: oidc.grant,
		cid: oidc.entities.Interaction?.cid || nanoid(),
		deviceCode: oidc.deviceCode?.jti,
		parJti:
			oidc.entities.PushedAuthorizationRequest?.jti ||
			oidc.entities.Interaction?.parJti
	});

	await interactionSession.save(ttl.Interaction);
	ctx.oidc.entity('Interaction', interactionSession);

	ctx.cookie[cookieNames.interaction].set({
		value: cookieID,
		path: `/ui/${uid}`,
		maxAge: ttl.Interaction * 1000
	});

	oidc.provider.emit('interaction.started', prompt);
	const destination = `/ui/${uid}/${prompt.name}`;
	return destination;
}
