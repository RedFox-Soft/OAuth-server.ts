import upperFirst from '../../helpers/_/upper_first.ts';
import camelCase from '../../helpers/_/camel_case.ts';
import * as errors from '../../helpers/errors.ts';
import { interactionPolicy } from '../../addon/index.js';
import nanoid from '../../helpers/nanoid.ts';
import omitBy from '../../helpers/_/omit_by.ts';
import { cookieNames } from 'lib/consts/param_list.js';
import { ttl } from 'lib/configs/liveTime.js';
import { Interaction } from 'lib/models/interaction.js';
import { eventBus } from '../../event_bus.js';

/*
 * The two login-prompt checks that compare a requested authentication context against the one the
 * session carries. Named here rather than imported so this module does not reach into the prompt's
 * internals; the strings are the prompt's `reason` values, which are already public — they reach a
 * relying party in the interaction details.
 */
const ACR_REASONS = new Set(['essential_acr', 'essential_acrs']);
const isAcrReason = (reason: string) => ACR_REASONS.has(reason);

/*
 * The interaction cookie's identity, owned next to the code that writes it.
 *
 * `(name, domain, path)` identifies a cookie, so the path is part of what has to be restated to clear
 * one — and `cookie.remove()` takes its path from the route's cookie schema, which compiles to `/`,
 * never from the cookie being cleared. Every clear therefore addressed a *different* cookie than the
 * one written here, so this cookie was never actually cleared in a browser. Deriving the clearing
 * attributes from the path that sets it is what keeps the two from drifting apart again; see
 * wiki/concepts/cookie-path-scoping.md.
 */
export const interactionCookiePath = (uid: string) => `/ui/${uid}`;

export const expiredInteractionCookie = (uid: string) => ({
	value: '',
	path: interactionCookiePath(uid),
	maxAge: 0,
	expires: new Date(0)
});

export default async function interactions(oidc) {
	const client = oidc.client;
	let failedCheck;
	let prompt;

	const policy = interactionPolicy();

	for (const poly of policy) {
		if (poly.name === 'consent' && client['consent.require'] === false) {
			continue;
		}
		// the interaction-policy check signature is a public extension API: checks read the
		// oidc context off a ctx-shaped argument, so the policy boundary keeps the wrapper shape.
		const result = await poly.executeChecks({ oidc });
		if (result) {
			({ firstError: failedCheck, ...prompt } = result);
			break;
		}
	}

	// no interaction requested
	if (!prompt) {
		// check there's an accountId to continue
		if (!oidc.session.payload.accountId) {
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
			Object.keys(oidc.resourceServers).every(
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

		eventBus.emit('authorization.accepted', oidc);
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

	/*
	 * The end user has authenticated and the requested authentication context still is not met, so
	 * another login page cannot change the outcome — that is the unbounded loop this guard closes.
	 * OIDC Core §5.5.1.1 calls for a failed authentication attempt here, not a further prompt.
	 *
	 * `oidc.result.login` is the discriminator between "has not tried yet", which must be shown a
	 * login page, and "tried, and it is still not enough" — the same state the `max_age` check and
	 * both consent checks already read for this purpose. Scoped to the ACR reasons: every other
	 * prompt can legitimately be satisfied by a further interaction.
	 */
	if (oidc.result?.login && prompt.reasons?.some(isAcrReason)) {
		throw new errors.UnmetAuthenticationRequirements(
			failedCheck?.error_description
		);
	}

	const uid = nanoid();
	const cookieID = nanoid();

	const interactionSession = new Interaction(uid, {
		prompt,
		cookieID,
		lastSubmission: oidc.result,
		accountId: oidc.session.payload.accountId,
		params: omitBy({ ...oidc.params }, (val) => typeof val === 'undefined'),
		trusted: oidc.trusted,
		session: oidc.session,
		grant: oidc.grant,
		cid: oidc.entities.Interaction?.cid || nanoid(),
		deviceCode: oidc.deviceCode?.jti,
		// `jti` is a real getter on BaseModel; `parJti` is not one on Interaction, so the carry-forward
		// has to read the payload. Without it the link to the pushed request is severed at the first
		// hand-off and a flow needing two interactions loses it entirely.
		parJti:
			oidc.entities.PushedAuthorizationRequest?.jti ||
			oidc.entities.Interaction?.payload?.parJti
	});

	await interactionSession.save(ttl.Interaction);
	oidc.entity('Interaction', interactionSession);

	oidc.cookie[cookieNames.interaction].set({
		value: cookieID,
		path: interactionCookiePath(uid),
		// Seconds, not milliseconds: the `* 1000` this carried handed the cookie a ~41-day lifetime for
		// a one-hour interaction (ttl.Interaction is already seconds).
		maxAge: ttl.Interaction
	});

	eventBus.emit('interaction.started', prompt);
	const destination = `/ui/${uid}/${prompt.name}`;
	return destination;
}
