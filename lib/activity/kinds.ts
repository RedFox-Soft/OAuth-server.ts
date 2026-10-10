import type { ActivityKind } from '../adapters/types.js';
import type { OIDCContext } from '../helpers/oidc_context.js';
import type { PipelineParams } from '../consts/param_list.js';

type SignIn = 'local' | 'federated';

/*
 * How the authorization being answered signed the person in, if it did — written onto the artifact it
 * produces, because only this request knows.
 *
 * A sign-in leaves `result.login` on the interaction it happened in. When a further interaction follows it
 * — consent, most often, and always for a device approval — the artifact is produced when *that* one
 * resumes, whose result holds only the consent; the sign-in is then the previous interaction's result, which
 * the new one carries as `lastSubmission` (lib/actions/authorization/interactions.ts). A reused session,
 * silent or not, leaves neither.
 *
 * The upstream comes from the session the sign-in wrote. `acr` is not used: an operator can rename its
 * values, and a password sign-in that completes a pending link carries an upstream too
 * (lib/federation/pending_link.ts).
 */
export function signInOf(
	oidc: OIDCContext<PipelineParams>
): SignIn | undefined {
	const login =
		oidc.result?.login ??
		oidc.entities.Interaction?.payload.lastSubmission?.login;
	if (login === undefined) return undefined;
	return oidc.session.payload.upstream === undefined ? 'local' : 'federated';
}

/*
 * The kind of activity a successful grant is. A refresh is a renewal by definition; anything else is the
 * sign-in its artifact recorded, or a renewal when it recorded none — including an artifact written before
 * the field existed, which is the conservative reading.
 */
export function kindOf(
	grantType: string,
	signIn: SignIn | undefined
): ActivityKind {
	if (grantType === 'refresh_token') return 'renewal';
	return signIn ?? 'renewal';
}
