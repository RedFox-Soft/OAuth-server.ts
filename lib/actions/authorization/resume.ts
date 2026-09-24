import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import type { Interaction } from 'lib/models/interaction.js';
import nanoid from '../../helpers/nanoid.js';
import { ISSUER } from 'lib/configs/env.js';
import { logout } from 'lib/html/logout.js';
import { SessionNotFound } from '../../helpers/errors.js';
import { resolveBucketForRequest } from '../../admin/auth/resolveBucket.js';

export default async function resumeAction(
	oidc: OIDCContext<PipelineParams>,
	interaction: Interaction
) {
	oidc.entity('Interaction', interaction);

	const {
		result,
		params: storedParams = {},
		trusted = [],
		session: originSession
	} = interaction.payload;

	const { session } = oidc;

	if (originSession?.uid && originSession.uid !== session.payload.uid) {
		throw new SessionNotFound(
			'interaction session and authentication session mismatch'
		);
	}

	/*
	 * Which population this sign-in is for. Derived here rather than carried on the login result
	 * because four handlers write that result — password, second factor, federated, and the recovery
	 * path — and threading one value through four writers is four chances for them to disagree about
	 * one bucket. The stored parameters say everything `resolveBucketForRequest` needs, and they are
	 * the same parameters the sign-in screen resolved its own bucket from.
	 */
	const bucketId = await resolveBucketForRequest(
		storedParams.client_id,
		storedParams.resource
	);

	/*
	 * An account change, and only an account change.
	 *
	 * Two different people of the *same* bucket is one replacing the other, and the end user is asked
	 * before their sign-in is taken over. Two people of *different* buckets is not that at all: an
	 * account identifier is only meaningful inside the bucket that issued it, so identifiers from two
	 * buckets are always unequal and say nothing about who is signing in. Comparing them alone turned
	 * reaching a second product into "you are already signed in as somebody else" — a sign-out demand
	 * in the middle of a sign-in, whose only working answer ended every session the browser held.
	 *
	 * The bucket is therefore compared first. A session carrying an account but no bucket predates
	 * this field; it is not attributed to a bucket, so it fails the comparison and is replaced rather
	 * than treated as a conflicting identity.
	 */
	if (
		result?.login &&
		session.payload.accountId &&
		session.payload.bucketId === bucketId &&
		session.payload.accountId !== result.login.accountId
	) {
		if (interaction.payload.session?.uid) {
			delete interaction.payload.session.uid;
			await interaction.persist();
		}

		const secret = nanoid();
		// On the payload: only payload keys are stored, and the sign-out confirmation reads it from there.
		session.payload.state = {
			secret,
			clientId: storedParams.client_id,
			postLogoutRedirectUri: `${ISSUER}/ui/${interaction.uid}/resume`
		};

		return logout(secret);
	}

	await interaction.destroy();

	oidc.params = storedParams;
	oidc.trusted = trusted;
	oidc.redirectUriCheckPerformed = true;

	if (result?.login) {
		const { transient, accountId, ts: loginTs, amr, acr } = result.login;

		session.loginAccount({
			accountId,
			bucketId,
			loginTs,
			amr,
			acr,
			transient
		});
	}

	oidc.result = result;

	if (!session.isNew) {
		session.resetIdentifier();
	}
}
