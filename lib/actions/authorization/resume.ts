import nanoid from '../../helpers/nanoid.js';
import epochTime from '../../helpers/epoch_time.js';
import { ISSUER } from 'lib/configs/env.js';
import { logout } from 'lib/html/logout.js';
import { SessionNotFound } from '../../helpers/errors.js';

export default async function resumeAction(ctx, interaction) {
	ctx.oidc.entity('Interaction', interaction);

	const {
		result,
		params: storedParams = {},
		trusted = [],
		session: originSession
	} = interaction.payload;

	const { session } = ctx.oidc;

	if (originSession?.uid && originSession.uid !== session.uid) {
		throw new SessionNotFound(
			'interaction session and authentication session mismatch'
		);
	}

	if (
		result?.login &&
		session.accountId &&
		session.accountId !== result.login.accountId
	) {
		if (interaction.session?.uid) {
			delete interaction.session.uid;
			await interaction.save(interaction.exp - epochTime());
		}

		const secret = nanoid();
		session.state = {
			secret,
			clientId: storedParams.client_id,
			postLogoutRedirectUri: `${ISSUER}/ui/${interaction.uid}/resume`
		};

		return logout(secret);
	}

	await interaction.destroy();

	ctx.oidc.params = storedParams;
	ctx.oidc.trusted = trusted;
	ctx.oidc.redirectUriCheckPerformed = true;

	if (result?.login) {
		const { remember = true, accountId, ts: loginTs, amr, acr } = result.login;

		session.loginAccount({
			accountId,
			loginTs,
			amr,
			acr,
			transient: !remember
		});
	}

	ctx.oidc.result = result;

	if (!session.isNew) {
		session.resetIdentifier();
	}
}
