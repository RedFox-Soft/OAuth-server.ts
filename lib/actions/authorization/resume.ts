import upperFirst from '../../helpers/_/upper_first.ts';
import camelCase from '../../helpers/_/camel_case.ts';
import nanoid from '../../helpers/nanoid.ts';
import * as errors from '../../helpers/errors.ts';
import { formPost } from '../../html/formPost.js';
import epochTime from '../../helpers/epoch_time.ts';
import { cookieNames } from 'lib/consts/param_list.js';

export default async function resumeAction(ctx, interaction) {
	ctx.oidc.entity('Interaction', interaction);

	const {
		result,
		params: storedParams = {},
		trusted = [],
		session: originSession
	} = interaction;

	const { session } = ctx.oidc;

	if (originSession?.uid && originSession.uid !== session.uid) {
		throw new errors.SessionNotFound(
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

		session.state = {
			secret: nanoid(),
			clientId: storedParams.client_id,
			postLogoutRedirectUri: ctx.oidc.urlFor(ctx.oidc.route, ctx.params)
		};

		formPost(ctx, ctx.oidc.urlFor('end_session_confirm'), {
			xsrf: session.state.secret,
			logout: 'yes'
		});

		return;
	}

	await interaction.destroy();

	ctx.oidc.params = storedParams;
	ctx.oidc.trusted = trusted;
	ctx.oidc.redirectUriCheckPerformed = true;

	if (result?.error) {
		const className = upperFirst(camelCase(result.error));
		if (errors[className]) {
			throw new errors[className](result.error_description);
		}
		throw new errors.CustomOIDCProviderError(
			result.error,
			result.error_description
		);
	}

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

	if (!session.new) {
		session.resetIdentifier();
	}
}
