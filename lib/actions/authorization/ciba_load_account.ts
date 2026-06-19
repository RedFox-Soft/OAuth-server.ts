import { InvalidRequest, UnknownUserId } from '../../helpers/errors.ts';
import omitBy from '../../helpers/_/omit_by.ts';
import instance from '../../helpers/weak_cache.ts';

import checkIdTokenHint from './check_id_token_hint.ts';

export default async function cibaLoadAccount(oidc, next) {
	const mechanisms = omitBy(
		{
			login_hint_token: oidc.params.login_hint_token,
			id_token_hint: oidc.params.id_token_hint,
			login_hint: oidc.params.login_hint
		},
		(value) => typeof value !== 'string' || !value
	);

	let mechanism;
	let length;
	let value;

	try {
		({
			0: [mechanism, value],
			length
		} = Object.entries(mechanisms));
	} catch (err) {}

	if (!length) {
		throw new InvalidRequest(
			'missing one of required parameters login_hint_token, id_token_hint, or login_hint'
		);
	} else if (length !== 1) {
		throw new InvalidRequest(
			'only one of required parameters login_hint_token, id_token_hint, or login_hint must be provided'
		);
	}

	const { findAccount, features } = instance(oidc.provider).configuration;
	const { ciba } = features;

	let accountId;

	switch (mechanism) {
		case 'id_token_hint':
			await checkIdTokenHint(oidc);
			({
				payload: { sub: accountId }
			} = oidc.entities.IdTokenHint);
			break;
		case 'login_hint_token':
			accountId = await ciba.processLoginHintToken({ oidc }, value);
			break;
		case 'login_hint':
			accountId = await ciba.processLoginHint({ oidc }, value);
			break;
	}

	if (!accountId) {
		throw new UnknownUserId('could not identify end-user');
	}
	const account = await findAccount({ oidc }, accountId);
	if (!account) {
		throw new UnknownUserId('could not identify end-user');
	}
	oidc.entity('Account', account);

	await ciba.verifyUserCode({ oidc }, account, value);

	return next();
}
