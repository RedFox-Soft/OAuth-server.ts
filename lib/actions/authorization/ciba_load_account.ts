import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import { InvalidRequest, UnknownUserId } from '../../helpers/errors.ts';
import { findAccount } from '../../addon/account.js';
import {
	processLoginHintToken,
	processLoginHint,
	verifyUserCode
} from '../../addon/index.js';

import checkIdTokenHint from './check_id_token_hint.ts';

export default async function cibaLoadAccount(
	oidc: OIDCContext<PipelineParams>
) {
	const mechanisms = Object.entries({
		login_hint_token: oidc.params.login_hint_token,
		id_token_hint: oidc.params.id_token_hint,
		login_hint: oidc.params.login_hint
	}).filter(
		(entry): entry is [string, string] =>
			typeof entry[1] === 'string' && entry[1] !== ''
	);
	const { length } = mechanisms;

	if (!length) {
		throw new InvalidRequest(
			'missing one of required parameters login_hint_token, id_token_hint, or login_hint'
		);
	} else if (length !== 1) {
		throw new InvalidRequest(
			'only one of required parameters login_hint_token, id_token_hint, or login_hint must be provided'
		);
	}

	const [[mechanism, value]] = mechanisms;
	let accountId;

	switch (mechanism) {
		case 'id_token_hint':
			await checkIdTokenHint(oidc);
			({
				payload: { sub: accountId }
			} = oidc.require('IdTokenHint'));
			break;
		case 'login_hint_token':
			accountId = await processLoginHintToken(oidc, value);
			break;
		case 'login_hint':
			accountId = await processLoginHint(oidc, value);
			break;
	}

	if (!accountId) {
		throw new UnknownUserId('could not identify end-user');
	}
	const account = await findAccount(oidc, accountId);
	if (!account) {
		throw new UnknownUserId('could not identify end-user');
	}
	oidc.entity('Account', account);

	await verifyUserCode(oidc, account, value);
}
