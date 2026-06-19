import instance from '../../helpers/weak_cache.ts';

/*
 * Loads the End-User's account referenced by the session.
 */
export default async function loadAccount(oidc) {
	const { accountId } = oidc.session.payload;

	if (accountId) {
		const account = await instance(oidc.provider).configuration.findAccount(
			oidc,
			accountId
		);
		oidc.entity('Account', account);
	}
}
