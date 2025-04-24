import instance from '../../helpers/weak_cache.ts';

/*
 * Loads the End-User's account referenced by the session.
 */
export default async function loadAccount(ctx) {
	const { accountId } = ctx.oidc.session;

	if (accountId) {
		const account = await instance(ctx.oidc.provider).configuration.findAccount(
			ctx,
			accountId
		);
		ctx.oidc.entity('Account', account);
	}
}
