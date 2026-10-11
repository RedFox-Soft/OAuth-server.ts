import { getBucketStore } from '../adapters/index.js';
import { recordBootstrapAudit } from './audit/record.js';
import { ADMIN_BUCKET_ID } from './consts.js';

/*
 * Turns password sign-in to the console back on, from the server (specs/080).
 *
 * The console refuses every change that would leave no super administrator a way in while passwords are off
 * (lib/admin/federation/reachability.ts), but it cannot stop an upstream provider from failing. This is the way
 * back for an operator who holds the server and not the console: `bun run admin:password-sign-in`. Recorded
 * with the bootstrap actor — nobody is signed in — and only when it changed something.
 */
export async function restorePasswordSignIn(): Promise<
	'restored' | 'already_on'
> {
	const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
	if (!bucket)
		throw new Error(
			"the administrators' bucket is missing: run db:setup first"
		);
	if (bucket.passwordLogin) return 'already_on';
	await recordBootstrapAudit('admin.passwordsignin.restore', ADMIN_BUCKET_ID);
	await getBucketStore().update(ADMIN_BUCKET_ID, { passwordLogin: true });
	return 'restored';
}
