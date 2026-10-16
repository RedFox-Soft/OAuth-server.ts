import type { UserBucketStoreInstance } from '../lib/adapters/types.js';
import { ADMIN_BUCKET_ID } from '../lib/admin/consts.js';

/*
 * Administrators' sign-up against a real datastore (specs/103): the migration closes sign-up on the administrators'
 * bucket where it is open without email verification, leaves it open where verification is required, and changes
 * nothing the second time. The bucket is put back as it was found. Shared by verify_mongodb.ts and
 * verify_postgres.ts.
 */

type Check = (name: string, ok: boolean, detail?: string) => void;

export interface AdminSignUpHooks {
	buckets: UserBucketStoreInstance;
	/* One application of the migration's half for this backend; answers its report lines. */
	apply(): Promise<unknown>;
}

export async function verifyAdminSignUp(
	hooks: AdminSignUpHooks,
	check: Check
): Promise<void> {
	const found = await hooks.buckets.find(ADMIN_BUCKET_ID);
	if (!found) {
		check("the administrators' bucket is provisioned", false);
		return;
	}
	const original = {
		registrationOpen: found.registrationOpen,
		emailVerificationRequired: found.emailVerificationRequired
	};

	try {
		await hooks.buckets.update(ADMIN_BUCKET_ID, {
			registrationOpen: true,
			emailVerificationRequired: false
		});
		const first = await hooks.apply();
		const closed = await hooks.buckets.find(ADMIN_BUCKET_ID);
		check(
			'the admin sign-up migration closes sign-up open without verification, and says so',
			closed?.registrationOpen === false &&
				JSON.stringify(first) ===
					JSON.stringify([
						"administrators' sign-up closed (it was open without email verification): 1"
					]),
			JSON.stringify([closed?.registrationOpen, first])
		);

		const second = await hooks.apply();
		check(
			'a second application of the admin sign-up migration changes nothing',
			JSON.stringify(second) ===
				JSON.stringify([
					"administrators' sign-up closed (it was open without email verification): 0"
				]),
			JSON.stringify(second)
		);

		await hooks.buckets.update(ADMIN_BUCKET_ID, {
			registrationOpen: true,
			emailVerificationRequired: true
		});
		await hooks.apply();
		const kept = await hooks.buckets.find(ADMIN_BUCKET_ID);
		check(
			'the admin sign-up migration leaves sign-up open where verification is required',
			kept?.registrationOpen === true,
			JSON.stringify(kept?.registrationOpen)
		);
	} finally {
		await hooks.buckets.update(ADMIN_BUCKET_ID, original);
	}
}
