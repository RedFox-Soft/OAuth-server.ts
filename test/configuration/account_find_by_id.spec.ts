import { describe, it, expect, beforeEach } from 'bun:test';
import { findAccount } from '../../lib/addon/account.ts';
import {
	getUserStore,
	resetAdminMemoryStores
} from '../../lib/adapters/index.ts';

// findAccount is no longer a provider configuration option — it is the built-in,
// DB-backed resolver imported directly. An unset client resolves to the default
// 'redfox' bucket via resolveBucketForClient.
describe('built-in findAccount (DB-backed)', () => {
	beforeEach(() => {
		resetAdminMemoryStores();
	});

	it('returns a promise', () => {
		expect(findAccount({}, 'id') instanceof Promise).toBe(true);
	});

	it('resolves an active user to an account whose claims come from the record', async () => {
		const user = await getUserStore('redfox').create(
			'jane@example.com',
			'pw',
			[],
			true
		);

		const account = await findAccount({}, user._id);

		expect(account.accountId).toBe(user._id);
		expect(await account.claims()).toEqual({
			sub: user._id,
			email: 'jane@example.com',
			email_verified: true
		});
	});

	it('resolves to nothing when no user record exists for the subject', async () => {
		const account = await findAccount({}, 'does-not-exist');
		expect(account).toBeUndefined();
	});

	it('resolves to nothing when the user record is inactive', async () => {
		const user = await getUserStore('redfox').create(
			'inactive@example.com',
			'pw',
			[],
			true
		);
		await getUserStore('redfox').update(user._id, { active: false });

		const account = await findAccount({}, user._id);
		expect(account).toBeUndefined();
	});
});
