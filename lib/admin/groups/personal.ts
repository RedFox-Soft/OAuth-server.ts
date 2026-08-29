import { getGroupStore } from '../../adapters/index.js';
import type { Group } from '../../adapters/types.js';

/*
 * The group created with an administrator's account, which the console presents as "Personal".
 *
 * Every administrator has exactly one, and it is what makes ownership a single mechanism: work that
 * belongs to nobody else is still owned by a group, so sharing it later is adding a member rather than
 * moving anything between two different kinds of owner.
 *
 * Idempotent, and that is load-bearing rather than defensive. Four call sites reach it — admin account
 * creation, the test seed, the deployment seed, and invitation acceptance — and the two seeds run
 * against a database that may already hold the account. Creating a second personal group for one
 * administrator would give them two "Personal" scopes and make `findPersonalFor` arbitrary.
 */
export async function ensurePersonalGroup(
	userId: string,
	email: string
): Promise<Group> {
	const store = getGroupStore();
	const existing = await store.findPersonalFor(userId);
	if (existing) return existing;
	return store.create({
		/*
		 * Named for the account so a super administrator reading the group list can tell whose it is.
		 * The console shows its owner "Personal" instead, so this name is for everyone *else*.
		 */
		name: email,
		kind: 'personal',
		members: [{ userId, role: 'owner' }]
	});
}
