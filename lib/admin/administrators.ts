import type { User } from '../adapters/types.js';
import { recordBootstrapAudit } from './audit/record.js';
import { ensurePersonalGroup } from './groups/personal.js';

/*
 * What creating an administrator account also does when nobody signed in did it: a person registered at
 * the console's own sign-in page.
 *
 * Every path that creates an administrator pairs the account with its personal group — a super
 * administrator's create, first-run setup, accepting an invitation — because the group is the scope the
 * console opens in, and without it a new administrator signs in pointed at nothing. Registration is the
 * fourth path and the first with no actor at all, so it is recorded with the bootstrap actor, as first-run
 * setup and an accepted invitation are: the trail must show that an account able to sign in to the
 * console came into existence, and who could be named for it.
 *
 * Recorded after the account and its group exist, not before as an admin route records: this is not an
 * authorized operator's intention that a late failure could leave unapplied, it is an event the public
 * door already caused, and naming the new personal group puts the entry in that administrator's own trail.
 */
export async function registeredAdministrator(
	user: Pick<User, '_id' | 'email'>
): Promise<void> {
	const group = await ensurePersonalGroup(user._id, user.email);
	await recordBootstrapAudit('admin.register', user._id, {
		ownerGroupId: group._id
	});
}
