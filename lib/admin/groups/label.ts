import { SYSTEM_GROUP_NAME } from '../consts.js';

/*
 * What a group is called in the console, which is not always what is stored on it.
 *
 * Two kinds do not carry their own display name. A personal group's stored name is its owner's email —
 * deliberately, so it can be told apart from every other personal group — but its own administrator
 * should see the plain word rather than their own address read back to them. And the reserved system
 * group is named from a constant, so a database seeded before the name changed does not show the older
 * one until the next db:setup.
 *
 * Shared by the Groups table, the scope switcher and the usage overview (specs/077), which labels every
 * bucket's customer on the server so the console and an agent read the same words: two sites labelling
 * the same rows differently is how a super administrator ended up with a list of identical "Personal"
 * entries. The server always labels as a third party (`own` absent), never as the group's own member.
 */
export function groupLabel(group: {
	name: string;
	kind: 'personal' | 'regular' | 'system';
	own?: boolean;
}): string {
	if (group.kind === 'system') return SYSTEM_GROUP_NAME;
	if (group.kind !== 'personal') return group.name;
	return group.own ? 'Personal' : `Personal — ${group.name}`;
}
