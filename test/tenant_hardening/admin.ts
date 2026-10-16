import { getGroupStore } from 'lib/adapters/index.ts';
import { emailsTo, extractInvitationToken } from '../mail_capture.ts';
import { call, type Caller } from '../plans/admin.ts';

export {
	call,
	cookieOf,
	createProject,
	idOf,
	superAdmin,
	tenant,
	type Caller
} from '../plans/admin.ts';

/* An address no other case in the run uses. */
export function freshEmail(prefix = 'person'): string {
	return `${prefix}-${Math.random().toString(36).slice(2, 10)}@tenant.test`;
}

export function invite(
	owner: Caller,
	email: string,
	role: 'member' | 'owner' = 'member',
	teamId = owner.teamId
): Promise<{ status: number; body: unknown }> {
	return call('POST', `/admin/api/teams/${teamId}/invitations`, owner.cookie, {
		email,
		role
	});
}

/* The token in the most recent invitation mailed to an address. */
export function invitationTokenFor(email: string): string {
	const mail = emailsTo(email).at(-1);
	const token = mail && extractInvitationToken(mail);
	if (!token) throw new Error(`no invitation mailed to ${email}`);
	return token;
}

export function accept(
	token: string,
	password?: string
): Promise<{ status: number; body: unknown }> {
	return call('POST', '/admin/api/invitations/accept', '', {
		token,
		...(password === undefined ? {} : { password })
	});
}

export async function membersOf(teamId: string): Promise<string[]> {
	const team = await getGroupStore().find(teamId);
	return (team?.members ?? []).map((m) => `${m.userId}:${m.role}`);
}
