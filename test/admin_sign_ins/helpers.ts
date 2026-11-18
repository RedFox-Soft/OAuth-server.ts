import { Type, type Static } from '@sinclair/typebox';

import { admin, type Reply } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import type { AdminKind } from '../administrators.ts';
import { grantSuperAdmin } from 'lib/admin/super_admins.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { PageView, PASSWORD } from '../person_activity/helpers.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';

/*
 * Administrators' sign-ins (specs/137) as a super administrator and an administrator meet them: an administrator
 * signs in to the console through the real screens, and the reading goes through the real admin routes after the
 * write the server makes once a minute.
 */

export const CONSOLE = 'admin-panel';
export const WIKI = 'admin-wiki';

let hash: string | undefined;

/* An administrator who can type a password at the console's sign-in, with a console cookie of their own. */
export async function administrator(
	kind: AdminKind = 'plain'
): Promise<{ user: User; email: string; cookie: string }> {
	await ensureAdminSeed();
	hash ??= await Bun.password.hash(PASSWORD);
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${kind}-${Math.random().toString(36).slice(2)}@acme.test`,
		hash,
		true
	);
	if (kind === 'super') await grantSuperAdmin(user._id);
	return { user, email: user.email, cookie: await cookieFor(user) };
}

export function signInsPath(adminId: string): string {
	return `/admin/api/admins/${encodeURIComponent(adminId)}/activity`;
}

export async function readSignIns(
	cookie: string,
	adminId: string,
	body: Record<string, unknown> = {}
): Promise<Reply> {
	await flushPersonActivityNow();
	return admin('POST', signInsPath(adminId), cookie, body);
}

/* What a super administrator reads once the server has written what it held. */
export async function signInsOf(
	cookie: string,
	adminId: string,
	body: Record<string, unknown> = {}
): Promise<PageView> {
	const reply = await readSignIns(cookie, adminId, body);
	if (reply.status !== 200) {
		throw new Error(
			`reading the sign-ins answered ${String(reply.status)}: ${JSON.stringify(reply.body)}`
		);
	}
	return shaped(PageView, reply.body);
}

export const OwnRow = Type.Object({
	at: Type.String(),
	outcome: Type.String(),
	place: Type.String(),
	method: Type.Union([Type.String(), Type.Null()]),
	reason: Type.Union([Type.String(), Type.Null()]),
	device: Type.Union([Type.String(), Type.Null()]),
	country: Type.Union([Type.String(), Type.Null()])
});

export const OwnView = Type.Union([
	Type.Object({ state: Type.Literal('off') }),
	Type.Object({ state: Type.Literal('empty'), since: Type.String() }),
	Type.Object({ state: Type.Literal('list'), rows: Type.Array(OwnRow) })
]);
export type OwnView = Static<typeof OwnView>;

export async function ownSignIns(cookie: string): Promise<Reply> {
	await flushPersonActivityNow();
	return admin('GET', '/admin/api/me/sign-ins', cookie);
}
