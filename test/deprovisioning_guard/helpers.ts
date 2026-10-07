import { expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { getUserStore } from 'lib/adapters/index.js';
import type { User } from 'lib/adapters/types.js';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { groupIdFor, sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { admin, type Reply } from '../provisioning/helpers.ts';
import {
	connect,
	patchOf,
	provider,
	scim,
	scimBucket,
	scimUser,
	type Connected,
	type ScimResponse
} from '../scim/helpers.ts';
import { present, shaped } from '../shape.ts';

export { patchOf, scim, scimUser };

/*
 * A bucket owned by one administrator's group, a SCIM connection on it, and that administrator's console
 * cookie — so the threshold, the release and the hold are reached the way the bucket's administrator reaches
 * them, over the real admin API.
 */

export interface Threshold {
	count: number;
	windowSeconds: number;
}

export interface Guarded extends Connected {
	cookie: string;
	owner: User;
}

export const HOUR = 3600;

export async function plainAdministrator(): Promise<{
	user: User;
	cookie: string;
}> {
	const user = await createAdministrator(
		'plain',
		`owner-${Math.random().toString(36).slice(2)}@x.io`
	);
	const session = await sessionFor(user);
	return { user, cookie: `${ADMIN_SESSION_COOKIE}=${session._id}` };
}

/* A guarded connection — or, with no threshold, one with the guard left off (the default). */
export async function guarded(threshold?: Threshold): Promise<Guarded> {
	const { user, cookie } = await plainAdministrator();
	const c = await connect(
		await scimBucket([provider('corp')], {
			ownerGroupId: await groupIdFor(user)
		})
	);
	const g = { ...c, cookie, owner: user };
	if (threshold) {
		const res = await setThreshold(g, threshold);
		expect(res.status).toBe(200);
	}
	return g;
}

export function connectionPath(g: Guarded): string {
	return `/admin/api/buckets/${g.bucket._id}/provisioning-connections/${g.connection._id}`;
}

export function setThreshold(
	g: Guarded,
	threshold: Threshold | null
): Promise<Reply> {
	return admin('PATCH', connectionPath(g), g.cookie, { threshold });
}

export function release(g: Guarded, cookie = g.cookie): Promise<Reply> {
	return admin('POST', `${connectionPath(g)}/release`, cookie);
}

const HoldView = Type.Object({
	hold: Type.Optional(
		Type.Object({ since: Type.String(), count: Type.Number() })
	),
	threshold: Type.Optional(
		Type.Object({ count: Type.Number(), windowSeconds: Type.Number() })
	)
});

/* The connection as its administrator sees it in the console. */
export async function viewOf(g: Guarded) {
	const res = await admin('GET', connectionPath(g), g.cookie);
	expect(res.status).toBe(200);
	return shaped(HoldView, res.json);
}

/* `n` active users provisioned by the connection; answers their ids. */
export async function provision(g: Guarded, n: number): Promise<string[]> {
	const ids: string[] = [];
	for (let i = 0; i < n; i += 1) {
		const res = await scim('POST', `${g.base}/Users`, {
			token: g.token,
			body: scimUser(`u${i}-${Math.random().toString(36).slice(2)}@contoso.com`)
		});
		expect(res.status).toBe(201);
		ids.push(shaped(Type.Object({ id: Type.String() }), res.json).id);
	}
	return ids;
}

/* The deactivation Okta and Entra both send: a PATCH replacing `active`. */
export function deactivate(g: Guarded, id: string): Promise<ScimResponse> {
	return scim('PATCH', `${g.base}/Users/${id}`, {
		token: g.token,
		body: patchOf([{ op: 'replace', path: 'active', value: false }])
	});
}

/* Deactivates each user in turn, failing unless every one is accepted. */
export async function deactivateAll(g: Guarded, ids: string[]): Promise<void> {
	for (const id of ids) {
		expect((await deactivate(g, id)).status).toBe(200);
	}
}

/* Deprovisions `threshold.count` users and has the next one refused, leaving the connection held. */
export async function tripped(threshold: Threshold): Promise<Guarded> {
	const g = await guarded(threshold);
	const ids = await provision(g, threshold.count + 1);
	await deactivateAll(g, ids.slice(0, threshold.count));
	const refused = present(
		ids[threshold.count],
		'the user beyond the threshold'
	);
	expect((await deactivate(g, refused)).status).toBe(429);
	return g;
}

export async function storedUser(g: Guarded, id: string): Promise<User | null> {
	return getUserStore(g.bucket._id).find(id);
}
