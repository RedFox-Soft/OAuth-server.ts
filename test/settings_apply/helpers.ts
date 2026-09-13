import { getUserStore } from 'lib/adapters/index.js';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.js';

import { sessionFor } from '../admin_session.js';
import { send } from '../feature_gate/helpers.js';

/*
 * A signed-in super administrator, because every case in this area changes a setting the way an
 * operator does — through the management API — rather than by assigning to the settings object. The
 * assignment is what the harness does between spec files, and proving it would prove the harness.
 */
export async function superAdminCookie(): Promise<string> {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`super-${Math.random()}@settings-apply.test`,
		'hash',
		['super_admin']
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

export interface SettingsState {
	values: Record<string, unknown>;
	pendingRestartKeys: string[];
	notInForceKeys: string[];
	appliedKeys?: string[];
}

export async function saveSettings(
	cookie: string,
	changes: Record<string, unknown>
): Promise<Response> {
	return send('/admin/api/settings', {
		method: 'PUT',
		headers: { cookie, 'content-type': 'application/json' },
		body: JSON.stringify(changes)
	});
}

export async function readSettings(cookie: string): Promise<SettingsState> {
	const res = await send('/admin/api/settings', {
		method: 'GET',
		headers: { cookie }
	});
	return (await res.json()) as SettingsState;
}

export async function discoveryDocument(): Promise<Record<string, unknown>> {
	const res = await send('/.well-known/openid-configuration', {
		method: 'GET'
	});
	return (await res.json()) as Record<string, unknown>;
}
