import { Type, type Static } from '@sinclair/typebox';

import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.js';

import { sessionFor } from '../admin_session.js';
import { send } from '../feature_gate/helpers.js';
import { shaped } from '../shape.js';
import { createAdministrator } from '../administrators.ts';

/*
 * A signed-in super administrator, because every case in this area changes a setting the way an
 * operator does — through the management API — rather than by assigning to the settings object. The
 * assignment is what the harness does between spec files, and proving it would prove the harness.
 */
export async function superAdminCookie(): Promise<string> {
	const user = await createAdministrator(
		'super',
		`super-${Math.random()}@settings-apply.test`
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

const SettingsState = Type.Object({
	values: Type.Record(Type.String(), Type.Unknown()),
	pendingRestartKeys: Type.Array(Type.String()),
	notInForceKeys: Type.Array(Type.String())
});

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

export async function readSettings(
	cookie: string
): Promise<Static<typeof SettingsState>> {
	const res = await send('/admin/api/settings', {
		method: 'GET',
		headers: { cookie }
	});
	return shaped(SettingsState, await res.json());
}

export async function discoveryDocument(): Promise<Record<string, unknown>> {
	const res = await send('/.well-known/openid-configuration', {
		method: 'GET'
	});
	return shaped(Type.Record(Type.String(), Type.Unknown()), await res.json());
}
