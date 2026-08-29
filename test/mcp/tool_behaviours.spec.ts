import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getUserStore,
	getProjectStore,
	adminAuditStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * The named acceptance scenarios of user stories 2, 3 and 4 that the surface-wide guards do not reach:
 * the individual refusals and reports an operator actually meets.
 *
 * One file rather than the eight per-group specs the task list sketched, because each would have carried
 * the same forty lines of harness to assert two or three things. What is grouped here is what these cases
 * have in common — they are all about a *specific* rule the underlying handler owns, reached through the
 * agent surface.
 */

let rpcId = 0;

async function rpc(body: unknown, token: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify(body)
		})
	);
	const text = await res.text();
	const isEvent = (res.headers.get('content-type') ?? '').includes(
		'text/event-stream'
	);
	const line = isEvent
		? text.split('\n').find((l) => l.startsWith('data:'))
		: undefined;
	return isEvent
		? line
			? JSON.parse(line.slice('data:'.length).trim())
			: undefined
		: text
			? JSON.parse(text)
			: undefined;
}

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

async function session() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`beh-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = (await at.save()) as unknown as string;
	await rpc(
		{
			jsonrpc: '2.0',
			id: ++rpcId,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			}
		},
		token
	);
	return { token, user };
}

/* describe-then-confirm, for the high-consequence tools these cases exercise. */
async function perform(
	token: string,
	name: string,
	args: Record<string, unknown>
) {
	const described = await rpc(call(name, args), token);
	const confirmationToken =
		described.result?.structuredContent?.confirmationToken;
	if (typeof confirmationToken !== 'string') return described;
	return rpc(call(name, { ...args, confirmationToken }), token);
}

function result(response: {
	result?: { structuredContent?: { result?: unknown } };
}) {
	return response.result?.structuredContent?.result;
}

describe('individual tool behaviours', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	// US2 AS-3: a change the console would refuse is refused the same way, and changes nothing.
	it('refuses an invalid redirect URI and leaves the client untouched', async () => {
		const { token } = await session();
		const project = await getProjectStore().create({
			name: 'Beh',
			slug: `beh-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const created = await rpc(
			call('client_create', {
				id: project._id,
				clientName: 'Valid',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://ok.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			}),
			token
		);
		const clientId = (result(created) as { clientId: string }).clientId;

		const refused = await rpc(
			call('client_update', {
				id: project._id,
				clientId,
				redirectUris: ['not a uri at all']
			}),
			token
		);
		expect(refused.result?.isError).toBe(true);

		// Untouched, not partially applied.
		const reread = await rpc(
			call('client_get', { id: project._id, clientId }),
			token
		);
		expect((result(reread) as { redirectUris: string[] }).redirectUris).toEqual(
			['https://ok.example.com/cb']
		);
	});

	// US2 AS-4: rotation returns a new secret once, and the rotation is recorded.
	it('rotates a client secret, returning it once and recording the rotation', async () => {
		const { token, user } = await session();
		const project = await getProjectStore().create({
			name: 'Rot',
			slug: `rot-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const created = await rpc(
			call('client_create', {
				id: project._id,
				clientName: 'Confidential',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://ok.example.com/cb'],
				tokenEndpointAuthMethod: 'client_secret_basic'
			}),
			token
		);
		const { clientId, secret } = result(created) as {
			clientId: string;
			secret: string;
		};

		const rotated = await perform(token, 'client_secret_rotate', {
			id: project._id,
			clientId
		});
		const next = (result(rotated) as { secret: string }).secret;

		expect(next).toBeString();
		expect(next).not.toBe(secret);

		const { entries } = await adminAuditStore.list({ actor: user._id });
		expect(entries.some((e) => e.action === 'client.secret.rotate')).toBe(true);
		// The rotation is the recorded fact; the secret itself never enters the trail.
		expect(JSON.stringify(entries)).not.toContain(next);
	});

	/*
	 * US4 AS-6, and the route to it is worth recording.
	 *
	 * `admin_deactivate` (DELETE) refuses self-deactivation *before* it counts super-administrators, and a
	 * caller must be an active super-administrator to get that far — so the count guard is unreachable
	 * through that tool, and is defence in depth behind the self-check. The guard is reached through
	 * `admin_update`, by the last super-administrator deactivating or demoting themselves, which is how
	 * `test/admin/last_super_admin.spec.ts` reaches it too.
	 *
	 * The stores are reset because the count is process-wide and other specs seed super-administrators
	 * into the same memory adapter — without it this asserts nothing.
	 */
	it('refuses to remove the last active super-administrator, both ways', async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
		const { token, user } = await session();

		const deactivated = await rpc(
			call('admin_update', { id: user._id, active: false }),
			token
		);
		expect(deactivated.result?.isError).toBe(true);
		expect(deactivated.result?.structuredContent?.message).toContain(
			'super_admin'
		);

		const demoted = await rpc(
			call('admin_update', { id: user._id, roles: ['project_admin'] }),
			token
		);
		expect(demoted.result?.isError).toBe(true);

		// And the self-check on the deactivate tool, which is what an operator actually meets first.
		const self = await perform(token, 'admin_deactivate', { id: user._id });
		expect(self.result?.isError).toBe(true);
		expect(self.result?.structuredContent?.message).toContain('yourself');
	});

	// US4 AS-5: the last signing key cannot be deleted.
	it('refuses to delete the only signing key', async () => {
		const { token } = await session();

		const listed = await rpc(call('jwks_list', {}), token);
		const keys = (result(listed) as { keys: { kid: string; use?: string }[] })
			.keys;
		const signing = keys.filter((k) => k.use === 'sig' || k.use === undefined);

		// Delete down to one, then assert the last is refused.
		for (const key of signing.slice(1)) {
			await perform(token, 'jwks_delete', { kid: key.kid });
		}

		const refused = await perform(token, 'jwks_delete', {
			kid: signing[0].kid
		});
		expect(refused.result?.isError).toBe(true);
	});

	// US4 AS-3: a configuration the server would refuse at boot is refused here, and nothing changes.
	it('refuses an invalid settings combination before persisting it', async () => {
		const { token } = await session();
		const before = ApplicationConfig['registrationManagement.enabled'];

		// registrationManagement is only valid alongside registration; the boot-time validator says so,
		// and the route runs that same validator over the merged config.
		const refused = await perform(token, 'settings_update', {
			'registration.enabled': false,
			'registrationManagement.enabled': true
		});

		expect(refused.result?.isError).toBe(true);
		// The running instance is untouched: an invalid config must not be half-applied and must not be
		// left to take the server down at the next restart.
		expect(ApplicationConfig['registrationManagement.enabled']).toBe(before);
	});

	// US4 AS-4: a change that only takes effect on restart says so.
	it('reports that a settings change needs a restart', async () => {
		const { token } = await session();

		const applied = await perform(token, 'settings_update', {
			'dpop.requireNonce': true
		});

		expect(applied.result?.isError).not.toBe(true);
		const body = result(applied) as { restartRequired?: boolean };
		expect(body.restartRequired).toBe(true);
	});

	// US3 AS-1 and AS-5: an end-user's lifecycle, and severing an identity without destroying the account.
	it('creates and resets an end-user, and severs an identity without deleting the account', async () => {
		const { token, user } = await session();

		const bucket = await rpc(call('bucket_create', { name: 'Users' }), token);
		const bucketId = (result(bucket) as { _id: string })._id;

		const email = `member-${Math.random()}@x.io`;
		const created = await rpc(
			call('bucket_user_create', {
				id: bucketId,
				email,
				password: 'a sufficiently long password'
			}),
			token
		);
		const uid = (result(created) as { _id: string })._id;

		const reset = await perform(token, 'bucket_user_password_reset', {
			id: bucketId,
			uid,
			password: 'a different sufficiently long password'
		});
		expect(reset.result?.isError).not.toBe(true);

		// Severing an identity the account does not have is a not-found, not a deletion of the account.
		const severed = await perform(token, 'federation_identity_delete', {
			id: bucketId,
			uid,
			providerId: 'never-linked'
		});
		expect(severed.result?.isError).toBe(true);

		const stillThere = await rpc(
			call('bucket_user_list', { id: bucketId }),
			token
		);
		expect(JSON.stringify(stillThere)).toContain(email);

		// The end-user rows carry the bucket as target scope, because a bare user id resolves to nobody.
		const { entries } = await adminAuditStore.list({ actor: user._id });
		const resetEntry = entries.find(
			(e) => e.action === 'enduser.password.reset'
		);
		expect(resetEntry?.targetScope).toBe(bucketId);
	});
});
