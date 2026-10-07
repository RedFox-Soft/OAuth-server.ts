import { describe, it, beforeAll, expect } from 'bun:test';

import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import bootstrap from '../test_helper.js';
import { groupIdFor, sessionFor } from '../admin_session.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	connect,
	patchOf,
	provider,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';
import { createAdministrator } from '../administrators.ts';

interface Entry {
	actorId: string;
	action: string;
	targetId: string;
	attributes?: string[];
	viaSurface?: string | null;
}

/**
 * @proves The administrators of a bucket can see every change a provisioning connection made to its users —
 * who, what, which attributes by name — and nothing for a request that was refused or changed nothing
 * (spec 070, User Story 6, scenarios 1–4; FR-040; IPSIE AL SCIM §8).
 */
describe('the audit trail of SCIM changes', () => {
	let c: Connected;
	let cookie: string;

	async function scimEntries(): Promise<Entry[]> {
		const res = await admin(
			'GET',
			'/admin/api/audit?viaSurface=scim&pageSize=100',
			cookie
		);
		expect(res.status).toBe(200);
		return res.json.entries as Entry[];
	}

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		/* An administrator of the bucket's group, not a super administrator: what they see is scoped. */
		const user = await createAdministrator(
			'plain',
			`owner-${Math.random()}@x.io`
		);
		const session = await sessionFor(user);
		cookie = `${ADMIN_SESSION_COOKIE}=${session._id}`;
		c = await connect(
			await scimBucket([provider('corp')], {
				ownerGroupId: await groupIdFor(user)
			})
		);
	});

	it('records a SCIM change under the connection, naming attributes and never their values', async () => {
		const created = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('yara@contoso.com', { displayName: 'Yara Secret-Name' })
		});

		const entry = (await scimEntries()).find(
			(e) => e.targetId === created.json.id
		);

		expect(entry).toMatchObject({
			actorId: `connection:${c.connection._id}`,
			action: 'enduser.create',
			viaSurface: 'scim'
		});
		expect(entry?.attributes).toContain('displayName');
		expect(JSON.stringify(entry)).not.toContain('Yara Secret-Name');
		expect(JSON.stringify(entry)).not.toContain('yara@contoso.com');
	});

	it('records nothing for a refused request or a patch that changes nothing', async () => {
		const created = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('zed@contoso.com', { displayName: 'Zed' })
		});
		const before = (await scimEntries()).length;

		const refused = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('ZED@contoso.com')
		});
		const unchanged = await scim(
			'PATCH',
			`${c.base}/Users/${created.json.id}`,
			{
				token: c.token,
				body: patchOf([{ op: 'replace', path: 'displayName', value: 'Zed' }])
			}
		);

		expect(refused.status).toBe(409);
		expect(unchanged.status).toBe(200);
		expect((await scimEntries()).length).toBe(before);
	});

	it('shows only connection entries when filtered to the SCIM surface', async () => {
		await admin(
			'PATCH',
			`/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`,
			cookie,
			{ displayName: 'Renamed by a person' }
		);

		const entries = await scimEntries();

		expect(entries.length).toBeGreaterThan(0);
		for (const entry of entries) {
			expect(entry.viaSurface).toBe('scim');
			expect(entry.actorId).toStartWith('connection:');
		}
	});
});
