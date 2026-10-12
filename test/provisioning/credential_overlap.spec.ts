import crypto from 'node:crypto';
import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	setSystemTime
} from 'bun:test';
import { Type } from '@sinclair/typebox';
import { exportJWK, generateKeyPair } from 'jose';

import { adminAuditStore } from 'lib/adapters/index.js';
import { TestAdapter } from 'test/models.js';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { shaped } from '../shape.ts';
import {
	connect,
	scim,
	scimBucket,
	type Connected,
	slugOf
} from '../scim/helpers.ts';
import { admin, basic, token } from './helpers.ts';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

const PreviousView = Type.Object({
	issuedAt: Type.String(),
	replacedAt: Type.String(),
	endsAt: Type.String(),
	lastUsedAt: Type.Union([Type.String(), Type.Null()]),
	stillUsedByDirectory: Type.Boolean()
});
const ConnectionRead = Type.Object({
	oauthCredential: Type.Union([
		Type.Object({
			kind: Type.String(),
			firstUsedAt: Type.Optional(Type.Union([Type.String(), Type.Null()])),
			previous: Type.Optional(PreviousView)
		}),
		Type.Null()
	]),
	staticToken: Type.Union([
		Type.Object({ previous: Type.Optional(PreviousView) }),
		Type.Null()
	]),
	warnings: Type.Array(Type.String())
});
const Issued = Type.Object({
	connection: ConnectionRead,
	secret: Type.Optional(Type.String()),
	token: Type.Optional(Type.String()),
	previousEndsAt: Type.Union([Type.String(), Type.Null()])
});

function connectionPath(c: Connected): string {
	return `/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`;
}

const clientIdOf = (c: Connected) => `scim-${c.connection._id}`;

async function issue(
	c: Connected,
	cookie: string,
	body: Record<string, unknown>
) {
	const reply = await admin(
		'POST',
		`${connectionPath(c)}/credentials`,
		cookie,
		body
	);
	expect(reply.status).toBe(201);
	return shaped(Issued, reply.body);
}

async function secretOf(
	c: Connected,
	cookie: string,
	body: Record<string, unknown> = {}
): Promise<string> {
	const issued = await issue(c, cookie, { kind: 'secret', ...body });
	if (!issued.secret) throw new Error('no secret was returned');
	return issued.secret;
}

/* A token request with a secret: the access token, or the error the endpoint answered. */
async function mint(c: Connected, secret: string) {
	const reply = await token(
		`/${slugOf(c.bucket)}/token`,
		{ grant_type: 'client_credentials' },
		basic(clientIdOf(c), secret)
	);
	return {
		access:
			typeof reply.json.access_token === 'string'
				? reply.json.access_token
				: '',
		error: reply.json.error
	};
}

async function scimStatus(c: Connected, bearer: string): Promise<number> {
	return (await scim('GET', `${c.base}/Users`, { token: bearer })).status;
}

async function read(c: Connected, cookie: string) {
	const reply = await admin('GET', connectionPath(c), cookie);
	expect(reply.status).toBe(200);
	return shaped(ConnectionRead, reply.body);
}

/**
 * @proves Replacing a SCIM connection's client secret or static token keeps the replaced value working until
 * the directory has used the new one and not the old one for an hour, and never past 24 hours; an
 * administrator's end of it — retiring it, revoking, replacing again — stops it and the tokens it obtained at
 * once and leaves the new value's tokens working; a key replaces at once; and no read shows a digest or a
 * token marker (spec 088, User Story 1).
 */
describe('replacing a SCIM credential without an outage', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	/* A fresh console session per case: a case that moves the clock a day on outlives the one before. */
	beforeEach(async () => {
		setSystemTime();
		cookie = await adminCookie();
	});

	afterEach(() => {
		setSystemTime();
	});

	it('obtains tokens with both the previous and the new secret after a replacement', async () => {
		const c = await connect(await scimBucket());
		const previous = await secretOf(c, cookie);

		const replaced = await issue(c, cookie, { kind: 'secret' });
		const fresh = replaced.secret ?? '';

		expect((await mint(c, previous)).access).not.toBe('');
		expect((await mint(c, fresh)).access).not.toBe('');
		expect(replaced.previousEndsAt).not.toBeNull();
		expect(replaced.connection.oauthCredential?.previous).toBeDefined();
	});

	it('says the previous secret ends 24 hours after the replacement at the latest', async () => {
		const c = await connect(await scimBucket());
		await secretOf(c, cookie);
		const now = new Date();
		setSystemTime(now);

		const replaced = await issue(c, cookie, { kind: 'secret' });

		expect(replaced.previousEndsAt).toBe(
			new Date(now.getTime() + 24 * HOUR).toISOString()
		);
	});

	it('refuses the previous secret once the new one was used and the previous one has not been for an hour', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		const previous = await secretOf(c, cookie);
		const fresh = await secretOf(c, cookie);
		setSystemTime(new Date(start.getTime() + MINUTE));
		await mint(c, fresh);

		setSystemTime(new Date(start.getTime() + MINUTE + HOUR + MINUTE));

		expect((await mint(c, previous)).error).toBe('invalid_client');
		expect((await mint(c, fresh)).access).not.toBe('');
	});

	it('keeps the previous secret working while the directory still uses it after trying the new one once', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		const previous = await secretOf(c, cookie);
		const fresh = await secretOf(c, cookie);
		setSystemTime(new Date(start.getTime() + MINUTE));
		await mint(c, fresh);
		setSystemTime(new Date(start.getTime() + 50 * MINUTE));
		await mint(c, previous);

		setSystemTime(new Date(start.getTime() + 105 * MINUTE));

		expect((await mint(c, previous)).access).not.toBe('');
	});

	it('tells the administrator the directory still uses the previous secret', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		const previous = await secretOf(c, cookie);
		const fresh = await secretOf(c, cookie);
		setSystemTime(new Date(start.getTime() + MINUTE));
		await mint(c, fresh);
		setSystemTime(new Date(start.getTime() + 20 * MINUTE));
		await mint(c, previous);

		const view = await read(c, cookie);

		expect(view.oauthCredential?.previous?.stillUsedByDirectory).toBe(true);
		expect(view.warnings).toContain('previous_credential_in_use');
	});

	it('refuses the previous secret 24 hours after the replacement however it is used', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		const previous = await secretOf(c, cookie);
		await secretOf(c, cookie);
		setSystemTime(new Date(start.getTime() + 23 * HOUR + 30 * MINUTE));
		await mint(c, previous);

		setSystemTime(new Date(start.getTime() + 24 * HOUR + MINUTE));

		expect((await mint(c, previous)).error).toBe('invalid_client');
	});

	it('stops the retired previous secret and its tokens and keeps the new secret’s tokens working', async () => {
		const c = await connect(await scimBucket());
		const previous = await secretOf(c, cookie);
		const fresh = await secretOf(c, cookie);
		const oldAccess = (await mint(c, previous)).access;
		const newAccess = (await mint(c, fresh)).access;

		const retired = await admin(
			'DELETE',
			`${connectionPath(c)}/credentials/oauth/previous`,
			cookie
		);

		expect(retired.status).toBe(200);
		expect((await mint(c, previous)).error).toBe('invalid_client');
		expect(await scimStatus(c, oldAccess)).toBe(401);
		expect(await scimStatus(c, newAccess)).toBe(200);
	});

	it('stops a token minted before tokens were marked when its secret is retired', async () => {
		const c = await connect(await scimBucket());
		const previous = await secretOf(c, cookie);
		const oldAccess = (await mint(c, previous)).access;
		/* As a token stored before this change was: no marker of the secret that obtained it. */
		const stored = TestAdapter.for('ClientCredentials').store;
		for (const [key, value] of stored) {
			if (
				key.endsWith(oldAccess) &&
				typeof value === 'object' &&
				!Array.isArray(value)
			) {
				Reflect.deleteProperty(value, 'credentialRef');
			}
		}
		await secretOf(c, cookie);

		await admin(
			'DELETE',
			`${connectionPath(c)}/credentials/oauth/previous`,
			cookie
		);

		expect(await scimStatus(c, oldAccess)).toBe(401);
	});

	it('refuses to retire a previous value when there is none that still works', async () => {
		const c = await connect(await scimBucket());
		await secretOf(c, cookie);

		const retired = await admin(
			'DELETE',
			`${connectionPath(c)}/credentials/oauth/previous`,
			cookie
		);

		expect(retired.status).toBe(404);
	});

	it('ends the oldest secret and its tokens when a secret is replaced again during an overlap', async () => {
		const c = await connect(await scimBucket());
		const first = await secretOf(c, cookie);
		const second = await secretOf(c, cookie);
		const firstAccess = (await mint(c, first)).access;
		const secondAccess = (await mint(c, second)).access;

		const third = await secretOf(c, cookie);

		expect((await mint(c, first)).error).toBe('invalid_client');
		expect((await mint(c, second)).access).not.toBe('');
		expect((await mint(c, third)).access).not.toBe('');
		expect(await scimStatus(c, firstAccess)).toBe(401);
		expect(await scimStatus(c, secondAccess)).toBe(200);
	});

	it('stops the replaced secret and every token it obtained at once when told to stop now', async () => {
		const c = await connect(await scimBucket());
		const previous = await secretOf(c, cookie);
		const oldAccess = (await mint(c, previous)).access;

		const replaced = await issue(c, cookie, { kind: 'secret', overlap: false });

		expect(replaced.previousEndsAt).toBeNull();
		expect((await mint(c, previous)).error).toBe('invalid_client');
		expect(await scimStatus(c, oldAccess)).toBe(401);
	});

	it('refuses both the current and the previous secret once the credential is revoked', async () => {
		const c = await connect(await scimBucket());
		const previous = await secretOf(c, cookie);
		const fresh = await secretOf(c, cookie);

		const revoked = await admin(
			'DELETE',
			`${connectionPath(c)}/credentials/oauth`,
			cookie
		);

		expect(revoked.status).toBe(200);
		expect((await mint(c, previous)).error).toBe('invalid_client');
		expect((await mint(c, fresh)).error).toBe('invalid_client');
	});

	it('accepts both the previous and the new static token on SCIM requests after a replacement', async () => {
		const c = await connect(await scimBucket());

		const replaced = await issue(c, cookie, { kind: 'static_token' });

		expect(await scimStatus(c, c.token)).toBe(200);
		expect(await scimStatus(c, replaced.token ?? '')).toBe(200);
		expect(replaced.previousEndsAt).not.toBeNull();
	});

	it('refuses the previous static token once the directory has moved to the new one for an hour', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		const replaced = await issue(c, cookie, { kind: 'static_token' });
		setSystemTime(new Date(start.getTime() + MINUTE));
		await scimStatus(c, replaced.token ?? '');

		setSystemTime(new Date(start.getTime() + 62 * MINUTE));

		expect(await scimStatus(c, c.token)).toBe(401);
		expect(await scimStatus(c, replaced.token ?? '')).toBe(200);
	});

	it('refuses a retired previous static token at once', async () => {
		const c = await connect(await scimBucket());
		await issue(c, cookie, { kind: 'static_token' });

		const retired = await admin(
			'DELETE',
			`${connectionPath(c)}/credentials/static_token/previous`,
			cookie
		);

		expect(retired.status).toBe(200);
		expect(await scimStatus(c, c.token)).toBe(401);
	});

	it('replaces a secret with a key at once, with no previous value', async () => {
		const c = await connect(await scimBucket());
		const previous = await secretOf(c, cookie);
		const { publicKey } = await generateKeyPair('ES256');
		const jwk = {
			...(await exportJWK(publicKey)),
			kid: 'k1',
			use: 'sig',
			alg: 'ES256'
		};

		const replaced = await issue(c, cookie, {
			kind: 'key',
			jwks: { keys: [jwk] }
		});

		expect(replaced.previousEndsAt).toBeNull();
		expect((await mint(c, previous)).error).toBe('invalid_client');
	});

	it('records in the audit trail until when a replaced value overlaps, and each retirement', async () => {
		const c = await connect(await scimBucket());
		await secretOf(c, cookie);
		const replaced = await issue(c, cookie, { kind: 'secret' });
		await admin(
			'DELETE',
			`${connectionPath(c)}/credentials/oauth/previous`,
			cookie
		);

		const issues = await adminAuditStore.list({
			action: 'provisioning.credential.issue',
			targetId: c.connection._id,
			limit: 10
		});
		const retires = await adminAuditStore.list({
			action: 'provisioning.credential.retire',
			targetId: c.connection._id,
			limit: 10
		});

		expect(issues.entries.map((e) => e.to)).toContain(replaced.previousEndsAt);
		expect(retires.entries).toHaveLength(1);
	});

	it('shows no digest and no token marker of either secret in any read', async () => {
		const c = await connect(await scimBucket());
		const previous = await secretOf(c, cookie);
		const fresh = await secretOf(c, cookie);
		await mint(c, previous);
		await mint(c, fresh);

		const one = await admin('GET', connectionPath(c), cookie);
		const all = await admin(
			'GET',
			`/admin/api/buckets/${c.bucket._id}/provisioning-connections`,
			cookie
		);

		for (const secret of [previous, fresh]) {
			const digest = crypto.createHash('sha256').update(secret).digest('hex');
			for (const reply of [one, all]) {
				const serialised = JSON.stringify(reply.body);
				expect(serialised).not.toContain(digest.slice(0, 16));
				expect(serialised).not.toContain(secret);
			}
		}
	});
});
