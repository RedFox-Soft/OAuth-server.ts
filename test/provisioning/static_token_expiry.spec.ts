import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	setSystemTime
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { shaped } from '../shape.ts';
import { connect, scim, scimBucket, type Connected } from '../scim/helpers.ts';
import { admin } from './helpers.ts';
import { planStaticTokenExpiry } from 'lib/consts/migrations.js';

const DAY = 24 * 60 * 60 * 1000;

const StaticTokenRead = Type.Object({
	staticToken: Type.Union([
		Type.Object({
			issuedAt: Type.String(),
			expiresAt: Type.Union([Type.String(), Type.Null()])
		}),
		Type.Null()
	]),
	warnings: Type.Array(Type.String())
});
const IssuedToken = Type.Object({
	connection: StaticTokenRead,
	token: Type.String()
});

function connectionPath(c: Connected): string {
	return `/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`;
}

async function issueToken(
	c: Connected,
	body: Record<string, unknown> = {}
): Promise<{ token: string; expiresAt: string | null }> {
	const reply = await admin(
		'POST',
		`${connectionPath(c)}/credentials`,
		await adminCookie(),
		{ kind: 'static_token', ...body }
	);
	expect(reply.status).toBe(201);
	const issued = shaped(IssuedToken, reply.body);
	return {
		token: issued.token,
		expiresAt: issued.connection.staticToken?.expiresAt ?? null
	};
}

async function warnings(c: Connected): Promise<string[]> {
	const reply = await admin('GET', connectionPath(c), await adminCookie());
	return shaped(StaticTokenRead, reply.body).warnings;
}

async function scimStatus(c: Connected, bearer: string): Promise<number> {
	return (await scim('GET', `${c.base}/Users`, { token: bearer })).status;
}

/**
 * @proves A SCIM static token lives as long as the lifetime chosen when it was issued and is refused after it,
 * the console warns two weeks ahead and once it has expired, a replaced token ends no later than its own
 * expiry, and an upgrade gives every older token a lifetime that refuses none of them for 90 days (spec 088,
 * User Story 2).
 */
describe('a SCIM static token expires', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		setSystemTime();
	});

	it('expires a year after issue unless another lifetime is chosen', async () => {
		const c = await connect(await scimBucket());
		const now = new Date();
		setSystemTime(now);

		const issued = await issueToken(c);

		expect(issued.expiresAt).toBe(
			new Date(now.getTime() + 365 * DAY).toISOString()
		);
	});

	it('expires after the 90 days chosen at issue', async () => {
		const c = await connect(await scimBucket());
		const now = new Date();
		setSystemTime(now);

		const issued = await issueToken(c, { lifetimeDays: 90 });

		expect(issued.expiresAt).toBe(
			new Date(now.getTime() + 90 * DAY).toISOString()
		);
	});

	it('refuses a lifetime for a credential that is not a static token', async () => {
		const c = await connect(await scimBucket());

		const reply = await admin(
			'POST',
			`${connectionPath(c)}/credentials`,
			await adminCookie(),
			{ kind: 'secret', lifetimeDays: 90 }
		);

		expect(reply.status).toBe(422);
	});

	it('refuses a static token on SCIM requests once it has expired', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		const issued = await issueToken(c, { lifetimeDays: 90 });

		setSystemTime(new Date(start.getTime() + 91 * DAY));

		expect(await scimStatus(c, issued.token)).toBe(401);
	});

	it('warns that the static token expires within 14 days', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		await issueToken(c, { lifetimeDays: 90 });

		setSystemTime(new Date(start.getTime() + 77 * DAY));

		expect(await warnings(c)).toContain('static_token_expiring');
	});

	it('warns of nothing about expiry while more than 14 days are left', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		await issueToken(c, { lifetimeDays: 90 });

		setSystemTime(new Date(start.getTime() + 70 * DAY));

		const said = await warnings(c);
		expect(said).not.toContain('static_token_expiring');
		expect(said).not.toContain('static_token_expired');
	});

	it('says the static token has expired once it has', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		await issueToken(c, { lifetimeDays: 90 });

		setSystemTime(new Date(start.getTime() + 91 * DAY));

		expect(await warnings(c)).toContain('static_token_expired');
	});

	it('ends a replaced static token at its own expiry when that comes before the overlap’s end', async () => {
		const c = await connect(await scimBucket());
		const start = new Date();
		setSystemTime(start);
		const first = await issueToken(c, { lifetimeDays: 90 });
		setSystemTime(new Date(start.getTime() + 90 * DAY - 60 * 60 * 1000));
		const second = await issueToken(c);

		setSystemTime(new Date(start.getTime() + 90 * DAY + 60 * 1000));

		expect(await scimStatus(c, first.token)).toBe(401);
		expect(await scimStatus(c, second.token)).toBe(200);
	});

	describe('upgrading a database holding tokens issued without a lifetime', () => {
		const upgrade = new Date('2026-10-12T12:00:00Z');
		const stored = (
			_id: string,
			fields: Record<string, unknown>
		): {
			_id: string;
			staticTokenDigest: unknown;
			staticTokenIssuedAt: unknown;
			staticTokenExpiresAt: unknown;
		} => ({
			_id,
			staticTokenDigest: 'd'.repeat(64),
			staticTokenIssuedAt: undefined,
			staticTokenExpiresAt: undefined,
			...fields
		});

		it('gives a two-year-old token 90 days from the upgrade', () => {
			const plan = planStaticTokenExpiry(
				[
					stored('old', {
						staticTokenIssuedAt: new Date(upgrade.getTime() - 730 * DAY)
					})
				],
				upgrade
			);

			expect(plan).toEqual([
				{
					connectionId: 'old',
					expiresAt: new Date(upgrade.getTime() + 90 * DAY)
				}
			]);
		});

		it('gives a month-old token a year from its issue', () => {
			const issuedAt = new Date(upgrade.getTime() - 30 * DAY);

			const plan = planStaticTokenExpiry(
				[stored('young', { staticTokenIssuedAt: issuedAt.toISOString() })],
				upgrade
			);

			expect(plan).toEqual([
				{
					connectionId: 'young',
					expiresAt: new Date(issuedAt.getTime() + 365 * DAY)
				}
			]);
		});

		it('leaves a token that already expires, and a connection holding none', () => {
			const plan = planStaticTokenExpiry(
				[
					stored('dated', {
						staticTokenExpiresAt: new Date(upgrade.getTime() + DAY)
					}),
					stored('none', { staticTokenDigest: undefined })
				],
				upgrade
			);

			expect(plan).toEqual([]);
		});

		it('finds nothing to do in connections it has already given an expiry', () => {
			const before = [
				stored('a', {
					staticTokenIssuedAt: new Date(upgrade.getTime() - 400 * DAY)
				})
			];
			const after = before.map((c) => ({
				...c,
				staticTokenExpiresAt: planStaticTokenExpiry(before, upgrade).find(
					(p) => p.connectionId === c._id
				)?.expiresAt
			}));

			expect(planStaticTokenExpiry(after, upgrade)).toEqual([]);
		});
	});
});
