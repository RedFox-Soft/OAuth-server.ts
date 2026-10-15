import { describe, it, beforeAll, afterEach, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { getBucketStore, getUserStore } from 'lib/adapters/index.js';
import type { UserBucket } from 'lib/adapters/types.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { SECRET_MASK } from 'lib/federation/consts.js';
import type { FederationProvider } from 'lib/federation/types.js';
import bootstrap from '../test_helper.js';
import { plainAdministrator } from '../deprovisioning_guard/helpers.ts';
import { admin } from '../provisioning/helpers.ts';
import { groupIdFor } from '../admin_session.ts';
import { connect, provider, scimBucket } from '../scim/helpers.ts';
import { shaped } from '../shape.ts';

const Signals = Type.Object({
	globalTokenRevocation: Type.Boolean(),
	backChannelLogout: Type.Boolean()
});

const ProviderDetail = Type.Object({
	id: Type.String(),
	clientSecret: Type.Optional(Type.String()),
	callbackUri: Type.String(),
	callbackStability: Type.Union([
		Type.Literal('stable'),
		Type.Literal('provisional')
	]),
	recognised: Type.Union([Type.String(), Type.Null()]),
	logoutSignals: Signals,
	capabilities: Type.Object({
		globalTokenRevocation: Type.Boolean(),
		backChannelLogout: Type.Boolean(),
		trySignIn: Type.Boolean()
	}),
	boundConnection: Type.Union([
		Type.Object({ id: Type.String(), displayName: Type.String() }),
		Type.Null()
	]),
	linkedUsers: Type.Number(),
	recommendedCorrelation: Type.Object({
		claim: Type.String(),
		attribute: Type.String()
	}),
	warnings: Type.Array(Type.String())
});

const Catalogue = Type.Object({
	providers: Type.Array(
		Type.Object({ catalogueId: Type.String(), callbackUri: Type.String() })
	)
});

interface Owned {
	bucket: UserBucket;
	cookie: string;
}

/* A bucket owned by one administrator's group, holding the given providers, and that administrator's cookie. */
async function owned(providers: FederationProvider[]): Promise<Owned> {
	const { user, cookie } = await plainAdministrator();
	const bucket = await scimBucket(providers, {
		ownerGroupId: await groupIdFor(user)
	});
	return { bucket, cookie };
}

function read(o: Owned, providerId: string, cookie = o.cookie) {
	return admin(
		'GET',
		`/admin/api/projects/${o.bucket._id}/federation/${providerId}`,
		cookie
	);
}

async function detail(o: Owned, providerId: string) {
	const res = await read(o, providerId);
	expect(res.status).toBe(200);
	return shaped(ProviderDetail, res.json);
}

async function linked(bucketId: string, providerId: string, n: number) {
	const store = getUserStore(bucketId);
	for (let i = 0; i < n; i += 1) {
		const user = await store.create(
			`${providerId}-${i}-${Math.random().toString(36).slice(2)}@contoso.com`,
			'a password that is long enough',
			true
		);
		await store.update(user._id, {
			federated: [{ providerId, sub: `sub-${user._id}`, linkedAt: new Date() }]
		});
	}
}

/**
 * @proves An administrator opening one identity provider of a bucket is told, by the server, where the provider
 * must send people back, which logout signals it can send and whether this instance accepts them, which
 * directory it belongs to and how many people a change to it reaches — without its secret, and only within a
 * bucket they may read (spec 084, User Story 2, R1).
 */
describe('reading one identity provider of a bucket', () => {
	let federation: boolean;
	let revocation: boolean;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		federation = ApplicationConfig['federation.enabled'];
		revocation = ApplicationConfig['globalTokenRevocation.enabled'];
	});

	afterEach(() => {
		ApplicationConfig['federation.enabled'] = federation;
		ApplicationConfig['globalTokenRevocation.enabled'] = revocation;
	});

	it('gives the callback address the catalogue tells the administrator to register', async () => {
		const o = await owned([
			provider('google', { issuer: 'https://accounts.google.com' })
		]);
		const catalogue = shaped(
			Catalogue,
			(
				await admin(
					'GET',
					`/admin/api/projects/${o.bucket._id}/federation/catalogue`,
					o.cookie
				)
			).json
		);

		const read = await detail(o, 'google');

		expect(read.callbackUri).toBe(
			catalogue.providers.find((p) => p.catalogueId === 'google')
				?.callbackUri ?? 'no google entry'
		);
		expect(read.callbackStability).toBe('stable');
		expect(read.recognised).toBe('google');
	});

	it('warns that the callback may change while the bucket has no address of its own', async () => {
		const { user, cookie } = await plainAdministrator();
		const bucket = await getBucketStore().create({
			ownerGroupId: await groupIdFor(user),
			name: `unaddressed-${Math.random()}`,
			federation: [provider('corp')]
		});

		const read = await detail({ bucket, cookie }, 'corp');

		expect(read.callbackStability).toBe('provisional');
		expect(read.warnings).toContain('callback_provisional');
	});

	it('names the provisioning connection bound to it', async () => {
		const o = await owned([provider('corp')]);
		const c = await connect(o.bucket);

		const read = await detail(o, 'corp');

		expect(read.boundConnection).toEqual({
			id: c.connection._id,
			displayName: c.connection.displayName
		});
	});

	it('counts only the people linked to that provider', async () => {
		const o = await owned([provider('corp'), provider('other')]);
		await linked(o.bucket._id, 'corp', 2);
		await linked(o.bucket._id, 'other', 1);

		const read = await detail(o, 'corp');

		expect(read.linkedUsers).toBe(2);
		expect(read.boundConnection).toBeNull();
	});

	it('says a GitHub provider can send neither logout signal', async () => {
		const o = await owned([
			provider('github', { issuer: 'https://github.com' })
		]);

		const read = await detail(o, 'github');

		expect(read.recognised).toBe('github');
		expect(read.logoutSignals).toEqual({
			globalTokenRevocation: false,
			backChannelLogout: false
		});
	});

	it('says an OIDC provider can send both signals, and which of them this instance accepts', async () => {
		ApplicationConfig['federation.enabled'] = true;
		ApplicationConfig['globalTokenRevocation.enabled'] = false;
		const o = await owned([provider('corp')]);

		const read = await detail(o, 'corp');

		expect(read.logoutSignals).toEqual({
			globalTokenRevocation: true,
			backChannelLogout: true
		});
		expect(read.capabilities).toEqual({
			globalTokenRevocation: false,
			backChannelLogout: true,
			trySignIn: true
		});
	});

	it('warns when a logout signal it accepts is switched off on this instance', async () => {
		ApplicationConfig['federation.enabled'] = true;
		ApplicationConfig['globalTokenRevocation.enabled'] = false;
		const o = await owned([
			provider('corp', { acceptsGlobalTokenRevocation: true })
		]);

		const read = await detail(o, 'corp');

		expect(read.warnings).toContain('signals_capability_off');
	});

	it('warns when a provider a directory relies on is disabled', async () => {
		const o = await owned([provider('corp')]);
		await connect(o.bucket);
		const fresh = await getBucketStore().find(o.bucket._id);
		await getBucketStore().update(o.bucket._id, {
			federation: (fresh?.federation ?? []).map((p) => ({
				...p,
				enabled: false
			}))
		});

		const read = await detail(o, 'corp');

		expect(read.warnings).toContain('bound_provider_disabled');
	});

	it('recommends matching a Microsoft provider’s people by oid against externalId', async () => {
		const o = await owned([
			provider('entra', {
				issuer:
					'https://login.microsoftonline.com/1d6e9c2a-0000-4000-8000-000000000001/v2.0'
			})
		]);

		const read = await detail(o, 'entra');

		expect(read.recommendedCorrelation).toEqual({
			claim: 'oid',
			attribute: 'externalId'
		});
	});

	it('masks the provider’s client secret', async () => {
		const o = await owned([
			provider('corp', { clientSecret: 'the-real-upstream-secret' })
		]);

		const res = await read(o, 'corp');

		expect(shaped(ProviderDetail, res.json).clientSecret).toBe(SECRET_MASK);
		expect(JSON.stringify(res.body)).not.toContain('the-real-upstream-secret');
	});

	it('answers 404 for a provider the bucket does not have', async () => {
		const o = await owned([provider('corp')]);

		const res = await read(o, 'nobody');

		expect(res.status).toBe(404);
	});

	it('refuses an administrator with no access to the bucket', async () => {
		const o = await owned([provider('corp')]);
		const { cookie } = await plainAdministrator();

		const res = await read(o, 'corp', cookie);

		expect(res.status).toBe(403);
		expect(res.json.callbackUri).toBeUndefined();
	});
});
