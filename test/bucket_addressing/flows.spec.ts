import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	mock
} from 'bun:test';

import bootstrap, {
	clearSeededBuckets,
	jsonToFormUrlEncoded,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { eventBus } from 'lib/event_bus.js';
import { sessionCookieName } from 'lib/consts/param_list.js';
import { DEFAULT_REQUEST_BUCKET } from 'lib/configs/issuer.js';
import { Grant } from 'lib/models/grant.js';
import { Session } from 'lib/models/session.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { Interaction } from 'lib/models/interaction.js';
import nanoid from '../../lib/helpers/nanoid.ts';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { acmeClient } from './flows.config.js';

const SLUG = 'acme';
const BUCKET_ID = 'acme-bucket';
const ACME_ISSUER = `${ISSUER}/${SLUG}`;
const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
const CIBA = 'urn:openid:params:grant-type:ciba';

type Json = Record<string, unknown>;

/**
 * @proves A device or backchannel flow started at a named bucket's address belongs to that bucket —
 * its verification page, its session and the issuer of the tokens it yields — and a client of another
 * bucket cannot start one there.
 */
describe('a flow started at a named bucket address', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'flows' });
		await seedBucket({
			bucketId: BUCKET_ID,
			slug: SLUG,
			clientId: 'acme-device',
			accountId: 'bob',
			client: acmeClient
		});
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	afterEach(() => {
		eventBus.removeAllListeners('device_code.saved');
		eventBus.removeAllListeners('backchannel_authentication_request.saved');
		mock.restore();
	});

	function post(
		path: string,
		clientId: string,
		secret: string,
		form: Record<string, string>
	) {
		return elysia.handle(
			new Request(`http://localhost${path}`, {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					...AuthorizationRequest.basicAuthHeader(clientId, secret)
				},
				body: jsonToFormUrlEncoded(form)
			})
		);
	}

	/* Compared exactly after decoding: the instance issuer is a prefix of every bucket's. */
	function issuerOfIdToken(idToken: string): string {
		const payload = JSON.parse(
			Buffer.from(idToken.split('.')[1], 'base64url').toString()
		) as { iss: string };
		return payload.iss;
	}

	async function grantFor(clientId: string, accountId: string) {
		const grant = new Grant({ clientId, accountId });
		grant.addOIDCScope('openid');
		return grant.save();
	}

	it('sends the end user to the bucket verification page', async () => {
		const response = await post(
			`/${SLUG}/device/auth`,
			'acme-device',
			'acme-secret',
			{ scope: 'openid' }
		);
		expect(response.status).toBe(200);
		const body = (await response.json()) as Json;

		expect(body.verification_uri).toBe(`${ACME_ISSUER}/device`);
		expect(String(body.verification_uri_complete)).toStartWith(
			`${ACME_ISSUER}/device?user_code=`
		);
	});

	it('issues an ID token carrying the bucket issuer once the device code is approved', async () => {
		const started = await post(
			`/${SLUG}/device/auth`,
			'acme-device',
			'acme-secret',
			{ scope: 'openid' }
		);
		const { device_code: deviceCode } = (await started.json()) as {
			device_code: string;
		};
		TestAdapter.for('DeviceCode').syncUpdate(setup.getTokenJti(deviceCode), {
			scope: 'openid',
			accountId: 'bob',
			grantId: await grantFor('acme-device', 'bob')
		});

		const redeemed = await post(
			`/${SLUG}/token`,
			'acme-device',
			'acme-secret',
			{
				grant_type: DEVICE,
				device_code: deviceCode
			}
		);
		expect(redeemed.status).toBe(200);
		const { id_token: idToken } = (await redeemed.json()) as {
			id_token: string;
		};

		expect(issuerOfIdToken(idToken)).toBe(ACME_ISSUER);
	});

	it('issues an ID token carrying the bucket issuer once a backchannel request is approved', async () => {
		const started = await post(
			`/${SLUG}/backchannel`,
			'acme-device',
			'acme-secret',
			{ scope: 'openid', login_hint: 'bob' }
		);
		expect(started.status).toBe(200);
		const { auth_req_id: authReqId } = (await started.json()) as {
			auth_req_id: string;
		};

		const redeemed = await post(
			`/${SLUG}/token`,
			'acme-device',
			'acme-secret',
			{
				grant_type: CIBA,
				auth_req_id: authReqId
			}
		);
		expect(redeemed.status).toBe(200);
		const { id_token: idToken } = (await redeemed.json()) as {
			id_token: string;
		};

		expect(issuerOfIdToken(idToken)).toBe(ACME_ISSUER);
	});

	it('refuses a client of the default bucket at the bucket device endpoint, storing nothing', async () => {
		const stored = mock();
		eventBus.on('device_code.saved', stored);

		const response = await post(
			`/${SLUG}/device/auth`,
			'default-device',
			'default-secret',
			{ scope: 'openid' }
		);

		expect(response.status).toBe(400);
		expect(((await response.json()) as Json).error).toBe('unauthorized_client');
		expect(stored).not.toHaveBeenCalled();
	});

	it('refuses a client of the default bucket at the bucket backchannel endpoint, storing nothing', async () => {
		const stored = mock();
		eventBus.on('backchannel_authentication_request.saved', stored);

		const response = await post(
			`/${SLUG}/backchannel`,
			'default-device',
			'default-secret',
			{ scope: 'openid', login_hint: 'bob' }
		);

		expect(response.status).toBe(400);
		expect(((await response.json()) as Json).error).toBe('unauthorized_client');
		expect(stored).not.toHaveBeenCalled();
	});

	it('keeps the instance verification page for a flow at the bare address', async () => {
		const response = await post(
			'/device/auth',
			'default-device',
			'default-secret',
			{
				scope: 'openid'
			}
		);
		expect(response.status).toBe(200);

		expect(((await response.json()) as Json).verification_uri).toBe(
			`${ISSUER}/device`
		);
	});

	/*
	 * The sign-in completes either way — the interaction's own result establishes it — so what shows the
	 * difference is which session it is written to. A device sign-in for a bucket's client that lands in
	 * the default bucket's cookie is a sign-in recorded against the wrong population.
	 */
	it('records a device sign-in for a bucket client in that bucket session', async () => {
		const uid = nanoid();
		const session = new Session({
			jti: nanoid(),
			accountId: 'bob',
			bucketId: BUCKET_ID,
			loginTs: epochTime()
		});
		const sessionId = await session.save();

		const params = { client_id: 'acme-device', scope: 'openid' };
		const deviceCode = new DeviceCode({
			params,
			clientId: 'acme-device',
			bucketId: BUCKET_ID,
			userCode: nanoid()
		});
		await deviceCode.save();

		await new Interaction(uid, {
			deviceCode: deviceCode.jti,
			session: { accountId: 'bob' },
			params,
			result: { login: { accountId: 'bob' } }
		}).save(30);

		const acmeSession = sessionCookieName({ _id: BUCKET_ID, slug: SLUG });
		const defaultSession = sessionCookieName(DEFAULT_REQUEST_BUCKET);
		const response = await elysia.handle(
			new Request(`http://localhost/ui/${uid}/device_resume`, {
				headers: {
					cookie: `_interaction=${nanoid()}; ${acmeSession}=${sessionId}`
				}
			})
		);
		expect(response.status).toBe(200);

		const written = response.headers
			.getSetCookie()
			.map((header) => header.split('=')[0]);
		expect(written).toContain(acmeSession);
		expect(written).not.toContain(defaultSession);
	});

	it('returns a management address beneath the bucket for a registration made there', async () => {
		const response = await elysia.handle(
			new Request(`http://localhost/${SLUG}/reg`, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({
					redirect_uris: ['https://registered.example.com/cb'],
					grant_types: ['authorization_code'],
					response_types: ['code']
				})
			})
		);
		expect(response.status).toBe(201);
		const body = (await response.json()) as Json;

		expect(String(body.registration_client_uri)).toStartWith(
			`${ACME_ISSUER}/reg/`
		);
	});
});
