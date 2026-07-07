import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	spyOn,
	mock
} from 'bun:test';

import nanoid from '../../lib/helpers/nanoid.ts';
import bootstrap, { agent, passInteractionChecks } from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { generate } from '../../lib/helpers/user_codes.ts';
import { Session } from 'lib/models/session.js';
import { ttl } from 'lib/configs/liveTime.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { Interaction } from 'lib/models/interaction.js';
import { Grant } from 'lib/models/grant.js';

let setup = null;
let uid;
let userCode;

// Builds a device interaction resumable at GET /ui/:uid/device_resume: a saved Session, a saved
// DeviceCode, and a saved Interaction referencing both. Returns the request cookie header.
async function buildResume({ auth = {}, result, accountId } = {}) {
	const session = new Session({
		jti: nanoid(),
		accountId,
		loginTs: epochTime()
	});
	const sessionId = await session.save(ttl.Session);

	const params = { client_id: 'client', ...auth };
	const deviceCode = new DeviceCode({ params, clientId: 'client', userCode });
	await deviceCode.save();

	const interaction = new Interaction(uid, {
		deviceCode: deviceCode.jti,
		session: { accountId },
		params,
		result
	});
	await interaction.save(30);

	return `_interaction=${nanoid()}; _session=${sessionId}`;
}

function get(cookie) {
	return agent.ui[uid].device_resume.get({ headers: { cookie } });
}

describe('device interaction resume /ui/:uid/device_resume', () => {
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url)();
	});

	beforeEach(() => {
		uid = nanoid();
		userCode = generate('base-20', '***-***-***');
	});

	afterEach(() => {
		mock.restore();
	});

	passInteractionChecks('native_client_prompt', () => {
		describe('general', () => {
			it('needs to find the code to resume', async () => {
				const accountId = nanoid();
				const cookie = await buildResume({
					auth: { scope: 'openid' },
					result: { login: { accountId } },
					accountId
				});

				spyOn(DeviceCode, 'find').mockResolvedValue(undefined);

				const { data } = await get(cookie);
				expect(data).toContain('id="op.deviceInputForm"');
				expect(data).toContain(
					'<p class="red">There was an error processing your request</p>'
				);
			});

			it('checks code is not expired', async () => {
				const accountId = nanoid();
				const cookie = await buildResume({
					auth: { scope: 'openid' },
					result: { login: { accountId } },
					accountId
				});

				spyOn(DeviceCode, 'find').mockResolvedValue({
					isExpired: true,
					payload: {}
				});

				const { data } = await get(cookie);
				expect(data).toContain('id="op.deviceInputForm"');
				expect(data).toContain(
					'<p class="red">There was an error processing your request</p>'
				);
			});

			it('checks code is not used already (accountId)', async () => {
				const accountId = nanoid();
				const cookie = await buildResume({
					auth: { scope: 'openid' },
					result: { login: { accountId } },
					accountId
				});

				spyOn(DeviceCode, 'find').mockResolvedValue({
					isExpired: false,
					payload: { accountId: 'foo' }
				});

				const { data } = await get(cookie);
				expect(data).toContain('id="op.deviceInputForm"');
				expect(data).toContain(
					'<p class="red">There was an error processing your request</p>'
				);
			});

			it('checks code is not used already (error)', async () => {
				const accountId = nanoid();
				const cookie = await buildResume({
					auth: { scope: 'openid' },
					result: { login: { accountId } },
					accountId
				});

				spyOn(DeviceCode, 'find').mockResolvedValue({
					isExpired: false,
					payload: { error: 'access_denied' }
				});

				const { data } = await get(cookie);
				expect(data).toContain('id="op.deviceInputForm"');
				expect(data).toContain(
					'<p class="red">There was an error processing your request</p>'
				);
			});
		});

		describe('login results', () => {
			it('processes a newly established session and binds the code', async () => {
				spyOn(Grant.prototype, 'getOIDCScope').mockReturnValue('openid');
				const accountId = nanoid();
				const cookie = await buildResume({
					auth: { scope: 'openid' },
					result: { login: { accountId } },
					accountId
				});

				const { status } = await get(cookie);
				expect(status).toBe(200);

				const code = await DeviceCode.findByUserCode(userCode);
				expect(code.payload).toHaveProperty('accountId');
			});
		});

		describe('interaction errors', () => {
			it('aborts an interaction when given an error result object', async () => {
				const accountId = nanoid();
				const cookie = await buildResume({
					auth: { scope: 'openid' },
					result: {
						error: 'access_denied',
						error_description: 'scope out of reach'
					},
					accountId
				});

				const { error, status, data } = await get(cookie);
				const body = data ?? error?.value;
				expect(body).toContain('id="op.deviceInputForm"');
				expect(body).toContain(
					'<p class="red">The Sign-in request was interrupted</p>'
				);
			});
		});
	});
});
