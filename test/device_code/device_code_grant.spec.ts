import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';
import base64url from 'base64url';

import bootstrap, { agent } from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { provider } from 'lib/provider.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { TestAdapter } from 'test/models.js';
import { ttl } from 'lib/configs/liveTime.js';
import instance from 'lib/helpers/weak_cache.js';
import { type BaseToken } from 'lib/models/base_token.ts';

function errorDetail(spy) {
	return spy.mock.calls[0][0].error_detail;
}

const grant_type = 'urn:ietf:params:oauth:grant-type:device_code';

function entityMap(spy) {
	const map = {};
	for (const [key, value] of spy.mock.calls) {
		map[key] = value;
	}
	return map;
}

function gtyOf(entity: BaseToken) {
	return entity?.payload?.gty;
}

describe('grant_type=urn:ietf:params:oauth:grant-type:device_code w/ conformIdTokenClaims=false', () => {
	let setup = null;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, {
			config: 'device_code_non_conform'
		})();
		await setup.login({
			scope: 'openid profile offline_access',
			accountId: 'sub'
		});
	});
	afterEach(() => {
		mock.restore();
		provider.removeAllListeners('grant.success');
		provider.removeAllListeners('grant.error');
	});

	it('returns the right stuff', async () => {
		const spy = mock();
		provider.once('grant.success', spy);

		const deviceCode = new DeviceCode({
			accountId: 'sub',
			grantId: setup.getGrantId(),
			scope: 'openid profile offline_access',
			clientId: 'client'
		});
		const code = await deviceCode.save();

		const { status, data } = await agent.token.post({
			client_id: 'client',
			device_code: code,
			grant_type
		});

		expect(status).toBe(200);
		expect(spy).toBeCalledTimes(1);
		[
			'access_token',
			'id_token',
			'expires_in',
			'token_type',
			'scope',
			'refresh_token'
		].forEach((prop) => expect(data).toHaveProperty(prop));
		expect(
			JSON.parse(base64url.decode(data.id_token.split('.')[1]))
		).toHaveProperty('given_name');
	});
});

describe('grant_type=urn:ietf:params:oauth:grant-type:device_code', () => {
	let setup = null;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url)();
		await setup.login({
			scope: 'openid profile offline_access',
			accountId: 'sub'
		});
	});
	afterEach(() => {
		mock.restore();
		provider.removeAllListeners('grant.success');
		provider.removeAllListeners('grant.error');
	});

	it('returns the right stuff', async () => {
		const spy = mock();
		provider.once('grant.success', spy);

		const deviceCode = new DeviceCode({
			accountId: 'sub',
			grantId: setup.getGrantId(),
			scope: 'openid profile offline_access',
			clientId: 'client'
		});
		const code = await deviceCode.save();

		const { status, data } = await agent.token.post({
			client_id: 'client',
			device_code: code,
			grant_type
		});

		expect(status).toBe(200);
		expect(spy).toBeCalledTimes(1);
		[
			'access_token',
			'id_token',
			'expires_in',
			'token_type',
			'scope',
			'refresh_token'
		].forEach((prop) => expect(data).toHaveProperty(prop));
		expect(
			JSON.parse(base64url.decode(data.id_token.split('.')[1]))
		).not.toHaveProperty('given_name');
	});

	it('populates ctx.oidc.entities (no offline_access)', async () => {
		const spy = spyOn(OIDCContext.prototype, 'entity');

		const deviceCode = new DeviceCode({
			accountId: 'sub',
			grantId: setup.getGrantId(),
			scope: 'openid',
			clientId: 'client'
		});
		const code = await deviceCode.save();

		const { data } = await agent.token.post({
			client_id: 'client',
			device_code: code,
			grant_type
		});

		expect(data.refresh_token).toBeUndefined();
		const entities = entityMap(spy);
		['Account', 'Grant', 'Client', 'DeviceCode', 'AccessToken'].forEach((k) =>
			expect(entities).toHaveProperty(k)
		);
		expect(gtyOf(entities.AccessToken)).toBe('device_code');
	});

	it('populates ctx.oidc.entities (w/ offline_access)', async () => {
		const spy = spyOn(OIDCContext.prototype, 'entity');

		const deviceCode = new DeviceCode({
			accountId: 'sub',
			grantId: setup.getGrantId(),
			scope: 'openid offline_access',
			clientId: 'client'
		});
		const code = await deviceCode.save();

		await agent.token.post({
			client_id: 'client',
			device_code: code,
			grant_type
		});

		const entities = entityMap(spy);
		[
			'Account',
			'Grant',
			'Client',
			'DeviceCode',
			'AccessToken',
			'RefreshToken'
		].forEach((k) => expect(entities).toHaveProperty(k));
		expect(gtyOf(entities.AccessToken)).toBe('device_code');
		expect(gtyOf(entities.RefreshToken)).toBe('device_code');
	});

	describe('validates', () => {
		it('device_code param presence', async () => {
			const { error } = await agent.token.post({
				client_id: 'client',
				grant_type
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: "missing required parameter 'device_code'"
			});
		});

		it('code being "found"', async () => {
			const spy = mock();
			provider.once('grant.error', spy);
			const { error } = await agent.token.post({
				client_id: 'client',
				grant_type,
				device_code:
					'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiIxNTU0M2RiYS0zYThmLTRiZWEtYmRjNi04NDQ2N2MwOWZjYTYiLCJpYXQiOjE0NjM2NTk2OTgsImV4cCI6MTQ2MzY1OTc1OCwiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.qUTaR48lavULtmDWBcpwhcF9NXhP8xzc-643h3yWLEgIyxPzKINT-upNn-byflH7P7rQlzZ-9SJKSs72ZVqWWMNikUGgJo-XmLyersONQ8sVx7v0quo4CRXamwyXfz2gq76gFlv5mtsrWwCij1kUnSaFm_HhAcoDPzGtSqhsHNoz36KjdmC3R-m84reQk_LEGizUeV-OmsBWJs3gedPGYcRCvsnW9qa21B0yZO2-HT9VQYY68UIGucDKNvizFRmIgepDZ5PUtsvyPD0PQQ9UHiEZvICeArxPLE8t1xz-lukpTMn8vA_YJ0s7kD9HYJUwxiYIuLXwDUNpGhsegxdvbw'
			});
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(errorDetail(spy)).toBe('device code not found');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('validates account is still there', async () => {
			spyOn(instance(provider).configuration, 'findAccount').mockResolvedValue(
				undefined
			);

			const spy = mock();
			provider.once('grant.error', spy);

			const deviceCode = new DeviceCode({
				accountId: 'sub',
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client'
			});
			const code = await deviceCode.save();

			const { error } = await agent.token.post({
				client_id: 'client',
				device_code: code,
				grant_type
			});
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(errorDetail(spy)).toBe(
				'device code invalid (referenced account not found)'
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('code belongs to client', async () => {
			const spy = mock();
			provider.once('grant.error', spy);

			const deviceCode = new DeviceCode({
				accountId: 'sub',
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client-other'
			});
			const code = await deviceCode.save();

			const { error } = await agent.token.post({
				client_id: 'client',
				device_code: code,
				grant_type
			});
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(errorDetail(spy)).toBe('client mismatch');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		describe('expired', () => {
			let prev;
			beforeAll(() => {
				prev = ttl.DeviceCode;
				ttl.DeviceCode = () => 0;
			});
			afterEach(() => {
				ttl.DeviceCode = prev;
			});

			it('validates code is not expired', async () => {
				const deviceCode = new DeviceCode({
					scope: 'openid',
					clientId: 'client'
				});
				const code = await deviceCode.save();

				const { error } = await agent.token.post({
					client_id: 'client',
					device_code: code,
					grant_type
				});
				expect(error.status).toBe(400);
				expect(error.value).toEqual({
					error: 'expired_token',
					error_description: 'device code is expired'
				});
			});
		});

		it('consumes the code', async () => {
			const deviceCode = new DeviceCode({
				accountId: 'sub',
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client'
			});
			const code = await deviceCode.save();

			const { status } = await agent.token.post({
				client_id: 'client',
				device_code: code,
				grant_type
			});
			expect(status).toBe(200);
			const jti = setup.getTokenJti(code);
			const stored = TestAdapter.for('DeviceCode').syncFind(jti);
			expect(stored.consumed).toBeLessThanOrEqual(epochTime());
		});

		it('validates code is not already used', async () => {
			const spy = mock();
			provider.once('grant.error', spy);

			const deviceCode = new DeviceCode({
				accountId: 'sub',
				grantId: setup.getGrantId(),
				scope: 'openid',
				clientId: 'client'
			});
			const code = await deviceCode.save();
			await deviceCode.consume();

			const { error } = await agent.token.post({
				client_id: 'client',
				device_code: code,
				grant_type
			});
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(errorDetail(spy)).toBe('device code already consumed');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});
	});

	it('responds with authorization_pending if interactions are still pending resolving', async () => {
		const deviceCode = new DeviceCode({
			scope: 'openid',
			clientId: 'client'
		});
		const code = await deviceCode.save();

		const { error } = await agent.token.post({
			client_id: 'client',
			device_code: code,
			grant_type
		});
		expect(error.status).toBe(400);
		expect(error.value).toEqual({
			error: 'authorization_pending',
			error_description:
				"authorization request is still pending as the end-user hasn't yet completed the user interaction steps"
		});
	});

	it('responds with a custom error if one is resolved with', async () => {
		const deviceCode = new DeviceCode({
			scope: 'openid',
			clientId: 'client',
			error: 'foo',
			errorDescription: 'bar'
		});
		const code = await deviceCode.save();

		const { error } = await agent.token.post({
			client_id: 'client',
			device_code: code,
			grant_type
		});
		expect(error.status).toBe(400);
		expect(error.value).toEqual({
			error: 'foo',
			error_description: 'bar'
		});
	});

	it('responds with a built-in error if one is resolved with', async () => {
		const spy = mock();
		provider.once('grant.error', spy);

		const deviceCode = new DeviceCode({
			scope: 'openid',
			clientId: 'client',
			error: 'access_denied',
			errorDescription: 'user has denied access'
		});
		const code = await deviceCode.save();

		const { error } = await agent.token.post({
			client_id: 'client',
			device_code: code,
			grant_type
		});
		expect(error.status).toBe(400);
		expect(error.value).toEqual({
			error: 'access_denied',
			error_description: 'user has denied access'
		});
		expect(spy).toBeCalledTimes(1);
	});
});
