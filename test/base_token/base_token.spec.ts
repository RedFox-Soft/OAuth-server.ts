import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	spyOn,
	mock,
	expect,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { TestAdapter } from 'test/models.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';

describe('BaseToken', () => {
	let setup = null;
	const adapter = TestAdapter.for('RefreshToken');
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	beforeEach(function () {
		spyOn(adapter, 'find');
		spyOn(adapter, 'upsert');
	});

	afterEach(function () {
		mock.restore();
		setSystemTime();
	});

	it('handles legacy structured tokens', async function () {
		const token = await new RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = setup.getTokenJti(token);
		adapter.syncUpdate(jti, { jwt: 'foo' });
		expect(await RefreshToken.find(token)).toBeUndefined();
	});

	it('handles expired tokens', async function () {
		const token = await new RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = setup.getTokenJti(token);
		adapter.syncUpdate(jti, { exp: 0 });
		expect(await RefreshToken.find(token)).toBeUndefined();
	});

	it('handles invalid inputs', async function () {
		for (const input of [true, Boolean, 1, Infinity, {}, [], new Set()]) {
			const result = await RefreshToken.find(input);
			expect(result).toBeUndefined();
		}
	});

	it('assigns returned consumed prop', async function () {
		const token = await new RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = setup.getTokenJti(token);
		const stored = TestAdapter.for('RefreshToken').syncFind(jti);
		stored.consumed = true;
		expect((await RefreshToken.find(token)).payload).toHaveProperty(
			'consumed',
			true
		);
	});

	it('uses expiration for upsert from global settings if not specified in token values', async function () {
		const token = await new RefreshToken({ grantId: 'foo' }).save();
		const jti = setup.getTokenJti(token);
		expect(adapter.upsert).toBeCalledWith(
			jti,
			expect.any(Object),
			14 * 24 * 60 * 60
		);
	});

	it('uses expiration for upsert from token values', async function () {
		const token = await new RefreshToken({
			grantId: 'foo',
			expiresIn: 60
		}).save();
		const jti = setup.getTokenJti(token);
		expect(adapter.upsert).toBeCalledWith(jti, expect.any(Object), 60);
	});

	it('resaves tokens with their actual remaining ttl passed to expiration', async function () {
		let token = new RefreshToken({ grantId: 'foo' });
		const value = await token.save();
		const jti = setup.getTokenJti(value);
		expect(adapter.upsert).toBeCalledWith(
			jti,
			expect.any(Object),
			14 * 24 * 60 * 60
		);
		adapter.upsert.mockClear();
		setSystemTime((((Date.now() / 1000) | 0) + 60) * 1000);

		token = await RefreshToken.find(value);
		await token.save();

		expect(adapter.upsert).toBeCalledWith(
			jti,
			expect.any(Object),
			14 * 24 * 60 * 60 - 60
		);
	});

	it('additional save does not change the token value', async function () {
		let token = new RefreshToken({
			grantId: 'foo'
		});
		const first = await token.save();

		token = await RefreshToken.find(first);
		expect(token.payload.scope).toBeUndefined();
		token.payload.scope = 'openid profile';
		const second = await token.save();

		token = await RefreshToken.find(first);
		expect(token.payload.scope).toBe('openid profile');
		token.payload.scope = 'openid profile email';
		const third = await token.save();

		token = await RefreshToken.find(first);
		expect(token.payload.scope).toBe('openid profile email');

		expect(second).toEqual(first);
		expect(third).toEqual(second);
	});

	it('rethrows adapter#find errors from session bound tokens looking up the session', async function () {
		const token = new RefreshToken({
			expiresWithSession: true,
			sessionUid: 'foo'
		});
		const value = await token.save();
		spyOn(TestAdapter.for('Session'), 'findByUid').mockRejectedValue(
			new Error('adapter throw!')
		);
		return expect(RefreshToken.find(value)).rejects.toThrow('adapter throw!');
	});

	it('consumed token save saves consumed', async function () {
		let token = new AuthorizationCode({
			grantId: 'foo',
			consumed: true
		});
		const first = await token.save();

		token = await AuthorizationCode.find(first);
		expect(token.payload.consumed).toBeTrue();
	});

	it('rethrows adapter#findByUserCode errors (Device Code)', async function () {
		spyOn(TestAdapter.for('DeviceCode'), 'findByUserCode').mockRejectedValue(
			new Error('adapter throw!')
		);
		return expect(DeviceCode.findByUserCode('123-456-789')).rejects.toThrow(
			'adapter throw!'
		);
	});
});
