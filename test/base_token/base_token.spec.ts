import { strict as assert } from 'node:assert';

import { createSandbox } from 'sinon';
import { expect } from 'chai';
import timekeeper from 'timekeeper';
import { describe, it, beforeAll, beforeEach, afterEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { TestAdapter } from 'test/models.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';

const sinon = createSandbox();

describe('BaseToken', () => {
	let setup = null;
	let adapter = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	beforeEach(function () {
		adapter = TestAdapter.for('RefreshToken');
		sinon.spy(adapter, 'find');
		sinon.spy(adapter, 'upsert');
	});

	afterEach(function () {
		sinon.restore();
		timekeeper.reset();
	});

	it('handles legacy structured tokens', async function () {
		const token = await new RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = setup.getTokenJti(token);
		adapter.syncUpdate(jti, { jwt: 'foo' });
		expect(await RefreshToken.find(token)).to.be.undefined;
	});

	it('handles expired tokens', async function () {
		const token = await new RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = setup.getTokenJti(token);
		adapter.syncUpdate(jti, { exp: 0 });
		expect(await RefreshToken.find(token)).to.be.undefined;
	});

	it('handles invalid inputs', async function () {
		for (const input of [true, Boolean, 1, Infinity, {}, [], new Set()]) {
			const result = await RefreshToken.find(input);
			expect(result).to.be.undefined;
		}
	});

	it('assigns returned consumed prop', async function () {
		const token = await new RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = setup.getTokenJti(token);
		const stored = TestAdapter.for('RefreshToken').syncFind(jti);
		stored.consumed = true;
		expect(await RefreshToken.find(token)).to.have.property('consumed', true);
	});

	it('uses expiration for upsert from global settings if not specified in token values', async function () {
		const token = await new RefreshToken({ grantId: 'foo' }).save();
		const jti = setup.getTokenJti(token);
		expect(adapter.upsert.calledWith(jti, sinon.match({}), 14 * 24 * 60 * 60))
			.to.be.true;
	});

	it('uses expiration for upsert from token values', async function () {
		const token = await new RefreshToken({
			grantId: 'foo',
			expiresIn: 60
		}).save();
		const jti = setup.getTokenJti(token);
		expect(adapter.upsert.calledWith(jti, sinon.match({}), 60)).to.be.true;
	});

	it('resaves tokens with their actual remaining ttl passed to expiration', async function () {
		let token = new RefreshToken({ grantId: 'foo' });
		const value = await token.save();
		const jti = setup.getTokenJti(value);
		sinon.assert.calledWith(
			adapter.upsert.getCall(0),
			jti,
			sinon.match({}),
			sinon.match((ttl) => {
				expect(ttl).to.be.closeTo(14 * 24 * 60 * 60, 1);
				return true;
			})
		);
		timekeeper.travel((((Date.now() / 1000) | 0) + 60) * 1000); // eslint-disable-line no-bitwise
		token = await RefreshToken.find(value);
		await token.save();
		sinon.assert.calledWith(
			adapter.upsert.getCall(1),
			jti,
			sinon.match({}),
			sinon.match((ttl) => {
				expect(ttl).to.be.closeTo(14 * 24 * 60 * 60 - 60, 1);
				return true;
			})
		);
	});

	it('additional save does not change the token value', async function () {
		let token = new RefreshToken({
			grantId: 'foo'
		});
		const first = await token.save();

		token = await RefreshToken.find(first);
		expect(token.scope).to.be.undefined;
		token.scope = 'openid profile';
		const second = await token.save();

		token = await RefreshToken.find(first);
		expect(token.scope).to.equal('openid profile');
		token.scope = 'openid profile email';
		const third = await token.save();

		token = await RefreshToken.find(first);
		expect(token.scope).to.equal('openid profile email');

		expect(second).to.equal(first);
		expect(third).to.equal(second);
	});

	it('rethrows adapter#find errors from session bound tokens looking up the session', async function () {
		const token = new RefreshToken({
			expiresWithSession: true,
			sessionUid: 'foo'
		});
		const value = await token.save();
		const adapterThrow = new Error('adapter throw!');
		sinon.stub(TestAdapter.for('Session'), 'findByUid').callsFake(async () => {
			throw adapterThrow;
		});
		return assert.rejects(RefreshToken.find(value), (err) => {
			TestAdapter.for('Session').findByUid.restore();
			expect(err).to.equal(adapterThrow);
			return true;
		});
	});

	it('consumed token save saves consumed', async function () {
		let token = new AuthorizationCode({
			grantId: 'foo',
			consumed: true
		});
		const first = await token.save();

		token = await AuthorizationCode.find(first);
		expect(token.consumed).to.be.true;
	});

	it('rethrows adapter#findByUserCode errors (Device Code)', async function () {
		const adapterThrow = new Error('adapter throw!');
		sinon
			.stub(TestAdapter.for('DeviceCode'), 'findByUserCode')
			.callsFake(async () => {
				throw adapterThrow;
			});
		return assert.rejects(
			DeviceCode.findByUserCode('123-456-789').then(() => {
				TestAdapter.for('DeviceCode').findByUserCode.restore();
			}),
			(err) => {
				TestAdapter.for('DeviceCode').findByUserCode.restore();
				expect(err).to.equal(adapterThrow);
				return true;
			}
		);
	});
});
