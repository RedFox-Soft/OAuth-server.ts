import { strict as assert } from 'node:assert';

import { createSandbox } from 'sinon';
import { expect } from 'chai';
import timekeeper from 'timekeeper';

import bootstrap from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { TestAdapter } from 'test/models.js';

const sinon = createSandbox();

describe('BaseToken', () => {
	before(bootstrap(import.meta.url));

	beforeEach(function () {
		this.adapter = TestAdapter.for('RefreshToken');
		sinon.spy(this.adapter, 'find');
		sinon.spy(this.adapter, 'upsert');
	});

	afterEach(timekeeper.reset);
	afterEach(sinon.restore);

	it('handles legacy structured tokens', async function () {
		const token = await new provider.RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = this.getTokenJti(token);
		this.adapter.syncUpdate(jti, {
			jwt: 'foo'
		});
		expect(await provider.RefreshToken.find(token)).to.be.undefined;
	});

	it('handles expired tokens', async function () {
		const token = await new provider.RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = this.getTokenJti(token);
		this.adapter.syncUpdate(jti, {
			exp: 0
		});
		expect(await provider.RefreshToken.find(token)).to.be.undefined;
	});

	it('handles invalid inputs', async function () {
		for (const input of [true, Boolean, 1, Infinity, {}, [], new Set()]) {
			const result = await provider.RefreshToken.find(input);
			expect(result).to.be.undefined;
		}
	});

	it('assigns returned consumed prop', async function () {
		const token = await new provider.RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = this.getTokenJti(token);
		const stored = TestAdapter.for('RefreshToken').syncFind(jti);
		stored.consumed = true;
		expect(await provider.RefreshToken.find(token)).to.have.property(
			'consumed',
			true
		);
	});

	it('uses expiration for upsert from global settings if not specified in token values', async function () {
		const token = await new provider.RefreshToken({
			grantId: 'foo'
		}).save();
		const jti = this.getTokenJti(token);
		expect(
			this.adapter.upsert.calledWith(jti, sinon.match({}), 14 * 24 * 60 * 60)
		).to.be.true;
	});

	it('uses expiration for upsert from token values', async function () {
		const token = await new provider.RefreshToken({
			grantId: 'foo',
			expiresIn: 60
		}).save();
		const jti = this.getTokenJti(token);
		expect(this.adapter.upsert.calledWith(jti, sinon.match({}), 60)).to.be.true;
	});

	it('resaves tokens with their actual remaining ttl passed to expiration', async function () {
		this.retries(1);

		let token = new provider.RefreshToken({
			grantId: 'foo'
		});
		const value = await token.save();
		const jti = this.getTokenJti(value);
		sinon.assert.calledWith(
			this.adapter.upsert.getCall(0),
			jti,
			sinon.match({}),
			sinon.match((ttl) => {
				expect(ttl).to.be.closeTo(14 * 24 * 60 * 60, 1);
				return true;
			})
		);
		timekeeper.travel((((Date.now() / 1000) | 0) + 60) * 1000); // eslint-disable-line no-bitwise
		token = await provider.RefreshToken.find(value);
		await token.save();
		sinon.assert.calledWith(
			this.adapter.upsert.getCall(1),
			jti,
			sinon.match({}),
			sinon.match((ttl) => {
				expect(ttl).to.be.closeTo(14 * 24 * 60 * 60 - 60, 1);
				return true;
			})
		);
	});

	it('additional save does not change the token value', async function () {
		let token = new provider.RefreshToken({
			grantId: 'foo'
		});
		const first = await token.save();

		token = await provider.RefreshToken.find(first);
		expect(token.scope).to.be.undefined;
		token.scope = 'openid profile';
		const second = await token.save();

		token = await provider.RefreshToken.find(first);
		expect(token.scope).to.equal('openid profile');
		token.scope = 'openid profile email';
		const third = await token.save();

		token = await provider.RefreshToken.find(first);
		expect(token.scope).to.equal('openid profile email');

		expect(second).to.equal(first);
		expect(third).to.equal(second);
	});

	it('rethrows adapter#find errors from session bound tokens looking up the session', async function () {
		const token = new provider.RefreshToken({
			expiresWithSession: true,
			sessionUid: 'foo'
		});
		const value = await token.save();
		const adapterThrow = new Error('adapter throw!');
		sinon.stub(TestAdapter.for('Session'), 'findByUid').callsFake(async () => {
			throw adapterThrow;
		});
		return assert.rejects(provider.RefreshToken.find(value), (err) => {
			TestAdapter.for('Session').findByUid.restore();
			expect(err).to.equal(adapterThrow);
			return true;
		});
	});

	it('consumed token save saves consumed', async function () {
		let token = new provider.AuthorizationCode({
			grantId: 'foo',
			consumed: true
		});
		const first = await token.save();

		token = await provider.AuthorizationCode.find(first);
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
