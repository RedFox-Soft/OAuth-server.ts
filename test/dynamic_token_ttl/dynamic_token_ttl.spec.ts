import * as url from 'node:url';

import { expect } from 'chai';
import sinon from 'sinon';
import cloneDeep from 'lodash/cloneDeep.js';

import bootstrap, { skipConsent } from '../test_helper.js';
import { IdToken } from 'lib/models/id_token.js';
import { Client } from 'lib/models/client.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { TestAdapter } from 'test/models.js';

describe('dynamic ttl', () => {
	before(bootstrap(import.meta.url));
	skipConsent();
	before(function () {
		this.prev = cloneDeep(i(provider).configuration.ttl);
	});
	afterEach(function () {
		i(provider).configuration.ttl = this.prev;
	});
	before(function () {
		return this.login({ scope: 'openid offline_access' });
	});

	it('client credentials', async function () {
		const ClientCredentials = sinon.fake.returns(123);
		i(provider).configuration.ttl.ClientCredentials = ClientCredentials;

		await this.agent
			.post('/token')
			.send({
				client_id: 'client',
				grant_type: 'client_credentials'
			})
			.type('form')
			.expect(200)
			.expect(({ body: { expires_in } }) => {
				expect(expires_in).to.eql(123);
			});

		expect(ClientCredentials).to.have.property('calledOnce', true);
		expect(ClientCredentials.args[0][1]).to.be.an.instanceof(
			provider.ClientCredentials
		);
		expect(ClientCredentials.args[0][2]).to.be.an.instanceof(provider.Client);
	});

	it('device flow init', async function () {
		const DeviceCodeFunc = sinon.fake.returns(123);
		i(provider).configuration.ttl.DeviceCode = DeviceCodeFunc;

		let device_code;
		await this.agent
			.post('/device/auth')
			.send({
				client_id: 'client',
				scope: 'openid offline_access',
				prompt: 'consent'
			})
			.type('form')
			.expect(200)
			.expect(({ body: { expires_in, device_code: dc } }) => {
				expect(expires_in).to.eql(123);
				device_code = dc;
			});

		expect(DeviceCodeFunc).to.have.property('calledOnce', true);
		expect(DeviceCodeFunc.args[0][1]).to.be.an.instanceof(DeviceCode);
		expect(DeviceCodeFunc.args[0][2]).to.be.an.instanceof(provider.Client);

		TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(device_code), {
			scope: 'openid offline_access',
			accountId: this.loggedInAccountId,
			grantId: this.getGrantId('client')
		});

		const IdTokenFunc = sinon.fake.returns(123);
		const AccessToken = sinon.fake.returns(1234);
		const RefreshToken = sinon.fake.returns(12345);
		i(provider).configuration.ttl.IdToken = IdTokenFunc;
		i(provider).configuration.ttl.AccessToken = AccessToken;
		i(provider).configuration.ttl.RefreshToken = RefreshToken;

		await this.agent
			.post('/token')
			.send({
				client_id: 'client',
				grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
				device_code
			})
			.type('form')
			.expect(200);

		expect(IdTokenFunc).to.have.property('calledOnce', true);
		expect(IdTokenFunc.args[0][1]).to.be.an.instanceof(IdToken);
		expect(IdTokenFunc.args[0][2]).to.be.an.instanceof(Client);

		expect(AccessToken).to.have.property('calledOnce', true);
		expect(AccessToken.args[0][1]).to.be.an.instanceof(provider.AccessToken);
		expect(AccessToken.args[0][2]).to.be.an.instanceof(Client);

		expect(RefreshToken).to.have.property('calledOnce', true);
		expect(RefreshToken.args[0][1]).to.be.an.instanceof(provider.RefreshToken);
		expect(RefreshToken.args[0][2]).to.be.an.instanceof(Client);
	});

	it('authorization flow returned tokens', async function () {
		const AuthorizationCode = sinon.fake.returns(12);
		i(provider).configuration.ttl.AuthorizationCode = AuthorizationCode;

		const auth = new AuthorizationRequest({ scope: 'openid' });

		await this.wrap({ route: '/auth', verb: 'get', auth }).expect(303);

		expect(AuthorizationCode).to.have.property('calledOnce', true);
		expect(AuthorizationCode.args[0][1]).to.be.an.instanceof(
			provider.AuthorizationCode
		);
		expect(AuthorizationCode.args[0][2]).to.be.an.instanceof(provider.Client);
	});

	it('authorization code', async function () {
		const IdTokenFunc = sinon.fake.returns(123);
		const AccessToken = sinon.fake.returns(1234);
		const RefreshToken = sinon.fake.returns(12345);
		i(provider).configuration.ttl.IdToken = IdTokenFunc;
		i(provider).configuration.ttl.AccessToken = AccessToken;
		i(provider).configuration.ttl.RefreshToken = RefreshToken;

		const auth = new AuthorizationRequest({
			scope: 'openid offline_access',
			prompt: 'consent'
		});

		let code;

		await this.wrap({ route: '/auth', verb: 'get', auth })
			.expect(303)
			.expect(({ headers: { location } }) => {
				({
					query: { code }
				} = url.parse(location, true));
			});

		await this.agent
			.post('/token')
			.send({
				client_id: 'client',
				grant_type: 'authorization_code',
				code_verifier: auth.code_verifier,
				code,
				redirect_uri: 'https://rp.example.com/cb'
			})
			.type('form')
			.expect(200);

		expect(IdTokenFunc).to.have.property('calledOnce', true);
		expect(IdTokenFunc.args[0][1]).to.be.an.instanceof(IdToken);
		expect(IdTokenFunc.args[0][2]).to.be.an.instanceof(Client);

		expect(AccessToken).to.have.property('calledOnce', true);
		expect(AccessToken.args[0][1]).to.be.an.instanceof(provider.AccessToken);
		expect(AccessToken.args[0][2]).to.be.an.instanceof(Client);

		expect(RefreshToken).to.have.property('calledOnce', true);
		expect(RefreshToken.args[0][1]).to.be.an.instanceof(provider.RefreshToken);
		expect(RefreshToken.args[0][2]).to.be.an.instanceof(Client);
	});

	it('refreshed tokens', async function () {
		const auth = new AuthorizationRequest({
			scope: 'openid offline_access',
			prompt: 'consent'
		});

		let code;

		await this.wrap({ route: '/auth', verb: 'get', auth })
			.expect(303)
			.expect(({ headers: { location } }) => {
				({
					query: { code }
				} = url.parse(location, true));
			});

		let refresh_token;

		await this.agent
			.post('/token')
			.send({
				client_id: 'client',
				grant_type: 'authorization_code',
				code_verifier: auth.code_verifier,
				code,
				redirect_uri: 'https://rp.example.com/cb'
			})
			.type('form')
			.expect(200)
			.expect(({ body: { refresh_token: rt } }) => {
				refresh_token = rt;
			});

		const IdTokenFunc = sinon.fake.returns(123);
		const AccessToken = sinon.fake.returns(1234);
		const RefreshToken = sinon.fake.returns(12345);
		i(provider).configuration.ttl.IdToken = IdTokenFunc;
		i(provider).configuration.ttl.AccessToken = AccessToken;
		i(provider).configuration.ttl.RefreshToken = RefreshToken;

		await this.agent
			.post('/token')
			.send({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token,
				redirect_uri: 'https://rp.example.com/cb'
			})
			.type('form')
			.expect(200);

		expect(IdTokenFunc).to.have.property('calledOnce', true);
		expect(IdTokenFunc.args[0][1]).to.be.an.instanceof(IdToken);
		expect(IdTokenFunc.args[0][2]).to.be.an.instanceof(Client);

		expect(AccessToken).to.have.property('calledOnce', true);
		expect(AccessToken.args[0][1]).to.be.an.instanceof(provider.AccessToken);
		expect(AccessToken.args[0][2]).to.be.an.instanceof(Client);

		expect(RefreshToken).to.have.property('calledOnce', true);
		expect(RefreshToken.args[0][1]).to.be.an.instanceof(provider.RefreshToken);
		expect(RefreshToken.args[0][2]).to.be.an.instanceof(Client);
	});
});
