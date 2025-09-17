import { expect } from 'chai';

import bootstrap from '../test_helper.js';
import { decode } from '../../lib/helpers/jwt.ts';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';

describe('signatures', () => {
	before(bootstrap(import.meta.url));

	describe('when id_token_signed_response_alg=HS256', () => {
		before(function () {
			return this.login();
		});

		beforeEach(async function () {
			const ac = new AuthorizationCode({
				accountId: this.loggedInAccountId,
				acr: i(provider).configuration.acrValues[0],
				authTime: epochTime(),
				clientId: 'client-sig-HS256',
				grantId: this.getGrantId('client-sig-HS256'),
				redirectUri: 'https://client.example.com/cb',
				scope: 'openid'
			});

			return this.agent
				.post('/token')
				.auth('client-sig-HS256', 'secret')
				.type('form')
				.send({
					redirect_uri: 'https://client.example.com/cb',
					grant_type: 'authorization_code',
					code: await ac.save()
				})
				.expect(200)
				.expect((response) => {
					this.idToken = response.body.id_token;
				});
		});

		it('issues an HS256 signed id_token', function () {
			const components = this.idToken.split('.');
			expect(components).to.have.lengthOf(3);
			expect(components[2]).not.to.equal('');
			expect(decode(this.idToken)).to.have.nested.property(
				'header.alg',
				'HS256'
			);
		});

		it('the HS256 signed token can be used as id_token_hint', function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				prompt: 'none',
				id_token_hint: this.idToken
			});
			auth.clientId = 'client-sig-HS256';

			return this.wrap({ auth, route: '/auth', verb: 'get' })
				.expect(303)
				.expect(auth.validatePresence(['code', 'state']))
				.expect(auth.validateState)
				.expect(auth.validateClientLocation);
		});
	});
});
