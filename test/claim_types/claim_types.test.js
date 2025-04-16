import { expect } from 'chai';
import bootstrap from '../test_helper.js';

describe('distributed and aggregated claims', () => {
	before(bootstrap(import.meta.url));
	before(function () {
		i(this.provider).configuration.findAccount = (ctx, id) =>
			Promise.resolve({
				accountId: id,
				claims() {
					return {
						sub: id,
						nickname: 'foobar',
						_claim_names: {
							given_name: 'src1',
							family_name: 'src2',
							email: 'notused'
						},
						_claim_sources: {
							src1: {
								endpoint: 'https://op.example.com/me',
								access_token: 'distributed'
							},
							src2: { JWT: 'foo.bar.baz' },
							notused: { JWT: 'foo.bar.baz' }
						}
					};
				}
			});
	});

	before(function () {
		return this.login({ scope: 'openid profile' });
	});
	after(function () {
		return this.logout();
	});

	context('userinfo', () => {
		it('should return _claim_names and _claim_sources members', async function () {
			const auth = new this.AuthorizationRequest({
				response_type: 'code',
				scope: 'openid profile'
			});

			const response = await this.getToken(auth);

			const { access_token } = response.body;

			return this.agent
				.get('/me')
				.auth(access_token, { type: 'bearer' })
				.expect(200)
				.expect((response) => {
					const payload = response.body;

					expect(payload).to.have.property('nickname', 'foobar');
					expect(payload).not.to.have.property('given_name');

					expect(payload).to.have.property('_claim_names');
					expect(payload).to.have.property('_claim_sources');

					expect(payload._claim_names).to.have.keys(
						'given_name',
						'family_name'
					);
					expect(payload._claim_sources).to.have.keys('src1', 'src2');
				});
		});

		it('does not return the members if these claims arent requested at all', async function () {
			const auth = new this.AuthorizationRequest({
				response_type: 'code',
				scope: 'openid'
			});

			const response = await this.getToken(auth);
			const { access_token } = response.body;

			return this.agent
				.get('/me')
				.auth(access_token, { type: 'bearer' })
				.expect(200)
				.expect((response) => {
					const payload = response.body;

					expect(payload).not.to.have.property('_claim_names');
					expect(payload).not.to.have.property('_claim_sources');
				});
		});
	});
});
