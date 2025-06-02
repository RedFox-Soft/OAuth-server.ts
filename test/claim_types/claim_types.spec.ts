import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { agent } from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

describe('distributed and aggregated claims', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();

		i(provider).configuration.findAccount = async (ctx, id) => ({
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

	describe('userinfo', () => {
		it('should return _claim_names and _claim_sources members', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid profile'
			});

			const cookie = await setup.login({ scope: 'openid profile' });

			const authRes = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			expect(authRes.status).toBe(303);
			const location = authRes.headers.get('location');
			const code = new URL(location).searchParams.get('code');

			const res = await auth.getToken(code);
			const { access_token } = res.data;

			const { data } = await agent.userinfo.get({
				headers: {
					authorization: `Bearer ${access_token}`
				}
			});

			expect(data).toHaveProperty('nickname', 'foobar');
			expect(data).not.toHaveProperty('given_name');

			expect(data).toHaveProperty('_claim_names');
			expect(data).toHaveProperty('_claim_sources');

			expect(data._claim_names).toContainKeys(['given_name', 'family_name']);
			expect(data._claim_sources).toContainKeys(['src1', 'src2']);
		});

		it('does not return the members if these claims arent requested at all', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			const cookie = await setup.login({ scope: 'openid profile' });

			const authRes = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			expect(authRes.status).toBe(303);
			const location = authRes.headers.get('location');
			const code = new URL(location).searchParams.get('code');

			const res = await auth.getToken(code);
			const { access_token } = res.data;

			const { data } = await agent.userinfo.get({
				headers: {
					authorization: `Bearer ${access_token}`
				}
			});

			expect(data).not.toHaveProperty('_claim_names');
			expect(data).not.toHaveProperty('_claim_sources');
		});
	});
});
