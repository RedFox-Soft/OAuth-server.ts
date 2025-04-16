import * as url from 'node:url';

import sinon from 'sinon';
import { decodeJwt } from 'jose';
import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('responds with a id_token containing auth_time', () => {
	before(bootstrap(import.meta.url));
	before(function () {
		return this.login();
	});

	const response_type = 'code';
	const scope = 'openid';

	it('when max_age was present in the request', async function () {
		const auth = new this.AuthorizationRequest({
			response_type,
			scope,
			max_age: 999
		});

		let id_token;
		let code;

		await this.wrap({ route: '/auth', verb: 'get', auth })
			.expect(303)

			.expect(auth.validatePresence(['code', 'state']))
			.expect(auth.validateState)
			.expect(auth.validateClientLocation)
			.expect((response) => {
				({
					query: { code }
				} = url.parse(response.headers.location, true));
			});

		await auth.getToken(code).expect((response) => {
			({ id_token } = response.body);
		});

		expect(decodeJwt(id_token)).to.have.property('auth_time');
	});

	context('special cases', () => {
		const sandbox = sinon.createSandbox();

		before(function () {
			sandbox
				.stub(this.provider.OIDCContext.prototype, 'promptPending')
				.returns(false);
		});

		after(sandbox.restore);

		it('when prompt=login was requested', async function () {
			const auth = new this.AuthorizationRequest({
				response_type,
				scope,
				prompt: 'login'
			});

			let id_token;
			let code;

			await this.wrap({ route: '/auth', verb: 'get', auth })
				.expect(303)
				.expect(auth.validatePresence(['code', 'state']))
				.expect(auth.validateState)
				.expect(auth.validateClientLocation)
				.expect((response) => {
					({
						query: { code }
					} = url.parse(response.headers.location, true));
				});

			await auth.getToken(code).expect((response) => {
				({ id_token } = response.body);
			});

			expect(decodeJwt(id_token)).to.have.property('auth_time');
		});

		it('when max_age=0 was requested', async function () {
			const auth = new this.AuthorizationRequest({
				response_type,
				scope,
				max_age: 0
			});

			let id_token;
			let code;

			await this.wrap({ route: '/auth', verb: 'get', auth })
				.expect(303)
				.expect(auth.validatePresence(['code', 'state']))
				.expect(auth.validateState)
				.expect(auth.validateClientLocation)
				.expect((response) => {
					({
						query: { code }
					} = url.parse(response.headers.location, true));
				});

			await auth.getToken(code).expect((response) => {
				({ id_token } = response.body);
			});

			expect(decodeJwt(id_token)).to.have.property('auth_time');
		});

		it('when client has default_max_age=0', async function () {
			const auth = new this.AuthorizationRequest({
				response_type,
				scope,
				client_id: 'client-with-default_max_age-zero'
			});

			let id_token;
			let code;

			await this.wrap({ route: '/auth', verb: 'get', auth })
				.expect(303)
				.expect(auth.validatePresence(['code', 'state']))
				.expect(auth.validateState)
				.expect(auth.validateClientLocation)
				.expect((response) => {
					({
						query: { code }
					} = url.parse(response.headers.location, true));
				});

			await auth.getToken(code).expect((response) => {
				({ id_token } = response.body);
			});

			expect(decodeJwt(id_token)).to.have.property('auth_time');
		});
	});

	it('when client has require_auth_time', async function () {
		const auth = new this.AuthorizationRequest({
			response_type,
			scope,
			client_id: 'client-with-require_auth_time'
		});

		let id_token;
		let code;

		await this.wrap({ route: '/auth', verb: 'get', auth })
			.expect(303)
			.expect(auth.validatePresence(['code', 'state']))
			.expect(auth.validateState)
			.expect(auth.validateClientLocation)
			.expect((response) => {
				({
					query: { code }
				} = url.parse(response.headers.location, true));
			});

		await auth.getToken(code).expect((response) => {
			({ id_token } = response.body);
		});

		expect(decodeJwt(id_token)).to.have.property('auth_time');
	});

	it('when client has default_max_age', async function () {
		const auth = new this.AuthorizationRequest({
			response_type,
			scope,
			client_id: 'client-with-default_max_age'
		});

		let id_token;
		let code;

		await this.wrap({ route: '/auth', verb: 'get', auth })
			.expect(303)
			.expect(auth.validatePresence(['code', 'state']))
			.expect(auth.validateState)
			.expect(auth.validateClientLocation)
			.expect((response) => {
				({
					query: { code }
				} = url.parse(response.headers.location, true));
			});

		await auth.getToken(code).expect((response) => {
			({ id_token } = response.body);
		});

		expect(decodeJwt(id_token)).to.have.property('auth_time');
	});
});
