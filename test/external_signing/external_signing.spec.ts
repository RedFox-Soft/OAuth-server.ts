import { expect } from 'chai';

import * as jose from 'jose';

import bootstrap, {
	enableNetConnect,
	resetNetConnect
} from '../test_helper.js';

const response_type = 'code';
const scope = 'openid';

describe('External Signing Keys', () => {
	before(enableNetConnect);
	before(bootstrap(import.meta.url));
	before(function () {
		return this.login();
	});
	after(resetNetConnect);

	it('still signs with in-process JWKS', async function () {
		const auth = new this.AuthorizationRequest({
			client_id: 'client-sig-internal',
			response_type,
			scope
		});

		const response = await this.getToken(auth);
		expect(response.body).to.have.property('id_token');
	});

	it('but signs with external keys too and verifies them local', async function () {
		const auth = new this.AuthorizationRequest({
			client_id: 'client-sig-external',
			response_type,
			scope
		});

		let response = await this.getToken(auth);
		expect(response.body).to.have.property('id_token');
		let id_token = response.body.id_token;

		await jose.compactVerify(
			id_token,
			jose.createRemoteJWKSet(
				new URL(this.provider.issuer + this.suitePath('/jwks'))
			)
		);

		auth.id_token_hint = id_token;

		response = await this.getToken(auth);
		expect(response.body).to.have.property('id_token');
	});
});
