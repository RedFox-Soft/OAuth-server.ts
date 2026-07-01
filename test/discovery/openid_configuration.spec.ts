import { describe, it, beforeAll, afterEach } from 'bun:test';
import { expect } from 'chai';
import { createSandbox } from 'sinon';

import bootstrap, { agent } from '../test_helper.js';
import { provider } from 'lib/provider.js';

const sinon = createSandbox();

const discoveryEndpoint = agent['.well-known']['openid-configuration'];

describe('/.well-known/openid-configuration', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	it('responds with json 200', async () => {
		const { status, response } = await discoveryEndpoint.get();

		expect(status).to.equal(200);
		expect(response.headers.get('content-type')).to.match(/application\/json/);
	});

	it('is configurable with extra properties', async () => {
		i(provider).configuration.discovery.service_documentation =
			'https://docs.example.com';
		i(provider).configuration.discovery.authorization_endpoint =
			'this will not be used';

		const { data } = await discoveryEndpoint.get();

		expect(data).to.have.property(
			'service_documentation',
			'https://docs.example.com'
		);
		expect(data.authorization_endpoint).not.to.equal('this will not be used');
	});

	describe('with unexpected exceptions', () => {
		afterEach(() => sinon.restore());

		it('handles exceptions with json 500 and emits server_error', async () => {
			const spy = sinon.spy();
			provider.once('server_error', spy);
			// Force the discovery handler to throw while it applies discovery overrides.
			sinon.stub(i(provider).configuration, 'discovery').get(() => {
				throw new Error('oops! something went wrong');
			});

			const { error } = await discoveryEndpoint.get();

			expect(error.status).to.equal(500);
			expect(error.value).to.eql({
				error: 'server_error',
				error_description: 'An unexpected error occurred'
			});
			expect(spy.calledOnce).to.be.true;
		});
	});
});
