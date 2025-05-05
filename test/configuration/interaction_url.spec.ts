import { expect } from 'chai';

import provider from '../../lib/index.ts';

describe('pathFor related behaviors', () => {
	it('throws an Error when invalid route path is requested', () => {
		const provider = new provider('http://localhost');
		expect(provider.pathFor('authorization')).to.equal('/auth');
		expect(() => provider.pathFor('foobar')).to.throw(
			Error,
			'No route found for name: foobar'
		);
	});

	it('interactionUrl resolves to /interaction/uid when devInteractions is disabled', async () => {
		const provider = new provider('http://localhost', {
			features: {
				devInteractions: { enabled: false }
			}
		});

		const url = await i(provider).configuration.interactions.url(
			{},
			new provider.Interaction('foobar', {})
		);

		expect(url).to.equal('/interaction/foobar');
	});
});
