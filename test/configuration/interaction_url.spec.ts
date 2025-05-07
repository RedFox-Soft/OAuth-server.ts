import { expect } from 'chai';
import { describe, it } from 'bun:test';
import provider from '../../lib/index.ts';

describe('pathFor related behaviors', () => {
	it('throws an Error when invalid route path is requested', () => {
		provider.init('http://localhost');
		expect(provider.pathFor('authorization')).to.equal('/auth');
		expect(() => provider.pathFor('foobar')).to.throw(
			Error,
			'No route found for name: foobar'
		);
	});

	it('interactionUrl resolves to /interaction/uid when devInteractions is disabled', async () => {
		provider.init('http://localhost', {
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
