import { expect } from 'chai';
import { describe, it } from 'bun:test';
import provider from '../../lib/index.ts';

describe('Provider configuration', () => {
	it('validates subjectTypes members', () => {
		const throws = [
			() => {
				provider.init('http://localhost:3000', {
					// eslint-disable-line no-new
					subjectTypes: ['public', 'pairwise', 'foobar']
				});
			},
			() => {
				provider.init('http://localhost:3000', {
					// eslint-disable-line no-new
					subjectTypes: ['foobar']
				});
			}
		];

		throws.forEach((fn) => {
			expect(fn).to.throw(
				'only public and pairwise subjectTypes are supported'
			);
		});
	});

	it('validates subjectTypes presence', () => {
		expect(() => {
			provider.init('http://localhost:3000', {
				// eslint-disable-line no-new
				subjectTypes: []
			});
		}).to.throw('subjectTypes must not be empty');
	});
});
