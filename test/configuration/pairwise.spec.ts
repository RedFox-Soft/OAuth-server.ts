import { expect } from 'chai';
import { describe, it } from 'bun:test';
import provider from '../../lib/index.ts';

describe('Provider configuration', () => {
	it('validates subjectTypes members', () => {
		const throws = [
			() => {
				provider.init({
					subjectTypes: ['public', 'pairwise', 'foobar']
				});
			},
			() => {
				provider.init({ subjectTypes: ['foobar'] });
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
			provider.init({ subjectTypes: [] });
		}).to.throw('subjectTypes must not be empty');
	});
});
