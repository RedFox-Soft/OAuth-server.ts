import htmlSafe from '../../lib/helpers/html_safe.ts';

describe('htmlSafe helper', () => {
	it('handles numbers', () => {
		expect(htmlSafe(1)).toEqual('1');
		expect(htmlSafe(1.1)).toEqual('1.1');
	});

	it('handles non finites', () => {
		expect(htmlSafe(NaN)).toEqual('');
		expect(htmlSafe(Infinity)).toEqual('');
		expect(htmlSafe(-Infinity)).toEqual('');
	});

	it('handles strings', () => {
		expect(htmlSafe('foobar&<>"\'')).toEqual('foobar&amp;&lt;&gt;&quot;&#39;');
		expect(htmlSafe('')).toEqual('');
	});

	it('handles booleans', () => {
		expect(htmlSafe(false)).toEqual('false');
		expect(htmlSafe(true)).toEqual('true');
	});

	it('handles the rest', () => {
		expect(htmlSafe(null)).toEqual('');
		expect(htmlSafe(undefined)).toEqual('');
	});
});
