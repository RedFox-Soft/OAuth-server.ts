/* eslint-disable no-new */

import { strict as assert } from 'node:assert';

import { expect } from 'chai';

import provider from '../../lib/index.ts';

describe('Provider issuer configuration', () => {
	it('validates the issuer input to be present and valid', () => {
		expect(() => {
			new provider();
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider({});
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider(0);
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider(true);
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('https://op.example.com?');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('https://op.example.com?query');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('https://op.example.com?query=complete');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('https://op.example.com#fragment');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('https://op.example.com?query=and#fragment');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('foobar');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('foobar:');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('foobar://');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('op.example.com');
		}).to.throw(assert.AssertionError);
		expect(() => {
			new provider('op.example.com:443');
		}).to.throw(assert.AssertionError);
	});
});

/* eslint-enable no-new */
