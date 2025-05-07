/* eslint-disable no-new */

import { strict as assert } from 'node:assert';

import { expect } from 'chai';
import { describe, it } from 'bun:test';
import provider from '../../lib/index.ts';

describe('Provider issuer configuration', () => {
	it('validates the issuer input to be present and valid', () => {
		expect(() => {
			provider.init();
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init({});
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init(0);
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init(true);
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('https://op.example.com?');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('https://op.example.com?query');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('https://op.example.com?query=complete');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('https://op.example.com#fragment');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('https://op.example.com?query=and#fragment');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('foobar');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('foobar:');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('foobar://');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('op.example.com');
		}).to.throw(assert.AssertionError);
		expect(() => {
			provider.init('op.example.com:443');
		}).to.throw(assert.AssertionError);
	});
});

/* eslint-enable no-new */
