import { describe, it, beforeEach, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from '../../lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import {
	renderSecurityTxt,
	SECURITY_CONTACT,
	SECURITY_POLICY_URL
} from 'lib/actions/security_txt.ts';

const DAY = 86_400_000;

// RFC 9116: Contact and Expires are required, Expires is ISO 8601 and should be under a year away,
// Canonical names the URL the file is served from, Policy points at the disclosure policy.
describe('GET /.well-known/security.txt', () => {
	beforeEach(async () => {
		await bootstrap(import.meta.url);
	});

	it('is served as plain text with the required fields', async () => {
		const res = await elysia.handle(
			new Request(`${ISSUER}/.well-known/security.txt`)
		);
		expect(res.status).toBe(200);
		expect(res.headers.get('content-type')).toBe('text/plain; charset=utf-8');

		const body = await res.text();
		expect(body).toContain(`Contact: ${SECURITY_CONTACT}`);
		expect(body).toContain(`Canonical: ${ISSUER}/.well-known/security.txt`);
		expect(body).toContain(`Policy: ${SECURITY_POLICY_URL}`);
		expect(body).toMatch(
			/^Expires: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/m
		);
		expect(body.endsWith('\n')).toBe(true);
	});

	it('expires in the future and within a year', () => {
		const now = new Date('2026-09-02T12:00:00.000Z');
		const line = renderSecurityTxt(now)
			.split('\n')
			.find((l) => l.startsWith('Expires: '));
		const expires = new Date((line as string).slice('Expires: '.length));
		expect(expires.getTime()).toBeGreaterThan(now.getTime());
		expect(expires.getTime()).toBeLessThan(now.getTime() + 365 * DAY);
	});

	it('names a mailto contact and an https policy', () => {
		expect(SECURITY_CONTACT.startsWith('mailto:')).toBe(true);
		expect(SECURITY_POLICY_URL.startsWith('https://')).toBe(true);
	});
});
