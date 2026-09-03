import { Elysia } from 'elysia';
import { ISSUER } from 'lib/configs/env.js';

export const SECURITY_CONTACT = 'mailto:security@foxauth.dev';
export const SECURITY_POLICY_URL =
	'https://github.com/RedFox-Soft/OAuth-server.ts/blob/main/SECURITY.md';

/*
 * Ninety days, computed per request. RFC 9116 wants Expires under a year out and the file kept fresh;
 * a fixed date would go stale in the repository and start refusing researchers the day it passed.
 */
export const SECURITY_TXT_VALIDITY_DAYS = 90;

export function renderSecurityTxt(now: Date): string {
	const expires = new Date(
		now.getTime() + SECURITY_TXT_VALIDITY_DAYS * 86_400_000
	);
	return `${[
		`Contact: ${SECURITY_CONTACT}`,
		`Expires: ${expires.toISOString()}`,
		`Canonical: ${ISSUER}/.well-known/security.txt`,
		`Policy: ${SECURITY_POLICY_URL}`,
		'Preferred-Languages: en'
	].join('\n')}\n`;
}

/*
 * The contact is the project's. Every self-hosted instance therefore tells a researcher where to
 * report a defect in the software, which is the right answer for a bug in this code; an operator who
 * wants their own contact on their own domain serves the file from their edge in front of this one.
 */
export const securityTxt = new Elysia().get(
	'/.well-known/security.txt',
	() =>
		new Response(renderSecurityTxt(new Date()), {
			headers: { 'content-type': 'text/plain; charset=utf-8' }
		})
);
