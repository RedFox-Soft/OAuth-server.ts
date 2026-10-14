/*
 * A browser walking a sign-in by hand, shared by the language-switch specs: it keeps its cookies and always
 * sends the same Accept-Language, as a real one would.
 */

import { expect } from 'bun:test';

import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { encodeParams } from '../test_helper.js';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.ts';

export const PASSWORD = 'correct horse battery';

export class Browser {
	#jar = new Map<string, string>();
	readonly setCookies: string[] = [];

	constructor(readonly acceptLanguage?: string) {}

	async request(path: string, init: RequestInit = {}) {
		const headers = new Headers(init.headers);
		if (this.acceptLanguage)
			headers.set('accept-language', this.acceptLanguage);
		if (this.cookie) headers.set('cookie', this.cookie);
		const response = await elysia.handle(
			new Request(`${ISSUER}${path}`, { ...init, headers })
		);
		for (const set of response.headers.getSetCookie()) {
			this.setCookies.push(set);
			const [pair] = set.split(';');
			const at = pair.indexOf('=');
			const name = pair.slice(0, at);
			const value = pair.slice(at + 1);
			if (!value || set.includes('Thu, 01 Jan 1970')) this.#jar.delete(name);
			else this.#jar.set(name, value);
		}
		return response;
	}

	post(path: string, fields: Record<string, string>) {
		return this.request(path, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams(fields)
		});
	}

	async page(path: string) {
		const response = await this.request(path);
		return { response, html: await response.text() };
	}

	/* Follows this server's redirects until a page answers. */
	async follow(response: Response) {
		let location = response.headers.get('location') ?? '';
		for (let hop = 0; hop < 6 && location.startsWith('/'); hop++) {
			const next = await this.request(location);
			if (next.status !== 302 && next.status !== 303) {
				return { location, html: await next.text() };
			}
			location = next.headers.get('location') ?? '';
		}
		return { location, html: '' };
	}

	get cookie() {
		return [...this.#jar].map(([k, v]) => `${k}=${v}`).join('; ');
	}

	/* Starts a sign-in at the application and answers the interaction's uid. */
	async startSignIn(params: Record<string, string> = {}) {
		const auth = new AuthorizationRequest({
			client_id: 'i18n-app',
			scope: 'openid',
			...params
		});
		const started = await this.request(`/auth?${encodeParams(auth.params)}`);
		expect(started.status).toBe(303);
		const location = started.headers.get('location') ?? '';
		return { uid: location.split('/')[2] ?? '', location };
	}
}

export function langOf(html: string): string | undefined {
	return /<html lang="([^"]+)"/.exec(html)?.[1];
}

/* The language switch on a page: where it posts, what it offers and in which language it names it. */
export function switchOf(html: string) {
	const form =
		/<form[^>]*action="(\/ui\/[^"]+\/language)"[^>]*>([\s\S]*?)<\/form>/.exec(
			html
		);
	if (!form) return undefined;
	return {
		action: form[1],
		lang: /name="lang" value="([^"]+)"/.exec(form[2])?.[1],
		page: /name="page" value="([^"]+)"/.exec(form[2])?.[1],
		button: /<button[^>]*lang="([^"]+)"[^>]*>([^<]+)<\/button>/.exec(form[2])
	};
}
