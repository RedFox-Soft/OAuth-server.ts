import { beforeAll, describe, expect, it, spyOn } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { fetchAnswering } from '../fetch_mock.js';
import {
	CONNECTED_SERVICE_CATALOGUE,
	type Revocation
} from 'lib/consts/connected_service_catalogue.ts';
import type { ResolvedService } from 'lib/connected_services/catalogue.ts';
import { revokeUpstream } from 'lib/connected_services/revoke.ts';

interface Sent {
	url: string;
	method: string;
	headers: Headers;
	body: string;
}

const CLIENT = { clientId: 'project-app', clientSecret: 'project-secret' };
const TOKENS = { refreshToken: 'stored-refresh', accessToken: 'stored-access' };
const BASIC = `Basic ${Buffer.from('project-app:project-secret').toString('base64')}`;

/* The request a revocation sends, captured whole: the outbound-fetch mock matches bodies only, never headers. */
async function sentFor(revocation: Revocation): Promise<Sent | undefined> {
	const sent: Sent[] = [];
	spyOn(globalThis, 'fetch').mockImplementation(
		fetchAnswering(async (input, init) => {
			const request = new Request(input, init);
			sent.push({
				url: request.url,
				method: request.method,
				headers: request.headers,
				body: await request.text()
			});
			return new Response(JSON.stringify({ ok: true, revoked: true }), {
				status: 200,
				headers: { 'content-type': 'application/json' }
			});
		})
	);
	// Only `revocation` is read by a revocation; the rest of a resolved service is a connect flow's concern.
	const service = { revocation } as ResolvedService;
	await revokeUpstream(service, CLIENT, TOKENS);
	return sent[0];
}

/* What each provider documents (research R8), by revocation kind. */
function expectDocumentedShape(revocation: Revocation, sent: Sent | undefined) {
	switch (revocation.kind) {
		case 'form': {
			const form = new URLSearchParams(sent?.body);
			expect(sent?.method).toBe('POST');
			expect(sent?.url).toBe(revocation.url);
			expect(form.get('token')).toBe(TOKENS.refreshToken);
			expect(form.get('token_type_hint')).toBe('refresh_token');
			expect(sent?.headers.get('authorization') ?? null).toBe(
				revocation.clientAuth ? BASIC : null
			);
			return;
		}
		case 'github_grant':
			expect(sent?.method).toBe('DELETE');
			expect(sent?.url).toBe(
				revocation.urlTemplate.replace('{client_id}', CLIENT.clientId)
			);
			expect(sent?.headers.get('authorization')).toBe(BASIC);
			expect(JSON.parse(sent?.body ?? '{}')).toEqual({
				access_token: TOKENS.accessToken
			});
			return;
		case 'slack':
			expect(sent?.method).toBe('POST');
			expect(sent?.url).toBe(revocation.url);
			expect(sent?.headers.get('authorization')).toBe(
				`Bearer ${TOKENS.accessToken}`
			);
			return;
		case 'none':
			expect(sent).toBeUndefined();
	}
}

/**
 * @proves Asking a provider to revoke sends exactly the request that provider documents, for every way of revoking
 * this server knows, so a disconnect is not silently ignored upstream.
 */
describe('a revocation request', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('for every revocation kind of the catalogue and of RFC 7009, sends the documented request', async () => {
		const kinds: Revocation[] = [
			...CONNECTED_SERVICE_CATALOGUE.map((entry) => entry.revocation),
			{
				kind: 'form',
				url: 'https://notes.example.com/oauth/revoke',
				clientAuth: true
			}
		];
		for (const revocation of kinds) {
			expectDocumentedShape(revocation, await sentFor(revocation));
		}
	});
});
