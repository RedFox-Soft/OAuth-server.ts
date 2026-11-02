import { guardedFetch } from '../shared/egress.js';
import type { RevocationOutcome } from '../event_bus.js';
import type { ResolvedService } from './catalogue.js';

/*
 * Asking a provider to revoke what it issued (specs/117 R8). Always after the local record is gone, so a
 * provider that hangs or refuses can never keep a token here; the outcome only decides what the person is
 * told and which event says what happened.
 */

/*
 * Four seconds, not the five client notifications take: a person's disconnect waits for this, and the whole
 * disconnect is promised within five (SC-007).
 */
export const REVOCATION_TIMEOUT_MS = 4_000;

export interface RevocableTokens {
	refreshToken?: string;
	accessToken?: string;
}

function basic(clientId: string, clientSecret: string): string {
	const credentials = `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`;
	return `Basic ${Buffer.from(credentials).toString('base64')}`;
}

async function sent(request: Promise<Response>): Promise<RevocationOutcome> {
	try {
		const response = await request;
		return response.ok ? 'revoked' : 'failed';
	} catch {
		return 'failed';
	}
}

export async function revokeUpstream(
	service: ResolvedService,
	client: { clientId: string; clientSecret?: string },
	tokens: RevocableTokens
): Promise<RevocationOutcome> {
	const revocation = service.revocation;
	if (revocation.kind === 'none') return 'not_supported';
	if (!tokens.refreshToken && !tokens.accessToken) return 'unreadable';

	switch (revocation.kind) {
		case 'form': {
			// The refresh token where there is one: revoking it ends the grant, which revoking an access token may not.
			const token = tokens.refreshToken ?? tokens.accessToken ?? '';
			const body = new URLSearchParams({
				token,
				token_type_hint: tokens.refreshToken ? 'refresh_token' : 'access_token'
			});
			const headers: Record<string, string> = {
				'content-type': 'application/x-www-form-urlencoded'
			};
			if (revocation.clientAuth) {
				if (!client.clientSecret) return 'failed';
				headers.authorization = basic(client.clientId, client.clientSecret);
			}
			return sent(
				guardedFetch(revocation.url, {
					method: 'POST',
					headers,
					body,
					timeoutMs: REVOCATION_TIMEOUT_MS
				})
			);
		}
		case 'github_grant': {
			if (!tokens.accessToken || !client.clientSecret) return 'failed';
			return sent(
				guardedFetch(
					revocation.urlTemplate.replace(
						'{client_id}',
						encodeURIComponent(client.clientId)
					),
					{
						method: 'DELETE',
						headers: {
							authorization: basic(client.clientId, client.clientSecret),
							accept: 'application/vnd.github+json',
							'content-type': 'application/json',
							'user-agent': 'FoxAuth'
						},
						body: JSON.stringify({ access_token: tokens.accessToken }),
						timeoutMs: REVOCATION_TIMEOUT_MS
					}
				)
			);
		}
		case 'slack': {
			if (!tokens.accessToken) return 'failed';
			try {
				const response = await guardedFetch(revocation.url, {
					method: 'POST',
					headers: {
						authorization: `Bearer ${tokens.accessToken}`,
						'content-type': 'application/x-www-form-urlencoded'
					},
					body: new URLSearchParams(),
					timeoutMs: REVOCATION_TIMEOUT_MS
				});
				if (!response.ok) return 'failed';
				// Slack answers 200 for everything; `ok` is the answer.
				const answer: unknown = await response.json();
				return typeof answer === 'object' &&
					answer !== null &&
					'ok' in answer &&
					answer.ok === true
					? 'revoked'
					: 'failed';
			} catch {
				return 'failed';
			}
		}
	}
}
