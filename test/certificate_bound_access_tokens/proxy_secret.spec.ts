import { describe, it, expect, beforeAll } from 'bun:test';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

/*
 * TLS ends at the proxy in front of this server, so a client certificate can only arrive in a header
 * the proxy sets — and a header is something any caller can set too, unless the proxy strips it. The
 * certificate is public (a self-signed client publishes it in its key set), so a certificate header this
 * server believed without asking where it came from let anyone authenticate as a self-signed TLS client,
 * or present a stolen certificate-bound token with its certificate. The header is believed only beside a
 * secret the proxy alone holds.
 */

const crt = new X509Certificate(
	readFileSync('./test/jwks/client.crt', { encoding: 'ascii' })
);

function tokenWith(headers: Record<string, string>) {
	return agent.token.post(
		{ grant_type: 'client_credentials' },
		{
			headers: {
				...AuthorizationRequest.basicAuthHeader('client', 'secret'),
				'x-client-cert': crt.raw.toString('base64'),
				...headers
			}
		}
	);
}

/**
 * @proves A client certificate header is believed only when the proxy's secret accompanies it.
 */
describe('a client certificate forwarded in a header', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, {
			config: 'certificate_bound_access_tokens'
		});
	});

	it('is ignored without the proxy secret', async () => {
		const res = await tokenWith({});

		expect(res.status).toBe(400);
	});

	it('is ignored with a secret that is not the proxy one', async () => {
		const res = await tokenWith({ 'x-client-cert-secret': 'a guess' });

		expect(res.status).toBe(400);
	});

	it('is believed with the proxy secret', async () => {
		const res = await tokenWith({
			'x-client-cert-secret': 'test-proxy-secret'
		});

		expect(res.status).toBe(200);
	});
});
