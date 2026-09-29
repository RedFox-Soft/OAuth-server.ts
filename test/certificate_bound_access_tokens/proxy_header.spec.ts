import { describe, it, expect, beforeAll, afterEach } from 'bun:test';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * TLS ends at the proxy in front of this server, so a client certificate can only arrive in a header the
 * proxy sets — and any caller can send a header, while the certificate itself is public (a self-signed
 * client publishes it in its key set). Believing the header is safe only when the proxy removes or
 * overwrites it on every incoming request, as RFC 9440 requires of it, and that is a fact about the
 * deployment. So the header is read only when the operator has said so, and then in RFC 9440's
 * `Client-Cert` form as well as the older bare base64 `x-client-cert`.
 */

const crt = new X509Certificate(
	readFileSync('./test/jwks/client.crt', { encoding: 'ascii' })
);
const trusted = ApplicationConfig['mTLS.trustProxyCertificateHeader'];

function tokenWith(headers: Record<string, string>) {
	return agent.token.post(
		{ grant_type: 'client_credentials' },
		{
			headers: {
				...AuthorizationRequest.basicAuthHeader('client', 'secret'),
				...headers
			}
		}
	);
}

/**
 * @proves A forwarded client certificate is read only when the operator states that the proxy sets
 * the header, and is then read from RFC 9440's Client-Cert or the older x-client-cert.
 */
describe('a client certificate forwarded in a header', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, {
			config: 'certificate_bound_access_tokens'
		});
	});

	afterEach(() => {
		ApplicationConfig['mTLS.trustProxyCertificateHeader'] = trusted;
	});

	it('is ignored while the operator has not said the proxy sets it', async () => {
		ApplicationConfig['mTLS.trustProxyCertificateHeader'] = false;

		const res = await tokenWith({
			'x-client-cert': crt.raw.toString('base64')
		});

		expect(res.status).toBe(400);
	});

	it('is read from the RFC 9440 Client-Cert field once the operator has', async () => {
		ApplicationConfig['mTLS.trustProxyCertificateHeader'] = true;

		const res = await tokenWith({
			'client-cert': `:${crt.raw.toString('base64')}:`
		});

		expect(res.status).toBe(200);
	});

	it('is read from the older x-client-cert once the operator has', async () => {
		ApplicationConfig['mTLS.trustProxyCertificateHeader'] = true;

		const res = await tokenWith({
			'x-client-cert': crt.raw.toString('base64')
		});

		expect(res.status).toBe(200);
	});

	it('ignores a Client-Cert that is not a structured-field byte sequence', async () => {
		ApplicationConfig['mTLS.trustProxyCertificateHeader'] = true;

		const res = await tokenWith({ 'client-cert': crt.raw.toString('base64') });

		expect(res.status).toBe(400);
	});
});
