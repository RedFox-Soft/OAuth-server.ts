import { X509Certificate } from 'node:crypto';

import { mustChange } from './_warn.ts';
import { mtlsProxySecret } from '../configs/env.js';
import constantEquals from '../helpers/constant_equals.js';
import type { OIDCContext } from '../helpers/oidc_context.ts';

// RFC 8705 does not mandate how the TLS-terminating proxy forwards the client certificate, so the
// source expresses it as an overridable hook. The default expects the PEM/DER certificate base64
// encoded in the `x-client-cert` header; deployments whose proxy uses a different header (e.g.
// `x-ssl-client-cert`) override `features.mTLS.getCertificate`. `oidc` is the request context, whose
// `get()` reads a request header.
//
// A header is something any caller can send, and the certificate is public — a self-signed client
// publishes it in its key set — so the header is believed only beside `x-client-cert-secret` carrying
// MTLS_PROXY_SECRET, which the proxy alone holds. Without it, any caller the proxy did not strip the
// header from could authenticate as a self-signed TLS client, or present a stolen certificate-bound
// token with its certificate. No secret configured means no certificate at all.
export function getCertificate(oidc: OIDCContext) {
	const cert = oidc.get('x-client-cert');
	if (!cert) {
		return undefined;
	}
	const secret = mtlsProxySecret();
	if (!secret) {
		mustChange(
			'features.mTLS.getCertificate',
			'trust a client certificate header: set MTLS_PROXY_SECRET and have the TLS-terminating proxy send it as x-client-cert-secret (certificate headers are ignored until then)'
		);
		return undefined;
	}
	const vouched = oidc.get('x-client-cert-secret');
	if (typeof vouched !== 'string' || !constantEquals(vouched, secret)) {
		return undefined;
	}
	try {
		return new X509Certificate(Buffer.from(cert, 'base64'));
	} catch {
		return undefined;
	}
}

// Whether the client certificate is verified and chains to a trusted CA; the deployment decides.
export function certificateAuthorized(_oidc: OIDCContext): boolean {
	mustChange(
		'features.mTLS.certificateAuthorized',
		'determine if the client certificate is verified and comes from a trusted CA'
	);
	throw new Error(
		'features.mTLS.certificateAuthorized function not configured'
	);
}

export function certificateSubjectMatches(
	_oidc: OIDCContext,
	_property: string,
	_expected: string
): boolean {
	mustChange(
		'features.mTLS.certificateSubjectMatches',
		'verify that the tls_client_auth_* registered client property value matches the certificate one'
	);
	throw new Error(
		'features.mTLS.certificateSubjectMatches function not configured'
	);
}
