import { X509Certificate } from 'node:crypto';

import { mustChange } from './_warn.ts';

// RFC 8705 does not mandate how the TLS-terminating proxy forwards the client certificate, so the
// source expresses it as an overridable hook. The default expects the PEM/DER certificate base64
// encoded in the `x-client-cert` header; deployments whose proxy uses a different header (e.g.
// `x-ssl-client-cert`) override `features.mTLS.getCertificate`. `ctx` is the OIDCContext, whose
// `get()` reads a request header.
export function getCertificate(ctx) {
	const cert = ctx.get('x-client-cert');
	if (!cert) {
		return undefined;
	}
	try {
		return new X509Certificate(Buffer.from(cert, 'base64'));
	} catch {
		return undefined;
	}
}

export function certificateAuthorized(_ctx) {
	mustChange(
		'features.mTLS.certificateAuthorized',
		'determine if the client certificate is verified and comes from a trusted CA'
	);
	throw new Error(
		'features.mTLS.certificateAuthorized function not configured'
	);
}

export function certificateSubjectMatches(_ctx, _property, _expected) {
	mustChange(
		'features.mTLS.certificateSubjectMatches',
		'verify that the tls_client_auth_* registered client property value matches the certificate one'
	);
	throw new Error(
		'features.mTLS.certificateSubjectMatches function not configured'
	);
}
