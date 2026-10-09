import { X509Certificate } from 'node:crypto';

import { mustChange } from './_warn.ts';
import { ApplicationConfig } from '../configs/application.js';
import type { OIDCContext } from '../helpers/oidc_context.ts';

/*
 * The client certificate a TLS-terminating proxy forwarded, or undefined.
 *
 * RFC 8705 leaves how the certificate reaches the server to the deployment; RFC 9440 standardises the
 * `Client-Cert` header for it — the DER certificate as a structured-field byte sequence, `:<base64>:` —
 * and a bare base64 `x-client-cert`, which proxies configured before RFC 9440 send, is read when that is
 * absent. A deployment whose proxy uses yet another header overrides `features.mTLS.getCertificate`.
 *
 * Read only when `mTLS.trustProxyCertificateHeader` says so. A header is something any caller can send
 * and the certificate is public — a self-signed client publishes it in its key set — so believing the
 * header is safe only when the proxy removes or overwrites it on every incoming request, as RFC 9440
 * requires of it. Whether it does is a fact about the deployment this server cannot observe, so the
 * operator states it; until they do, no certificate is read at all.
 */
export function getCertificate(oidc: OIDCContext) {
	const standard = oidc.get('client-cert');
	const legacy = oidc.get('x-client-cert');
	if (!standard && !legacy) {
		return undefined;
	}
	if (!ApplicationConfig['mTLS.trustProxyCertificateHeader']) {
		mustChange(
			'features.mTLS.getCertificate',
			'read a forwarded client certificate: switch on mTLS.trustProxyCertificateHeader once the TLS-terminating proxy sets Client-Cert and strips any incoming copy (certificate headers are ignored until then)'
		);
		return undefined;
	}
	const encoded = standard ? byteSequence(standard) : legacy;
	if (!encoded) {
		return undefined;
	}
	try {
		return new X509Certificate(Buffer.from(encoded, 'base64'));
	} catch {
		return undefined;
	}
}

/* RFC 8941 §3.3.5: a byte sequence is base64 between colons. Anything else is not one. */
function byteSequence(value: string): string | undefined {
	const match = value.trim().match(/^:([A-Za-z0-9+/=]*):$/);
	return match?.[1] || undefined;
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
