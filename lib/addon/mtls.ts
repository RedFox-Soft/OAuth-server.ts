import { mustChange } from './_warn.ts';

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
