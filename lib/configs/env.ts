const issuer = process.env.ISSUER;
if (!issuer) {
	throw new Error('ISSUER environment variable is not set');
}

export const ISSUER = issuer;

/*
 * The secret a TLS-terminating proxy sends beside the client certificate it forwards, so a certificate
 * header is believed only when the proxy, not the caller, set it (see lib/addon/mtls.ts). A deployment
 * value rather than a setting: it is a credential, and the settings surface is read back by the console
 * and the agent. Read on each call so a missing value is noticed where it matters, not at boot for every
 * deployment that never enables mTLS.
 */
export function mtlsProxySecret(): string | undefined {
	return process.env.MTLS_PROXY_SECRET || undefined;
}
