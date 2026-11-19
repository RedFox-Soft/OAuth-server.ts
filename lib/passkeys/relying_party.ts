import { isIP } from 'node:net';

import {
	issuerFor,
	shownNameOf,
	type RequestBucket
} from '../configs/issuer.js';

/*
 * The relying party a project's passkeys belong to (specs/139 research R4): one RP ID and one origin, both from the
 * project's own issuer, never from the request. A root or path project uses the instance's host, a subdomain project
 * its subdomain, a host project its host. Nothing reads `X-Forwarded-Host`; the request host is only ever compared.
 */
export interface RelyingParty {
	rpId: string;
	origin: string;
	/* What the browser shows beside the passkey: the project's shown name. */
	name: string;
}

export function relyingPartyOf(
	bucket: RequestBucket & { displayName?: string }
): RelyingParty {
	const issuer = new URL(issuerFor(bucket));
	return {
		rpId: rpIdFor(bucket),
		origin: issuer.origin,
		name: shownNameOf(bucket)
	};
}

/*
 * The RP ID a project's passkeys have at this address, or would have at another: an address change previews it for
 * the address it is about to take (specs/140 research R7), so it takes any shape the issuer is derived from.
 */
export function rpIdFor(bucket: RequestBucket): string {
	return new URL(issuerFor(bucket)).hostname;
}

function hostOf(issuer: string): string {
	return new URL(issuer).hostname.replace(/^\[|\]$/g, '');
}

/*
 * Whether an instance at this address can host passkeys at all: only when its host is a name. An IPv4 or IPv6
 * address can never be an RP ID (WebAuthn §5.1.3), so turning passkeys on there is refused. A host project's own host
 * is never an address (lib/consts/request_host.ts), so asking about the instance covers every project.
 */
export function passkeysPossible(issuer: string): boolean {
	return isIP(hostOf(issuer)) === 0;
}

/*
 * Whether browsers will decline to offer passkeys at this address until it is served over HTTPS: WebAuthn runs only
 * in a secure context, and plain `http` is one only at `localhost` and the names under it. Warned about, not refused,
 * so an instance on plain http (this suite's among them) can still be set up before its certificate arrives.
 */
export function passkeysNeedHttps(issuer: string): boolean {
	const url = new URL(issuer);
	if (url.protocol !== 'http:') return false;
	const host = hostOf(issuer).toLowerCase();
	return host !== 'localhost' && !host.endsWith('.localhost');
}

/* Kept beside the rules above for their callers; it lives in a module a browser bundle may import. */
export { passkeysAccepted } from './accepted.js';
