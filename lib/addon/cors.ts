import { mustChange } from './_warn.ts';

// Decides whether a CORS request should be allowed based on the request's client.
// The default denies every origin (and warns) so a deployment that wants
// client-based CORS must override it. Must be synchronous and return a Boolean.
export function clientBasedCORS(_ctx, _origin, _client) {
	mustChange(
		'clientBasedCORS',
		'control CORS allowed Origins based on the client making a CORS request'
	);
	return false;
}
