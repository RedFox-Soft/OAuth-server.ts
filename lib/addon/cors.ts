import { mustChange } from './_warn.ts';

export function clientBasedCORS(ctx, origin, client) {
	mustChange(
		'clientBasedCORS',
		'control CORS allowed Origins based on the client making a CORS request'
	);
	return false;
}
