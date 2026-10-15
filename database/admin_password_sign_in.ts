import { selectBackend } from '../lib/adapters/selectBackend.js';

/*
 * Turns password sign-in to the console back on, for an operator locked out of it (specs/080).
 *
 *   bun run admin:password-sign-in
 *
 * For the case the console cannot cover: password sign-in is off and every identity provider of the
 * administrators' bucket has failed upstream. Works against whichever datastore is configured, and changes
 * nothing when password sign-in is already on.
 */

if (selectBackend(process.env) === 'memory') {
	console.error(
		'no datastore is configured, so there is no console to restore. Set MONGODB_URI or POSTGRES_URL.'
	);
	process.exit(1);
}

// Imported only now: the adapter index connects to the configured datastore as a side effect of import.
const { restorePasswordSignIn } =
	await import('../lib/admin/password_sign_in.js');

const outcome = await restorePasswordSignIn();
console.log(
	outcome === 'restored'
		? 'Password sign-in is on for the Administrators project.'
		: 'Password sign-in was already on for the Administrators project; nothing changed.'
);
process.exit(0);
