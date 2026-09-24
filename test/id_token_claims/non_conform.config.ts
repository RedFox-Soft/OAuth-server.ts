import config from './conform.config.js';

// conformIdTokenClaims now lives on ApplicationConfig. Only that flag is exported: the base
// config's own ApplicationConfig flags were never inherited here (only the default export was
// ever carried over, and the harness does not read it), and spreading them in now would change
// what this spec exercises.
export const ApplicationConfig = {
	conformIdTokenClaims: false,
	/*
	 * The signed-userinfo cases need it, as in conform.config.ts. They once got a signed response
	 * without it by assigning the algorithm to the resolved client, bypassing the recognition that
	 * would have stripped it; then by inheriting conform's validated client through the memo.
	 */
	'jwtUserinfo.enabled': true
};

// Clients are seeded from the `clients` named export; inherit the base set.
export { clients } from './conform.config.js';

export default config;
