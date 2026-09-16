/*
 * Borrowed from the per-bucket sessions area, which is where the two-bucket fixture lives. A second
 * copy would drift from it the first time either bucket's clients change, and what these cases
 * exercise is the same fixture seen from the sign-out end.
 *
 * `clients` is named explicitly rather than carried by `export *`: the harness reads the binding off
 * the module it loads, and a star re-export left it undefined — every request answered
 * `invalid_client` for a client the config plainly declares.
 */

export {
	clients,
	ApplicationConfig
} from '../per_bucket_sessions/per_bucket_sessions.config.js';
