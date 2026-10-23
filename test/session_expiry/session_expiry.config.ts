/*
 * The arrangement test/amr settled on, unchanged: the same clients reach an ID token through the
 * authorization code, refresh token and device code grants, and `claimsParameter` is on so a case can ask
 * for `session_expiry` through it.
 */
export { ApplicationConfig, clients, default } from '../amr/amr.config.ts';
