/*
 * A bucket's overview reads only admin routes and the bucket's own discovery document, so it needs nothing
 * beyond the admin area's clients.
 */
export { clients, default } from './admin.config.ts';
