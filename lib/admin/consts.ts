export const ADMIN_PROJECT_ID = 'admin';
export const ADMIN_BUCKET_ID = 'admin';
/*
 * The group that owns containers no administrator managed at migration time. Reachable only by super
 * administrators, and exempt from the at-least-one-owner rule for the same reason the reserved admin
 * project and bucket are exempt from the group model: it is a holding area, not a tenant.
 *
 * Real rather than defensive — a super administrator can create a project with an empty manager list,
 * so containers in exactly this state already exist.
 */
export const UNASSIGNED_GROUP_ID = 'unassigned';
export const ADMIN_CLIENT_ID = 'admin-panel';
export const ADMIN_SESSION_COOKIE = '_admin_session';

export const ADMIN_SESSION_TTL_SECONDS = 60 * 60; // sliding
export const ADMIN_SESSION_ABSOLUTE_TTL_SECONDS = 60 * 60 * 12; // hard cap
