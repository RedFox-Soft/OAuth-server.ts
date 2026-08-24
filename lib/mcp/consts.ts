import { ISSUER } from '../configs/env.js';
import { routeNames } from '../consts/param_list.js';

/*
 * Re-exported from `routeNames` rather than declared here, so the feature-gate classification table —
 * which is deliberately dependency-light and cannot import this module — and the mounted routes read
 * the same literal. A path rename lands in one place.
 *
 * MCP_METADATA_ROUTE is RFC 9728 protected resource metadata: the MCP specification requires an MCP
 * server to publish it so a client can discover which authorization server to use. This server is its
 * own, so the document names ISSUER.
 */
export const MCP_ROUTE = routeNames.mcp;
export const MCP_METADATA_ROUTE = routeNames.mcp_metadata;

/*
 * The audience an access token must carry to reach `/mcp`, and the resource indicator (RFC 8707) a
 * client requests to obtain one.
 *
 * Built from ISSUER rather than configured, because it is not a deployment choice: it identifies this
 * server's MCP endpoint, and an operator who could set it to something else could only get it wrong.
 * Audience separation is what stops a token minted for the UserInfo endpoint from administering the
 * server — `lib/actions/userinfo.ts` already refuses any token that carries an audience at all, so
 * the boundary holds in both directions once `/mcp` requires this one.
 */
export const MCP_RESOURCE = `${ISSUER.replace(/\/$/, '')}${MCP_ROUTE}`;

/*
 * The reserved client an MCP agent authenticates as. Seeded into the admin project, which is what
 * routes it to the admin bucket: `lib/admin/auth/resolveBucket.ts` sends a client to that bucket only
 * when it is the reserved console client or belongs to a project whose bucket is the admin bucket. A
 * dynamically registered client falls through to 'redfox' and cannot authenticate an administrator at
 * all — see specs/024-admin-mcp-control-plane/research.md D6 for why DCR is not the path here.
 */
export const ADMIN_MCP_CLIENT_ID = 'admin-mcp';

/*
 * How long a confirmation for a high-consequence operation stays redeemable. Long enough for an
 * operator to read what the agent proposed and answer, short enough that an abandoned confirmation
 * cannot be redeemed later against state that has since changed.
 */
export const MCP_CONFIRMATION_TTL_SECONDS = 300;

export const MCP_SERVER_NAME = 'oauth-server-admin';
