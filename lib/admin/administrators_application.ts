import { ADMIN_BUCKET_ID, ADMIN_CLIENT_ID } from './consts.js';
import { ADMIN_MCP_CLIENT_ID } from '../mcp/consts.js';

/*
 * An application a super administrator registered in the administrators' bucket for an internal tool
 * (specs/109): it signs the instance's administrators in and is fenced off from everything that acts inside
 * this server. The two seeded clients live in the same bucket and are not such applications — the console is
 * the control plane's own sign-in and `admin-mcp` is the agent's way in.
 *
 * A leaf, because the resource arm (`lib/addon/resources.ts`) asks it on the token path, where the admin
 * service and its model graph must not be imported.
 */
export function isAdministratorsApplication(record: {
	clientId: string;
	bucketId?: string;
}): boolean {
	return (
		record.bucketId === ADMIN_BUCKET_ID &&
		record.clientId !== ADMIN_CLIENT_ID &&
		record.clientId !== ADMIN_MCP_CLIENT_ID
	);
}
