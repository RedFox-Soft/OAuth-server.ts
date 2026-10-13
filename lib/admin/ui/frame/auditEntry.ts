/* An entry as `GET /admin/api/audit` answers it, shared by the Audit page and the Recent changes cards. */
export interface AuditEntry {
	_id: string;
	actorId: string;
	actorEmail: string;
	/* A directory's or upstream provider's display name, resolved by the read (specs/085); null when gone. */
	actorName?: string | null;
	action: string;
	targetType: string;
	targetId: string;
	targetScope: string | null;
	attributes?: string[];
	cascade: Record<string, number> | null;
	/* The key an operation acted on (specs/085); absent on entries written before it was recorded. */
	kid?: string | null;
	/* An address change's address before and after: a slug or hostname, null for none. */
	from?: string | null;
	to?: string | null;
	/* Absent or null on an entry made in the console: the field was added after the trail began. */
	viaSurface?: 'mcp' | 'scim' | 'upstream' | 'self-service' | null;
	viaClientId?: string | null;
	timestamp: string;
}

/*
 * The sentinel a provisioning connection is recorded under (lib/admin/audit/record.ts). Shown as what it is,
 * because the raw value in the email column reads as a malformed address rather than as a directory.
 */
export const CONNECTION_ACTOR_PREFIX = 'connection:';

/* An upstream identity provider's global token revocation: `upstream:<bucketId>:<providerId>` (specs/072). */
const UPSTREAM_ACTOR_PREFIX = 'upstream:';

/* An end user acting on their own access from their connected-applications page (specs/095). */
const ENDUSER_ACTOR_PREFIX = 'enduser:';

/* The server itself, destroying a bucket whose 30 days of scheduled deletion ran out (specs/090). */
const RETENTION_ACTOR = 'system:retention';

export function actorLabel(row: AuditEntry): string {
	if (row.actorId === RETENTION_ACTOR) return 'The server (30 days elapsed)';
	if (row.actorId.startsWith(CONNECTION_ACTOR_PREFIX)) {
		return row.actorName
			? `Directory ${row.actorName}`
			: `SCIM connection ${row.actorId.slice(CONNECTION_ACTOR_PREFIX.length)}`;
	}
	if (row.actorId.startsWith(UPSTREAM_ACTOR_PREFIX)) {
		const provider = row.actorName ?? row.actorId.split(':').at(-1) ?? '';
		return `Identity provider ${provider}`.trim();
	}
	if (row.actorId.startsWith(ENDUSER_ACTOR_PREFIX)) {
		return row.actorName
			? `${row.actorName} (the person themselves)`
			: 'The person themselves';
	}
	return row.actorEmail;
}
