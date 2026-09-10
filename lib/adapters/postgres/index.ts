export { SqlAdapter } from './sqlAdapter.js';
export { configStore } from './configStore.js';
export { UserStore } from './userStore.js';
export { JWKSStore } from './jwksStore.js';
export { GroupStore } from './groupStore.js';
export { GroupInvitationStore } from './groupInvitationStore.js';
export { ProjectStore } from './projectStore.js';
export { ProtectedResourceStore } from './protectedResourceStore.js';
export { McpClientPermissionStore } from './mcpClientPermissionStore.js';
export { UserBucketStore } from './userBucketStore.js';
export { AdminSessionStore } from './adminSessionStore.js';
export { AdminAuditStore } from './adminAuditStore.js';
export { ErrorStore } from './errorStore.js';
export { McpConfirmationStore } from './mcpConfirmationStore.js';
export { SmtpSettingsStore } from './smtpSettingsStore.js';
export { SingletonSecretStore } from './singletonSecretStore.js';
export { SchemaMigrationStore } from './schemaMigrationStore.js';
export { MigrationLeaseStore } from './migrationLeaseStore.js';

/* Not a store: the expiry sweeper this backend needs in place of the TTL index PostgreSQL does not
 * have. Exported so the selection site can start it, rather than started here — a module that begins
 * a timer merely by being imported is one a script cannot import to read a plan. */
export { SWEEP_INTERVAL_MS, startSweeper, sweepOnce } from './reap.js';

/* Provisioning, for the operator command and for creating a bucket's user table at runtime. */
export {
	applyIndexes,
	ensureTable,
	indexName,
	indexStatements,
	isDuplicateTable,
	isIndexConflict,
	isInsufficientPrivilege,
	planFor,
	provisionUserArea,
	tableExists,
	tableStatement,
	type PlannedIndex
} from './provision.js';

export { close, ping, sql } from './db.js';
