import type { UnnormalizedJWK } from 'lib/configs/verifyJWKs.ts';

export interface User {
	_id: string;
	email: string;
	verified: boolean;
	password: string;
	active: boolean;
	roles: string[];
	createdAt: Date;
	updatedAt: Date;
	lastLoginAt: Date | null;
	// Optional extra OIDC claims sourced with the account (e.g. profile claims
	// like given_name, or distributed/aggregated `_claim_names`/`_claim_sources`).
	// Merged into the account's claims() output; the provider masks by scope.
	claims?: Record<string, unknown>;
}

export interface ModelAdapter<TPayload = unknown> {
	upsert(id: string, payload: TPayload, expiresIn?: number): Promise<void>;
	find(id: string): Promise<TPayload | undefined>;
	findByUserCode(userCode: string): Promise<TPayload | undefined>;
	findByUid(uid: string): Promise<TPayload | undefined>;
	destroy(id: string): Promise<void>;
	revokeByGrantId(grantId: string): Promise<void>;
	consume(id: string): Promise<void>;
}

export interface ModelAdapterConstructor {
	new (name: string): ModelAdapter<Record<string, unknown>>;
}

export type {
	KnownModelName,
	ModelPayloadByName,
	PayloadForModel
} from './modelTypes.js';

export interface AdapterConfigStore {
	get(): Promise<Record<string, unknown> | null>;
	set(config: Record<string, unknown>): Promise<void>;
}

export interface SmtpSettings {
	host: string;
	port: number;
	secure: boolean;
	username: string;
	// Stored as provided; never returned to clients (masked) and never logged.
	password: string;
	fromName: string;
	fromEmail: string;
}

// Runtime, super-admin-editable SMTP transport config. Read live by the mailer on
// every send so changes take effect without a provider restart (kept out of the
// boot-only ApplicationConfig for that reason).
export interface SmtpSettingsStoreInstance {
	get(): Promise<SmtpSettings | null>;
	set(settings: SmtpSettings): Promise<void>;
}

export interface SmtpSettingsStoreConstructor {
	new (): SmtpSettingsStoreInstance;
}

export interface UserStoreInstance {
	find(id: string): Promise<User | null>;
	findByEmail(email: string): Promise<User | null>;
	create(
		email: string,
		password: string,
		roles?: string[],
		verified?: boolean
	): Promise<User>;
	list(): Promise<User[]>;
	update(
		id: string,
		patch: Partial<Pick<User, 'roles' | 'active' | 'password' | 'verified'>>
	): Promise<User | null>;
	destroy(id: string): Promise<void>;
}

export interface UserStoreConstructor {
	new (name?: string): UserStoreInstance;
}

/*
 * The key store reads back what was persisted, so what it returns is `UnnormalizedJWK`, not `JWKS`:
 * a key provisioned out of band may be missing `kid` or `use`, which only verifyJWKs fills in. The
 * store used to claim `JWKS` — normalization it never performs — which is precisely how a bug that
 * compared a stored key's absent `kid` against a live one went unnoticed by the compiler.
 *
 * `set` accepts either, since `JWKS` is the normalized form of the same key.
 */
export interface JWKSStoreInstance {
	get(keyId: string): Promise<UnnormalizedJWK | null>;
	set(keyId: string, key: UnnormalizedJWK): Promise<void>;
	delete(keyId: string): Promise<void>;
	getAll(): Promise<UnnormalizedJWK[]>;
}

export interface JWKSStoreConstructor {
	new (): JWKSStoreInstance;
}

export interface AdminAuditEntry {
	_id: string;
	actorId: string;
	actorEmail: string;
	action: string;
	targetType: string;
	targetId: string;
	timestamp: Date;
}

// Append-only by construction: there is intentionally no update or delete method, so an
// admin audit trail cannot be tampered with through the adapter (constitution: immutable
// audit log for every state-changing administrative action).
export interface AdminAuditStoreInstance {
	record(
		entry: Omit<AdminAuditEntry, '_id' | 'timestamp'>
	): Promise<AdminAuditEntry>;
	list(filter?: {
		targetType?: string;
		targetId?: string;
	}): Promise<AdminAuditEntry[]>;
}

export interface AdminAuditStoreConstructor {
	new (): AdminAuditStoreInstance;
}

export interface Project {
	_id: string;
	name: string;
	slug: string;
	type: 'admin' | 'regular';
	managedBy: string[];
	bucketId: string | null;
	clientIds: string[];
	createdAt: Date;
	updatedAt: Date;
}

export interface ProjectStoreInstance {
	create(data: {
		_id?: string;
		name: string;
		slug: string;
		type?: 'admin' | 'regular';
		managedBy?: string[];
		bucketId?: string | null;
		clientIds?: string[];
	}): Promise<Project>;
	find(id: string): Promise<Project | null>;
	findBySlug(slug: string): Promise<Project | null>;
	list(): Promise<Project[]>;
	listByManager(userId: string): Promise<Project[]>;
	update(
		id: string,
		patch: Partial<
			Pick<Project, 'name' | 'managedBy' | 'bucketId' | 'clientIds'>
		>
	): Promise<Project | null>;
	destroy(id: string): Promise<void>;
	countByBucket(bucketId: string): Promise<number>;
	findByClientId(clientId: string): Promise<Project | null>;
}

export interface ProjectStoreConstructor {
	new (): ProjectStoreInstance;
}

export type VerificationMethod = 'link' | 'code';

export interface UserBucket {
	_id: string;
	name: string;
	managedBy: string[];
	roles: string[];
	authMethods: string[];
	// Whether self-service registration is accepted for this bucket. The reserved
	// admin bucket seeds this false; every other bucket defaults true.
	registrationOpen: boolean;
	// Whether a newly registered account must verify its email before it counts as
	// verified (and, when required, before it can sign in).
	emailVerificationRequired: boolean;
	// Which proof the registrant uses when verification is required.
	verificationMethod: VerificationMethod;
	createdAt: Date;
	updatedAt: Date;
}

export interface UserBucketStoreInstance {
	create(data: {
		_id?: string;
		name: string;
		managedBy?: string[];
		roles?: string[];
		authMethods?: string[];
		registrationOpen?: boolean;
		emailVerificationRequired?: boolean;
		verificationMethod?: VerificationMethod;
	}): Promise<UserBucket>;
	find(id: string): Promise<UserBucket | null>;
	list(): Promise<UserBucket[]>;
	listByManager(userId: string): Promise<UserBucket[]>;
	update(
		id: string,
		patch: Partial<
			Pick<
				UserBucket,
				| 'name'
				| 'managedBy'
				| 'roles'
				| 'authMethods'
				| 'registrationOpen'
				| 'emailVerificationRequired'
				| 'verificationMethod'
			>
		>
	): Promise<UserBucket | null>;
	destroy(id: string): Promise<void>;
}

export interface UserBucketStoreConstructor {
	new (): UserBucketStoreInstance;
}

export interface AdminSession {
	_id: string;
	userId: string;
	bucketId: string;
	tokens: { accessToken?: string; idToken?: string; refreshToken?: string };
	createdAt: Date;
	expiresAt: Date;
	absoluteExpiresAt: Date;
}

export interface AdminSessionStoreInstance {
	create(data: {
		userId: string;
		bucketId: string;
		tokens: AdminSession['tokens'];
		ttlSeconds: number;
		absoluteTtlSeconds: number;
	}): Promise<AdminSession>;
	find(id: string): Promise<AdminSession | null>;
	touch(id: string, ttlSeconds: number): Promise<void>;
	destroy(id: string): Promise<void>;
}

export interface AdminSessionStoreConstructor {
	new (): AdminSessionStoreInstance;
}
