import type { JWKS } from 'lib/configs/verifyJWKs.ts';

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

export interface UserStoreInstance {
	find(id: string): Promise<User | null>;
	findByEmail(email: string): Promise<User | null>;
	create(email: string, password: string, roles?: string[]): Promise<User>;
	list(): Promise<User[]>;
	update(
		id: string,
		patch: Partial<Pick<User, 'roles' | 'active' | 'password'>>
	): Promise<User | null>;
}

export interface UserStoreConstructor {
	new (name?: string): UserStoreInstance;
}

export interface JWKSStoreInstance {
	get(keyId: string): Promise<JWKS | null>;
	set(keyId: string, key: JWKS): Promise<void>;
	delete(keyId: string): Promise<void>;
	getAll(): Promise<JWKS[]>;
}

export interface JWKSStoreConstructor {
	new (): JWKSStoreInstance;
}

export interface Project {
	_id: string;
	name: string;
	slug: string;
	type: 'admin' | 'regular';
	managedBy: string[];
	bucketId: string | null;
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
	}): Promise<Project>;
	find(id: string): Promise<Project | null>;
	findBySlug(slug: string): Promise<Project | null>;
	list(): Promise<Project[]>;
	listByManager(userId: string): Promise<Project[]>;
	update(
		id: string,
		patch: Partial<Pick<Project, 'name' | 'managedBy' | 'bucketId'>>
	): Promise<Project | null>;
	destroy(id: string): Promise<void>;
	countByBucket(bucketId: string): Promise<number>;
}

export interface ProjectStoreConstructor {
	new (): ProjectStoreInstance;
}

export interface UserBucket {
	_id: string;
	name: string;
	managedBy: string[];
	roles: string[];
	authMethods: string[];
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
	}): Promise<UserBucket>;
	find(id: string): Promise<UserBucket | null>;
	list(): Promise<UserBucket[]>;
	listByManager(userId: string): Promise<UserBucket[]>;
	update(
		id: string,
		patch: Partial<
			Pick<UserBucket, 'name' | 'managedBy' | 'roles' | 'authMethods'>
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
