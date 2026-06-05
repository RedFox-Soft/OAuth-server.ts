import type { JWKS } from 'lib/configs/verifyJWKs.ts';

export interface User {
	_id: string;
	email: string;
	verified: boolean;
	password: string;
	active: boolean;
	createdAt: Date;
	updatedAt: Date;
	lastLoginAt: Date | null;
}

export interface ModelAdapter {
	upsert(id: string, payload: unknown, expiresIn?: number): Promise<void>;
	find(id: string): Promise<unknown>;
	findByUserCode(userCode: string): Promise<unknown>;
	findByUid(uid: string): Promise<unknown>;
	destroy(id: string): Promise<void>;
	revokeByGrantId(grantId: string): Promise<void>;
	consume(id: string): Promise<void>;
}

export interface ModelAdapterConstructor {
	new (name: string): ModelAdapter;
}

export interface AdapterConfigStore {
	get(): Promise<Record<string, unknown> | null>;
	set(config: Record<string, unknown>): Promise<void>;
}

export interface UserStoreInstance {
	find(id: string): Promise<User | null>;
	findByEmail(email: string): Promise<User | null>;
	create(email: string, password: string): Promise<void>;
}

export interface UserStoreConstructor {
	new (name?: string): UserStoreInstance;
}

export interface JWKSStoreInstance {
	get(keyId: string): Promise<Record<string, JWKS> | null>;
	set(keyId: string, key: Record<string, JWKS>): Promise<void>;
	delete(keyId: string): Promise<void>;
	getAll(): Promise<Array<Record<string, JWKS>>>;
}

export interface JWKSStoreConstructor {
	new (): JWKSStoreInstance;
}
