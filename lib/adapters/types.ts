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
	create(email: string, password: string): Promise<void>;
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
