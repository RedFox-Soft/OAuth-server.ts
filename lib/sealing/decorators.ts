import nanoid from '../helpers/nanoid.js';
import {
	bindingOf,
	CONNECTED_ACCOUNT_TOKEN_FIELDS,
	PRIVATE_JWK_MEMBERS,
	type SealTarget
} from '../consts/sealed_fields.js';
import type {
	BucketKey,
	BucketKeysStoreInstance,
	ConnectedAccountStoreInstance,
	ModelAdapter,
	SecretStoreInstance,
	SmtpSettingsStoreInstance,
	UserBucketStoreInstance,
	UserStoreInstance
} from '../adapters/types.js';
import { activeKeyring } from './keyring.js';
import { isSealed, openBytes, openText, seal, sealBytes } from './seal.js';
import { keyringChecked, noteRegenerated } from './startup.js';
import {
	noteReadable,
	noteReadableUnder,
	noteUnreadable
} from './unreadable.js';

/*
 * The seam where stored secrets are sealed and opened (specs/116 research R1): every store that holds a
 * declared leaf is handed out wrapped in one of these, so code above the stores reads and writes plaintext
 * and code below them stores whatever it is given. A writer that goes through a store cannot forget to seal.
 *
 * A leaf that cannot be opened is removed from what the read returns, never replaced (research R7): every
 * consumer already treats an absent secret as "not configured" and refuses, whereas any placeholder would
 * flow into a comparison or a credential.
 *
 * Without a keyring nothing is sealed, and sealed values are still opened when the keys allow.
 */

type Hook = (args: unknown[]) => Promise<unknown[]>;
type ResultHook = (result: unknown, args: unknown[]) => Promise<unknown>;

/*
 * A delegate rather than a Proxy: every method is an own property of the decorated object, so a spec that
 * replaces one (`spyOn(store, 'update')`) replaces what callers actually reach, which a Proxy's get trap
 * would hide. Methods run against the store itself; its data properties are read and written through.
 */
function decorate<T extends object>(
	target: T,
	methods: readonly string[],
	hooks: { args?: Record<string, Hook>; result?: ResultHook }
): T {
	const delegate = Object.create(
		Object.getPrototypeOf(target) as object
	) as Record<string, unknown>;
	const source = target as Record<string, unknown>;
	const seen = new Set<string>();
	for (
		let level: object | null = target;
		level && level !== Object.prototype;
		level = Object.getPrototypeOf(level) as object | null
	) {
		for (const name of Object.getOwnPropertyNames(level)) {
			if (name === 'constructor' || seen.has(name)) continue;
			seen.add(name);
			const descriptor = Object.getOwnPropertyDescriptor(level, name);
			const method: unknown = descriptor?.value;
			if (typeof method === 'function') {
				const hook = hooks.args?.[name];
				// Looked up at each call, so a method replaced on the store itself is the one that runs.
				const current = (...args: unknown[]): unknown =>
					(source[name] as (...args: unknown[]) => unknown).apply(target, args);
				delegate[name] = methods.includes(name)
					? async (...args: unknown[]) => {
							await keyringChecked();
							const callArgs = hook ? await hook(args) : args;
							const result: unknown = await current(...callArgs);
							return hooks.result ? hooks.result(result, args) : result;
						}
					: current;
			} else {
				Object.defineProperty(delegate, name, {
					get: () => source[name],
					set: (value: unknown) => {
						source[name] = value;
					},
					enumerable: descriptor?.enumerable ?? true,
					configurable: true
				});
			}
		}
	}
	return delegate as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		return false;
	}
	const prototype = Object.getPrototypeOf(value) as unknown;
	return prototype === Object.prototype || prototype === null;
}

/* Applies `open` to every record `matches` finds in a result: the record itself, a list, or one level of a page. */
async function walk(
	value: unknown,
	matches: (record: Record<string, unknown>) => boolean,
	open: (record: Record<string, unknown>) => Promise<Record<string, unknown>>,
	depth = 2
): Promise<unknown> {
	if (Array.isArray(value)) {
		return Promise.all(value.map((item) => walk(item, matches, open, depth)));
	}
	if (!isRecord(value)) return value;
	if (matches(value)) return open(value);
	if (depth === 0) return value;
	let changed = false;
	const copy: Record<string, unknown> = { ...value };
	for (const [name, member] of Object.entries(value)) {
		if (Array.isArray(member) || isRecord(member)) {
			const next = await walk(member, matches, open, depth - 1);
			if (next !== member) {
				copy[name] = next;
				changed = true;
			}
		}
	}
	return changed ? copy : value;
}

async function sealedText(
	value: unknown,
	target: SealTarget
): Promise<unknown> {
	if (typeof value !== 'string' || value === '' || isSealed(value))
		return value;
	if (!activeKeyring()) return value;
	return seal(value, bindingOf(target));
}

const ABSENT = Symbol('unreadable');

async function openedText(
	value: unknown,
	target: SealTarget
): Promise<unknown> {
	if (typeof value !== 'string' || !isSealed(value)) return value;
	const binding = bindingOf(target);
	const opened = await openText(value, binding);
	if (opened.ok) {
		noteReadable(binding);
		return opened.value;
	}
	noteUnreadable(target, opened.reason, opened.kid);
	return ABSENT;
}

const UNREADABLE_FIELDS = Symbol('unreadable fields');

/*
 * Sets `name` to `value`, or removes it when the value could not be opened and says so on the record, for the
 * one caller that has to tell "never had a secret" from "has one nobody can read" (a client, research R7).
 */
function place(
	record: Record<string, unknown>,
	name: string,
	value: unknown
): void {
	if (value !== ABSENT) {
		record[name] = value;
		return;
	}
	delete record[name];
	const marked = record as Record<symbol, string[] | undefined>;
	Object.defineProperty(record, UNREADABLE_FIELDS, {
		value: [...(marked[UNREADABLE_FIELDS] ?? []), name],
		enumerable: false,
		configurable: true
	});
}

/* The fields a decorated read removed from this record because they could not be opened. */
export function unreadableFieldsOf(record: object): readonly string[] {
	return (
		(record as Record<symbol, string[] | undefined>)[UNREADABLE_FIELDS] ?? []
	);
}

// ---------------------------------------------------------------- buckets: federation provider credentials

const PROVIDER_FIELDS = [
	['clientSecret', 'providerSecret'],
	['signingKey', 'providerSigningKey']
] as const;

async function providers(
	bucketId: string,
	federation: unknown,
	convert: (value: unknown, target: SealTarget) => Promise<unknown>
): Promise<unknown> {
	if (!Array.isArray(federation)) return federation;
	return Promise.all(
		federation.map(async (provider: unknown) => {
			if (!isRecord(provider) || typeof provider.id !== 'string') {
				return provider;
			}
			const copy = { ...provider };
			for (const [field, kind] of PROVIDER_FIELDS) {
				if (field in copy) {
					place(
						copy,
						field,
						await convert(copy[field], {
							kind,
							bucketId,
							providerId: provider.id
						})
					);
				}
			}
			return copy;
		})
	);
}

/* A project's connected services (specs/117): one secret each, bound to the service's id. */
async function services(
	bucketId: string,
	connectedServices: unknown,
	convert: (value: unknown, target: SealTarget) => Promise<unknown>
): Promise<unknown> {
	if (!Array.isArray(connectedServices)) return connectedServices;
	return Promise.all(
		connectedServices.map(async (service: unknown) => {
			if (
				!isRecord(service) ||
				typeof service.id !== 'string' ||
				!('clientSecret' in service)
			) {
				return service;
			}
			const copy = { ...service };
			place(
				copy,
				'clientSecret',
				await convert(copy.clientSecret, {
					kind: 'connectedServiceSecret',
					bucketId,
					serviceId: service.id
				})
			);
			return copy;
		})
	);
}

function holdsSecrets(data: Record<string, unknown>): boolean {
	const federation = Array.isArray(data.federation) ? data.federation : [];
	const connected = Array.isArray(data.connectedServices)
		? data.connectedServices
		: [];
	return (
		federation.some(
			(provider: unknown) =>
				isRecord(provider) &&
				(typeof provider.clientSecret === 'string' ||
					typeof provider.signingKey === 'string')
		) ||
		connected.some(
			(service: unknown) =>
				isRecord(service) && typeof service.clientSecret === 'string'
		)
	);
}

export function sealedBucketStore(
	store: UserBucketStoreInstance
): UserBucketStoreInstance {
	return decorate(
		store,
		[
			'create',
			'find',
			'findBySlug',
			'findByHost',
			'setAddress',
			'list',
			'listByGroup',
			'update',
			'setPlan',
			'scheduleDeletion',
			'cancelDeletion',
			'claimPurge'
		],
		{
			args: {
				create: async ([data, ...rest]) => {
					if (!isRecord(data) || !holdsSecrets(data)) {
						return [data, ...rest];
					}
					// A binding needs the id, so a bucket created with credentials is given one here.
					const _id = typeof data._id === 'string' ? data._id : nanoid();
					return [
						{
							...data,
							_id,
							...('federation' in data
								? {
										federation: await providers(
											_id,
											data.federation,
											sealedText
										)
									}
								: {}),
							...('connectedServices' in data
								? {
										connectedServices: await services(
											_id,
											data.connectedServices,
											sealedText
										)
									}
								: {})
						},
						...rest
					];
				},
				update: async ([id, patch, ...rest]) => {
					if (
						typeof id !== 'string' ||
						!isRecord(patch) ||
						!('federation' in patch || 'connectedServices' in patch)
					) {
						return [id, patch, ...rest];
					}
					const next: Record<string, unknown> = { ...patch };
					if ('federation' in patch) {
						noteReadableUnder(`userBuckets/${id}/federation/`);
						next.federation = await providers(id, patch.federation, sealedText);
					}
					if ('connectedServices' in patch) {
						noteReadableUnder(`userBuckets/${id}/connectedServices/`);
						next.connectedServices = await services(
							id,
							patch.connectedServices,
							sealedText
						);
					}
					return [id, next, ...rest];
				}
			},
			result: (result) =>
				walk(
					result,
					(record) =>
						typeof record._id === 'string' && Array.isArray(record.federation),
					async (bucket) => ({
						...bucket,
						federation: await providers(
							bucket._id as string,
							bucket.federation,
							openedText
						),
						...(Array.isArray(bucket.connectedServices)
							? {
									connectedServices: await services(
										bucket._id as string,
										bucket.connectedServices,
										openedText
									)
								}
							: {})
					})
				)
		}
	);
}

// ---------------------------------------------------------------- users: TOTP secrets

async function withTotp(
	user: Record<string, unknown>,
	target: SealTarget,
	convert: (value: unknown, target: SealTarget) => Promise<unknown>
): Promise<Record<string, unknown>> {
	if (!isRecord(user.totp) || !('secret' in user.totp)) return user;
	const totp = { ...user.totp };
	place(totp, 'secret', await convert(totp.secret, target));
	return { ...user, totp };
}

export function sealedUserStore(
	store: UserStoreInstance,
	bucketId: string
): UserStoreInstance {
	return decorate(
		store,
		[
			'find',
			'findByEmail',
			'create',
			'findByFederatedIdentity',
			'findLinkedTo',
			'list',
			'query',
			'findMany',
			'update'
		],
		{
			args: {
				update: async ([id, patch, ...rest]) => {
					if (
						typeof id !== 'string' ||
						!isRecord(patch) ||
						!('totp' in patch)
					) {
						return [id, patch, ...rest];
					}
					const target: SealTarget = {
						kind: 'totpSecret',
						bucketId,
						userId: id
					};
					noteReadable(bindingOf(target));
					return [id, await withTotp(patch, target, sealedText), ...rest];
				}
			},
			result: (result) =>
				walk(
					result,
					(record) => typeof record._id === 'string' && isRecord(record.totp),
					(user) =>
						withTotp(
							user,
							{ kind: 'totpSecret', bucketId, userId: user._id as string },
							openedText
						)
				)
		}
	);
}

// ---------------------------------------------------------------- SMTP password

export function sealedSmtpSettingsStore(
	store: SmtpSettingsStoreInstance
): SmtpSettingsStoreInstance {
	const target: SealTarget = { kind: 'smtpPassword' };
	return decorate(store, ['get', 'set'], {
		args: {
			set: async ([settings, ...rest]) => {
				if (!isRecord(settings)) return [settings, ...rest];
				noteReadable(bindingOf(target));
				return [
					{
						...settings,
						password: await sealedText(settings.password, target)
					},
					...rest
				];
			}
		},
		result: async (result) => {
			if (!isRecord(result) || !('password' in result)) return result;
			const copy = { ...result };
			place(copy, 'password', await openedText(copy.password, target));
			return copy;
		}
	});
}

// ---------------------------------------------------------------- signing and encryption keys

async function withPrivateMembers(
	key: Record<string, unknown>,
	convert: (value: unknown, target: SealTarget) => Promise<unknown>
): Promise<Record<string, unknown>> {
	if (!isRecord(key.jwk)) return key;
	// A revoked key's private half is never used again, so it is neither opened nor reported unreadable.
	if (key.state === 'revoked' && convert === openedText) return key;
	const jwk = { ...key.jwk };
	for (const member of PRIVATE_JWK_MEMBERS) {
		if (member in jwk) {
			place(
				jwk,
				member,
				await convert(jwk[member], {
					kind: 'privateKey',
					keyId: key._id as string,
					bucketId: key.bucketId as string,
					kid: key.kid as string,
					member
				})
			);
		}
	}
	return { ...key, jwk };
}

export function sealedBucketKeysStore(
	store: BucketKeysStoreInstance
): BucketKeysStoreInstance {
	return decorate(
		store,
		['listByBucket', 'find', 'createIfAbsent', 'setState'],
		{
			args: {
				createIfAbsent: async ([key, ...rest]) =>
					isRecord(key)
						? [await withPrivateMembers(key, sealedText), ...rest]
						: [key, ...rest]
			},
			result: async (result) => {
				const opened = await walk(
					result,
					(record) => typeof record._id === 'string' && isRecord(record.jwk),
					(key) => withPrivateMembers(key, openedText),
					1
				);
				if (
					isRecord(opened) &&
					(opened as Partial<BucketKey>).state === 'revoked'
				) {
					noteReadableUnder(`bucketKeys/${opened._id as string}/`);
				}
				return opened;
			}
		}
	);
}

// ---------------------------------------------------------------- model areas: client secrets, pending enrolments

const MODEL_METHODS = [
	'upsert',
	'create',
	'find',
	'findByUid',
	'findByUserCode',
	'findByOwner',
	'findByIndexed'
];

export function sealedClientAdapter<T>(
	adapter: ModelAdapter<T>
): ModelAdapter<T> {
	const sealPayload: Hook = async ([id, payload, ...rest]) => {
		if (typeof id !== 'string' || !isRecord(payload))
			return [id, payload, ...rest];
		const target: SealTarget = { kind: 'clientSecret', clientId: id };
		noteReadable(bindingOf(target));
		if (!('clientSecret' in payload)) return [id, payload, ...rest];
		return [
			id,
			{
				...payload,
				clientSecret: await sealedText(payload.clientSecret, target)
			},
			...rest
		];
	};
	return decorate(adapter, MODEL_METHODS, {
		args: { upsert: sealPayload, create: sealPayload },
		result: (result, args) =>
			walk(
				result,
				(record) => 'clientSecret' in record,
				async (payload) => {
					const clientId =
						typeof payload.clientId === 'string'
							? payload.clientId
							: String(args[0]);
					const copy = { ...payload };
					place(
						copy,
						'clientSecret',
						await openedText(copy.clientSecret, {
							kind: 'clientSecret',
							clientId
						})
					);
					return copy;
				},
				0
			)
	});
}

function pendingTarget(
	payload: Record<string, unknown>,
	uid: string
): SealTarget | null {
	return typeof payload.bucketId === 'string' &&
		typeof payload.accountId === 'string'
		? {
				kind: 'totpPending',
				uid,
				bucketId: payload.bucketId,
				accountId: payload.accountId
			}
		: null;
}

export function sealedTotpEnrollmentAdapter<T>(
	adapter: ModelAdapter<T>
): ModelAdapter<T> {
	const sealPayload: Hook = async ([id, payload, ...rest]) => {
		if (typeof id !== 'string' || !isRecord(payload))
			return [id, payload, ...rest];
		const target = pendingTarget(payload, id);
		if (!target) return [id, payload, ...rest];
		return [
			id,
			{ ...payload, secret: await sealedText(payload.secret, target) },
			...rest
		];
	};
	return decorate(adapter, MODEL_METHODS, {
		args: { upsert: sealPayload, create: sealPayload },
		result: (result, args) =>
			walk(
				result,
				(record) => 'secret' in record,
				async (payload) => {
					const target = pendingTarget(
						payload,
						typeof args[0] === 'string' ? args[0] : ''
					);
					if (!target) return payload;
					const copy = { ...payload };
					place(copy, 'secret', await openedText(copy.secret, target));
					return copy;
				},
				0
			)
	});
}

// ---------------------------------------------------------------- server-wide singleton secrets

/*
 * The singleton stores answer with what they read back, and `replace` compares against the stored value; so
 * the bytes a read opened are remembered against what it returned, and handed back as `observed`.
 */
export function sealedSecretStore(
	store: SecretStoreInstance,
	kind: 'dpopNonceSecret' | 'errorOriginSalt'
): SecretStoreInstance {
	const target: SealTarget = { kind };
	const binding = bindingOf(target);
	const stored = new WeakMap<object, unknown>();

	async function opened(value: unknown): Promise<unknown> {
		if (!(value instanceof Uint8Array) || !isSealed(value)) return value;
		const result = await openBytes(value, binding);
		if (!result.ok) {
			noteUnreadable(target, result.reason, result.kid);
			/*
			 * Present but unusable (no caller accepts zero bytes), which is what makes the DPoP secret and the
			 * salt be replaced; the replacement compares against the sealed bytes this stands for.
			 */
			const unusable = Buffer.alloc(0);
			stored.set(unusable, value);
			return unusable;
		}
		noteReadable(binding);
		stored.set(result.value, value);
		return result.value;
	}

	async function sealed(secret: Buffer): Promise<Buffer> {
		return activeKeyring() ? sealBytes(secret, binding) : secret;
	}

	return decorate(store, ['read', 'create', 'replace'], {
		args: {
			create: async ([secret]) => [await sealed(secret as Buffer)],
			replace: async ([observed, secret]) => {
				const raw =
					typeof observed === 'object' && observed !== null
						? stored.get(observed)
						: undefined;
				// Replacing the placeholder an unreadable value read as is a regeneration the status reports.
				if (
					raw !== undefined &&
					observed instanceof Uint8Array &&
					observed.length === 0
				) {
					await noteRegenerated(kind);
				}
				return [raw ?? observed, await sealed(secret as Buffer)];
			}
		},
		result: (result) => opened(result)
	});
}

// ---------------------------------------------------------------- connected accounts: upstream tokens

/*
 * Thrown by the connected-account store for a write while no keyring is in use (specs/117 FR-017). Unlike every
 * secret above, an upstream token is never kept in plaintext, not even until a keyring arrives: the service
 * layer refuses earlier with a message for the person, and this makes the property hold for any caller.
 */
export class KeyringRequired extends Error {
	constructor() {
		super(
			'a connected-account token cannot be stored while no keyring is in use'
		);
		this.name = 'KeyringRequired';
	}
}

async function accountTokens(
	record: Record<string, unknown>,
	convert: (value: unknown, target: SealTarget) => Promise<unknown>
): Promise<Record<string, unknown>> {
	if (
		typeof record._id !== 'string' ||
		typeof record.bucketId !== 'string' ||
		typeof record.accountId !== 'string'
	) {
		return record;
	}
	const copy = { ...record };
	for (const field of CONNECTED_ACCOUNT_TOKEN_FIELDS) {
		if (field in copy) {
			place(
				copy,
				field,
				await convert(copy[field], {
					kind: 'connectedAccountToken',
					id: record._id,
					field,
					bucketId: record.bucketId,
					accountId: record.accountId
				})
			);
		}
	}
	return copy;
}

export function sealedConnectedAccountStore(
	store: ConnectedAccountStoreInstance
): ConnectedAccountStoreInstance {
	return decorate(
		store,
		[
			'put',
			'find',
			'listByAccount',
			'destroy',
			'destroyByAccount',
			'destroyByService',
			'destroyByBucket'
		],
		{
			args: {
				put: async ([record, ...rest]) => {
					if (!activeKeyring()) throw new KeyringRequired();
					if (!isRecord(record)) return [record, ...rest];
					noteReadableUnder(`connectedAccounts/${String(record._id)}/`);
					return [await accountTokens(record, sealedText), ...rest];
				}
			},
			result: (result) =>
				walk(
					result,
					(record) =>
						typeof record._id === 'string' &&
						typeof record.serviceId === 'string',
					(record) => accountTokens(record, openedText),
					0
				)
		}
	);
}
