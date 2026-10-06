import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import type { ModelAdapter } from '../types.js';
import { isRecord } from '../../helpers/_/object.js';

type StoredRecord = Record<string, unknown>;

/*
 * A model area's record as the collection holds it: an object under `payload`. Which model's payload it
 * is, is the model's to check (BaseModel.fromStored), so a document is read as untyped and narrowed.
 */
function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

function payloadOf(
	document: { payload?: unknown } | null
): StoredRecord | undefined {
	return isRecord(document?.payload) ? document.payload : undefined;
}

export class MongoAdapter<
	TModelName extends string = string
> implements ModelAdapter<StoredRecord> {
	name: TModelName;

	constructor(name: TModelName) {
		this.name = name;
	}

	async upsert(_id: string, payload: StoredRecord, expiresIn: number) {
		let expiresAt!: Date;

		if (expiresIn) {
			expiresAt = new Date(Date.now() + expiresIn * 1000);
		}

		/*
		 * Absent, not null, for a member the model left undefined — at any depth. A session's pending
		 * sign-out names no client when no id_token_hint was sent; stored as nulls, the record failed its
		 * schema on the way back and was read as no session at all. The filter is an id, never undefined.
		 */
		await this.coll().updateOne(
			{ _id },
			{ $set: { payload, ...(expiresAt ? { expiresAt } : undefined) } },
			{ upsert: true, ...ABSENT_UNDEFINED }
		);
	}

	async find(_id: string) {
		const result = await this.coll().findOne(
			{ _id },
			{ projection: { payload: 1 } }
		);

		return payloadOf(result);
	}

	async findByUserCode(userCode: string) {
		const result = await this.coll().findOne(
			{ 'payload.userCode': userCode },
			{ projection: { payload: 1 } }
		);

		return payloadOf(result);
	}

	async findByUid(uid: string) {
		const result = await this.coll().findOne(
			{ 'payload.uid': uid },
			{ projection: { payload: 1 } }
		);

		return payloadOf(result);
	}

	async destroy(_id: string) {
		await this.coll().deleteOne({ _id });
	}

	async revokeByGrantId(grantId: string) {
		await this.coll().deleteMany({ 'payload.grantId': grantId });
	}

	async destroyByOwner(field: string, value: string) {
		/*
		 * `field` is a declared inventory value, never caller input, and the drift guard proves each one
		 * is a plain identifier — so this interpolation cannot produce an operator or a dotted path.
		 */
		const result = await this.coll().deleteMany({
			[`payload.${field}`]: value
		});
		return result.deletedCount;
	}

	async findByOwner(field: string, value: string) {
		/* `field` is a declared inventory value, never caller input — the rule `destroyByOwner` states. */
		const found = await this.coll()
			.find({ [`payload.${field}`]: value }, { projection: { payload: 1 } })
			.toArray();
		return found
			.map((document) => payloadOf(document))
			.filter((payload): payload is StoredRecord => payload !== undefined);
	}

	async destroyUnusedSince(
		markerField: string,
		usedField: string,
		ageField: string,
		before: number
	) {
		/*
		 * Every field name is a declared inventory value, never caller input, and the drift guard proves
		 * each one is a plain identifier — so these interpolations cannot produce an operator or a dotted
		 * path. Same rule and same reason as `destroyByOwner` above.
		 */
		const result = await this.coll().deleteMany({
			[`payload.${markerField}`]: true,
			[`payload.${usedField}`]: { $exists: false },
			[`payload.${ageField}`]: { $lt: before }
		});
		return result.deletedCount;
	}

	/*
	 * The unconsumed state is part of the filter, so of racing callers only one matches. `null` in `$in`
	 * also matches a record written before `consumed` defaulted to `false`.
	 */
	async consume(_id: string) {
		const result = await this.coll().updateOne(
			{ _id, 'payload.consumed': { $in: [false, null] } },
			{ $set: { 'payload.consumed': Math.floor(Date.now() / 1000) } }
		);
		return result.modifiedCount === 1;
	}

	/*
	 * An upsert whose filter matches only an *expired* record under the id. No record: the upsert
	 * inserts. An expired one the TTL monitor has not reaped yet: it is replaced. A live one: the filter
	 * misses, the upsert tries to insert the same `_id`, and the primary key refuses it — that refusal is
	 * the answer, and it holds under concurrency because the key does.
	 */
	async create(_id: string, payload: StoredRecord, expiresIn: number) {
		const expiresAt = new Date(Date.now() + expiresIn * 1000);
		try {
			await this.coll().updateOne(
				{ _id, expiresAt: { $lte: new Date() } },
				{ $set: { payload, expiresAt } },
				// As in upsert: the filter's members are an id and a date, never undefined.
				{ upsert: true, ...ABSENT_UNDEFINED }
			);
			return true;
		} catch (error) {
			if (isDuplicateKey(error)) return false;
			throw error;
		}
	}

	/*
	 * `$inc` answered with the document after the write, so each racing caller reads back its own
	 * value. `field` is a code constant, never caller input, and the interpolation cannot produce an
	 * operator for the reason `destroyByOwner` gives.
	 */
	async increment(_id: string, field: string, expiresIn?: number) {
		const expiry =
			expiresIn === undefined
				? {}
				: {
						$set: {
							expiresAt: new Date(Date.now() + expiresIn * 1000),
							'payload.exp': Math.floor(Date.now() / 1000) + expiresIn
						}
					};
		const result = await this.coll().findOneAndUpdate(
			{ _id },
			{ $inc: { [`payload.${field}`]: 1 }, ...expiry },
			{ returnDocument: 'after', projection: { payload: 1 } }
		);
		const value = payloadOf(result)?.[field];
		return typeof value === 'number' ? value : undefined;
	}

	coll(name: string = this.name) {
		return db.collection<{ _id: string; payload?: unknown }>(name);
	}
}
