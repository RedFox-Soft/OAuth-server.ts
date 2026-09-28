import { db } from './db.js';
import type { ModelAdapter } from '../types.js';
import { isRecord } from '../../helpers/_/object.js';

type StoredRecord = Record<string, unknown>;

/*
 * A model area's record as the collection holds it: an object under `payload`. Which model's payload it
 * is, is the model's to check (BaseModel.fromStored), so a document is read as untyped and narrowed.
 */
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

		await this.coll().updateOne(
			{ _id },
			{ $set: { payload, ...(expiresAt ? { expiresAt } : undefined) } },
			{ upsert: true }
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

	async consume(_id: string) {
		await this.coll().findOneAndUpdate(
			{ _id },
			{ $set: { 'payload.consumed': Math.floor(Date.now() / 1000) } }
		);
	}

	coll(name: string = this.name) {
		return db.collection<{ _id: string; payload?: unknown }>(name);
	}
}
