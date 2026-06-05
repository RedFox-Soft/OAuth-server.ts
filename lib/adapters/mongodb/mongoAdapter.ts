import { db } from './db.js';

export class MongoAdapter {
	name: string;

	constructor(name: string) {
		this.name = name;
	}

	async upsert(_id: string, payload: Record<string, any>, expiresIn: number) {
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

		if (!result) return;
		return result.payload;
	}

	async findByUserCode(userCode: string) {
		const result = await this.coll().findOne(
			{ 'payload.userCode': userCode },
			{ projection: { payload: 1 } }
		);

		if (!result) return;
		return result.payload;
	}

	async findByUid(uid: string) {
		const result = await this.coll().findOne(
			{ 'payload.uid': uid },
			{ projection: { payload: 1 } }
		);

		if (!result) return;
		return result.payload;
	}

	async destroy(_id: string) {
		await this.coll().deleteOne({ _id });
	}

	async revokeByGrantId(grantId: string) {
		await this.coll().deleteMany({ 'payload.grantId': grantId });
	}

	async consume(_id: string) {
		await this.coll().findOneAndUpdate(
			{ _id },
			{ $set: { 'payload.consumed': Math.floor(Date.now() / 1000) } }
		);
	}

	coll(name: string = this.name) {
		return db.collection<{ _id: string; payload: Record<string, any> }>(name);
	}
}
