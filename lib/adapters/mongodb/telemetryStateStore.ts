import crypto from 'crypto';
import { ObjectId } from 'mongodb';

import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	TelemetryState,
	type LookupFigures,
	type LookupKey,
	type Registration,
	type TelemetryCountDeltas,
	type TelemetryStateStoreInstance
} from '../types.js';

function stringTo24CharHex(value: string): string {
	return crypto
		.createHash('sha256')
		.update(value)
		.digest('hex')
		.substring(0, 24);
}

/* A duplicate key on the fixed _id is how a losing creator learns another process won. */
function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

export class TelemetryStateStore implements TelemetryStateStoreInstance {
	private collectionName: string = STORE_AREAS.serviceConfig;
	private stateId = new ObjectId(stringTo24CharHex('telemetryState'));

	private collection() {
		// Untyped documents: the paths written here (`counts.<day>.tokens.<grant>`) are built at run time.
		return db.collection(this.collectionName);
	}

	async instanceId(): Promise<string> {
		const existing = await this.read();
		if (existing) return existing.instanceId;
		try {
			await this.collection().insertOne({
				_id: this.stateId,
				instanceId: crypto.randomUUID()
			});
		} catch (error) {
			if (!isDuplicateKey(error)) throw error;
		}
		const stored = await this.read();
		if (!stored) {
			throw new Error('the usage-reporting state could not be read back');
		}
		return stored.instanceId;
	}

	async claimDay(day: string): Promise<boolean> {
		const result = await this.collection().updateOne(
			{
				_id: this.stateId,
				$or: [
					{ lastClaimedDay: { $exists: false } },
					{ lastClaimedDay: { $lt: day } }
				]
			},
			{ $set: { lastClaimedDay: day } }
		);
		return result.modifiedCount === 1;
	}

	async addCounts(
		day: string,
		deltas: TelemetryCountDeltas,
		keepDays: readonly string[]
	): Promise<void> {
		const increments: Record<string, number> = {
			[`counts.${day}.serverErrors`]: deltas.serverErrors
		};
		for (const [name, added] of Object.entries(deltas.tokens)) {
			increments[`counts.${day}.tokens.${name}`] = added;
		}
		await this.collection().updateOne(
			{ _id: this.stateId },
			{ $inc: increments }
		);

		const state = await this.read();
		const stale = Object.keys(state?.counts ?? {}).filter(
			(kept) => !keepDays.includes(kept)
		);
		if (stale.length > 0) {
			await this.collection().updateOne(
				{ _id: this.stateId },
				{
					$unset: Object.fromEntries(stale.map((old) => [`counts.${old}`, '']))
				}
			);
		}
	}

	async recordSend(
		reportJson: string,
		deliveredAt: Date | null
	): Promise<void> {
		await this.collection().updateOne(
			{ _id: this.stateId },
			{
				$set: {
					lastReport: reportJson,
					...(deliveredAt ? { lastDeliveredAt: deliveredAt.toISOString() } : {})
				}
			}
		);
	}

	async recordAttackSend(
		reportJson: string,
		deliveredAt: Date | null
	): Promise<void> {
		await this.collection().updateOne(
			{ _id: this.stateId },
			{
				$set: {
					lastAttackReport: reportJson,
					...(deliveredAt
						? { lastAttackDeliveredAt: deliveredAt.toISOString() }
						: {})
				}
			}
		);
	}

	async raiseAttackerListBuiltAt(builtAt: string): Promise<void> {
		await this.collection().updateOne(
			{
				_id: this.stateId,
				$or: [
					{ attackerListBuiltAt: { $exists: false } },
					{ attackerListBuiltAt: { $lt: builtAt } }
				]
			},
			{ $set: { attackerListBuiltAt: builtAt } }
		);
	}

	async raiseNetworkFactsBuiltAt(builtAt: string): Promise<void> {
		await this.collection().updateOne(
			{
				_id: this.stateId,
				$or: [
					{ networkFactsBuiltAt: { $exists: false } },
					{ networkFactsBuiltAt: { $lt: builtAt } }
				]
			},
			{ $set: { networkFactsBuiltAt: builtAt } }
		);
	}

	async claimRegistrationDay(day: string): Promise<boolean> {
		const result = await this.collection().updateOne(
			{
				_id: this.stateId,
				$or: [
					{ 'registration.lastClaimedDay': { $exists: false } },
					{ 'registration.lastClaimedDay': { $lt: day } }
				]
			},
			{ $set: { 'registration.lastClaimedDay': day } }
		);
		return result.modifiedCount === 1;
	}

	async updateRegistration(
		changes: Partial<Registration>,
		clear: readonly (keyof Registration)[] = []
	): Promise<void> {
		const set: Record<string, unknown> = {};
		for (const [member, value] of Object.entries(changes)) {
			set[`registration.${member}`] = value;
		}
		const unset: Record<string, ''> = {};
		for (const member of clear) {
			if (!(`registration.${member}` in set)) {
				unset[`registration.${member}`] = '';
			}
		}
		const update = {
			...(Object.keys(set).length > 0 ? { $set: set } : {}),
			...(Object.keys(unset).length > 0 ? { $unset: unset } : {})
		};
		if (Object.keys(update).length === 0) return;
		await this.collection().updateOne({ _id: this.stateId }, update);
	}

	async setLookupKey(value: LookupKey | { droppedAt: string }): Promise<void> {
		if ('receivedAt' in value) {
			await this.collection().updateOne(
				{ _id: this.stateId },
				{ $set: { lookupKey: { ...value } } }
			);
			return;
		}
		await this.collection().updateOne(
			{ _id: this.stateId, lookupKey: { $exists: true } },
			{ $set: { 'lookupKey.droppedAt': value.droppedAt } }
		);
	}

	/*
	 * A pipeline update, so the used-up day of the stored figures is kept in the same statement that replaces them.
	 * `$literal` because a value beginning with `$` would otherwise be read as a field path.
	 */
	async recordLookups(figures: LookupFigures): Promise<void> {
		if (figures.exhaustedDay !== undefined) {
			await this.collection().updateOne(
				{ _id: this.stateId },
				{ $set: { lookups: { ...figures } } }
			);
			return;
		}
		await this.collection().updateOne({ _id: this.stateId }, [
			{
				$set: {
					lookups: {
						$cond: [
							{ $eq: ['$lookups.day', { $literal: figures.day }] },
							{
								$mergeObjects: [
									{ $literal: figures },
									{ exhaustedDay: '$lookups.exhaustedDay' }
								]
							},
							{ $literal: figures }
						]
					}
				}
			}
		]);
	}

	async noteFirstKeyReport(at: string): Promise<void> {
		await this.collection().updateOne(
			{
				_id: this.stateId,
				'registration.firstKeyReportAt': { $exists: false }
			},
			{ $set: { 'registration.firstKeyReportAt': at } }
		);
	}

	async read(): Promise<TelemetryState | null> {
		const found = await this.collection().findOne({ _id: this.stateId });
		if (!found) return null;
		const { _id, ...doc } = found;
		return documentOf(this.collectionName, TelemetryState, doc);
	}
}
