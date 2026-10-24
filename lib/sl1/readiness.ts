import { adapter, getBucketStore } from '../adapters/index.ts';
import { isAddressable } from '../admin/auth/bucketAddress.ts';
import { ApplicationConfig } from '../configs/application.ts';
import { SL1_SETTING_PREREQUISITES } from '../configs/configuration.ts';
import { ISSUER } from '../configs/env.ts';
import { issuerFor } from '../configs/issuer.ts';
import { isScheduledForDeletion } from '../consts/bucket_deletion.ts';
import { SL1_DEFAULT_SIGNING_ALGORITHM } from '../consts/sl1.ts';
import { keysFor, rootKeys } from '../keys/issuer_keys.ts';
import { validateClient } from '../models/client/validate.ts';
import {
	sl1,
	sl1ClientViolations,
	sl1Exempt,
	type Sl1Violation
} from './rules.ts';

export type Sl1Readiness = {
	enabled: boolean;
	canEnable: boolean;
	settings: { key: string; required: string; actual: unknown }[];
	issuers: {
		issuer: string;
		projectId?: string;
		signingAlgorithms: string[];
	}[];
	clients: {
		projectId: string;
		clientId: string;
		clientName?: string;
		violations: Sl1Violation[];
	}[];
};

export type Sl1Issuer = Sl1Readiness['issuers'][number];

/*
 * The issuers that could not sign for a client given the profile's default algorithm: the root, and every project with
 * an address of its own (the others sign with the root's keys). A project scheduled for deletion serves nothing.
 */
export async function issuersWithoutDefaultSigner(): Promise<Sl1Issuer[]> {
	const missing: Sl1Issuer[] = [];
	const root = (await rootKeys()).signingAlgorithms ?? [];
	if (!root.includes(SL1_DEFAULT_SIGNING_ALGORITHM)) {
		missing.push({ issuer: ISSUER, signingAlgorithms: [...root] });
	}
	for (const bucket of await getBucketStore().list()) {
		if (!isAddressable(bucket) || isScheduledForDeletion(bucket)) continue;
		const signingAlgorithms = (await keysFor(bucket)).signingAlgorithms ?? [];
		if (!signingAlgorithms.includes(SL1_DEFAULT_SIGNING_ALGORITHM)) {
			missing.push({
				issuer: issuerFor(bucket),
				projectId: bucket._id,
				signingAlgorithms: [...signingAlgorithms]
			});
		}
	}
	return missing;
}

/*
 * Every application a project holds that the profile would refuse or change. A client registered dynamically at the
 * root belongs to no project and the store keeps no index of such clients, so it is not listed here; the profile still
 * refuses it at use. A record that no longer validates is already unusable and says nothing about the profile.
 */
async function clientsAffected(): Promise<Sl1Readiness['clients']> {
	const affected: Sl1Readiness['clients'] = [];
	for (const bucket of await getBucketStore().list()) {
		if (isScheduledForDeletion(bucket)) continue;
		for (const record of await adapter('Client').findByIndexed(
			'bucketId',
			bucket._id
		)) {
			let client;
			try {
				client = validateClient(record);
			} catch {
				continue;
			}
			if (sl1Exempt(client)) continue;
			const violations = sl1ClientViolations(client, record);
			if (violations.length) {
				affected.push({
					projectId: bucket._id,
					clientId: client.clientId,
					...(client.clientName ? { clientName: client.clientName } : {}),
					violations
				});
			}
		}
	}
	return affected;
}

/* What turning the profile on would need and what it would refuse, computed without enabling anything. */
export async function sl1Readiness(): Promise<Sl1Readiness> {
	const settings = SL1_SETTING_PREREQUISITES.filter(
		(p) => !p.holds(ApplicationConfig)
	).map((p) => ({
		key: p.key,
		required: p.required,
		actual: ApplicationConfig[p.key]
	}));
	const issuers = await issuersWithoutDefaultSigner();
	return {
		enabled: sl1(),
		canEnable: settings.length === 0 && issuers.length === 0,
		settings,
		issuers,
		clients: await clientsAffected()
	};
}
