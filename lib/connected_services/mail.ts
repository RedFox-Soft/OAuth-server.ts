import { getUserStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { accountPageBase } from '../account_page/client.js';
import { routeNames } from '../consts/param_list.js';
import { emailLanguage } from '../i18n/resolve.js';
import { deliver, mailDeliveryConfigured } from '../mail/mailer.js';
import {
	connectedAccountEmail,
	type ConnectedAccountNotice
} from '../mail/templates/connected_account.js';
import type { ConnectedAccount } from './types.js';

/*
 * The person told about their connected accounts (specs/118 R12): an account broke, or someone else removed it.
 * Never awaited by whatever caused it, so a deletion of a service with thousands of accounts answers before the
 * mail goes, and a failure is logged without the address. Only to a verified address: the message names an upstream
 * account, and an address nobody proved may be somebody else's.
 */

const IN_FLIGHT = 4;

interface Notice {
	bucket: UserBucket;
	record: ConnectedAccount;
	notice: ConnectedAccountNotice;
	serviceName: string;
}

const queue: Notice[] = [];
let workers = 0;
const settled: (() => void)[] = [];

async function send({
	bucket,
	record,
	notice,
	serviceName
}: Notice): Promise<void> {
	if (!(await mailDeliveryConfigured())) return;
	const user = await getUserStore(bucket._id).find(record.accountId);
	if (!user?.email || !user.verified) return;
	await deliver({
		to: user.email,
		...connectedAccountEmail(
			notice,
			{
				bucketName: bucket.displayName ?? bucket.name,
				serviceName,
				label: record.label,
				url: `${accountPageBase(bucket)}${routeNames.account_services}`
			},
			emailLanguage(user)
		)
	});
}

async function work(): Promise<void> {
	workers += 1;
	try {
		for (let next = queue.shift(); next; next = queue.shift()) {
			try {
				await send(next);
			} catch (error) {
				console.error(
					'connected services: a mail about a connected account could not be sent',
					{ connectedAccountId: next.record._id, notice: next.notice, error }
				);
			}
		}
	} finally {
		workers -= 1;
		if (workers === 0) settled.splice(0).forEach((resolve) => resolve());
	}
}

function enqueue(notices: Notice[]): void {
	queue.push(...notices);
	while (workers < IN_FLIGHT && queue.length > 0) void work();
}

function serviceNameOf(bucket: UserBucket, serviceId: string): string {
	return (
		(bucket.connectedServices ?? []).find((service) => service.id === serviceId)
			?.displayName ?? serviceId
	);
}

export function noticeBroken(
	bucket: UserBucket,
	record: ConnectedAccount
): void {
	enqueue([
		{
			bucket,
			record,
			notice: 'broken',
			serviceName: serviceNameOf(bucket, record.serviceId)
		}
	]);
}

/* An administrator disconnected one account, or deleted the service: `bucket` as it was, with the service on it. */
export function noticeRemoved(
	bucket: UserBucket,
	records: ConnectedAccount[],
	notice: 'removed' | 'service_removed'
): void {
	enqueue(
		records.map((record) => ({
			bucket,
			record,
			notice,
			serviceName: serviceNameOf(bucket, record.serviceId)
		}))
	);
}

/* Test-only: wait until every mail queued so far has been tried. */
export function mailsSettled(): Promise<void> {
	if (workers === 0 && queue.length === 0) return Promise.resolve();
	return new Promise((resolve) => settled.push(resolve));
}
